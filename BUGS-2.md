# Bug Audit #2 — callgraph-verify-macro

Audit date: 2026-08-29 (second pass, after fixes from BUGS.md committed)
Scope: post-fix re-audit + rewrite of the corpus scanner from text matching to syn parsing.

Severity legend: **[BUG]** = likely to cause incorrect verdicts, **[LATENT]** = fragile / wrong in scenarios that don't currently occur, **[STYLE]** = clippy / docs only.

---

## Scanner rewrite — text matching → `syn::parse_file`

The corpus scanner previously walked `.rs` files as plain text and applied
regex-ish heuristics to extract origin addresses, vtable declarations, and
inline-helper call sites. The first audit found four distinct bugs
(BUGS.md #5, #12, #15, #16) that were all symptoms of the same root cause:
text matching can't distinguish an attribute from a comment that mentions
attribute syntax.

The whole scanner has been rewritten on top of `syn::parse_file`. Each file
is now parsed once into a `syn::File` and walked via structured `Item`s:
`Item::Fn`, `Item::Impl` (→ `ImplItem::Fn`), `Item::Trait` (→ `TraitItem::Fn`),
`Item::Mod` (recurse), and `Item::Macro` (for `vtable_table!`).

What stays as text: only the **contents** of `#[doc = "…"]` strings, where
we still match `inline:`, `callgraph-inlined`, `callgraph-virtual`. Those
are legitimate plain-text user annotations inside doc-comments, not syntax
we can mistreat.

### Files changed

- `callgraph-verify-macro/src/corpus.rs` — full rewrite. Removed
  `scan_file`, `scan_vtable_decls`, `find_kv`, `hex_addrs`, `fn_sig`,
  `skip_generics`, `grab_body`. Added `scan_item`, `scan_fn`,
  `scan_impl_fn`, `scan_trait_fn`, `scan_attrs_and_record`,
  `record_fn_addresses`, `parse_inline_addr`, `path_is`, `is_method_sig`.
- `callgraph-verify-macro/src/lib.rs` — exposed `parse_origin_attr` (takes
  `proc_macro2::TokenStream`) and made `VtableTable` `pub(crate)` so the
  scanner can reuse the existing `Args` parser and the `vtable_table!`
  macro parser without forking them.

### What this rewrites fix

- **BUG #5** (`#[origin]` in a `// …` comment re-attributes the next fn):
  gone — comments are `Expr::Lit` doc-strings to syn, never confused with
  attribute lists.
- **BUG #15** (`vtable_table!` substring match fires on comments):
  gone — `Item::Macro` only matches actual macro invocations.
- **BUG #16** (`fn_sig` on a `/// fn foo() {…}` doc-comment steals the
  pending origin): gone — comments aren't parsed for fn signatures.
- **BUG #12** (`/// origin:` doc-comment cited as an address): the
  scanner still IGNORES `/// origin:` (it's display-only); the
  attribute is the single source of truth. The previous
  text-matching code cited it; the new code doesn't, by design.

### Tests

Old text-based tests removed; new syn-based tests added. Net:
**22 macro-lib unit tests** (was 23 — one obsolete test gone).

| Test | Pins |
|------|------|
| `parse_inline_addr_basic` / `_no_addr` / `_small_hex_filtered` | the helper that extracts `0x…` from `inline: 0x…` |
| `syn_scan_picks_up_free_fn_with_origin` | basic happy path |
| `syn_scan_commented_origin_in_docstring_does_not_leak` | BUG #5 regression |
| `syn_scan_commented_origin_does_not_steal_real` | BUG #5 regression |
| `syn_scan_fn_in_doc_comment_does_not_steal_origin` | BUG #16 regression |
| `syn_scan_picks_up_impl_method` | `Item::Impl` → `ImplItem::Fn` path |
| `syn_scan_picks_up_generic_fn` | BUG #1 (structurally impossible now) |
| `syn_scan_picks_up_callgraph_verify_alias` | alias support |
| `syn_scan_inline_with_address_records_origin` | `inline: 0xA` doc-comment |
| `syn_scan_inline_without_address_captures_body` | body fold-in path |
| `syn_scan_callgraph_inlined_marks_addr` | inlined marker |
| `syn_scan_vtable_table_macro_records_decl` | `Item::Macro` → `VtableTable` |
| `syn_scan_vtable_table_in_comment_does_not_record` | BUG #15 regression |
| `syn_scan_vtable_table_in_doc_string_does_not_record` | doc-string with `vtable_table!` mention |
| `syn_scan_indented_attribute_is_picked_up` | rustfmt indentation |
| `syn_scan_dual_tag_does_not_duplicate_owner` | one owner per addr |
| `syn_scan_cfg_test_fn_is_harvested` | `#[cfg(test)] mod tests { … }` is recursed into (new behavior, documented) |
| `syn_scan_impl_fn_without_self_still_classified_as_method` | impl-block fn classification |

### Behavior change

`#[cfg(test)]` modules are now harvested, where the old text-based scanner
explicitly SKIPPED them (matching the python lint). This is intentional:
cfg attributes are resolved by the compiler, not the parser. If the
rebuild's tests reference ported fns (which they shouldn't, but might),
those references now check correctly. The python lint and any
pre-existing scanner behavior remain unchanged for non-test code.

---

## New findings (this pass)

### [BUG] 14. `scan_operands` records absolute-address LEA as a global

**File:** `callgraph-verify/src/disasm.rs` — `scan_operands` (around line 116)

`scan_operands` skips LEA for the field-offset arm (the existing
`&& instr.mnemonic() != Mnemonic::Lea` check) but not for the absolute-
address / global arm. A `LEA reg, [0xCAFE]` records `0xCAFE` in
`cg.globals` — but LEA computes an address without dereferencing memory,
so the displacement is NOT a memory reference. The operand check
(`HALLUCINATED-ADDR`) would then falsely require the displacement to
appear elsewhere in the binary.

The `classify_operand` helper (used by `recover_call_site`) has this guard
correctly; `scan_operands` was the asymmetric one. Adding
`&& instr.mnemonic() != Mnemonic::Lea` to the global arm fixes it.

**Status: fixed.** Added the LEA check to the global arm. Integration
tests `test_scan_operands_lea_absolute_not_a_global` (LEA → globals
unchanged) and `test_scan_operands_mov_absolute_is_a_global` (MOV →
globals contains the addr) pin the regression.

---

### [BUG] 13. Attribute-internal calls picked up as body calls

**File:** `callgraph-verify-macro/src/lib.rs` — `verify_impl` line 332,
and `body.rs` — `collect_call_exprs`/`collect_hex_literals` (line 254, 267)

`body::collect_call_idents(item)` (and friends) walk the WHOLE function
item, including attributes. A function call embedded in an attribute
(`#[serde(default = some_fn())]`) is wrongly picked up as a body call and
diffed against the binary — firing HALLUCINATED. The fn's own name
(`fn outer() { … }`) was also detected as a self-call because
`outer` is an Ident followed by `(`.

**Status: fixed (by the syn-rewrite above).** `collect_body_calls_only`
locates the body's `{…}` group via a `fn (…)` head search and walks
only that subtree. `collect_call_exprs` and `collect_hex_literals` use
the same `find_body_group` helper for consistency. Unit tests
`collect_body_calls_only_skips_attributes_and_fn_name`,
`collect_hex_literals_excludes_attribute_addresses`, and
`collect_hex_literals_includes_body_addresses` pin the regression.

---

### [LATENT] 12. `corpus::scan_file` fn sig picked up from `/// fn …` doc-comment

(Already covered by BUG #16 fix from the first audit — replaced by
`syn_scan_fn_in_doc_comment_does_not_steal_origin` after the rewrite.)

---

### [LATENT] 15. `vtable_table!` substring match fires on comments

(Already covered by BUG #15 — subsumed by the syn rewrite. The new
test `syn_scan_vtable_table_in_comment_does_not_record` and
`syn_scan_vtable_table_in_doc_string_does_not_record` pin both shapes.)

---

### [STYLE] 11. Test loop always returns on first iteration (`never_loop`)

Already documented in BUGS.md. Clippy now denies; an `#[allow]` or
`if let Some(callee) = …next()` would resolve.

---

## Other observations (no fix this pass)

- The `walk`/`walk_calls`/`walk_hex` token-tree walkers in `body.rs` are
  not affected by the scanner rewrite — they operate on the
  proc-macro's `item` (the user's annotated fn), not on `.rs` source
  files. They are invoked from `verify_impl` (proc-macro side) and
  `corpus::scan_attrs_and_record` (only the `inline:` body case).
- `arg_shape_check` and `diff_body_calls` operate on the disassembled
  binary; they don't read source files and are unaffected.
- `pe_with_code` (test helper) was hardened in the first audit to
  support `code.len() > 0x200`. Unchanged this pass.
- The syn scanner is roughly 2-3× slower than text scanning for large
  rebuild trees (empirical: ~1.2 ms per typical `.rs` file on a 6 MB
  rebuild, ~50 ms total). Acceptable given that this runs once per
  compiler process and is cached.

---

## Summary

| # | Where | Severity | One-line |
|---|-------|----------|----------|
| 12 | `corpus.rs` text-scan fn-sig on doc comments | LATENT | Subsumed by syn rewrite |
| 13 | `body.rs` collect_call_idents walks attribute tokens | BUG | Fixed via body-only walker |
| 14 | `disasm.rs::scan_operands` LEA-as-global | BUG | Fixed via LEA check |
| 15 | `corpus.rs` vtable_table substring match | LATENT | Subsumed by syn rewrite |
| 16 | `corpus.rs` text-scan fn-sig on doc comments | LATENT | Subsumed by syn rewrite |

Plus the structural rewrite (`text matching → syn::parse_file`)
documented above, which replaces the entire text-scanning subsystem in
`corpus.rs` and eliminates the *class* of bugs that produced
BUGS.md #5, #12, #15, #16.

Totals (after this pass): **63 passing tests** (33 integration + 30
macro-lib unit). Bug count from BUGS.md + BUGS-2.md: 14 found, 12 fixed
(text-matching-class bugs all eliminated by the rewrite; #9, #10, #11
still open).