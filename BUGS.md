# Bug Audit — callgraph-verify-macro

Audit date: 2026-08-29
Scope: `callgraph-verify-macro` workspace (proc-macro + core lib + tests)

Severity legend: **[BUG]** = likely to cause incorrect verdicts or dropped checks, **[LATENT]** = fragile / wrong in scenarios that don't currently occur, **[STYLE]** = clippy / docs only.

---

## [BUG] 1. Generic functions are silently dropped from the corpus

**File:** `callgraph-verify-macro/src/corpus.rs` — `fn_sig` (around line 167)

For a declaration like `pub fn foo<T>(x: T) -> T { … }` the parser builds `name` from characters before `(`, but `take_while(alphanumeric || '_')` stops at the `<` of the generic, leaving `name` empty and the function returning `None`. The next line then misses the signature, so the pending `#[origin(0xA)]` address is dropped, the function is not added to `corpus.free_fns` / `corpus.methods`, and any body call to that name resolves to nothing — i.e. it is silently classified as `HALLUCINATED`.

**Repro:** any ported function with a generic parameter.

**Fix sketch:** advance past the generic params before searching for `(`, e.g. by skipping a balanced `<…>` block, or by accepting a name that includes a `::` path and only scanning until `<` or `(`.

**Status: fixed in this audit (see code change).** Added `skip_generics` that consumes a balanced `<…>` block via depth counting, then re-locates `(` from the original `after_fn` slice so the self-receiver detection still indexes correctly. Nested generics, lifetime parameters, and `const N: usize` are all handled. Unit tests in `corpus::tests` cover the regression (`fn_sig_generic_function`, `fn_sig_generic_with_bound`, `fn_sig_generic_with_lifetime_and_const`, `fn_sig_generic_with_nested_bound`) plus the helpers (`skip_generics_*`).

---

## [BUG] 2. `reg_params` ignores CALL-clobbered registers

**File:** `callgraph-verify/src/disasm.rs` — `reg_params` (around line 301)

The scan tracks `ecx_written` / `edx_written` from explicit `MOV`/`XOR`/`LEA` writes to those registers, but never marks them as written across a `CALL`. Per the x86 cdecl/fastcall/thiscall conventions, ECX and EDX are caller-saved, so a `CALL` effectively clobbers both. As a result, after any prior `CALL` in the entry block, a subsequent `MOV EAX, [ECX]` falsely flips `ecx_param = true` even though ECX is not an entry parameter. This causes `arg_shape_check` to mis-classify the callee as `thiscall`/`fastcall` and include spurious ECX/EDX "arguments" in the diff, producing false `ARG-SHAPE` violations.

**Fix:** when `instr.flow_control() == FlowControl::Call`, set both `ecx_written = true` and `edx_written = true`.

**Status: fixed.** Integration tests `test_reg_params_real_thiscall` (a plain `MOV EAX, [ECX+0x10]; RET` still flags ECX), `test_reg_params_cdecl_after_call_does_not_flag_ecx` (CALL then ECX read → no param), and `test_reg_params_cdecl_after_call_does_not_flag_edx` (CALL then EDX read → no param) pin the regression.

---

## [BUG] 3. `has_direct_branch_target` byte-scan false positives

**File:** `callgraph-verify/src/lib.rs` — `has_direct_branch_target` (around line 43)

The function scans every byte position in `.text` and treats any `0xE8` / `0xE9` / `0x0F 0x8x` byte sequence as a CALL/JMP/Jcc, regardless of whether it sits on an actual instruction boundary. A `0xE8` byte that lives inside some other instruction's encoding will still have four bytes interpreted as a rel32 displacement; the computed target `text_va + i + 5 + rel` can coincidentally equal the queried `target`, returning `true` even when no real branch reaches it. The macro consumes this result to suppress the `VTABLE-ONLY DISPATCH` warning, so a false positive silently masks a legitimate mis-route.

**Fix sketch:** seed the scan from known instruction starts (decode once with iced-x86, then walk the resulting IP list), or accept the over-approximation but document it loudly.

**Status: fixed.** Added `text_instruction_starts(pe) -> Arc<BTreeSet<u64>>`, which decodes `.text` once via iced-x86 and returns every IP that starts a valid x86 instruction. The set is cached in a process-wide `Mutex<HashMap<(image_base, text_rva, text_vsize), OnceLock<Arc<BTreeSet<u64>>>>>` so repeated calls amortize the decode cost. `has_direct_branch_target` now gates each `0xE8`/`0xE9`/`0x0F 0x8x` hit on `starts.contains(&text_va + i)` — spurious branch-opcode bytes inside other instructions are rejected. Integration tests `test_has_direct_branch_target_rejects_spurious_e8` (crafted PE where a spurious `0xE8` inside `CMP BYTE [EAX], 0xE8` would have computed the queried target) and `test_has_direct_branch_target_real_call_is_detected` (a real `CALL rel32` at an instruction start IS still detected) pin the regression.

---

## [BUG] 4. `scan_operands` accepts indexed memory as a struct-field offset

**File:** `callgraph-verify/src/disasm.rs` — `scan_operands` (around line 121)

The `else if` arm checks `base != ESP && base != EBP && disp > 0 && disp < MAX_FIELD_OFFSET` but does **not** require `index == Register::None`. An access like `[EAX + ECX*4 + 0x10]` (an array index) is therefore recorded in `cg.field_offsets` as field `0x10`. The downstream `Spec::check` then expects every declared field offset to appear in this set, so a user declaring `fields = [0x10]` can be falsely told the offset is referenced when it only appeared in an indexed expression.

`classify_operand` (used by `recover_call_site`) gets this right — `index == Register::None` is enforced there. The asymmetry is the bug.

**Fix:** mirror the same `index == Register::None` guard in `scan_operands`.

**Status: fixed.** Added `index == Register::None` to the `scan_operands` field-offset arm. Integration tests `test_scan_operands_indexed_memory_not_a_field` (array index doesn't pollute `field_offsets`) and `test_scan_operands_plain_memory_is_a_field` (plain `[reg+disp]` still does) pin the regression.

---

## [BUG] 5. `is_origin_attr` matches commented-out `#[origin(..)]`

**File:** `callgraph-verify-macro/src/corpus.rs` — `scan_file` (around line 213)

```rust
let is_origin_attr =
    line.contains("#[") && (line.contains("origin(") || line.contains("callgraph_verify("));
```

A line like `// see #[origin(0xA)]` satisfies both clauses (the `#[` substring is present and `origin(` is a substring), so `pending.extend(hex_addrs(line, true))` runs and `0xA` becomes the pending origin for the next function signature the scanner encounters. Commented-out attributes silently re-attribute the wrong address.

**Fix:** require the line to start with `#[` (or at least not start with `//`) before accepting it as an attribute. Simplest: `line.trim_start().starts_with("#[")` instead of `line.contains("#[")`.

**Status: fixed.** Replaced `line.contains("#[")` with `line.trim_start().starts_with("#[")` in `scan_file`. Integration tests in `corpus::tests`: `scan_file_real_attribute_is_picked_up` (real attr works), `scan_file_commented_attribute_is_ignored` (a `// see #[origin(..)]` line does NOT contribute), `scan_file_commented_attribute_does_not_steal_pending_origin` (comment can't override a real attribute), and `scan_file_indented_attribute_is_picked_up` (leading whitespace preserved).

---

## [BUG] 6. `VTABLE-ONLY DISPATCH` warning discards the slot info it looked up

**File:** `callgraph-verify-macro/src/lib.rs` — `verify_impl` (around line 501)

```rust
if vtm.contains_key(&args.addr)
    && !callgraph_verify::has_direct_branch_target(&pe, args.addr)
{
    if let Some(&(vt_va, slot)) = vtm.get(&args.addr) {
        let _ = (vt_va, slot);   // <-- discarded
    }
    warn_once(&format!(
        "VTABLE-ONLY DISPATCH: {:#010x} is reached only via vtable slot …",
        args.addr
    ));
}
```

The macro goes to the trouble of looking up `(vt_va, slot)` for the very purpose of telling the user *which* vtable and *which* slot — and then throws the values away. The warning message is identical regardless of where the address was found, which defeats the stated purpose of the warning ("verify the slot index matches your `vtable_table!` declaration").

**Fix:** include `vt_va` and `slot` in the message.

**Status: fixed in this audit (see code change).**

---

## [BUG] 7. `classify_arg` `name.starts_with("rd")` over-matches

**File:** `callgraph-verify-macro/src/body.rs` — `classify_arg` (around line 167)

```rust
if name.starts_with("rd") && inner.len() >= 2 {
```

This matches the intended helpers (`rd8`, `rd16`, `rd32`, `rdf32`) **and** anything else beginning with `rd` (`read`, `rdata`, `rdb`, …). `DENY` only covers `read`. So a call like `rdata(base, 0x10)` is classified as `Field(0x10)` even though it is not a struct-field access. For the `g*` arm immediately below, an explicit list (`"g8" | "g16" | "g32" | "g64" | "gf32" | "gf64"`) is used — that pattern should be used here too.

**Fix:** replace `starts_with("rd")` with a `matches!` list analogous to the `g*` arm.

**Status: fixed.** Replaced with an explicit list: `rd8 | rd16 | rd32 | rd64 | rdf32 | rdf64`. Unit tests in `body::tests`: `classify_arg_rd_helpers_are_field` (the listed names DO classify as Field), `classify_arg_non_rd_helpers_are_other` (`read`, `rdata`, `rdb`, `rdr` do NOT), `classify_arg_g_helpers_are_global` (the `g*` arm unchanged), `classify_arg_bare_literal_is_immediate` (bare `0x10` → Imm), `classify_arg_rd_with_non_literal_offset_is_other` (variable offset doesn't fabricate a field).

---

## [BUG] 8. `block_buf` reset loses args inside branch targets

**File:** `callgraph-verify/src/disasm.rs` — `analyze` (around line 400–407)

When a `ConditionalBranch` is encountered, the branch target is pushed to `work` and `block_buf` is cleared. When the outer `while let Some(start)` loop later pops that target, it reads a fresh 2 KiB window starting at the target and re-initializes `block_buf` to empty. Any preceding setup instructions for calls inside the branch target (e.g. `MOV ECX, 5; TEST EAX, EAX; JNZ skip; …`) live in the **predecessor's** `block_buf` and are no longer in scope when the call is processed. `recover_call_site` therefore yields empty `ecx`/`edx`/`stack` for that call, undercounting arguments on the taken path.

**Fix sketch:** keep `block_buf` global across the function walk (cleared only at true function boundaries and after each CALL), or carry a small per-block predecessor window into the work item.

**Status: fixed.** Two changes in `analyze`:
1. Added a `branch_seed: HashMap<u64, Vec<Instruction>>`. When a `ConditionalBranch` / `UnconditionalBranch` / indirect-jump case pushes a target `t` onto `work`, also record the current `block_buf` (cloned) as the target's seed. When the outer loop later pops `t`, the new `block_buf` is initialized from that seed (`branch_seed.remove(&start).unwrap_or_default()`), so the target's first CALL inherits the predecessor's arg-setup. The first seed for a target wins — later pushes from other predecessors are dropped (the args are equivalent along either path up to the branch).
2. Removed `block_buf.clear()` at the `ConditionalBranch` arm. The fallthrough path's first CALL also benefits from the predecessor's args; the buffer still gets cleared after a CALL (post-call args start fresh) or at the next function entry.

Integration tests `test_analyze_branch_target_inherits_predblock_args` (taken-path CALL recovers ECX=5) and `test_analyze_fallthrough_path_still_recovers_args` (fallthrough CALL still recovers ECX=5) pin both sides of the regression.

---

## [LATENT] 9. `vtable_method_map` caches per-process ignoring its inputs

**File:** `callgraph-verify-macro/src/lib.rs` — `vtable_method_map` (around line 189)

```rust
fn vtable_method_map(pe: &Pe, declared: &[(u64, usize)]) -> &'static HashMap<u64, (u64, usize)> {
    static M: OnceLock<HashMap<u64, (u64, usize)>> = OnceLock::new();
    M.get_or_init(|| { /* builds from `pe` and `declared` */ });
}
```

The static is built from the **first** `(pe, declared)` pair the macro ever sees and then returned for every subsequent invocation regardless of inputs. In a single-tenant build there is exactly one PE and one corpus, so the cached value happens to be correct. Any future multi-target workflow (test binaries, fuzz harnesses, workspace-wide verifications) will silently return a stale map.

**Fix:** key the cache on `(pe.image_base, declared)` or make the map a per-corpus field, like `corpus_map` already does.

**Status: fixed.** Replaced the single `static M: OnceLock<…>` with a process-wide `Mutex<HashMap<CacheKey, OnceLock<Arc<HashMap<…>>>>>` keyed on `(image_base, declared-fingerprint)`. Steady-state lookups are lock-free (`OnceLock::get()` returns the cached `Arc`); the mutex is only held on the very first request per `(PE, corpus)` pair. Unit tests in `lib::tests`: `cache_key_distinguishes_image_bases`, `cache_key_distinguishes_declared_lists`, `cache_key_equal_for_same_inputs`, `vtable_method_map_is_per_pe_and_decl`.

---

## [LATENT] 10. `vtable_table!` macro emits a fat-pointer → `u32` cast

**File:** `callgraph-verify-macro/src/lib.rs` — `vtable_table` (around line 766)

```rust
(VT.get_or_init(|| { … }) as *const [usize; #slots]) as u32
```

`OnceLock::get_or_init` returns `&[usize; N]`, coerced to `*const [usize; N]` (a fat pointer: data ptr + length). The subsequent `as u32` is allowed by Rust but truncates to the low 32 bits of the **data pointer** and **drops the length**. The generated `fn name() -> u32` therefore loses the array length entirely at the use point.

In typical rebuild usage the caller already knows the length at compile time, so this happens to work. But if any consumer expects the `u32` to round-trip back to the slice, the length is gone.

**Fix:** return `*const [usize; N]` (the caller knows `N` already) or `(*const usize, usize)` (data, len).

**Status: fixed.** Changed the generated signature from `pub fn #name() -> u32` to `pub fn #name() -> *const [usize; #slots]`. The fat-pointer return type carries both the data pointer AND the compile-time-known length `N`. Callers that only need the data pointer can coerce with `as *const usize` at the call site. Doc comment updated.

---

## [STYLE] 11. Test loop always returns on the first iteration

**File:** `callgraph-verify/tests/integration.rs` — `test_has_direct_branch_target_called_function` (around line 459)

Clippy `never_loop`:

```rust
for callee in cg.call_targets() {
    assert!(has_direct_branch_target(&pe, callee), …);
    return;
}
```

The `return` is unconditional on the first iteration, so the loop body never repeats. The intent reads as "check any callee", which is what the test does. Clippy suggests:

```rust
if let Some(callee) = cg.call_targets().into_iter().next() {
    assert!(has_direct_branch_target(&pe, callee), …);
}
```

Functionally equivalent; cleaner. Suppress with `#[allow(clippy::never_loop)]` if the original shape is preferred.

**Status: fixed.** Replaced the `for callee in cg.call_targets() { …; return; }` with `if let Some(&callee) = cg.call_targets().iter().next() { … }`. Clippy no longer warns; the test still pins the rel32-scan correctness for any one direct-call pair.

---

## Summary

| # | Where | Severity | One-line |
|---|-------|----------|----------|
| 1 | `corpus.rs::fn_sig` | BUG | Generic fns silently dropped from corpus — **fixed** |
| 2 | `disasm.rs::reg_params` | BUG | ECX/EDX not marked written across CALL → false ARG-SHAPE — **fixed** |
| 3 | `lib.rs::has_direct_branch_target` | BUG | Byte-scan false positives suppress VTABLE-ONLY warning — **fixed** |
| 4 | `disasm.rs::scan_operands` | BUG | Indexed memory accepted as field offset — **fixed** |
| 5 | `corpus.rs::scan_file` is_origin_attr | BUG | Commented `#[origin(..)]` re-attributes next fn — **fixed** |
| 6 | `lib.rs::verify_impl` VTABLE-ONLY block | BUG | (vt_va, slot) discarded from warning — **fixed** |
| 7 | `body.rs::classify_arg` | BUG | `starts_with("rd")` over-matches non-field names — **fixed** |
| 8 | `disasm.rs::analyze` block_buf | BUG | Args lost inside branch targets — **fixed** |
| 9 | `lib.rs::vtable_method_map` | LATENT | Static cache ignores inputs — **fixed** |
| 10 | `lib.rs::vtable_table!` | LATENT | Fat-pointer → u32 drops length — **fixed** |
| 11 | `tests/integration.rs:459` | STYLE | `for … { … return; }` is a never_loop — **fixed** |