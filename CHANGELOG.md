# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.9] - 2026-11-05

### Performance

- Cache per-image, per-address disassembly and CFG fingerprints so repeated
  verifier checks reuse the same analysis results within a compiler process.

## [0.1.8] - 2026-11-05

### Added

- `Pe::fixup_post_image(pre) -> Option<u64>`: the runtime (post-fixup) image
  of a single link-time address, or `None` for PE and for pre values that are
  not LE 07 fixup sites. Single-value counterpart of `fixup_post_images`.
- `Pe::fixup_rel32_target(loc) -> Option<u64>` / `fixup_rel32_pairs()`: LE 08
  self-relative records as `(operand_va, target_va)`. The loader writes
  `target-(operand+4)`, so the record target is the runtime destination of an
  on-disk `rel32=0` placeholder (`call $+5`, e.g. DOS4GW `int 2Fh` stubs).

### Added

- `--list`/`--count`/`--summary` follow direct-call and tail-call targets
  into non-executable code objects. Object type flags are unreliable (a
  read/write object can hold the main code and mix it with data), so a
  reachability pass now enumerates such code instead of a linear sweep.

### Fixed

- E006's branch-target scan runs over every non-executable section too, so a
  function referenced only from a read/write code object is no longer
  falsely `ORIGIN-UNREFERENCED` (widening the accept-set only).
- `call $+5` (`rel32=0`, target == `next_ip`) is no longer recorded as a call
  to the next instruction. When an LE 08 self-relative fixup patches the
  operand, the fixup's runtime target is recorded instead; otherwise the
  site is treated as a GET-PC no-op. Two integration tests that used
  `call $+5` as a synthetic call now use real rel32 targets.
- Jump-table harvesting on DOS4GW LE binaries. A switch table's base
  (`jmp dword [idx*4+TABLE]`) and its 32-bit entries are stored as link-time
  values that the loader relocates, so reading them raw made every entry look
  out of the function span: `switch_cases` collapsed to 0 and a ported body
  that spelled a hidden arm's `CALL` was reported HALLUCINATED (`E012`) - the
  arm was never harvested. Both the table base and each entry are now
  translated through `Pe::fixup_post_image` before the range check and the
  page-map read. PE (no fixup tables) is byte-for-byte unchanged. Pinned by
  the real Watcom LE fixture test
  `dos_switch_table_entries_translate_pre_fixup` and the env-gated real-LE
  sweep `real_le_jump_table_entries_translate_to_post_images`; the PE path
  stays covered by `c_switch_case_calls_recovered`.
- Hidden-arm calls are now ACCEPTANCE-ONLY. The demand analysis reads
  tables untranslated (`MISSING` unchanged from 0.1.7); the translated
  analysis feeds the acceptance set, so a body may spell an arm's `CALL`
  without tripping `E012` and is never required to (`E013` unchanged).
  This unblocks porting hidden arms with no regression on existing ports.
- The callgraph walk stops at the DOS `INT 21h` process-termination service
  (`AH=4Ch`) when the immediately preceding instruction loads AX with that
  service. Other interrupt instructions remain fallthrough-capable API calls;
  this prevents adjacent function bytes after a fatal DOS exit from being
  attributed to the current function.
- `callgraph_verify --asm` annotates zero-displacement LE-08 `CALL rel32`
  placeholders with their runtime destinations. The byte dump remains raw;
  the annotation explains call-graph edges that are not visible in the
  pre-fixup operand bytes.

## [0.1.7] - 2026-11-01

### Changed

- Scrubbed third-party project names from the published docs, comments, and
  test descriptions. Local real-PE CFG pins now read `CALLGRAPH_REAL_PE`
  (falling back to `real.exe` at the workspace root) instead of a named
  sample binary; they still skip cleanly when no binary is present.

### Fixed

- ORIGIN-UNREFERENCED (`E006`) now counts LE fixup post images as referenced.
  `referenced_addrs` indexed only the link-time dwords physically present in
  the image, so a slot-seeded callback stored as `mov dword [slot],64ABAh`
  (runtime `0x74ABA`) failed the gate even though HALLUCINATED-ADDR already
  accepted the same post value through `fixup_post_images`. The accept set is
  widened with the post images of the collected pre values (over-approximation
  only, so a genuine entry is never rejected). Pinned by the synthetic-LE unit
  test `le_referenced_addrs_include_fixup_post_images`, the real Watcom LE
  fixture test `dos_referenced_addrs_include_fixup_post_images`, and the
  env-gated real-binary sweep `real_le_fixup_post_images_are_referenced`
  (512 pre/post pairs pinned on a real LE binary).

## [0.1.6] - 2026-10-31

### Added

- `#[origin(addr, indirect_targets = [0xNN, ...])]`: declared targets the
  function reaches only through a register/memory (stack-slot) indirect
  call. Acceptance-only: a body that spells one as a direct call is
  faithful, it never becomes a `MISSING` requirement, and it is validated
  (executable-section VA + the function really has an indirect call).
  New API: `Spec::indirect_targets` and `diff_body_calls_ext` (the old
  `diff_body_calls` is a no-target wrapper). Pinned by
  `test_diff_body_calls_indirect_target_accepted` plus the real-codegen
  `c_indirect_target_accepted_on_real_output` (MSVC and MinGW, `/O2` and
  `/Od`).
- Branch-polarity ground truth in `CallGraph`: `signed_branches` /
  `unsigned_branches` / `equality_branches` count every conditional branch
  by condition class (`JL/JLE/JG/JGE` vs `JB/JBE/JA/JAE` vs `JE/JNE`),
  harvested in `analyze` alongside the call set. The gate still checks CFG
  *structure* only (an inverted `je`/`jne` mirror passes), but ports and
  tests can now pin which class the binary uses. Pinned on real MSVC
  output in `tests/c_cpp_integration.rs`: `branch_caller` (`x > 100`) and
  `loop_sum` (`i <= n`) each keep a signed branch on `/O2` and `/Od`;
  `decision_chain` keeps 13 equality branches.
- Unported-call inventory in `CorpusDiff::unported`: binary edges with no
  `#[origin]` in the corpus. Bodies may still omit these with a `TODO`
  (never fatal — no new `MISSING`), but the macro now emits an
  informational `UNPORTED-CALLS` note listing them instead of staying
  silent-green. Pinned by `c_diff_body_calls_reports_unported` on the real
  C fixture (partial corpus: `leaf_const` edge is `unported`, not `missing`).
- E021 POLARITY (advisory NOTE, code reserved): the binary tests one branch
  class the body never tests — a wrong-class predicate the call/CFG checks
  can't see (`==` ported as `>` passes the gate while mis-modeling the
  binary). Binary side from the `CallGraph::{signed,unsigned,equality}_
  branches` harvest; Rust side from the new `CondCounts` harvest (`==`/
  `!=`, match literal arms, `matches!`, bare flag tests, `if`/`while` `let`
  ⇒ eq; relational binops, match range arms, `for` loops ⇒ rel). Reports
  only gross divergence (equality ≥3 with body eq == 0; signed+unsigned ≥2
  with body rel == 0). NOTE-only by design, never fatal: downstream trees
  abstract predicates their HLE provably fixes, and there is no waiver
  mechanism for sound abstractions. Taken-arm inversions WITHIN a class
  (`==` vs `!=`) stay a hand-audit (documented). Pinned by 8 `body.rs`
  counting tests plus the binary-side integration pins (decision_chain
  eq=14, nested_sum signed=2 on real MSVC output).
- ARG-SHAPE const-prop deliberately NOT shipped: resolving `let`-bound
  args to concrete kinds exposed a latent positional-model mismatch
  (Rust arg #0 vs the callee's EDX slot) against downstream trees whose
  universal `let x = <lit>` idiom previously read as `Other` (hundreds of
  false fires on a green tree). `classify_expr` keeps its literal-only
  contract; the finding is recorded here so the model fix (register-aware
  alignment) can land first.
- E016 third-prong tightening: `conditionals >= 12` now fires at
  branchiness ≤ 1 (was == 0), where branchiness counts `if`/`match`/loops
  plus `&&`/`||` (each short-circuits through its own JCC, so a fused
  condition earns its keep). A single-`if` wrapper no longer defeats the
  gate. Pinned by `tests/real_structure.rs` on the real Od decision_chain.
- MISSING now covers self-recursion: a direct CALL to the function's own
  entry with no same-name body call is E013 (own addrs were excluded
  outright, so a dropped self-call passed silently). Self tail-JMPs stay
  out (a loop port is faithful there; the CFG gate covers it). Pinned by
  `c_recurse_sum_calls_itself` (new `recurse_sum` fixture fn, both MSVC
  modes) plus `tests/real_structure.rs` (fail without / pass with the
  self-call, real Od output).
- LE fixup awareness (closes the "fixups TODO" caveat for data addresses):
  `parse_le` now walks the fixup page/record tables and absorbs every
  internal-07 (absolute) pair as `(pre, post)` content values; 08
  (self-relative) records are parsed and validated without contributing
  (a relative offset names no address); 02 (selector) records are skipped.
  `Spec` present-checks and the E015 operand check accept post-fixup
  images of referenced pre-fixup addresses — widening only, never a demand;
  call-graph/CFG ground truth stays pre-fixup (code objects are not
  relocated). A record kind outside the grammar skips the tables loudly
  (`FixupStatus::Skipped` + macro NOTE, image stays pre-fixup) instead of
  failing the parse; corruption stays fatal. Pinned by 4 synthetic-LE
  `pe.rs` unit tests (narrow/list 07, 08 validation, unknown-kind skip,
  table-adjacency proof) and `dos_fixup_post_images_accepted` (real Watcom
  LE on CI; skips without the fixture). `Pe::fixup_pairs` exposes the
  absorbed pairs for diagnostics and real-file round-trip tests.

### Fixed

- CI `c_recurse_sum_calls_itself` no longer assumes MinGW keeps a self-call:
  GCC 13 `/O2` rewrites the non-tail recursion into an iterative loop. MSVC
  still must show the direct self-CALL; MinGW now accepts a real self edge
  (its `/O0` build) OR the loop back-edge the compiler emitted instead
  (`cfg_fingerprint().loops >= 1`), so the test checks both real shapes
  instead of skipping the toolchain.
- `dos_fixup_post_images_accepted` no longer feeds an immediate constant to
  `Spec::globals` (a false HALLUCINATED on the real `cmp eax,10000h`) and no
  longer asserts that Watcom's DS-relative fixture must expose an in-image
  pre value (it never does: the pre images are object-relative offsets, not
  VAs). It now round-trips every real 07 pair through `Pe::fixup_pairs` +
  `fixup_post_images` and checks globals/imm refs through their own Spec
  buckets; Spec acceptance stays pinned by the synthetic
  `le_fixup_post_global_passes_spec`.

## [0.1.5] - 2026-10-25

### Fixed

- Entry-stub tail blindness: a function whose whole body is one unconditional
  `JMP` (MSVC sibling-call `tail_caller -> JMP tail_target`, ICF forwarders)
  was followed as intra-function flow because the target sits inside the 64 KB
  walk span, hiding the tail edge (`calls={} tails={}`) and leaking the
  callee's globals into the caller. A single-instruction entry block ending in
  an in-range unconditional `JMP` is now a tail call (never followed). Scoped
  to exactly one instruction so a `JMP` over an inline table after a prologue
  keeps the old follow behavior.
- Register-indirect switch blindness (MinGW `-O0`): GCC lowers the unoptimized
  `classify` switch to `shl; add $TABLE; mov (%reg),%reg; jmp *%reg`, whose
  `JMP` carries no memory operand for `follow_jump_table` to read (1 indirect
  jump, 0 cases, 0 calls). The harvest now recovers the table base from the
  `add`/`lea`/`mov` that built the load register, gated on the same switch
  evidence (`cmp`/`test` + conditional branch) so vtable
  `mov %eax,[%ecx+slot]; jmp *%eax` sequences stay untouched.

## [0.1.4] - 2026-10-25

### Fixed

- Indirect-jump gate blindness for Watcom-style switches: `follow_jump_table`
  required a SIB index, so `shl reg,2` + `jmp [reg+TABLE]` (e.g. real LE
  `0x602c0`, `0x6077f`) recovered zero case bodies -- callers spelling the
  hidden calls tripped E012 HALLUCINATED, and omitting them could never trip
  E013 MISSING. The harvest now accepts the unindexed `[reg+TABLE]` shape
  when the block carries switch evidence (a `cmp`/`test` plus a conditional
  branch) and the base register is written in-block (excluding `cmp`/`test`
  self-satisfaction), so vtable tail-jumps like `jmp [ecx+0x44]` keep
  today's behavior. On LE binaries the table entries are pre-fixup bytes,
  so the table read yields no in-range targets and decoding continues at
  the fallthrough address, where Watcom lays the case bodies contiguously
  (verified: `0x602c0`'s five hidden `0x7d6ae` calls). Absolute `[disp]`
  IAT jumps are never followed: the disp names data, not code, and
  fallthrough past a non-returning jump attributes neighboring functions'
  calls here (verified: 9 KB / 20-call blowup on a real PE at `0x006ff480`
  with a naive fix). The CFG leader walk, block builder, and
  `cfg_fingerprint` keep the SIB-only read so fingerprints stay
  byte-stable; only the call harvest gains the fallthrough arm.
- Regression tests: synthetic-PE `tests/jump_tables.rs` (Watcom no-index
  plus SIB images via a tiny `Asm` helper, no toolchain, fail-before /
  pass-after verified by stash), real-compiler `c_switch_case_calls_recovered`
  / `c_od_switch_case_calls_recovered` / `cpp_switch_dispatch_recognized`
  in `tests/c_cpp_integration.rs` (MSVC SIB table recovers 8x `leaf_add`;
  MSVC folds C++ cases to a shared tail so the table side pins
  `indirect_jumps >= 1` and `switch_cases >= 8`), and a downstream real-world
  check (`cargo check --workspace --all-targets` on a real PE: 0 errors before
  on 0.1.1, 0 errors after with the fix).

### Added

- Real-compiler integration tests in GitHub Actions
  (`.github/workflows/integration.yml`): CI compiles
  `callgraph-verify/test-fixtures/` with genuine toolchains and runs the
  verifier over that output — C and C++ to 32-bit PE via MSVC `cl` (Windows)
  and MinGW-w64 (Ubuntu), plus a DOS4GW linear executable via Open Watcom
  `owcc -bdos4g` (Ubuntu). New suites: `tests/c_cpp_integration.rs`
  (symbol-anchored call-graph, Spec, operand, CFG, vtable, and IAT checks
  via linker-map / `nm` manifests — including unoptimized `/Od` twins for
  weak-optimizer shapes and an incremental-linking twin whose ILT thunks pin
  `resolve_thunk` on real output), `tests/dos_le_integration.rs`
  (shape-discovered coverage of the `parse_le` path: sweep, byte-scan
  agreement, Spec gates, leaf/loop existence), and
  `tests/real_binary_sweep.rs` (local-only whole-image sweeps over a
  user-provided real-world binary such as a 2000s-era MSVC exe, via
  `CALLGRAPH_REAL_EXE`). Missing fixtures skip locally but fail under
  `CALLGRAPH_REQUIRE_FIXTURES=1` (set in CI) so a broken build step can
  never silently green the suite. DOS tests pin call/CFG facts only —
  absolute globals/vtables stay out until LE fixup support lands.

### Fixed

- Hardened the `has_direct_branch_target` perf regression test against
  wall-clock flakes. Two changes, detection power preserved: the three
  tests in `tests/perf.rs` now serialize on a file-local mutex (cargo runs
  one binary's tests on parallel threads, and a sibling test's 4 MB scan —
  done while holding the caches' global locks — used to stall the measured
  batch and trip the assertion), and the threshold relaxed from
  `batch*10 < warmup` to `batch*2 < warmup` (a rescan-per-call regression
  costs the batch ~200 scans ≈ 200× warmup, so it still fails by ~400×;
  a cached batch passes with ~500× headroom).

## [0.1.3] - 2026-10-24

### Added

- `callgraph_verify::tail_referenced`: the address-side half of the
  tail-call wide set — union of a tail target's globals, immediates, and
  IAT slots, for the E015 referenced set. Mirrors `diff_body_calls`'
  folding of tail-callees' direct calls. Regression tests: synthetic-PE
  `test_tail_referenced_includes_tail_target_globals`, real-compiler
  `c_tail_caller_global_covered` (new `tail_caller`/`tail_target` pair
  plus `g_tail_tag` global in `test-fixtures/c/callgraph.c`, wired
  through `build_fixtures.py` manifests; asserts the fold on the -O2
  JMP shape and the direct edge on the -O0 CALL shape).

### Fixed

- E008 CORPUS-GAP now names the skipped files: the corpus scanner
  records unreadable/unparseable inputs in `Corpus::parse_errors`
  instead of silently dropping them, and the E008 diagnostic appends
  the list. Previously a single broken file produced one misleading
  gap per contained origin with no hint at the real cause (real
  instance: 121 E008s for one unbalanced brace). The E008 trybuild
  fixtures (`e005`, `e006`, `e008`) now run against a corpus containing
  a deliberately broken file and pin the appended note. Regression
  tests: `b05b_parse_error_is_recorded_not_silent`,
  `parse_errors_note_names_skipped_files`.
- E015 HALLUCINATED-ADDR accepts addresses referenced by a tail-call
  target (via `tail_referenced`). Previously the gate demanded
  duplicating a shared tail body (no MISSING) yet forbade its addresses
  (not in the duplicating function's own extent, and `globals=[...]`
  pins are present-checks that would themselves fail) — an
  unsatisfiable pair with no faithful encoding. The fold only ever
  widens acceptance, mirroring the call-side wide set; existing E015
  snapshots are unchanged.

## [0.1.2] - 2026-10-24

### Fixed

- `referenced_addrs` (the ORIGIN-UNREFERENCED scan) now indexes `JMP
  short rel8` (`0xEB`) targets alongside CALL/JMP rel32 and Jcc rel32.
  A function reached solely via short jump was invisible to the scan
  and needed an `unreferenced` waiver (real instance: an LE binary at
  `0x9dbe2`, reached only by `EB F0` from `0x9dbeb` — E006 fired on a
  genuine entry). Over-approximation is unchanged: a stray `0xEB`
  only ever widens the accept set. Regression tests:
  `test_referenced_addrs_indexes_jmp_short`,
  `test_referenced_addrs_still_indexes_call_rel32`.
- Real-binary before/after (an LE binary and its downstream port @ 1753 fns):
  before, `#[origin(0x9dbe2)]` failed E006; after, it passes with no
  waiver and no other diagnostic delta (`cargo check` green, count
  unchanged).

## [0.1.1] - 2026-10-24

### Fixed

- `int n` is no longer treated as a function terminator in the harvest,
  `--asm` printer, and skeleton walks. DOS `int 21h` / DPMI `int 31h` are
  API calls that return normally, so decoding now continues at `next_ip()`.
  Before, listings truncated at the first `int`, extents were under-measured,
  and calls reachable only via post-`int` fallthrough were silently dropped
  from the call set (blinding the gate's MISSING check for those callees).
- Regression test: post-`int` CALL is harvested and `max_end` covers the
  tail (`test_int_does_not_terminate_decode`).

## [0.1.0] - 2026-10-24

Initial crates.io release.

### Added

- `#[origin(VA)]` compile-time call-graph gate: HALLUCINATED / MISSING /
  DUP-ADDR / ARG-SHAPE / HALLUCINATED-ADDR / CFG / VTABLE-DISPATCH /
  ORIGIN-UNREFERENCED checks, always on.
- `callgraph_verify` CLI: `--asm`, `--skeleton`, `--list`, `--count`,
  `--summary`, `--declared`, `--exact` over LE and PE targets.
- DOS4GW LE support (synthesized PE image for real LE binaries; fixups TODO).
- SIB-indexed in-image displacements harvested as globals.
- `vtable_table!` declaration support with indirectly-called slot
  verification.

[Unreleased]: https://github.com/stackmator/callgraph-verify-macro/compare/v0.1.9...HEAD
[0.1.9]: https://github.com/stackmator/callgraph-verify-macro/compare/v0.1.8...v0.1.9
[0.1.8]: https://github.com/stackmator/callgraph-verify-macro/compare/v0.1.7...v0.1.8
[0.1.7]: https://github.com/stackmator/callgraph-verify-macro/compare/v0.1.6...v0.1.7
[0.1.6]: https://github.com/stackmator/callgraph-verify-macro/compare/v0.1.5...v0.1.6
[0.1.5]: https://github.com/stackmator/callgraph-verify-macro/compare/v0.1.4...v0.1.5
[0.1.4]: https://github.com/stackmator/callgraph-verify-macro/compare/v0.1.3...v0.1.4
[0.1.3]: https://github.com/stackmator/callgraph-verify-macro/compare/v0.1.2...v0.1.3
[0.1.2]: https://github.com/stackmator/callgraph-verify-macro/compare/v0.1.1...v0.1.2
[0.1.1]: https://github.com/stackmator/callgraph-verify-macro/compare/v0.1.0...v0.1.1
[0.1.0]: https://github.com/stackmator/callgraph-verify-macro/releases/tag/v0.1.0
## How to resolve a `call $+5` (rel32=0) target

FALL.EXE has many call sites encoded as `e8 00 00 00 00` whose true target is supplied by an LE `08` self-relative fixup. `--skeleton` still prints the on-disk next-ip only. `--asm` now adds the runtime destination beside such a call while preserving the raw bytes. Dump the full resolved map with the `dump_rel32` example:

```
cargo run -q -p callgraph-verify --example dump_rel32 -- <FALL.EXE> > rel32.txt
rg "^0x4f2bb " rel32.txt      # output: <operand_va> <target_va>
```

`fixup_rel32_pairs()` yields `(loc, target)` with `loc` = the operand address = call instruction address + 1. Check this map before wiring any "call-next" TODO; several such sites resolve to real obj2 functions.
