# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

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
- ARG-SHAPE `let`-bound const propagation in `body.rs`: `let k = 0x10;`
  records `k -> Imm(16)` so a later `f(k)` checks the value instead of
  skipping as `Other`. Sound under-approximation — rebinding to anything
  non-concrete, `=`/compound assignment, `ref` bindings, and shadowing
  binders (`for`/`while`-`let`/`if`-`let`/closures/match arms/block scope/
  `let`-`else`) all evict. Pinned by 11 `body.rs` unit tests plus
  `tests/real_arg_shape.rs`: fixtures generated from the live MSVC Od
  manifest (`branch_caller` stages `PUSH 1` before `CALL leaf_add`) prove
  `let k = 1` stays clean while `let k = 0x99` fires E014
  (`arg #1 is Imm(153), but the binary's call passes Imm(1)`).
- E021 POLARITY (new fatal code): the binary tests one branch class the
  body never tests — a wrong-class predicate the call/CFG checks can't see
  (`==` ported as `>` passes the gate while mis-modeling the binary).
  Binary side from the `CallGraph::{signed,unsigned,equality}_branches`
  harvest; Rust side from the new `CondCounts` harvest (`==`/`!=`, match
  literal arms, `matches!`, bare flag tests, `if`/`while` `let` ⇒ eq;
  relational binops, match range arms, `for` loops ⇒ rel). Fires only on
  gross divergence (equality ≥3 with body eq == 0; signed+unsigned ≥ 2 with
  body rel == 0). Taken-arm inversions WITHIN a class (`==` vs `!=`) stay a
  hand-audit (documented). Pinned by `tests/real_polarity.rs` on real MSVC
  Od output (decision_chain eq=14, nested_sum signed=2) plus 8 `body.rs`
  counting tests. New-code note for downstream trees: E021 can fire where
  E016 stayed silent (branch classes with <12 total conditionals); re-bless
  or port the predicate.
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
  LE on CI; skips without the fixture).

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
  required a SIB index, so `shl reg,2` + `jmp [reg+TABLE]` (e.g. FALL.EXE
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
  calls here (verified: 9 KB / 20-call blowup on `noivilbo.exe 0x006ff480`
  with a naive fix). The CFG leader walk, block builder, and
  `cfg_fingerprint` keep the SIB-only read so fingerprints stay
  byte-stable; only the call harvest gains the fallthrough arm.
- Regression tests: synthetic-PE `tests/jump_tables.rs` (Watcom no-index
  plus SIB images via a tiny `Asm` helper, no toolchain, fail-before /
  pass-after verified by stash), real-compiler `c_switch_case_calls_recovered`
  / `c_od_switch_case_calls_recovered` / `cpp_switch_dispatch_recognized`
  in `tests/c_cpp_integration.rs` (MSVC SIB table recovers 8x `leaf_add`;
  MSVC folds C++ cases to a shared tail so the table side pins
  `indirect_jumps >= 1` and `switch_cases >= 8`), and an elder-engine-rs
  real-world check (`cargo check --workspace --all-targets` on
  `noivilbo.exe`: 0 errors before on 0.1.1, 0 errors after with the fix).

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
  user-provided period binary such as an Oblivion-era exe, via
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
  and needed an `unreferenced` waiver (real instance: FALL.EXE
  `0x9dbe2`, reached only by `EB F0` from `0x9dbeb` — E006 fired on a
  genuine entry). Over-approximation is unchanged: a stray `0xEB`
  only ever widens the accept set. Regression tests:
  `test_referenced_addrs_indexes_jmp_short`,
  `test_referenced_addrs_still_indexes_call_rel32`.
- Real-binary before/after (FALL.EXE, dagger-engine-rs @ 1753 fns):
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
- DOS4GW LE support (synthesized PE image for FALL.EXE; fixups TODO).
- SIB-indexed in-image displacements harvested as globals.
- `vtable_table!` declaration support with indirectly-called slot
  verification.

[Unreleased]: https://github.com/stackmator/callgraph-verify-macro/compare/v0.1.5...HEAD
[0.1.5]: https://github.com/stackmator/callgraph-verify-macro/compare/v0.1.4...v0.1.5
[0.1.4]: https://github.com/stackmator/callgraph-verify-macro/compare/v0.1.3...v0.1.4
[0.1.3]: https://github.com/stackmator/callgraph-verify-macro/compare/v0.1.2...v0.1.3
[0.1.2]: https://github.com/stackmator/callgraph-verify-macro/compare/v0.1.1...v0.1.2
[0.1.1]: https://github.com/stackmator/callgraph-verify-macro/compare/v0.1.0...v0.1.1
[0.1.0]: https://github.com/stackmator/callgraph-verify-macro/releases/tag/v0.1.0
