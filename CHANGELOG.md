# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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

[Unreleased]: https://github.com/stackmator/callgraph-verify-macro/compare/v0.1.4...HEAD
[0.1.4]: https://github.com/stackmator/callgraph-verify-macro/compare/v0.1.3...v0.1.4
[0.1.3]: https://github.com/stackmator/callgraph-verify-macro/compare/v0.1.2...v0.1.3
[0.1.2]: https://github.com/stackmator/callgraph-verify-macro/compare/v0.1.1...v0.1.2
[0.1.1]: https://github.com/stackmator/callgraph-verify-macro/compare/v0.1.0...v0.1.1
[0.1.0]: https://github.com/stackmator/callgraph-verify-macro/releases/tag/v0.1.0
