# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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

[Unreleased]: https://github.com/stackmator/callgraph-verify-macro/compare/v0.1.1...HEAD
[0.1.1]: https://github.com/stackmator/callgraph-verify-macro/compare/v0.1.0...v0.1.1
[0.1.0]: https://github.com/stackmator/callgraph-verify-macro/releases/tag/v0.1.0
