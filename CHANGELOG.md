# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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
