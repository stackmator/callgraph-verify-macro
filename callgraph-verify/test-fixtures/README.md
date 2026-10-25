# Real-compiler fixtures

Small C, C++, and DOS programs compiled to 32-bit binaries by CI and
verified by the integration tests. They prove the verifier handles genuine
compiler output — CRT startup, optimized branches, thiscall methods,
vtables, Watcom codegen — not just hand-assembled byte strings.

| Fixture | Source | Built to | By | Tests |
|---|---|---|---|---|
| C | `c/callgraph.c` | 32-bit PE | MSVC `cl` / MinGW `gcc` | `tests/c_cpp_integration.rs` |
| C++ | `cpp/callgraph.cpp` | 32-bit PE | MSVC `cl` / MinGW `g++` | `tests/c_cpp_integration.rs` |
| DOS | `dos/callgraph.c` | DOS/4GW LE | Open Watcom `owcc -bdos4g` | `tests/dos_le_integration.rs` |
| C-od | `c/callgraph.c` | 32-bit PE, `/Od`/`-O0` | MSVC `cl` / MinGW `gcc` | `c_od_*` in `c_cpp_integration.rs` |
| C-dbg | `c/callgraph.c` | 32-bit PE, `/Od`+ILT | MSVC `cl`+`link /INCREMENTAL` only | `c_dbg_*` in `c_cpp_integration.rs` |

The `-od`/`-dbg` twins cover old-compiler shapes no version-pinned toolchain
in CI could: VS2005-era installers don't run on modern runners, and no
maintained action ships MSVC 8.0/9.0. Instead: `/Od` gives EBP frames, no
inlining, and naive codegen (the weak-optimizer proxy, on both toolchains),
and `/INCREMENTAL` routes every call through ILT `JMP real` thunks (the
old-debug-build shape; exercises `resolve_thunk` and the diff's
thunk-tolerant wide set). GNU ld has no incremental linking, so the `-dbg`
twin is MSVC-only and its tests skip elsewhere. Watcom already builds
without optimization flags, so the DOS fixture is inherently weak-optimizer
output.

## Build

```sh
python3 build_fixtures.py --out <dir>   # default: <repo>/target/fixtures
```

* Windows: run from an x86 VS dev prompt (`vcvarsall x86`), or use the
  `ilammy/msvc-dev-cmd` action with `arch: x86` — needs `cl`/`link` on PATH.
* Linux: needs `i686-w64-mingw32-gcc` / `-g++` (`gcc-mingw-w64-i686`,
  `g++-mingw-w64-i686` packages).
* DOS: built automatically when `owcc` is on PATH (CI installs it via
  `open-watcom/setup-watcom` with `target: dos`); skipped with a note
  otherwise. No optimization flags on purpose — `wcc386` does not inline
  without `-oe`, so every call edge survives.

Each PE fixture also gets a `<stem>_addrs.json` manifest
(`{"leaf_add": "0x401000", ...}`) with preferred VAs extracted from the
linker map (MSVC) or `nm` (MinGW). The DOS fixture has no manifest —
`dos_le_integration.rs` discovers functions by shape instead, since wlink
map parsing is not worth the fragility.

## Consuming tests

Tests resolve fixtures via `$CALLGRAPH_{C,CPP,DOS}_EXE` (+ `$..._ADDRS` for
the manifests, plus `$CALLGRAPH_C_{OD,DBG}_EXE/ADDRS` for the `/Od` and
`/INCREMENTAL` C twins), falling back to `<repo>/target/fixtures/`. When
nothing is found they SKIP (plain `cargo test` without a C toolchain stays
green). CI exports `CALLGRAPH_REQUIRE_FIXTURES=1`, which turns a missing
fixture into a hard failure so a broken build step can never silently
green the suite by skipping. Two deliberate exceptions, documented at
their use sites: the MSVC-only `c_callgraph_dbg` twin (GNU ld cannot emit
ILT thunks) and `CALLGRAPH_REAL_EXE` below.

## Sweeping your own period binaries

`tests/real_binary_sweep.rs` runs the whole-image agreement + diff-clean
sweeps over any 32-bit PE/LE pointed at by `CALLGRAPH_REAL_EXE` — e.g. an
Oblivion-era exe built with MSVC 2005/2008, the crate's actual domain,
which can never be committed (size + licensing). Local-only by design:
it skips when the variable is unset, even under REQUIRE.

## Rules for editing fixture sources

* Every function must be reachable from `main` (or the linker discards it)
  and marked NOINLINE (C/C++; the DOS build relies on no-opt instead).
* Keep at least one of each shape the tests pin: a 2-callee caller
  (`branch_caller`), a leaf (`leaf_const`), a loop (`loop_sum`), a nested
  loop (`nested_sum`, the E016 `loops >= 2` threshold), a dense 8-case
  switch (`classify`, the `switch_cases >= 3` threshold), a 14-strong
  if-chain (`decision_chain`, the `conditionals >= 12` threshold), an
  inlinable pair (`tiny_sum` called twice by `uses_tiny`, address taken —
  the /O2-vs-/Od inlining differential), an indirect call (`apply_twice`),
  globals (`g_counter`, `g_k2`), a struct field pair
  (`field_read`/`field_write`), and — C++ only — a virtual call
  (`cpp_use_virtual_fn`) plus a member-reading method (`Circle::kind`,
  the thiscall/vtable-only pins).
* DOS scope: LE fixups are not applied yet (`Pe::parse_le` docs), so only
  call edges / indirect counts / CFG shape are pinned on LE — never
  absolute globals, immediates, or IAT slots.
