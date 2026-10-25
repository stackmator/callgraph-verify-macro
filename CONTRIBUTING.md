# Contributing

All contributors are welcome — human or otherwise. **AI agents are welcome
to open PRs on this repo if they have tokens to spare.**

## How to contribute

1. Fork, branch, commit, open a PR against `main`. Small, reviewable
   diffs beat large ones.
2. Explain the *why*: link the binary behavior, test case, or gate
   diagnostic that motivates the change.

## Ground rules

- The verifier is a trust boundary. Every check that exists is always on —
  do not add flags, env vars, or config knobs that weaken or skip checks.
  (Past `STRICT_*=0`-style escape hatches were removed for exactly this
  reason: agents flipped them off instead of fixing the underlying issue.)
- Error messages are a UI for agents: keep them self-contained, greppable
  (stable `E###` codes), and actionable (say what to do, not just what
  failed). If you change a diagnostic, update the tests that pin it.
- Disassembler changes must not move existing function boundaries without
  a test proving the new partitioning (see the `int`-fallthrough fix and
  its regression test for the template).

## Before opening a PR

```sh
cargo test -p callgraph-verify            # 64 integration + perf
cargo test -p callgraph-verify-macro      # 77 unit (+ doc tests)
```

All green, plus a `CHANGELOG.md` entry under `[Unreleased]` following
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/). If the change
alters gate behavior on a real binary, say which one and show the
before/after (`--summary` deltas, new/moved diagnostics, or lack thereof).

## Real-compiler fixture tests

`callgraph-verify/test-fixtures/` holds small C, C++, and DOS programs
that CI compiles with genuine toolchains (MSVC, MinGW, Open Watcom) and
that `tests/c_cpp_integration.rs` / `tests/dos_le_integration.rs` verify
(see `test-fixtures/README.md`). To run them locally:

```sh
# Windows (x86 dev prompt): MSVC build; Linux: MinGW cross-build.
python3 callgraph-verify/test-fixtures/build_fixtures.py
cargo test -p callgraph-verify --test c_cpp_integration
cargo test -p callgraph-verify --test dos_le_integration   # needs owcc; skips without it
```

If you touch fixture sources, keep every function reachable from `main`
and preserve the shapes the tests pin (caller/leaf/loop/indirect/global/
field/virtual — see the fixtures README). If you touch the verifier's
PE/LE parsing or call harvesting, these suites plus the GitHub
`integration` workflow are the acceptance bar.
