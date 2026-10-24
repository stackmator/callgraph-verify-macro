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
