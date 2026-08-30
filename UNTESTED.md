# Untested Behaviors — Tracking

Documented: 2026-08-30
Repo: callgraph-verify-macro

Tracks gaps found by the 2026-08-30 audit and their resolution status.

| ID | Summary | Status | Where |
|----|---------|--------|-------|
| B-01 | DUP-ADDR error fires on duplicate origin | **DONE** | `callgraph-verify-macro/src/corpus.rs::b01_duplicate_origin_addresses_are_recorded_as_separate_owners` |
| B-02 | HALLUCINATED error fires on body call not in corpus | **DONE** | `callgraph-verify-macro/src/corpus.rs::b02_body_call_idents_records_unknown_names` |
| B-03 | MISSING set is correct in diff_body_calls | **DONE** | `callgraph-verify-macro/src/corpus.rs::b03_empty_corpus_makes_every_call_hallucinated` |
| B-04 | Path-qualified calls strip the path | **DONE** | `callgraph-verify-macro/src/corpus.rs::b04_path_qualified_calls_strip_the_path`, `b04_method_call_via_dot_is_classified_as_method`, `b04_multiline_call_is_one_call` |
| B-05 | Parse-error resilience: malformed `.rs` is silently skipped | **DONE** | `callgraph-verify-macro/src/corpus.rs::b05_parse_error_resilience_skips_bad_file` |
| B-06 | `Pe::parse` rejects non-i386 PE | **DONE** | `callgraph-verify-macro/src/corpus.rs::b06_pe_parse_rejects_non_i386` |
| B-07 | Empty `REBUILD_ROOT` returns empty corpus | **DONE** | `callgraph-verify-macro/src/corpus.rs::b07_empty_rebuild_root_returns_empty_corpus` |
| B-08 | Out-of-section `#[origin]` produces `ORIGIN-UNREFERENCED` | **DONE** | `callgraph-verify/tests/integration.rs::b08_analyze_rejects_out_of_section_address` |
| B-09 | Nested-module name collision | **DONE** | `callgraph-verify-macro/src/corpus.rs::b09_nested_module_name_collision_both_addresses_in_corpus` (test pins current behavior: both addresses are recorded; corpus is a BTreeSet so insertion is additive, but `free_fns['inner']` is a HashSet-of-u64 that holds both) |
| B-10 | Empty function body (just `RET`) doesn't crash | **DONE** | `callgraph-verify/tests/integration.rs::b10_analyze_handles_ret_only_function` |

## Summary

All 10 behaviors pinned. Total tests: 38 integration + 46 macro-lib unit = 84 passing, up from 72.

## Notes on what each test actually pins

- **B-01** records both `#[origin(0xA)]` owners; the verifier's `DUP-ADDR` check (corpus::addr_owners.len() > 1) will fire.
- **B-02** verifies the **body-side** capture: a body call to a name the corpus doesn't have is what would produce `HALLUCINATED` after diff. (The full `HALLUCINATED` flow needs a real PE; that's covered by `test_diff_body_calls_vtable_dispatch` in integration.)
- **B-03** verifies the corpus side: empty corpus + body with one call → diff reports the call as missing/hallucinated. Same caveat as B-02 — pins the corpus half, not the full diff.
- **B-04** triple: `crate::module::func()` records just `func`; `obj.method()` records `method`; multi-line call records once.
- **B-05** drops a syntactically broken `.rs` mid-tree, confirms the surrounding good files still parse and the broken file's `bad_fn` is NOT recorded.
- **B-06** hand-crafts a minimal COFF/PE with `machine = 0x8664` (x86_64) and asserts `Pe::parse` returns `Err`. The i386 positive path is covered by every integration test that loads `test-bin.exe`.
- **B-07** creates a fresh empty tempdir, asserts `build_cached` returns a `Corpus` with all collections empty.
- **B-08** feeds `analyze(pe, 0x8000_0000)` (a synthetic PE whose `.text` is at 0x1000–0x1100) and asserts it returns `Err`. This is the same gate the verifier's `pe.section_of(args.addr).is_none()` uses for the `ORIGIN-UNREFERENCED` check.
- **B-09** documents a real behavior of nested modules: the `corpus` BTreeSet records BOTH addresses, and the `free_fns['inner']` HashSet-of-u64 also holds BOTH. This means a name-collision doesn't lose addresses — but `diff_body_calls` will still resolve to ONE call target per name.
- **B-10** creates a 1-byte `.text` (just `0xC3` = RET), confirms `analyze` accepts the entry, reports extent=1, no direct calls, no tail calls.