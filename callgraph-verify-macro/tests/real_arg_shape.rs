//! Real-fixture ARG-SHAPE const-prop pins.
//!
//! The binary side is a genuine MSVC build (`c_callgraph_od.exe`): Od
//! `branch_caller` stages `PUSH 1` before `CALL leaf_add`, so the call site
//! recovers `stack = [Other, Imm(1)]` (see `c_od_call_site_recovers_pushed_
//! imm_arg` in `callgraph-verify`). The Rust side is a `let`-bound argument.
//! Before const-prop, `leaf_add(q, k)` classified `k` as `Other` (skipped),
//! so the mismatch fixture compiled clean; after, the `0x99` miss fires
//! E014 and the `1` match stays clean.
//!
//! The fixtures AND the expected `.stderr` are GENERATED from the live
//! manifest (VAs differ per toolchain build) into `tests/testdata/
//! real_arg_shape/` (gitignored, like all of `testdata/`), then driven
//! through trybuild. MSVC-only: MinGW stages stack args with MOV (see the
//! `c_od` test's toolchain note), so there is no `Imm(1)` ground truth to
//! diff against elsewhere — other toolchains skip. Generating the snapshot
//! keeps the pin immune to VA drift while staying exact: if E014 stops
//! firing, or its wording/span changes, trybuild fails loudly.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

fn fixtures_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("target")
        .join("fixtures")
}

fn parse_manifest(json: &Path) -> (BTreeMap<String, u64>, String) {
    let text = std::fs::read_to_string(json).expect("read od addrs manifest");
    let v: serde_json::Value =
        serde_json::from_str(&text).expect("parse od addrs manifest");
    let toolchain = v
        .get("toolchain")
        .and_then(|t| t.as_str())
        .unwrap_or("unknown")
        .to_string();
    let raw = v
        .get("symbols")
        .and_then(|s| s.as_object())
        .unwrap_or_else(|| panic!("manifest {} has no symbols map", json.display()));
    let mut addrs = BTreeMap::new();
    for (k, val) in raw {
        let s = val.as_str().unwrap_or_else(|| {
            panic!("bad VA {val:?} for {k} in {}", json.display())
        });
        let n = if let Some(h) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
            u64::from_str_radix(h, 16)
        } else {
            s.parse()
        }
        .unwrap_or_else(|_| panic!("bad VA {s:?} for {k} in {}", json.display()));
        addrs.insert(k.clone(), n);
    }
    (addrs, toolchain)
}

/// Generate the corpus + pass/fail fixtures from the live Od manifest.
/// Returns the two fixture paths. Idempotent — overwrites every run so a
/// fixture rebuild can never go stale silently.
fn setup_real_arg_shape(manifest_dir: &Path) -> (PathBuf, PathBuf) {
    let exe = std::env::var("CALLGRAPH_C_OD_EXE")
        .map(PathBuf::from)
        .unwrap_or_else(|_| fixtures_dir().join("c_callgraph_od.exe"));
    let json = std::env::var("CALLGRAPH_C_OD_ADDRS")
        .map(PathBuf::from)
        .unwrap_or_else(|_| fixtures_dir().join("c_callgraph_od_addrs.json"));
    if !exe.exists() || !json.exists() {
        if std::env::var("CALLGRAPH_REQUIRE_FIXTURES")
            .map(|v| v == "1")
            .unwrap_or(false)
        {
            panic!(
                "real ARG-SHAPE fixtures missing (REQUIRE=1): exe={} (exists={}), addrs={} (exists={}). Run test-fixtures/build_fixtures.py first.",
                exe.display(),
                exe.exists(),
                json.display(),
                json.exists()
            );
        }
        eprintln!(
            "skipping real ARG-SHAPE fixtures: {} or {} not present",
            exe.display(),
            json.display()
        );
        return (PathBuf::new(), PathBuf::new());
    }
    let (addrs, toolchain) = parse_manifest(&json);
    if toolchain != "msvc" {
        eprintln!(
            "skipping real ARG-SHAPE fixtures on {toolchain} (PUSH-imm ground truth is MSVC-only; see c_od_call_site_recovers_pushed_imm_arg)"
        );
        return (PathBuf::new(), PathBuf::new());
    }
    let bc = addrs.get("branch_caller").unwrap_or_else(|| {
        panic!("od manifest has no branch_caller");
    });
    let leaf = addrs.get("leaf_add").unwrap_or_else(|| {
        panic!("od manifest has no leaf_add");
    });

    let dir = manifest_dir.join("tests").join("testdata").join("real_arg_shape");
    let corpus_dir = dir.join("corpus");
    std::fs::create_dir_all(&corpus_dir).expect("create real_arg_shape corpus");
    // Partial corpus: exactly the origin under test + the spelled callee.
    // `leaf_const` (branch_caller's other edge) stays unported — the macro
    // notes it (UNPORTED-CALLS, stderr-only) instead of firing MISSING.
    std::fs::write(
        corpus_dir.join("lib.rs"),
        format!(
            "use callgraph_verify_macro::origin;\n\
             #[origin({bc:#010x})]\n\
             pub fn branch_caller_probe() {{}}\n\
             #[origin({leaf:#010x})]\n\
             #[allow(dead_code)]\n\
             pub fn leaf_add() {{}}\n"
        ),
    )
    .expect("write real_arg_shape corpus");
    let pass = dir.join("pass_let_arg.rs");
    std::fs::write(
        &pass,
        format!(
             "//! Real-fixture ARG-SHAPE pass: `let k = 1` must classify Imm(1),\n\
             //! matching the binary's `PUSH 1` at the Od branch_caller -> leaf_add site.\n\
             use callgraph_verify_macro::origin;\n\
             \n\
             #[origin({bc:#010x})]\n\
             pub fn f(_q: u32) {{\n\
             \x20   let k = 1;\n\
             \x20   leaf_add(_q, k);\n\
             }}\n\
             \n\
             #[allow(dead_code)]\n\
             fn leaf_add(_a: u32, _b: u32) {{}}\n\
             \n\
             fn main() {{}}\n"
        ),
    )
    .expect("write pass fixture");
    let fail = dir.join("fail_let_arg.rs");
    std::fs::write(
        &fail,
        format!(
            "//! Real-fixture ARG-SHAPE fail: `let k = 0x99` must classify Imm(0x99),\n\
             //! mismatching the binary's `PUSH 1` — E014 must fire (before const-prop\n\
             //! `k` was `Other` and this compiled clean).\n\
             use callgraph_verify_macro::origin;\n\
             \n\
             #[origin({bc:#010x})]\n\
             pub fn f(_q: u32) {{\n\
             \x20   let k = 0x99;\n\
             \x20   leaf_add(_q, k);\n\
             }}\n\
             \n\
             fn main() {{}}\n"
        ),
    )
    .expect("write fail fixture");
    // The expected `.stderr`, generated from the same live VAs (this keeps
    // the pin immune to manifest VA drift: a stale committed snapshot would
    // fail on any fixture rebuild with shifted addresses). The pin is still
    // exact — if E014 stops firing, or its wording/span changes, trybuild
    // fails loudly against this text.
    std::fs::write(
        dir.join("fail_let_arg.stderr"),
        format!(
            "error:   [CG-VERIFY-E014 ARG-SHAPE] `leaf_add` (→{leaf:#010x}) arg #1 is Imm(153), but the binary's call passes Imm(1)\n\
             \x20          -> fix: change arg #1 at this call site to match what the binary passes (or restructure the call if the binary's arg 1 is recovered from an ICF-folded stub — see lib.rs comment near arg_shape_check)\n\
             \x20--> tests/testdata/real_arg_shape/fail_let_arg.rs\n\
             \x20 |\n\
             \x20 |     leaf_add(_q, k);\n\
             \x20 |     ^^^^^^^^\n"
        ),
    )
    .expect("write fail stderr");
    // TARGET_EXE for the trybuild-spawned rustc invocations: the real Od PE.
    std::env::set_var("TARGET_EXE", exe.to_str().unwrap());
    std::env::set_var("REBUILD_ROOT", corpus_dir.to_str().unwrap());
    (pass, fail)
}

#[test]
fn real_arg_shape() {
    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let (pass, fail) = setup_real_arg_shape(&manifest_dir);
    if pass.as_os_str().is_empty() {
        return; // skipped (no fixture / non-MSVC) — see messages above
    }
    // The pass fixture must compile with ZERO gate diagnostics: the
    // `let k = 1` const must match the binary's Imm(1) (and the partial
    // corpus must not fire MISSING for the unported leaf_const edge).
    {
        let t = trybuild::TestCases::new();
        t.pass(pass.to_str().unwrap());
    }
    // The fail fixture must fire E014 (Imm(0x99) vs Imm(1)).
    {
        let t = trybuild::TestCases::new();
        t.compile_fail(fail.to_str().unwrap());
    }
}
