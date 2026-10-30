//! Real-fixture structural pins: E016 branchiness + recursion MISSING.
//!
//! The binary side is genuine MSVC output (`c_callgraph_od.exe`):
//! * `decision_chain` branches ~14 times while a single-`if` body has
//!   branchiness 1 — the tightened E016 third prong (≤1 instead of ==0)
//!   must fire. Before the tightening the lone `if` defeated the gate.
//! * `recurse_sum` directly CALLs itself — a body that drops the self-call
//!   must fire MISSING (self edges used to be excluded outright); a body
//!   that spells it stays clean.
//!
//! Fixtures AND expected `.stderr`s are generated from the live manifest
//! into gitignored `tests/testdata/real_structure/`, then driven through
//! trybuild. MSVC-only (Od codegen shapes); other toolchains skip.

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

fn va(addrs: &BTreeMap<String, u64>, name: &str) -> u64 {
    *addrs.get(name).unwrap_or_else(|| panic!("od manifest has no {name}"))
}

/// Generate the corpus + fixtures + expected `.stderr`s from the live Od
/// manifest. Returns the three fixture paths. Idempotent.
fn setup(manifest_dir: &Path) -> (PathBuf, PathBuf, PathBuf) {
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
                "real STRUCTURE fixtures missing (REQUIRE=1): exe={} (exists={}), addrs={} (exists={}). Run test-fixtures/build_fixtures.py first.",
                exe.display(),
                exe.exists(),
                json.display(),
                json.exists()
            );
        }
        eprintln!(
            "skipping real STRUCTURE fixtures: {} or {} not present",
            exe.display(),
            json.display()
        );
        return (PathBuf::new(), PathBuf::new(), PathBuf::new());
    }
    let (addrs, toolchain) = parse_manifest(&json);
    if toolchain != "msvc" {
        eprintln!("skipping real STRUCTURE fixtures on {toolchain} (Od ground truth is MSVC-only)");
        return (PathBuf::new(), PathBuf::new(), PathBuf::new());
    }
    let dc = va(&addrs, "decision_chain");
    let rs = va(&addrs, "recurse_sum");

    let dir = manifest_dir.join("tests").join("testdata").join("real_structure");
    let corpus_dir = dir.join("corpus");
    std::fs::create_dir_all(&corpus_dir).expect("create real_structure corpus");
    std::fs::write(
        corpus_dir.join("lib.rs"),
        format!(
            "use callgraph_verify_macro::origin;\n\
             #[origin({dc:#010x})]\n\
             pub fn decision_chain_probe() {{}}\n\
             #[origin({rs:#010x})]\n\
             pub fn recurse_sum() {{}}\n"
        ),
    )
    .expect("write real_structure corpus");

    let fail_thin = dir.join("fail_thin_body.rs");
    std::fs::write(
        &fail_thin,
        format!(
            "//! Real-fixture E016 fail: the Od decision_chain binary branches\n\
             //! ~14 times, but this single-`if` body has branchiness 1 — the\n\
             //! tightened third prong (<=1) must fire. Before the tightening\n\
             //! the lone `if` defeated the gate.\n\
             use callgraph_verify_macro::origin;\n\
             \n\
             #[origin({dc:#010x})]\n\
             pub fn f(_q: u32) -> i32 {{\n\
             \x20   if _q == 3 {{ 1 }} else {{ 2 }}\n\
             }}\n\
             \n\
             fn main() {{}}\n"
        ),
    )
    .expect("write fail_thin fixture");
    std::fs::write(
        dir.join("fail_thin_body.stderr"),
        format!(
            "error:   [CG-VERIFY-E016 CFG] binary branches heavily (14 conditionals) but the body has branchiness 1 (≤1 if/match/loop/&&/||)\n\
             \x20          -> fix: the body reproduces too few branches — re-check the binary's branch structure (cmp/test/jcc) and port the predicates\n\
             \x20--> tests/testdata/real_structure/fail_thin_body.rs\n\
             \x20 |\n\
             \x20 | pub fn f(_q: u32) -> i32 {{\n\
             \x20 |     ^^\n"
        ),
    )
    .expect("write fail_thin stderr");

    let fail_noself = dir.join("fail_noself.rs");
    std::fs::write(
        &fail_noself,
        format!(
            "//! Real-fixture MISSING fail (recursion): the Od recurse_sum binary\n\
             //! directly CALLs itself, but this body drops the self-call —\n\
             //! MISSING must fire. Before the self-edge check this compiled\n\
             //! clean (own addrs were excluded outright).\n\
             use callgraph_verify_macro::origin;\n\
             \n\
             #[origin({rs:#010x})]\n\
             pub fn recurse_sum(_q: i32) -> i32 {{\n\
             \x20   if _q <= 0 {{ 0 }} else {{ _q }}\n\
             }}\n\
             \n\
             fn main() {{}}\n"
        ),
    )
    .expect("write fail_noself fixture");
    std::fs::write(
        dir.join("fail_noself.stderr"),
        format!(
            "error:   [CG-VERIFY-E013 MISSING] binary calls `recurse_sum` ({rs:#010x}) — body doesn't\n\
             \x20          -> fix: add the call — the binary has a real CALL to {rs:#010x}, so the faithful body must spell it (or reproduce the callee's work inline, matching the binary)\n\
             \x20--> tests/testdata/real_structure/fail_noself.rs\n\
             \x20 |\n\
             \x20 | pub fn recurse_sum(_q: i32) -> i32 {{\n\
             \x20 |     ^^\n"
        ),
    )
    .expect("write fail_noself stderr");

    let pass_self = dir.join("pass_self.rs");
    std::fs::write(
        &pass_self,
        format!(
            "//! Real-fixture MISSING pass (recursion): the body spells the\n\
             //! self-call, so MISSING stays silent (false-positive guard).\n\
             use callgraph_verify_macro::origin;\n\
             \n\
             #[origin({rs:#010x})]\n\
             pub fn recurse_sum(_q: i32) -> i32 {{\n\
             \x20   if _q <= 0 {{ 0 }} else {{ recurse_sum(_q - 1) + _q }}\n\
             }}\n\
             \n\
             fn main() {{}}\n"
        ),
    )
    .expect("write pass_self fixture");

    std::env::set_var("TARGET_EXE", exe.to_str().unwrap());
    std::env::set_var("REBUILD_ROOT", corpus_dir.to_str().unwrap());
    (fail_thin, fail_noself, pass_self)
}

#[test]
fn real_structure() {
    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let (fail_thin, fail_noself, pass_self) = setup(&manifest_dir);
    if fail_thin.as_os_str().is_empty() {
        return; // skipped (no fixture / non-MSVC)
    }
    {
        let t = trybuild::TestCases::new();
        t.compile_fail(fail_thin.to_str().unwrap());
    }
    {
        let t = trybuild::TestCases::new();
        t.compile_fail(fail_noself.to_str().unwrap());
    }
    {
        let t = trybuild::TestCases::new();
        t.pass(pass_self.to_str().unwrap());
    }
}
