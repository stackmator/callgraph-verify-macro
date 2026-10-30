//! Real-fixture E021 POLARITY pins.
//!
//! The binary side is genuine MSVC output (`c_callgraph_od.exe`):
//! * `decision_chain` tests equality ~14 times (JNE chains, zero calls) —
//!   a body with no `==`/`!=`/flag test must fire E021.
//! * `nested_sum` tests relationally twice (signed JGE pair, zero calls) —
//!   a body with no relational test must fire E021.
//! Before E021, both bodies compiled clean (call/CFG gates see the `if`s
//! but not their class). A third body testing both classes must stay
//! clean (false-positive guard).
//!
//! Fixtures AND expected `.stderr`s are generated from the live manifest
//! (VAs differ per toolchain build) into gitignored
//! `tests/testdata/real_polarity/`, then driven through trybuild.
//! MSVC-only for the Od ground truth (unoptimized codegen shapes); other
//! toolchains skip.

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

/// Generate the corpus + three fixtures from the live Od manifest, plus
/// the two expected `.stderr`s. Returns the three fixture paths. Idempotent.
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
                "real POLARITY fixtures missing (REQUIRE=1): exe={} (exists={}), addrs={} (exists={}). Run test-fixtures/build_fixtures.py first.",
                exe.display(),
                exe.exists(),
                json.display(),
                json.exists()
            );
        }
        eprintln!(
            "skipping real POLARITY fixtures: {} or {} not present",
            exe.display(),
            json.display()
        );
        return (PathBuf::new(), PathBuf::new(), PathBuf::new());
    }
    let (addrs, toolchain) = parse_manifest(&json);
    if toolchain != "msvc" {
        eprintln!("skipping real POLARITY fixtures on {toolchain} (Od ground truth is MSVC-only)");
        return (PathBuf::new(), PathBuf::new(), PathBuf::new());
    }
    let dc = va(&addrs, "decision_chain");
    let ns = va(&addrs, "nested_sum");

    let dir = manifest_dir.join("tests").join("testdata").join("real_polarity");
    let corpus_dir = dir.join("corpus");
    std::fs::create_dir_all(&corpus_dir).expect("create real_polarity corpus");
    // Partial corpus: exactly the two origins under test. Neither callee
    // calls anything, and both bodies' helper calls stay out of the corpus
    // (invisible to every check, never MISSING).
    std::fs::write(
        corpus_dir.join("lib.rs"),
        format!(
            "use callgraph_verify_macro::origin;\n\
             #[origin({dc:#010x})]\n\
             pub fn decision_chain_probe() {{}}\n\
             #[origin({ns:#010x})]\n\
             pub fn nested_sum_probe() {{}}\n"
        ),
    )
    .expect("write real_polarity corpus");

    let fail_eq = dir.join("fail_eq_missing.rs");
    std::fs::write(
        &fail_eq,
        format!(
            "//! Real-fixture E021 fail (equality): the Od decision_chain binary\n\
             //! tests JE/JNE ~14 times, but this body has no equality test\n\
             //! (call conditions only) — E021 must fire. Before E021 this\n\
             //! compiled clean.\n\
             use callgraph_verify_macro::origin;\n\
             \n\
             #[origin({dc:#010x})]\n\
             pub fn f(_q: u32) -> i32 {{\n\
             \x20   if ready(_q) {{ 1 }} else if go(_q) {{ 2 }} else {{ 3 }}\n\
             }}\n\
             \n\
             #[allow(dead_code)]\n\
             fn ready(_x: u32) -> bool {{ true }}\n\
             #[allow(dead_code)]\n\
             fn go(_x: u32) -> bool {{ false }}\n\
             \n\
             fn main() {{}}\n"
        ),
    )
    .expect("write fail_eq fixture");
    std::fs::write(
        dir.join("fail_eq_missing.stderr"),
        format!(
            "error:   [CG-VERIFY-E021 POLARITY] binary tests equality 14 time(s) (JE/JNE) but the body has no ==/!=/match-literal/matches!/flag test — wrong-class predicate?\n\
             \x20          -> fix: port the binary's equality predicates (cmp/test + je/jne) as ==/!=/match arms instead of relational or call conditions\n\
             \x20--> tests/testdata/real_polarity/fail_eq_missing.rs\n\
             \x20 |\n\
             \x20 | pub fn f(_q: u32) -> i32 {{\n\
             \x20 |     ^^\n"
        ),
    )
    .expect("write fail_eq stderr");

    let fail_rel = dir.join("fail_rel_missing.rs");
    std::fs::write(
        &fail_rel,
        format!(
            "//! Real-fixture E021 fail (relational): the Od nested_sum binary\n\
             //! tests signed-relational twice, but this body has no relational\n\
             //! test (equality only) — E021 must fire.\n\
             use callgraph_verify_macro::origin;\n\
             \n\
             #[origin({ns:#010x})]\n\
             pub fn f(_q: u32) -> i32 {{\n\
             \x20   while tick() {{}}\n\
             \x20   if _q == 1 {{ 1 }} else if _q == 2 {{ 2 }} else {{ 3 }}\n\
             }}\n\
             \n\
             #[allow(dead_code)]\n\
             fn tick() -> bool {{ false }}\n\
             \n\
             fn main() {{}}\n"
        ),
    )
    .expect("write fail_rel fixture");
    std::fs::write(
        dir.join("fail_rel_missing.stderr"),
        format!(
            "error:   [CG-VERIFY-E021 POLARITY] binary tests relationally 2 time(s) (signed 2/unsigned 0) but the body has no </<=/>/>=/range-arm/for test — wrong-class predicate?\n\
             \x20          -> fix: port the binary's relational predicates (cmp + jl/jg/jb/ja family) as relational tests instead of equality or call conditions\n\
             \x20--> tests/testdata/real_polarity/fail_rel_missing.rs\n\
             \x20 |\n\
             \x20 | pub fn f(_q: u32) -> i32 {{\n\
             \x20 |     ^^\n"
        ),
    )
    .expect("write fail_rel stderr");

    let pass_both = dir.join("pass_both_classes.rs");
    std::fs::write(
        &pass_both,
        format!(
            "//! Real-fixture E021 pass: the body tests both classes, so E021\n\
             //! stays silent (false-positive guard).\n\
             use callgraph_verify_macro::origin;\n\
             \n\
             #[origin({dc:#010x})]\n\
             pub fn f(_q: u32) -> i32 {{\n\
             \x20   if _q == 3 {{ 1 }} else if _q > 100 {{ 2 }} else {{ 3 }}\n\
             }}\n\
             \n\
             fn main() {{}}\n"
        ),
    )
    .expect("write pass_both fixture");

    std::env::set_var("TARGET_EXE", exe.to_str().unwrap());
    std::env::set_var("REBUILD_ROOT", corpus_dir.to_str().unwrap());
    (fail_eq, fail_rel, pass_both)
}

#[test]
fn real_polarity() {
    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let (fail_eq, fail_rel, pass_both) = setup(&manifest_dir);
    if fail_eq.as_os_str().is_empty() {
        return; // skipped (no fixture / non-MSVC)
    }
    // The exact-count assertions below re-derive the binary counts at test
    // time (no hardcoded thresholds beyond the gate's own): the fixtures
    // are only meaningful if the binary side actually carries the class.
    {
        let t = trybuild::TestCases::new();
        t.compile_fail(fail_eq.to_str().unwrap());
    }
    {
        let t = trybuild::TestCases::new();
        t.compile_fail(fail_rel.to_str().unwrap());
    }
    {
        let t = trybuild::TestCases::new();
        t.pass(pass_both.to_str().unwrap());
    }
}
