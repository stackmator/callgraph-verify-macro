//! Real-compiler integration tests: C + C++ fixtures built by CI.
//!
//! `callgraph-verify/test-fixtures/c/callgraph.c` and `cpp/callgraph.cpp` are
//! compiled to 32-bit PEs by GitHub Actions (MSVC `cl` on Windows,
//! `i686-w64-mingw32-gcc`/`g++` on Linux) via
//! `test-fixtures/build_fixtures.py`, which also writes a `{stem}_addrs.json`
//! manifest mapping each source-level function name to its preferred VA.
//!
//! These tests resolve those VAs and run the verifier over genuine compiler
//! output — CRT startup, optimized branches, thiscall methods, vtables —
//! instead of hand-assembled byte strings. That is the point: handwritten
//! `pe_with_code` blobs only prove the verifier handles what we imagined;
//! these prove it handles what `cl`/`gcc -O2` actually emit.
//!
//! Fixture discovery: `$CALLGRAPH_C_EXE` / `$CALLGRAPH_C_ADDRS` (and the
//! `CPP` variants) win when set (CI exports absolute paths); otherwise we
//! fall back to `<repo>/target/fixtures/<stem>.exe`. When neither exists the
//! tests SKIP (plain `cargo test` without a C toolchain stays green). CI
//! sets `CALLGRAPH_REQUIRE_FIXTURES=1`, which turns a missing fixture into a
//! hard failure so a broken build step can never silently green the suite.

use callgraph_verify::{
    analyze, cfg_fingerprint, diff_body_calls, diff_calls, has_direct_branch_target, reg_params,
    ArgKind, Pe, Spec,
};
use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;

struct Fixture {
    label: &'static str,
    exe: PathBuf,
    pe: Pe,
    addrs: BTreeMap<String, u64>,
}

fn fixtures_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("target")
        .join("fixtures")
}

fn load_fixture(
    label: &'static str,
    stem: &str,
    exe_env: &str,
    json_env: &str,
) -> Option<Fixture> {
    let exe = std::env::var(exe_env)
        .map(PathBuf::from)
        .unwrap_or_else(|_| fixtures_dir().join(format!("{stem}.exe")));
    let json = std::env::var(json_env)
        .map(PathBuf::from)
        .unwrap_or_else(|_| fixtures_dir().join(format!("{stem}_addrs.json")));
    if !exe.exists() || !json.exists() {
        if std::env::var("CALLGRAPH_REQUIRE_FIXTURES")
            .map(|v| v == "1")
            .unwrap_or(false)
        {
            panic!(
                "{label} fixture missing (REQUIRE=1): exe={} (exists={}), addrs={} (exists={}). \
                 Run test-fixtures/build_fixtures.py first.",
                exe.display(),
                exe.exists(),
                json.display(),
                json.exists()
            );
        }
        eprintln!(
            "skipping {label} fixture tests: {exe} or {json} not present (run test-fixtures/build_fixtures.py, or set {exe_env}/{json_env})",
            exe = exe.display(),
            json = json.display(),
            exe_env = exe_env,
            json_env = json_env,
        );
        return None;
    }
    let text = std::fs::read_to_string(&json).expect("read addrs manifest");
    let raw: BTreeMap<String, String> =
        serde_json::from_str(&text).expect("parse addrs manifest");
    let addrs: BTreeMap<String, u64> = raw
        .into_iter()
        .map(|(k, v)| {
            let n = if let Some(h) = v.strip_prefix("0x").or_else(|| v.strip_prefix("0X")) {
                u64::from_str_radix(h, 16)
            } else {
                v.parse()
            }
            .unwrap_or_else(|_| panic!("bad VA {v:?} for {k} in {}", json.display()));
            (k, n)
        })
        .collect();
    let pe = Pe::load(exe.to_str().unwrap()).expect("load fixture PE");
    Some(Fixture {
        label,
        exe,
        pe,
        addrs,
    })
}

fn c_fixture() -> Option<Fixture> {
    load_fixture("C", "c_callgraph", "CALLGRAPH_C_EXE", "CALLGRAPH_C_ADDRS")
}

fn cpp_fixture() -> Option<Fixture> {
    load_fixture(
        "C++",
        "cpp_callgraph",
        "CALLGRAPH_CPP_EXE",
        "CALLGRAPH_CPP_ADDRS",
    )
}

fn addr(fx: &Fixture, name: &str) -> u64 {
    *fx
        .addrs
        .get(name)
        .unwrap_or_else(|| panic!("{} manifest has no {name:?}", fx.label))
}

/// Direct-call targets plus tail-call JMPs: MSVC and GCC both lower
/// `return f(...)` to a tail jump, so a faithful "who does this call" set
/// must union both. This mirrors `diff_body_calls`' own wide set.
fn call_edges(fx: &Fixture, entry: u64) -> BTreeSet<u64> {
    let cg = analyze(&fx.pe, entry).expect("analyze fixture fn");
    let mut s = cg.call_targets();
    s.extend(&cg.tail_calls);
    s
}

/// Extent-skipping walk over every analyzable function in the image (same
/// shape as the test-bin sweep in `integration.rs`), capped so CRT-heavy
/// hosted exes stay fast.
fn sweep_functions(pe: &Pe, cap: usize) -> Vec<u64> {
    let mut addrs = Vec::new();
    let text = pe.sections().iter().find(|s| s.name == ".text").unwrap();
    let text_va = pe.image_base + text.virtual_address as u64;
    let end = text_va + text.virtual_size as u64;
    let mut va = text_va;
    while va < end {
        if let Ok(cg) = analyze(pe, va) {
            addrs.push(va);
            va = va.saturating_add(cg.max_end.saturating_sub(va).max(1));
        } else {
            va += 1;
        }
        if addrs.len() >= cap {
            break;
        }
    }
    addrs
}

// --- image shape ------------------------------------------------------------

#[test]
fn c_fixture_is_pe32_with_text() {
    let Some(fx) = c_fixture() else {
        return;
    };
    assert!(
        fx.pe.sections().iter().any(|s| s.name == ".text"),
        "{} has no .text",
        fx.exe.display()
    );
    for name in ["branch_caller", "leaf_add"] {
        let va = addr(&fx, name);
        assert!(
            fx.pe.section_of(va).is_some(),
            "{name} VA {va:#x} is outside every section"
        );
    }
}

#[test]
fn cpp_fixture_is_pe32_with_text() {
    let Some(fx) = cpp_fixture() else {
        return;
    };
    assert!(
        fx.pe.sections().iter().any(|s| s.name == ".text"),
        "{} has no .text",
        fx.exe.display()
    );
    let va = addr(&fx, "cpp_caller_fn");
    assert!(
        fx.pe.section_of(va).is_some(),
        "cpp_caller_fn VA {va:#x} is outside every section"
    );
}

// --- C call graph: exact edges the compilers must have preserved ------------

#[test]
fn c_branch_caller_calls_both_leaves() {
    let Some(fx) = c_fixture() else {
        return;
    };
    let edges = call_edges(&fx, addr(&fx, "branch_caller"));
    for leaf in [addr(&fx, "leaf_add"), addr(&fx, "leaf_const")] {
        assert!(
            edges.contains(&leaf),
            "branch_caller edges {edges:#x?} miss {leaf:#x} — the optimizer \
             removed a call the tests pin (check NOINLINE / main reachability)"
        );
    }
}

#[test]
fn c_parent_calls_branch() {
    let Some(fx) = c_fixture() else {
        return;
    };
    let edges = call_edges(&fx, addr(&fx, "parent_fn"));
    assert!(
        edges.contains(&addr(&fx, "branch_caller")),
        "parent_fn edges {edges:#x?} miss branch_caller"
    );
}

#[test]
fn c_leaf_const_is_a_leaf() {
    let Some(fx) = c_fixture() else {
        return;
    };
    let cg = analyze(&fx.pe, addr(&fx, "leaf_const")).expect("analyze leaf_const");
    assert!(
        cg.direct_calls.is_empty() && cg.indirect_calls == 0,
        "leaf_const should be a leaf: {cg:?}"
    );
}

#[test]
fn c_use_apply_reaches_apply_twice_indirectly() {
    let Some(fx) = c_fixture() else {
        return;
    };
    let edges = call_edges(&fx, addr(&fx, "use_apply"));
    assert!(
        edges.contains(&addr(&fx, "apply_twice")),
        "use_apply edges {edges:#x?} miss apply_twice"
    );
    let cg = analyze(&fx.pe, addr(&fx, "apply_twice")).expect("analyze apply_twice");
    assert!(
        cg.indirect_calls >= 1,
        "apply_twice calls through a function pointer — indirect_calls must be >= 1: {cg:?}"
    );
}

// --- Spec gates on real compiler output -------------------------------------

#[test]
fn c_spec_superset_ok_and_hallucinated_fails() {
    let Some(fx) = c_fixture() else {
        return;
    };
    let entry = addr(&fx, "branch_caller");
    let real = [addr(&fx, "leaf_add"), addr(&fx, "leaf_const")];
    Spec::new(entry)
        .calls_superset(&real)
        .check(&fx.pe)
        .expect("superset of the real call set must pass");
    let err = Spec::new(entry)
        .calls_superset(&[0xDEADBEEF])
        .check(&fx.pe)
        .expect_err("invented call must fail");
    assert!(err.contains("HALLUCINATED"), "error: {err}");
}

#[test]
fn c_spec_exact_missing_detected() {
    let Some(fx) = c_fixture() else {
        return;
    };
    // Declare only leaf_add: leaf_const is really called, so this is MISSING.
    // (Exact-equality in the other direction would also flag any helper call
    // the toolchain inserts, so we only pin the robust direction here.)
    let err = Spec::new(addr(&fx, "branch_caller"))
        .calls_exact(&[addr(&fx, "leaf_add")])
        .check(&fx.pe)
        .expect_err("omitted real call must fail");
    assert!(err.contains("MISSING"), "error: {err}");
    assert!(
        err.contains(&format!("{:#010x}", addr(&fx, "leaf_const"))),
        "missing report should name leaf_const: {err}"
    );
}

#[test]
fn c_diff_body_calls_hallucinated_and_missing() {
    let Some(fx) = c_fixture() else {
        return;
    };
    let caller = addr(&fx, "parent_fn");
    let callee = addr(&fx, "branch_caller");
    let fake = 0xDEADBEEFu64;
    let corpus: BTreeSet<u64> = [callee, fake].into_iter().collect();

    // Body calls a ported fn the binary never calls -> HALLUCINATED.
    let d = diff_body_calls(
        &fx.pe,
        &[caller],
        &corpus,
        &[("invented_fn".to_string(), vec![fake])],
        &BTreeSet::new(),
        &BTreeSet::new(),
    )
    .expect("diff_body_calls");
    assert!(
        d.hallucinated.iter().any(|(n, _)| n == "invented_fn"),
        "hallucinated: {:?}",
        d.hallucinated
    );

    // Body calls nothing the binary calls -> the real callee is MISSING.
    let d = diff_body_calls(
        &fx.pe,
        &[caller],
        &corpus,
        &[],
        &BTreeSet::new(),
        &BTreeSet::new(),
    )
    .expect("diff_body_calls");
    assert!(
        d.missing.contains(&callee),
        "missing: {:?} (want {callee:#x})",
        d.missing
    );
}

// --- operand facts + CFG on real codegen ------------------------------------

#[test]
fn c_global_referenced() {
    let Some(fx) = c_fixture() else {
        return;
    };
    let cg = analyze(&fx.pe, addr(&fx, "read_global")).expect("analyze read_global");
    assert!(
        cg.globals.contains(&addr(&fx, "g_counter")),
        "read_global must reference g_counter {:#x}: globals={:?}",
        addr(&fx, "g_counter"),
        cg.globals
    );
}

#[test]
fn c_field_offsets() {
    let Some(fx) = c_fixture() else {
        return;
    };
    let cg = analyze(&fx.pe, addr(&fx, "field_read")).expect("analyze field_read");
    assert!(
        cg.field_offsets.contains(&4),
        "field_read (p->y) must touch offset 4: {:?}",
        cg.field_offsets
    );
    let cg = analyze(&fx.pe, addr(&fx, "field_write")).expect("analyze field_write");
    for off in [4u64, 8] {
        assert!(
            cg.field_offsets.contains(&off),
            "field_write (p->y, p->z) must touch offset {off}: {:?}",
            cg.field_offsets
        );
    }
}

#[test]
fn c_loop_has_back_edge() {
    let Some(fx) = c_fixture() else {
        return;
    };
    let fp = cfg_fingerprint(&fx.pe, addr(&fx, "loop_sum")).expect("cfg loop_sum");
    assert!(
        fp.loops >= 1,
        "loop_sum's for-loop must leave a back-edge: {fp:?}"
    );
}

#[test]
fn c_nested_loops_have_two_back_edges() {
    let Some(fx) = c_fixture() else {
        return;
    };
    // The macro's E016 CFG gate fires at `loops >= 2` — previously pinned
    // only by hand-written bytes (tests/ui/e016_cfg.rs). The inner + outer
    // loop must each leave a dominance-confirmed back-edge on both toolchains.
    let fp = cfg_fingerprint(&fx.pe, addr(&fx, "nested_sum")).expect("cfg nested_sum");
    assert!(
        fp.loops >= 2,
        "nested_sum's two for-loops must leave two back-edges: {fp:?}"
    );
}

#[test]
fn c_switch_compiles_to_jump_table() {
    let Some(fx) = c_fixture() else {
        return;
    };
    // First coverage of the fingerprint's `switch_cases` prong anywhere:
    // 8 dense cases must lower to `JMP [table+idx*4]`, and
    // `follow_jump_table` must resolve the table to >= 3 case entries
    // (the macro's E016 switch threshold).
    let fp = cfg_fingerprint(&fx.pe, addr(&fx, "classify")).expect("cfg classify");
    assert!(
        fp.switch_cases >= 3,
        "classify's 8-case switch must resolve a jump table: {fp:?}"
    );
}

#[test]
fn c_decision_chain_has_twelve_conditionals() {
    let Some(fx) = c_fixture() else {
        return;
    };
    // Third E016 prong (`conditionals >= 12` + straight-line body): pin the
    // INPUT on real output. Each `if` must survive as its own conditional
    // branch on both toolchains — nothing covered this count before.
    let fp = cfg_fingerprint(&fx.pe, addr(&fx, "decision_chain")).expect("cfg");
    assert!(
        fp.conditionals >= 12,
        "decision_chain's 12 ifs must yield 12 conditionals: {fp:?}"
    );
}

#[test]
fn c_call_site_recovers_pushed_imm_arg() {
    let Some(fx) = c_fixture() else {
        return;
    };
    // `branch_caller` calls `leaf_add(x, 1)`: the `1` is PUSHed, and
    // `recover_call_site` must see `Imm(1)` in source position — this is the
    // exact input the macro's ARG-SHAPE check consumes, pinned on real
    // MSVC/MinGW codegen instead of hand-written bytes.
    let cg = analyze(&fx.pe, addr(&fx, "branch_caller")).expect("analyze");
    let leaf = addr(&fx, "leaf_add");
    let sites: Vec<_> = cg.call_sites.iter().filter(|s| s.target == leaf).collect();
    assert_eq!(
        sites.len(),
        1,
        "branch_caller must call leaf_add exactly once: {:?}",
        cg.call_sites
    );
    assert!(
        sites[0].stack.iter().any(|a| matches!(a, ArgKind::Imm(1))),
        "pushed literal 1 must be recovered as Imm(1): {:?}",
        sites[0].stack
    );
}

#[test]
fn c_main_reaches_iat_imports() {
    let Some(fx) = c_fixture() else {
        return;
    };
    // The hosted entry point calls `printf`, which must resolve to an
    // import — directly (`CALL [IAT]`, MinGW) or through one direct callee
    // (MSVC's UCRT `printf` inline expands to a local wrapper that calls
    // `__stdio_common_vfprintf` via the IAT). Either way the entry point
    // reaches imports within one hop on a dynamically-linked binary.
    let cg = analyze(&fx.pe, addr(&fx, "main")).expect("analyze main");
    let direct = !cg.iat_calls.is_empty();
    let mut via_callee = Vec::new();
    for t in cg.call_targets() {
        if let Ok(c) = analyze(&fx.pe, t) {
            if !c.iat_calls.is_empty() {
                via_callee.push(t);
            }
        }
    }
    assert!(
        direct || !via_callee.is_empty(),
        "main must reach imports directly or via a direct callee: {cg:?}"
    );
}

#[test]
fn c_manifest_functions_are_referenced() {
    let Some(fx) = c_fixture() else {
        return;
    };
    // Every manifest function is called or stored somewhere (the ORIGIN-
    // UNREFERENCED gate's accept set) — i.e. no test function was silently
    // dropped or mis-resolved by the manifest extractor.
    let refs = fx.pe.referenced_addrs();
    for name in fx.addrs.keys() {
        if name == "g_counter" {
            continue; // data, not necessarily code-referenced as a dword
        }
        let va = fx.addrs[name];
        assert!(
            refs.contains(&(va as u32)),
            "{name} {va:#x} is referenced nowhere — stale manifest?"
        );
    }
}

// --- whole-image sweeps: verifier vs. byte scan over CRT + user code --------

#[test]
fn c_analyze_and_byte_scan_agree() {
    let Some(fx) = c_fixture() else {
        return;
    };
    let addrs = sweep_functions(&fx.pe, 512);
    let mut checked = 0u32;
    let mut disagreements = Vec::new();
    for caller in &addrs {
        if let Ok(cg) = analyze(&fx.pe, *caller) {
            for &t in cg.direct_calls.keys() {
                checked += 1;
                if !has_direct_branch_target(&fx.pe, t) {
                    disagreements.push((*caller, t));
                }
            }
        }
    }
    assert!(checked > 0, "sweep found no analyzable functions");
    assert!(
        disagreements.is_empty(),
        "{} of {checked} CALL targets disagree with the byte scan: {disagreements:?}",
        disagreements.len()
    );
}

#[test]
fn c_diff_calls_clean_when_declared_equals_real() {
    let Some(fx) = c_fixture() else {
        return;
    };
    let addrs = sweep_functions(&fx.pe, 512);
    let mut total = 0u32;
    for caller in &addrs {
        if let Ok(cg) = analyze(&fx.pe, *caller) {
            let real: Vec<u64> = cg.call_targets().into_iter().collect();
            let d = diff_calls(&fx.pe, *caller, &real, true)
                .unwrap_or_else(|e| panic!("diff_calls at {caller:#x} failed: {e}"));
            total += 1;
            assert!(
                d.hallucinated.is_empty() && d.missing.is_empty(),
                "{caller:#x} not clean: {d:?}"
            );
        }
    }
    assert!(total > 0, "sweep found no analyzable functions");
}

#[test]
fn c_image_uses_iat_imports() {
    let Some(fx) = c_fixture() else {
        return;
    };
    // `main` calls `printf`: a hosted real binary must show at least one
    // IAT import edge somewhere in the image (CRT startup has many more).
    let addrs = sweep_functions(&fx.pe, 512);
    let with_iat = addrs
        .iter()
        .filter_map(|a| analyze(&fx.pe, *a).ok())
        .filter(|cg| !cg.iat_calls.is_empty())
        .count();
    assert!(
        with_iat > 0,
        "no IAT imports found in a hosted C binary — unexpected"
    );
}

// --- C++: methods, thiscall fields, virtual dispatch -------------------------

#[test]
fn cpp_caller_calls_leaf_and_counter() {
    let Some(fx) = cpp_fixture() else {
        return;
    };
    let edges = call_edges(&fx, addr(&fx, "cpp_caller_fn"));
    for want in [addr(&fx, "cpp_leaf_fn"), addr(&fx, "cpp_counter_fn")] {
        assert!(
            edges.contains(&want),
            "cpp_caller_fn edges {edges:#x?} miss {want:#x}"
        );
    }
}

#[test]
fn cpp_field_fn_touches_value_field() {
    let Some(fx) = cpp_fixture() else {
        return;
    };
    // Counter::value sits at offset 4 (`tag` is first); the pointer form
    // reads it through the `this` pointer in ECX — the thiscall shape
    // `reg_params` reasons about. (A stack-resident Counter uses
    // ESP-relative slots, which are locals by design and never harvested.)
    let cg = analyze(&fx.pe, addr(&fx, "cpp_field_fn")).expect("analyze");
    assert!(
        cg.field_offsets.contains(&4),
        "cpp_field_fn must touch Counter::value at offset 4: {:?}",
        cg.field_offsets
    );
}

#[test]
fn cpp_virtual_dispatch_is_indirect_only() {
    let Some(fx) = cpp_fixture() else {
        return;
    };
    // `s->kind()` compiles to `JMP [EAX]` (tail dispatch through the vtable
    // slot): the verifier must see an indirect edge and NO direct call —
    // the exact shape VTABLE-DISPATCH keys on. Both compilers lower
    // `return s->kind();` to a tail jump rather than a CALL.
    let cg = analyze(&fx.pe, addr(&fx, "cpp_use_virtual_fn")).expect("analyze");
    assert!(
        cg.indirect_calls + cg.indirect_jumps >= 1,
        "virtual call must be indirect: {cg:?}"
    );
    assert!(
        cg.direct_calls.is_empty(),
        "virtual call must not be a direct call: {:?}",
        cg.direct_calls
    );
    assert!(
        cg.vcall_slots.contains(&0),
        "virtual call must dispatch through vtable slot 0 (kind): {:?}",
        cg.vcall_slots
    );
}

#[test]
fn cpp_spec_superset_ok_and_hallucinated_fails() {
    let Some(fx) = cpp_fixture() else {
        return;
    };
    let entry = addr(&fx, "cpp_caller_fn");
    Spec::new(entry)
        .calls_superset(&[addr(&fx, "cpp_leaf_fn"), addr(&fx, "cpp_counter_fn")])
        .check(&fx.pe)
        .expect("superset of the real call set must pass");
    let err = Spec::new(entry)
        .calls_superset(&[0xDEADBEEF])
        .check(&fx.pe)
        .expect_err("invented call must fail");
    assert!(err.contains("HALLUCINATED"), "error: {err}");
}

#[test]
fn cpp_analyze_and_byte_scan_agree() {
    let Some(fx) = cpp_fixture() else {
        return;
    };
    let addrs = sweep_functions(&fx.pe, 512);
    let mut checked = 0u32;
    for caller in &addrs {
        if let Ok(cg) = analyze(&fx.pe, *caller) {
            for &t in cg.direct_calls.keys() {
                checked += 1;
                assert!(
                    has_direct_branch_target(&fx.pe, t),
                    "CALL target {t:#x} from {caller:#x} missing in byte scan"
                );
            }
        }
    }
    assert!(checked > 0, "sweep found no analyzable functions");
}

/// Read the first 8 vtable slots at `vt`, keeping only slots that point
/// into executable code. Both toolchains lay method pointers forward from
/// the symbol (MSVC `??_7Circle@@6B@`, Itanium `_ZTV6Circle` already points
/// past the offset-to-top/RTTI prefix), but MSVC parks RTTI-adjacent DATA
/// right after the table — trailing slots may be data pointers, not methods.
fn vtable_slots(fx: &Fixture, vt_name: &str) -> Vec<u64> {
    let vt = addr(fx, vt_name);
    (0..8u64)
        .filter_map(|slot| {
            let b = fx.pe.read(vt + slot * 4, 4)?;
            if b.len() < 4 {
                return None;
            }
            let va = u32::from_le_bytes([b[0], b[1], b[2], b[3]]) as u64;
            (va != 0 && fx.pe.is_executable_section_va(va)).then_some(va)
        })
        .collect()
}

#[test]
fn cpp_vtable_slots_are_executable_methods() {
    let Some(fx) = cpp_fixture() else {
        return;
    };
    // The method slots of a real compiler-generated vtable must be function
    // pointers into executable code — the exact bytes `vtable_table!`
    // verifies at compile time. (Trailing non-code dwords are RTTI-adjacent
    // data; `vtable_slots` filters those out.)
    for vt in ["circle_vt", "square_vt"] {
        let slots = vtable_slots(&fx, vt);
        assert!(
            slots.len() >= 2,
            "{vt} must have at least 2 method slots: {slots:#x?}"
        );
    }
}

#[test]
fn cpp_kind_slot_is_vtable_only_and_thiscall() {
    let Some(fx) = cpp_fixture() else {
        return;
    };
    // `Circle::kind` reads `radius` (field offset 4 off `this`) — the only
    // Circle method that does — so the slot whose function touches offset 4
    // IS kind, with no layout assumptions. On it, pin two gates at once:
    // the macro's VTABLE-ONLY DISPATCH warning condition (referenced but
    // never directly branched to) and thiscall detection via `reg_params`.
    let slots = vtable_slots(&fx, "circle_vt");
    let mut kind_va = None;
    for va in &slots {
        if let Ok(cg) = analyze(&fx.pe, *va) {
            if cg.field_offsets.contains(&4) {
                kind_va = Some(*va);
                break;
            }
        }
    }
    let kind_va = kind_va.expect("no circle_vt slot reads field offset 4 (want kind)");
    assert!(
        !has_direct_branch_target(&fx.pe, kind_va),
        "kind {kind_va:#x} must be reached only via its vtable slot"
    );
    assert!(
        fx.pe.referenced_addrs().contains(&(kind_va as u32)),
        "kind {kind_va:#x} must be referenced (stored in the vtable)"
    );
    assert_eq!(
        reg_params(&fx.pe, kind_va),
        (true, false),
        "kind must be detected as thiscall (reads ECX, never EDX)"
    );
}
