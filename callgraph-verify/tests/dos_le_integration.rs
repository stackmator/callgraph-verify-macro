//! DOS4GW LE integration tests: a REAL Watcom-built linear executable.
//!
//! `callgraph-verify/test-fixtures/dos/callgraph.c` is compiled by CI with
//! Open Watcom (`owcc -bdos4g`) to a 32-bit DOS/4GW LE binary and parsed by
//! `Pe::parse_le`. FALL.EXE — the motivating LE target — cannot be checked
//! into the repo, so this fixture is the only real-LE coverage the suite has.
//!
//! No address manifest: parsing wlink maps is fragile, so these tests
//! discover functions by SHAPE (callers, leaves, loops) instead of by name.
//! That is enough to pin the LE path: parsing, CFG walk, call harvesting,
//! the byte-scan gates, and the Spec HALLUCINATED/MISSING gates.
//!
//! Scope warning (mirrors `pe.rs`): LE fixups are NOT applied yet, so
//! absolute-address facts (globals, immediates, IAT) are pre-fixup bytes on
//! LE. These tests pin call edges, indirect counts, and CFG shape only —
//! never absolute VAs.
//!
//! Fixture discovery mirrors `c_cpp_integration.rs`: `$CALLGRAPH_DOS_EXE`
//! wins, else `<repo>/target/fixtures/dos_callgraph.exe`. Missing fixture
//! skips unless `CALLGRAPH_REQUIRE_FIXTURES=1` (set in CI), which fails.

use callgraph_verify::{analyze, cfg_fingerprint, diff_calls, has_direct_branch_target, Pe, Spec};
use std::path::PathBuf;

fn load_dos() -> Option<(PathBuf, Pe)> {
    let exe = std::env::var("CALLGRAPH_DOS_EXE")
        .map(PathBuf::from)
        .unwrap_or_else(|_| {
            PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                .join("..")
                .join("target")
                .join("fixtures")
                .join("dos_callgraph.exe")
        });
    if !exe.exists() {
        if std::env::var("CALLGRAPH_REQUIRE_FIXTURES")
            .map(|v| v == "1")
            .unwrap_or(false)
        {
            panic!(
                "DOS fixture missing (REQUIRE=1): {} not present. \
                 Install Open Watcom and run test-fixtures/build_fixtures.py",
                exe.display()
            );
        }
        eprintln!(
            "skipping DOS4GW LE tests: {} not present (need owcc -bdos4g; see test-fixtures/README.md)",
            exe.display()
        );
        return None;
    }
    let pe = Pe::load(exe.to_str().unwrap()).expect("load DOS LE fixture");
    Some((exe, pe))
}

/// Executable sections in VA order. `parse_le` names the first executable
/// object `.text` (later ones `.textN`), but matching on the characteristics
/// bits instead of the name keeps this test independent of that convention.
fn code_sections(pe: &Pe) -> Vec<(u64, u64)> {
    let mut secs: Vec<(u64, u64)> = pe
        .sections()
        .iter()
        .filter(|s| s.is_executable())
        .map(|s| {
            let start = pe.image_base + s.virtual_address as u64;
            (start, start + s.virtual_size.max(s.raw_size) as u64)
        })
        .collect();
    secs.sort();
    secs
}

/// Extent-skipping walk over every executable section, capped so a
/// CRT-heavy binary stays fast.
fn sweep_functions(pe: &Pe, cap: usize) -> Vec<u64> {
    let mut addrs = Vec::new();
    for (start, end) in code_sections(pe) {
        let mut va = start;
        while va < end {
            if let Ok(cg) = analyze(pe, va) {
                addrs.push(va);
                va = va.saturating_add(cg.max_end.saturating_sub(va).max(1));
            } else {
                va += 1;
            }
            if addrs.len() >= cap {
                return addrs;
            }
        }
    }
    addrs
}

#[test]
fn dos_le_parses_with_code_sections() {
    let Some((exe, pe)) = load_dos() else {
        return;
    };
    // LE images are identity-mapped: parse_le synthesizes image_base 0 with
    // object reloc bases as RVAs (a PE would carry 0x400000-style base).
    assert_eq!(
        pe.image_base, 0,
        "{}: expected LE identity base 0, got {:#x}",
        exe.display(),
        pe.image_base
    );
    assert!(
        !code_sections(&pe).is_empty(),
        "{}: no executable section found",
        exe.display()
    );
}

#[test]
fn dos_sweep_finds_real_functions() {
    let Some(_) = load_dos() else {
        return;
    };
    let (_, pe) = load_dos().unwrap();
    let addrs = sweep_functions(&pe, 512);
    // dos/callgraph.c alone defines 13 functions; Watcom startup adds more.
    assert!(
        addrs.len() >= 5,
        "sweep found only {} analyzable functions — LE parse or walk is broken",
        addrs.len()
    );
}

#[test]
fn dos_byte_scan_agrees_with_analyze() {
    let Some(_) = load_dos() else {
        return;
    };
    let (_, pe) = load_dos().unwrap();
    let addrs = sweep_functions(&pe, 512);
    let mut checked = 0u32;
    let mut disagreements = Vec::new();
    for caller in &addrs {
        if let Ok(cg) = analyze(&pe, *caller) {
            for &t in cg.direct_calls.keys() {
                checked += 1;
                if !has_direct_branch_target(&pe, t) {
                    disagreements.push((*caller, t));
                }
            }
        }
    }
    assert!(checked > 0, "sweep found no direct calls at all");
    assert!(
        disagreements.is_empty(),
        "{} of {checked} Watcom CALL targets disagree with the byte scan: {disagreements:?}",
        disagreements.len()
    );
}

#[test]
fn dos_diff_clean_when_declared_equals_real() {
    let Some(_) = load_dos() else {
        return;
    };
    let (_, pe) = load_dos().unwrap();
    let addrs = sweep_functions(&pe, 512);
    let mut total = 0u32;
    for caller in &addrs {
        if let Ok(cg) = analyze(&pe, *caller) {
            let real: Vec<u64> = cg.call_targets().into_iter().collect();
            let d = diff_calls(&pe, *caller, &real, true)
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
fn dos_spec_gates_on_discovered_caller() {
    let Some(_) = load_dos() else {
        return;
    };
    let (_, pe) = load_dos().unwrap();
    let addrs = sweep_functions(&pe, 512);
    // branch_caller makes two direct calls; any swept caller with >= 1
    // direct call exercises the same gates without needing its name.
    let caller = addrs
        .iter()
        .find(|a| {
            analyze(&pe, **a)
                .map(|cg| !cg.direct_calls.is_empty())
                .unwrap_or(false)
        })
        .copied()
        .expect("no caller found in Watcom binary");
    let cg = analyze(&pe, caller).unwrap();
    let real: Vec<u64> = cg.call_targets().into_iter().collect();

    Spec::new(caller)
        .calls_superset(&real)
        .check(&pe)
        .expect("superset of the real call set must pass");

    let mut with_fake = real.clone();
    with_fake.push(0xDEADBEEF);
    let err = Spec::new(caller)
        .calls_superset(&with_fake)
        .check(&pe)
        .expect_err("invented call must fail");
    assert!(err.contains("HALLUCINATED"), "error: {err}");

    let err = Spec::new(caller)
        .calls_exact(&[])
        .check(&pe)
        .expect_err("omitted real call must fail");
    assert!(err.contains("MISSING"), "error: {err}");
}

#[test]
fn dos_leaf_and_loop_exist() {
    let Some(_) = load_dos() else {
        return;
    };
    let (_, pe) = load_dos().unwrap();
    let addrs = sweep_functions(&pe, 512);
    let has_leaf = addrs.iter().any(|a| {
        analyze(&pe, *a)
            .map(|cg| cg.direct_calls.is_empty() && cg.indirect_calls == 0)
            .unwrap_or(false)
    });
    assert!(
        has_leaf,
        "no leaf function in Watcom binary (want e.g. leaf_const)"
    );
    let mut looped = Vec::new();
    for a in &addrs {
        if let Ok(fp) = cfg_fingerprint(&pe, *a) {
            if fp.loops >= 1 {
                looped.push(*a);
            }
        }
    }
    assert!(
        !looped.is_empty(),
        "no function with a loop back-edge (want e.g. loop_sum)"
    );
}

#[test]
fn dos_call_targets_are_referenced() {
    let Some(_) = load_dos() else {
        return;
    };
    let (_, pe) = load_dos().unwrap();
    // The ORIGIN-UNREFERENCED gate's accept set must contain every direct
    // call target — scoped to the first executable section so a hypothetical
    // multi-object layout (rel32 scan covers `.text` only) cannot false-fail.
    let (first_start, first_end) = code_sections(&pe)
        .into_iter()
        .next()
        .expect("no code section");
    let refs = pe.referenced_addrs();
    assert!(!refs.is_empty(), "referenced_addrs is empty on LE");
    let mut checked = 0u32;
    let mut missing = Vec::new();
    let mut va = first_start;
    while va < first_end {
        if let Ok(cg) = analyze(&pe, va) {
            for &t in cg.direct_calls.keys() {
                if (first_start..first_end).contains(&t) {
                    checked += 1;
                    if !refs.contains(&(t as u32)) {
                        missing.push(t);
                    }
                }
            }
            va = va.saturating_add(cg.max_end.saturating_sub(va).max(1));
        } else {
            va += 1;
        }
    }
    assert!(checked > 0, "no intra-section calls found");
    assert!(
        missing.is_empty(),
        "{} of {checked} LE call targets missing from referenced_addrs: {missing:#x?}",
        missing.len()
    );
}
