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
//! Scope note (mirrors `pe.rs`): direct CALL rel32 (the call graph) is
//! fixup-independent, but absolute-address facts (globals, immediates) are
//! pre-fixup bytes on LE — with post-fixup images accepted wherever a 07
//! record maps them (`Pe::fixup_post_images`). Most tests pin call edges,
//! indirect counts, and CFG shape only; `dos_fixup_post_images_accepted`
//! pins the widening itself on real Watcom output.
//!
//! Fixture discovery mirrors `c_cpp_integration.rs`: `$CALLGRAPH_DOS_EXE`
//! wins, else `<repo>/target/fixtures/dos_callgraph.exe`. Missing fixture
//! skips — EVEN under `CALLGRAPH_REQUIRE_FIXTURES=1`. The DOS toolchain
//! (Open Watcom) is installed on the ubuntu CI job only, so requiring the
//! fixture everywhere would red the Windows job for a toolchain it can
//! never have; the ubuntu job is the DOS gate. Same precedent as the
//! MSVC-only ILT-thunk fixture in the other direction.

use callgraph_verify::{
    analyze, cfg_fingerprint, diff_calls, has_direct_branch_target, FixupStatus, Pe, Spec,
};
use std::collections::BTreeSet;
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
        // NOTE: deliberately exempt from CALLGRAPH_REQUIRE_FIXTURES (see
        // header): Watcom lives on the ubuntu job only.
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
fn dos_nested_loops_have_two_back_edges() {
    let Some(_) = load_dos() else {
        return;
    };
    let (_, pe) = load_dos().unwrap();
    // Back-edges are rel32-based, hence fixup-independent: safe to pin on LE.
    let addrs = sweep_functions(&pe, 512);
    let mut best = 0usize;
    for a in &addrs {
        if let Ok(fp) = cfg_fingerprint(&pe, *a) {
            best = best.max(fp.loops);
        }
    }
    assert!(
        best >= 2,
        "no swept LE function has two loop back-edges (want nested_sum); max loops = {best}"
    );
}

#[test]
fn dos_switch_table_resolves() {
    let Some(_) = load_dos() else {
        return;
    };
    let (_, pe) = load_dos().unwrap();
    // Watcom lowers the dense 8-case `classify` switch to control flow;
    // `follow_jump_table` must resolve >= 3 case entries if it emits a
    // table (compare chains satisfy the conditionals disjunct instead).
    // Caveat: LE fixups are unapplied, so if wlink leaves table entries as
    // pre-fixup values outside the function span this finds nothing — that
    // outcome confirms the pe.rs caveat with real evidence (relax and
    // document it then).
    let addrs = sweep_functions(&pe, 512);
    let mut best_switch = 0usize;
    let mut best_cond = 0usize;
    for a in &addrs {
        if let Ok(fp) = cfg_fingerprint(&pe, *a) {
            best_switch = best_switch.max(fp.switch_cases);
            best_cond = best_cond.max(fp.conditionals);
        }
    }
    assert!(
        best_switch >= 3 || best_cond >= 5,
        "no swept LE function shows switch control flow (want classify): \
         max switch_cases = {best_switch}, max conditionals = {best_cond}"
    );
}

#[test]
fn dos_decision_chain_has_many_conditionals() {
    let Some(_) = load_dos() else {
        return;
    };
    let (_, pe) = load_dos().unwrap();
    // Watcom -od preserves each `if` as its own Jcc: the 12-strong chain
    // must show up as >= 12 conditionals on some swept function.
    let addrs = sweep_functions(&pe, 512);
    let mut best = 0usize;
    for a in &addrs {
        if let Ok(fp) = cfg_fingerprint(&pe, *a) {
            best = best.max(fp.conditionals);
        }
    }
    assert!(
        best >= 12,
        "no swept LE function has 12 conditionals (want decision_chain); max = {best}"
    );
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
fn dos_fixup_post_images_accepted() {
    let Some(_) = load_dos() else {
        return;
    };
    let (_, pe) = load_dos().unwrap();
    // Coherence pin for the fixup-aware accept-set on a REAL Watcom LE:
    // every post image of a referenced pre-fixup global must pass a Spec
    // present-check (pre values keep passing; garbage keeps failing).
    // If the fixture's tables hold no 07 pairs (or were skipped as a novel
    // dialect), there is nothing post-fixup to pin — the synthetic-LE unit
    // tests in pe.rs carry the proof in that case.
    if pe.fixup_count() == 0 {
        match pe.fixup_status() {
            FixupStatus::Skipped { reason } => {
                eprintln!("DOS fixture fixups skipped ({reason}); nothing post-fixup to pin")
            }
            FixupStatus::Applied { .. } => {
                eprintln!("DOS fixture has no 07 pairs; nothing post-fixup to pin")
            }
            FixupStatus::Absent => eprintln!("DOS fixture has no fixup tables"),
        }
        return;
    }
    let addrs = sweep_functions(&pe, 512);
    let mut validated = 0u32;
    for a in &addrs {
        let Ok(cg) = analyze(&pe, *a) else {
            continue;
        };
        let pres: BTreeSet<u64> = cg.globals.union(&cg.imm_addrs).copied().collect();
        if pres.is_empty() {
            continue;
        }
        for post in pe.fixup_post_images(&pres) {
            Spec::new(*a)
                .globals(&[post])
                .check(&pe)
                .unwrap_or_else(|e| {
                    panic!("post-fixup image {post:#x} of {a:#x} must be accepted: {e}")
                });
            validated += 1;
        }
        // Pre-fixup behavior is unchanged: the pre value passes, garbage fails.
        for pre in pres.iter().take(1) {
            Spec::new(*a)
                .globals(&[*pre])
                .check(&pe)
                .expect("pre-fixup global must still pass");
        }
        if validated >= 4 {
            break; // enough real-LE evidence; the sweep is not the point
        }
    }
    assert!(
        validated > 0,
        "fixup pairs exist but no swept function references a patched pre value"
    );
    let err = Spec::new(addrs[0])
        .globals(&[0xDEADBEEF])
        .check(&pe)
        .expect_err("garbage global must still fail");
    assert!(err.contains("HALLUCINATED"), "error: {err}");
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
