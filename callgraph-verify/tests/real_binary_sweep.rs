//! Local-only sweep over a user-provided real binary (e.g. an Oblivion-era
//! exe built with MSVC 2005/2008 — the crate's actual domain, which cannot
//! be committed to the repo for size and licensing reasons).
//!
//! Set `CALLGRAPH_REAL_EXE` to a 32-bit PE (or DOS4GW LE) path. Skipped when
//! unset — including under `CALLGRAPH_REQUIRE_FIXTURES=1`, which governs
//! only the committed fixtures (this file can never exist in CI).
//!
//! The assertions mirror the whole-image sweeps in `c_cpp_integration.rs`:
//! decoder/byte-scan agreement and diff-cleanliness over every analyzable
//! function, plus a printed summary (run with `-- --nocapture` to see it).

use callgraph_verify::{analyze, diff_calls, has_direct_branch_target, Pe};

#[test]
fn real_binary_sweeps_agree_and_diff_clean() {
    let exe = match std::env::var("CALLGRAPH_REAL_EXE") {
        Ok(p) if !p.trim().is_empty() => p,
        _ => {
            eprintln!(
                "skipping: set CALLGRAPH_REAL_EXE=<path-to-32bit-exe> to sweep a real binary"
            );
            return;
        }
    };
    let pe = Pe::load(&exe).unwrap_or_else(|e| panic!("load {exe}: {e}"));
    // Only check callers that are REFERENCED (a rel32 target or a stored
    // dword): that is the crate's own definition of a plausible function
    // entry (the ORIGIN-UNREFERENCED gate). A blind extent-skip walk also
    // lands mid-gap on alignment padding, whose bytes decode to junk with
    // junk rel32 targets (e.g. noivilbo.exe 0x497A59: a 3-byte NOP sled
    // followed by `JP`/`ADD` filler) — checking those would blame the
    // verifier for decoding non-code. The macro never analyzes such
    // addresses either: every `#[origin]` must pass the referenced gate.
    let refs = pe.referenced_addrs();
    // And only check targets INSIDE the image: a decoded `CALL` to kernel
    // space (e.g. noivilbo.exe 0xBCAE8B `OUT DX,AL` + ... + `CALL
    // 0xDAC27BB9` — data decoded as code) is definitionally not a real
    // direct call, and the byte scan (like `referenced_addrs`) only indexes
    // in-image targets. Real missed-branch bugs always land in-image.
    let (lo, hi) = pe.image_range();

    // Walk every executable section the way the fixture sweeps do.
    let mut starts: Vec<(u64, u64)> = pe
        .sections()
        .iter()
        .filter(|s| s.is_executable())
        .map(|s| {
            let start = pe.image_base + s.virtual_address as u64;
            (start, start + s.virtual_size.max(s.raw_size) as u64)
        })
        .collect();
    starts.sort();
    assert!(!starts.is_empty(), "{exe} has no executable section");

    let mut fns = 0u32;
    let mut checked_callers = 0u32;
    let mut calls = 0u32;
    let mut disagreements = Vec::new();
    let mut unclean = Vec::new();
    for (start, end) in starts {
        let mut va = start;
        while va < end {
            if let Ok(cg) = analyze(&pe, va) {
                fns += 1;
                // Diff-cleanliness is meaningful for every analyzable entry
                // (it must never panic or contradict its own call set).
                let real: Vec<u64> = cg.call_targets().into_iter().collect();
                match diff_calls(&pe, va, &real, true) {
                    Ok(d) if d.hallucinated.is_empty() && d.missing.is_empty() => {}
                    other => unclean.push((va, format!("{other:?}"))),
                }
                // Byte-scan agreement only for referenced (plausibly real)
                // entries — see the note above.
                if refs.contains(&(va as u32)) {
                    checked_callers += 1;
                    for &t in cg.direct_calls.keys() {
                        if !(lo..hi).contains(&t) {
                            continue; // decode artifact, see note above
                        }
                        calls += 1;
                        if !has_direct_branch_target(&pe, t) {
                            disagreements.push((va, t));
                        }
                    }
                }
                va = va.saturating_add(cg.max_end.saturating_sub(va).max(1));
            } else {
                va += 1;
            }
        }
    }
    eprintln!(
        "{exe}: swept {fns} entries ({checked_callers} referenced), {calls} direct calls"
    );
    assert!(fns > 0, "no analyzable functions in {exe}");
    assert!(
        disagreements.is_empty(),
        "{} of {calls} CALL targets disagree with the byte scan: {disagreements:?}",
        disagreements.len()
    );
    assert!(
        unclean.is_empty(),
        "{} of {fns} functions not diff-clean: {unclean:?}",
        unclean.len()
    );
}
