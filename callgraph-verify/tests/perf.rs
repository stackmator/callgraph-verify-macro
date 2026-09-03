//! Performance-regression guards for the whole-`.text` scans.
//!
//! `has_direct_branch_target` used to byte-scan the ENTIRE `.text` blob on
//! every call. The proc-macro calls it once per inline marker per `#[origin]`
//! expansion, so a 6 MB `.text` × 77 markers × ~1800 tagged fns turned a
//! rebuild's compile into a ~30-minute scan-fest. The fix caches all rel32
//! branch targets in one pass; these tests fail loudly if a future change
//! reintroduces per-call rescanning.
//!
//! The timing assertions are SELF-CALIBRATING instead of absolute: they
//! compare a batch of repeat lookups against the one-time warmup cost on the
//! same PE, so they hold on any machine speed and in both debug and release.
//! A rescan-per-call implementation fails them by ~100×, a cached one passes
//! with ~1000× margin.

use callgraph_verify::{has_direct_branch_target, Pe};
use std::time::Instant;

/// Image base used by the synthetic PEs below (same convention as integration.rs).
const BASE: u64 = 0x0040_0000;
/// `.text` RVA — the builders map file offset 0x200 to this VA.
const TEXT_RVA: u32 = 0x1000;

/// Build a PE32 whose `.text` is `text_len` bytes of `fill` (padded with
/// 0x90 NOPs), followed by `code` at the START of the section. `fill` must
/// not contain 0xE8/0xE9/0x0F-8x bytes unless intended: the branch-target
/// scan is pure byte matching gated on instruction starts.
fn pe_with_text(fill: &[u8], code: &[u8], text_len: usize) -> Pe {
    assert!(fill.len() + code.len() <= text_len);
    let mut text: Vec<u8> = Vec::with_capacity(text_len);
    text.extend_from_slice(code);
    while text.len() < text_len {
        let room = text_len - text.len();
        let take = fill.len().min(room);
        text.extend_from_slice(&fill[..take]);
    }
    let text_raw = ((text.len() + 0x1ff) & !0x1ff) as u32;
    let e_lfanew: u32 = 0x40;
    // Section raw data lives at file offset `text_raw` and spans `text_raw`
    // bytes (raw_offset == raw_size == text_raw, like integration.rs's
    // builder), so the file must be ~2× text_raw long.
    let mut data: Vec<u8> = vec![0; 0x400 + text_raw as usize * 2];
    data[0..2].copy_from_slice(b"MZ");
    data[0x3c..0x40].copy_from_slice(&e_lfanew.to_le_bytes());
    let pe_off = e_lfanew as usize;
    data[pe_off..pe_off + 4].copy_from_slice(b"PE\0\0");
    let coff = pe_off + 4;
    data[coff..coff + 2].copy_from_slice(&0x014cu16.to_le_bytes());
    data[coff + 2..coff + 4].copy_from_slice(&1u16.to_le_bytes());
    data[coff + 16..coff + 18].copy_from_slice(&0x60u16.to_le_bytes());
    let opt = coff + 20;
    data[opt..opt + 2].copy_from_slice(&0x010bu16.to_le_bytes());
    data[opt + 28..opt + 32].copy_from_slice(&(BASE as u32).to_le_bytes());
    let sec_off = opt + 0x60;
    data[sec_off..sec_off + 8].copy_from_slice(b".text\0\0\0");
    data[sec_off + 8..sec_off + 12].copy_from_slice(&(text.len() as u32).to_le_bytes());
    data[sec_off + 12..sec_off + 16].copy_from_slice(&TEXT_RVA.to_le_bytes());
    data[sec_off + 16..sec_off + 20].copy_from_slice(&text_raw.to_le_bytes());
    data[sec_off + 20..sec_off + 24].copy_from_slice(&text_raw.to_le_bytes());
    data[text_raw as usize..text_raw as usize + text.len()].copy_from_slice(&text);
    Pe::parse(data).expect("parse")
}

/// 3-byte canonical NOP — no branch opcodes, keeps the instruction count
/// (and thus the one-time decode cost) at |text|/3.
const NOP_FILL: &[u8] = &[0x0F, 0x1F, 0x00];
/// 4 MB of `.text` — same order of magnitude as noivilbo.exe's 6.4 MB.
const TEXT_LEN: usize = 4 * 1024 * 1024;

/// REGRESSION GUARD: repeat `has_direct_branch_target` lookups must be
/// amortized lookups, not full `.text` rescans.
///
/// Calibration: the FIRST call pays the one-time decode of 4 MB of `.text`
/// plus one scan; the next 200 calls against a cached implementation cost
/// microseconds combined. If a change reintroduces the per-call byte scan,
/// the batch costs ~200 scans and exceeds the warmup cost ~100×.
#[test]
fn has_direct_branch_target_repeat_lookups_are_not_rescans() {
    // No branch opcodes anywhere → every lookup below is a MISS, which was
    // the worst case for the old scanner (it walked to the end of .text to
    // conclude "no branch targets this address").
    let pe = pe_with_text(NOP_FILL, &[], TEXT_LEN);
    let first = BASE + TEXT_RVA as u64;

    let t0 = Instant::now();
    assert!(!has_direct_branch_target(&pe, first));
    let warmup = t0.elapsed();
    assert!(
        warmup.as_millis() > 0,
        "warmup did no measurable work — test PE too small to calibrate against"
    );

    const N: u32 = 200;
    let t1 = Instant::now();
    for k in 0..N {
        // Distinct, in-.text addresses; all miss.
        let a = BASE + TEXT_RVA as u64 + (k as u64 * 16) + 1;
        assert!(!has_direct_branch_target(&pe, a));
    }
    let batch = t1.elapsed();

    assert!(
        batch * 10 < warmup,
        "200 repeat lookups took {batch:?} vs {warmup:?} for the first (warmup) call — \
         has_direct_branch_target is rescanning .text per call; the all-branch-targets \
         cache in lib.rs was dropped or its key stopped matching"
    );
}

/// The branch-target cache key must distinguish same-layout PEs with
/// DIFFERENT `.text` bytes (test binaries, a rebuilt exe). If the key ever
/// loses the content component (the BUG #9 input-ignoring-cache class), the
/// second PE inherits the first's target set and this test fails
/// deterministically — no timing involved.
#[test]
fn has_direct_branch_target_cache_distinguishes_same_layout_pes() {
    // PE A: pure NOP sled — nothing is a branch target.
    let pe_a = pe_with_text(NOP_FILL, &[], 0x1000);
    // PE B: identical header layout, but starts with `CALL rel32` (rel 0 →
    // targets its own next_ip, offset 5) followed by RET, padded with the
    // same NOP fill.
    let pe_b = pe_with_text(NOP_FILL, &[0xE8, 0x00, 0x00, 0x00, 0x00, 0xC3], 0x1000);
    let call_target = BASE + TEXT_RVA as u64 + 5;

    // Warm any cache entry PE A might create, then prove the lookups disagree.
    assert!(!has_direct_branch_target(&pe_a, call_target));
    assert!(
        has_direct_branch_target(&pe_b, call_target),
        "PE B's CALL target not found — the branch-target cache treated PE B \
         as PE A (cache key ignores PE identity/content)"
    );
    // And in the other order: a fresh process ordering must behave the same.
    let pe_c = pe_with_text(NOP_FILL, &[0xE8, 0x00, 0x00, 0x00, 0x00, 0xC3], 0x2000);
    let pe_d = pe_with_text(NOP_FILL, &[], 0x2000);
    assert!(has_direct_branch_target(&pe_c, call_target));
    assert!(!has_direct_branch_target(&pe_d, call_target));
}

/// A `.text` HIT must still be found after the cache is warm (guards the
/// cache build itself: a broken one-pass builder could produce an empty set
/// that makes every lookup miss "fast").
#[test]
fn has_direct_branch_target_finds_hits_in_large_text() {
    // A CALL buried in the NOP fill (at an instruction boundary — the fill is
    // 3-byte NOPs, so offset 3*k starts an instruction) whose rel32 targets
    // its own next_ip: `E8 00 00 00 00` at code offset 3 → target offset 8.
    let mut code = vec![0x0F, 0x1F, 0x00];
    code.extend_from_slice(&[0xE8, 0x00, 0x00, 0x00, 0x00]);
    let pe = pe_with_text(NOP_FILL, &code, TEXT_LEN);
    let call_target = BASE + TEXT_RVA as u64 + 8;

    assert!(
        has_direct_branch_target(&pe, call_target),
        "the buried CALL target must be found in the cached branch-target set"
    );
    // A miss inside the same PE stays a miss.
    assert!(!has_direct_branch_target(
        &pe,
        BASE + TEXT_RVA as u64 + 0x40
    ));
}
