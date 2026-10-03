//! End-to-end compile-error fixtures for the `CG-VERIFY-Exxx` codes that
//! can be exercised via `trybuild`. Each fixture under `tests/ui/*.rs` is a
//! tiny Rust file that should fail with one specific code; the matching
//! `.stderr` snapshot pins the exact rendered message.
//!
//! ## Trybuild limitations, and what we cover
//!
//! Trybuild caches cargo build outputs per source file; env-var changes
//! between fixture phases do NOT invalidate the cache, so we can only run
//! ONE phase with a stable env. We pick the PE-loaded phase because it
//! exercises every code that fires after binary load: E005 (outside
//! section), E006 (unreferenced), E008 (corpus gap), and the in-message
//! text for the codes that share wording (E012 HALLUCINATED, E013 MISSING,
//! etc.) — those are tested by the unit tests in `error.rs` instead, since
//! trybuild can't easily drive a body-vs-binary diff without the corpus
//! scanner seeing both the fixture and a multi-fn source corpus.
//!
//! Codes NOT covered by trybuild and instead pinned by the unit test in
//! `error.rs::all_codes_have_stable_prefix_label_and_prefix_string`:
//! E001 UNKNOWN-ATTR-KEY, E002 UNKNOWN-ATTR-FLAG, E003 NOT-A-FUNCTION,
//! E004 TARGET-EXE-UNLOADABLE, E007 DECLARED-FACTS, E009 DUP-ADDR,
//! E011 VTABLE-DISPATCH, E012 HALLUCINATED,
//! E013 MISSING, E014 ARG-SHAPE, E015 HALLUCINATED-ADDR, E016 CFG,
//! E017 ANALYZE, E018 CFG-FINGERPRINT, E019 VTABLE-SLOT, E020 VTABLE-SLOT-OOB.
//!
//! ## Workflow
//!
//! 1. Edit a fixture file.
//! 2. Run `cargo test -p callgraph-verify-macro --test error_codes`.
//!    If a `.stderr` snapshot is missing or stale, trybuild writes a `wip/`
//!    copy. Move it into place.
//! 3. To regenerate all `.stderr` files at once after a wording change:
//!    `TRYBUILD=overwrite cargo test -p callgraph-verify-macro --test error_codes`.
//!    Review the diff before committing — wording changes are user-visible.

use std::path::{Path, PathBuf};

/// Build a minimal valid PE32 image with a `.text` section, a fake
/// vtable at `.rdata` VA 0xA00000 (slot 0 → 0x00403000), AND a single
/// real CALL at the entry of `.text` that branches to 0x00402000.
/// Returns the raw bytes ready to write to disk.
///
/// The .text bytes at VA 0x401000:
///
/// ```text
/// 0x401000: E8 FB 0F 00 00       CALL 0x00402000
/// 0x401005: C3                   RET
/// 0x401006: (zero-padded to 0x200)
/// ```
///
/// The CALL provides a binary-side ground truth for MISSING (E013),
/// ARG-SHAPE (E014), HALLUCINATED-ADDR (E015), and CFG (E016) fixtures
/// — the body can either invoke the call (matches), omit it (MISSING),
/// or add a phantom call (HALLUCINATED).
fn build_synthetic_pe() -> Vec<u8> {
    let image_base: u32 = 0x0040_0000;
    let text_va: u32 = 0x1000;
    let text_raw: u32 = 0x200;
    // RVAs are relative to image_base. .rdata at RVA 0x600000 lives at
    // VA 0x00A00000 (where the E011 vtable fixture expects it).
    let rdata_va: u32 = 0x600000;
    let rdata_raw: u32 = 0x200;
    let e_lfanew: u32 = 0x40;
    // File size: enough for headers (0x400) + .text raw (0x200) + .rdata raw (0x200).
    let mut data: Vec<u8> = vec![0; 0x400 + text_raw as usize + rdata_raw as usize];
    data[0..2].copy_from_slice(b"MZ");
    data[0x3c..0x40].copy_from_slice(&e_lfanew.to_le_bytes());
    let pe_off = e_lfanew as usize;
    data[pe_off..pe_off + 4].copy_from_slice(b"PE\0\0");
    let coff = pe_off + 4;
    data[coff..coff + 2].copy_from_slice(&0x014cu16.to_le_bytes()); // machine = i386
    data[coff + 2..coff + 4].copy_from_slice(&2u16.to_le_bytes()); // NumberOfSections
    data[coff + 16..coff + 18].copy_from_slice(&0x60u16.to_le_bytes()); // SizeOfOptionalHeader
    let opt = coff + 20;
    data[opt..opt + 2].copy_from_slice(&0x010bu16.to_le_bytes()); // magic = PE32
    data[opt + 28..opt + 32].copy_from_slice(&image_base.to_le_bytes());

    // Section 1: .text
    let sec_off = opt + 0x60;
    data[sec_off..sec_off + 8].copy_from_slice(b".text\0\0\0");
    data[sec_off + 8..sec_off + 12].copy_from_slice(&text_raw.to_le_bytes()); // VirtualSize
    data[sec_off + 12..sec_off + 16].copy_from_slice(&text_va.to_le_bytes()); // VirtualAddress
    data[sec_off + 16..sec_off + 20].copy_from_slice(&text_raw.to_le_bytes()); // SizeOfRawData
    data[sec_off + 20..sec_off + 24].copy_from_slice(&text_raw.to_le_bytes()); // PointerToRawData

    // Section 2: .rdata (the vtable location)
    let rdata_sec_off = sec_off + 40;
    data[rdata_sec_off..rdata_sec_off + 8].copy_from_slice(b".rdata\0\0");
    data[rdata_sec_off + 8..rdata_sec_off + 12].copy_from_slice(&rdata_raw.to_le_bytes());
    data[rdata_sec_off + 12..rdata_sec_off + 16].copy_from_slice(&rdata_va.to_le_bytes());
    data[rdata_sec_off + 16..rdata_sec_off + 20].copy_from_slice(&rdata_raw.to_le_bytes());
    // .rdata raw data starts at file offset text_raw * 2 (right after .text's
    // 0x200-byte block).
    data[rdata_sec_off + 20..rdata_sec_off + 24]
        .copy_from_slice(&(text_raw * 2).to_le_bytes());

    // .text layout (file offset = text_raw = 0x200):
    //   [0]:   6A 20              PUSH 0x20        ; staged arg kind = Imm(0x20)
    //   [2]:   E8 F9 0F 00 00     CALL 0x402000
    //   [7]:   74 FE              JE -2            ; back-edge #1 (0x401007 → 0x401005)
    //   [9]:   EB FE              JMP -2           ; back-edge #2 (0x401009 → 0x401007)
    //   [0xB..0xF]: 0x00401000 dword — anchors ORIGIN-UNREFERENCED
    //
    // Three reachable blocks:
    //   * Block at 0x401000: PUSH, CALL, JE
    //     Successors: 0x401005 (JE-taken, back-edge into middle of CALL's rel32
    //                            — iced-x86 treats this as a "block" so the
    //                            loop count goes up by 1) and 0x401009 (fall-through)
    //   * Block at 0x401009: JMP -2 → 0x401007 (back-edge into the JE — loop count +1)
    //
    // The PUSH is consumed by E014 ARG-SHAPE; the CALL gives E013 MISSING
    // something to compare against; the two back-edges give E016 CFG `loops = 2`
    // so the `loops >= 2` threshold is met; the dword makes 0x401000
    // "referenced" so ORIGIN-UNREFERENCED doesn't drown out everything else.
    let text_file_off = text_raw as usize;
    data[text_file_off] = 0x6A; // PUSH imm8
    data[text_file_off + 1] = 0x20; // 0x20
    data[text_file_off + 2..text_file_off + 7]
        .copy_from_slice(&[0xE8, 0xF9, 0x0F, 0x00, 0x00]);
    // JE -2 (rel8 = 0xFE): 0x401007 → 0x401005 (back-edge #1)
    data[text_file_off + 7] = 0x74;
    data[text_file_off + 8] = 0xFE;
    // JMP -2 (rel8 = 0xFE): 0x401009 → 0x401007 (back-edge #2 — branches into
    // the middle of the JE; iced-x86 may decode as a separate block from
    // 0x401005 because that address is reached as the JE target)
    data[text_file_off + 9] = 0xEB;
    data[text_file_off + 0xA] = 0xFE;
    data[text_file_off + 0xB..text_file_off + 0xF]
        .copy_from_slice(&0x00401000u32.to_le_bytes());

    // Vtable slot 0 → 0x00403000 (little-endian). .rdata raw data starts at
    // file offset text_raw * 2.
    let rdata_file_off = (text_raw * 2) as usize;
    data[rdata_file_off..rdata_file_off + 4].copy_from_slice(&0x00403000u32.to_le_bytes());

    // Section 2: .rdata2 (the second vtable location for E019)
    // .rdata's header ends at sec_off + 40 + 40 = sec_off + 80. The next
    // section header starts there.
    let rdata2_va: u32 = 0x601000;
    let rdata2_sec_off = sec_off + 80;
    data[rdata2_sec_off..rdata2_sec_off + 8].copy_from_slice(b".rdata2\0");
    data[rdata2_sec_off + 8..rdata2_sec_off + 12].copy_from_slice(&rdata_raw.to_le_bytes());
    data[rdata2_sec_off + 12..rdata2_sec_off + 16].copy_from_slice(&rdata2_va.to_le_bytes());
    data[rdata2_sec_off + 16..rdata2_sec_off + 20].copy_from_slice(&rdata_raw.to_le_bytes());
    // .rdata.dup raw data starts at file offset text_raw * 3.
    data[rdata2_sec_off + 20..rdata2_sec_off + 24]
        .copy_from_slice(&(text_raw * 3).to_le_bytes());
    let rdata2_file_off = (text_raw * 3) as usize;
    data[rdata2_file_off..rdata2_file_off + 4].copy_from_slice(&0x00402000u32.to_le_bytes());

    // Bump section count to 3 and resize the file to fit .rdata.dup raw data.
    data[coff + 2..coff + 4].copy_from_slice(&3u16.to_le_bytes());
    let new_len = 0x400 + text_raw as usize * 3;
    data.resize(new_len, 0);

    data
}

/// Materialise the synthetic PE + a multi-file corpus under `tests/testdata/`
/// so the fixtures have something to point at. Idempotent — overwrites both
/// files on every test run so a corpus edit doesn't get stale between runs.
///
/// The corpus is set up for several fixtures:
///   - `lib.rs` declares `#[origin(0x401000)]` for `probe`, so CORPUS-GAP
///     does NOT fire when a fixture targets 0x401000.
///   - `real_call.rs` declares `#[origin(0x00402000)]` for `real_call` —
///     a body-call target with a corpus entry.
fn setup_testdata(manifest_dir: &Path) -> (PathBuf, PathBuf) {
    let testdata = manifest_dir.join("tests").join("testdata");
    std::fs::create_dir_all(&testdata).expect("create tests/testdata");
    let pe_path = testdata.join("synthetic_pe.bin");
    let corpus_dir = testdata.join("corpus");
    std::fs::create_dir_all(&corpus_dir).expect("create tests/testdata/corpus");
    std::fs::write(&pe_path, build_synthetic_pe()).expect("write synthetic_pe.bin");
    std::fs::write(
        corpus_dir.join("lib.rs"),
        "use callgraph_verify_macro::origin;\n\
         #[origin(0x00401000)]\n\
         pub fn probe() {}\n\
         // Second owner of 0x00401000 — used by the E009 DUP-ADDR fixture.\n\
         #[origin(0x00401000)]\n\
         #[allow(dead_code)]\n\
         pub fn probe_duplicate() {}\n",
    )
    .expect("write corpus lib.rs");
    std::fs::write(
        corpus_dir.join("real_call.rs"),
        "use callgraph_verify_macro::origin;\n\
         #[origin(0x00402000)]\n\
         #[allow(dead_code)]\n\
         pub fn real_call() {}\n",
    )
    .expect("write corpus real_call.rs");
    // For E011 VTABLE-DISPATCH: declare a vtable whose slot 0 holds
    // 0x00403000, and register `dispatched` at that origin. The fixture
    // body calls `dispatched()` directly — the verifier sees the vtable
    // mapping and gates the build with E011.
    std::fs::write(
        corpus_dir.join("vtable_dispatch.rs"),
        "use callgraph_verify_macro::{origin, vtable_table};\n\
         #[origin(0x00403000)]\n\
         #[allow(dead_code)]\n\
         pub fn dispatched() {}\n\
         vtable_table! {\n            name = test_vt,\n            va = 0x00A00000,\n            slots = 1,\n            default = crate::vtable_unimplemented;\n            0 = dispatched;\n         }\n         #[allow(dead_code)]\n         fn vtable_unimplemented() {}\n",
    )
    .expect("write corpus vtable_dispatch.rs");
    // For E019 VTABLE-SLOT (mismatch): the fixture declares slot 0 → fn
    // `mismatch_fn`, but the engine vtable at VA 0xA01000 actually holds
    // 0x00402000. So `mismatch_fn` is registered at 0x404000 (NOT
    // 0x402000), and the verifier flags the mismatch.
    std::fs::write(
        corpus_dir.join("vtable_mismatch.rs"),
        "use callgraph_verify_macro::{origin, vtable_table};\n\
         #[origin(0x00404000)]\n\
         #[allow(dead_code)]\n\
         pub fn mismatch_fn() {}\n\
         vtable_table! {\n            name = mismatch_vt,\n            va = 0x00A01000,\n            slots = 1,\n            default = crate::vtable_unimplemented;\n            0 = mismatch_fn;\n         }\n         #[allow(dead_code)]\n         fn vtable_unimplemented_m() {}\n",
    )
    .expect("write corpus vtable_mismatch.rs");
    // For E020 VTABLE-SLOT-OOB: declare slot 5 with only `slots = 1`.
    std::fs::write(
        corpus_dir.join("vtable_oob.rs"),
        "use callgraph_verify_macro::{origin, vtable_table};\n\
         #[origin(0x00405000)]\n\
         #[allow(dead_code)]\n\
         pub fn oob_fn() {}\n",
    )
    .expect("write corpus vtable_oob.rs");
    // For macro-expansion fixtures (e012_hallucinated_via_macro,
    // e013_missing_satisfied_via_macro): unambiguous local macro_rules
    // definitions the verifier is expected to see through. The fixtures
    // pull this file in with `include!` (so rustc can expand the macros)
    // while the corpus scanner reads it from here (so the verifier can
    // resolve the definitions).
    std::fs::write(
        corpus_dir.join("macro_defs.rs"),
        "#[allow(unused_macros)]\nmacro_rules! sneaky {\n    ($x:expr) => { oob_fn($x) };\n}\n#[allow(unused_macros)]\nmacro_rules! caller {\n    ($x:expr) => { real_call($x) };\n}\n",
    )
    .expect("write corpus macro_defs.rs");
    (pe_path, corpus_dir)
}

/// Write a small non-PE file at `tests/testdata/not_a_pe.bin` so the
/// E004 fixture can point TARGET_EXE at it. The file exists (so the macro's
/// "exists but corrupt" branch fires) but isn't a valid PE image.
fn setup_not_a_pe(manifest_dir: &Path) -> PathBuf {
    let path = manifest_dir.join("tests").join("testdata").join("not_a_pe.bin");
    std::fs::write(&path, b"definitely not a PE image\n").expect("write not_a_pe.bin");
    path
}

/// Run the full trybuild matrix in two phases with different env values
/// per phase, using different fixture globs so each phase's fixtures are
/// run exactly once (trybuild's cargo cache doesn't invalidate on
/// non-RUSTFLAGS env changes, so we cannot re-run a fixture with a
/// different env — once it's compiled with one env, the cached binary is
/// reused regardless of subsequent env changes).
///
/// Phase1 (`tests/ui/e00[1-4]*.rs`): TARGET_EXE points at a file that
/// exists but is not a valid PE — this exercises the E004
/// TARGET-EXE-UNLOADABLE gate plus the parser-side E001/E002/E003 codes
/// that fire before env is read.
///
/// Phase2 (`tests/ui/e0[05-9]*.rs`): TARGET_EXE points at the synthetic
/// PE so every PE-dependent code (E005+) can fire.
#[test]
fn ui() {
    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let not_a_pe = setup_not_a_pe(&manifest_dir);
    let (pe, corpus) = setup_testdata(&manifest_dir);

    // Phase1: PE-free. Bogus-but-existing TARGET_EXE.
    std::env::set_var("TARGET_EXE", not_a_pe.to_str().unwrap());
    std::env::set_var("REBUILD_ROOT", corpus.to_str().unwrap());
    {
        let t = trybuild::TestCases::new();
        t.compile_fail("tests/ui/e00[1-4]*.rs");
    }

    // Phase2: PE-loaded. Synthetic PE + corpus. Explicit per-fixture names
    // (no glob char-class — earlier `e0[05-9]*.rs` accidentally matched
    // e004 too in some trybuild builds, polluting its .stderr).
    std::env::set_var("TARGET_EXE", pe.to_str().unwrap());
    {
        let t = trybuild::TestCases::new();
        // Phase-2 fixtures: every code in 05..=20 except ones we explicitly
        // skip. Add new fixtures to this list as more codes get coverage.
        let phase2 = [
            "tests/ui/e005_origin_outside_section.rs",
            "tests/ui/e006_origin_unreferenced.rs",
            "tests/ui/e007_declared_facts.rs",
            "tests/ui/e008_corpus_gap.rs",
            "tests/ui/e009_dup_addr.rs",
            "tests/ui/e011_vtable_dispatch.rs",
            "tests/ui/e012_hallucinated.rs",
            "tests/ui/e012_hallucinated_via_macro.rs",
            "tests/ui/e013_missing.rs",
            "tests/ui/e013_missing_satisfied_via_macro.rs",
            "tests/ui/e014_arg_shape.rs",
            "tests/ui/e015_hallucinated_addr.rs",
            "tests/ui/e016_cfg.rs",
            "tests/ui/e019_vtable_slot.rs",
            "tests/ui/e020_vtable_slot_oob.rs",
        ];
        for fixture in phase2 {
            if std::path::Path::new(fixture).exists() {
                t.compile_fail(fixture);
            }
        }
    }
}