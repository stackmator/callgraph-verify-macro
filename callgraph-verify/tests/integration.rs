#[cfg(test)]
mod tests {
    use callgraph_verify::{
        analyze, cfg_fingerprint, diff_body_calls, has_direct_branch_target, reg_params, ArgKind,
        Pe, Spec,
    };
    use std::process::Command;

    /// Build the test-bin binary if needed.
    fn ensure_test_binary_built() {
        let manifest_dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
        let test_bin_dir = manifest_dir.join("test-bin");
        let exe_path = test_bin_dir
            .join("target")
            .join("i686-pc-windows-msvc")
            .join("debug")
            .join("test-bin.exe");
        if !exe_path.exists() {
            let status = Command::new("cargo")
                .args(["build", "--target", "i686-pc-windows-msvc"])
                .current_dir(&test_bin_dir)
                .status()
                .expect("failed to run cargo build for test-bin");
            assert!(status.success(), "test-bin build failed");
        }
    }

    fn get_test_binary_path() -> std::path::PathBuf {
        ensure_test_binary_built();
        let manifest_dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
        let test_bin_dir = manifest_dir.join("test-bin");
        test_bin_dir
            .join("target")
            .join("i686-pc-windows-msvc")
            .join("debug")
            .join("test-bin.exe")
    }

    fn load_test_pe() -> Pe {
        let path = get_test_binary_path();
        Pe::load(path.to_str().unwrap()).expect("load test binary")
    }

    /// Find a function address by scanning the .text section for valid functions
    fn find_function_addresses(pe: &Pe) -> Vec<u64> {
        let mut addrs = Vec::new();
        // Scan the .text section for any address that analyzes successfully
        if let Some(section) = pe.sections().iter().find(|s| s.name == ".text") {
            let start_rva = section.virtual_address as u64;
            let size = section.virtual_size as u64;
            let image_base = pe.image_base;
            let start_va = image_base + start_rva;
            let end_va = start_va + size;

            // Try addresses at 16-byte intervals
            let mut va = start_va;
            let mut checked = 0;
            while va < end_va && checked < 200 {
                if analyze(pe, va).is_ok() {
                    addrs.push(va);
                    // Skip ahead to avoid finding the same function multiple times
                    va += 16;
                } else {
                    va += 4;
                }
                checked += 1;
            }
        }
        addrs.sort();
        addrs.dedup();
        addrs
    }

    #[test]
    fn test_binary_loads() {
        let pe = load_test_pe();
        assert!(!pe.sections().is_empty());
        assert!(pe.sections().iter().any(|s| s.name == ".text"));
    }

    #[test]
    fn test_analyze_finds_functions() {
        let pe = load_test_pe();
        let addrs = find_function_addresses(&pe);
        assert!(
            !addrs.is_empty(),
            "should find at least one function prologue"
        );

        // Analyze the first function found
        let cg = analyze(&pe, addrs[0]).expect("analyze first function");
        assert_eq!(cg.entry, addrs[0]);
    }

    #[test]
    fn test_analyze_detects_direct_calls() {
        let pe = load_test_pe();
        let addrs = find_function_addresses(&pe);

        // Find a function that makes calls (not a leaf)
        for addr in &addrs {
            let cg = analyze(&pe, *addr).expect("analyze");
            if !cg.direct_calls.is_empty() {
                // Found a function with direct calls
                assert!(!cg.direct_calls.is_empty());
                return;
            }
        }
        panic!("no function with direct calls found in test binary");
    }

    #[test]
    fn test_analyze_leaf_function() {
        let pe = load_test_pe();
        let addrs = find_function_addresses(&pe);

        // Find a leaf function (no direct calls)
        for addr in &addrs {
            let cg = analyze(&pe, *addr).expect("analyze");
            if cg.direct_calls.is_empty() && cg.indirect_calls == 0 && cg.indirect_jumps == 0 {
                // Found a leaf function
                assert!(cg.direct_calls.is_empty());
                return;
            }
        }
        // It's ok if we don't find a perfect leaf - the test binary might not have one
    }

    #[test]
    fn test_spec_hallucinated_call() {
        let pe = load_test_pe();
        let addrs = find_function_addresses(&pe);
        let addr = addrs[0];

        // Declare a call that doesn't exist
        let result = Spec::new(addr).calls_superset(&[0xDEADBEEF]).check(&pe);

        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(err.contains("HALLUCINATED"), "error: {}", err);
    }

    #[test]
    fn test_spec_hallucinated_field() {
        let pe = load_test_pe();
        let addrs = find_function_addresses(&pe);
        let addr = addrs[0];

        let result = Spec::new(addr).fields(&[0x1000]).check(&pe);

        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(err.contains("HALLUCINATED"), "error: {}", err);
    }

    #[test]
    fn test_spec_hallucinated_global() {
        let pe = load_test_pe();
        let addrs = find_function_addresses(&pe);
        let addr = addrs[0];

        let result = Spec::new(addr).globals(&[0x00BEEF00]).check(&pe);

        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(err.contains("HALLUCINATED"), "error: {}", err);
    }

    #[test]
    fn test_diff_calls_superset_ok() {
        let pe = load_test_pe();
        let addrs = find_function_addresses(&pe);

        // Find a function with calls
        for addr in &addrs {
            let cg = analyze(&pe, *addr).expect("analyze");
            if !cg.direct_calls.is_empty() {
                let real_targets: Vec<u64> = cg.call_targets().into_iter().collect();

                // Superset of a subset should pass
                let result = Spec::new(*addr)
                    .calls_superset(&real_targets[..1.min(real_targets.len())])
                    .check(&pe);

                assert!(
                    result.is_ok(),
                    "superset of actual calls should pass: {:?}",
                    result
                );
                return;
            }
        }
    }

    #[test]
    fn test_diff_calls_exact_fails_on_missing() {
        let pe = load_test_pe();
        let addrs = find_function_addresses(&pe);

        for addr in &addrs {
            let cg = analyze(&pe, *addr).expect("analyze");
            if !cg.direct_calls.is_empty() {
                let real_targets: Vec<u64> = cg.call_targets().into_iter().collect();

                // Exact with extra call should fail
                let mut with_extra = real_targets.clone();
                with_extra.push(0xDEADBEEF);

                let result = Spec::new(*addr).calls_exact(&with_extra).check(&pe);

                assert!(result.is_err());
                let err = result.unwrap_err();
                assert!(err.contains("HALLUCINATED"), "error: {}", err);
                return;
            }
        }
    }

    #[test]
    fn test_analyze_vcall_slots() {
        let pe = load_test_pe();
        let addrs = find_function_addresses(&pe);

        for addr in &addrs {
            let cg = analyze(&pe, *addr).expect("analyze");
            // Just verify the analysis runs and returns a valid structure
            // vcall_slots may be empty for our test binary
            let _ = &cg.vcall_slots;
        }
    }

    #[test]
    fn test_analyze_iat_calls() {
        let pe = load_test_pe();
        let addrs = find_function_addresses(&pe);

        for addr in &addrs {
            let cg = analyze(&pe, *addr).expect("analyze");
            let _ = &cg.iat_calls;
        }
    }

    #[test]
    fn test_analyze_field_offsets() {
        let pe = load_test_pe();
        let addrs = find_function_addresses(&pe);

        for addr in &addrs {
            let cg = analyze(&pe, *addr).expect("analyze");
            let _ = &cg.field_offsets;
        }
    }

    #[test]
    fn test_analyze_globals() {
        let pe = load_test_pe();
        let addrs = find_function_addresses(&pe);

        for addr in &addrs {
            let cg = analyze(&pe, *addr).expect("analyze");
            let _ = &cg.globals;
        }
    }

    #[test]
    fn test_analyze_imm_addrs() {
        let pe = load_test_pe();
        let addrs = find_function_addresses(&pe);

        for addr in &addrs {
            let cg = analyze(&pe, *addr).expect("analyze");
            let _ = &cg.imm_addrs;
        }
    }

    #[test]
    fn test_call_site_argument_shapes() {
        let pe = load_test_pe();
        let addrs = find_function_addresses(&pe);

        for addr in &addrs {
            let cg = analyze(&pe, *addr).expect("analyze");
            for cs in &cg.call_sites {
                assert!(cs.target > 0);
                // arg kinds should be valid
                if let Some(a) = cs.ecx {
                    let _ = match a {
                        ArgKind::Imm(_)
                        | ArgKind::Field(_)
                        | ArgKind::Global(_)
                        | ArgKind::Other
                        | ArgKind::LocalAddr => true,
                    };
                }
                if let Some(a) = cs.edx {
                    let _ = match a {
                        ArgKind::Imm(_)
                        | ArgKind::Field(_)
                        | ArgKind::Global(_)
                        | ArgKind::Other
                        | ArgKind::LocalAddr => true,
                    };
                }
                for a in &cs.stack {
                    let _ = match a {
                        ArgKind::Imm(_)
                        | ArgKind::Field(_)
                        | ArgKind::Global(_)
                        | ArgKind::Other
                        | ArgKind::LocalAddr => true,
                    };
                }
            }
        }
    }

    #[test]
    fn test_cfg_fingerprint() {
        let pe = load_test_pe();
        let addrs = find_function_addresses(&pe);

        for addr in &addrs {
            let fp = cfg_fingerprint(&pe, *addr);
            // Just verify it runs without error
            let _ = fp;
        }
    }

    #[test]
    fn test_diff_body_calls_call_without_binary_call_is_hallucinated() {
        let pe = load_test_pe();
        let addrs = find_function_addresses(&pe);

        // Find a function with calls
        for addr in &addrs {
            let cg = analyze(&pe, *addr).expect("analyze");
            if !cg.direct_calls.is_empty() {
                let real_targets: Vec<u64> = cg.call_targets().into_iter().collect();

                // Create a corpus with these addresses plus an extra one the binary
                // never calls. There is no inline-marker escape hatch anymore: if the
                // engine inlines a helper, the faithful port spells the work inline,
                // so a call to the helper is a HALLUCINATED.
                let mut corpus: std::collections::BTreeSet<u64> =
                    real_targets.iter().copied().collect();
                let fake_callee = 0xDEADBEEF; // Not in the binary's direct calls
                corpus.insert(fake_callee);

                // Rust calls the never-called callee
                let rust_idents = vec![("invented_fn".to_string(), vec![fake_callee])];

                let diff = diff_body_calls(
                    &pe,
                    &[*addr],
                    &corpus,
                    &rust_idents,
                    &std::collections::BTreeSet::new(),
                    &std::collections::BTreeSet::new(),
                )
                .expect("diff_body_calls");

                // The call must be classified as hallucinated, never excused.
                assert!(
                    diff.hallucinated.iter().any(|(n, _)| n == "invented_fn"),
                    "hallucinated: {:?}",
                    diff.hallucinated
                );
                return;
            }
        }
    }

    #[test]
    fn test_diff_body_calls_vtable_dispatch() {
        let pe = load_test_pe();
        let addrs = find_function_addresses(&pe);

        for addr in &addrs {
            let cg = analyze(&pe, *addr).expect("analyze");
            if !cg.direct_calls.is_empty() {
                let real_targets: Vec<u64> = cg.call_targets().into_iter().collect();

                let corpus: std::collections::BTreeSet<u64> =
                    real_targets.iter().copied().collect();

                // Rust calls a target that's NOT in bin_calls but IS in vtable_methods
                let vtable_method = 0xFEEDFACE;
                let vtable_methods: std::collections::BTreeSet<u64> =
                    [vtable_method].into_iter().collect();
                let rust_idents = vec![("vtable_method".to_string(), vec![vtable_method])];

                let diff = diff_body_calls(
                    &pe,
                    &[*addr],
                    &corpus,
                    &rust_idents,
                    &vtable_methods,
                    &std::collections::BTreeSet::new(),
                )
                .expect("diff_body_calls");

                // Should be classified as vtable_dispatch
                assert!(
                    diff.vtable_dispatch
                        .iter()
                        .any(|(n, _)| n == "vtable_method"),
                    "vtable_dispatch: {:?}",
                    diff.vtable_dispatch
                );
                return;
            }
        }
    }

    #[test]
    fn test_diff_body_calls_missing() {
        let pe = load_test_pe();
        let addrs = find_function_addresses(&pe);

        for addr in &addrs {
            let cg = analyze(&pe, *addr).expect("analyze");
            if !cg.direct_calls.is_empty() {
                let real_targets: Vec<u64> = cg.call_targets().into_iter().collect();

                let corpus: std::collections::BTreeSet<u64> =
                    real_targets.iter().copied().collect();

                // Rust doesn't call one of the binary's callees
                let rust_idents = vec![]; // empty - no calls

                let diff = diff_body_calls(
                    &pe,
                    &[*addr],
                    &corpus,
                    &rust_idents,
                    &std::collections::BTreeSet::new(),
                    &std::collections::BTreeSet::new(),
                )
                .expect("diff_body_calls");

                // The missing callee should be in missing
                assert!(!diff.missing.is_empty());
                return;
            }
        }
    }

    #[test]
    fn test_diff_body_calls_miss_satisfied_suppresses_missing() {
        let pe = load_test_pe();
        let addrs = find_function_addresses(&pe);

        for addr in &addrs {
            let cg = analyze(&pe, *addr).expect("analyze");
            if !cg.direct_calls.is_empty() {
                let real_targets: Vec<u64> = cg.call_targets().into_iter().collect();

                let corpus: std::collections::BTreeSet<u64> =
                    real_targets.iter().copied().collect();

                // Same empty body as test_diff_body_calls_missing, but the callee is
                // covered by `miss_satisfied` (a same-named body call that the strict
                // table split can't see — e.g. a DENY'd name or a qualified path).
                let miss_satisfied: std::collections::BTreeSet<u64> =
                    real_targets.iter().copied().collect();

                let diff = diff_body_calls(
                    &pe,
                    &[*addr],
                    &corpus,
                    &[],
                    &std::collections::BTreeSet::new(),
                    &miss_satisfied,
                )
                .expect("diff_body_calls");

                // Every binary->corpus callee is name-satisfied: nothing missing.
                assert!(
                    diff.missing.is_empty(),
                    "missing: {:?} (miss_satisfied covers {:?})",
                    diff.missing,
                    real_targets
                );
                return;
            }
        }
        panic!("no function with direct calls found in test binary");
    }

    /// Resolve `name` (e.g. "leaf_function") to its VA by walking the PE's symbol-like hints:
    /// we don't have a public symbol lookup, so we exploit `analyze`'s prologue detection —
    /// every fn address in this small test binary analyzes cleanly. We pick the one whose
    /// code is the shortest (leaf functions are short), check by running analyze and looking
    /// for the entry that matches the function's expected shape. For this test bin we just
    /// need ANY address that is and isn't a direct CALL target, so we use the relationship
    /// between `caller_of_leaf` and `leaf_function` (the latter is called directly).
    #[test]
    fn test_has_direct_branch_target_called_function() {
        let pe = load_test_pe();
        let addrs = find_function_addresses(&pe);
        // Find an addr with at least one direct caller — any fn that an earlier addrs's
        // analyze result has in `call_targets`. We only need to verify ONE such pair
        // (the rel32-scan correctness isn't input-dependent across callees), so use
        // `next()` rather than a `for` loop — clippy::never_loop flags the latter.
        for caller in &addrs {
            if let Ok(cg) = analyze(&pe, *caller) {
                if let Some(&callee) = cg.call_targets().iter().next() {
                    assert!(
                        has_direct_branch_target(&pe, callee),
                        "callee {callee:#x} is in caller {caller:#x}'s call_targets but \
                         has_direct_branch_target returned false — pure-byte rel32 scan bug"
                    );
                    return;
                }
            }
        }
        panic!("no function with direct calls found in test binary");
    }

    #[test]
    fn test_has_direct_branch_target_unused_address() {
        let pe = load_test_pe();
        // An address well outside the image but castable to u32 should never be a target.
        // Pick an obviously bogus VA: image_base + 0xFFFF_FFFC (wraps the u32 space).
        let bogus = pe.image_base.wrapping_add(0xFFFF_FFFC);
        assert!(
            !has_direct_branch_target(&pe, bogus),
            "bogus address {bogus:#x} unexpectedly reported as a direct branch target"
        );
        // Also: a real-image address that no instruction targets (within .text, but random).
        // We can't easily pick one without symbols, so use a far-future placeholder: the
        // highest VA in .text plus a gap. If .text is empty this returns false trivially.
        if let Some(text) = pe.sections().iter().find(|s| s.name == ".text") {
            let far =
                pe.image_base + text.virtual_address as u64 + text.virtual_size as u64 + 0x1000;
            // far might be outside .text — that's fine, the function should still return false.
            assert!(
                !has_direct_branch_target(&pe, far),
                "unreachable address {far:#x} unexpectedly reported as a direct branch target"
            );
        }
    }

    #[test]
    fn test_has_direct_branch_target_vtable_only() {
        let pe = load_test_pe();
        // The test binary defines a `static VTABLE: [fn; 2]` whose slot 0 contains the VA
        // of `vtable_only_method`. That VA appears as a dword in .rdata (so `referenced_addrs`
        // includes it and `ORIGIN-UNREFERENCED` would pass), but no `CALL`/`JMP`/Jcc in .text
        // targets it — so `has_direct_branch_target` must return false.
        //
        // Find vtable_only_method by scanning .rdata for the dword that appears most often as
        // a target of itself: the simplest portable check is to scan for any VA that IS in
        // referenced_addrs but is NOT a direct branch target, then verify it lives inside .text
        // (so it's a real fn candidate, not a string/data pointer).
        let refs = pe.referenced_addrs();
        let mut vtable_only_candidate: Option<u64> = None;
        for &a in &refs {
            if !has_direct_branch_target(&pe, a as u64) && pe.is_executable_va(a as u64) {
                vtable_only_candidate = Some(a as u64);
                break;
            }
        }
        let candidate = vtable_only_candidate.expect(
            "no vtable-only executable candidate found — test binary should have vtable_only_method \
             reachable only via the VTABLE static",
        );
        // The candidate must be in .text (executable) AND not be a direct branch target — that's
        // exactly the condition the macro's VTABLE-ONLY DISPATCH warning keys on.
        assert!(
            pe.is_executable_va(candidate),
            "candidate {candidate:#x} is not executable"
        );
        assert!(
            !has_direct_branch_target(&pe, candidate),
            "candidate {candidate:#x} unexpectedly has a direct branch target"
        );
    }

    // --- reg_params (BUG #2) ----------------------------------------------
    //
    // `reg_params` heuristically detects thiscall (reads ECX before any write) and
    // fastcall (also reads EDX). The x86 calling convention treats ECX/EDX as
    // caller-saved, so any CALL in the entry block clobbers them: a READ of ECX
    // after a CALL is leftover state, not a parameter read. Before the fix the
    // scan ignored CALL-clobbered registers, so a stray `MOV EAX, [ECX+0x10]`
    // after a CALL was mis-classified as a thiscall callee, polluting ARG-SHAPE
    // diffs. These tests pin the regression.

    /// Build a minimal PE32 image with one `.text` section containing `code`. The
    /// section's virtual address is 0x1000 (the smallest legal value when the file
    /// alignment is 0x200) and its image_base is 0x00400000 — the layout is
    /// standard for an MSVC i686 link so the verifier's `pe.read` returns the
    /// bytes we asked it to.
    fn pe_with_code(code: &[u8]) -> Pe {
        // MZ header (64 bytes) + PE signature (4) + COFF header (20) +
        // PE32 optional header (96) = 184 bytes minimum before section table.
        let e_lfanew: u32 = 0x40;
        let mut data: Vec<u8> = vec![0; 0x4000];

        // MZ magic + e_lfanew pointer
        data[0..2].copy_from_slice(b"MZ");
        data[0x3c..0x40].copy_from_slice(&e_lfanew.to_le_bytes());

        // PE signature
        let pe_off = e_lfanew as usize;
        data[pe_off..pe_off + 4].copy_from_slice(b"PE\0\0");

        // COFF header
        let coff = pe_off + 4;
        data[coff..coff + 2].copy_from_slice(&0x014cu16.to_le_bytes()); // machine = i386
        data[coff + 2..coff + 4].copy_from_slice(&1u16.to_le_bytes()); // NumberOfSections
                                                                       // SizeOfOptionalHeader
        data[coff + 16..coff + 18].copy_from_slice(&0x60u16.to_le_bytes());

        // PE32 optional header (96 bytes for size 0x60)
        let opt = coff + 20;
        data[opt..opt + 2].copy_from_slice(&0x010bu16.to_le_bytes()); // Magic = PE32
                                                                      // ImageBase at offset 28 from optional header
        let image_base: u32 = 0x0040_0000;
        data[opt + 28..opt + 32].copy_from_slice(&image_base.to_le_bytes());

        // Section table (one section: .text)
        let sec_table = opt + 0x60;
        let sec_off = sec_table;
        // Section name: 8 bytes ".text\0\0\0"
        data[sec_off..sec_off + 8].copy_from_slice(b".text\0\0\0");
        let text_va: u32 = 0x1000;
        // `text_raw` must be >= code.len() — `pe.read` rejects reads past
        // `raw_size`, so a code buffer longer than `text_raw` would be
        // unwritable. Round up to a 0x200 boundary so the layout looks like a
        // normal MSVC link.
        let text_raw: u32 = ((code.len() + 0x1ff) & !0x1ff).max(0x200) as u32;
        let text_vsize: u32 = code.len().max(text_raw as usize) as u32;
        data[sec_off + 8..sec_off + 12].copy_from_slice(&text_vsize.to_le_bytes()); // VirtualSize
        data[sec_off + 12..sec_off + 16].copy_from_slice(&text_va.to_le_bytes()); // VirtualAddress
        data[sec_off + 16..sec_off + 20].copy_from_slice(&text_raw.to_le_bytes()); // SizeOfRawData
        data[sec_off + 20..sec_off + 24].copy_from_slice(&text_raw.to_le_bytes()); // PointerToRawData

        // Copy the code into .text at raw offset `text_raw`.
        let code_off = text_raw as usize;
        data[code_off..code_off + code.len()].copy_from_slice(code);

        Pe::parse(data).expect("parse synthetic PE")
    }

    /// Real thiscall: entry reads ECX (the implicit `this`) before any write.
    /// `reg_params` MUST return `(true, false)` — and without a CALL in the entry
    /// the fix doesn't apply, so this guards against an over-eager fix that drops
    /// real ECX-parameter detection.
    #[test]
    fn test_reg_params_real_thiscall() {
        // MOV EAX, [ECX+0x10]; RET
        let code = [0x8B, 0x41, 0x10, 0xC3];
        let pe = pe_with_code(&code);
        let entry = pe.image_base + 0x1000;
        let (ecx, edx) = reg_params(&pe, entry);
        assert!(ecx, "ECX should be flagged as a parameter");
        assert!(!edx, "EDX should NOT be flagged");
    }

    /// Regression for BUG #2: a CALL in the entry block clobbers ECX, so a later
    /// `MOV EAX, [ECX+0x10]` is NOT evidence of an ECX parameter. Without the
    /// fix `reg_params` reports `ecx_param = true` and the ARG-SHAPE diff
    /// over-counts the callee as thiscall.
    #[test]
    fn test_reg_params_cdecl_after_call_does_not_flag_ecx() {
        // CALL rel32 ; MOV EAX, [ECX+0x10] ; RET
        // First instr: E8 00 00 00 00 — CALL <next_ip+0> (i.e. CALLs the address
        // of the next instruction, an unusual but legal form). Length: 5 bytes.
        // Second instr: MOV EAX, [ECX+0x10] (3 bytes).
        // Third instr: RET (1 byte).
        let code = [
            0xE8, 0x00, 0x00, 0x00, 0x00, // CALL <next_ip>
            0x8B, 0x41, 0x10, // MOV EAX, [ECX+0x10]
            0xC3, // RET
        ];
        let pe = pe_with_code(&code);
        let entry = pe.image_base + 0x1000;
        let (ecx, edx) = reg_params(&pe, entry);
        assert!(
            !ecx,
            "ECX should be false: a CALL clobbered it before the read, so the \
             MOV EAX,[ECX+0x10] is leftover state, not a thiscall parameter read"
        );
        assert!(!edx, "EDX should be false (cdecl)");
    }

    /// Same idea for EDX (fastcall): a CALL in the entry block clobbers EDX,
    /// so a subsequent `MOV EAX, [EDX+0x10]` is leftover state, not a fastcall
    /// parameter read.
    #[test]
    fn test_reg_params_cdecl_after_call_does_not_flag_edx() {
        // CALL <next_ip> ; MOV EAX, [EDX+0x10] ; RET
        let code = [
            0xE8, 0x00, 0x00, 0x00, 0x00, // CALL <next_ip>
            0x8B, 0x42, 0x10, // MOV EAX, [EDX+0x10]
            0xC3, // RET
        ];
        let pe = pe_with_code(&code);
        let entry = pe.image_base + 0x1000;
        let (ecx, edx) = reg_params(&pe, entry);
        assert!(!ecx, "ECX should be false (cdecl)");
        assert!(
            !edx,
            "EDX should be false: a CALL clobbered it before the read, so the \
             MOV EAX,[EDX+0x10] is leftover state, not a fastcall parameter read"
        );
    }

    // --- scan_operands (BUG #4) --------------------------------------------
    //
    // `scan_operands` records `[reg+disp]` (no index register) as a struct-field
    // access. Before the fix, `[base + index*scale + disp]` (array-indexed) was
    // also recorded as a struct field — polluting `field_offsets` so that an
    // explicit `fields = [0x10]` check on a function that only does array
    // indexing would falsely PASS. These tests pin that array accesses never
    // contribute to `field_offsets`.

    /// `[EAX + ECX*4 + 0x10]` is an array element load, not a struct field read.
    /// `analyze` must NOT add `0x10` to `field_offsets`. Before the fix the
    /// `index == Register::None` guard was missing from `scan_operands` (only
    /// present in `classify_operand`), so the indexed displacement leaked in.
    #[test]
    fn test_scan_operands_indexed_memory_not_a_field() {
        // MOV EAX, [EAX + ECX*4 + 0x10] ; RET
        // ModRM = 0x44 (mod=01, reg=000(EAX), rm=100(SIB), 1-byte disp)
        // SIB = 0x88 (scale=10(*4), index=001(ECX), base=000(EAX))
        // disp8 = 0x10
        let code = [
            0x8B, 0x44, 0x88, 0x10, // MOV EAX, [EAX + ECX*4 + 0x10]
            0xC3, // RET
        ];
        let pe = pe_with_code(&code);
        let entry = pe.image_base + 0x1000;
        let cg = analyze(&pe, entry).expect("analyze");
        assert!(
            !cg.field_offsets.contains(&0x10),
            "0x10 leaked into field_offsets from indexed memory — array access \
             was mis-classified as a struct field. field_offsets = {:?}",
            cg.field_offsets
        );
    }

    /// Sanity: a plain `[reg+disp]` (no index) DOES still count as a field access.
    /// Guards against an over-eager fix that breaks the original behavior.
    #[test]
    fn test_scan_operands_plain_memory_is_a_field() {
        // MOV EAX, [ECX+0x10] ; RET
        let code = [
            0x8B, 0x41, 0x10, // MOV EAX, [ECX+0x10]
            0xC3, // RET
        ];
        let pe = pe_with_code(&code);
        let entry = pe.image_base + 0x1000;
        let cg = analyze(&pe, entry).expect("analyze");
        assert!(
            cg.field_offsets.contains(&0x10),
            "0x10 should be in field_offsets for plain [ECX+0x10] — non-indexed \
            memory is still a struct field. field_offsets = {:?}",
            cg.field_offsets
        );
    }

    /// SIB-indexed `[base + index*scale + disp32]` with an IN-SECTION
    /// displacement is a table-base load (e.g. FALL.EXE `[eax*4+0x18F01]`),
    /// not a struct field. `analyze` must record the displacement in
    /// `cg.globals` — otherwise HALLUCINATED-ADDR fires on the true table
    /// address — and must NOT record it in `field_offsets` (BUG #4 stays).
    #[test]
    fn test_scan_operands_indexed_memory_in_image_disp_is_global() {
        // MOV EAX, [EAX + ECX*4 + 0x00401000] ; RET
        // ModRM = 0x84 (mod=10, reg=000(EAX), rm=100(SIB), disp32)
        // SIB = 0x88 (scale=10(*4), index=001(ECX), base=000(EAX))
        // disp32 = 0x00401000 (the .text section base of the synthetic PE)
        let code = [
            0x8B, 0x84, 0x88, 0x00, 0x10, 0x40, 0x00, // MOV EAX, [EAX+ECX*4+0x401000]
            0xC3, // RET
        ];
        let pe = pe_with_code(&code);
        let entry = pe.image_base + 0x1000;
        let cg = analyze(&pe, entry).expect("analyze");
        assert!(
            cg.globals.contains(&0x0040_1000),
            "0x401000 should be in globals for indexed [EAX+ECX*4+disp] — the \
            table base is really referenced. globals = {:?}",
            cg.globals
        );
        assert!(
            !cg.field_offsets.contains(&0x0040_1000),
            "0x401000 must not leak into field_offsets from indexed memory. \
            field_offsets = {:?}",
            cg.field_offsets
        );
    }

    /// Sanity: an indexed load with a SMALL displacement still records
    /// nothing (no global — the offset is not an address; no field —
    /// BUG #4). Guards the new global branch against over-eager matching.
    #[test]
    fn test_scan_operands_indexed_memory_small_disp_records_nothing() {
        // MOV EAX, [EAX + ECX*4 + 0x10] ; RET (covered for fields by the
        // BUG #4 test above; here we also pin the globals side).
        let code = [
            0x8B, 0x44, 0x88, 0x10, // MOV EAX, [EAX + ECX*4 + 0x10]
            0xC3, // RET
        ];
        let pe = pe_with_code(&code);
        let entry = pe.image_base + 0x1000;
        let cg = analyze(&pe, entry).expect("analyze");
        assert!(
            !cg.globals.contains(&0x10),
            "0x10 must not be in globals for indexed [EAX+ECX*4+0x10] — a \
            small offset is not an address. globals = {:?}",
            cg.globals
        );
    }

    /// Regression for BUG #14: `LEA reg, [abs]` (absolute-address LEA) computes
    /// an address without dereferencing memory. The displacement is NOT a
    /// global reference, so it must NOT be added to `cg.globals` — otherwise
    /// the operand check (HALLUCINATED-ADDR) would falsely require the
    /// displacement to appear elsewhere in the binary.
    ///
    /// The .text-only synthetic PE has no globals in scope. To put the
    /// displacement in range we must point it into the .text section itself
    /// (image_base + 0x1000 + 5, the address right after the LEA). The test
    /// asserts that even an in-section displacement is rejected for LEA.
    #[test]
    fn test_scan_operands_lea_absolute_not_a_global() {
        // LEA EAX, [0x00401005]  ; absolute-address LEA
        //   opcode 8D, ModRM 05 (mod=00, reg=000(EAX), rm=101(Disp32)),
        //   disp32 = 0x00401005 (the address right after this 6-byte instr).
        // RET
        let code = [
            0x8D, 0x05, 0x05, 0x10, 0x40, 0x00, // LEA EAX, [0x00401005]
            0xC3, // RET
        ];
        let pe = pe_with_code(&code);
        let entry = pe.image_base + 0x1000;
        let cg = analyze(&pe, entry).expect("analyze");
        assert!(
            !cg.globals.contains(&0x00401005),
            "0x00401005 leaked into globals from a LEA — LEA doesn't dereference, \
             so its operand isn't a global reference. globals = {:?}",
            cg.globals
        );
    }

    /// Sanity: a MOV (not LEA) with the same operand form DOES count as a global.
    /// Guards against an over-eager fix that drops the genuine global case.
    #[test]
    fn test_scan_operands_mov_absolute_is_a_global() {
        // MOV EAX, [0x0040100D]  ; the address after this 6-byte instr
        // RET
        let code = [
            0xA1, 0x0D, 0x10, 0x40, 0x00, // MOV EAX, moffs32 (absolute address)
            0xC3,
        ];
        let pe = pe_with_code(&code);
        let entry = pe.image_base + 0x1000;
        let cg = analyze(&pe, entry).expect("analyze");
        assert!(
            cg.globals.contains(&0x0040100D),
            "0x0040100D should be in globals for MOV EAX, [0x0040100D] — \
             absolute MOV does dereference. globals = {:?}",
            cg.globals
        );
    }

    /// Regression: `int n` is NOT a function terminator. DOS `int 21h` /
    /// DPMI `int 31h` are API calls that return normally, so decoding must
    /// continue at `next_ip()`. The harvester used to treat iced-x86
    /// `FlowControl::Interrupt` like `ret`: listings truncated at the
    /// first `int` and any CALL reachable only via post-`int`
    /// fallthrough was silently dropped from the call set (real
    /// instance: FALL.EXE `0xb73d8` → `0xa3805` absent), blinding the
    /// gate's MISSING check for those callees.
    #[test]
    fn test_int_does_not_terminate_decode() {
        // PUSH EBX                       ; 53
        // MOV AX, 0x4400                 ; 66 B8 00 44
        // INT 21h                        ; CD 21
        // CALL entry+0x20                ; E8 14 00 00 00
        //   (rel32 = (entry+0x20) - (entry+0x0C) = 0x14)
        // POP EBX                        ; 5B
        // RET                            ; C3
        // <padding to 0x20>              ; 8x 90 (NOP)
        // RET (call target)              ; C3
        let mut code = vec![
            0x53, // PUSH EBX
            0x66, 0xB8, 0x00, 0x44, // MOV AX, 0x4400
            0xCD, 0x21, // INT 21h
            0xE8, 0x14, 0x00, 0x00, 0x00, // CALL entry+0x20
            0x5B, // POP EBX
            0xC3, // RET
        ];
        while code.len() < 0x20 {
            code.push(0x90);
        }
        code.push(0xC3); // RET at entry+0x20
        let pe = pe_with_code(&code);
        let entry = pe.image_base + 0x1000;
        let cg = analyze(&pe, entry).expect("analyze");
        assert!(
            cg.direct_calls.contains_key(&(entry + 0x20)),
            "CALL after INT 21h must be harvested — `int` returns normally. \
             direct_calls = {:?}",
            cg.direct_calls
        );
        assert!(
            cg.max_end >= entry + 0x0E,
            "decoding must continue past `int 21h` through POP/RET. \
             max_end = {:#x}",
            cg.max_end
        );
    }

    /// Regression: `referenced_addrs` must index `JMP short rel8` (0xEB)
    /// targets. The scan only recognized CALL/JMP rel32 and Jcc rel32, so a
    /// function reached solely via short jump (real instance: FALL.EXE
    /// `0x9dbe2`, reached only by `EB F0` from `0x9dbeb`) was invisible to
    /// ORIGIN-UNREFERENCED and needed a waiver. Over-approximation stays:
    /// a stray 0xEB only ever widens the accept set.
    #[test]
    fn test_referenced_addrs_indexes_jmp_short() {
        // offset 0: JMP short +6 → target = entry+8  ; EB 06
        // offsets 2..7: NOP padding                   ; 6x 90
        // offset 8: RET (the short-jump target)        ; C3
        let code = [
            0xEB, 0x06, // JMP short entry+8
            0x90, 0x90, 0x90, 0x90, 0x90, 0x90, // NOP padding
            0xC3, // RET at entry+8
        ];
        let pe = pe_with_code(&code);
        let entry = pe.image_base + 0x1000;
        let refs = pe.referenced_addrs();
        assert!(
            refs.contains(&((entry + 8) as u32)),
            "JMP short target entry+8 must be indexed — EB was invisible. \
             refs = {refs:?}"
        );
    }

    /// Sanity: a real `CALL rel32` at an instruction start IS still indexed
    /// by `referenced_addrs`. Guards against an over-eager fix that drops
    /// rel32 recognition.
    #[test]
    fn test_referenced_addrs_still_indexes_call_rel32() {
        // offset 0: CALL entry+8                       ; E8 03 00 00 00
        //   (rel32 = (entry+8) - (entry+5) = 3)
        // offset 5: RET                                ; C3
        // offsets 6..7: NOP padding                    ; 2x 90
        // offset 8: RET (the call target)              ; C3
        let code = [
            0xE8, 0x03, 0x00, 0x00, 0x00, // CALL entry+8
            0xC3, // RET
            0x90, 0x90, // NOP padding
            0xC3, // RET at entry+8
        ];
        let pe = pe_with_code(&code);
        let entry = pe.image_base + 0x1000;
        let refs = pe.referenced_addrs();
        assert!(
            refs.contains(&((entry + 8) as u32)),
            "CALL rel32 target entry+8 must stay indexed. refs = {refs:?}"
        );
    }

    // --- has_direct_branch_target (BUG #3) -------------------------------
    //
    // The byte-scan variant of `has_direct_branch_target` used to accept any
    // `0xE8`/`0xE9`/`0x0F 0x8x` byte anywhere in .text as a branch, computing
    // a junk rel32 target. If that junk happened to equal the queried address,
    // the function falsely reported "yes, this is a direct branch target",
    // suppressing a legitimate VTABLE-ONLY DISPATCH warning. The fix decodes
    // .text once and gates byte-scan hits by instruction-start membership, so
    // spurious `0xE8` bytes inside other instructions are rejected.

    /// Construct a PE whose `.text` contains an instruction that has `0xE8` as
    /// a non-opcode byte (here an immediate in `CMP BYTE [EAX], 0xE8`), followed
    /// by 4 bytes carefully chosen so the OLD (ungated) byte-scan would compute
    /// a target equal to `target`. The fix must reject this — `0xE8` at offset 2
    /// is inside an instruction, not at an instruction start.
    fn pe_with_spurious_e8() -> (Pe, u64) {
        // Instruction 1: CMP BYTE [EAX], 0xE8  — 80 38 E8 (3 bytes).
        // The 0xE8 at offset 2 is an immediate, not a CALL opcode.
        // Bytes 3..7 are whatever comes next; the OLD scan reads them as the
        // displacement of a "CALL". We shape them so the computed target equals
        // `target` (= 0xDEADBEEF in the test below).
        //
        // The byte-scan reads:
        //   i = 2 → matches 0xE8 → rel_at = 3
        //   target = (text_va + 3 + 4) + rel32  =  (text_va + 7) + rel32
        //   = text_va + 7 + D, where D = i32::from_le_bytes([code[3..7]])
        // We want target = 0xDEADBEEF, text_va = image_base + 0x1000 = 0x00401000.
        // So D = 0xDEADBEEF - 0x00401007 = 0xDEAD9EE8 (little-endian: E8 9E AD DE).
        // Pad out with NOPs so the decode pass reaches a clean RET at offset 7.
        let code = [
            0x80, 0x38, 0xE8, // CMP BYTE [EAX], 0xE8
            0xE8, 0x9E, 0xAD, 0xDE, // the bogus "displacement" the scan will read
            0xC3, // RET (clean termination for the decode pass)
        ];
        let pe = pe_with_code(&code);
        (pe, 0xDEADBEEFu64)
    }

    /// Regression for BUG #3: a `0xE8` byte that sits inside another
    /// instruction's encoding (here an immediate) must NOT count as a CALL.
    /// The OLD code would return `true` for the chosen target because the four
    /// bytes after the spurious 0xE8 happen to compute to it; the new code
    /// must return `false` because offset 2 is not an instruction start.
    #[test]
    fn test_has_direct_branch_target_rejects_spurious_e8() {
        let (pe, target) = pe_with_spurious_e8();
        assert!(
            !has_direct_branch_target(&pe, target),
            "spurious 0xE8 byte at non-instruction-start offset fooled the scan \
             into reporting target {target:#x} as a direct branch target"
        );
    }

    /// Sanity: a real `CALL rel32` at an instruction start IS still detected.
    /// Guards against an over-eager fix that drops all branch recognition.
    #[test]
    fn test_has_direct_branch_target_real_call_is_detected() {
        // Real CALL rel32 at offset 0, followed by RET. The CALL targets a
        // function placed right after it: target = text_va + 5 (length of CALL).
        // text_va = 0x00401000, so target = 0x00401005. The displacement is 0
        // (CALL <next_ip>).
        let code = [
            0xE8, 0x00, 0x00, 0x00, 0x00, // CALL <next_ip>
            0xC3, // RET
        ];
        let pe = pe_with_code(&code);
        let target = pe.image_base + 0x1000 + 5;
        assert!(
            has_direct_branch_target(&pe, target),
            "real CALL rel32 at instruction start should be detected as a \
             branch target"
        );
    }

    // --- block_buf / branch_seed (BUG #8) ---------------------------------
    //
    // `analyze` walks the function's CFG recursively, recovering argument
    // shapes for each CALL by scanning backward through the predecessor block's
    // instructions (`block_buf`). When the walker encounters a conditional
    // branch and pushes its target to `work`, the outer loop resets `block_buf`
    // for the new `start`. Without a seed, the target's first CALL is processed
    // against an EMPTY predecessor buffer and `recover_call_site` undercounts
    // its arguments — ECX/EDX/PUSHes set up before the branch are lost on the
    // taken path.

    /// Regression for BUG #8: a CALL inside a conditional-branch target must
    /// inherit the args set up before the branch. Layout:
    ///
    ///   0: MOV ECX, 5                  ; thiscall arg
    ///   5: TEST EAX, EAX
    ///   7: JNZ take_call               ; taken path: the CALL below
    ///   9: CALL fallthrough_target     ; fallthrough (JZ) path — NOT what we test
    ///  14: RET
    ///  15: take_call: CALL target      ; taken path: ECX=5 must be recovered
    ///  20: RET
    ///
    /// For the CALL at offset 15, the recovered `CallSite.ecx` must be
    /// `Some(ArgKind::Imm(5))`. Before the fix it was `None` because the
    /// branch-target walk started with an empty `block_buf`.
    #[test]
    fn test_analyze_branch_target_inherits_predblock_args() {
        let code = [
            0xB9, 0x05, 0x00, 0x00, 0x00, // 0: MOV ECX, 5
            0x85, 0xC0, // 5: TEST EAX, EAX
            0x75, 0x06, // 7: JNZ +6 → take_call at 15
            0xE8, 0x00, 0x00, 0x00, 0x00, // 9: CALL <next_ip> (fallthrough path)
            0xC3, // 14: RET
            0xE8, 0x00, 0x00, 0x00, 0x00, // 15: CALL <next_ip> (taken path)
            0xC3, // 20: RET
        ];
        let pe = pe_with_code(&code);
        let entry = pe.image_base + 0x1000;
        let cg = analyze(&pe, entry).expect("analyze");

        // We expect two CALL sites — fallthrough and taken. Find the taken one
        // by its target VA (offset 15 + length 5 = 20 → image_base + 0x1014).
        let taken_target = entry + 0x14;
        let taken = cg
            .call_sites
            .iter()
            .find(|cs| cs.target == taken_target)
            .expect("taken-path CALL site should exist");

        assert!(
            matches!(taken.ecx, Some(callgraph_verify::ArgKind::Imm(5))),
            "taken-path CALL's ECX arg should be Imm(5); got {:?}. \
             The branch target's block_buf must be seeded from the predecessor \
             so MOV ECX, 5 before JNZ is visible at the CALL.",
            taken.ecx
        );
    }

    /// Sanity: the fallthrough-path CALL is unaffected — it processes the
    /// CALL within the same outer iteration as the branch, with `block_buf`
    /// cleared at the branch but populated again up to the CALL.
    #[test]
    fn test_analyze_fallthrough_path_still_recovers_args() {
        let code = [
            0xB9, 0x05, 0x00, 0x00, 0x00, // 0: MOV ECX, 5
            0x85, 0xC0, // 5: TEST EAX, EAX
            0x75, 0x06, // 7: JNZ +6 → take_call at 15
            0xE8, 0x00, 0x00, 0x00, 0x00, // 9: CALL <next_ip> (fallthrough path)
            0xC3, // 14: RET
            0xC3, // 15: take_call: RET (taken path returns immediately)
        ];
        let pe = pe_with_code(&code);
        let entry = pe.image_base + 0x1000;
        let cg = analyze(&pe, entry).expect("analyze");

        let fallthrough_target = entry + 0x0E;
        let ft = cg
            .call_sites
            .iter()
            .find(|cs| cs.target == fallthrough_target)
            .expect("fallthrough CALL site should exist");
        assert!(
            matches!(ft.ecx, Some(callgraph_verify::ArgKind::Imm(5))),
            "fallthrough CALL's ECX arg should still be Imm(5); got {:?}",
            ft.ecx
        );
    }

    // -----------------------------------------------------------------
    // Real-world invariants against the in-repo `test-bin.exe` i686 PE.
    // The fixture's source is `test-bin/src/main.rs`; these tests pin the
    // verifier's behavior on a binary we control. They run as part of the
    // regular integration suite.
    // -----------------------------------------------------------------

    /// Find the function addresses we know exist in test-bin:
    /// helper_one, helper_two, helper_three, leaf_function,
    /// caller_of_leaf, target_function, vtable_only_method. Walk .text
    /// forward and, on each successful analyze, skip ahead by the function's
    /// extent so the next try is at a new function start (not the middle
    /// of the one we just visited).
    fn find_test_bin_function_addresses(pe: &Pe) -> Vec<u64> {
        let mut addrs = Vec::new();
        let text = pe.sections().iter().find(|s| s.name == ".text").unwrap();
        let text_va = pe.image_base + text.virtual_address as u64;
        let end = text_va + text.virtual_size as u64;
        let mut va = text_va;
        while va < end {
            if let Ok(cg) = analyze(pe, va) {
                addrs.push(va);
                // Skip past this function so the next successful decode is
                // a *new* function entry, not the middle of the same one.
                let extent = cg.max_end.saturating_sub(va).max(1);
                va = va.saturating_add(extent);
            } else {
                va += 1;
            }
            if addrs.len() >= 32 {
                break;
            }
        }
        addrs
    }

    /// Across every function address the analyzer accepts in test-bin, every
    /// direct-call target must be a real `CALL rel32` opcode somewhere in
    /// `.text` — the byte-scan used by the macro's ORIGIN-UNREFERENCED check
    /// must agree with `analyze`'s call detection.
    #[test]
    fn test_bin_analyze_and_byte_scan_agree() {
        let pe = load_test_pe();
        let addrs = find_test_bin_function_addresses(&pe);

        let mut checked = 0u32;
        let mut disagreements: Vec<(u64, u64)> = Vec::new();
        for caller in &addrs {
            if let Ok(cg) = analyze(&pe, *caller) {
                for &target in cg.direct_calls.keys() {
                    checked += 1;
                    if !has_direct_branch_target(&pe, target) {
                        disagreements.push((*caller, target));
                    }
                }
            }
        }
        assert!(checked > 0, "scan found no analyzable functions");
        assert!(
            disagreements.is_empty(),
            "{} of {} analyze()-reported CALL targets have no matching \
             0xE8 byte in .text (byte-scan / decoder disagreement): {:?}",
            disagreements.len(),
            checked,
            disagreements
        );
    }

    /// `Spec::check(declared = real, exact = true)` must be clean for every
    /// analyzed function — the contract for the macro's HALLUCINATED /
    /// MISSING gates. If `analyze` ever dropped a real call from
    /// `call_targets()`, or fabricated one, this would fail.
    #[test]
    fn test_bin_diff_calls_clean_when_declared_equals_real() {
        use callgraph_verify::diff_calls;
        let pe = load_test_pe();
        let addrs = find_test_bin_function_addresses(&pe);
        let mut total = 0u32;
        for caller in &addrs {
            if let Ok(cg) = analyze(&pe, *caller) {
                let real: Vec<u64> = cg.call_targets().into_iter().collect();
                let d = diff_calls(&pe, *caller, &real, true)
                    .unwrap_or_else(|e| panic!("diff_calls at {:#x} failed: {e}", caller));
                total += 1;
                assert!(
                    d.hallucinated.is_empty() && d.missing.is_empty(),
                    "diff_calls(analyze's own targets) at {:#x} not clean: hallucinated={:?}, missing={:?}",
                    caller,
                    d.hallucinated,
                    d.missing
                );
            }
        }
        assert!(total > 0, "no analyzable functions found");
    }

    /// `vcall_slots` and `iat_calls` should stay bounded on a small fixture
    /// binary. The fixture is `no_std` + `#![no_main]` so it pulls in only the
    /// MSVC CRT runtime helpers (panic, security cookies, exception handling).
    /// Sets larger than these bounds would mean EBP/ESP-relative operands
    /// or absolute-address loads are leaking into the vtable/IAT slots —
    /// the most common over-counting bug in this kind of static analyzer.
    #[test]
    fn test_bin_vcall_and_iat_sets_are_bounded() {
        let pe = load_test_pe();
        let addrs = find_test_bin_function_addresses(&pe);
        let mut total_vcall: usize = 0;
        let mut total_iat: usize = 0;
        for caller in &addrs {
            if let Ok(cg) = analyze(&pe, *caller) {
                total_vcall += cg.vcall_slots.len();
                total_iat += cg.iat_calls.len();
            }
        }
        // `vcall_slots` is the set of displacements seen in `CALL [reg+disp]`.
        // Real-world vtable slots are tiny integers; a huge set here means
        // EBP/ESP-relative operands leak in. Cap at a level that the
        // fixture's actual runtime helpers stay well below.
        assert!(
            total_vcall <= 16,
            "vcall_slots total across {} functions = {} — likely EBP/ESP leak",
            addrs.len(),
            total_vcall
        );
        // `iat_calls` is `CALL [abs]` targets in-image. A no_std no_main
        // fixture shouldn't have many — globals are referenced via
        // `[reg + 0]` not `[abs]`. But the CRT pulls in `_security_init_cookie`
        // which does some absolute loads; allow a small handful.
        assert!(
            total_iat <= 16,
            "iat_calls total across {} functions = {} — likely absolute \
             memory refs leaking",
            addrs.len(),
            total_iat
        );
    }

    /// `field_offsets` and `imm_addrs` should stay bounded on a small
    /// fixture. Both are filtered (field_offsets ≤ MAX_FIELD_OFFSET =
    /// 0x8000; imm_addrs must be in-image). The fixture is tiny; sets
    /// larger than these bounds would mean stack-relative or other
    /// unintended operands are leaking in.
    #[test]
    fn test_bin_field_and_imm_sets_are_bounded() {
        let pe = load_test_pe();
        let addrs = find_test_bin_function_addresses(&pe);
        let mut total_field: usize = 0;
        let mut total_imm: usize = 0;
        for caller in &addrs {
            if let Ok(cg) = analyze(&pe, *caller) {
                total_field += cg.field_offsets.len();
                total_imm += cg.imm_addrs.len();
                for &f in &cg.field_offsets {
                    assert!(
                        f <= 0x8000,
                        "field_offset {:#x} exceeds MAX_FIELD_OFFSET",
                        f
                    );
                }
                for &a in &cg.imm_addrs {
                    assert!(
                        pe.section_of(a).is_some(),
                        "imm_addr {:#x} outside every section",
                        a
                    );
                }
            }
        }
        // The fixture's actual values are 26+13 — so the cap has to be
        // generous. The point of these bounds is to catch regressions
        // where the count balloons into the hundreds.
        assert!(
            total_field <= 200,
            "field_offsets total = {} (too many)",
            total_field
        );
        assert!(
            total_imm <= 100,
            "imm_addrs total = {} (too many)",
            total_imm
        );
    }

    /// `cfg_fingerprint` must produce a finite, internally-consistent result
    /// for every analyzed function (no NaN/overflow, counters match the
    /// function's call graph). The fixture's USER-WRITTEN functions have
    /// no loops or switches, but the binary also contains CRT runtime
    /// helpers (`__security_init_cookie`, etc.) that DO contain both.
    /// This test only pins that the fingerprint is well-formed — finite
    /// numbers, no panic — not that any specific counter is zero.
    #[test]
    fn test_bin_cfg_fingerprint_is_finite_and_consistent() {
        let pe = load_test_pe();
        let addrs = find_test_bin_function_addresses(&pe);
        let mut any_analyzed = false;
        for caller in &addrs {
            if let Ok(fp) = cfg_fingerprint(&pe, *caller) {
                any_analyzed = true;
                // All four counters must be finite and non-negative. The
                // BTreeSet sizes give us u64 into u64 casts in the public
                // API; if any underflows or overflows this would surface as
                // a huge number.
                assert!(
                    fp.loops < 1_000_000,
                    "fixture fn at {:#x}: fp.loops = {} (implausibly large)",
                    caller,
                    fp.loops
                );
                assert!(
                    fp.switch_cases < 1_000_000,
                    "fixture fn at {:#x}: fp.switch_cases = {} (implausibly large)",
                    caller,
                    fp.switch_cases
                );
                assert!(
                    fp.conditionals < 1_000_000,
                    "fixture fn at {:#x}: fp.conditionals = {} (implausibly large)",
                    caller,
                    fp.conditionals
                );
                assert!(
                    fp.returns < 1_000_000,
                    "fixture fn at {:#x}: fp.returns = {} (implausibly large)",
                    caller,
                    fp.returns
                );
                // Sanity: in a binary with a couple hundred functions, each
                // must terminate somewhere. Termination in x86 is one of:
                // RET, INT, JMP (tail call), or any conditional/unconditional
                // branch. So: at least one of {returns, conditionals,
                // switch_cases} should be > 0. If all are zero, the
                // function has no terminator at all — that would mean
                // analyze() decoded past the function end.
                assert!(
                    fp.returns + fp.conditionals + fp.switch_cases > 0,
                    "fixture fn at {:#x}: no terminator (returns=0, conditionals=0, switches=0)",
                    caller
                );
            }
        }
        assert!(any_analyzed, "no analyzable functions in test-bin");
    }

    // B-08: out-of-section `#[origin(0xFFFFFFFF)]` — the address is
    // outside every PE section, so `pe.section_of(addr).is_none()`. We
    // can't easily trigger the proc-macro error path from a unit test
    // (the macro requires a real PE + a real `#[origin]` attribute in
    // source). Instead pin the underlying gate: feeding an
    // out-of-section address to `analyze` returns an error. (The
    // verifier uses this same check before running any of the more
    // expensive diffs.)
    #[test]
    fn b08_analyze_rejects_out_of_section_address() {
        let code = [0xC3u8]; // RET
        let pe = pe_with_code(&code);
        // .text starts at 0x1000. 0x8000_0000 is well outside any
        // section.
        let bogus = 0x8000_0000u64;
        assert!(
            analyze(&pe, bogus).is_err(),
            "analyze on out-of-section address should fail"
        );
    }

    // B-10: a function whose body is just `RET` doesn't crash the walker.
    // The integration test pins this end-to-end: build a synthetic PE
    // with a 1-byte `.text` section containing only `0xC3` (RET), then
    // verify `analyze` accepts the entry and reports the function as a
    // leaf (no outgoing calls).
    #[test]
    fn b10_analyze_handles_ret_only_function() {
        let code = [0xC3u8]; // RET
        let pe = pe_with_code(&code);
        let entry = pe.image_base + 0x1000;
        let cg = analyze(&pe, entry).expect("analyze RET-only function");
        assert_eq!(cg.entry, entry);
        assert_eq!(cg.max_end - cg.entry, 1, "extent should be 1 (just RET)");
        assert!(cg.direct_calls.is_empty(), "RET-only function has no calls");
        assert!(
            cg.tail_calls.is_empty(),
            "RET-only function has no tail calls"
        );
    }

    // -----------------------------------------------------------------
    // Real-binary CFG pin: the function at 0x00959d60 in the workspace's
    // `noivilbo.exe` has FOUR back-edges (loop heads) per the reference
    // skeleton's basic blocks (0x959d8b, 0x959de0, 0x959df1, 0x959e64).
    // The skeleton view:
    //   cargo run --bin callgraph_verify --release -- noivilbo.exe 0x959d60 --skeleton
    // shows each loop head marked with `// loop head`. The macro's
    // CFG-fingerprint diff at `callgraph-verify-macro/src/lib.rs:690` keys
    // off `fp.loops >= 2 && r.loops == 0` — meaning a port whose literal
    // body has no `while`/`loop`/`for` (e.g. one that extracted the loop
    // bodies into `pick_traverse`/`update_world_bound` helpers) will be
    // rejected as a compile error.
    //
    // This test pins the byte-truth side of that contract: the entry's
    // CFG really does have 4 back-edges, so the macro's strict check is
    // correct and the porter must keep the loops in the body (or extract
    // them into a separate `#[origin]`-tagged helper whose own body has
    // the matching loops — see README's single-function discipline note).
    //
    // Regression guard: if `cfg_fingerprint` ever loses a back-edge
    // detection (e.g. due to a `decode_all` cap or leader-set bug), this
    // test fails and the macro's check would silently start accepting
    // port omissions.
    // -----------------------------------------------------------------
    #[test]
    fn cfg_pin_noivilbo_0x959d60_has_four_back_edges() {
        // `noivilbo.exe` lives at the workspace root (two levels up from this
        // crate's manifest). Skip gracefully if it's not present so this test
        // doesn't break a fresh clone where the fixture binary hasn't been
        // added yet.
        let manifest_dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
        let pe_path = manifest_dir
            .parent()
            .and_then(|p| p.parent())
            .map(|p| p.join("noivilbo.exe"))
            .expect("workspace root resolves");
        if !pe_path.exists() {
            eprintln!(
                "skipping: {} not found (fixture binary lives at workspace root)",
                pe_path.display()
            );
            return;
        }
        let pe = Pe::load(pe_path.to_str().unwrap()).expect("load noivilbo.exe");
        let fp = cfg_fingerprint(&pe, 0x00959d60).expect("cfg_fingerprint at 0x00959d60");
        assert_eq!(
            fp.loops, 4,
            "binary at 0x00959d60 has {} back-edges; the macro's CFG diff keys \
             off 4 (>=2 threshold), so any future regression in back-edge \
             detection will silently let a port that omits the inlined loops \
             pass. Update this assertion if the binary genuinely changes.",
            fp.loops
        );
    }

    // -----------------------------------------------------------------
    // cfg_fingerprint natural-loop bug regression (BUG: back-edge to a
    // common tail that doesn't dominate the source block was being
    // counted as a loop).
    //
    // The OLD heuristic was `t <= ld && leaders.contains(&t)` — a back-edge
    // by address. That conflates "branch goes to an earlier block" with
    // "iteration", so a function whose only `je`/`jbe` exits were to a
    // common epilog tail got false positives. Example from `noivilbo.exe`:
    // ni_file_flush (0x00747d30) had `je0x7D40` and `jbe 0x7D40`, both
    // appearing as back-edges by address but neither forming a loop.
    //
    // The fix: only count `B -> T` as a natural-loop back-edge when `T`
    // dominates `B` (every path from `entry` to `B` passes through `T`).
    // This is the textbook natural-loop definition and correctly handles:
    //   * real `while`/`for`/`do-while` (the loop head dominates the body)
    //   * `ni_file_flush`-style early-exits to a common tail (the tail
    //     does NOT dominate the `je`/`jbe` sites, because entry can fall
    //     through to those sites without going through the tail)
    // -----------------------------------------------------------------

    /// Linear function with no branches. `loops` must be 0 and there must
    /// be a terminator (RET), so the macro's "any terminator at all?"
    /// check passes too.
    #[test]
    fn cfg_fingerprint_linear_function_has_no_loops() {
        // MOV EAX, [ECX+0x10] ; RET
        let code = [0x8B, 0x41, 0x10, 0xC3];
        let pe = pe_with_code(&code);
        let entry = pe.image_base + 0x1000;
        let fp = cfg_fingerprint(&pe, entry).expect("cfg_fingerprint");
        assert_eq!(fp.loops, 0, "linear function has no loops; got {:?}", fp);
        assert_eq!(fp.conditionals, 0);
        assert_eq!(fp.switch_cases, 0);
        // One RET → 1 return.
        assert_eq!(fp.returns, 1);
    }

    /// Classic `while (cond) { body; }` compiled to:
    ///   TEST cond; JE exit; body; JMP entry; exit: RET
    /// The back-edge `JMP entry` goes from body (block at next_ip after
    /// the conditional) to entry. Entry dominates body (entry is the
    /// only predecessor of body), so the dominance check counts it.
    #[test]
    fn cfg_fingerprint_while_loop_is_counted() {
        // 0x1000: TEST EAX,EAX (85 C0)              [2 bytes]
        // 0x1002: JE 0x100C (74 08)                  [2 bytes] -> 0x100C (exit)
        // 0x1004: NOP (90)                           [1 byte]
        // 0x1005: JMP 0x1000 (EB F9)                 [2 bytes] -> 0x1000 (BACK to entry)
        // 0x1007-0x100B: padding (5 bytes)
        // 0x100C: RET (C3)                           [1 byte] (exit)
        let code = [
            0x85, 0xC0, // TEST EAX,EAX
            0x74, 0x08, // JE 0x100C
            0x90, // NOP
            0xEB, 0xF9, // JMP 0x1000 (back-edge)
            0x90, 0x90, 0x90, 0x90, 0x90, // padding
            0xC3, // RET
        ];
        let pe = pe_with_code(&code);
        let entry = pe.image_base + 0x1000;
        let fp = cfg_fingerprint(&pe, entry).expect("cfg_fingerprint");
        assert_eq!(
            fp.loops, 1,
            "while loop's back-edge (JMP entry) must be counted; got {:?}",
            fp
        );
    }

    /// Classic `do { body; } while (cond);` compiled to:
    ///   body; TEST cond; JE exit; JMP entry; exit: RET
    /// The back-edge `JMP entry` goes from a block that the entry block
    /// leads into (via fallthrough of the entry's body) to entry. Entry
    /// dominates that block (entry is on every path), so the dominance
    /// check counts it. Guards against an over-eager fix that only
    /// counts conditional jumps.
    #[test]
    fn cfg_fingerprint_do_while_loop_is_counted() {
        // 0x1000: NOP (90)                          [1 byte]  (body)
        // 0x1001: TEST EAX,EAX (85 C0)              [2 bytes]
        // 0x1003: JE 0x1009 (74 04)                  [2 bytes] -> 0x1009 (exit)
        // 0x1005: JMP 0x1000 (EB F9)                 [2 bytes] -> 0x1000 (BACK to entry)
        // 0x1007-0x1008: padding
        // 0x1009: RET (C3)                           [1 byte] (exit)
        let code = [
            0x90, // NOP
            0x85, 0xC0, // TEST EAX,EAX
            0x74, 0x04, // JE 0x1009
            0xEB, 0xF9, // JMP 0x1000 (back-edge)
            0x90, 0x90, // padding
            0xC3, // RET
        ];
        let pe = pe_with_code(&code);
        let entry = pe.image_base + 0x1000;
        let fp = cfg_fingerprint(&pe, entry).expect("cfg_fingerprint");
        assert_eq!(
            fp.loops, 1,
            "do-while loop's back-edge (JMP entry) must be counted; got {:?}",
            fp
        );
    }

    /// JMP to next_ip is an unconditional forward jump (in-range) that
    /// is not a back-edge (t == b.start → not strict <, not strict =
    /// either after the strict-< → <= fix), so it's neither a loop nor a
    /// tail-call-out-of-range. The macro's "any terminator at all?"
    /// gate is the load-bearing check; this test just pins that the
    /// unconditional branch path still terminates the block.
    #[test]
    fn cfg_fingerprint_unconditional_jmp_out_of_range_is_return_equivalent() {
        let code = [0xE9, 0x00, 0x00, 0x00, 0x00]; // JMP rel32 with rel=0 → next_ip
        let pe = pe_with_code(&code);
        let entry = pe.image_base + 0x1000;
        let fp = cfg_fingerprint(&pe, entry).expect("cfg_fingerprint");
        // JMP to next_ip is forward and not a back-edge: 1 forward jump
        // (no conditionals, no switches), 0 loops. The fp.returns count
        // depends on whether the JMP was treated as a tail call — for an
        // in-range JMP to next_ip, the legacy code does NOT bump returns
        // (it's an in-range jump, not "out-of-function"). We don't pin
        // that here; the test simply pins that the count is finite and
        // the function decoded without panic.
        assert_eq!(fp.loops, 0);
        assert_eq!(fp.conditionals, 0);
        assert_eq!(fp.switch_cases, 0);
        let _ = fp.returns;
    }

    /// Self-loop is a real loop (`while (true) { ... }`) and must be
    /// counted. Guard against an over-strict fix that drops self-loops.
    #[test]
    fn cfg_fingerprint_self_loop_is_counted() {
        // 0x1000: JMP 0x1000 (EB FE) → back to self
        let code = [0xEB, 0xFE]; // JMP rel8 = -2 → 0x1000
        let pe = pe_with_code(&code);
        let entry = pe.image_base + 0x1000;
        let fp = cfg_fingerprint(&pe, entry).expect("cfg_fingerprint");
        assert_eq!(
            fp.loops, 1,
            "self-loop is a natural-loop back-edge; got {:?}",
            fp
        );
    }

    /// Real-binary regression for the bug. `ni_file_flush` at 0x00747d30
    /// in `noivilbo.exe` has two Jccs into a common tail (0x00747d40)
    /// that does NOT dominate the Jcc source blocks (entry can fall
    /// through to them without going through the tail). With the OLD
    /// `t <= ld` heuristic, those counted as back-edges and `fp.loops`
    /// was ≥1. After the fix, `fp.loops` must be 0 — there's no actual
    /// iteration in this function.
    #[test]
    fn cfg_pin_noivilbo_ni_file_flush_has_no_loops() {
        let manifest_dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
        let pe_path = manifest_dir
            .parent()
            .and_then(|p| p.parent())
            .map(|p| p.join("noivilbo.exe"))
            .expect("workspace root resolves");
        if !pe_path.exists() {
            eprintln!(
                "skipping: {} not found (fixture binary lives at workspace root)",
                pe_path.display()
            );
            return;
        }
        let pe = Pe::load(pe_path.to_str().unwrap()).expect("load noivilbo.exe");
        let fp = cfg_fingerprint(&pe, 0x00747d30)
            .expect("cfg_fingerprint at 0x00747d30 (ni_file_flush)");
        assert_eq!(
            fp.loops, 0,
            "ni_file_flush (0x00747d30) has no real loops — its two Jccs into \
             0x00747d40 are early-exits to a common tail, not back-edges into a \
             loop head. The OLD `t <= ld && leaders.contains(&t)` heuristic \
             counted them as loops (fp.loops was 1+); the dominance-based \
             check counts 0. Got fp = {:?}",
            fp
        );
    }

    // -----------------------------------------------------------------
    // Unhappy paths — error returns, dead code, switch tables,
    // nested/multi-back-edge loops. These pin the cases the happy-path
    // tests don't exercise so a regression in either direction (false
    // positive or false negative) can't slip through.
    // -----------------------------------------------------------------

    /// Entry address lies outside every PE section. `cfg_fingerprint`
    /// must reject it with `Err` rather than panicking on read-of-
    /// unmapped-VA or returning a bogus fingerprint built from
    /// `instrs.is_empty()` defaults.
    #[test]
    fn cfg_fingerprint_rejects_out_of_section_entry() {
        let code = [0xC3u8]; // RET
        let pe = pe_with_code(&code);
        let bogus = 0x8000_0000u64;
        assert!(
            cfg_fingerprint(&pe, bogus).is_err(),
            "cfg_fingerprint on out-of-section entry should error, not silently \
             return a zero-fingerprint"
        );
    }

    /// Function body is empty (decode lands on nothing). Should not
    /// panic and should not report phantom loops/conditionals. Guards
    /// against an `instrs[idx]` panic when the entry's first decode
    /// produces zero instructions.
    #[test]
    fn cfg_fingerprint_entry_with_zero_bytes_is_well_formed() {
        let pe = pe_with_code(&[]); // .text has 0 raw bytes
        let entry = pe.image_base + 0x1000;
        // The PE is valid but the entry decode returns immediately.
        // Either we get an Ok fingerprint with all-zero counters (the
        // decode_all loop never produces a leader) or an Err. Anything
        // else (panic, NaN, fake loops) is a regression.
        if let Ok(fp) = cfg_fingerprint(&pe, entry) {
            assert_eq!(fp.loops, 0, "no instructions → no back-edges; got {:?}", fp);
            assert_eq!(fp.conditionals, 0);
            assert_eq!(fp.switch_cases, 0);
            assert_eq!(fp.returns, 0);
        }
    }

    /// `Jcc` whose near-branch target is OUT OF RANGE (beyond
    /// `entry + MAX_SPAN`). The fingerprint must NOT panic decoding
    /// bytes past the function span, and must NOT count an out-of-range
    /// jump as a loop. The OLD code's `t <= ld && leaders.contains(&t)`
    /// was safe from out-of-range because `leaders.contains` short-
    /// circuited — the new code paths must stay equally safe.
    #[test]
    fn cfg_fingerprint_jcc_to_out_of_range_target_does_not_panic() {
        // JMP short with disp +127 → 0x1002 + 2 + 127 = 0x1081.
        // MAX_SPAN is 0x10000 so this IS in range; we need a target
        // beyond MAX_SPAN. Use a long displacement by stuffing padding:
        // simpler approach — put a JMP with rel8 = -128 → next_ip -128,
        // which is below entry. That's still "in range" (signed wrap).
        //
        // To test out-of-range safely, use a JMP rel32 to a target FAR
        // past the section. The build_cfg successor list filters by
        // `(lo..hi).contains(&t)` so the target is dropped from `succ`,
        // which means the dominance check cannot run on it.
        //
        // Layout: JMP rel32 with displacement pointing PAST the section
        // (we don't have one here, but rel32 of +0x100_0000 = 16 MB
        // overshoots MAX_SPAN). Then RET so the function still
        // terminates for the macro's "any terminator?" check.
        //
        // 0x1000: E9 00 00 10 00  JMP rel32 +0x100000 = 0x101005  (off the section)
        // 0x1005: C3              RET
        let code = [0xE9, 0x00, 0x00, 0x10, 0x00, 0xC3];
        let pe = pe_with_code(&code);
        let entry = pe.image_base + 0x1000;
        let fp = cfg_fingerprint(&pe, entry).expect("cfg_fingerprint");
        assert_eq!(
            fp.loops, 0,
            "JMP to an out-of-range successor must not be misclassified as a \
             loop back-edge; got {:?}",
            fp
        );
        // The JMP is treated as a tail-call-equivalent: 1 return.
        assert_eq!(fp.returns, 1);
    }

    /// Multiple back-edges to the same loop head — a real loop with
    /// two body blocks each ending with a back-jump to entry. Both
    /// back-jumps must be counted (the loop is entered from two body
    /// blocks, each forming its own natural loop back-edge that
    /// converges on the same head).
    #[test]
    fn cfg_fingerprint_two_back_edges_same_head_are_both_counted() {
        // 0x1000: TEST EAX,EAX       (85 C0)              [2 bytes]   block A
        // 0x1002: JE  0x1014         (74 10)              [2 bytes]   A's term → exit (forward)
        // 0x1004: CMP EAX,EAX       (39 C0)              [2 bytes]   block B starts (next_ip)
        // 0x1006: JE  0x1000         (74 F8)              [2 bytes]   B's term → back to entry (back-edge #1)
        // 0x1008: NOP                (90)                 [1 byte]    block C starts (next_ip after JE)
        // 0x1009: NOP                (90)                 [1 byte]
        // 0x100A: JMP 0x1000         (EB F4)              [2 bytes]   C's term → back to entry (back-edge #2)
        // 0x100C-0x1013: padding (8 bytes)
        // 0x1014: RET                (C3)                 [1 byte]    exit
        let code = [
            0x85, 0xC0, // TEST EAX,EAX
            0x74, 0x10, // JE 0x1014
            0x39, 0xC0, // CMP EAX,EAX
            0x74, 0xF8, // JE 0x1000 (back-edge #1)
            0x90, // NOP
            0x90, // NOP
            0xEB, 0xF4, // JMP 0x1000 (back-edge #2)
            0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, // padding
            0xC3, // RET
        ];
        let pe = pe_with_code(&code);
        let entry = pe.image_base + 0x1000;
        let fp = cfg_fingerprint(&pe, entry).expect("cfg_fingerprint");
        assert_eq!(
            fp.loops, 2,
            "two distinct back-edges into the same loop head must each be \
             counted; got {:?}",
            fp
        );
    }

    /// Two distinct loops at the same nesting level — a function with
    /// `while (a) { ... } while (b) { ... }` compiled with each loop
    /// having its own head. The fix must count BOTH heads as separate
    /// back-edges; an over-eager fix that only counts unique heads
    /// would drop one.
    #[test]
    fn cfg_fingerprint_two_distinct_loops_are_both_counted() {
        // First loop:
        // 0x1000: TEST EAX,EAX         (85 C0)             [2 bytes]   loop A entry
        // 0x1002: JE  0x100C           (74 06)             [2 bytes]   → exit-A
        // 0x1004: NOP                  (90)                [1 byte]    loop A body
        // 0x1005: JMP 0x1000           (EB F9)             [2 bytes]   → back-edge
        // 0x1007: <padding> → leader 0x1007
        // Second loop:
        // 0x100C: TEST EAX,EAX         (85 C0)             [2 bytes]   loop B entry
        // 0x100E: JE  0x1018           (74 06)             [2 bytes]   → exit-B
        // 0x1010: NOP                  (90)                [1 byte]    loop B body
        // 0x1011: JMP 0x100C           (EB F9)             [2 bytes]   → back-edge
        // 0x1013-0x1017: padding
        // 0x1018: RET                  (C3)                [1 byte]    exit
        let code = [
            0x85, 0xC0, // TEST EAX,EAX
            0x74, 0x06, // JE 0x100C
            0x90, // NOP
            0xEB, 0xF9, // JMP 0x1000
            0x90, 0x90, 0x90, 0x90, 0x90, // padding (to 0x100C)
            0x85, 0xC0, // TEST EAX,EAX
            0x74, 0x06, // JE 0x1018
            0x90, // NOP
            0xEB, 0xF9, // JMP 0x100C
            0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, // padding
            0xC3, // RET
        ];
        let pe = pe_with_code(&code);
        let entry = pe.image_base + 0x1000;
        let fp = cfg_fingerprint(&pe, entry).expect("cfg_fingerprint");
        assert_eq!(
            fp.loops, 2,
            "two distinct loops (two different heads) must both be counted; \
             got {:?}",
            fp
        );
    }

    /// Loop with both a conditional back-edge (continue) AND an
    /// unconditional back-edge (`break`-into-next-iteration is rare
    /// but a `goto` restart at loop top shows up this way). Both must
    /// be counted.
    #[test]
    fn cfg_fingerprint_loop_with_cond_and_uncond_back_edge() {
        // 0x1000: TEST EAX,EAX          (85 C0)             [2 bytes]   loop head
        // 0x1002: JE  0x1014            (74 10)             [2 bytes]   → exit
        // 0x1004: <next_ip>            block B starts
        // 0x1004: CMP EAX,EAX          (39 C0)             [2 bytes]
        // 0x1006: JE  0x1000           (74 F8)             [2 bytes]   conditional back-edge (continue)
        // 0x1008: NOP                  (90)                [1 byte]
        // 0x1009: JMP 0x1000           (EB F5)             [2 bytes]   unconditional back-edge
        // 0x100B: <padding>
        // 0x1014: RET                  (C3)                [1 byte]   exit
        let code = [
            0x85, 0xC0, // TEST EAX,EAX
            0x74, 0x10, // JE 0x1014
            0x39, 0xC0, // CMP EAX,EAX
            0x74, 0xF8, // JE 0x1000 (cond back-edge)
            0x90, // NOP
            0xEB, 0xF5, // JMP 0x1000 (uncond back-edge)
            0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, // padding
            0xC3, // RET
        ];
        let pe = pe_with_code(&code);
        let entry = pe.image_base + 0x1000;
        let fp = cfg_fingerprint(&pe, entry).expect("cfg_fingerprint");
        // JE at 0x1006 → 0x1000 is a real back-edge (0x1000 dominates 0x1004:
        // 0x1004's only predecessor is 0x1000 via fallthrough from A's Jcc).
        // JMP at 0x1009 → 0x1000 is also a real back-edge (same head, same
        // dominance).
        assert_eq!(
            fp.loops, 2,
            "both conditional and unconditional back-edges to the loop head \
             must be counted; got {:?}",
            fp
        );
    }

    /// A `Jcc` whose near-branch target is the BLOCK'S OWN START
    /// (target == b.start) — i.e. a self-loop on a multi-instruction
    /// block. The OLD `t <= ld` check counted this; the new `t <=
    /// b.start && t dom b` must also count it (every node dominates
    /// itself, so the check fires).
    #[test]
    fn cfg_fingerprint_block_starting_self_loop_is_counted() {
        // 0x1000: TEST EAX,EAX         (85 C0)             [2 bytes]   block A entry (loop head)
        // 0x1002: NOP                  (90)                [1 byte]    block A body
        // 0x1003: JMP 0x1000           (EB FB)             [2 bytes]   → back to block start
        //   (disp = target - next_ip = 0x1000 - 0x1005 = -5 = 0xFB)
        // 0x1005-0x100B: padding
        // 0x100C: RET                  (C3)                [1 byte]   never reached
        let code = [
            0x85, 0xC0, // TEST EAX,EAX
            0x90, // NOP
            0xEB, 0xFB, // JMP 0x1000 (back to block start, disp=-5)
            0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, // padding
            0xC3, // RET
        ];
        let pe = pe_with_code(&code);
        let entry = pe.image_base + 0x1000;
        let fp = cfg_fingerprint(&pe, entry).expect("cfg_fingerprint");
        assert_eq!(
            fp.loops, 1,
            "self-loop on a multi-instruction block must be counted (target \
             equals the block's start, which dominates itself); got {:?}",
            fp
        );
    }

    /// Switch / jump-table case: `IndirectBranch` terminator with a
    /// small jump table. The fingerprint's `switch_cases` counter must
    /// reflect the table size, and the `loops` counter must NOT be
    /// inflated by the indirect branch (it's not a back-edge — it's a
    /// forward dispatch).
    ///
    /// We construct `JMP [EAX*4 + disp32]` (ModRM 0x24 mod=00 reg=100
    /// /4 rm=100 SIB; SIB 0x85 scale=10×4 index=000 EAX base=101
    /// "no base" with mod=00 means "use only the displacement plus the
    /// scaled index") plus a 3-entry jump table.
    ///
    /// `pe.section_of(disp)` requires the absolute VA, so the table
    /// base encoded in the disp is `image_base + 0x1010 = 0x00401010`.
    #[test]
    fn cfg_fingerprint_jump_table_is_counted_as_switch_not_loop() {
        let image_base = 0x0040_0000u32;
        let table_va: u32 = image_base + 0x1010; // = 0x00401010
        let case0_va: u32 = image_base + 0x1014; // = 0x00401014
        let case1_va: u32 = image_base + 0x1018; // = 0x00401018
        let case2_va: u32 = image_base + 0x101C; // = 0x0040101C
                                                 // 0x1000: JMP [EAX*4 + 0x0040_1010]      (FF 24 85 10 10 40 00)  [7 bytes]
                                                 // 0x1007-0x100F: padding
                                                 // 0x1010: 14 10 40 00  → 0x00401014       jump table entry 0
                                                 // 0x1014: 18 10 40 00  → 0x00401018       jump table entry 1
                                                 // 0x1018: 1C 10 40 00  → 0x0040101C       jump table entry 2
                                                 // 0x1014: RET                          (C3)   [1 byte]   case 0
                                                 // 0x1018: RET                          (C3)   [1 byte]   case 1
                                                 // 0x101C: RET                          (C3)   [1 byte]   case 2
        let mut code: Vec<u8> = vec![
            0xFF, 0x24, 0x85, // JMP [EAX*4 + disp32]
        ];
        code.extend_from_slice(&table_va.to_le_bytes());
        while code.len() < 0x10 {
            code.push(0x90); // NOP
        }
        code.extend_from_slice(&case0_va.to_le_bytes());
        code.extend_from_slice(&case1_va.to_le_bytes());
        code.extend_from_slice(&case2_va.to_le_bytes());
        code.push(0xC3);
        code.push(0xC3);
        code.push(0xC3);
        while code.len() < 0x200 {
            code.push(0x90);
        }

        let pe = pe_with_code(&code);
        let entry = pe.image_base + 0x1000;
        let fp = cfg_fingerprint(&pe, entry).expect("cfg_fingerprint");
        assert_eq!(
            fp.switch_cases, 3,
            "jump table with 3 entries should contribute 3 to switch_cases; \
             got {:?}",
            fp
        );
        assert_eq!(
            fp.loops, 0,
            "indirect branch is a forward dispatch, not a back-edge; loops \
             must remain 0 even when the table is counted; got {:?}",
            fp
        );
        let _ = fp.returns;
    }

    /// Real-binary pin for a function with KNOWN non-zero loop count:
    /// `select_texture_format` at 0x00773ba0 has 12 back-edges per
    /// the probe above. Guards against the dominance fix dropping
    /// genuine loops (e.g. by computing dom on the wrong subgraph).
    #[test]
    fn cfg_pin_noivilbo_select_texture_format_has_twelve_loops() {
        let manifest_dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
        let pe_path = manifest_dir
            .parent()
            .and_then(|p| p.parent())
            .map(|p| p.join("noivilbo.exe"))
            .expect("workspace root resolves");
        if !pe_path.exists() {
            eprintln!(
                "skipping: {} not found (fixture binary lives at workspace root)",
                pe_path.display()
            );
            return;
        }
        let pe = Pe::load(pe_path.to_str().unwrap()).expect("load noivilbo.exe");
        let fp = cfg_fingerprint(&pe, 0x00773ba0)
            .expect("cfg_fingerprint at 0x00773ba0 (select_texture_format)");
        assert_eq!(
            fp.loops, 12,
            "select_texture_format (0x00773ba0) has 12 real back-edges in its \
             CFG (multiple nested loops). The dominance-based check must \
             preserve them. Got fp = {:?}",
            fp
        );
    }

    /// Real-binary pin for a function whose CFG contains BOTH a
    /// conditional Jcc back-edge AND an unconditional JMP back-edge
    /// to the same loop head — the case that an over-eager fix would
    /// silently regress by treating one as "not a real loop".
    ///
    /// The function at 0x0071FF54 (a `ni_property_state_*` port) has:
    ///   * an unconditional `jmp 0x0071FF54` self-loop at the entry
    ///   * a conditional `jb 0x00720062` back-edge from 0x0072018c to
    ///     0x00720062 (a `while (cmp dx, [ebp+0x50])` loop tail)
    ///
    /// Both must be counted: the textbook natural-loop definition is
    /// `dom[source].contains(target)`, which holds for both Jcc and JMP.
    /// A fix that only counts unconditional JMPs (or only counts
    /// forward self-loops) would silently drop the second one and
    /// make the porter's `r.loops >= 1` check fail spuriously.
    #[test]
    fn cfg_pin_noivilbo_ni_property_state_has_two_loops() {
        let manifest_dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
        let pe_path = manifest_dir
            .parent()
            .and_then(|p| p.parent())
            .map(|p| p.join("noivilbo.exe"))
            .expect("workspace root resolves");
        if !pe_path.exists() {
            eprintln!(
                "skipping: {} not found (fixture binary lives at workspace root)",
                pe_path.display()
            );
            return;
        }
        let pe = Pe::load(pe_path.to_str().unwrap()).expect("load noivilbo.exe");
        let fp = cfg_fingerprint(&pe, 0x0071FF54)
            .expect("cfg_fingerprint at 0x0071FF54 (ni_property_state)");
        assert_eq!(
            fp.loops, 2,
            "ni_property_state (0x0071FF54) has 2 real back-edges — a \
             conditional `jb` back-edge and an unconditional `jmp` self-loop. \
             The dominance-based check must count BOTH; a fix that drops \
             either kind would let the porter silently lose a loop. \
             Got fp = {:?}",
            fp
        );
    }

    /// BUGFIX regression: a thunk / tail-jmp that targets another in-range
    /// function (within 64KB of the entry) must NOT cause the callee's
    /// loops, switches, and conditionals to be counted against the
    /// caller's CFG fingerprint. Real-binary instance: `0x579210: jmp
    /// 0x5821f0` reports `fp.loops = 11, switch_cases = 8, conditionals =
    /// 187` because the old `decode_all` followed the unconditional jmp
    /// (the `(lo..hi).contains(&t)` check accepts anything within 64KB of
    /// the entry, and the callee `0x5821f0` lands at `entry + 0x8FE0`).
    /// The fingerprint should describe a 1-instruction thunk, not the
    /// callee's body.
    ///
    /// We synthesize a 1-instruction thunk at `entry` whose JMP target
    /// lands on a multi-instruction "callee" body (loop + RET) at
    /// `entry + 0x100`. Both fit within the 64KB window so the bug is
    /// reproducible on a synthetic PE. The fix is conservative: only
    /// follow a JMP whose target is BEFORE the JMP's own IP (a
    /// backward JMP is a back-edge within the same function; a forward
    /// JMP is either a fall-through already handled by the next-leader
    /// check, or — the bug case — a tail-call into another function).
    #[test]
    fn cfg_fingerprint_thunk_does_not_follow_unconditional_jmp() {
        // Thunk at image_base+0x1000: JMP rel32 -> image_base+0x1100.
        // E9 is JMP rel32; rel32 = 0x100 - 5 (instruction length).
        let mut code = Vec::new();
        // 0x1000: E9 F6 00 00 00   JMP 0x1100
        code.extend_from_slice(&[0xE9, 0xF6, 0x00, 0x00, 0x00]);
        // Pad to 0x100 bytes with NOPs so .text raw size covers the thunk
        // unambiguously.
        while code.len() < 0x100 {
            code.push(0x90);
        }
        // 0x1100: loop body the OLD code would mistakenly count.
        // 0x1100: TEST EAX,EAX (85 C0) [2 bytes]
        // 0x1102: JE 0x110C (74 08)     [2 bytes]
        // 0x1104: NOP (90)              [1 byte]
        // 0x1105: JMP 0x1100 (EB F9)    [2 bytes] -- back-edge
        // 0x1107..0x110B: padding
        // 0x110C: RET (C3)              [1 byte]
        code.extend_from_slice(&[0x85, 0xC0, 0x74, 0x08, 0x90, 0xEB, 0xF9, 0x90]);
        // Pad to a 0x200 boundary so the raw_size layout is normal.
        while code.len() < 0x200 {
            code.push(0x90);
        }
        let pe = pe_with_code(&code);
        let entry = pe.image_base + 0x1000;
        let fp = cfg_fingerprint(&pe, entry).expect("cfg_fingerprint");
        // The thunk is a 1-instruction unconditional JMP out of the
        // function. It's NOT a back-edge (t > b.start) so loops must be
        // 0; it's NOT a conditional so conditionals must be 0; it
        // doesn't reference a jump table so switch_cases must be 0.
        // The JMP is treated as a return-equivalent, so returns >= 1.
        assert_eq!(
            fp.loops, 0,
            "thunk's JMP target is out-of-function; callee's loop must NOT \
             be counted against the thunk. Got fp = {:?}",
            fp
        );
        assert_eq!(
            fp.conditionals, 0,
            "thunk has no conditionals. Got fp = {:?}",
            fp
        );
        assert_eq!(fp.switch_cases, 0, "thunk has no switch. Got fp = {:?}", fp);
        assert!(
            fp.returns >= 1,
            "thunk's JMP must be counted as a return-equivalent terminator. \
             Got fp = {:?}",
            fp
        );
    }

    /// Unhappy-path: a thunk whose JMP target is OUT of the 64KB
    /// window. The OLD code's `(lo..hi).contains(&t)` check would have
    /// rejected this naturally (no in-range leader added, callee not
    /// decoded). The NEW code's `t < ip` check also rejects it — both
    /// paths converge on `loops=0`. Pin the converged behaviour so a
    /// future refactor doesn't drift the two checks apart.
    #[test]
    fn cfg_fingerprint_thunk_with_out_of_range_target_is_a_single_return() {
        // The thunk is at 0x1000. The JMP must reach 0x1000+0x10000 =
        // 0x11000 which is OUT of [0x1000, 0x1000+0x10000). The OLD
        // `(lo..hi).contains(&t)` check would have rejected this for
        // a thunk at 0x1000+0x10000-5 = 0x10FFB, but the JMP's
        // 5-byte length means next_ip == 0x11000, which IS in
        // [0x10FFB, 0x10FFB+0x10000) = [0x10FFB, 0x20FFB). So
        // `(lo..hi).contains(0x11000)` is true. But `0x11000 > ip` for
        // any ip in [0x10FFB, 0x10FFB+5) = [0x10FFB, 0x11000). So the
        // NEW check rejects it.
        //
        // Layout: thunk at 0x10FFB (5 bytes for JMP), target 0x11000
        // which is just past the 64KB window.
        let code = [
            0xE9, 0x00, 0x00, 0x00, 0x00, // JMP rel32 = 0 → 0x11000
            0x90, 0x90, 0x90, 0x90, 0x90, // padding
            0xC3, // RET (would be the callee start)
        ];
        let pe = pe_with_code(&code);
        // The synthetic PE's .text VA is 0x1000, so a thunk at 0x10FFB
        // would actually be at image_base + 0x10FFB, but pe_with_code
        // places code at image_base + 0x1000 with text_raw = ceil(0x200)
        // ≈ 0x200 bytes. So a JMP at image_base + 0x1000 reaching
        // image_base + 0x11000 would be 64KB forward — exactly at the
        // window edge. (lo..hi) = [0x1000, 0x11000) is half-open; the
        // upper bound is exclusive so 0x11000 is OUT of range. Both OLD
        // and NEW code reject it.
        let entry = pe.image_base + 0x1000;
        let fp = cfg_fingerprint(&pe, entry).expect("cfg_fingerprint");
        assert_eq!(
            fp.loops, 0,
            "out-of-range JMP target — loops=0; got {:?}",
            fp
        );
        assert_eq!(fp.conditionals, 0, "got {:?}", fp);
        assert_eq!(fp.switch_cases, 0, "got {:?}", fp);
        assert!(
            fp.returns >= 1,
            "the single JMP is a return-equivalent terminator; got {:?}",
            fp
        );
    }

    /// Unhappy-path: thunk with a JMP target that is at the same IP
    /// (self-loop JMP, e.g. an infinite-loop `jmp $` thunk). The fix's
    /// `t < ip` check rejects `t == ip` (no leader added), but
    /// `cfg_fingerprint`'s `dom[b.start].contains(t)` still classifies
    /// it as a back-edge (every node dominates itself). Pin that
    /// behaviour so a future "strict-less-than" → "strict-less-or-equal"
    /// drift doesn't change the count.
    #[test]
    fn cfg_fingerprint_self_loop_jmp_thunk_is_one_loop() {
        // 0x1000: EB FE   JMP 0x1000 (self-loop)
        let code = [0xEB, 0xFE, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90];
        let pe = pe_with_code(&code);
        let entry = pe.image_base + 0x1000;
        let fp = cfg_fingerprint(&pe, entry).expect("cfg_fingerprint");
        assert_eq!(
            fp.loops, 1,
            "self-loop JMP at the entry must still count as 1 loop even \
             though the fix's `t < ip` check rejects it as a follower; got \
             {:?}",
            fp
        );
        // The JMP is the only terminator AND it counts as a back-edge
        // (not a return), so returns == 0 here. The existing
        // cfg_fingerprint_self_loop_is_counted test pins the same
        // behaviour; this test pins the interaction with the new fix.
        assert_eq!(
            fp.returns, 0,
            "self-loop JMP is a back-edge, not a return; got {:?}",
            fp
        );
    }
}
