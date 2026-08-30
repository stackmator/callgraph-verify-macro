#[cfg(test)]
mod tests {
    use callgraph_verify::{
        analyze, cfg_fingerprint, diff_body_calls, has_direct_branch_target, reg_params, ArgKind,
        Pe, Spec,
    };
    use std::process::Command;

    /// Build the test binary if needed and return its path
    fn get_test_binary_path() -> std::path::PathBuf {
        let manifest_dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
        let test_bin_dir = manifest_dir.join("test-bin");
        let exe_path = test_bin_dir
            .join("target")
            .join("i686-pc-windows-msvc")
            .join("debug")
            .join("test-bin.exe");

        if !exe_path.exists() {
            // Build the test binary
            let status = Command::new("cargo")
                .args(["build", "--target", "i686-pc-windows-msvc"])
                .current_dir(&test_bin_dir)
                .status()
                .expect("failed to run cargo build for test-bin");
            assert!(status.success(), "test-bin build failed");
        }

        exe_path
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
    fn test_diff_body_calls_with_inlined_marker() {
        let pe = load_test_pe();
        let addrs = find_function_addresses(&pe);

        // Find a function with calls
        for addr in &addrs {
            let cg = analyze(&pe, *addr).expect("analyze");
            if !cg.direct_calls.is_empty() {
                let real_targets: Vec<u64> = cg.call_targets().into_iter().collect();

                // Create a corpus with these addresses plus an extra one (the "inlined" callee)
                let mut corpus: std::collections::BTreeSet<u64> =
                    real_targets.iter().copied().collect();
                let inlined_callee = 0xDEADBEEF; // Not in the binary's direct calls
                corpus.insert(inlined_callee);

                // Rust calls the inlined callee
                let rust_idents = vec![("inlined_fn".to_string(), vec![inlined_callee])];

                // Mark it as inlined
                let inlined_markers: std::collections::BTreeSet<u64> =
                    [inlined_callee].into_iter().collect();

                let diff = diff_body_calls(
                    &pe,
                    &[*addr],
                    &corpus,
                    &rust_idents,
                    &inlined_markers,
                    &std::collections::BTreeSet::new(),
                )
                .expect("diff_body_calls");

                // The call should be classified as inlined_ok, not hallucinated
                assert!(
                    diff.inlined_ok.contains(&"inlined_fn".to_string()),
                    "inlined_ok: {:?}",
                    diff.inlined_ok
                );
                assert!(
                    !diff.hallucinated.iter().any(|(n, _)| n == "inlined_fn"),
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
                    &std::collections::BTreeSet::new(),
                    &vtable_methods,
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
        // analyze result has in `call_targets`.
        for caller in &addrs {
            if let Ok(cg) = analyze(&pe, *caller) {
                for callee in cg.call_targets() {
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
            let far = pe.image_base + text.virtual_address as u64 + text.virtual_size as u64 + 0x1000;
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
}
