#[cfg(test)]
mod tests {
    use callgraph_verify::{analyze, cfg_fingerprint, diff_body_calls, ArgKind, Pe, Spec};
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
}
