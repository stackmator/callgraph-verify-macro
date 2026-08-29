//! CLI: dump the pure-byte call graph of one function in the target binary.
//!
//!   callgraph_verify <exe> <addr> [--declared 0xA,0xB,...] [--exact]
//!
//! With no `--declared`, prints the real direct-call targets, tail calls and
//! indirect-call/jump counts. With `--declared`, diffs them and exits non-zero
//! on any hallucinated (or, with `--exact`, missing) call.

use callgraph_verify::{analyze, diff_calls, skel, Pe};

fn parse_addr(s: &str) -> Result<u64, String> {
    let s = s.trim().trim_start_matches("0x").trim_start_matches("0X");
    u64::from_str_radix(s, 16).map_err(|e| format!("bad addr {s:?}: {e}"))
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 3 {
        eprintln!(
            "usage: {} <exe> <addr-hex> [--declared 0xA,0xB,...] [--exact] [--skeleton]",
            args.first()
                .map(String::as_str)
                .unwrap_or("callgraph_verify")
        );
        std::process::exit(2);
    }
    let exe = &args[1];
    let addr = parse_addr(&args[2]).unwrap_or_else(|e| fatal(&e));

    let mut declared: Option<Vec<u64>> = None;
    let mut exact = false;
    let mut skeleton = false;
    let mut i = 3;
    while i < args.len() {
        match args[i].as_str() {
            "--skeleton" | "--skel" | "show-skeleton" => skeleton = true,
            "--exact" => exact = true,
            "--declared" => {
                i += 1;
                let list = args
                    .get(i)
                    .unwrap_or_else(|| fatal("--declared needs a value"));
                declared = Some(
                    list.split(',')
                        .filter(|s| !s.trim().is_empty())
                        .map(|s| parse_addr(s).unwrap_or_else(|e| fatal(&e)))
                        .collect(),
                );
            }
            other => fatal(&format!("unknown arg {other:?}")),
        }
        i += 1;
    }

    let pe = Pe::load(exe).unwrap_or_else(|e| fatal(&e));

    if skeleton {
        match skel::emit_skeleton(&pe, addr) {
            Ok(s) => print!("{s}"),
            Err(e) => fatal(&e),
        }
        return;
    }

    match declared {
        None => {
            let cg = analyze(&pe, addr).unwrap_or_else(|e| fatal(&e));
            println!(
                "function {:#010x}  (extent ~{} bytes)",
                cg.entry,
                cg.max_end - cg.entry
            );
            println!("  direct calls ({}):", cg.direct_calls.len());
            for (t, n) in &cg.direct_calls {
                let tag = if *n > 1 {
                    format!("  (x{n})")
                } else {
                    String::new()
                };
                println!("    CALL {t:#010x}{tag}");
            }
            if !cg.tail_calls.is_empty() {
                println!("  tail-call JMPs ({}):", cg.tail_calls.len());
                for t in &cg.tail_calls {
                    println!("    JMP  {t:#010x}");
                }
            }
            if !cg.call_sites.is_empty() {
                println!("  call-site argument shapes:");
                for cs in &cg.call_sites {
                    let mut parts: Vec<String> = Vec::new();
                    if let Some(a) = cs.ecx {
                        parts.push(format!("ecx={a:?}"));
                    }
                    if let Some(a) = cs.edx {
                        parts.push(format!("edx={a:?}"));
                    }
                    for (i, a) in cs.stack.iter().enumerate() {
                        parts.push(format!("s{i}={a:?}"));
                    }
                    println!("    CALL {:#010x} ({})", cs.target, parts.join(", "));
                }
            }
            println!("  indirect calls (reg/mem dispatch): {}", cg.indirect_calls);
            println!("  indirect jumps (jump tables):      {}", cg.indirect_jumps);
            print_set("vcall slots (CALL [reg+0xNN])", &cg.vcall_slots, true);
            print_set("IAT imports (CALL [abs])", &cg.iat_calls, false);
            print_set("struct field offsets ([reg+0xNN])", &cg.field_offsets, true);
            print_set("globals (abs data refs)", &cg.globals, false);
            print_set(
                "in-image immediates (vtable/fnptr/str)",
                &cg.imm_addrs,
                false,
            );
            if cg.decode_errors > 0 {
                println!("  decode stops (padding/data/end):   {}", cg.decode_errors);
            }
        }
        Some(d) => {
            let diff = diff_calls(&pe, addr, &d, exact).unwrap_or_else(|e| fatal(&e));
            if diff.is_clean() {
                println!("OK {addr:#010x}: declared call set matches the binary");
            } else {
                for h in &diff.hallucinated {
                    println!("HALLUCINATED {h:#010x}  — binary never directly calls it");
                }
                for m in &diff.missing {
                    println!("MISSING      {m:#010x}  — binary calls it, not declared");
                }
                std::process::exit(1);
            }
        }
    }
}

/// Print a labelled set of addresses/offsets; `small` formats as short hex
/// (offsets/slots), otherwise as full 10-digit VAs.
fn print_set(label: &str, set: &std::collections::BTreeSet<u64>, small: bool) {
    if set.is_empty() {
        return;
    }
    let items: Vec<String> = set
        .iter()
        .map(|v| {
            if small {
                format!("{v:#x}")
            } else {
                format!("{v:#010x}")
            }
        })
        .collect();
    println!("  {label} ({}): {}", set.len(), items.join(", "));
}

fn fatal(msg: &str) -> ! {
    eprintln!("error: {msg}");
    std::process::exit(2);
}
