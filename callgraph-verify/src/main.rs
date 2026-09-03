//! CLI: dump the pure-byte call graph of one function in the target binary.
//!
//!   callgraph_verify <exe> <addr-hex> [--declared 0xA,0xB,...] [--exact]
//!   callgraph_verify <exe> --list   [--max N]
//!   callgraph_verify <exe> --count
//!   callgraph_verify <exe> --summary
//!   callgraph_verify <exe> --json   [--max N]
//!
//! With no `--declared`, prints the real direct-call targets, tail calls and
//! indirect-call/jump counts. With `--declared`, diffs them and exits non-zero
//! on any hallucinated (or, with `--exact`, missing) call.
//!
//! `--list`, `--count`, `--summary`, `--json` enumerate every function in
//! `.text` by walking forward and skipping past each `analyze()`'s reported
//! extent. Output: one line per function entry with size, direct-call count,
//! and tail-call count. Useful for "how many functions does this PE have?".

use callgraph_verify::{analyze, diff_calls, skel, Pe};
use std::collections::BTreeSet;

fn parse_addr(s: &str) -> Result<u64, String> {
    let s = s.trim().trim_start_matches("0x").trim_start_matches("0X");
    u64::from_str_radix(s, 16).map_err(|e| format!("bad addr {s:?}: {e}"))
}

#[derive(Default)]
struct FnStats {
    entries: u32,
    total_extent: u64,
    total_direct_calls: u64,
    total_tail_calls: u64,
    total_indirect_calls: u64,
    total_indirect_jumps: u64,
    with_calls: u32,
    leaf: u32, // functions with no outgoing calls at all
}

/// Walk every code section (PE32 characteristics `MEM_EXECUTE` or
/// `CNT_CODE` — typically both on `.text`) and collect (entry_va, extent,
/// call-graph summary) for every distinct function. Data sections
/// (`.rdata`, `.data`, `.rsrc`, `.idata`, `.reloc`, `.tls`) are skipped
/// even if their bytes happen to decode as valid x86 — they'd otherwise
/// inflate the function count with phantom entries from random data
/// bytes that happen to start a valid opcode.
fn enumerate_functions(pe: &Pe, max: u32) -> Vec<(u64, u64, callgraph_verify::CallGraph)> {
    let mut out: Vec<(u64, u64, callgraph_verify::CallGraph)> = Vec::new();
    for sec in pe.sections() {
        if !sec.is_executable() {
            continue;
        }
        let sec_va = pe.image_base + sec.virtual_address as u64;
        let sec_end = sec_va + sec.virtual_size as u64;
        let mut va = sec_va;
        while va < sec_end {
            if let Ok(cg) = analyze(pe, va) {
                let extent = cg.max_end.saturating_sub(va).max(1);
                out.push((va, extent, cg));
                va = va.saturating_add(extent);
            } else {
                va += 1;
            }
            if out.len() as u32 >= max {
                break;
            }
        }
    }
    out
}

fn print_usage(prog: &str) -> ! {
    eprintln!(
        "usage: {prog} <exe> <addr-hex> [--declared 0xA,0xB,...] [--exact] [--skeleton]\n\
         \n       {prog} <exe> --list   [--max N]\n\
         \n       {prog} <exe> --count\n\
         \n       {prog} <exe> --summary\n\
         \n       {prog} <exe> --json   [--max N]"
    );
    std::process::exit(2);
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 3 {
        print_usage(
            args.first()
                .map(String::as_str)
                .unwrap_or("callgraph_verify"),
        );
    }
    let _prog = args
        .first()
        .cloned()
        .unwrap_or_else(|| "callgraph_verify".into());
    let exe = &args[1];

    // Mode dispatch: positional <addr> = per-function detail (existing);
    // --list / --count / --summary / --json = whole-binary enumeration.
    let mode = args[2].clone();
    let mut max: u32 = u32::MAX;

    match mode.as_str() {
        "--count" => {
            let pe = Pe::load(exe).unwrap_or_else(|e| fatal(&e));
            let n = enumerate_functions(&pe, u32::MAX).len();
            println!("{n}");
            return;
        }
        "--summary" => {
            let pe = Pe::load(exe).unwrap_or_else(|e| fatal(&e));
            let entries = enumerate_functions(&pe, u32::MAX);
            let stats = summarise(&entries);
            print_summary(exe, &stats);
            return;
        }
        "--list" => {
            parse_max(&args[3..], &mut max);
            let pe = Pe::load(exe).unwrap_or_else(|e| fatal(&e));
            let entries = enumerate_functions(&pe, max);
            for (va, extent, cg) in &entries {
                println!(
                    "{va:#010x}  extent={extent:>5}  calls={:>3}  tails={:>2}  indir_calls={:>2}  indir_jumps={:>2}",
                    cg.direct_calls.len(),
                    cg.tail_calls.len(),
                    cg.indirect_calls,
                    cg.indirect_jumps,
                );
            }
            println!("(total: {} functions)", entries.len());
            return;
        }
        "--json" => {
            parse_max(&args[3..], &mut max);
            let pe = Pe::load(exe).unwrap_or_else(|e| fatal(&e));
            let entries = enumerate_functions(&pe, max);
            print_json(&pe, &entries);
            return;
        }
        _ => {}
    }

    // Per-function mode: <addr> is required, plus optional flags.
    let addr = parse_addr(&mode).unwrap_or_else(|e| fatal(&e));

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

fn parse_max(args: &[String], max: &mut u32) {
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--max" => {
                i += 1;
                if let Some(v) = args.get(i) {
                    *max = v.parse().unwrap_or_else(|_| fatal("--max needs a number"));
                } else {
                    fatal("--max needs a value");
                }
            }
            other => fatal(&format!("unknown arg {other:?}")),
        }
        i += 1;
    }
}

fn summarise(entries: &[(u64, u64, callgraph_verify::CallGraph)]) -> FnStats {
    let mut s = FnStats::default();
    for (_, extent, cg) in entries {
        s.entries += 1;
        s.total_extent += extent;
        s.total_direct_calls += cg.direct_calls.len() as u64;
        s.total_tail_calls += cg.tail_calls.len() as u64;
        s.total_indirect_calls += cg.indirect_calls as u64;
        s.total_indirect_jumps += cg.indirect_jumps as u64;
        if !cg.direct_calls.is_empty() || !cg.tail_calls.is_empty() || cg.indirect_calls > 0 {
            s.with_calls += 1;
        }
        if cg.direct_calls.is_empty() && cg.tail_calls.is_empty() && cg.indirect_calls == 0 {
            s.leaf += 1;
        }
    }
    s
}

fn print_summary(exe: &str, s: &FnStats) {
    // Header names the ANALYZED binary (argv[1]), not this tool's own path.
    println!("{} ({} functions)", pe_path_label(exe), s.entries);
    println!(
        "  total extent:        {} bytes ({:.1} KB)",
        s.total_extent,
        s.total_extent as f64 / 1024.0
    );
    println!("  total direct calls:  {}", s.total_direct_calls);
    println!("  total tail calls:    {}", s.total_tail_calls);
    println!("  total indirect calls: {}", s.total_indirect_calls);
    println!("  total indirect jumps: {}", s.total_indirect_jumps);
    println!(
        "  with any outgoing call: {} ({:.1}%)",
        s.with_calls,
        pct(s.with_calls, s.entries)
    );
    println!(
        "  leaves (no outgoing): {} ({:.1}%)",
        s.leaf,
        pct(s.leaf, s.entries)
    );
    if s.entries > 0 {
        println!(
            "  avg direct calls / fn: {:.2}",
            s.total_direct_calls as f64 / s.entries as f64
        );
        println!(
            "  avg extent / fn:      {:.1} bytes",
            s.total_extent as f64 / s.entries as f64
        );
    }
}

/// `argv[0]` is the program path; this strips it to just the basename for
/// display in the summary header.
fn pe_path_label(prog: &str) -> &str {
    std::path::Path::new(prog)
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or(prog)
}

fn pct(part: u32, whole: u32) -> f64 {
    if whole == 0 {
        0.0
    } else {
        (part as f64) * 100.0 / (whole as f64)
    }
}

/// Minimal hand-rolled JSON writer (avoids a serde dependency). The output
/// is well-formed JSON suitable for piping into jq.
fn print_json(pe: &Pe, entries: &[(u64, u64, callgraph_verify::CallGraph)]) {
    println!("{{");
    println!("  \"image_base\": {:#x},", pe.image_base);
    println!("  \"sections\": [");
    for (i, s) in pe.sections().iter().enumerate() {
        let comma = if i + 1 < pe.sections().len() { "," } else { "" };
        println!(
            "    {{\"name\": {:?}, \"va\": \"{:#x}..{:#x}\", \"raw_size\": {}}}{comma}",
            s.name,
            pe.image_base + s.virtual_address as u64,
            pe.image_base + s.virtual_address as u64 + s.virtual_size as u64,
            s.raw_size,
        );
    }
    println!("  ],");
    println!("  \"functions\": [");
    for (i, (va, extent, cg)) in entries.iter().enumerate() {
        let comma = if i + 1 < entries.len() { "," } else { "" };
        let targets: Vec<String> = cg.direct_calls.keys().map(|t| format!("{t:#x}")).collect();
        let tails: Vec<String> = cg.tail_calls.iter().map(|t| format!("{t:#x}")).collect();
        println!(
            "    {{\"entry\": \"{va:#x}\", \"extent\": {extent}, \
             \"direct_calls\": {targets:?}, \"tail_calls\": {tails:?}, \
             \"indirect_calls\": {}, \"indirect_jumps\": {}}}{comma}",
            cg.indirect_calls, cg.indirect_jumps,
        );
    }
    println!("  ]");
    println!("}}");
}

/// Print a labelled set of addresses/offsets; `small` formats as short hex
/// (offsets/slots), otherwise as full 10-digit VAs.
fn print_set(label: &str, set: &BTreeSet<u64>, small: bool) {
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
