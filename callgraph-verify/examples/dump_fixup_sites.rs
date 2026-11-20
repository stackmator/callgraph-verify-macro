use callgraph_verify::Pe;
fn main() {
    let path = std::env::args().nth(1).expect("usage: dump_fixup_sites <exe> [lo-va]");
    let pe = Pe::load(&path).expect("load");
    let lo = std::env::args()
        .nth(2)
        .and_then(|s| u64::from_str_radix(s.trim_start_matches("0x"), 16).ok())
        .unwrap_or(0);
    let mut sites: Vec<_> = pe.fixup_sites().iter().filter(|(l, _, _)| *l >= lo).collect();
    sites.sort();
    for (loc, pre, target) in sites {
        if pre == target {
            continue; // loader-writes-same-value records are not value-changing
        }
        println!("{loc:#08x} {pre:#08x} -> {target:#08x}");
    }
}
