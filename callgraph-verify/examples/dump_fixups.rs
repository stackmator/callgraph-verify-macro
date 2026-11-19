use callgraph_verify::Pe;
fn main() {
    let path = std::env::args().nth(1).expect("usage: dump_fixups <exe> [filter-pre]");
    let pe = Pe::load(&path).expect("load");
    let filter = std::env::args().nth(2);
    let mut v: Vec<(u64, u64)> = pe.fixup_pairs().to_vec();
    v.sort();
    let shown = match filter.as_deref() {
        Some(prefix) => {
            let low = u64::from_str_radix(prefix.trim_start_matches("0x"), 16)
                .expect("filter must be hexadecimal");
            v.into_iter().filter(|(pre, _)| *pre >= low && *pre < low + 0x1000).collect()
        }
        None => v,
    };
    for (pre, post) in shown {
        println!("{pre:#08x} -> {post:#08x}");
    }
}
