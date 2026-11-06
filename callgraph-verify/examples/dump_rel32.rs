use callgraph_verify::Pe;
fn main() {
    let path = std::env::args().nth(1).expect("usage: dump_rel32 <exe>");
    let pe = Pe::load(&path).expect("load");
    let mut v: Vec<(u64, u64)> = pe.fixup_rel32_pairs().to_vec();
    v.sort();
    for (loc, tgt) in v {
        println!("{loc:#x} {tgt:#x}");
    }
}
