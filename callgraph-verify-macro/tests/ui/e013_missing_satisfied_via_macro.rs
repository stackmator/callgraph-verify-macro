//! Fixture: expansion SATISFIES an edge (positive control for the
//! macro-expansion feature).
//!
//! Expected: WITHOUT expansion this body would draw MISSING (it never
//! spells `real_call`, which the binary at 0x401000 calls) plus E016 (no
//! loop). WITH expansion the `caller!` edge resolves, the `for` loop
//! covers the binary's back-edges, and the `0x20` argument matches the
//! binary's `PUSH 0x20` — so the only diagnostic left is the orthogonal
//! E009 DUP-ADDR noise every 0x401000 fixture carries (two corpus owners).
//! If expansion ever stops working, MISSING + E016 reappear here.

include!("../testdata/corpus/macro_defs.rs");

use callgraph_verify_macro::origin;

#[origin(0x00401000)]
pub fn f() {
    for _ in 0..2 {
        caller!(0x20);
    }
}
