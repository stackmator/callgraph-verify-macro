//! Fixture: E020 VTABLE-SLOT-OOB.
//!
//! Expected: `vtable_table!` declares `slots = 1` but the fixture entry
//! wires slot 5. The verifier rejects the index as out-of-bounds.

use callgraph_verify_macro::vtable_table;

vtable_table! {
    name = oob_vt,
    va = 0x00B00000,
    slots = 1,
    default = crate::vtable_unimplemented_o;
    5 = oob_fn;
}

#[allow(dead_code)]
fn vtable_unimplemented_o() {}