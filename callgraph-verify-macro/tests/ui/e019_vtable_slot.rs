//! Fixture: E019 VTABLE-SLOT.
//!
//! Expected: the vtable_table! wires slot 0 of VA 0x00A01000 to
//! `mismatch_fn`, but the engine vtable at that VA actually holds
//! 0x00402000 (real_call). `mismatch_fn`'s corpus origin is 0x00404000.
//! The verifier flags the slot mismatch.

use callgraph_verify_macro::vtable_table;

vtable_table! {
    name = mismatch_vt,
    va = 0x00A01000,
    slots = 1,
    default = crate::vtable_unimplemented_m;
    0 = mismatch_fn;
}

#[allow(dead_code)]
fn vtable_unimplemented_m() {}