//! Fixture: E014 ARG-SHAPE.
//!
//! Expected: the body calls `real_call(0x10)` (passes an immediate 0x10),
//! but the binary at 0x401000 stages `PUSH 0x20` immediately before its
//! `CALL 0x402000`, so the binary passes Imm(0x20). The verifier
//! compares the concrete arg kinds and flags the mismatch.

use callgraph_verify_macro::origin;

#[origin(0x00401000)]
pub fn f() {
    real_call(0x10);
}