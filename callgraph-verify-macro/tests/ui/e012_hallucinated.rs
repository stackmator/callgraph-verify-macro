//! Fixture: E012 HALLUCINATED.
//!
//! Expected: body calls `dispatched()` (which the corpus has registered at
//! 0x00403000), but the binary at 0x401000 never directly calls 0x403000 —
//! every caller reaches it via the vtable. The verifier flags the body's
//! direct invocation as HALLUCINATED.

use callgraph_verify_macro::origin;

#[origin(0x00401000)]
pub fn f() {
    dispatched();
}