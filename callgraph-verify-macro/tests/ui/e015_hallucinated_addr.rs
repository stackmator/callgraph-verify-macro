//! Fixture: E015 HALLUCINATED-ADDR.
//!
//! Expected: the body reads from `0x00A00004`, an in-image address (it's
//! inside the synthetic PE's `.rdata` section so `pe.section_of(...)`
//! succeeds) but NOT one the binary at 0x401000 references. The verifier
//! flags the stray literal.

use callgraph_verify_macro::origin;

#[origin(0x00401000)]
pub fn f() -> u32 {
    unsafe { (0x00A00004 as *const u32).read_volatile() }
}