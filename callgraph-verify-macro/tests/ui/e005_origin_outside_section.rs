//! Fixture: E005 ORIGIN-OUTSIDE-SECTION.
//!
//! Expected: the address 0xFFFF0000 lies outside every PE section of the
//! synthetic PE (which maps `0x401000..0x401200` only). The verifier emits
//! E005 with the address embedded.

use callgraph_verify_macro::origin;

#[origin(0xFFFF0000)]
pub fn f() {}