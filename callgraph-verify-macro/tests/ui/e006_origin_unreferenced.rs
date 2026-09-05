//! Fixture: E006 ORIGIN-UNREFERENCED.
//!
//! Expected: 0x401100 is inside `.text` but no byte in the binary encodes
//! a CALL/JMP/Jcc to it (the synthetic PE's .text is all zeros, so nothing
//! references anything). The verifier emits E006 with the waive hint.

use callgraph_verify_macro::origin;

#[origin(0x00401100)]
pub fn f() {}