//! Fixture: E009 DUP-ADDR.
//!
//! Expected: two `#[origin(0x401000)]` functions claim the same binary
//! address. The corpus scanner records both as owners; the verifier gates
//! the second one on DUP-ADDR, listing all owners so the porter can find
//! the duplicate.

use callgraph_verify_macro::origin;

#[origin(0x00401000)]
pub fn first() {}

#[origin(0x00401000)]
pub fn second() {}