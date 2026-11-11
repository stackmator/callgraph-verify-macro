//! Fixture: E022 BODY-SOURCE-UNAVAILABLE.
use callgraph_verify_macro::origin;

#[origin(0x00401000, body_from = [0xdeadbeef])]
pub fn alias() {}
