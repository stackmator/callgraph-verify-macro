//! Fixture: E013 MISSING.
//!
//! Expected: the binary at 0x401000 contains `CALL 0x00402000` (see the
//! synthetic-PE builder), but the body omits any call to `real_call`.
//! The verifier emits MISSING with the address and the corpus-resolved
//! name.

use callgraph_verify_macro::origin;

#[origin(0x00401000)]
pub fn f() {}