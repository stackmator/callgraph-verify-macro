//! Fixture: E002 UNKNOWN-ATTR-FLAG.
//!
//! Expected: bare flag other than `unreferenced` is rejected. The parser
//! points at the offending ident.

use callgraph_verify_macro::origin;

#[origin(0x00401000, strict_anything)]
pub fn f() {}