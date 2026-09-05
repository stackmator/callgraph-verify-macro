//! Fixture: E003 NOT-A-FUNCTION.
//!
//! Expected: attribute on a non-fn item (here, a struct) fails fast. The
//! macro must never silently walk a struct's field list as a "body" — that
//! was a real bug before the syn-parse path landed.

use callgraph_verify_macro::origin;

#[origin(0x00401000)]
pub struct NotAFunction {
    pub x: u32,
}