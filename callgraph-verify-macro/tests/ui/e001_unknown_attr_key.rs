//! Fixture: E001 UNKNOWN-ATTR-KEY.
//!
//! Expected: the parser rejects `bogus = [...]` on the attribute and the
//! rustc gutter points at the `bogus` ident. This is a `syn::Error` (not a
//! `RichError`), so the rendered text is propagated verbatim from the parser
//! message — agents grepping for `[CG-VERIFY-E001]` should find this exact
//! wording.

use callgraph_verify_macro::origin;

#[origin(0x00401000, bogus = [0x00402000])]
pub fn f() {}