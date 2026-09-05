//! Fixture: E010 FOLD-SKIP HOLE.
//!
//! Expected: the body calls `amb()`, which the corpus has registered as an
//! AMBIGUOUS inline helper (defined twice — `amb_a.rs` and `amb_b.rs`).
//! Ambiguous helpers can't be folded into the caller, so their ported call
//! to `real_call` (also a corpus-registered origin) silently escapes
//! verification. The verifier gates the build with E010 until the
//! ambiguity is resolved.

use callgraph_verify_macro::origin;

#[origin(0x00401000)]
pub fn f() {
    amb();
}