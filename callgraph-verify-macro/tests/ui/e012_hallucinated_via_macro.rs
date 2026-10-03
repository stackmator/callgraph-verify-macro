//! Fixture: E012 HALLUCINATED via macro expansion.
//!
//! Expected: the body calls `oob_fn()` ONLY through `sneaky!`, whose
//! definition lives in the corpus (`tests/testdata/corpus/macro_defs.rs`,
//! pulled in with `include!` so rustc itself can expand it) — the corpus
//! registers `oob_fn` at 0x00405000, which the binary at 0x401000 never
//! calls. With macro expansion the verifier sees through `sneaky!` and
//! flags the direct edge as HALLUCINATED; without it the macro would stay
//! opaque (and only MISSING would fire).

include!("../testdata/corpus/macro_defs.rs");

use callgraph_verify_macro::origin;

#[origin(0x00401000)]
pub fn f() {
    sneaky!(0);
}
