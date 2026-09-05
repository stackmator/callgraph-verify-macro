//! Fixture: E008 CORPUS-GAP.
//!
//! Expected: the address 0x401000 IS in the corpus (so the self-check
//! passes), but the corpus file contains ONLY that origin — a different
//! address 0x401100 is NOT in the corpus, so the self-check fails for it.
//! This pins the E008 wording.

use callgraph_verify_macro::origin;

#[origin(0x00401100)]
pub fn f() {}