//! Fixture: E016 CFG.
//!
//! Expected: the body has NO loop (no `while`/`loop`/`for`), but the
//! binary at 0x401000 has 2 back-edges (the JMP-to-start loop and the
//! self-loop). cfg_fingerprint counts both, so the `loops >= 2 && body
//! loops == 0` gate fires.

use callgraph_verify_macro::origin;

#[origin(0x00401000)]
pub fn f() {
    real_call(0x20);
}