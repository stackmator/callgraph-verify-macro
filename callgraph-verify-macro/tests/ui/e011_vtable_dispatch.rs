//! Fixture: E011 VTABLE-DISPATCH.
//!
//! Expected: the corpus declares a vtable at VA 0x00A00000 whose slot 0
//! holds the engine address 0x00403000, and registers `#[origin(0x00403000)]
//! fn dispatched()`. The fixture body calls `dispatched()` directly — but
//! the binary routes every caller through the vtable, so the verifier
//! gates the build with E011.

use callgraph_verify_macro::origin;

#[origin(0x00401000)]
pub fn f() {
    dispatched();
}