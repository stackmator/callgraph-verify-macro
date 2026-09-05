//! Fixture: E004 TARGET-EXE-UNLOADABLE.
//!
//! This fixture forces E004 by setting TARGET_EXE (in the test runner) to a
//! path that exists on disk but is not a valid PE — the macro reads the env
//! at proc-macro expansion time and refuses to silently disable verification.
//! The .stderr snapshot pins the exact rendered message including the
//! `$DIR/tests/testdata/not_a_pe.bin` path, which is normalised by trybuild.

use callgraph_verify_macro::origin;

#[origin(0x00401000)]
pub fn f() {}