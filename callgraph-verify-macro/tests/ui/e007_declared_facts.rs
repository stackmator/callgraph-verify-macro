//! Fixture: E007 DECLARED-FACTS.
//!
//! Expected: `calls_exact = [0x00402000]` pins a CALL the synthetic PE does
//! NOT contain, so `Spec::check` rejects it. The verifier wraps the
//! violation message in `[CG-VERIFY-E007 DECLARED-FACTS]` and exits with
//! compile_error!.

use callgraph_verify_macro::origin;

#[origin(0x00401000, calls_exact = [0x00402000])]
pub fn f() {}