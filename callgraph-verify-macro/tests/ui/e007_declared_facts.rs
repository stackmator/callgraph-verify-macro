//! Fixture: E007 DECLARED-FACTS.
//!
//! Expected: `fields = [0x4]` pins a field offset the synthetic PE does NOT
//! touch — its `.text` (PUSH/CALL/JE/JMP/dword) has no memory operand, so
//! `analyze` reports no field offsets and `Spec::check` rejects the declared
//! one. The verifier wraps the violation message in
//! `[CG-VERIFY-E007 DECLARED-FACTS]` and exits with compile_error!.

use callgraph_verify_macro::origin;

#[origin(0x00401000, fields = [0x4])]
pub fn f() {}