//! Rich error construction for the macro's `compile_error!` diagnostics.
//!
//! Each diagnostic carries:
//!   * a stable, machine-greppable `code` (e.g. `CG-VERIFY-E001 HALLUCINATED`),
//!   * a human-readable `message`,
//!   * an optional `fix` line ("-> fix: …"), and
//!   * an optional `span` — when present, the diagnostic is attached to the
//!     offending token in the source instead of the attribute call site, so
//!     rustc's gutter points at the line the agent must edit.
//!
//! `compile_error!` collapses multiple errors into one message, so the
//! constructor emits a multi-line string with `\n  ` indentation matching the
//! existing convention. We also produce a small per-`#[origin]` "context"
//! header so the agent can see binary-vs-body call sets side by side.
//!
//! Codes are part of the public contract: do not renumber. New codes append.

use proc_macro2::Span;
use std::fmt;

/// Stable error code. Append-only; never renumber. The numeric prefix is the
/// stable token an AI agent greps for; the suffix word is the human label
/// that's already in the existing prose (HALLUCINATED, MISSING, …). Tests
/// that assert on message text use the suffix word, not the number, so the
/// numbers can be reshuffled freely — but agents depend on them being stable,
/// so once published, don't change them.
///
/// `#[allow(dead_code)]` keeps the enum exhaustive even when a particular
/// code is currently emitted via the inline format string in `lib.rs`
/// (parser-side errors are propagated as `syn::Error`, not `RichError`,
/// because `syn` formats them itself). The codes are still part of the
/// documented contract and may be promoted to `RichError` later.
#[allow(dead_code)]
#[derive(Debug, Clone, Copy)]
pub enum Code {
    /// `#[origin(0xA, foo)]` — unknown key on the attribute. E001.
    UnknownAttrKey,
    /// `#[origin(foo)]` — bare flag other than `unreferenced`. E002.
    UnknownAttrFlag,
    /// The attribute was applied to a non-fn item. E003.
    NotAFunction,
    /// `TARGET_EXE` is set but the binary is unloadable / missing. E004.
    TargetExeUnloadable,
    /// The claimed origin address is outside any PE section. E005.
    OriginOutsideSection,
    /// The claimed origin address is never referenced in the binary. E006.
    OriginUnreferenced,
    /// Explicit declared facts (fields/globals/vtables/…) failed. E007.
    DeclaredFacts,
    /// `REBUILD_ROOT` is set but does not contain this `#[origin]`'s addr. E008.
    CorpusGap,
    /// Two Rust fns claim the same origin address. E009.
    DupAddr,
    /// Body directly calls a vtable method (must use `vcall_*`). E011.
    VTableDispatch,
    /// Body calls something the binary never does. E012.
    Hallucinated,
    /// Binary calls something the body omits. E013.
    Missing,
    /// Argument kinds at a call site disagree with the binary's recovery. E014.
    ArgShape,
    /// Body bakes an in-image address the binary never references. E015.
    HallucinatedAddr,
    /// Structural CFG divergence (loops, switches, conditionals). E016.
    Cfg,
    /// `analyze()` itself failed for the origin address. E017.
    Analyze,
    /// `cfg_fingerprint()` failed for the origin address. E018.
    CfgFingerprint,
    /// Per-slot vtable mismatch in a `vtable_table!`. E019.
    VTableSlot,
    /// A vtable slot was declared past `slots = N`. E020.
    VTableSlotOob,
}

impl Code {
    /// Stable numeric prefix (the part agents grep for). Do not change.
    pub fn number(self) -> &'static str {
        match self {
            Code::UnknownAttrKey => "E001",
            Code::UnknownAttrFlag => "E002",
            Code::NotAFunction => "E003",
            Code::TargetExeUnloadable => "E004",
            Code::OriginOutsideSection => "E005",
            Code::OriginUnreferenced => "E006",
            Code::DeclaredFacts => "E007",
            Code::CorpusGap => "E008",
            Code::DupAddr => "E009",
            Code::VTableDispatch => "E011",
            Code::Hallucinated => "E012",
            Code::Missing => "E013",
            Code::ArgShape => "E014",
            Code::HallucinatedAddr => "E015",
            Code::Cfg => "E016",
            Code::Analyze => "E017",
            Code::CfgFingerprint => "E018",
            Code::VTableSlot => "E019",
            Code::VTableSlotOob => "E020",
        }
    }

    /// Short label that already existed in the prose (HALLUCINATED, …).
    pub fn label(self) -> &'static str {
        match self {
            Code::UnknownAttrKey => "UNKNOWN-ATTR-KEY",
            Code::UnknownAttrFlag => "UNKNOWN-ATTR-FLAG",
            Code::NotAFunction => "NOT-A-FUNCTION",
            Code::TargetExeUnloadable => "TARGET-EXE-UNLOADABLE",
            Code::OriginOutsideSection => "ORIGIN-OUTSIDE-SECTION",
            Code::OriginUnreferenced => "ORIGIN-UNREFERENCED",
            Code::DeclaredFacts => "DECLARED-FACTS",
            Code::CorpusGap => "CORPUS-GAP",
            Code::DupAddr => "DUP-ADDR",
            Code::VTableDispatch => "VTABLE-DISPATCH",
            Code::Hallucinated => "HALLUCINATED",
            Code::Missing => "MISSING",
            Code::ArgShape => "ARG-SHAPE",
            Code::HallucinatedAddr => "HALLUCINATED-ADDR",
            Code::Cfg => "CFG",
            Code::Analyze => "ANALYZE",
            Code::CfgFingerprint => "CFG-FINGERPRINT",
            Code::VTableSlot => "VTABLE-SLOT",
            Code::VTableSlotOob => "VTABLE-SLOT-OOB",
        }
    }

    /// Full prefix as it appears in diagnostics: `[CG-VERIFY-E012 HALLUCINATED]`.
    pub fn prefix(self) -> String {
        format!("[CG-VERIFY-{} {}]", self.number(), self.label())
    }
}

impl fmt::Display for Code {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.prefix())
    }
}

/// One diagnostic produced by the verifier. `span` is the source location to
/// attach it to (the offending token when known, the attribute call site
/// otherwise); `fix` is an optional "-> fix: …" hint line.
#[derive(Debug, Clone)]
pub struct RichError {
    pub code: Code,
    pub message: String,
    pub fix: Option<String>,
    pub span: Option<Span>,
}

impl RichError {
    pub fn new(code: Code, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
            fix: None,
            span: None,
        }
    }

    /// Builder-style fix hint. Shown on a second indented line as
    /// `  -> fix: …`.
    pub fn with_fix(mut self, msg: impl Into<String>) -> Self {
        self.fix = Some(msg.into());
        self
    }

    /// Attach to a specific token in the source. Without this, the macro
    /// falls back to the attribute call site — agents get a green gutter
    /// next to the `#[origin(...)]` and have to search the body manually.
    pub fn with_span(mut self, span: Span) -> Self {
        self.span = Some(span);
        self
    }

    /// Render the diagnostic as one indented block.
    ///
    /// ```text
    ///   [CG-VERIFY-E012 HALLUCINATED] body calls `foo` (0x401000) — binary at 0x4028d0 never calls it
    ///     -> fix: remove the call, or port `foo` at 0x401000 with its own `#[origin(0xADDR)]`
    /// ```
    pub fn render(&self) -> String {
        let mut s = format!("  {} {}", self.code.prefix(), self.message);
        if let Some(fix) = &self.fix {
            s.push_str(&format!("\n    -> fix: {fix}"));
        }
        s
    }
}

impl std::fmt::Display for RichError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.render())
    }
}

/// Render many diagnostics under one header. The header carries the origin
/// address (and `vtable_table!` name when applicable) so an agent knows which
/// `#[origin]` produced the error without scrolling.
#[allow(dead_code)]
pub fn render_block(addr: u64, header: &str, errs: &[RichError]) -> String {
    let mut s = format!("#[origin({:#010x})] {}\n", addr, header);
    if errs.is_empty() {
        return s;
    }
    for e in errs {
        s.push('\n');
        s.push_str(&e.render());
    }
    s
}

/// Render a `vtable_table!` block under its own header.
#[allow(dead_code)]
pub fn render_vtable_block(name: &str, va: u64, errs: &[RichError]) -> String {
    let mut s = format!("vtable_table!({}, {va:#010x})", name);
    if errs.is_empty() {
        return s;
    }
    for e in errs {
        s.push('\n');
        s.push_str(&e.render());
    }
    s
}

/// Build a single `compile_error!` token from a diagnostic block, optionally
/// attached to a span. Falls back to `Span::call_site()` when the chosen
/// span is `None`. proc-macro2's `Span` does NOT implement `PartialEq`, so
/// we can't compare for "is this a call-site span" — instead we always
/// attach at the chosen span and add a note line when it differs from
/// `call_site()` via `Spanned::span()`'s location round-trip.
#[allow(dead_code)]
pub fn compile_error(msg: &str, span: Option<Span>) -> proc_macro::TokenStream {
    let sp = span.unwrap_or_else(Span::call_site);
    let err = syn::Error::new(sp, msg).to_compile_error();
    err.into()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn codes_are_stable() {
        // Regression: changing the numeric suffix breaks agents that grep
        // for these tokens. If you must renumber, update this test in the
        // same commit — and document the change in CHANGELOG.md.
        assert_eq!(Code::Hallucinated.number(), "E012");
        assert_eq!(Code::Missing.number(), "E013");
        assert_eq!(Code::ArgShape.number(), "E014");
        assert_eq!(Code::Cfg.number(), "E016");
        assert_eq!(Code::DupAddr.number(), "E009");
        assert_eq!(Code::HallucinatedAddr.number(), "E015");
        assert_eq!(Code::CorpusGap.number(), "E008");
    }

    #[test]
    fn prefix_includes_label() {
        let p = Code::Hallucinated.prefix();
        assert_eq!(p, "[CG-VERIFY-E012 HALLUCINATED]");
    }

    /// Exhaustive pin of every Code variant's stable contract: the numeric
    /// prefix, the human-readable label, and the assembled `[CG-VERIFY-E0XX
    /// LABEL]` string. If you change any of these, agents that grep build
    /// output will break — update this test in the same commit and document
    /// the change. Catches renumbering AND accidental label typos that would
    /// otherwise only show up in a trybuild stderr mismatch.
    #[test]
    fn all_codes_have_stable_prefix_label_and_prefix_string() {
        use Code::*;
        let cases: &[(&str, &str, Code)] = &[
            // (number, label, variant)
            ("E001", "UNKNOWN-ATTR-KEY", UnknownAttrKey),
            ("E002", "UNKNOWN-ATTR-FLAG", UnknownAttrFlag),
            ("E003", "NOT-A-FUNCTION", NotAFunction),
            ("E004", "TARGET-EXE-UNLOADABLE", TargetExeUnloadable),
            ("E005", "ORIGIN-OUTSIDE-SECTION", OriginOutsideSection),
            ("E006", "ORIGIN-UNREFERENCED", OriginUnreferenced),
            ("E007", "DECLARED-FACTS", DeclaredFacts),
            ("E008", "CORPUS-GAP", CorpusGap),
            ("E009", "DUP-ADDR", DupAddr),
            ("E011", "VTABLE-DISPATCH", VTableDispatch),
            ("E012", "HALLUCINATED", Hallucinated),
            ("E013", "MISSING", Missing),
            ("E014", "ARG-SHAPE", ArgShape),
            ("E015", "HALLUCINATED-ADDR", HallucinatedAddr),
            ("E016", "CFG", Cfg),
            ("E017", "ANALYZE", Analyze),
            ("E018", "CFG-FINGERPRINT", CfgFingerprint),
            ("E019", "VTABLE-SLOT", VTableSlot),
            ("E020", "VTABLE-SLOT-OOB", VTableSlotOob),
        ];
        for (number, label, code) in cases {
            assert_eq!(code.number(), *number, "number drift for {:?}", code);
            assert_eq!(code.label(), *label, "label drift for {:?}", code);
            assert_eq!(
                code.prefix(),
                format!("[CG-VERIFY-{number} {label}]"),
                "prefix assembly drift for {:?}",
                code
            );
        }
    }

    /// Every Code renders into the indented block shape that rustc sees in
    /// compile_error! output. This catches a typo in `RichError::render`
    /// (e.g. losing the leading two-space indent) which would only otherwise
    /// surface in trybuild stderr mismatches.
    #[test]
    fn render_indents_message_and_fix_with_stable_shape() {
        let e = RichError::new(Code::Missing, "binary calls `foo` (0x401000)")
            .with_fix("port `foo` to 0x401000");
        let s = e.render();
        // Indent: two-space prefix on the first line, four-space prefix on
        // the fix line.
        assert!(
            s.starts_with("  [CG-VERIFY-E013 MISSING] binary calls `foo`"),
            "first-line shape drifted: {s:?}"
        );
        assert!(
            s.contains("\n    -> fix: port `foo` to 0x401000"),
            "fix-line shape drifted: {s:?}"
        );
    }

    #[test]
    fn rich_error_renders_fix_on_second_line() {
        let e = RichError::new(Code::Hallucinated, "body calls `foo` (0x401000)")
            .with_fix("remove the call");
        let s = e.render();
        assert!(s.starts_with("  [CG-VERIFY-E012 HALLUCINATED] body calls `foo`"));
        assert!(s.contains("\n    -> fix: remove the call"));
    }

    #[test]
    fn render_block_lists_all_diagnostics() {
        let errs = vec![
            RichError::new(Code::Hallucinated, "x"),
            RichError::new(Code::Missing, "y"),
        ];
        let s = render_block(0x4028d0, "verification failed", &errs);
        assert!(s.contains("#[origin(0x004028d0)] verification failed"));
        assert!(s.contains("[CG-VERIFY-E012 HALLUCINATED] x"));
        assert!(s.contains("[CG-VERIFY-E013 MISSING] y"));
    }
}