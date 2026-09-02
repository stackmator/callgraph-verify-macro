//! Extract the set of function names a Rust function body calls, by walking its
//! token tree. A call site is an identifier immediately followed by a `(...)`
//! group: `foo(..)`, `path::foo(..)`, AND method calls `x.foo(..)`. Method calls
//! are included because a faithful port routinely calls a ported fn as a method
//! (`HEAP.allocate(..)` → `MemoryHeap::Allocate` 0x00401aa0), and the strict
//! MISSING check would otherwise flag that real call as absent. Generic method
//! names that collide with std/trait fns (`.get()`, `.clone()`, …) are filtered
//! by [`DENY`]; resolution further requires the name to be `origin:`-tagged.

use proc_macro2::{Delimiter, TokenStream, TokenTree};
use std::collections::HashSet;
use syn::visit::{self, Visit};
use syn::{Block, Expr, ExprCall, ExprLit, ExprMethodCall, ImplItemFn, ItemFn, Lit};

/// Common std/core/trait method names that collide with generically-named ported
/// fns; resolving them by bare name is unreliable, so they're excluded (same list
/// as verify_callgraph.py). Cost: a hallucinated call to a *generically* named
/// ported fn isn't caught; distinctly-named ones still are.
pub const DENY: &[&str] = &[
    "new",
    "default",
    "from",
    "with_capacity",
    "push",
    "pop",
    "len",
    "is_empty",
    "clone",
    "into",
    "value",
    "get",
    "set",
    "add",
    "sub",
    "mul",
    "div",
    "parse",
    "next",
    "iter",
    "map",
    "collect",
    "unwrap",
    "expect",
    "read",
    "write",
    "abs",
    "sqrt",
    "min",
    "max",
    "as_ptr",
    "as_mut_ptr",
    "read_unaligned",
    "write_unaligned",
    "to_vec",
    "to_bits",
    "from_bits",
    "contains",
    "insert",
    "remove",
    "find",
    "count",
    "sort_by",
    "load",
    "store",
    "offset",
    "wrapping_add",
];

/// Call sites found in a body, split by syntactic kind so name resolution can
/// disambiguate collisions (e.g. the CRT free-fn `free()` vs the method
/// `x.free()` / `MemoryHeap::Free`).
#[derive(Default)]
pub struct BodyCalls {
    /// `foo(..)` and `path::foo(..)` — resolved against free/associated fns.
    pub plain: HashSet<String>,
    /// `x.foo(..)` — resolved against methods (fns with a `self` receiver).
    pub method: HashSet<String>,
}

/// Everything the verifier harvests from one function body in a single syn
/// pass: call NAMES (for the corpus diff), per-site call EXPRESSIONS with
/// classified args (for the ARG-SHAPE diff), and MACRO invocations — whose
/// bodies are opaque token streams the verifier cannot see (surfaced as a
/// NOTE by the macro, never silently skipped).
pub struct FnBodyFacts {
    pub names: BodyCalls,
    pub exprs: Vec<CallExpr>,
    pub macros: Vec<String>,
}

struct FnBodyVisitor {
    facts: FnBodyFacts,
}

impl<'ast> Visit<'ast> for FnBodyVisitor {
    fn visit_expr_call(&mut self, e: &'ast ExprCall) {
        if let Expr::Path(p) = &*e.func {
            if let Some(seg) = p.path.segments.last() {
                let name = seg.ident.to_string();
                self.facts.exprs.push(CallExpr {
                    name: name.clone(),
                    is_method: false,
                    // Turbofish (`foo::<u32>(..)`) lives in the path segment's
                    // generic arguments; the callee name is still the segment
                    // ident, so explicit generics resolve like plain calls.
                    args: e.args.iter().map(classify_expr).collect(),
                });
                self.facts.names.plain.insert(name);
            }
        }
        visit::visit_expr_call(self, e);
    }

    fn visit_expr_method_call(&mut self, m: &'ast ExprMethodCall) {
        let name = m.method.to_string();
        self.facts.exprs.push(CallExpr {
            name: name.clone(),
            is_method: true,
            args: m.args.iter().map(classify_expr).collect(),
        });
        self.facts.names.method.insert(name);
        visit::visit_expr_method_call(self, m);
    }

    fn visit_macro(&mut self, mac: &'ast syn::Macro) {
        if let Some(seg) = mac.path.segments.last() {
            self.facts.macros.push(seg.ident.to_string());
        }
        // No recursion into `mac.tokens`: a macro body is an opaque token
        // stream — calls/loops inside it cannot be statically verified. The
        // macro surfaces `macros` as an OPAQUE-MACRO note instead.
    }
}

/// Harvest [`FnBodyFacts`] from a parsed block. Syn-based on purpose: the
/// token-tree walker mis-classified turbofish calls (`foo::<u32>(x)` — an
/// Ident followed by `::`/`<` puncts, not a paren group) as "not a call",
/// counted tuple-pattern destructures (`let Foo(a) = y;`) as calls, and could
/// not distinguish a macro invocation from anything else.
pub fn collect_block_facts(block: &Block) -> FnBodyFacts {
    let mut v = FnBodyVisitor {
        facts: FnBodyFacts {
            names: BodyCalls::default(),
            exprs: Vec::new(),
            macros: Vec::new(),
        },
    };
    v.visit_block(block);
    v.facts
}

/// A `#[origin]`-attributed item: a free fn or an impl/trait method (attribute
/// macros receive both as `attrs + fn-head + block` token streams).
pub enum FnLike {
    Free(ItemFn),
    Method(ImplItemFn),
}

impl FnLike {
    pub fn block(&self) -> &Block {
        match self {
            FnLike::Free(f) => &f.block,
            FnLike::Method(m) => &m.block,
        }
    }
}

/// Parse the attribute's item as a function (free or method). `Err` means the
/// macro was applied to a non-fn item — the caller turns that into a
/// `compile_error!` instead of walking e.g. a struct's field list as a "body".
pub fn parse_fn_like(ts: &TokenStream) -> syn::Result<FnLike> {
    if let Ok(f) = syn::parse2::<ItemFn>(ts.clone()) {
        return Ok(FnLike::Free(f));
    }
    syn::parse2::<ImplItemFn>(ts.clone()).map(FnLike::Method)
}

/// Classify a parsed argument expression into a [`RustArg`], mirroring the
/// binary-side `ArgKind`. Only confidently-classifiable forms are concrete:
/// integer literals (`Imm`, any base, suffix tolerated), the byte-helper
/// idioms `rd*(base, 0xNN)` (`Field`) and `g*(addr)` (`Global`). Floats,
/// negatives, paths, arithmetic and macro output are `Other` — the ARG-SHAPE
/// diff skips non-concrete positions.
pub fn classify_expr(e: &Expr) -> RustArg {
    match e {
        Expr::Lit(ExprLit {
            lit: Lit::Int(li), ..
        }) => li
            .base10_parse::<u64>()
            .map(RustArg::Imm)
            .unwrap_or(RustArg::Other),
        Expr::Call(c) => {
            let Expr::Path(p) = &*c.func else {
                return RustArg::Other;
            };
            if p.path.segments.len() != 1 {
                return RustArg::Other;
            }
            let name = p.path.segments[0].ident.to_string();
            let args: Vec<&Expr> = c.args.iter().collect();
            if matches!(
                name.as_str(),
                "rd8" | "rd16" | "rd32" | "rd64" | "rdf32" | "rdf64"
            ) && args.len() >= 2
            {
                if let RustArg::Imm(off) = classify_expr(args[1]) {
                    return RustArg::Field(off);
                }
                return RustArg::Other;
            }
            if matches!(
                name.as_str(),
                "g8" | "g16" | "g32" | "g64" | "gf32" | "gf64"
            ) && !args.is_empty()
            {
                return match classify_expr(args[0]) {
                    RustArg::Imm(a) | RustArg::Global(a) => RustArg::Global(a),
                    _ => RustArg::Other,
                };
            }
            RustArg::Other
        }
        _ => RustArg::Other,
    }
}

/// A recovered Rust argument, classified to mirror the binary-side `callgraph_verify::ArgKind`
/// so the two can be diffed. Only the confidently-classifiable kinds; everything else is `Other`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RustArg {
    Imm(u64),
    Field(u64),
    Global(u64),
    Other,
}

/// One call expression in the body: the callee name, whether it was a method call (`x.f(..)`),
/// and its classified positional arguments.
#[derive(Debug)]
pub struct CallExpr {
    pub name: String,
    pub is_method: bool,
    pub args: Vec<RustArg>,
}

/// Coarse control-flow keyword counts of a body, for the CFG-fingerprint diff. Counts keyword
/// identifiers anywhere in the token tree (a crude but adequate proxy for source control flow).
#[derive(Default, Debug)]
pub struct RustCfg {
    /// Iterations that actually loop: `while`/`loop`/`for` whose body is not
    /// a single immediate `break`/`return` (those are placeholder no-ops,
    /// not iterations — see `cfg_keyword_counts`).
    pub loops: usize,
    pub matches: usize, // match
    pub ifs: usize,     // if
    pub returns: usize, // return
}

/// Locations of `loop { ... }` blocks that are syntactic placeholders —
/// the body is an immediate `break;` (with at most leading trivia), so the
/// "loop" never iterates. Reported separately so the macro can flag a
/// body that uses these to satisfy the CFG check without reproducing the
/// binary's iteration.
#[derive(Default, Debug)]
pub struct FakeLoops {
    /// Each entry: the span of the `loop` keyword, paired with a short
    /// reason string for the error message (e.g. "body is just `break;`").
    pub spans: Vec<(proc_macro2::Span, &'static str)>,
}

pub fn cfg_keyword_counts(ts: TokenStream) -> RustCfg {
    let mut c = RustCfg::default();
    let mut fakes = FakeLoops::default();
    // Single fake-loop pass at the top level (the walker recurses into
    // every group, so this finds all fakes in one walk — calling it
    // again inside the count loop would double-count).
    walk_for_fake_loops(ts.clone(), &mut fakes);
    count_kw(ts, &mut c);
    // Subtract placeholder `loop {}`s from the count — they appear in the
    // token stream as `loop` keywords but don't actually iterate. The
    // caller (the macro's CFG check) still sees the fakes list and can
    // surface them as a NOTE explaining why the count went down.
    c.loops = c.loops.saturating_sub(fakes.spans.len());
    c
}

/// Detect placeholder loops whose body is a single immediate `break;` (with
/// at most leading punctuation / comments). Catches two shapes:
///
///   * `loop { break; }` — bare `loop` keyword, no condition.
///   * `while <expr> { break; }` — `while` with an unconditional `break;`
///     on iteration 1. The condition expression may contain real code (the
///     call you wanted to invoke), but the LOOP does not iterate. A body
///     that uses `let _ = while !cond { break; };` would otherwise count
///     as a real loop and slip past the CFG gate.
///
/// `for x in xs { break; }` is NOT flagged: the iterator expression is
/// meaningful and the loop body is non-trivial even if it breaks
/// immediately — `for` has no analogous fake shape.
///
/// Other patterns — `loop { let x = foo(); break; }`, `loop { if cond {
/// break; } ... }`, `while cond { ... real work ...; break; }` — are NOT
/// flagged: those have real structure even if they don't match the binary.
pub fn fake_loop_spans(ts: TokenStream) -> FakeLoops {
    let mut f = FakeLoops::default();
    walk_for_fake_loops(ts, &mut f);
    f
}

fn walk_for_fake_loops(ts: TokenStream, f: &mut FakeLoops) {
    let tts: Vec<TokenTree> = ts.into_iter().collect();
    for (i, tt) in tts.iter().enumerate() {
        if let TokenTree::Group(g) = tt {
            walk_for_fake_loops(g.stream(), f);
        }
        // Look for the pattern: `loop` or `while` ident followed by a
        // `{ ... }` group whose entire body is `break;`.
        if let TokenTree::Ident(id) = tt {
            let kw = id.to_string();
            if kw != "loop" && kw != "while" {
                continue;
            }
            // Skip `for ... { ... }` — `for` has its own dedicated shape and
            // is structurally different (iterator expression matters even if
            // the body breaks immediately).
            if let Some(TokenTree::Ident(prev)) = tts.get(i.wrapping_sub(1)) {
                if prev == "for" {
                    continue;
                }
            }
            // For `loop`, the body group is the very next token. For
            // `while`, the body group follows the condition expression
            // (`!cond`, `foo()`, `let x = …`); scan forward until we find
            // the first `{ ... }` group, ignoring any other groups (parens
            // around the condition) and Puncts/Idents in between.
            let body_group = if kw == "loop" {
                tts.get(i + 1)
            } else {
                scan_for_body_group(&tts, i + 1)
            };
            let Some(TokenTree::Group(g)) = body_group else { continue };
            if g.delimiter() != Delimiter::Brace {
                continue;
            }
            if is_placeholder_break_body(g.stream()) {
                let reason: &'static str = if kw == "while" {
                    "body is just `break;` under `while`"
                } else {
                    "body is just `break;`"
                };
                f.spans.push((id.span(), reason));
            }
        }
    }
}

/// Walk forward from `start` looking for the `{ ... }` group that follows
/// a `while` keyword's condition expression. The condition may be a single
/// identifier (`while cond`), a unary prefix (`while !cond`), a function
/// call (`while cond()`), a parenthesised expression (`while (a && b)`),
/// or a `let` binding (`while let Some(x) = foo.next()`). All of those
/// surface as Puncts / Idents / paren-groups between the `while` and the
/// body brace — none of them are themselves the body brace.
///
/// We step past everything except the first `{ ... }` Brace group we see;
/// that group is the loop body. Paren groups (`( ... )`) are skipped past
/// in one step (their contents may contain unrelated braces from nested
/// generics — `while let Some(HashMap<K, V>) = …`). A `[ ... ]` Bracket
/// group inside a `while let` pattern (e.g. `while let [a, b] = arr`) is
/// similarly stepped past.
fn scan_for_body_group<'a>(tts: &'a [TokenTree], start: usize) -> Option<&'a TokenTree> {
    let mut j = start;
    while let Some(tt) = tts.get(j) {
        match tt {
            TokenTree::Group(g) if g.delimiter() == Delimiter::Brace => return Some(tt),
            TokenTree::Group(_) => j += 1,
            _ => j += 1,
        }
    }
    None
}

fn is_placeholder_break_body(body: TokenStream) -> bool {
    // Skip leading trivia (punctuation like ; or ,) and any nested
    // doc/regular comments via whitespace — proc_macro2 surfaces comments
    // as `Punct`s with no text, so we only need to filter non-trivia
    // tokens. Acceptable placeholders: just `break;` (with optional
    // trailing semicolon and optional surrounding whitespace tokens).
    let mut seen_break = false;
    for tt in body {
        match tt {
            TokenTree::Ident(id) => {
                if id == "break" && !seen_break {
                    seen_break = true;
                } else {
                    return false;
                }
            }
            TokenTree::Punct(_) => continue, // ; , etc. — trivia
            TokenTree::Literal(_) => return false, // any literal = real code
            TokenTree::Group(_) => return false, // any nested group = real code
        }
    }
    seen_break
}

fn count_kw(ts: TokenStream, c: &mut RustCfg) {
    for tt in ts {
        match tt {
            TokenTree::Group(g) => count_kw(g.stream(), c),
            TokenTree::Ident(id) => match id.to_string().as_str() {
                "while" | "loop" | "for" => c.loops += 1,
                "match" => c.matches += 1,
                "if" => c.ifs += 1,
                "return" => c.returns += 1,
                _ => {}
            },
            _ => {}
        }
    }
}

/// Collect every **hex** integer literal (`0x...`) appearing anywhere in a token
/// stream, type-suffix and `_` separators tolerated (`0x00b333b0u32`, `0xa7_e38c`).
/// Used by the opt-in operand-fact check to harvest the in-image ADDRESS constants
/// a body bakes in (globals, RTTI typedescs, vtable VAs, fn pointers). Restricted
/// to hex form on purpose: every VA in this corpus is written in hex, and a decimal
/// literal that coincidentally lands in a PE section would be a false positive.
pub fn collect_hex_literals(ts: TokenStream) -> Vec<u64> {
    let mut out = Vec::new();
    walk_hex(ts, &mut out);
    out
}

fn walk_hex(ts: TokenStream, out: &mut Vec<u64>) {
    for tt in ts {
        match tt {
            TokenTree::Group(g) => walk_hex(g.stream(), out),
            TokenTree::Literal(l) => {
                let s = l.to_string();
                let Some(rest) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) else {
                    continue;
                };
                // Take leading hex digits / `_`, stopping at the type suffix (`u32`…).
                let hex: String = rest
                    .chars()
                    .take_while(|c| c.is_ascii_hexdigit() || *c == '_')
                    .filter(|c| *c != '_')
                    .collect();
                if !hex.is_empty() {
                    if let Ok(v) = u64::from_str_radix(&hex, 16) {
                        out.push(v);
                    }
                }
            }
            _ => {}
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proc_macro2::TokenStream;
    use quote::ToTokens;
    use std::str::FromStr;

    /// Parse a full `fn` source and harvest facts from its body block — the
    /// exact path `verify_impl` takes (`parse_fn_like` -> `collect_block_facts`).
    fn facts_of(src: &str) -> FnBodyFacts {
        let f: ItemFn = syn::parse_str(src).expect("parse fn");
        collect_block_facts(&f.block)
    }

    fn hex_of_body(src: &str) -> Vec<u64> {
        let f: ItemFn = syn::parse_str(src).expect("parse fn");
        let ts = f.block.to_token_stream();
        collect_hex_literals(ts)
    }

    // --- syn visitor: turbofish / patterns / macros -------------------------

    /// Regression (audit probe): `foo::<u32>(1)` was INVISIBLE to the old
    /// token walker (an Ident followed by `::`/`<` puncts, not a paren group)
    /// — a real call missed -> false MISSING; a hallucinated call missed ->
    /// false pass. The syn visitor sees `ExprCall` regardless of turbofish.
    #[test]
    fn turbofish_call_is_collected() {
        let facts = facts_of("fn f() { foo::<u32>(1); }");
        assert!(facts.names.plain.contains("foo"), "{:?}", facts.names.plain);
        assert_eq!(facts.exprs.len(), 1, "{:?}", facts.exprs);
        assert_eq!(facts.exprs[0].name, "foo");
        assert!(!facts.exprs[0].is_method);
    }

    #[test]
    fn turbofish_method_call_is_collected_as_method() {
        let facts = facts_of("fn f() { x.foo::<u32>(1); }");
        assert!(facts.names.method.contains("foo"), "{:?}", facts.names.method);
        assert!(facts.names.plain.is_empty(), "{:?}", facts.names.plain);
        assert!(facts.exprs.len() == 1 && facts.exprs[0].is_method, "{:?}", facts.exprs);
    }

    /// A tuple-struct pattern `let Foo(a) = y;` is a PATTERN, not a call
    /// expression — the token walker counted `Foo` as a call (noise in the
    /// corpus diff); the syn visitor must not.
    #[test]
    fn tuple_struct_pattern_is_not_a_call() {
        let facts = facts_of("fn f(y: Foo) { let Foo(_a) = y; }");
        assert!(facts.names.plain.is_empty(), "{:?}", facts.names.plain);
        assert!(facts.exprs.is_empty(), "{:?}", facts.exprs);
    }

    /// Macro invocations are OPAQUE: captured by name in `facts.macros` (the
    /// macro emits an OPAQUE-MACRO note) and NOT recursed — `all_work!(x)`
    /// inside the body must not contribute call names or CFG keywords.
    #[test]
    fn macro_invocations_are_captured_and_not_recursed() {
        let facts = facts_of("fn f() { my_macro!(); other!(1, 2); }");
        assert!(facts.macros.contains(&"my_macro".to_string()), "{:?}", facts.macros);
        assert!(facts.macros.contains(&"other".to_string()), "{:?}", facts.macros);
        assert!(facts.names.plain.is_empty(), "{:?}", facts.names.plain);
        assert!(facts.exprs.is_empty(), "{:?}", facts.exprs);
    }

    /// Path-qualified calls record just the trailing segment (B-04).
    #[test]
    fn path_qualified_call_records_trailing_segment() {
        let facts = facts_of("fn f() { crate::module::func(1, 2); }");
        assert!(facts.names.plain.contains("func"), "{:?}", facts.names.plain);
        assert!(!facts.names.plain.contains("crate"), "{:?}", facts.names.plain);
        assert!(!facts.names.plain.contains("module"), "{:?}", facts.names.plain);
    }

    /// The fn's own name and anything inside attributes are not body calls —
    /// `collect_block_facts` only sees the parsed Block. (BUG #13 / #14)
    #[test]
    fn fn_name_and_attrs_are_not_body_calls() {
        let src = "#[some_attr(default = attribute_fn())] fn outer() { real_fn(); }";
        let f: ItemFn = syn::parse_str(src).expect("parse fn");
        let facts = collect_block_facts(&f.block);
        assert!(facts.names.plain.contains("real_fn"), "{:?}", facts.names.plain);
        assert!(!facts.names.plain.contains("attribute_fn"), "{:?}", facts.names.plain);
        assert!(!facts.names.plain.contains("outer"), "{:?}", facts.names.plain);
    }

    // --- classify_expr (ARG-SHAPE argument classification) ------------------

    /// Only the canonical byte-helper names classify as field accesses; the
    /// old `starts_with("rd")` over-matched `read`/`rdata`. (BUG #7)
    #[test]
    fn classify_expr_rd_helpers_are_field() {
        for name in ["rd8", "rd16", "rd32", "rd64", "rdf32", "rdf64"] {
            let e: Expr = syn::parse_str(&format!("{name}(base, 0x10)")).unwrap();
            assert!(matches!(classify_expr(&e), RustArg::Field(0x10)), "{name}");
        }
        for name in ["read", "rdata", "rdb", "rdr"] {
            let e: Expr = syn::parse_str(&format!("{name}(base, 0x10)")).unwrap();
            assert!(matches!(classify_expr(&e), RustArg::Other), "{name}");
        }
    }

    #[test]
    fn classify_expr_g_helpers_are_global() {
        for name in ["g8", "g16", "g32", "g64", "gf32", "gf64"] {
            let e: Expr = syn::parse_str(&format!("{name}(0x00BEEF)")).unwrap();
            assert!(matches!(classify_expr(&e), RustArg::Global(0xBEEF)), "{name}");
        }
    }

    #[test]
    fn classify_expr_int_literal_is_imm() {
        for lit in ["0x10", "16", "16u32", "0x10_u32"] {
            let e: Expr = syn::parse_str(lit).unwrap();
            assert!(matches!(classify_expr(&e), RustArg::Imm(0x10)), "{lit}");
        }
    }

    /// A float literal must NOT classify as a concrete immediate — the old
    /// token parse of "1.5" yielded Imm(1) and fed ARG-SHAPE a fabricated
    /// constant to mismatch against.
    #[test]
    fn classify_expr_float_is_other() {
        for lit in ["1.5", "1.5f32", "2e3"] {
            let e: Expr = syn::parse_str(lit).unwrap();
            assert!(matches!(classify_expr(&e), RustArg::Other), "{lit}");
        }
    }

    #[test]
    fn classify_expr_rd_with_non_literal_offset_is_other() {
        let e: Expr = syn::parse_str("rd32(base, offset)").unwrap();
        assert!(matches!(classify_expr(&e), RustArg::Other));
    }

    // --- collect_hex_literals (operand-fact check input) --------------------

    /// The caller passes ONLY the body block (`parse_fn_like` -> block), so
    /// hex inside `#[origin(0xA, calls = [0xB, 0xC])]` structurally cannot
    /// leak into the operand check. (BUG #13)
    #[test]
    fn collect_hex_literals_excludes_attribute_addresses() {
        let lits = hex_of_body(
            "#[origin(0x004028d0, calls = [0x00401f00, 0x00401f20])] fn outer() {}",
        );
        assert!(!lits.contains(&0x004028d0), "attr hex leaked: {:?}", lits);
        assert!(!lits.contains(&0x00401f00), "attr hex leaked: {:?}", lits);
        assert!(!lits.contains(&0x00401f20), "attr hex leaked: {:?}", lits);
    }

    /// Hex literals INSIDE the body ARE included.
    #[test]
    fn collect_hex_literals_includes_body_literals() {
        let lits = hex_of_body("#[origin(0x004028d0)] fn outer() { let g = 0x00401f00u32; }");
        assert!(lits.contains(&0x00401f00), "{:?}", lits);
        assert!(!lits.contains(&0x004028d0), "attr leaked: {:?}", lits);
    }

    // --- cfg_keyword_counts / fake_loop_spans (fake-loop placeholder guard) -

    /// A real `loop { ... }` that contains code BEFORE the break (or no
    /// break at all) is NOT a placeholder — `cfg_keyword_counts` should
    /// count it as 1 and `fake_loop_spans` should report zero.
    #[test]
    fn cfg_real_loop_with_iteration_is_counted() {
        let ts = TokenStream::from_str(
            "pub fn outer() { loop { foo(); if cond { break; } } }",
        )
        .unwrap();
        let r = cfg_keyword_counts(ts.clone());
        assert_eq!(r.loops, 1, "real loop should count: {:?}", r);
        let f = fake_loop_spans(ts);
        assert!(f.spans.is_empty(), "real loop should not be flagged as fake: {:?}", f.spans);
    }

    /// The exact pattern from the bug report: `loop { break; }` (possibly
    /// with a comment, possibly without a semicolon). `cfg_keyword_counts`
    /// must subtract it (return 0) and `fake_loop_spans` must flag it.
    #[test]
    fn cfg_fake_loop_placeholder_is_subtracted() {
        // Bare form: `loop { break; }`
        let ts = TokenStream::from_str("pub fn outer() { loop { break; } }").unwrap();
        let r = cfg_keyword_counts(ts.clone());
        assert_eq!(r.loops, 0, "fake loop must NOT count as iteration: {:?}", r);
        let f = fake_loop_spans(ts.clone());
        assert_eq!(f.spans.len(), 1, "expected 1 fake loop, got {}: {:?}", f.spans.len(), f.spans);
        assert_eq!(f.spans[0].1, "body is just `break;`");

        // Without the trailing semicolon — still a placeholder.
        let ts = TokenStream::from_str("pub fn outer() { loop { break } }").unwrap();
        let r = cfg_keyword_counts(ts.clone());
        assert_eq!(r.loops, 0, "fake loop (no semi) must NOT count: {:?}", r);

        // Mixed: 2 real + 1 fake. Net count should be 2.
        let ts = TokenStream::from_str(
            "pub fn outer() { loop { foo(); if cond { break; } } loop { break; } \
             loop { bar(); if other { break; } } }",
        )
        .unwrap();
        let r = cfg_keyword_counts(ts.clone());
        assert_eq!(r.loops, 2, "3 loops - 1 fake = 2: {:?}", r);
        let f = fake_loop_spans(ts);
        assert_eq!(f.spans.len(), 1, "exactly 1 fake in 3 loops: {:?}", f.spans);
    }

    /// Sanity: a body with NO `loop` keyword at all returns 0 loops, zero
    /// fake loops. Guards against an over-eager walker that subtracts
    /// from nothing.
    #[test]
    fn cfg_no_loop_keyword_yields_zero_loops() {
        let ts = TokenStream::from_str("pub fn outer() { foo(); bar(); }").unwrap();
        let r = cfg_keyword_counts(ts.clone());
        assert_eq!(r.loops, 0, "{}", r.loops);
        let f = fake_loop_spans(ts);
        assert!(f.spans.is_empty(), "no fake loops: {:?}", f.spans);
    }

/// `for` is NOT a placeholder: it always carries an iterator expression
    /// and the loop body's first break being immediate doesn't make the
    /// loop fake. `cfg_keyword_counts` counts it as a real loop;
    /// `fake_loop_spans` ignores it.
    ///
    /// `while cond { break; }` IS a placeholder: the LOOP never iterates
    /// (it breaks on entry 1), so it satisfies `c.loops` without doing
    /// real work. `fake_loop_spans` flags it; `cfg_keyword_counts`
    /// subtracts it.
    #[test]
    fn cfg_for_is_real_loop_while_with_break_is_fake() {
        // `for x in xs { break; }` — real loop, not a placeholder.
        let ts = TokenStream::from_str(
            "pub fn outer() { for x in xs { break; } }",
        )
        .unwrap();
        let r = cfg_keyword_counts(ts.clone());
        assert_eq!(r.loops, 1, "`for` counts as a real loop: {:?}", r);
        let f = fake_loop_spans(ts);
        assert!(f.spans.is_empty(), "`for` is never fake: {:?}", f);

        // `while cond { break; }` — fake: the loop never iterates.
        let ts = TokenStream::from_str(
            "pub fn outer() { while cond { break; } }",
        )
        .unwrap();
        let r = cfg_keyword_counts(ts.clone());
        assert_eq!(r.loops, 0, "fake `while` must NOT count as iteration: {:?}", r);
        let f = fake_loop_spans(ts);
        assert_eq!(f.spans.len(), 1, "expected 1 fake `while`: {:?}", f);
        assert_eq!(f.spans[0].1, "body is just `break;` under `while`");

        // `while cond { real_work(); break; }` — NOT a placeholder: the body
        // has real work before the break, so it counts as a real loop.
        let ts = TokenStream::from_str(
            "pub fn outer() { while cond { foo(); break; } }",
        )
        .unwrap();
        let r = cfg_keyword_counts(ts.clone());
        assert_eq!(r.loops, 1, "real `while` body counts: {:?}", r);
        let f = fake_loop_spans(ts);
        assert!(f.spans.is_empty(), "real `while` body is not fake: {:?}", f);

        // Mixed: 1 fake `while` + 1 real `for`. Net count = 1.
        let ts = TokenStream::from_str(
            "pub fn outer() { while cond { break; } for x in xs { break; } }",
        )
        .unwrap();
        let r = cfg_keyword_counts(ts.clone());
        assert_eq!(r.loops, 1, "fake `while` subtracted: {:?}", r);
        let f = fake_loop_spans(ts);
        assert_eq!(f.spans.len(), 1, "exactly 1 fake: {:?}", f);
    }

    /// Regression: the exact shape from the `ni_source_texture_load_binary`
    /// bug report. `let _x = while !cond { break; };` is invalid Rust AND
    /// a fake-loop placeholder — it adds nothing to `r.loops` because the
    /// loop never iterates. Without this, the rebuild body containing two
    /// such placeholders silently passed the CFG gate (binary has 2
    /// loops, body "has" 2 loops — both fake).
    #[test]
    fn cfg_fake_while_with_negation_is_subtracted() {
        // The exact bug-report shape: `let _buf = while !cond { break; };`
        let ts = TokenStream::from_str(
            "pub fn outer() { let _buf = while !cond { break; }; }",
        )
        .unwrap();
        let r = cfg_keyword_counts(ts.clone());
        assert_eq!(r.loops, 0, "fake `while !cond {{ break; }}` must not count: {:?}", r);
        let f = fake_loop_spans(ts.clone());
        assert_eq!(f.spans.len(), 1, "expected 1 fake: {:?}", f);
        assert_eq!(f.spans[0].1, "body is just `break;` under `while`");

        // Full ni_source_texture_load_binary shape: two fake whiles + a
        // real `for` in the middle. Net count = 1 (the real `for`).
        let ts = TokenStream::from_str(
            "pub fn outer() { \
                 let _a = while !mgr_dispatch(this) { break; }; \
                 for i in 0..n { wr16(buf, i, read_u16(s)); } \
                 let _b = while !mgr_state_init(this) { break; }; \
             }",
        )
        .unwrap();
        let r = cfg_keyword_counts(ts.clone());
        assert_eq!(r.loops, 1, "2 fake whiles + 1 real for = 1: {:?}", r);
        let f = fake_loop_spans(ts);
        assert_eq!(f.spans.len(), 2, "exactly 2 fakes: {:?}", f);
        for (sp, reason) in &f.spans {
            assert_eq!(*reason, "body is just `break;` under `while`", "span: {:?}", sp);
        }
    }
}
