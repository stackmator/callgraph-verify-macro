//! Extract the set of function names a Rust function body calls, by walking its
//! token tree. A call site is an identifier immediately followed by a `(...)`
//! group: `foo(..)`, `path::foo(..)`, AND method calls `x.foo(..)`. Method calls
//! are included because a faithful port routinely calls a ported fn as a method
//! (`HEAP.allocate(..)` → `MemoryHeap::Allocate` 0x00401aa0), and the strict
//! MISSING check would otherwise flag that real call as absent. Generic method
//! names that collide with std/trait fns (`.get()`, `.clone()`, …) are filtered
//! by [`DENY`]; resolution further requires the name to be `#[origin]`-tagged.

use proc_macro2::{Delimiter, Span, TokenStream, TokenTree};
use std::collections::{HashMap, HashSet};
use syn::spanned::Spanned;
use syn::visit::{self, Visit};
use syn::{BinOp, Block, Expr, ExprCall, ExprLit, ExprMethodCall, ImplItemFn, ItemFn, Lit, Pat};

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
/// classified args (for the ARG-SHAPE diff), MACRO invocations — whose
/// bodies are opaque token streams the verifier cannot see (surfaced as a
/// NOTE by the macro, never silently skipped) — and CONDITION counts (for
/// the POLARITY diff: which branch classes the body actually tests).
pub struct FnBodyFacts {
    pub names: BodyCalls,
    pub exprs: Vec<CallExpr>,
    pub macros: Vec<String>,
    pub conds: CondCounts,
}

/// How many tests of each branch class a Rust body contains — the source
/// side of the POLARITY check (E021). An approximation of "how many
/// conditional JCCs this body implies", deliberately coarse (short-circuit
/// chains and compound conditions undercount by a little; the firing
/// thresholds absorb that):
/// * `eq`: `==`/`!=` binops, `match` arms with literal patterns,
///   `matches!` invocations, bare `if`/`while` conditions (a bare flag test
///   lowers to `test`+`je`), and `if`/`while` `let` conditions
///   (discriminant test). A call condition (`if ready(x)`) counts 0 — the
///   callee is a different function.
/// * `rel`: `<`/`<=`/`>`/`>=` binops, `match` range-pattern arms, `for`
///   loops (a range loop is a relational exit test).
/// * `lazy`: `&&`/`||` binops (each short-circuits through its own JCC;
///   feeds the E016 branchiness sum, not E021).
#[derive(Default, Debug)]
pub struct CondCounts {
    pub eq: u32,
    pub rel: u32,
    pub lazy: u32,
}

struct FnBodyVisitor {
    facts: FnBodyFacts,
    /// In-scope single-assignment bindings with confidently-classified values:
    /// `let k = 0x10;` records `k -> Imm(16)` so a later `f(k)` classifies
    /// concrete instead of `Other`. A sound under-approximation, never a
    /// guess: any rebinding to a non-concrete value, any `x = ...` /
    /// compound assignment, and any shadowing binder (`for` patterns,
    /// `while`/`if` `let` conditions, closure params, match arms, block
    /// scoping, `let`-`else` divergence, `ref` bindings) evicts the name.
    /// Unknown still means `Other`, which the ARG-SHAPE diff skips.
    lets: HashMap<String, RustArg>,
}

/// Every identifier a pattern binds (shadowing the outer scope): plain
/// idents, `x: T` ascriptions, and anything nested in tuple/struct/slice/
/// reference/`|` patterns. Non-binding patterns contribute nothing.
fn pat_bound_idents(pat: &Pat) -> Vec<String> {
    match pat {
        Pat::Ident(pi) => vec![pi.ident.to_string()],
        Pat::Type(pt) => pat_bound_idents(&pt.pat),
        Pat::Tuple(p) => p.elems.iter().flat_map(pat_bound_idents).collect(),
        Pat::TupleStruct(p) => p.elems.iter().flat_map(pat_bound_idents).collect(),
        Pat::Struct(p) => p.fields.iter().flat_map(|f| pat_bound_idents(&f.pat)).collect(),
        Pat::Slice(p) => p.elems.iter().flat_map(pat_bound_idents).collect(),
        Pat::Reference(p) => pat_bound_idents(&p.pat),
        Pat::Paren(p) => pat_bound_idents(&p.pat),
        Pat::Or(p) => p
            .cases
            .iter()
            .flat_map(pat_bound_idents)
            .collect::<HashSet<_>>()
            .into_iter()
            .collect(),
        _ => Vec::new(),
    }
}

impl FnBodyVisitor {
    /// Classify a call argument: single-ident paths resolve through the
    /// in-scope let-bindings first, everything else falls back to
    /// [`classify_expr`].
    fn classify_arg(&self, e: &Expr) -> RustArg {
        if let Expr::Path(p) = e {
            if p.path.segments.len() == 1 {
                if let Some(a) = self.lets.get(&p.path.segments[0].ident.to_string()) {
                    return a.clone();
                }
            }
        }
        classify_expr(e)
    }

    /// `x = ...` / `x op= ...` kills the binding — the stored literal no
    /// longer holds. Only plain ident targets; `*p = v` / `s.f = v` leave
    /// the address/value binding itself intact.
    fn evict_assign_target(&mut self, left: &Expr) {
        if let Expr::Path(p) = left {
            if p.path.segments.len() == 1 {
                self.lets.remove(&p.path.segments[0].ident.to_string());
            }
        }
    }

    /// Condition-class counting for E021 (see `CondCounts`): comparison
    /// binops imply their class's JCC; `&&`/`||` imply a (usually
    /// equality-class) short-circuit JCC each, counted as `lazy` for the
    /// E016 branchiness sum.
    fn count_binop(&mut self, op: &BinOp) {
        if matches!(op, BinOp::Eq(..) | BinOp::Ne(..)) {
            self.facts.conds.eq += 1;
        } else if matches!(
            op,
            BinOp::Lt(..) | BinOp::Le(..) | BinOp::Gt(..) | BinOp::Ge(..)
        ) {
            self.facts.conds.rel += 1;
        } else if matches!(op, BinOp::And(..) | BinOp::Or(..)) {
            self.facts.conds.lazy += 1;
        }
    }

    /// `match` arms imply the discriminant tests the binary lowers to
    /// JCCs: literal patterns are equality tests, range patterns are
    /// relational. Wildcard/identifier arms test nothing.
    fn count_arm_pat(&mut self, pat: &Pat) {
        match pat {
            Pat::Lit(_) => self.facts.conds.eq += 1,
            Pat::Range(_) => self.facts.conds.rel += 1,
            Pat::Or(p) => {
                for case in &p.cases {
                    self.count_arm_pat(case);
                }
            }
            Pat::Paren(p) => self.count_arm_pat(&p.pat),
            Pat::Ident(pi) => {
                if let Some((_, sub)) = &pi.subpat {
                    self.count_arm_pat(sub);
                }
            }
            Pat::Type(pt) => self.count_arm_pat(&pt.pat),
            Pat::Reference(p) => self.count_arm_pat(&p.pat),
            _ => {}
        }
    }
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
                    args: e.args.iter().map(|a| self.classify_arg(a)).collect(),
                    span: e.span(),
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
            args: m.args.iter().map(|a| self.classify_arg(a)).collect(),
            span: m.span(),
        });
        self.facts.names.method.insert(name);
        visit::visit_expr_method_call(self, m);
    }

    fn visit_block(&mut self, b: &'ast Block) {
        // Block scoping: bindings made inside die at the closing brace.
        let saved = self.lets.clone();
        visit::visit_block(self, b);
        self.lets = saved;
    }

    fn visit_local(&mut self, l: &'ast syn::Local) {
        // The initializer's own calls see the pre-binding map (the name
        // isn't bound until after its own init evaluates).
        visit::visit_local(self, l);
        // Simple shape only: `let name = <concrete>;` with no `else`
        // diverger and no `ref` (a reference is not the value). Anything
        // else evicts whatever the pattern binds (destructuring, `let`-`else`
        // flow-through, `ref` shadows are all unknown).
        let simple_name = match &l.pat {
            Pat::Ident(pi) if pi.by_ref.is_none() && pi.subpat.is_none() => {
                Some(pi.ident.to_string())
            }
            Pat::Type(pt) => match &*pt.pat {
                Pat::Ident(pi) if pi.by_ref.is_none() && pi.subpat.is_none() => {
                    Some(pi.ident.to_string())
                }
                _ => None,
            },
            _ => None,
        };
        match (simple_name, l.init.as_ref()) {
            (Some(name), Some(init)) if init.diverge.is_none() => {
                match self.classify_arg(&init.expr) {
                    concrete @ (RustArg::Imm(_) | RustArg::Field(_) | RustArg::Global(_)) => {
                        self.lets.insert(name, concrete);
                    }
                    _ => {
                        self.lets.remove(&name);
                    }
                }
            }
            _ => {
                for bound in pat_bound_idents(&l.pat) {
                    self.lets.remove(&bound);
                }
            }
        }
    }

    fn visit_expr_assign(&mut self, e: &'ast syn::ExprAssign) {
        visit::visit_expr_assign(self, e);
        self.evict_assign_target(&e.left);
    }

    fn visit_expr_binary(&mut self, e: &'ast syn::ExprBinary) {
        self.count_binop(&e.op);
        visit::visit_expr_binary(self, e);
        // Compound assignment (`+=`, `&=`, `<<=`, ...) mutates like `=`.
        // (Assign-op `BinOp`s carry their token payload, hence `(..)`.)
        if matches!(
            e.op,
            BinOp::AddAssign(..)
                | BinOp::SubAssign(..)
                | BinOp::MulAssign(..)
                | BinOp::DivAssign(..)
                | BinOp::RemAssign(..)
                | BinOp::BitXorAssign(..)
                | BinOp::BitAndAssign(..)
                | BinOp::BitOrAssign(..)
                | BinOp::ShlAssign(..)
                | BinOp::ShrAssign(..)
        ) {
            self.evict_assign_target(&e.left);
        }
    }

    fn visit_expr_for_loop(&mut self, e: &'ast syn::ExprForLoop) {
        // A range loop is a relational exit test.
        self.facts.conds.rel += 1;
        // The loop pattern shadows the outer scope for the whole loop.
        let saved = self.lets.clone();
        for bound in pat_bound_idents(&e.pat) {
            self.lets.remove(&bound);
        }
        visit::visit_expr_for_loop(self, e);
        self.lets = saved;
    }

    fn visit_expr_while(&mut self, e: &'ast syn::ExprWhile) {
        self.facts.conds.eq += cond_eq_value(&e.cond);
        // `while let PAT = ...` binds PAT for the body.
        let saved = self.lets.clone();
        if let Expr::Let(el) = &*e.cond {
            for bound in pat_bound_idents(&el.pat) {
                self.lets.remove(&bound);
            }
        }
        visit::visit_expr_while(self, e);
        self.lets = saved;
    }

    fn visit_expr_if(&mut self, e: &'ast syn::ExprIf) {
        self.facts.conds.eq += cond_eq_value(&e.cond);
        // The condition evaluates in the outer scope; `if let PAT = ...`
        // binds PAT for the then-branch only (`else` sees the outer scope).
        self.visit_expr(&e.cond);
        for attr in &e.attrs {
            self.visit_attribute(attr);
        }
        if let Expr::Let(el) = &*e.cond {
            let saved = self.lets.clone();
            for bound in pat_bound_idents(&el.pat) {
                self.lets.remove(&bound);
            }
            self.visit_block(&e.then_branch);
            self.lets = saved;
        } else {
            self.visit_block(&e.then_branch);
        }
        if let Some((_tok, els)) = &e.else_branch {
            self.visit_expr(els);
        }
    }

    fn visit_arm(&mut self, a: &'ast syn::Arm) {
        self.count_arm_pat(&a.pat);
        // The arm pattern (and its guard) shadow the outer scope; bindings
        // made in the arm body die with it.
        let saved = self.lets.clone();
        for bound in pat_bound_idents(&a.pat) {
            self.lets.remove(&bound);
        }
        visit::visit_arm(self, a);
        self.lets = saved;
    }

    fn visit_expr_closure(&mut self, e: &'ast syn::ExprClosure) {
        // Closure params shadow the outer scope; everything bound inside
        // dies with the closure.
        let saved = self.lets.clone();
        for input in &e.inputs {
            for bound in pat_bound_idents(input) {
                self.lets.remove(&bound);
            }
        }
        visit::visit_expr_closure(self, e);
        self.lets = saved;
    }

    fn visit_macro(&mut self, mac: &'ast syn::Macro) {
        if let Some(seg) = mac.path.segments.last() {
            let name = seg.ident.to_string();
            // `matches!` is (almost always) an equality test on the
            // discriminant; range patterns inside are rare enough to accept
            // the approximation (documented in `CondCounts`).
            if name == "matches" {
                self.facts.conds.eq += 1;
            }
            self.facts.macros.push(name);
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
            conds: CondCounts::default(),
        },
        lets: HashMap::new(),
    };
    v.visit_block(block);
    v.facts
}

/// Classify one `if`/`while` condition for E021's `eq` term: +1 when the
/// condition implies an equality JCC that no other counter sees — a bare
/// flag test (`if x`, `while !ready`: `test`+`je`), an `if`/`while` `let`
/// (discriminant test), or a compound with no explicit comparison (the
/// `&&`/`||` structure itself undercounts, so the bare arm earns one).
/// Conditions containing a call (`if ready(x)`) earn 0 — the callee is a
/// different function. Conditions with an explicit `==`/`!=`/relational
/// binop earn 0 here (the binop walk already counted them).
fn cond_eq_value(cond: &Expr) -> u32 {
    if let Expr::Let(_) = cond {
        return 1;
    }
    let mut has_call = false;
    let mut has_cmp = false;
    fn walk(e: &Expr, has_call: &mut bool, has_cmp: &mut bool) {
        match e {
            Expr::Call(_) | Expr::MethodCall(_) => *has_call = true,
            Expr::Binary(b) => {
                if matches!(
                    b.op,
                    BinOp::Eq(..)
                        | BinOp::Ne(..)
                        | BinOp::Lt(..)
                        | BinOp::Le(..)
                        | BinOp::Gt(..)
                        | BinOp::Ge(..)
                ) {
                    *has_cmp = true;
                }
                walk(&b.left, has_call, has_cmp);
                walk(&b.right, has_call, has_cmp);
            }
            Expr::Unary(u) => walk(&u.expr, has_call, has_cmp),
            Expr::Paren(p) => walk(&p.expr, has_call, has_cmp),
            _ => {}
        }
    }
    walk(cond, &mut has_call, &mut has_cmp);
    if !has_call && !has_cmp {
        1
    } else {
        0
    }
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

    /// Best-effort span pointing at the function declaration itself (the
    /// `fn` keyword). Used as the fallback anchor when a diagnostic has no
    /// more specific token to attach to. With `Span::call_site()` the
    /// rustc gutter always lights up the attribute line; this often lights
    /// up the `fn name(...)` line, which is one click closer to the body
    /// in IDEs.
    pub fn attr_target_span(&self) -> Span {
        match self {
            FnLike::Free(f) => f.sig.fn_token.span,
            FnLike::Method(m) => m.sig.fn_token.span,
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
/// and its classified positional arguments. `span` points at the call expression itself so
/// the macro can attach HALLUCINATED / ARG-SHAPE / VTABLE-DISPATCH errors to the exact call
/// site in the source (not the attribute line) — agents and IDEs both navigate better when
/// rustc's gutter points at the offending token.
#[derive(Debug)]
pub struct CallExpr {
    pub name: String,
    pub is_method: bool,
    pub args: Vec<RustArg>,
    pub span: Span,
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
            let Some(TokenTree::Group(g)) = body_group else {
                continue;
            };
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
fn scan_for_body_group(tts: &[TokenTree], start: usize) -> Option<&TokenTree> {
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
    walk_hex(ts, &mut |v, _span| out.push(v));
    out
}

/// Same scan as `collect_hex_literals`, but ALSO records each literal's
/// `Span`. The macro's `HALLUCINATED-ADDR` diagnostic attaches to the
/// literal that bakes the invented address, so rustc lights up exactly the
/// spot the agent must change — instead of the `#[origin(...)]` line.
///
/// Span identity is per-token: a literal written twice produces two
/// distinct spans, but the value `HashMap` collapses them. The first span
/// seen for each value wins, which is fine for navigation purposes.
pub fn collect_hex_literal_spans(ts: TokenStream) -> std::collections::HashMap<u64, Span> {
    let mut out = std::collections::HashMap::new();
    walk_hex(ts, &mut |v, sp| {
        out.entry(v).or_insert(sp);
    });
    out
}

fn walk_hex(ts: TokenStream, out: &mut dyn FnMut(u64, Span)) {
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
                        out(v, l.span());
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
        assert!(
            facts.names.method.contains("foo"),
            "{:?}",
            facts.names.method
        );
        assert!(facts.names.plain.is_empty(), "{:?}", facts.names.plain);
        assert!(
            facts.exprs.len() == 1 && facts.exprs[0].is_method,
            "{:?}",
            facts.exprs
        );
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
        assert!(
            facts.macros.contains(&"my_macro".to_string()),
            "{:?}",
            facts.macros
        );
        assert!(
            facts.macros.contains(&"other".to_string()),
            "{:?}",
            facts.macros
        );
        assert!(facts.names.plain.is_empty(), "{:?}", facts.names.plain);
        assert!(facts.exprs.is_empty(), "{:?}", facts.exprs);
    }

    /// Path-qualified calls record just the trailing segment (B-04).
    #[test]
    fn path_qualified_call_records_trailing_segment() {
        let facts = facts_of("fn f() { crate::module::func(1, 2); }");
        assert!(
            facts.names.plain.contains("func"),
            "{:?}",
            facts.names.plain
        );
        assert!(
            !facts.names.plain.contains("crate"),
            "{:?}",
            facts.names.plain
        );
        assert!(
            !facts.names.plain.contains("module"),
            "{:?}",
            facts.names.plain
        );
    }

    /// The fn's own name and anything inside attributes are not body calls —
    /// `collect_block_facts` only sees the parsed Block. (BUG #13 / #14)
    #[test]
    fn fn_name_and_attrs_are_not_body_calls() {
        let src = "#[some_attr(default = attribute_fn())] fn outer() { real_fn(); }";
        let f: ItemFn = syn::parse_str(src).expect("parse fn");
        let facts = collect_block_facts(&f.block);
        assert!(
            facts.names.plain.contains("real_fn"),
            "{:?}",
            facts.names.plain
        );
        assert!(
            !facts.names.plain.contains("attribute_fn"),
            "{:?}",
            facts.names.plain
        );
        assert!(
            !facts.names.plain.contains("outer"),
            "{:?}",
            facts.names.plain
        );
    }

    // --- let-bound const propagation (ARG-SHAPE `Other` gap) -----------------
    // `collect_block_facts` (the exact path `verify_impl` takes) resolves
    // single-ident args through in-scope `let` bindings.

    fn args_of(src: &str) -> Vec<RustArg> {
        let facts = facts_of(src);
        assert_eq!(facts.exprs.len(), 1, "{:?}", facts.exprs);
        facts.exprs[0].args.clone()
    }

    fn conds_of(src: &str) -> (u32, u32, u32) {
        let f = facts_of(src);
        (f.conds.eq, f.conds.rel, f.conds.lazy)
    }

    // --- condition-class counting (E021 POLARITY ground truth) --------------

    #[test]
    fn eq_binops_count_as_eq() {
        assert_eq!(conds_of("fn f(q: u32) -> u32 { if q == 1 { 1 } else { 2 } }"), (1, 0, 0));
        assert_eq!(conds_of("fn f(q: u32) -> bool { q != 0 && q != 1 }"), (2, 0, 1));
    }

    #[test]
    fn rel_binops_count_as_rel() {
        assert_eq!(conds_of("fn f(q: u32) -> u32 { if q > 100 { 1 } else { 2 } }"), (0, 1, 0));
        assert_eq!(conds_of("fn f(q: u32) -> u32 { if q >= 1 && q <= 9 { 1 } else { 2 } }"), (0, 2, 1));
    }

    #[test]
    fn bare_flag_test_counts_as_eq() {
        // A bare `if x` lowers to test+je — same class as ==.
        assert_eq!(conds_of("fn f(x: bool) -> u32 { if x { 1 } else { 2 } }"), (1, 0, 0));
        assert_eq!(conds_of("fn f(x: bool) -> u32 { if !x { 1 } else { 2 } }"), (1, 0, 0));
    }

    #[test]
    fn call_condition_counts_nothing() {
        // `if ready(x)` is a different function's branch.
        assert_eq!(conds_of("fn f(q: u32) -> u32 { if ready(q) { 1 } else { 2 } }"), (0, 0, 0));
    }

    #[test]
    fn match_arms_count_by_pattern_class() {
        assert_eq!(
            conds_of("fn f(q: u32) -> u32 { match q { 0 => 1, 1 => 2, _ => 3 } }"),
            (2, 0, 0)
        );
        assert_eq!(
            conds_of("fn f(q: u32) -> u32 { match q { 0..=9 => 1, _ => 2 } }"),
            (0, 1, 0)
        );
    }

    #[test]
    fn for_loop_counts_as_rel() {
        assert_eq!(conds_of("fn f(n: u32) -> u32 { let mut s = 0; for i in 0..n { s += i; } s }"), (0, 1, 0));
    }

    #[test]
    fn if_let_counts_as_eq() {
        assert_eq!(conds_of("fn f(q: Option<u32>) -> u32 { if let Some(v) = q { v } else { 0 } }"), (1, 0, 0));
    }

    #[test]
    fn matches_macro_counts_as_eq() {
        assert_eq!(conds_of("fn f(q: u32) -> bool { matches!(q, 1 | 2) }"), (1, 0, 0));
    }

    #[test]
    fn let_literal_propagates_to_call_arg() {
        assert_eq!(
            args_of("fn f() { let k = 0x10; real_call(k); }"),
            vec![RustArg::Imm(0x10)]
        );
    }

    #[test]
    fn let_chain_propagates() {
        assert_eq!(
            args_of("fn f() { let a = 8; let b = a; real_call(b); }"),
            vec![RustArg::Imm(8)]
        );
    }

    #[test]
    fn let_type_ascription_propagates() {
        assert_eq!(
            args_of("fn f() { let k: u32 = 0x20; real_call(k); }"),
            vec![RustArg::Imm(0x20)]
        );
    }

    #[test]
    fn reassign_to_nonconcrete_kills_binding() {
        // `let k = g();` rebinds k to an unknown value.
        let facts = facts_of("fn f() { let k = 1; let k = g(); real_call(k); }");
        assert_eq!(facts.exprs.len(), 2, "{:?}", facts.exprs);
        assert_eq!(facts.exprs[1].args, vec![RustArg::Other]);
    }

    #[test]
    fn plain_assign_kills_binding() {
        assert_eq!(
            args_of("fn f() { let k = 1; k = 2; real_call(k); }"),
            vec![RustArg::Other]
        );
    }

    #[test]
    fn compound_assign_kills_binding() {
        assert_eq!(
            args_of("fn f() { let k = 1; k += 2; real_call(k); }"),
            vec![RustArg::Other]
        );
    }

    #[test]
    fn block_scope_kills_binding() {
        // `k` bound inside a block is gone after the closing brace.
        let facts = facts_of("fn f() { { let k = 3; real_call(k); } real_call(k); }");
        assert_eq!(facts.exprs.len(), 2, "{:?}", facts.exprs);
        assert_eq!(facts.exprs[0].args, vec![RustArg::Imm(3)]);
        assert_eq!(facts.exprs[1].args, vec![RustArg::Other]);
    }

    #[test]
    fn for_pattern_shadows_outer_binding() {
        assert_eq!(
            args_of("fn f() { let x = 1; for x in 0..n { real_call(x); } }"),
            vec![RustArg::Other]
        );
    }

    #[test]
    fn ref_binding_is_not_the_value() {
        // `let ref k = 5` binds a reference — propagating Imm(5) would be a
        // false ARG-SHAPE Imm against whatever the binary stages.
        assert_eq!(
            args_of("fn f() { let ref k = 5; real_call(k); }"),
            vec![RustArg::Other]
        );
    }

    #[test]
    fn unbound_path_stays_other() {
        assert_eq!(
            args_of("fn f(q: u32) { real_call(q); }"),
            vec![RustArg::Other]
        );
    }

    #[test]
    fn init_call_sees_prebinding_map() {
        // The initializer's own calls classify against the map BEFORE the
        // new binding lands: `g` here must not see `k`.
        let facts = facts_of("fn f() { let k = g(1); real_call(k); }");
        assert_eq!(facts.exprs.len(), 2, "{:?}", facts.exprs);
        assert_eq!(facts.exprs[0].args, vec![RustArg::Imm(1)]);
        assert_eq!(facts.exprs[1].args, vec![RustArg::Other]);
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
            assert!(
                matches!(classify_expr(&e), RustArg::Global(0xBEEF)),
                "{name}"
            );
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
    /// hex inside `#[origin(0xA, fields = [0xB, 0xC])]` structurally cannot
    /// leak into the operand check. (BUG #13)
    #[test]
    fn collect_hex_literals_excludes_attribute_addresses() {
        let lits =
            hex_of_body("#[origin(0x004028d0, fields = [0x00401f00, 0x00401f20])] fn outer() {}");
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
        let ts =
            TokenStream::from_str("pub fn outer() { loop { foo(); if cond { break; } } }").unwrap();
        let r = cfg_keyword_counts(ts.clone());
        assert_eq!(r.loops, 1, "real loop should count: {:?}", r);
        let f = fake_loop_spans(ts);
        assert!(
            f.spans.is_empty(),
            "real loop should not be flagged as fake: {:?}",
            f.spans
        );
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
        assert_eq!(
            f.spans.len(),
            1,
            "expected 1 fake loop, got {}: {:?}",
            f.spans.len(),
            f.spans
        );
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
        let ts = TokenStream::from_str("pub fn outer() { for x in xs { break; } }").unwrap();
        let r = cfg_keyword_counts(ts.clone());
        assert_eq!(r.loops, 1, "`for` counts as a real loop: {:?}", r);
        let f = fake_loop_spans(ts);
        assert!(f.spans.is_empty(), "`for` is never fake: {:?}", f);

        // `while cond { break; }` — fake: the loop never iterates.
        let ts = TokenStream::from_str("pub fn outer() { while cond { break; } }").unwrap();
        let r = cfg_keyword_counts(ts.clone());
        assert_eq!(
            r.loops, 0,
            "fake `while` must NOT count as iteration: {:?}",
            r
        );
        let f = fake_loop_spans(ts);
        assert_eq!(f.spans.len(), 1, "expected 1 fake `while`: {:?}", f);
        assert_eq!(f.spans[0].1, "body is just `break;` under `while`");

        // `while cond { real_work(); break; }` — NOT a placeholder: the body
        // has real work before the break, so it counts as a real loop.
        let ts = TokenStream::from_str("pub fn outer() { while cond { foo(); break; } }").unwrap();
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
        let ts =
            TokenStream::from_str("pub fn outer() { let _buf = while !cond { break; }; }").unwrap();
        let r = cfg_keyword_counts(ts.clone());
        assert_eq!(
            r.loops, 0,
            "fake `while !cond {{ break; }}` must not count: {:?}",
            r
        );
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
            assert_eq!(
                *reason, "body is just `break;` under `while`",
                "span: {:?}",
                sp
            );
        }
    }
}
