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

/// Walks the WHOLE token stream (attributes, fn head, body) collecting call
/// idents. Retained as a public API for callers that want the full inventory;
/// the macro's own verifier uses [`collect_body_calls_only`] which excludes
/// leading attributes and the fn head.
#[allow(dead_code)]
pub fn collect_call_idents(ts: TokenStream) -> BodyCalls {
    let mut out = BodyCalls::default();
    walk(ts, &mut out);
    out
}

/// Walk only the function body (the `{ ... }` block), skipping the function
/// name itself, its parameters, AND any `#[attribute(...)]` on the item. The
/// raw `walk` over the entire item conflated three things that look like
/// calls but aren't: the function's own name (`fn outer() { … }` matches
/// `outer()` because `outer` is an Ident followed by a parenthesized group),
/// the attribute macro name (`#[serde(...)]` matches `serde(...)`), and any
/// call embedded inside an attribute (`#[some_attr(default = helper())]`).
/// All three polluted the corpus diff with bogus names. (BUG #13 / #14)
pub fn collect_body_calls_only(ts: TokenStream) -> BodyCalls {
    let mut out = BodyCalls::default();
    if let Some(body) = find_body_group(ts) {
        walk(body, &mut out);
    }
    out
}

fn find_body_group(ts: TokenStream) -> Option<TokenStream> {
    // Walk the token tree at the top level; the first `{...}` group at the
    // SHALLOWEST depth that follows `fn <name>(...)` is the body. Any earlier
    // `{...}` belongs to something else (struct literals, blocks in attribute
    // args, etc.) — but those aren't reached from a top-level `fn`, so the
    // first brace group we see AFTER we've seen the parameter parens is the
    // body. To handle attributes (each `[...]` group) and nested generics
    // cleanly, we just track a small state machine: ignore tokens until we
    // see `fn <ident>` followed by a `(...)` group, then the next `{...}` group
    // is the body.
    let tts: Vec<TokenTree> = ts.into_iter().collect();
    let mut i = 0;
    while i < tts.len() {
        match &tts[i] {
            TokenTree::Group(g) if g.delimiter() == Delimiter::Brace => {
                return Some(g.stream());
            }
            TokenTree::Ident(id) if id.to_string() == "fn" => {
                // Skip `fn`, then the name (one Ident), then the `(...)` group.
                i += 1;
                // Optional name (could be path with `::` — consume up to `(`).
                while i < tts.len() && !matches!(&tts[i], TokenTree::Group(g) if g.delimiter() == Delimiter::Parenthesis) {
                    i += 1;
                }
                if i < tts.len() {
                    i += 1; // past `(...)`
                }
            }
            _ => i += 1,
        }
    }
    None
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
pub struct CallExpr {
    pub name: String,
    pub is_method: bool,
    pub args: Vec<RustArg>,
}

/// Parse a hex/decimal integer literal token string (suffix and `_` separators tolerated).
fn parse_int(s: &str) -> Option<u64> {
    let s = s.trim();
    if let Some(rest) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
        let hex: String = rest
            .chars()
            .take_while(|c| c.is_ascii_hexdigit() || *c == '_')
            .filter(|c| *c != '_')
            .collect();
        return u64::from_str_radix(&hex, 16).ok();
    }
    let dec: String = s
        .chars()
        .take_while(|c| c.is_ascii_digit() || *c == '_')
        .filter(|c| *c != '_')
        .collect();
    if dec.is_empty() {
        None
    } else {
        dec.parse().ok()
    }
}

/// Split a parenthesized token stream into its top-level (comma-separated) argument token lists.
fn split_args(ts: TokenStream) -> Vec<Vec<TokenTree>> {
    let mut out = vec![Vec::new()];
    for tt in ts {
        if let TokenTree::Punct(p) = &tt {
            if p.as_char() == ',' {
                out.push(Vec::new());
                continue;
            }
        }
        out.last_mut().unwrap().push(tt);
    }
    if out.last().map(|v| v.is_empty()).unwrap_or(false) {
        out.pop();
    }
    out
}

/// Classify one argument's token slice into a `RustArg`. Recognizes integer literals
/// (`Imm`), the project byte-helper idioms `rd*(base, 0xNN)` (`Field`) and `g*(0xNN)`
/// (`Global`), and a bare in-image address literal (`Global`); everything else is `Other`.
fn classify_arg(toks: &[TokenTree]) -> RustArg {
    // Bare integer literal.
    if toks.len() == 1 {
        if let TokenTree::Literal(l) = &toks[0] {
            if let Some(v) = parse_int(&l.to_string()) {
                // A bare literal is an immediate (even a raw address literal — the binary `PUSH`es
                // it as an immediate too); `g*(addr)` below is what reads a global's contents.
                return RustArg::Imm(v);
            }
        }
    }
    // `name(...)` / `path::name(...)` — find the callee name + its argument group.
    let grp_idx = toks
        .iter()
        .position(|t| matches!(t, TokenTree::Group(g) if g.delimiter() == Delimiter::Parenthesis));
    if let Some(gi) = grp_idx {
        if gi > 0 {
            if let (TokenTree::Ident(name), TokenTree::Group(g)) = (&toks[gi - 1], &toks[gi]) {
                let name = name.to_string();
                let inner = split_args(g.stream());
                // rd8/rd16/rd32/rdf32/... (base, offset) → field access at `offset`. Use an
                // explicit list (mirroring the `g*` arm below) so that names like `read`
                // or `rdata` aren't mis-classified as struct-field helpers just because
                // they happen to start with `rd`. (BUG #7) Extend this list when new
                // byte-helper width variants are introduced.
                if matches!(
                    name.as_str(),
                    "rd8" | "rd16" | "rd32" | "rd64" | "rdf32" | "rdf64"
                ) && inner.len() >= 2
                {
                    if let RustArg::Imm(off) = classify_arg(&inner[1]) {
                        return RustArg::Field(off);
                    }
                    return RustArg::Other;
                }
                // g8/g16/g32/gf32/... (addr) → global at `addr`.
                if matches!(
                    name.as_str(),
                    "g8" | "g16" | "g32" | "g64" | "gf32" | "gf64"
                ) && !inner.is_empty()
                {
                    if let RustArg::Global(a) | RustArg::Imm(a) = classify_arg(&inner[0]) {
                        return RustArg::Global(a);
                    }
                }
            }
        }
    }
    RustArg::Other
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
                if prev.to_string() == "for" {
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
                let s = id.to_string();
                if s == "break" && !seen_break {
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

pub fn collect_call_exprs(ts: TokenStream) -> Vec<CallExpr> {
    let mut out = Vec::new();
    if let Some(body) = find_body_group(ts.clone()) {
        walk_calls(body, &mut out);
    } else {
        walk_calls(ts, &mut out);
    }
    out
}

fn walk_calls(ts: TokenStream, out: &mut Vec<CallExpr>) {
    let tts: Vec<TokenTree> = ts.into_iter().collect();
    for (i, tt) in tts.iter().enumerate() {
        if let TokenTree::Group(g) = tt {
            walk_calls(g.stream(), out); // recurse into every group, incl. argument groups
        }
        if let TokenTree::Ident(id) = tt {
            if let Some(TokenTree::Group(g)) = tts.get(i + 1) {
                if g.delimiter() == Delimiter::Parenthesis {
                    let is_method =
                        i > 0 && matches!(&tts[i - 1], TokenTree::Punct(p) if p.as_char() == '.');
                    let args = split_args(g.stream())
                        .iter()
                        .map(|a| classify_arg(a))
                        .collect();
                    out.push(CallExpr {
                        name: id.to_string(),
                        is_method,
                        args,
                    });
                }
            }
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
    if let Some(body) = find_body_group(ts.clone()) {
        walk_hex(body, &mut out);
    } else {
        walk_hex(ts, &mut out);
    }
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

fn walk(ts: TokenStream, out: &mut BodyCalls) {
    let tts: Vec<TokenTree> = ts.into_iter().collect();
    for (i, tt) in tts.iter().enumerate() {
        if let TokenTree::Group(g) = tt {
            walk(g.stream(), out); // recurse into every group (incl. the body block)
        }
        if let TokenTree::Ident(id) = tt {
            let followed_by_parens = matches!(
                tts.get(i + 1),
                Some(TokenTree::Group(g)) if g.delimiter() == Delimiter::Parenthesis
            );
            if !followed_by_parens {
                continue;
            }
            let is_method =
                i > 0 && matches!(&tts[i - 1], TokenTree::Punct(p) if p.as_char() == '.');
            if is_method {
                out.method.insert(id.to_string());
            } else {
                out.plain.insert(id.to_string());
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::body::{collect_call_idents, collect_hex_literals};
    use proc_macro2::{Delimiter, Group, Ident, Span, TokenStream, TokenTree};
    use std::str::FromStr;

    /// Parse `s` as a TokenStream and return its token-tree slice — this is the
    /// shape `classify_arg` expects.
    fn toks(s: &str) -> Vec<TokenTree> {
        TokenStream::from_str(s)
            .expect("parse")
            .into_iter()
            .collect()
    }

    /// Build `name(arg1, arg2, ...)` as a token slice by parsing each piece
    /// individually and stitching.
    fn call_toks(name: &str, args: &[&str]) -> Vec<TokenTree> {
        let mut v = vec![TokenTree::Ident(Ident::new(name, Span::call_site()))];
        let mut inner: TokenStream = TokenStream::new();
        for (i, a) in args.iter().enumerate() {
            if i > 0 {
                inner.extend(TokenStream::from_str(",").unwrap());
            }
            inner.extend(TokenStream::from_str(a).unwrap());
        }
        v.push(TokenTree::Group(Group::new(Delimiter::Parenthesis, inner)));
        v
    }

    // --- classify_arg (BUG #7) --------------------------------------------

    /// Regression: the old `starts_with("rd")` over-matched every name that
    /// started with `rd` (`read`, `rdata`, …) and classified it as a struct-field
    /// access. With an explicit list, only the canonical byte helpers count.
    #[test]
    fn classify_arg_rd_helpers_are_field() {
        for name in ["rd8", "rd16", "rd32", "rd64", "rdf32", "rdf64"] {
            let toks = call_toks(name, &["base", "0x10"]);
            assert!(
                matches!(classify_arg(&toks), RustArg::Field(0x10)),
                "{name}(base, 0x10) should be Field(0x10), got {:?}",
                classify_arg(&toks)
            );
        }
    }

    #[test]
    fn classify_arg_non_rd_helpers_are_other() {
        // `read` and `rdata` start with `rd` but are NOT byte-helper idioms.
        // They must classify as Other, not Field — otherwise a call like
        // `read(p, 0x10)` would be reported as a field access at 0x10.
        for name in ["read", "rdata", "rdb", "rdr"] {
            let toks = call_toks(name, &["base", "0x10"]);
            assert!(
                matches!(classify_arg(&toks), RustArg::Other),
                "{name}(base, 0x10) should be Other (not a byte helper), got {:?}",
                classify_arg(&toks)
            );
        }
    }

    #[test]
    fn classify_arg_g_helpers_are_global() {
        for name in ["g8", "g16", "g32", "g64", "gf32", "gf64"] {
            let toks = call_toks(name, &["0x00BEEF"]);
            assert!(
                matches!(classify_arg(&toks), RustArg::Global(0xBEEF)),
                "{name}(0xBEEF) should be Global(0xBEEF), got {:?}",
                classify_arg(&toks)
            );
        }
    }

    #[test]
    fn classify_arg_bare_literal_is_immediate() {
        let toks = toks("0x10");
        assert!(matches!(classify_arg(&toks), RustArg::Imm(0x10)));
    }

    #[test]
    fn classify_arg_rd_with_non_literal_offset_is_other() {
        // The offset must be a literal int to be classified as Field; anything
        // else falls through to Other. Guards against classifying a variable
        // offset as a known field.
        let toks = call_toks("rd32", &["base", "offset"]);
        assert!(matches!(classify_arg(&toks), RustArg::Other));
    }

    // --- collect_call_idents / collect_call_exprs / collect_hex_literals ---

    /// `collect_body_calls_only` walks only the function body's `{ ... }`
    /// group, skipping leading `#[attribute(...)]` and the `fn name(...)`
    /// head. A function call embedded in an attribute
    /// (e.g. `#[serde(default = some_fn())]`) must NOT pollute the corpus
    /// diff, and the function's own name (`fn outer() { … }`) must not be
    /// counted as a self-call. (BUG #13 / #14)
    #[test]
    fn collect_body_calls_only_skips_attributes_and_fn_name() {
        // Simulate an item: an attribute group with a call, the fn head, and a
        // real body call. Real body has `real_fn()`. Attribute contains
        // `attribute_fn()`. The fn name itself is `outer`.
        let ts = TokenStream::from_str(
            "#[some_attr(default = attribute_fn())] pub fn outer() { real_fn(); }",
        )
        .unwrap();
        let calls = collect_body_calls_only(ts);
        assert!(
            calls.plain.contains("real_fn"),
            "real_fn (in body) should be picked up: {:?}",
            calls.plain
        );
        assert!(
            !calls.plain.contains("attribute_fn"),
            "attribute_fn (inside #[..]) should NOT be picked up as a body call: {:?}",
            calls.plain
        );
        assert!(
            !calls.plain.contains("outer"),
            "fn name `outer` should NOT be counted as a self-call: {:?}",
            calls.plain
        );
    }

    /// `collect_hex_literals` also walks only the body — hex literals inside
    /// `#[origin(0xA, calls = [0xB, 0xC])]` are NOT included. The macro
    /// itself applies `v == args.addr` to skip the function's own address,
    /// and the operand check should only see addresses the BODY actually
    /// bakes in (global reads, vtable VAs, fn pointers pushed as immediates),
    /// not the declared `calls = [..]` / `globals = [..]` lists which are
    /// already validated by the explicit `Spec` clauses. (BUG #13)
    #[test]
    fn collect_hex_literals_excludes_attribute_addresses() {
        let ts = TokenStream::from_str(
            "#[origin(0x004028d0, calls = [0x00401f00, 0x00401f20])] pub fn outer() {}",
        )
        .unwrap();
        let lits = collect_hex_literals(ts);
        // The body is empty, so no hex literals are emitted.
        assert!(!lits.contains(&0x004028d0), "attr hex leaked: {:?}", lits);
        assert!(!lits.contains(&0x00401f00), "attr hex leaked: {:?}", lits);
        assert!(!lits.contains(&0x00401f20), "attr hex leaked: {:?}", lits);
    }

/// Sanity: hex literals INSIDE the body ARE included.
    #[test]
    fn collect_hex_literals_includes_body_literals() {
        let ts = TokenStream::from_str(
            "#[origin(0x004028d0)] pub fn outer() { let g = 0x00401f00u32; }",
        )
        .unwrap();
        let lits = collect_hex_literals(ts);
        assert!(lits.contains(&0x00401f00), "{:?}", lits);
        // The attribute's own address is NOT included — it's outside the body.
        assert!(
            !lits.contains(&0x004028d0),
            "attr 0x004028d0 leaked into body hex: {:?}",
            lits
        );
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
