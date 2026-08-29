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

pub fn collect_call_idents(ts: TokenStream) -> BodyCalls {
    let mut out = BodyCalls::default();
    walk(ts, &mut out);
    out
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
    pub loops: usize,   // while / loop / for
    pub matches: usize, // match
    pub ifs: usize,     // if
    pub returns: usize, // return
}

pub fn cfg_keyword_counts(ts: TokenStream) -> RustCfg {
    let mut c = RustCfg::default();
    count_kw(ts, &mut c);
    c
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
    walk_calls(ts, &mut out);
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
}
