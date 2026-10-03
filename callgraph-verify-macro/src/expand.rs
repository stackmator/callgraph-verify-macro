//! Best-effort expansion of local `macro_rules!` invocations so the
//! call/CFG/hex harvests see through them.
//!
//! ## Why this exists
//!
//! The verifier walks `#[origin]` fn bodies for call names, control-flow
//! keywords and hex literals. A macro invocation used to be fully opaque:
//! calls inside the expansion (e.g. `vb_unlock_epilogue!` expanding to a
//! `memmove` edge) escaped every check, and the only recourse was
//! inlining the macro body at each use site by hand. This module resolves
//! unambiguous workspace `macro_rules!` definitions (harvested by the
//! corpus scan) and substitutes them, so all three downstream pipelines
//! operate on expanded tokens.
//!
//! ## Deliberate limits (documented, not bugs)
//!
//! * Only `macro_rules!` with simple `($v:kind, ...)` arms. Arms whose
//!   matcher is anything else, and bodies containing repetitions
//!   (`$(...)*`), resolve to *unexpandable* — the invocation stays opaque
//!   and the OPAQUE-MACRO note still fires for it.
//! * The `$(,)?` optional-trailing-comma idiom is accepted in matchers
//!   (it is ubiquitous and unambiguous).
//! * Matching is arity-only: fragment kinds (`:expr` vs `:ty`) are not
//!   validated. A wrong-kind argument would fail rustc parsing anyway;
//!   the verifier mirrors structure, not types.
//! * Ambiguity: if two or more definitions share a name anywhere in the
//!   scanned tree, NONE of them is used (textual scope is not modeled).
//! * Proc macros, builtins (`vec!`, `format!`, …) and anything not found
//!   in the corpus defs stay opaque, exactly as before.
//! * Recursion: expansion runs to a fixpoint with a pass cap; a
//!   self-recursive macro stops with its inner invocation still opaque.
//! * Spans: definition bodies are parsed from file text, so spliced
//!   tokens carry dummy spans. Diagnostics for expansion-derived calls
//!   attach at the attribute line (same as today's fallback anchor).
//!   Argument tokens keep their real spans (they come from the compiler).

use proc_macro2::{Delimiter, Spacing, TokenStream, TokenTree};
use std::collections::HashMap;

/// One usable `macro_rules!` arm: ordered `$`-params and the raw
/// transcriber body (rendered to string — see below) to substitute into.
#[derive(Clone, Debug)]
pub struct MacroArm {
    /// `$`-names in matcher order (e.g. `["this", "vb"]`).
    pub params: Vec<String>,
    /// Transcriber token stream, rendered via `Display`.
    ///
    /// Stored as text (not tokens) because the corpus lives in a
    /// process-global cache that must stay `Send + Sync`, and token
    /// streams backed by the real compiler are neither. Re-parsed on
    /// each expansion; macro bodies are tiny so the cost is negligible.
    /// (`Display`/`FromStr` round-trips lexing losslessly for the token
    /// shapes this expander matches on.)
    pub body_src: String,
}

/// One `macro_rules!` definition site.
#[derive(Clone, Debug)]
pub struct MacroDef {
    pub arms: Vec<MacroArm>,
}

/// Fixpoint pass cap. Real expansions are shallow (1–3 levels); the cap
/// only binds pathological self-recursive macros, which then stay
/// (visibly) opaque instead of hanging the build.
pub const MAX_EXPAND_PASSES: u32 = 16;

/// Parse a `macro_rules!` definition from a `syn::ItemMacro` node (as
/// produced by the corpus scan of `Item::Macro` with path `macro_rules`).
/// The macro name lives in `ItemMacro.ident` — syn drops it from
/// `mac.tokens`, which hold just the rules. Returns the macro name plus
/// its usable arms. Arms that need repetitions or non-trivial matchers
/// are dropped; if none survive, returns `None`.
pub fn parse_macro_rules(mac: &syn::ItemMacro, _defined_in: &str) -> Option<(String, MacroDef)> {
    if !path_is_macro_rules(&mac.mac.path) {
        return None;
    }
    let name = mac.ident.as_ref()?.to_string();
    if name == "macro_rules" {
        return None;
    }
    // Rules stream: split top-level `;` into arms. (`mac.tokens` holds just
    // the rules — syn consumed the `name { ... }` wrapper.)
    let mut arms = Vec::new();
    for arm_toks in split_top_level(mac.mac.tokens.clone(), ';') {
        if arm_toks.is_empty() {
            continue;
        }
        if let Some(arm) = parse_arm(&arm_toks) {
            arms.push(arm);
        }
    }
    if arms.is_empty() {
        return None;
    }
    Some((
        name,
        MacroDef { arms },
    ))
}

fn path_is_macro_rules(path: &syn::Path) -> bool {
    path.segments
        .last()
        .map(|s| s.ident == "macro_rules")
        .unwrap_or(false)
}

/// Parse one `matcher => transcriber` arm. Returns `None` unless the arm
/// is in the supported simple shape.
fn parse_arm(toks: &[TokenTree]) -> Option<MacroArm> {
    let arrow = find_top_level_arrow(toks)?;
    let (matcher_toks, transcriber_toks) = toks.split_at(arrow);
    // Skip the two `=>` puncts.
    let body: Vec<TokenTree> = transcriber_toks[2..].to_vec();
    // Matcher must be exactly one group: `($a:k, $b:k, ...)`.
    let inner: Vec<TokenTree> = match matcher_toks {
        [TokenTree::Group(g)] => g.stream().into_iter().collect(),
        _ => return None,
    };
    let mut params = Vec::new();
    let mut i = 0;
    // Strip `$(,)?` optional-trailing-comma idioms first.
    let inner = strip_optional_trailing_commas(&inner);
    while i < inner.len() {
        match &inner[i] {
            TokenTree::Punct(p) if p.as_char() == '$' => {
                let next = inner.get(i + 1)?;
                match next {
                    TokenTree::Ident(v) => {
                        params.push(v.to_string());
                        i += 2;
                    }
                    _ => return None,
                }
                // After `$v` expect `:` kind then `,` or end.
                match inner.get(i) {
                    Some(TokenTree::Punct(c)) if c.as_char() == ':' => {
                        // Skip `:kind` (one ident or path-ish run to the comma).
                        i += 1;
                        while let Some(t) = inner.get(i) {
                            match t {
                                TokenTree::Punct(c) if c.as_char() == ',' => {
                                    i += 1;
                                    break;
                                }
                                _ => i += 1,
                            }
                        }
                    }
                    Some(TokenTree::Punct(c)) if c.as_char() == ',' => i += 1,
                    None => {}
                    _ => return None,
                }
            }
            _ => return None,
        }
    }
    // Validate the body: every `$` must be a known param, `$crate`, or a
    // repetition (which disqualifies the arm).
    if !body_is_substitutable(&body, &params) {
        return None;
    }
    let body_src: TokenStream = body.into_iter().collect();
    Some(MacroArm {
        params,
        body_src: body_src.to_string(),
    })
}

/// Remove `$(,)?` subsequences (Punct `$`, paren-group holding exactly one
/// comma, Punct `?`) from a matcher token list.
fn strip_optional_trailing_commas(toks: &[TokenTree]) -> Vec<TokenTree> {
    let mut out = Vec::with_capacity(toks.len());
    let mut i = 0;
    while i < toks.len() {
        if matches!(&toks[i], TokenTree::Punct(p) if p.as_char() == '$')
            && matches!(&toks.get(i+1), Some(TokenTree::Group(g)) if g.delimiter() == Delimiter::Parenthesis && {
                let inner: Vec<TokenTree> = g.stream().into_iter().collect();
                inner.len() == 1 && matches!(&inner[0], TokenTree::Punct(c) if c.as_char() == ',')
            })
            && matches!(&toks.get(i+2), Some(TokenTree::Punct(q)) if q.as_char() == '?')
        {
            i += 3;
            continue;
        }
        out.push(toks[i].clone());
        i += 1;
    }
    out
}

/// True if every `$` in the (possibly nested) body tokens is substitutable:
/// `$param` for a known param, or `$crate`. Any `$`+Group (repetition) or
/// unknown `$ident` disqualifies the arm.
fn body_is_substitutable(toks: &[TokenTree], params: &[String]) -> bool {
    let mut i = 0;
    while i < toks.len() {
        match &toks[i] {
            TokenTree::Punct(p) if p.as_char() == '$' => match toks.get(i + 1) {
                Some(TokenTree::Group(_)) => return false,
                Some(TokenTree::Ident(v)) => {
                    let s = v.to_string();
                    if s != "crate" && !params.iter().any(|q| q == &s) {
                        return false;
                    }
                    i += 1;
                }
                _ => return false,
            },
            TokenTree::Group(g) => {
                let inner: Vec<TokenTree> = g.stream().into_iter().collect();
                if !body_is_substitutable(&inner, params) {
                    return false;
                }
            }
            _ => {}
        }
        i += 1;
    }
    true
}

/// Split a token stream at top-level occurrences of the given punct char
/// (depth tracked through groups, which are opaque single nodes here —
/// only top-level separators split).
fn split_top_level(ts: TokenStream, sep: char) -> Vec<Vec<TokenTree>> {
    let mut out: Vec<Vec<TokenTree>> = vec![Vec::new()];
    for tt in ts {
        match &tt {
            TokenTree::Punct(p) if p.as_char() == sep => out.push(Vec::new()),
            _ => out.last_mut().unwrap().push(tt),
        }
    }
    out
}

/// Find the index of a top-level `=>` (`=` Joint + `>`). Groups are opaque.
fn find_top_level_arrow(toks: &[TokenTree]) -> Option<usize> {
    let mut i = 0;
    while i + 1 < toks.len() {
        if let (TokenTree::Punct(a), TokenTree::Punct(b)) = (&toks[i], &toks[i + 1]) {
            if a.as_char() == '=' && a.spacing() == Spacing::Joint && b.as_char() == '>' {
                return Some(i);
            }
        }
        i += 1;
    }
    None
}

/// Expand a body block's tokens with `defs` (when present) and harvest
/// facts from the result. Returns the facts, the token stream the
/// CFG/hex harvests should use, and whether the reparse fallback fired.
///
/// The fallback fires when expansion produces tokens that no longer parse
/// as a block — e.g. a comma-transcriber arm (`=> foo($a), bar($b)`)
/// spliced into statement position. The caller falls back to the
/// unexpanded body (opaque macros stay invisible); it should surface that
/// fact (the macro emits a note) rather than silently continuing.
pub fn expand_and_collect(
    block: &syn::Block,
    defs: Option<&HashMap<String, Vec<MacroDef>>>,
) -> (crate::body::FnBodyFacts, TokenStream, bool) {
    use quote::ToTokens;
    let Some(defs) = defs else {
        return (
            crate::body::collect_block_facts(block),
            block.to_token_stream(),
            false,
        );
    };
    let expanded_ts = expand_block_tokens(block.to_token_stream(), defs);
    match syn::parse2::<syn::Block>(expanded_ts.clone()) {
        Ok(expanded_block) => (
            crate::body::collect_block_facts(&expanded_block),
            expanded_ts,
            false,
        ),
        Err(_) => (
            crate::body::collect_block_facts(block),
            block.to_token_stream(),
            true,
        ),
    }
}
/// Expand all unambiguous local `macro_rules!` invocations in `ts`,
/// running to a fixpoint (bounded by [`MAX_EXPAND_PASSES`]).
pub fn expand_block_tokens(
    ts: TokenStream,
    defs: &HashMap<String, Vec<MacroDef>>,
) -> TokenStream {
    let mut cur = ts;
    for _ in 0..MAX_EXPAND_PASSES {
        let (next, changed) = expand_once(cur.clone(), defs);
        cur = next;
        if !changed {
            break;
        }
    }
    cur
}

/// One expansion pass. Returns the rewritten stream plus whether anything
/// changed. Invocation shape is the token triple
/// `Ident(name) ! Group(args)`; `macro_rules!` itself is never expanded.
fn expand_once(
    ts: TokenStream,
    defs: &HashMap<String, Vec<MacroDef>>,
) -> (TokenStream, bool) {
    let toks: Vec<TokenTree> = ts.into_iter().collect();
    let mut out: Vec<TokenTree> = Vec::with_capacity(toks.len());
    let mut changed = false;
    let mut i = 0;
    while i < toks.len() {
        if let Some(expanded) = try_expand_at(&toks, i, defs) {
            let (len, replacement) = expanded;
            out.extend(replacement);
            i += len;
            changed = true;
            continue;
        }
        // Recurse into groups so nested invocations are found.
        match &toks[i] {
            TokenTree::Group(g) => {
                let (inner, inner_changed) = expand_once(g.stream(), defs);
                if inner_changed {
                    let mut ng = proc_macro2::Group::new(g.delimiter(), inner);
                    ng.set_span(g.span());
                    out.push(TokenTree::Group(ng));
                    changed = true;
                } else {
                    out.push(toks[i].clone());
                }
            }
            _ => out.push(toks[i].clone()),
        }
        i += 1;
    }
    (out.into_iter().collect(), changed)
}

/// If `toks[i..]` is an expandable invocation, return how many tokens it
/// spans plus the substituted replacement.
fn try_expand_at(
    toks: &[TokenTree],
    i: usize,
    defs: &HashMap<String, Vec<MacroDef>>,
) -> Option<(usize, Vec<TokenTree>)> {
    let rest = toks.get(i..)?;
    let (name, args) = match rest {
        [TokenTree::Ident(n), TokenTree::Punct(bang), TokenTree::Group(g), ..]
            if bang.as_char() == '!' =>
        {
            (n.to_string(), g.stream())
        }
        _ => return None,
    };
    if name == "macro_rules" {
        return None;
    }
    let candidates = defs.get(&name)?;
    // Ambiguity: two different definition sites with the same name means
    // textual scope is unknowable here — stay opaque.
    if candidates.len() != 1 {
        return None;
    }
    let def = &candidates[0];
    let mut arg_segs = split_top_level(args, ',');
    // Drop one trailing empty segment (the `$(,)?` call shape `f!(a,)`).
    if matches!(arg_segs.last(), Some(seg) if seg.is_empty()) {
        arg_segs.pop();
    }
    for arm in &def.arms {
        if arm.params.len() != arg_segs.len() {
            continue;
        }
        if let Some(expanded) = substitute(&arm.body_src, &arm.params, &arg_segs) {
            return Some((3, expanded));
        }
    }
    None
}

/// Substitute `$param` occurrences in the arm body with the corresponding
/// actual argument token streams. Returns `None` on an unsubstitutable `$`
/// (caller keeps the invocation opaque).
fn substitute(
    body_src: &str,
    params: &[String],
    args: &[Vec<TokenTree>],
) -> Option<Vec<TokenTree>> {
    use std::str::FromStr;
    let body: Vec<TokenTree> = TokenStream::from_str(body_src).ok()?.into_iter().collect();
    substitute_tokens(&body, params, args)
}

/// Token-level substitution worker (recursive into groups).
fn substitute_tokens(
    body: &[TokenTree],
    params: &[String],
    args: &[Vec<TokenTree>],
) -> Option<Vec<TokenTree>> {
    let mut out: Vec<TokenTree> = Vec::with_capacity(body.len());
    let mut i = 0;
    while i < body.len() {
        match &body[i] {
            TokenTree::Punct(p) if p.as_char() == '$' => match body.get(i + 1) {
                Some(TokenTree::Ident(v)) => {
                    let s = v.to_string();
                    if s == "crate" {
                        out.push(body[i].clone());
                        out.push(body[i + 1].clone());
                    } else if let Some(pos) = params.iter().position(|q| q == &s) {
                        out.extend(args[pos].iter().cloned());
                    } else {
                        return None;
                    }
                    i += 2;
                    continue;
                }
                _ => return None,
            },
            TokenTree::Group(g) => {
                let inner: Vec<TokenTree> = g.stream().into_iter().collect();
                let sub = substitute_tokens(&inner, params, args)?;
                let mut ng = proc_macro2::Group::new(g.delimiter(), sub.into_iter().collect());
                ng.set_span(g.span());
                out.push(TokenTree::Group(ng));
            }
            _ => out.push(body[i].clone()),
        }
        i += 1;
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use quote::ToTokens;
    use std::str::FromStr;

    fn def_of(src: &str) -> (String, MacroDef) {
        // `src` is the full `macro_rules! name { ... }` item; parse it the
        // way the corpus scan does (Item::Macro, name in ItemMacro.ident).
        let item: syn::Item = syn::parse_str(src).expect("parse macro_rules item");
        let m = match item {
            syn::Item::Macro(m) => m,
            other => panic!("expected Item::Macro, got {:?}", std::mem::discriminant(&other)),
        };
        parse_macro_rules(&m, "test.rs").expect("def must parse")
    }

    /// Parse a `macro_rules!` item like `def_of`, returning None-able output.
    fn try_def_of(src: &str) -> Option<(String, MacroDef)> {
        let item: syn::Item = syn::parse_str(src).unwrap();
        match item {
            syn::Item::Macro(m) => parse_macro_rules(&m, "t.rs"),
            _ => None,
        }
    }

    fn defs_of(src: &str) -> HashMap<String, Vec<MacroDef>> {
        let (name, def) = def_of(src);
        let mut m = HashMap::new();
        m.insert(name, vec![def]);
        m
    }

    fn expand(src: &str, defs: &HashMap<String, Vec<MacroDef>>) -> String {
        expand_block_tokens(TokenStream::from_str(src).unwrap(), defs).to_string()
    }

    #[test]
    fn simple_expr_arm_parses() {
        let (name, def) = def_of("macro_rules! cp { ($e:expr, $d:expr) => { wr32($e, $d) }; }");
        assert_eq!(name, "cp");
        assert_eq!(def.arms.len(), 1);
        assert_eq!(def.arms[0].params, vec!["e".to_string(), "d".to_string()]);
    }

    #[test]
    fn optional_trailing_comma_idiom_accepted() {
        let (_, def) = def_of(
            "macro_rules! rd { ($p:expr, $off:expr $(,)?) => {{ rd32($p, $off) }}; }",
        );
        assert_eq!(def.arms.len(), 1);
        assert_eq!(def.arms[0].params, vec!["p".to_string(), "off".to_string()]);
    }

    #[test]
    fn repetition_in_body_bails() {
        // The arm needs a repetition, so no usable arm survives.
        let parsed = try_def_of("macro_rules! fwd { ($($a:ident),*) => { g($($a),*) }; }");
        assert!(parsed.is_none(), "repetition arm must not parse: {:?}", parsed.map(|p| p.0));
    }

    #[test]
    fn non_group_matcher_bails() {
        let out = try_def_of("macro_rules! lit { $e:expr => { $e }; }");
        assert!(out.is_none());
    }

    #[test]
    fn unknown_dollar_ident_bails() {
        let out = try_def_of("macro_rules! bad { ($e:expr) => { $oops }; }");
        assert!(out.is_none());
    }

    #[test]
    fn basic_substitution() {
        let defs = defs_of("macro_rules! cp { ($e:expr, $d:expr) => { wr32($e, $d) }; }");
        let got = expand("{ cp!(a, b); }", &defs);
        assert!(got.contains("wr32"), "got: {got}");
        assert!(got.contains('a') && got.contains('b'), "got: {got}");
        assert!(!got.contains("cp !"), "invocation must be gone: {got}");
    }

    #[test]
    fn trailing_comma_invocation_works() {
        let defs = defs_of("macro_rules! rd { ($p:expr, $off:expr $(,)?) => {{ rd32($p, $off) }}; }");
        let got = expand("{ rd!(buf, 0x10,); }", &defs);
        assert!(got.contains("rd32"), "got: {got}");
    }

    #[test]
    fn arity_mismatch_left_opaque() {
        let defs = defs_of("macro_rules! cp { ($e:expr, $d:expr) => { wr32($e, $d) }; }");
        let got = expand("{ cp!(a); }", &defs);
        assert!(got.contains("cp"), "must stay opaque: {got}");
    }

    #[test]
    fn unknown_macro_left_opaque() {
        let defs = defs_of("macro_rules! cp { ($e:expr) => { $e }; }");
        let got = expand("{ vec![1, 2]; format!(\"{}\", x); }", &defs);
        assert!(got.contains("vec") && got.contains("format"), "got: {got}");
    }

    #[test]
    fn ambiguous_name_left_opaque() {
        let mut defs = defs_of("macro_rules! dup { ($e:expr) => { a($e) }; }");
        let (_, other) = def_of("macro_rules! dup { ($e:expr) => { b($e) }; }");
        defs.get_mut("dup").unwrap().push(other);
        let got = expand("{ dup!(x); }", &defs);
        assert!(got.contains("dup"), "ambiguous must stay opaque: {got}");
    }

    #[test]
    fn macro_rules_itself_never_expanded() {
        let defs: HashMap<String, Vec<MacroDef>> = HashMap::new();
        let got = expand("{ macro_rules! foo { ($e:expr) => { $e }; } }", &defs);
        assert!(got.contains("macro_rules"), "got: {got}");
    }

    #[test]
    fn nested_macro_expands_to_fixpoint() {
        let mut defs = defs_of("macro_rules! inner { ($e:expr) => { target($e) }; }");
        let (_, outer) = def_of("macro_rules! outer { ($e:expr) => { inner!($e) }; }");
        defs.insert("outer".to_string(), vec![outer]);
        let got = expand("{ outer!(v); }", &defs);
        assert!(got.contains("target"), "got: {got}");
        assert!(!got.contains("outer") && !got.contains("inner"), "got: {got}");
    }

    #[test]
    fn self_recursive_macro_terminates() {
        let defs = defs_of("macro_rules! rec { ($e:expr) => { rec!($e) }; }");
        let got = expand("{ rec!(v); }", &defs);
        // Must terminate; the inner invocation stays (opaque note still fires).
        assert!(got.contains("rec"), "got: {got}");
    }

    #[test]
    fn growing_recursion_hits_pass_cap() {
        // Each pass doubles the nesting; the fixpoint cap must stop it.
        let defs = defs_of("macro_rules! grow { ($e:expr) => { grow!(grow!($e)) }; }");
        let got = expand("{ grow!(v); }", &defs);
        assert!(got.contains("grow"), "got: {got}");
    }

    #[test]
    fn substitute_unknown_dollar_returns_none() {
        // Defensive branch: pre-validation normally rejects these bodies,
        // but a direct call with uncovered params must bail, not splice.
        let out = substitute("{ foo($zz) }", &["a".to_string()], &[vec![]]);
        assert!(out.is_none());
    }

    #[test]
    fn dollar_crate_passes_through() {
        let defs = defs_of(
            "macro_rules! wrap { ($e:expr) => { $crate::m::f($e) }; }",
        );
        let got = expand("{ wrap!(v); }", &defs);
        // (`$crate` renders with a space in Display; what matters is the
        // path survives with the argument substituted.)
        assert!(got.contains("crate"), "got: {got}");
        assert!(got.contains('f') && got.contains('v'), "got: {got}");
        assert!(!got.contains("wrap"), "invocation must be gone: {got}");
    }

    #[test]
    fn multi_arm_first_match_wins() {
        let defs = defs_of(
            "macro_rules! m { ($e:expr) => { one($e) }; ($e:expr, $f:expr) => { two($e, $f) }; }",
        );
        assert_eq!(expand("{ m!(v); }", &defs).contains("one"), true);
        let got2 = expand("{ m!(v, w); }", &defs);
        assert!(got2.contains("two"), "got: {got2}");
    }

    #[test]
    fn unparseable_expansion_falls_back_to_unexpanded() {
        // Comma-transcriber arm: parses as a def (matcher + body are both
        // well-formed token runs), but splicing `foo(x), bar(y)` into
        // statement position does not parse as a block.
        let defs = defs_of("macro_rules! pair { ($a:expr, $b:expr) => { foo($a), bar($b) }; }");
        // Sanity: without the fallback this would be an error — the arm
        // itself is sub-optimal but legal macro_rules.
        let block: syn::Block = syn::parse_str("{ pair!(x, y); }").unwrap();
        let (facts, ts, fell_back) = expand_and_collect(&block, Some(&defs));
        assert!(fell_back, "comma-transcriber expansion must not parse as a block");
        // Fallback facts == unexpanded facts: the invocation stays opaque,
        // and neither spliced call leaks into the edge set.
        assert!(
            facts.macros.contains(&"pair".to_string()),
            "{:?}",
            facts.macros
        );
        assert!(facts.names.plain.is_empty(), "{:?}", facts.names.plain);
        assert_eq!(ts.to_string(), block.to_token_stream().to_string());
    }

    #[test]
    fn no_defs_means_no_expansion_no_fallback() {
        let block: syn::Block = syn::parse_str("{ pair!(x, y); }").unwrap();
        let (facts, _, fell_back) = expand_and_collect(&block, None);
        assert!(!fell_back);
        assert!(facts.macros.contains(&"pair".to_string()));
    }

    #[test]
    fn block_body_substitution_shapes_calls() {
        // End-to-end shape: the expanded block parses and the inner call is
        // visible to the syn visitor used for edge collection.
        let defs = defs_of(
            "macro_rules! rel { ($o:expr) => { g($o); free($o); }; }",
        );
        let expanded = expand_block_tokens(
            TokenStream::from_str("{ rel!(p); }").unwrap(),
            &defs,
        );
        let block: syn::Block = syn::parse2(expanded).expect("expanded must parse as block");
        let facts = crate::body::collect_block_facts(&block);
        assert!(facts.names.plain.contains("g"), "{:?}", facts.names.plain);
        assert!(facts.names.plain.contains("free"), "{:?}", facts.names.plain);
        assert!(facts.macros.is_empty(), "{:?}", facts.macros);
    }
}
