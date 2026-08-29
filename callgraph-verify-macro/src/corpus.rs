//! Build the `name -> origin-addr` map for the rebuild by scanning the source
//! tree. A proc-macro can't see the compiler's symbol table, but it can read the
//! files — so we harvest every function's declared origin address from its tag.
//!
//! Three tag forms are recognized, each associated with the `fn NAME` below it:
//!   * `#[origin(0x004028d0)]`        — the structured attribute (preferred)
//!   * `#[callgraph_verify(0x..)]`    — the verifier attribute (alias)
//!   * `/// origin: 0x004028d0`       — the legacy doc-comment convention
//!
//! Scanned once per compiler process and cached.

use std::collections::{BTreeSet, HashMap, HashSet};
use std::str::FromStr;
use std::sync::{Arc, OnceLock};

use crate::body::BodyCalls;

pub struct Corpus {
    /// Free / associated fns (no `self` receiver), keyed by name.
    pub free_fns: HashMap<String, HashSet<u64>>,
    /// Methods (have a `self` receiver), keyed by name.
    pub methods: HashMap<String, HashSet<u64>>,
    pub addr2name: HashMap<u64, String>,
    /// Every fn site (`<path>:<line> <name>`) that cites each origin address, deduped
    /// per fn. A binary fn may be implemented by exactly ONE Rust fn, so any address
    /// with >1 owner here is a duplicate (mirrors `check_origins.py`'s dup-addr check).
    pub addr_owners: HashMap<u64, Vec<String>>,
    pub corpus: BTreeSet<u64>,
    /// `inline:`-tagged helpers (no own address) → the calls in their body. The
    /// binary inlines these into callers, so a caller's verification folds in these
    /// calls — catching an invented call hidden inside an untagged inline helper.
    pub inline_fns: HashMap<String, BodyCalls>,
    /// Inline-helper names defined in more than one place (e.g. a per-module `rd`).
    /// Bare-name fold-in can't tell which one a caller meant, so these are skipped.
    pub inline_ambiguous: HashSet<String>,
    /// Origin addresses of fns carrying a `callgraph-inlined` marker: the binary inlines
    /// the callee into its callers, so a direct Rust call to it is faithful even though
    /// no caller shows a direct `CALL 0xADDR`.
    pub inlined_markers: BTreeSet<u64>,
    /// `(engine vtable VA, slot count)` for every `vtable_table!` the rebuild declares.
    /// Lets the verifier read those engine vtables from the PE and recognize which call
    /// targets are virtual methods (→ "use vcall, not a direct call").
    pub declared_vtables: Vec<(u64, usize)>,
}

/// Scan `root` for the corpus map, caching the result per root path.
pub fn corpus_map(root: &str) -> Arc<Corpus> {
    static CACHE: OnceLock<std::sync::Mutex<HashMap<String, Arc<Corpus>>>> = OnceLock::new();
    let cache = CACHE.get_or_init(|| std::sync::Mutex::new(HashMap::new()));
    let mut m = cache.lock().unwrap();
    if let Some(c) = m.get(root) {
        return c.clone();
    }
    let built = Arc::new(build(root));
    m.insert(root.to_string(), built.clone());
    built
}

fn build(root: &str) -> Corpus {
    let mut c = Corpus {
        free_fns: HashMap::new(),
        methods: HashMap::new(),
        addr2name: HashMap::new(),
        addr_owners: HashMap::new(),
        corpus: BTreeSet::new(),
        inline_fns: HashMap::new(),
        inline_ambiguous: HashSet::new(),
        inlined_markers: BTreeSet::new(),
        declared_vtables: Vec::new(),
    };
    let root_path = std::path::Path::new(root);
    for path in rust_files(root_path) {
        let Ok(text) = std::fs::read_to_string(&path) else {
            continue;
        };
        let disp = path
            .strip_prefix(root_path)
            .unwrap_or(&path)
            .to_string_lossy()
            .replace('\\', "/");
        scan_file(&text, &disp, &mut c);
        scan_vtable_decls(&text, &mut c);
    }
    c
}

/// Collect `vtable_table! { … va = 0xVA, slots = N … }` declarations (va + slot count).
fn scan_vtable_decls(text: &str, c: &mut Corpus) {
    let lines: Vec<&str> = text.lines().collect();
    for i in 0..lines.len() {
        if !lines[i].contains("vtable_table!") {
            continue;
        }
        let (mut va, mut slots) = (None, None);
        for line in lines.iter().skip(i).take(10) {
            if va.is_none() {
                if let Some(p) = find_kv(line, "va") {
                    va = hex_addrs(&line[p..], true).first().copied();
                }
            }
            if slots.is_none() {
                if let Some(p) = find_kv(line, "slots") {
                    let n: String = line[p..]
                        .chars()
                        .skip_while(|ch| *ch != '=')
                        .skip_while(|ch| !ch.is_ascii_digit())
                        .take_while(|ch| ch.is_ascii_digit())
                        .collect();
                    slots = n.parse().ok();
                }
            }
            if va.is_some() && slots.is_some() {
                break;
            }
        }
        if let (Some(v), Some(s)) = (va, slots) {
            c.declared_vtables.push((v, s));
        }
    }
}

/// Find a `key` followed by `=` (a `key = value` field), returning the byte offset of `key`.
fn find_kv(line: &str, key: &str) -> Option<usize> {
    let mut from = 0;
    while let Some(rel) = line[from..].find(key) {
        let at = from + rel;
        let after = line[at + key.len()..].trim_start();
        // word boundary before, and `=` after (allowing whitespace)
        let before_ok = at == 0 || !line.as_bytes()[at - 1].is_ascii_alphanumeric();
        if before_ok && after.starts_with('=') {
            return Some(at);
        }
        from = at + key.len();
    }
    None
}

/// Collect hex addresses (`0x...`) appearing on a line.
fn hex_addrs(line: &str, first_only: bool) -> Vec<u64> {
    let bytes = line.as_bytes();
    let mut out = Vec::new();
    let mut i = 0;
    while i + 1 < bytes.len() {
        if bytes[i] == b'0' && (bytes[i + 1] == b'x' || bytes[i + 1] == b'X') {
            let mut j = i + 2;
            while j < bytes.len() && bytes[j].is_ascii_hexdigit() {
                j += 1;
            }
            if j > i + 2 {
                if let Ok(v) = u64::from_str_radix(&line[i + 2..j], 16) {
                    out.push(v);
                    if first_only {
                        return out;
                    }
                }
            }
            i = j;
        } else {
            i += 1;
        }
    }
    out
}

/// The function name + whether it is a method (has a `self` receiver), from a
/// signature line, e.g. `pub unsafe fn free(&self, ptr: u32) {` → ("free", true).
/// Generics are skipped: `pub fn foo<T>(x: T)` → ("foo", false). Without the skip,
/// `take_while` stops at `<`, producing an empty name and silently dropping the fn
/// from the corpus (calls to it then become HALLUCINATED).
fn fn_sig(line: &str) -> Option<(String, bool)> {
    let idx = line.find("fn ")?;
    let after_fn = &line[idx + 3..];
    // Skip a balanced generic parameter list `<...>` if present, so `foo<T>` parses
    // as name "foo" rather than name "". Nested generics like `<T, U=U::Item>` are
    // handled by tracking angle depth; the inner `<` of an associated-type bound
    // (`<T where T: Foo<Bar>>`) doesn't fool us because depth only opens on `<`.
    let after_generics = skip_generics(after_fn);
    let paren_in_sig = after_generics.find('(')?; // a real signature has '(' on the same line
    // The name is whatever sits between `fn ` (or the closing `>`) and the first
    // non-name character (`(`, `<`, whitespace, …). Path-qualified names
    // (`crate::foo`) and lifetimes are not name chars; only alphanumeric + `_`.
    let name: String = after_generics[..paren_in_sig]
        .chars()
        .take_while(|c| c.is_alphanumeric() || *c == '_')
        .collect();
    if name.is_empty() {
        return None;
    }
    // The full rest of the signature (from after `fn `) is needed to read the first
    // parameter list — params may sit between generics and the outer `(`. For the
    // common case the outer `(` is the same as `paren_in_sig`; here we re-locate
    // it on the original `after_fn` slice so `rest[paren + 1..]` still works.
    let paren = after_fn.find('(')?;
    // Method iff the first parameter is a `self` receiver.
    let first_param = after_fn[paren + 1..].split([',', ')']).next().unwrap_or("");
    let is_method = first_param.replace(['&', ' '], "").starts_with("self")
        || first_param.contains("mut self")
        || first_param
            .trim_start_matches(['&', ' '])
            .starts_with("self");
    Some((name, is_method))
}

/// If `s` begins with a balanced `<...>` generic parameter list, return the slice
/// starting just after the closing `>`. Otherwise return `s` unchanged. Counts `<`
/// and `>` to handle nested generics (e.g. `<T: Foo<Bar>>`); does not attempt to
/// parse string/char literals or comments — fine for the short signatures we see.
fn skip_generics(s: &str) -> &str {
    let bytes = s.as_bytes();
    if bytes.first().copied() != Some(b'<') {
        return s;
    }
    let mut depth: usize = 1;
    for (i, &b) in bytes.iter().enumerate().skip(1) {
        match b {
            b'<' => depth += 1,
            b'>' => {
                depth -= 1;
                if depth == 0 {
                    return &s[i + 1..];
                }
            }
            _ => {}
        }
    }
    s
}

fn scan_file(text: &str, disp_path: &str, c: &mut Corpus) {
    let lines: Vec<&str> = text.lines().collect();
    let mut pending: Vec<u64> = Vec::new();
    let mut pending_inline = false;
    let mut pending_cginlined = false;
    for i in 0..lines.len() {
        let line = lines[i].trim_start();
        if line.starts_with("#[cfg(test)]") || line.starts_with("mod tests") {
            break; // ignore test modules, matching the python lint
        }
        // `callgraph-inlined` (binary inlines the callee) and `callgraph-virtual` (binary
        // dispatches it via vtable) both mean: a direct Rust call is faithful even though the
        // caller shows no `CALL 0xADDR`. Both add the addr to `inlined_markers`.
        if line.starts_with("//")
            && (line.contains("callgraph-inlined") || line.contains("callgraph-virtual"))
        {
            pending_cginlined = true;
        }

        // Harvest the origin address from the PROC-MACRO ATTRIBUTE only — the single
        // source of truth. A `/// origin:` doc comment is decorative and is IGNORED
        // (it's for humans / the python lint's display). The `#[..]` guard + the
        // `origin(` / `callgraph_verify(` token match every spelling: `#[origin(..)]`,
        // `#[callgraph_verify(..)]`, and the full path `#[callgraph_verify_macro::origin(..)]`.
        // One fn = one binary fn (fusion banned), so only the first addr is taken.
        //
        // The `trim_start().starts_with("#[")` check is intentional: a naive
        // `line.contains("#[")` would also fire on commented-out attributes like
        // `// see #[origin(0xA)]`, silently re-attributing the wrong address to
        // the next function. (BUG #5)
        let is_origin_attr = line.trim_start().starts_with("#[")
            && (line.contains("origin(") || line.contains("callgraph_verify("));
        if is_origin_attr {
            pending.extend(hex_addrs(line, true)); // addr is the first arg
        } else if line.starts_with("//")
            && line
                .trim_start_matches('/')
                .trim_start()
                .starts_with("inline:")
        {
            // `/// inline:` / `// inline:` helper tag. Two flavours:
            //   * with an address ("inline: 0x0070b780 (typed entry over [ni_node_ctor])") — the
            //     fn IS / is part of that binary fn, so a call to it resolves to that address. It is
            //     also marked inlinable (added to `inlined_markers`) so a direct call is faithful
            //     whether the binary `CALL`s the address or inlines it into the caller.
            //   * address-less ("inline: flag accessor") — fall back to body fold-in (the binary
            //     inlines the helper's own calls into the caller).
            // Incidental small hex (vtable slots like 0x84, byte offsets) is excluded by the
            // 0x40_0000 image-base floor so it isn't mistaken for a function address.
            let addrs: Vec<u64> = hex_addrs(line, false)
                .into_iter()
                .filter(|&a| a >= 0x40_0000)
                .collect();
            if addrs.is_empty() {
                pending_inline = true;
            } else {
                pending.extend(addrs);
                pending_cginlined = true;
            }
        }

        // A signature whose `(` is on a later line (rustfmt-wrapped long params)
        // would otherwise be missed — and a missed signature SILENTLY drops the
        // pending origin tag, leaving that fn (and calls resolving to it)
        // unverified. Join a few lines so the wrapped form still parses.
        let sig = fn_sig(line).or_else(|| {
            if line.contains("fn ") && !line.starts_with("//") && !line.contains('(') {
                let end = (i + 4).min(lines.len());
                fn_sig(&lines[i..end].join(" "))
            } else {
                None
            }
        });
        if let Some((name, is_method)) = sig {
            if !pending.is_empty() {
                let map = if is_method {
                    &mut c.methods
                } else {
                    &mut c.free_fns
                };
                let set = map.entry(name.clone()).or_default();
                // Dedup addrs WITHIN this one fn first: a fn that carries both the
                // `#[origin(0xA)]` attribute and the `/// origin: 0xA` doc-comment (the
                // current dual-tag convention) cites 0xA twice — that is NOT a duplicate,
                // so it must contribute exactly one owner entry for 0xA.
                let mut seen_here: HashSet<u64> = HashSet::new();
                let label = format!("{disp_path}:{} {}", i + 1, name);
                for &a in &pending {
                    set.insert(a);
                    c.addr2name.entry(a).or_insert_with(|| name.clone());
                    c.corpus.insert(a);
                    if pending_cginlined {
                        c.inlined_markers.insert(a);
                    }
                    if seen_here.insert(a) {
                        c.addr_owners.entry(a).or_default().push(label.clone());
                    }
                }
            } else if pending_inline {
                // Untagged inline helper: capture the calls in its body so callers
                // can fold them in (the binary inlines this helper's calls).
                let body = grab_body(&lines, i);
                if let Ok(ts) = proc_macro2::TokenStream::from_str(&body) {
                    if c.inline_fns
                        .insert(name.clone(), crate::body::collect_call_idents(ts))
                        .is_some()
                    {
                        c.inline_ambiguous.insert(name); // defined in >1 place
                    }
                }
            }
            pending.clear();
            pending_inline = false;
            pending_cginlined = false;
        } else if line.is_empty() {
            pending.clear(); // a blank line ends a doc/attr block
            pending_inline = false;
            pending_cginlined = false;
        }
    }
}

/// Grab a function body `{ … }` (first brace to its match) starting at line `start`.
/// Brace counting is naïve (doesn't strip strings/comments), which is fine for the
/// small arithmetic helpers `inline:` is used for.
fn grab_body(lines: &[&str], start: usize) -> String {
    let mut s = String::new();
    let mut depth = 0i32;
    let mut started = false;
    for line in &lines[start..] {
        for ch in line.chars() {
            if ch == '{' {
                depth += 1;
                started = true;
            }
            if started {
                s.push(ch);
            }
            if ch == '}' {
                depth -= 1;
                if started && depth == 0 {
                    return s;
                }
            }
        }
        if started {
            s.push('\n');
        }
        if s.len() > 200_000 {
            break;
        }
    }
    s
}

fn rust_files(root: &std::path::Path) -> Vec<std::path::PathBuf> {
    let mut out = Vec::new();
    let skip: HashSet<&str> = ["target", "tests", "examples", "benches"]
        .into_iter()
        .collect();
    let mut stack = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        let Ok(rd) = std::fs::read_dir(&dir) else {
            continue;
        };
        for entry in rd.flatten() {
            let p = entry.path();
            if p.is_dir() {
                if !skip.contains(p.file_name().and_then(|s| s.to_str()).unwrap_or("")) {
                    stack.push(p);
                }
            } else if p.extension().and_then(|s| s.to_str()) == Some("rs") {
                out.push(p);
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::{fn_sig, scan_file, skip_generics, Corpus};

    // --- skip_generics ----------------------------------------------------

    #[test]
    fn skip_generics_passthrough_when_no_angle() {
        assert_eq!(skip_generics("foo(x: u32)"), "foo(x: u32)");
        assert_eq!(skip_generics("(x: u32)"), "(x: u32)");
        assert_eq!(skip_generics(""), "");
    }

    #[test]
    fn skip_generics_simple() {
        assert_eq!(skip_generics("<T>(x: T)"), "(x: T)");
        assert_eq!(skip_generics("<T, U>(x: T, y: U)"), "(x: T, y: U)");
    }

    #[test]
    fn skip_generics_nested() {
        assert_eq!(skip_generics("<T: Foo<Bar>>(x: T)"), "(x: T)");
        assert_eq!(
            skip_generics("<T, U = Vec<T::Item>>(x: T, y: U)"),
            "(x: T, y: U)"
        );
    }

    #[test]
    fn skip_generics_with_lifetime_and_const() {
        assert_eq!(
            skip_generics("<'a, T, const N: usize>(x: &'a T) -> &'a T"),
            "(x: &'a T) -> &'a T"
        );
    }

    // --- fn_sig ----------------------------------------------------------

    #[test]
    fn fn_sig_plain_function() {
        let (name, is_method) = fn_sig("pub fn foo(x: u32) -> u32 {").unwrap();
        assert_eq!(name, "foo");
        assert!(!is_method);
    }

    #[test]
    fn fn_sig_method_with_self() {
        let (name, is_method) = fn_sig("pub unsafe fn free(&self, ptr: u32) {").unwrap();
        assert_eq!(name, "free");
        assert!(is_method);
    }

    #[test]
    fn fn_sig_method_with_mut_self() {
        let (name, is_method) = fn_sig("fn add(&mut self, x: u32) {").unwrap();
        assert_eq!(name, "add");
        assert!(is_method);
    }

    /// Regression for BUG #1: generic functions used to be silently dropped because
    /// `take_while(alphanumeric|_)` stopped at `<`, producing an empty name. Calls
    /// to such ported fns would then resolve to nothing and be flagged HALLUCINATED.
    #[test]
    fn fn_sig_generic_function() {
        let (name, is_method) = fn_sig("pub fn foo<T>(x: T) -> T {").unwrap();
        assert_eq!(name, "foo");
        assert!(!is_method);
    }

    #[test]
    fn fn_sig_generic_with_bound() {
        let (name, is_method) =
            fn_sig("pub fn clone_into<T: Clone>(&self, dst: &mut T) {").unwrap();
        assert_eq!(name, "clone_into");
        assert!(is_method);
    }

    #[test]
    fn fn_sig_generic_with_lifetime_and_const() {
        let (name, is_method) =
            fn_sig("pub fn map<'a, T, const N: usize>(x: &'a T) -> &'a T {").unwrap();
        assert_eq!(name, "map");
        assert!(!is_method);
    }

    #[test]
    fn fn_sig_generic_with_nested_bound() {
        let (name, is_method) =
            fn_sig("pub fn deep<T: Foo<Bar>>(x: T) -> T {").unwrap();
        assert_eq!(name, "deep");
        assert!(!is_method);
    }

    #[test]
    fn fn_sig_no_paren_returns_none() {
        // A `fn` reference in a comment without `(` shouldn't be picked up.
        assert!(fn_sig("// see fn foo above for details").is_none());
    }

    // --- scan_file: attribute vs comment (BUG #5) -------------------------

    /// Build a corpus by running `scan_file` on `text` (no vtable decls). The
    /// returned corpus exposes `free_fns`/`methods` keyed by fn name; we assert
    /// that the right names are present (and the wrong ones absent).
    fn scan(text: &str) -> Corpus {
        let mut c = Corpus {
            free_fns: std::collections::HashMap::new(),
            methods: std::collections::HashMap::new(),
            addr2name: std::collections::HashMap::new(),
            addr_owners: std::collections::HashMap::new(),
            corpus: std::collections::BTreeSet::new(),
            inline_fns: std::collections::HashMap::new(),
            inline_ambiguous: std::collections::HashSet::new(),
            inlined_markers: std::collections::BTreeSet::new(),
            declared_vtables: Vec::new(),
        };
        scan_file(text, "test.rs", &mut c);
        c
    }

    #[test]
    fn scan_file_real_attribute_is_picked_up() {
        let text = "\
#[origin(0x004028d0)]
pub unsafe fn foo() {}
";
        let c = scan(text);
        assert!(c.free_fns.contains_key("foo"));
        assert!(c.corpus.contains(&0x004028d0));
    }

    /// Regression for BUG #5: a commented-out `#[origin(..)]` reference (a `//` line
    /// that just *mentions* the attribute syntax in prose) used to be matched as a
    /// real attribute. The address from the comment then attached to the next fn
    /// signature — silently mis-attributing it. With the fix only lines that
    /// actually start with `#[` are treated as attributes.
    #[test]
    fn scan_file_commented_attribute_is_ignored() {
        let text = "\
// see #[origin(0xDEADBEEF)] for the old version
pub unsafe fn foo() {}
";
        let c = scan(text);
        // The corpus must NOT contain 0xDEADBEEF — the `#[origin(..)]` was inside a
        // comment, not a real attribute. Before the fix the address leaked in and
        // got attached to `foo` as its pending origin.
        assert!(
            !c.corpus.contains(&0xDEADBEEF),
            "commented #[origin(0xDEADBEEF)] leaked into the corpus: {:?}",
            c.corpus
        );
        // And the address must not be claimable by any fn (no owner entry).
        assert!(
            !c.addr2name.contains_key(&0xDEADBEEF),
            "commented origin was attributed as `foo`'s address — addr2name: {:?}",
            c.addr2name
        );
    }

    #[test]
    fn scan_file_commented_attribute_does_not_steal_pending_origin() {
        // A real attribute, then a commented reference to a *different* address,
        // then the function. The function's real origin must win — the comment's
        // address must not override or coexist.
        let text = "\
#[origin(0x004028d0)]
// historical note: was originally #[origin(0xCAFEBABE)]
pub unsafe fn foo() {}
";
        let c = scan(text);
        assert!(c.free_fns.contains_key("foo"));
        assert!(c.corpus.contains(&0x004028d0), "real origin present");
        assert!(
            !c.corpus.contains(&0xCAFEBABE),
            "comment address 0xCAFEBABE leaked into corpus"
        );
    }

    #[test]
    fn scan_file_indented_attribute_is_picked_up() {
        // rustfmt may indent attributes — the leading whitespace must not break
        // the starts_with check (we already trim_start before checking).
        let text = "\
    #[origin(0x004028d0)]
    pub unsafe fn foo() {}
";
        let c = scan(text);
        assert!(c.free_fns.contains_key("foo"));
        assert!(c.corpus.contains(&0x004028d0));
    }
}
