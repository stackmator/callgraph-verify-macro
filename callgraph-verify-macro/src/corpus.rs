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
use std::sync::{Arc, OnceLock};

use syn::{
    parse_file as syn_parse_file, Attribute, Expr, FnArg, ImplItem, ImplItemFn, Item, ItemFn,
    Lit, Meta, Signature, TraitItem, TraitItemFn,
};

use crate::body::BodyCalls;
use crate::{parse_origin_attr, VtableTable};

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
        // syn-based scan: every comment-vs-attribute-vs-code ambiguity is
        // resolved by the Rust parser; the only text matching left is inside
        // doc-comment strings, which are legitimate plain text.
        let Ok(file) = syn_parse_file(&text) else {
            continue;
        };
        for item in &file.items {
            scan_item(item, &disp, &mut c);
        }
    }
    c
}

/// Recursively walk one top-level item. Free functions and impl-block / trait-
/// block methods are the only places where `#[origin(..)]` can attribute an
/// address; macro invocations are scanned for `vtable_table!`.
fn scan_item(item: &Item, disp_path: &str, c: &mut Corpus) {
    match item {
        Item::Fn(f) => scan_fn(f, disp_path, c),
        Item::Impl(i) => {
            for ii in &i.items {
                if let ImplItem::Fn(m) = ii {
                    scan_impl_fn(m, disp_path, c);
                }
            }
        }
        Item::Trait(t) => {
            for ti in &t.items {
                if let TraitItem::Fn(m) = ti {
                    scan_trait_fn(m, disp_path, c);
                }
            }
        }
        Item::Macro(m) => {
            if path_is(&m.mac.path, "vtable_table") {
                if let Ok(t) = syn::parse2::<VtableTable>(m.mac.tokens.clone()) {
                    c.declared_vtables.push((t.va, t.slots));
                }
            }
        }
        Item::Mod(m) => {
            // Recurse into nested modules (e.g. `mod tests { fn foo() {} }`) so
            // their `#[origin]` annotations are picked up. The old text scanner
            // used to BREAK on `#[cfg(test)]` / `mod tests` — that was
            // matching the python-lint convention to skip test modules. The
            // syn-based scanner harvests them; tests pin the new behavior.
            if let Some((_, items)) = &m.content {
                for sub in items {
                    scan_item(sub, disp_path, c);
                }
            }
        }
        _ => {}
    }
}

/// True if `path`'s last segment equals `name` (e.g. `vtable_table`,
/// `callgraph_verify_macro::vtable_table`).
fn path_is(path: &syn::Path, name: &str) -> bool {
    path.segments
        .last()
        .map(|s| s.ident == name)
        .unwrap_or(false)
}

/// Harvest a free `fn`'s origin and inline annotations.
fn scan_fn(f: &ItemFn, disp_path: &str, c: &mut Corpus) {
    let name = f.sig.ident.to_string();
    let is_method = is_method_sig(&f.sig);
    scan_attrs_and_record(&f.attrs, &name, is_method, Some(&f.block), disp_path, c);
}

/// Harvest an `impl`-block method's origin and inline annotations.
fn scan_impl_fn(m: &ImplItemFn, disp_path: &str, c: &mut Corpus) {
    let name = m.sig.ident.to_string();
    let is_method = true; // `self` is implicit inside an impl block
    scan_attrs_and_record(&m.attrs, &name, is_method, Some(&m.block), disp_path, c);
}

/// Harvest a trait method's origin and inline annotations (a trait default body).
fn scan_trait_fn(m: &TraitItemFn, disp_path: &str, c: &mut Corpus) {
    let name = m.sig.ident.to_string();
    let is_method = true;
    let block = m.default.as_ref();
    scan_attrs_and_record(&m.attrs, &name, is_method, block, disp_path, c);
}

/// Walk an attribute list looking for `#[origin(0xA)]` / `#[callgraph_verify(0xA)]`,
/// `#[doc = "inline: ..."]` / `#[doc = "callgraph-inlined"]`, and the
/// `inline:` and `unreferenced` flags. Record everything into `c`.
fn scan_attrs_and_record(
    attrs: &[Attribute],
    name: &str,
    is_method: bool,
    body: Option<&syn::Block>,
    disp_path: &str,
    c: &mut Corpus,
) {
    let mut addrs: Vec<u64> = Vec::new();
    let mut inline_body = false;
    let mut cginlined = false;

    for attr in attrs {
        match &attr.meta {
            Meta::Path(p) => {
                // Bare path attributes don't carry origin addresses.
                let _ = p;
            }
            Meta::List(m) => {
                if !attr.path().is_ident("origin") && !attr.path().is_ident("callgraph_verify") {
                    continue;
                }
                // The token stream between the parens — `parse_origin_attr`
                // uses the existing `Args` parser.
                if let Ok(o) = parse_origin_attr(m.tokens.clone()) {
                    addrs.push(o.addr);
                }
            }
            Meta::NameValue(nv) if nv.path.is_ident("doc") => {
                // Doc comments are stored as `#[doc = "..."]` by syn.
                if let Expr::Lit(el) = &nv.value {
                    if let Lit::Str(s) = &el.lit {
                        let txt = s.value();
                        if txt.contains("callgraph-inlined") || txt.contains("callgraph-virtual") {
                            cginlined = true;
                        }
                        // `inline: 0x0070b780 (...)` — parse the address.
                        // `inline: flag accessor` — no address, fall back to
                        // body fold-in via `inline_body`.
                        if let Some(addr) = parse_inline_addr(&txt) {
                            addrs.push(addr);
                            cginlined = true;
                        } else if txt.trim_start().starts_with("inline:") {
                            inline_body = true;
                        }
                    }
                }
            }
            _ => {}
        }
    }

    if !addrs.is_empty() {
        record_fn_addresses(&addrs, name, is_method, cginlined, disp_path, c);
    } else if inline_body {
        // Untagged inline helper: capture the calls in its body so callers
        // can fold them in.
        if let Some(block) = body {
            let ts = quote::quote!(#block);
            if c.inline_fns
                .insert(name.to_string(), crate::body::collect_body_calls_only(ts))
                .is_some()
            {
                c.inline_ambiguous.insert(name.to_string());
            }
        }
    }
}

/// Pull a single 0x… address out of an `inline: <addr> …` doc-comment. Returns
/// `None` if the comment is `inline: <no-addr>`. Image-base floor (0x40_0000)
/// filters out incidental small hex like vtable slots.
fn parse_inline_addr(txt: &str) -> Option<u64> {
    let after = txt.trim_start().strip_prefix("inline:")?.trim_start();
    // Take the first whitespace-delimited token.
    let first = after.split_whitespace().next()?;
    if !first.starts_with("0x") && !first.starts_with("0X") {
        return None;
    }
    // Strip Rust `_` digit separators (e.g. `0xAFFE_BABE`) before parsing.
    let stripped: String = first[2..].chars().filter(|c| *c != '_').collect();
    let v = u64::from_str_radix(&stripped, 16).ok()?;
    if v >= 0x40_0000 {
        Some(v)
    } else {
        None
    }
}

fn record_fn_addresses(
    addrs: &[u64],
    name: &str,
    is_method: bool,
    cginlined: bool,
    disp_path: &str,
    c: &mut Corpus,
) {
    let map = if is_method {
        &mut c.methods
    } else {
        &mut c.free_fns
    };
    let set = map.entry(name.to_string()).or_default();
    let mut seen_here: HashSet<u64> = HashSet::new();
    // The proc-macro's own span would give us a real file:line, but here we
    // only have `disp_path` (the source-tree-relative path). Per-fn line is
    // not available without a syn Span mapping; using `?` keeps the label
    // unique within the file while still grouping by `disp_path`. (The DUP-ADDR
    // gate doesn't require exact line info, just a stable unique label.)
    let label = format!("{disp_path}:? {name}");
    for &a in addrs {
        set.insert(a);
        c.addr2name.entry(a).or_insert_with(|| name.to_string());
        c.corpus.insert(a);
        if cginlined {
            c.inlined_markers.insert(a);
        }
        if seen_here.insert(a) {
            c.addr_owners.entry(a).or_default().push(label.clone());
        }
    }
}

// Bring `syn::parse_file` into scope without the `Result` arm: the build()
// caller handles parse errors by skipping the file.
//
// (Note: the previous text-matching helpers — find_kv, hex_addrs, fn_sig,
// skip_generics, grab_body, scan_file — are no longer needed. syn parses
// every file into structured Items; the only string matching left is inside
// doc-comment contents (legitimate plain text). Tests for the old helpers
// are replaced with syn-based equivalents below.)

/// True if the function's first parameter is a `self` receiver.
fn is_method_sig(sig: &Signature) -> bool {
    matches!(sig.inputs.first(), Some(FnArg::Receiver(_)))
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
    use super::{parse_inline_addr, scan_item, Corpus, Item};

    /// Build a Corpus and run every item in `text` through `scan_item` (the
    /// syn-based walker). Mirrors what `build()` does for one file.
    fn scan_text(text: &str) -> Corpus {
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
        let file = syn::parse_file(text).expect("parse");
        for item in &file.items {
            scan_item(item, "test.rs", &mut c);
        }
        c
    }

    // --- parse_inline_addr -------------------------------------------------

    #[test]
    fn parse_inline_addr_basic() {
        assert_eq!(parse_inline_addr("inline: 0x004028d0 (foo)").unwrap(), 0x004028d0);
        assert_eq!(parse_inline_addr("inline: 0xAFFE_BABE").unwrap(), 0xAFFEBABE);
    }

    #[test]
    fn parse_inline_addr_no_addr() {
        // No address after `inline:` → None (caller falls back to body fold-in).
        assert!(parse_inline_addr("inline: flag accessor").is_none());
    }

    #[test]
    fn parse_inline_addr_small_hex_filtered() {
        // Below 0x40_0000 → filtered out as incidental hex (vtable slot, offset).
        assert!(parse_inline_addr("inline: 0x84").is_none());
    }

    // --- syn-based scan ----------------------------------------------------

    #[test]
    fn syn_scan_picks_up_free_fn_with_origin() {
        let c = scan_text("#[origin(0x004028d0)] pub unsafe fn foo() {}");
        assert!(c.free_fns.contains_key("foo"));
        assert!(c.corpus.contains(&0x004028d0));
    }

    /// Regression for BUG #5: a commented-out `#[origin(..)]` reference in a
    /// doc-comment or `// …` line used to be matched as a real attribute and
    /// silently re-attribute the next fn. syn-based parsing sees comments as
    /// `Expr::Lit` doc-comments, not attributes — the address stays out.
    #[test]
    fn syn_scan_commented_origin_in_docstring_does_not_leak() {
        let c = scan_text(
            "\
// see #[origin(0xDEADBEEF)] for the old version
pub unsafe fn foo() {}
",
        );
        assert!(
            !c.corpus.contains(&0xDEADBEEF),
            "commented #[origin(0xDEADBEEF)] leaked into corpus: {:?}",
            c.corpus
        );
        assert!(!c.addr2name.contains_key(&0xDEADBEEF));
    }

    #[test]
    fn syn_scan_commented_origin_does_not_steal_real() {
        let c = scan_text(
            "\
#[origin(0x004028d0)]
/// historical note: was originally #[origin(0xCAFEBABE)]
pub unsafe fn foo() {}
",
        );
        assert!(c.corpus.contains(&0x004028d0));
        assert!(!c.corpus.contains(&0xCAFEBABE));
    }

    /// Regression for BUG #16: a `/// fn foo() {…}` doc-comment with fn-like
    /// text used to be parsed by the text scanner as a real signature. syn
    /// treats it as a string literal — it has no fn definition.
    #[test]
    fn syn_scan_fn_in_doc_comment_does_not_steal_origin() {
        let c = scan_text(
            "\
#[origin(0x004028d0)]
/// See `fn bar()` for context.
pub unsafe fn foo() {}
",
        );
        assert_eq!(
            c.addr2name.get(&0x004028d0).map(String::as_str),
            Some("foo"),
            "0x004028d0 should belong to `foo`, not a doc-comment fn: {:?}",
            c.addr2name
        );
    }

    /// syn-based scanning handles `#[origin]` on methods (impl-block fns).
    #[test]
    fn syn_scan_picks_up_impl_method() {
        let c = scan_text(
            "\
struct S;
impl S {
    #[origin(0x004028d0)]
    pub fn foo(&self) {}
}
",
        );
        assert!(c.methods.contains_key("foo"));
        assert!(c.corpus.contains(&0x004028d0));
    }

    /// syn handles generic functions correctly (no `take_while` on the raw
    /// text — BUG #1 was a text-scanner bug that's now structurally impossible).
    #[test]
    fn syn_scan_picks_up_generic_fn() {
        let c = scan_text("#[origin(0x004028d0)] pub fn foo<T: Clone>(x: T) -> T { x }");
        assert!(c.free_fns.contains_key("foo"));
        assert!(c.corpus.contains(&0x004028d0));
    }

    /// `#[callgraph_verify(0xA)]` is an alias for `#[origin(0xA)]`.
    #[test]
    fn syn_scan_picks_up_callgraph_verify_alias() {
        let c = scan_text("#[callgraph_verify(0x004028d0)] pub unsafe fn foo() {}");
        assert!(c.free_fns.contains_key("foo"));
        assert!(c.corpus.contains(&0x004028d0));
    }

    /// `/// inline: 0xA …` doc-comment with an address → records the addr,
    /// marks it as inlinable.
    #[test]
    fn syn_scan_inline_with_address_records_origin() {
        let c = scan_text(
            "\
/// inline: 0x0070b780 (typed entry over [ni_node_ctor])
pub unsafe fn helper() {}
",
        );
        assert!(c.free_fns.contains_key("helper"));
        assert!(c.corpus.contains(&0x0070b780));
        assert!(c.inlined_markers.contains(&0x0070b780));
    }

    /// `/// inline: <no-addr>` → captures body calls for fold-in.
    #[test]
    fn syn_scan_inline_without_address_captures_body() {
        let c = scan_text(
            "\
/// inline: flag accessor
pub unsafe fn flag_helper() { real_callee(); }
fn real_callee() {}
",
        );
        assert!(c.inline_fns.contains_key("flag_helper"));
        let bc = &c.inline_fns["flag_helper"];
        assert!(
            bc.plain.contains("real_callee"),
            "real_callee should be in the captured body calls: plain={:?}, method={:?}",
            bc.plain,
            bc.method
        );
    }

    /// `/// callgraph-inlined` and `/// callgraph-virtual` markers register
    /// the fn's address as inlinable (faithful direct call) regardless of
    /// whether the binary CALLs it.
    #[test]
    fn syn_scan_callgraph_inlined_marks_addr() {
        let c = scan_text(
            "\
/// callgraph-inlined
#[origin(0x004028d0)]
pub unsafe fn foo() {}
",
        );
        assert!(c.inlined_markers.contains(&0x004028d0));
    }

    /// `vtable_table!` macro invocation is parsed via syn::parse_file; the
    /// `declared_vtables` list gets (va, slots) tuples from it. Regression for
    /// BUG #15 (text-based substring match against `vtable_table!`).
    #[test]
    fn syn_scan_vtable_table_macro_records_decl() {
        let c = scan_text(
            "\
vtable_table! {
    name = my_vt,
    va = 0x00A88EA4,
    slots = 98,
    default = vtable::vtable_unimplemented;
    1 = helper;
}
",
        );
        assert!(
            c.declared_vtables.contains(&(0x00A88EA4, 98)),
            "vtable decl not recorded: {:?}",
            c.declared_vtables
        );
    }

    #[test]
    fn syn_scan_vtable_table_in_comment_does_not_record() {
        let c = scan_text(
            "\
// see vtable_table! in another module
fn helper() {}
",
        );
        assert!(
            c.declared_vtables.is_empty(),
            "comment mentioning vtable_table! should not produce a decl: {:?}",
            c.declared_vtables
        );
    }

    /// A plain `#[doc = "..."]` comment that mentions `vtable_table!` is
    /// not parsed as a macro invocation (it's a string literal attribute).
    #[test]
    fn syn_scan_vtable_table_in_doc_string_does_not_record() {
        let c = scan_text(
            "\
/// Use `vtable_table!` to declare engine vtables.
fn helper() {}
",
        );
        assert!(c.declared_vtables.is_empty());
    }

    /// Indented attributes (rustfmt) work — `trim_start()` was a text-scanner
    /// hack; syn handles indentation natively.
    #[test]
    fn syn_scan_indented_attribute_is_picked_up() {
        let c = scan_text("    #[origin(0x004028d0)]\n    pub fn foo() {}");
        assert!(c.free_fns.contains_key("foo"));
        assert!(c.corpus.contains(&0x004028d0));
    }

    /// Multiple addresses in one `#[origin]` should each be recorded as the
    /// fn's address (rare but supported via the dual-tag convention).
    #[test]
    fn syn_scan_dual_tag_does_not_duplicate_owner() {
        let c = scan_text(
            "\
#[origin(0x004028d0)]
/// origin: 0x004028d0
pub unsafe fn foo() {}
",
        );
        // 0x004028d0 should appear once in addr_owners (one fn = one owner).
        let owners = &c.addr_owners[&0x004028d0];
        assert_eq!(owners.len(), 1, "expected one owner, got {owners:?}");
    }

    /// `cfg(test)` modules in the source tree are not skipped by the syn
    /// scanner (the python-lint behavior). Documented behavior change: this
    /// scanner DOES harvest them, since `cfg(test)` is resolved by the
    /// compiler, not the parser. Pin the new behavior.
    #[test]
    fn syn_scan_cfg_test_fn_is_harvested() {
        let c = scan_text(
            "\
#[cfg(test)]
mod tests {
    #[origin(0x004028d0)]
    fn foo() {}
}
",
        );
        assert!(c.free_fns.contains_key("foo"));
    }

    /// `is_method` is set for impl-block fns even without `self` (rare but
    /// valid syntax — `impl S { fn foo() {} }` is a free fn returning Self).
    /// In practice every impl fn is a method. Confirm the metadata.
    #[test]
    fn syn_scan_impl_fn_without_self_still_classified_as_method() {
        // syn represents `impl S { fn foo() {} }` as an ImplItemFn whose first
        // arg is NOT a Receiver. We classify any impl fn as a method, so it
        // ends up in `methods` not `free_fns`.
        let c = scan_text(
            "\
struct S;
impl S {
    #[origin(0x004028d0)]
    fn foo() -> Self { S }
}
",
        );
        assert!(c.methods.contains_key("foo"));
        assert!(!c.free_fns.contains_key("foo"));
    }
}
