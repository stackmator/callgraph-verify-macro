//! Build the `name -> origin-addr` map for the rebuild by scanning the source
//! tree. A proc-macro can't see the compiler's symbol table, but it can read the
//! files — so we harvest every function's declared origin address from its tag.
//!
//! Only one tag form is recognized, associated with the `fn NAME` below it:
//!   * `#[origin(0x004028d0)]` — the provenance tag + verifier attribute
//!
//! Scanned once per compiler process and cached.

use std::collections::{BTreeSet, HashMap, HashSet};
use std::sync::{Arc, OnceLock};

use syn::{
    parse_file as syn_parse_file, Attribute, FnArg, ImplItem, ImplItemFn, Item, ItemFn, Meta,
    Signature, TraitItem, TraitItemFn,
};

use crate::{expand, parse_origin_attr, VtableTable};

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
    /// `(engine vtable VA, slot count)` for every `vtable_table!` the rebuild declares.
    /// Lets the verifier read those engine vtables from the PE and recognize which call
    /// targets are virtual methods (→ "use vcall, not a direct call").
    pub declared_vtables: Vec<(u64, usize)>,
    /// `macro_rules!` definitions by macro name (all definition sites; an
    /// entry with more than one def is ambiguous and never expanded).
    /// Harvested by the same file scan so the body check can see through
    /// unambiguous local macros (see `expand`).
    pub macro_defs: HashMap<String, Vec<expand::MacroDef>>,
    /// Source files the scanner had to skip (`"<relpath>: <reason>"`),
    /// i.e. unreadable or unparseable. Every `#[origin]` inside them is
    /// invisible to the corpus, so their functions report a misleading
    /// CORPUS-GAP instead of the real cause. The verifier surfaces this
    /// list on every E008 so the actual breakage is actionable.
    pub parse_errors: Vec<String>,
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

/// Build a corpus from a directory tree, bypassing the process-global
/// cache. For tests that need to exercise different roots in the same
/// process (the cache in `corpus_map` would otherwise return the first
/// root's result forever).
#[cfg(test)]
pub(crate) fn build_cached(root: &str) -> Arc<Corpus> {
    Arc::new(build(root))
}

fn build(root: &str) -> Corpus {
    let mut c = Corpus {
        free_fns: HashMap::new(),
        methods: HashMap::new(),
        addr2name: HashMap::new(),
        addr_owners: HashMap::new(),
        corpus: BTreeSet::new(),
        declared_vtables: Vec::new(),
        macro_defs: HashMap::new(),
        parse_errors: Vec::new(),
    };
    let root_path = std::path::Path::new(root);
    for path in rust_files(root_path) {
        let text = match std::fs::read_to_string(&path) {
            Ok(t) => t,
            Err(e) => {
                c.parse_errors.push(format!(
                    "{}: unreadable ({e})",
                    disp_of(root_path, &path)
                ));
                continue;
            }
        };
        let disp = disp_of(root_path, &path);
        // syn-based scan: the Rust parser resolves every comment-vs-attribute-vs-code
        // ambiguity; only structured attributes carry provenance facts, never comments.
        // A file that fails to parse is recorded (not silently skipped): every
        // #[origin] inside it would otherwise report a misleading CORPUS-GAP.
        match syn_parse_file(&text) {
            Ok(file) => {
                for item in &file.items {
                    scan_item(item, &disp, &mut c);
                }
            }
            Err(e) => {
                // syn errors are multi-line; keep the first line (file:line + kind).
                let first = e.to_string().lines().next().unwrap_or("parse error").to_string();
                c.parse_errors.push(format!("{disp}: unparseable ({first})"));
            }
        }
    }
    c
}

/// Display path of `path` relative to the corpus `root`, `/`-separated.
fn disp_of(root_path: &std::path::Path, path: &std::path::Path) -> String {
    path.strip_prefix(root_path)
        .unwrap_or(path)
        .to_string_lossy()
        .replace('\\', "/")
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
            if path_is(&m.mac.path, "macro_rules") {
                if let Some((name, def)) = expand::parse_macro_rules(m, disp_path) {
                    c.macro_defs.entry(name).or_default().push(def);
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

/// Harvest a free `fn`'s origin annotation.
fn scan_fn(f: &ItemFn, disp_path: &str, c: &mut Corpus) {
    let name = f.sig.ident.to_string();
    let is_method = is_method_sig(&f.sig);
    scan_attrs_and_record(&f.attrs, &name, is_method, disp_path, c);
}

/// Harvest an `impl`-block method's origin annotation.
fn scan_impl_fn(m: &ImplItemFn, disp_path: &str, c: &mut Corpus) {
    let name = m.sig.ident.to_string();
    let is_method = true; // `self` is implicit inside an impl block
    scan_attrs_and_record(&m.attrs, &name, is_method, disp_path, c);
}

/// Harvest a trait method's origin annotation (a trait default body).
fn scan_trait_fn(m: &TraitItemFn, disp_path: &str, c: &mut Corpus) {
    let name = m.sig.ident.to_string();
    let is_method = true;
    scan_attrs_and_record(&m.attrs, &name, is_method, disp_path, c);
}

/// Walk an attribute list looking for `#[origin(0xA)]`
/// and the `unreferenced` flag. Record every origin address into `c`.
fn scan_attrs_and_record(attrs: &[Attribute], name: &str, is_method: bool, disp_path: &str, c: &mut Corpus) {
    let mut addrs: Vec<u64> = Vec::new();

    for attr in attrs {
        match &attr.meta {
            Meta::Path(_) | Meta::NameValue(_) => {
                // Bare-path and name-value attributes (doc comments, derives, …)
                // carry no structured origin facts — they are ignored.
            }
            Meta::List(m) => {
                // Match on the LAST segment of the path: the macro is typically
                // invoked as `#[callgraph_verify_macro::origin(VA)]` (3 segments),
                // not bare `#[origin(VA)]`. `is_ident` returns true ONLY for a
                // single-segment path — using it here silently rejected every
                // qualified `#[origin]` tag in the workspace, then the
                // CORPUS-GAP self-check fired for every fn (it looked like the
                // scanner saw zero origins). Same helper as vtable_table below.
                if !path_is(attr.path(), "origin") {
                    continue;
                }
                // The token stream between the parens — `parse_origin_attr`
                // uses the existing `Args` parser.
                if let Ok(o) = parse_origin_attr(m.tokens.clone()) {
                    addrs.push(o.addr);
                }
            }
        }
    }

    if !addrs.is_empty() {
        record_fn_addresses(&addrs, name, is_method, disp_path, c);
    }
}

fn record_fn_addresses(
    addrs: &[u64],
    name: &str,
    is_method: bool,
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
        if seen_here.insert(a) {
            c.addr_owners.entry(a).or_default().push(label.clone());
        }
    }
}

// Bring `syn::parse_file` into scope without the `Result` arm: the build()
// caller handles parse errors by skipping the file.
//
// (Note: the previous text-matching helpers — find_kv, hex_addrs, fn_sig,
// skip_generics, grab_body, scan_file — and the doc-comment `inline:` /
// `callgraph-inlined` / `origin:` scanning are all gone. syn parses every
// file into structured Items, and provenance facts come ONLY from the
// `#[origin(..)]` attributes. Tests for the old
// helpers are replaced with syn-based equivalents below.)

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
    use super::{build_cached, scan_item, Corpus};

    /// Build a Corpus and run every item in `text` through `scan_item` (the
    /// syn-based walker). Mirrors what `build()` does for one file.
    fn scan_text(text: &str) -> Corpus {
        let mut c = Corpus {
            free_fns: std::collections::HashMap::new(),
            methods: std::collections::HashMap::new(),
            addr2name: std::collections::HashMap::new(),
            addr_owners: std::collections::HashMap::new(),
            corpus: std::collections::BTreeSet::new(),
            declared_vtables: Vec::new(),
            macro_defs: std::collections::HashMap::new(),
            parse_errors: Vec::new(),
        };
        let file = syn::parse_file(text).expect("parse");
        for item in &file.items {
            scan_item(item, "test.rs", &mut c);
        }
        c
    }

    /// Parse a statement list as a Block and harvest its body facts — the
    /// same visitor the verifier runs over `#[origin]` fn bodies.
    fn block_facts_of(stmts: &str) -> crate::body::FnBodyFacts {
        let block: syn::Block = syn::parse_str(&format!("{{ {stmts} }}")).expect("parse block");
        crate::body::collect_block_facts(&block)
    }

    // --- syn-based scan ----------------------------------------------------

    /// Regression: the old doc-comment `/// inline:` / `/// callgraph-inlined`
    /// conventions are gone. Comments carry no structured facts — a doc comment
    /// mentioning `inline:` must NOT create an origin or any corpus entry.
    #[test]
    fn syn_scan_inline_doc_comment_does_not_affect_corpus() {
        let c = scan_text(
            "\
#[origin(0x004028d0)]
/// inline: 0x0070b780 (typed entry over [ni_node_ctor])
pub unsafe fn foo() {}
",
        );
        assert_eq!(c.corpus.len(), 1, "expected only the attribute's addr: {:?}", c.corpus);
        assert!(c.corpus.contains(&0x004028d0));
        assert!(!c.corpus.contains(&0x0070b780));
    }

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

    /// Regression: `#[callgraph_verify_macro::origin(VA)]` (the FULL path the
    /// macro is actually invoked with, three segments, not one) was silently
    /// dropped because the scanner checked `attr.path().is_ident("origin")`
    /// — `is_ident` is true only for a single-segment path. With the bug,
    /// every qualified `#[origin]` tag in the workspace was rejected and the
    /// CORPUS-GAP self-check fired for every tagged fn. Match on the last
    /// segment (`path_is` helper, same as `vtable_table!`).
    #[test]
    fn syn_scan_picks_up_qualified_origin_path() {
        let c = scan_text("#[callgraph_verify_macro::origin(0x004028d0)] pub unsafe fn foo() {}");
        assert!(
            c.free_fns.contains_key("foo"),
            "qualified `#[callgraph_verify_macro::origin(...)]` was dropped: {:?}",
            c.free_fns
        );
        assert!(
            c.corpus.contains(&0x004028d0),
            "qualified origin addr missing from corpus: {:?}",
            c.corpus
        );
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

    /// A doc comment mentioning `origin:` (the legacy convention) alongside the
    /// real attribute must NOT double-register the owner: comments carry no
    /// structured facts, so only the `#[origin]` records the address.
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

    // ====================================================================
    // Unhappy-path / regression tests (B-01..B-10 coverage).
    // ====================================================================

    // B-01: Two `#[origin(0xA)]` on different functions → both are recorded as
    // owners of address 0xA in `addr_owners`. The verifier's DUP-ADDR
    // check triggers when there is more than one owner. We pin that the
    // corpus actually records both (i.e. the dup-detection input exists
    // and is correct).
    #[test]
    fn b01_duplicate_origin_addresses_are_recorded_as_separate_owners() {
        let c = scan_text(
            "\
#[origin(0x004028d0)]
pub unsafe fn foo_a() {}
#[origin(0x004028d0)]
pub unsafe fn foo_b() {}
",
        );
        let owners = c.addr_owners.get(&0x004028d0).expect("addr present");
        // The DUP-ADDR check looks at `owners.len() > 1`. We assert BOTH
        // owners are present so the check actually fires.
        assert_eq!(owners.len(), 2, "expected 2 owners, got {owners:?}");
        assert!(owners.iter().any(|s| s.contains("foo_a")));
        assert!(owners.iter().any(|s| s.contains("foo_b")));
    }

    // B-04: Path-qualified calls strip the path. `crate::module::func()`
    // records just `func`, not `crate` and not `module`.
    #[test]
    fn b04_path_qualified_calls_strip_the_path() {
        let facts = block_facts_of("crate::module::func(1, 2);");
        assert!(
            facts.names.plain.contains("func"),
            "path-qualified `crate::module::func()` should record just `func`, got: {:?}",
            facts.names.plain
        );
        assert!(
            !facts.names.plain.contains("crate"),
            "leading path segment `crate` leaked into plain: {:?}",
            facts.names.plain
        );
        assert!(
            !facts.names.plain.contains("module"),
            "middle path segment `module` leaked into plain: {:?}",
            facts.names.plain
        );
    }

    // B-04 (method): `obj.method()` is a method call, not a plain call.
    #[test]
    fn b04_method_call_via_dot_is_classified_as_method() {
        let facts = block_facts_of("obj.method(1, 2);");
        assert!(
            facts.names.plain.is_empty(),
            "method leaked to plain: {:?}",
            facts.names.plain
        );
        assert!(
            facts.names.method.contains("method"),
            "method not captured: {:?}",
            facts.names.method
        );
    }

    // B-04 (multi-line call): a call split across lines is one call.
    #[test]
    fn b04_multiline_call_is_one_call() {
        let facts = block_facts_of(
            "foo(
    1,
    2,
);",
        );
        assert!(
            facts.names.plain.contains("foo"),
            "multi-line call should record `foo` once, got: {:?}",
            facts.names.plain
        );
        assert_eq!(
            facts.names.plain.len(),
            1,
            "expected exactly 1 call, got: {:?}",
            facts.names.plain
        );
    }

    // B-09: A function defined in two modules with the same name → the
    // corpus records the second one (because the walker overwrites on
    // duplicate names in the `free_fns` map). The `corpus` BTreeSet, by
    // contrast, accumulates BOTH addresses (Set::insert is additive, not
    // overwriting). Documenting the actual behavior; the existing
    // pipeline relies on unique function names — having two `inner`
    // functions in different modules is silently OK as long as the
    // verifier's call-graph diff picks ONE (the first/last walker wins
    // for resolution, but both addresses show up in the corpus for
    // owner-tracking purposes).
    #[test]
    fn b09_nested_module_name_collision_both_addresses_in_corpus() {
        let c = scan_text(
            "\
mod a {
    #[origin(0x004028d0)]
    pub fn inner() {}
}
mod b {
    #[origin(0x004028d1)]
    pub fn inner() {}
}
",
        );
        // Both addresses are in the corpus (BTreeSet is additive).
        assert!(c.corpus.contains(&0x004028d0));
        assert!(c.corpus.contains(&0x004028d1));
        // Both functions are recorded as owners of their respective
        // addresses.
        assert!(c.addr_owners.contains_key(&0x004028d0));
        assert!(c.addr_owners.contains_key(&0x004028d1));
        // The free_fns map (HashMap<String, HashSet<u64>>) has the name
        // registered with BOTH addresses — last-wins is at the per-name
        // level only when the addresses are different but stored as the
        // same set. Both addresses survive.
        let free_inner = c.free_fns.get("inner").expect("`inner` recorded");
        assert_eq!(
            free_inner.len(),
            2,
            "free_fns['inner'] should have both addresses, got {free_inner:?}"
        );
    }

    // B-05: A `.rs` file with a syntax error is silently skipped — the
    // walker must NOT panic and must still pick up origins from the
    // surrounding good files.
    #[test]
    fn b05_parse_error_resilience_skips_bad_file() {
        let dir = std::env::temp_dir().join("callgraph_b05");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();

        // Good file with one origin.
        std::fs::write(
            dir.join("good.rs"),
            "#[origin(0x004028d0)]\npub unsafe fn good_fn() {}\n",
        )
        .unwrap();

        // Bad file with unbalanced braces. syn::parse_file returns Err;
        // the walker must continue past it.
        std::fs::write(dir.join("bad.rs"), "pub unsafe fn bad_fn( {}\n").unwrap();

        // Another good file.
        std::fs::write(
            dir.join("good2.rs"),
            "#[origin(0x004028e0)]\npub unsafe fn other_good() {}\n",
        )
        .unwrap();

        let c = build_cached(dir.to_str().unwrap());
        assert!(
            c.corpus.contains(&0x004028d0),
            "good.rs origin not picked up: {:?}",
            c.corpus
        );
        assert!(
            c.corpus.contains(&0x004028e0),
            "good2.rs origin not picked up: {:?}",
            c.corpus
        );
        // The bad file's function should not appear (its origin attribute
        // was never reached because parsing failed).
        assert!(
            !c.free_fns.contains_key("bad_fn"),
            "bad_fn should be skipped: {:?}",
            c.free_fns
        );
    }

    // B-05b: A `.rs` file with a syntax error is RECORDED, not silently
    // skipped — `parse_errors` names it so the verifier can point at the
    // real breakage instead of emitting a misleading CORPUS-GAP per origin.
    #[test]
    fn b05b_parse_error_is_recorded_not_silent() {
        let dir = std::env::temp_dir().join("callgraph_b05b");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();

        std::fs::write(
            dir.join("good.rs"),
            "#[origin(0x004028d0)]\npub unsafe fn good_fn() {}\n",
        )
        .unwrap();
        std::fs::write(dir.join("bad.rs"), "pub unsafe fn bad_fn( {}\n").unwrap();

        let c = build_cached(dir.to_str().unwrap());
        assert!(
            c.corpus.contains(&0x004028d0),
            "good.rs origin not picked up: {:?}",
            c.corpus
        );
        assert_eq!(
            c.parse_errors.len(),
            1,
            "exactly the bad file should be recorded: {:?}",
            c.parse_errors
        );
        assert!(
            c.parse_errors[0].starts_with("bad.rs:"),
            "entry names the file: {:?}",
            c.parse_errors
        );
    }

    // B-07: An empty REBUILD_ROOT (a directory with no `.rs` files)
    // returns a Corpus with zero entries. The verifier must not crash
    // when the corpus is empty.
    #[test]
    fn b07_empty_rebuild_root_returns_empty_corpus() {
        let dir = std::env::temp_dir().join("callgraph_b07");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();

        let c = build_cached(dir.to_str().unwrap());
        assert!(
            c.corpus.is_empty(),
            "empty dir should have empty corpus: {:?}",
            c.corpus
        );
        assert!(c.free_fns.is_empty());
        assert!(c.methods.is_empty());
        assert!(c.addr_owners.is_empty());
    }

    // B-XX: `macro_rules!` definitions are harvested for the body
    // expander: a simple arm parses, a repetition-only macro yields no
    // usable arms (and is not stored), and a name defined twice stays
    // ambiguous (two defs — the expander must decline it).
    #[test]
    fn bxx_macro_rules_defs_harvested() {
        let dir = std::env::temp_dir().join("callgraph_bxx_macros");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(
            dir.join("a.rs"),
            "macro_rules! rel { ($o:expr) => { g($o); }; }\n\
             macro_rules! fwd { ($($a:ident),*) => { g($($a),*) }; }\n",
        )
        .unwrap();
        std::fs::write(
            dir.join("b.rs"),
            "macro_rules! rel { ($o:expr) => { h($o); }; }\n",
        )
        .unwrap();
        let c = build_cached(dir.to_str().unwrap());
        // `rel` is defined twice -> ambiguous (two defs stored).
        let rel = c.macro_defs.get("rel").expect("rel harvested");
        assert_eq!(rel.len(), 2, "ambiguous name keeps both defs: {rel:?}");
        // `fwd` needs repetitions -> no usable arm -> not stored.
        assert!(
            !c.macro_defs.contains_key("fwd"),
            "repetition-only def must not be stored: {:?}",
            c.macro_defs.keys()
        );
    }

    // B-02: `diff_body_calls` returns a hallucinated entry for a body
    // call name that doesn't exist in the corpus. We can't invoke
    // `diff_body_calls` directly from this test (it needs a real PE),
    // so we pin the underlying contract via `body::collect_call_idents`:
    // a body call whose name is not in the corpus, combined with no
    // direct_calls at that target, is what produces the
    // `HALLUCINATED` error. We assert the inverse here: the call
    // collection step in `body` records a name that the corpus would
    // then fail to resolve.
    #[test]
    fn b02_body_call_idents_records_unknown_names() {
        // `some_random_helper` is not a built-in and not in any corpus.
        let facts = block_facts_of("some_random_helper();");
        assert!(
            facts.names.plain.contains("some_random_helper"),
            "the body call should be captured: {:?}",
            facts.names.plain
        );
        // (The verifier's diff_body_calls then fails to resolve it and
        // reports it as HALLUCINATED — this test pins the body side.)
    }

    // B-03: pin the corpus_map API used by the verifier — empty file
    // tree returns a corpus whose `corpus` is empty (BTreeSet is
    // additive and remains empty when nothing is added). When
    // `diff_body_calls` is called with an empty corpus, the missing
    // set is the entire body's call set, classified as HALLUCINATED.
    #[test]
    fn b03_empty_corpus_makes_every_call_hallucinated() {
        let dir = std::env::temp_dir().join("callgraph_b03");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(
            dir.join("body.rs"),
            "pub unsafe fn body() { imaginary_call(); }\n",
        )
        .unwrap();
        let c = build_cached(dir.to_str().unwrap());
        // No `#[origin]` attributes anywhere, so the corpus is empty.
        assert!(
            c.corpus.is_empty(),
            "corpus should be empty, got: {:?}",
            c.corpus
        );
        assert!(c.free_fns.is_empty());
    }

    // B-06: `Pe::parse` rejects an x64 PE. We build a minimal COFF/PE
    // header with `machine = 0x8664` (x86_64) and verify it returns
    // `Err`. The i386 case (`machine = 0x14c`) is the positive path
    // (already covered by the integration tests that load test-bin.exe).
    #[test]
    fn b06_pe_parse_rejects_non_i386() {
        use callgraph_verify::Pe;
        // Minimal PE32 header. Layout (offsets within the file):
        //   0x00  "MZ"
        //   0x3c  e_lfanew -> PE header
        //   PE:    "PE\0\0" + COFF(20) + OptHdr(96) + SectHdr(40)
        //   We place PE at offset 0x40, COFF at 0x44, OptHdr at 0x58,
        //   SectHdr at 0xb8. machine is at PE+4 = 0x44.
        let mut data = vec![0u8; 0x100];
        // MZ magic
        data[0..2].copy_from_slice(b"MZ");
        data[0x3c..0x40].copy_from_slice(&0x40u32.to_le_bytes());
        // PE\0\0
        data[0x40..0x44].copy_from_slice(b"PE\0\0");
        // COFF: machine at +4
        data[0x44..0x46].copy_from_slice(&0x8664u16.to_le_bytes()); // x86_64
        data[0x46..0x48].copy_from_slice(&1u16.to_le_bytes()); // num sections
        data[0x50..0x52].copy_from_slice(&0x60u16.to_le_bytes()); // size of optional header
                                                                  // OptHdr magic (PE32 = 0x10b)
        data[0x58..0x5a].copy_from_slice(&0x10bu16.to_le_bytes());
        assert!(Pe::parse(data).is_err(), "x64 PE should be rejected");
    }

    // B-10: an empty function (just `RET`) doesn't crash `analyze`.
    // Use the synthetic PE helper from the integration test to plant
    // a `RET` in .text and verify the walker accepts it.
    //
    // (This is in integration tests as a pin of `analyze` robustness
    // — the corpus unit tests don't have a PE builder, so this is
    // tested at the integration level.)
    //
    // B-08: out-of-section `#[origin(0xFFFFFFFF)]` — tested at the
    // integration level because the verifier runs as a proc-macro
    // and we need a real PE.
}
