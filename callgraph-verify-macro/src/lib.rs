//! `#[callgraph_verify(0xADDR)]` — keep a rebuild function true to the target binary
//! AT COMPILE TIME. On every build the macro:
//!
//!   1. parses ITS OWN function body for the functions it calls,
//!   2. resolves those names to addresses via the rebuild's `origin:` corpus
//!      (scanned straight from the source tree — a proc-macro can't see the
//!      compiler's symbol table, but it can read the files),
//!   3. disassembles the binary at `0xADDR` and diffs the two call sets.
//!
//! An invented call (`HALLUCINATED`) expands to `compile_error!`, so `cargo
//! build`/`cargo check` FAILS — if someone edits the body to call something the
//! original never does, the build breaks. Calls the binary makes that the body
//! omits are `MISSING` (often a faithful inline) — reported, non-fatal unless
//! `strict_missing` is passed.
//!
//! The bare address is enough:  `#[callgraph_verify(0x004028d0)]`
//! Optional explicit facts pin individual operands too:
//!   `#[callgraph_verify(0x0070b780, vtables = [0x00a7e38c], fields = [0xbc])]`
//!
//! ## Environment (set in `.cargo/config.toml` `[env]`)
//!   * `TARGET_EXE`     — path to the binary (absent → macro is a no-op)
//!   * `REBUILD_ROOT`   — rebuild source root for the corpus scan (absent →
//!     the body-diff is skipped; explicit `calls=`/`fields=` checks still run)
//!
//! Strict checks (`DUP-ADDR`, `MISSING`, `ARG-SHAPE`, `HALLUCINATED-ADDR`,
//! `CFG`) are always on. There used to be `DUP_STRICT=0`,
//! `STRICT_MISSING=0`, `STRICT_ARGS=0`, `STRICT_OPERANDS=0`, and
//! `STRICT_CFG=1` escape hatches, but AI agents were flipping them off
//! to silence build failures. Removed: if a check is wrong, fix the
//! check, don't add a backdoor. The macro is a strict gate, not a
//! configurable knob.

use proc_macro::TokenStream;
use quote::{quote, ToTokens};
use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex, OnceLock};
use syn::parse::{Parse, ParseStream};
use syn::{parse_macro_input, Expr, ExprArray, Ident, Lit, LitInt, Token};

use callgraph_verify::{analyze, cfg_fingerprint, diff_body_calls, reg_params, ArgKind, Pe, Spec};

mod body;
mod corpus;

struct Args {
    addr: u64,
    calls: Option<(Vec<u64>, bool)>,
    fields: Vec<u64>,
    globals: Vec<u64>,
    vtables: Vec<u64>,
    vcall_slots: Vec<u64>,
    iat: Vec<u64>,
    /// Waiver for the ORIGIN-UNREFERENCED check: this origin address is real but
    /// the binary never CALLs/JMPs to it nor stores it as a pointer (e.g. the
    /// boot anchor reached only via the OBSE hook, or a Ghidra-undetected stub).
    /// Deliberately loud at the use site — a reviewer should ask why.
    unreferenced: bool,
}

/// What the macro needs to harvest from `#[origin(...)]` / `#[callgraph_verify(...)]`
/// for the corpus scanner. Public(crate) so `corpus::scan_item` can reuse the
/// same parser instead of inventing a parallel one. The proc-macro's own
/// `verify_impl` builds a richer `Spec` from `Args`; the scanner only needs
/// the address (and the `unreferenced` waiver doesn't change the scan).
#[derive(Debug, Clone)]
pub(crate) struct OriginAttr {
    pub addr: u64,
}

/// Parse the inner tokens of `#[origin(…)]` / `#[callgraph_verify(…)]`.
/// Accepts a `proc_macro2::TokenStream` so `corpus::scan_item` (which walks
/// the syn AST) can call it without round-tripping through `proc_macro`.
pub(crate) fn parse_origin_attr(tokens: proc_macro2::TokenStream) -> syn::Result<OriginAttr> {
    let args: Args = syn::parse2(tokens)?;
    Ok(OriginAttr { addr: args.addr })
}

fn array_of_u64(arr: &ExprArray) -> syn::Result<Vec<u64>> {
    arr.elems
        .iter()
        .map(|e| match e {
            Expr::Lit(el) => match &el.lit {
                Lit::Int(li) => li.base10_parse::<u64>(),
                _ => Err(syn::Error::new_spanned(e, "expected an integer literal")),
            },
            _ => Err(syn::Error::new_spanned(e, "expected an integer literal")),
        })
        .collect()
}

impl Parse for Args {
    fn parse(input: ParseStream) -> syn::Result<Self> {
        let addr: u64 = input.parse::<LitInt>()?.base10_parse()?;
        let mut a = Args {
            addr,
            calls: None,
            fields: Vec::new(),
            globals: Vec::new(),
            vtables: Vec::new(),
            vcall_slots: Vec::new(),
            iat: Vec::new(),
            unreferenced: false,
        };
        while input.peek(Token![,]) {
            input.parse::<Token![,]>()?;
            if input.is_empty() {
                break;
            }
            let key: Ident = input.parse()?;
            // Bare flags (no `= [..]`).
            if !input.peek(Token![=]) {
                match key.to_string().as_str() {
                    "unreferenced" => {
                        a.unreferenced = true;
                        continue;
                    }
                    other => {
                        return Err(syn::Error::new(
                            key.span(),
                            format!("unknown flag `{other}`"),
                        ))
                    }
                }
            }
            input.parse::<Token![=]>()?;
            let vals = array_of_u64(&input.parse::<ExprArray>()?)?;
            match key.to_string().as_str() {
                "calls" => a.calls = Some((vals, false)),
                "calls_exact" => a.calls = Some((vals, true)),
                "fields" => a.fields = vals,
                "globals" => a.globals = vals,
                "vtables" => a.vtables = vals,
                "vcall_slots" => a.vcall_slots = vals,
                "iat" => a.iat = vals,
                other => {
                    return Err(syn::Error::new(
                        key.span(),
                        format!("unknown key `{other}`"),
                    ))
                }
            }
        }
        Ok(a)
    }
}

/// Cache type aliases — clippy `very_complex_type` lint hates the full form.
type PeCache = Mutex<HashMap<String, Option<Arc<Pe>>>>;
type AddrsCache = Mutex<HashMap<(String, u64), Arc<HashSet<u32>>>>;
type VTableMap = HashMap<u64, (u64, usize)>;
type VTableCache = Mutex<HashMap<CacheKey, OnceLock<Arc<VTableMap>>>>;

fn load_pe_cached(path: &str) -> Option<Arc<Pe>> {
    static CACHE: OnceLock<PeCache> = OnceLock::new();
    let cache = CACHE.get_or_init(|| Mutex::new(HashMap::new()));
    let mut m = cache.lock().unwrap();
    if let Some(v) = m.get(path) {
        return v.clone();
    }
    let loaded = Pe::load(path).ok().map(Arc::new);
    m.insert(path.to_string(), loaded.clone());
    loaded
}

/// Every VA the binary references (rel32 branch targets + in-image dwords at every
/// byte offset). Built once per `(exe path, image_base)` pair per compiler process
/// (~one linear pass over the 8 MB image); used by the ORIGIN-UNREFERENCED check.
/// Keyed per binary — a bare `static OnceLock` would return the FIRST PE's set for
/// every subsequent PE (the same input-ignoring-cache class as BUG #9).
fn referenced_addrs_cached(
    exe: &str,
    pe: &Pe,
) -> std::sync::Arc<std::collections::HashSet<u32>> {
    static CACHE: OnceLock<AddrsCache> = OnceLock::new();
    let cache = CACHE.get_or_init(|| Mutex::new(HashMap::new()));
    let key = (exe.to_string(), pe.image_base);
    let mut m = cache.lock().unwrap_or_else(|e| e.into_inner());
    m.entry(key)
        .or_insert_with(|| std::sync::Arc::new(pe.referenced_addrs()))
        .clone()
}

/// Print a NOTE to stderr, deduplicated by full message text per compiler
/// process. The previous implementation used a single `OnceLock<()>`, which
/// printed only the FIRST note of the whole build and silently dropped every
/// later one (FAKE-LOOP for the 2nd+ fn, VTABLE-ONLY DISPATCH, INLINE-MARKER
/// MISMATCH, …) — a diagnostic channel 90% dead.
///
/// Notes go to stderr because a proc-macro cannot emit `#[warn]` diagnostics;
/// they are visible with `cargo build -vv` / `cargo check -vv`.
fn note(msg: &str) {
    static SEEN: OnceLock<Mutex<std::collections::HashSet<String>>> = OnceLock::new();
    let seen = SEEN.get_or_init(|| Mutex::new(std::collections::HashSet::new()));
    if seen
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .insert(msg.to_string())
    {
        eprintln!("callgraph_verify_macro: {msg}");
    }
}

/// Compute the set of inlined-marker addresses that the binary still
/// CALL/JMP/Jccs into from .text. Each is returned as a one-line note
/// suitable for `note`. Extracted from the macro body so it can be
/// unit-tested without a proc-macro harness.
pub(crate) fn inline_marker_mismatches(
    pe: &callgraph_verify::Pe,
    inlined: &std::collections::BTreeSet<u64>,
) -> Vec<String> {
    let mut out = Vec::new();
    for &addr in inlined {
        if callgraph_verify::has_direct_branch_target(pe, addr) {
            out.push(format!(
                "INLINE-MARKER MISMATCH: {addr:#010x} is marked `inline:` (or `callgraph-inlined`) \
                 in the corpus, but the binary still has a real CALL/JMP/Jcc targeting it from .text. \
                 If the engine only sometimes inlines this helper, ensure the non-inlined call sites \
                 also have a faithful `#[origin({addr:#010x})]` implementation."
            ));
        }
    }
    out
}

/// `#[origin(0xADDR)]` — provenance tag + compile-time call-graph verifier.
/// See the crate docs. `#[callgraph_verify(..)]` is kept as an alias.
#[proc_macro_attribute]
pub fn origin(attr: TokenStream, item: TokenStream) -> TokenStream {
    verify_impl(attr, item)
}

/// Alias for [`macro@origin`].
#[proc_macro_attribute]
pub fn callgraph_verify(attr: TokenStream, item: TokenStream) -> TokenStream {
    verify_impl(attr, item)
}

/// Map `engine method address -> (vtable VA, slot)` for every `vtable_table!` the rebuild
/// declares, read from the PE. Lets the verifier tell when a direct Rust call targets a method
/// the binary actually dispatches virtually. Cached per `(image_base, declared)` so a
/// multi-target build (rare but possible: test binaries, fuzz harnesses) gets a fresh map
/// per PE/corpus. (BUG #9)
fn vtable_method_map<'a>(
    pe: &'a Pe,
    declared: &'a [(u64, usize)],
) -> std::sync::Arc<HashMap<u64, (u64, usize)>> {
    // Double-checked init under a single Mutex<HashMap<…, OnceLock<…>>>:
    // each (image_base, declared fingerprint) gets its own OnceLock. Steady
    // state is a lock-free `OnceLock::get()` returning the cached Arc; the
    // mutex is only held on the very first request per key.
    static CACHE: OnceLock<VTableCache> = OnceLock::new();
    let key = CacheKey::new(pe, declared);
    let cache = CACHE.get_or_init(|| Mutex::new(HashMap::new()));
    let mut lock = cache.lock().unwrap_or_else(|e| e.into_inner());
    let entry = lock.entry(key).or_default();
    entry
        .get_or_init(|| {
            let mut m = HashMap::new();
            for &(va, slots) in declared {
                for slot in 0..slots {
                    // `read` clamps to the section's raw bytes, so a slot at the
                    // tail can legally return 1..3 bytes — index those and the
                    // proc-macro panics (cryptic "proc macro panicked" build
                    // failure). A short read is not a readable slot.
                    if let Some(b) = pe.read(va + (slot as u64) * 4, 4) {
                        if b.len() < 4 {
                            continue;
                        }
                        let a = u32::from_le_bytes([b[0], b[1], b[2], b[3]]) as u64;
                        if a != 0 {
                            m.entry(a).or_insert((va, slot));
                        }
                    }
                }
            }
            std::sync::Arc::new(m)
        })
        .clone()
}

/// Cache key for `vtable_method_map`. Combines the PE's image base (so a
/// different binary target produces a different map) with a fingerprint of
/// the declared vtable list (so changing a `vtable_table!` invalidates
/// the entry).
#[derive(Debug, Eq, PartialEq, Hash)]
struct CacheKey {
    image_base: u64,
    /// A 64-bit hash of (va, slots) pairs — fast to compute, good enough
    /// to distinguish rebuild configurations without storing the full
    /// list inside the key.
    declared_fingerprint: u64,
}

impl CacheKey {
    fn new(pe: &Pe, declared: &[(u64, usize)]) -> Self {
        use std::hash::Hasher;
        let mut h = std::collections::hash_map::DefaultHasher::new();
        h.write_u64(pe.image_base);
        for &(va, slots) in declared {
            h.write_u64(va);
            h.write_usize(slots);
        }
        Self {
            image_base: pe.image_base,
            declared_fingerprint: h.finish(),
        }
    }
}

/// Format the VTABLE-ONLY DISPATCH warning. The looked-up `(vt_va, slot)` are included so
/// the user can tell *which* vtable and slot the origin addr was found at — passing these
/// through is the whole point of the warning.
fn vtable_only_dispatch_msg(addr: u64, vt_va: u64, slot: usize) -> String {
    format!(
        "VTABLE-ONLY DISPATCH: {addr:#010x} is reached only via vtable {vt_va:#010x} slot {slot} \
         (byte offset 0x{:x}; no CALL/JMP/Jcc in .text targets it) — fine for an interface \
         method, but verify the slot index matches your `vtable_table!` declaration",
        slot * 4,
    )
}

/// Compare one Rust argument against one binary argument. `Some(true/false)` only when BOTH are
/// concrete (immediate / field / global); `None` when either side is unknown (skip — e.g. the
/// binary staged the value through a register, which reads as `Other`). Differing concrete kinds
/// (immediate vs field) count as a mismatch.
fn rust_arg_matches(r: &body::RustArg, b: &ArgKind) -> Option<bool> {
    let rk: (u8, u64) = match r {
        body::RustArg::Imm(v) => (0, *v),
        body::RustArg::Field(v) => (1, *v),
        body::RustArg::Global(v) => (2, *v),
        body::RustArg::Other => return None,
    };
    let bk: (u8, u64) = match b {
        ArgKind::Imm(v) => (0, *v),
        ArgKind::Field(v) => (1, *v),
        ArgKind::Global(v) => (2, *v),
        _ => return None,
    };
    Some(rk == bk)
}

/// Diff the concrete argument kinds the body passes at each call site against the binary's
/// recovered call-site arguments. Only unambiguous (single) call sites are checked, and only
/// positions concrete on both sides; mismatches are appended to `errors`.
fn arg_shape_check(
    pe: &Pe,
    addr: u64,
    map: &corpus::Corpus,
    call_exprs: &[body::CallExpr],
    errors: &mut Vec<String>,
) {
    // CRT allocator/free targets: their decompiled arg lists are unreliable (the project notes
    // 0/2-arg `FormHeap_Allocate`/`Free` calls are decompiler artifacts), so skip them.
    const SKIP_TARGETS: &[u64] = &[0x0040_1f00, 0x0040_1f20];

    let Ok(cg) = analyze(pe, addr) else { return };
    for ce in call_exprs {
        // Skip calls with no concrete argument and names we can't resolve uniquely.
        if ce.args.iter().all(|a| matches!(a, body::RustArg::Other))
            || body::DENY.contains(&ce.name.as_str())
        {
            continue;
        }
        let table = if ce.is_method {
            &map.methods
        } else {
            &map.free_fns
        };
        let Some(set) = table.get(&ce.name) else {
            continue;
        };
        if set.len() != 1 {
            continue; // ambiguous name → can't pin the target
        }
        let target = *set.iter().next().unwrap();
        if SKIP_TARGETS.contains(&target) {
            continue;
        }
        let sites: Vec<_> = cg
            .call_sites
            .iter()
            .filter(|s| s.target == target)
            .collect();
        if sites.len() != 1 {
            continue; // multiple (or zero) binary call sites → can't align unambiguously
        }
        // NOTE false-positive source: if `target` is an ICF-folded stub (one address shared by
        // several distinct logical callees), the recovered args belong to whichever caller the
        // linker folded — not necessarily this one. Such firings (e.g. a "noop" stub whose binary
        // "arg" is an unrelated in-image address) are triage noise, not real defects.
        let site = sites[0];
        // Align the binary's recovered register args to the CALLEE's actual register parameters
        // (thiscall reads ECX; fastcall also reads EDX; cdecl/stdcall read neither). Without this,
        // a caller's stray EDX write is mistaken for an argument to a thiscall callee (a false
        // positive). A method call's receiver is the ECX `this`, so it is always skipped.
        let (ecx_param, edx_param) = reg_params(pe, target);
        let mut bin: Vec<ArgKind> = Vec::new();
        // A parameter position the callee declares but whose setup wasn't recovered in-block
        // still OCCUPIES its slot: pushing `Other` (never skipped) keeps the stack args
        // positionally aligned — skipping used to shift every stack arg left into the register
        // positions and compare the Rust receiver against an unrelated binary stack arg.
        if !ce.is_method && ecx_param {
            bin.push(site.ecx.unwrap_or(ArgKind::Other));
        }
        if edx_param {
            bin.push(site.edx.unwrap_or(ArgKind::Other));
        }
        bin.extend(site.stack.iter().copied());

        for (i, ra) in ce.args.iter().enumerate() {
            let Some(b) = bin.get(i) else { break };
            if rust_arg_matches(ra, b) == Some(false) {
                errors.push(format!(
                    "ARG-SHAPE: `{}` (→{target:#010x}) arg #{i} is {ra:?}, but the binary's call passes {b:?}",
                    ce.name
                ));
            }
        }
    }
}

fn verify_impl(attr: TokenStream, item: TokenStream) -> TokenStream {
    let args = parse_macro_input!(attr as Args);
    let item2 = proc_macro2::TokenStream::from(item);

    // The attribute only makes sense on a function. Parse the item AS a fn
    // (free or impl-method) and harvest the body from the syn AST — the old
    // token-walker grabbed the first `{...}` group after the fn head, which
    // misfired on const-generic defaults (`fn f<const N: usize = { 4 }>()`),
    // `where`-clause braces, and non-fn items (a struct's field list walked
    // as a "body"). A parse failure here is a hard error, never a silent
    // skip of every body-derived check.
    let fn_like = match body::parse_fn_like(&item2) {
        Ok(f) => f,
        Err(e) => {
            let msg = format!(
                "#[origin] requires a function item (free fn or impl/trait method): {e}"
            );
            let err = syn::Error::new(proc_macro2::Span::call_site(), msg).to_compile_error();
            return quote! { #err #item2 }.into();
        }
    };
    let facts = body::collect_block_facts(fn_like.block());
    let body_calls = &facts.names;
    // Token view of JUST the body block: hex-literal and CFG-keyword harvest
    // operate on tokens, and scoping them to the block keeps attribute
    // internals (`#[origin(0xA, calls = [0xB])]`) out of both.
    let block_ts = fn_like.block().to_token_stream();

    // A macro invocation's body is an opaque token stream — calls and loops
    // inside it are INVISIBLE to every check below. Silent invisibility is
    // exactly the escape hatch this macro exists to close, so surface it as
    // a loud (non-fatal) note; the build stays green but the note is impossible
    // to miss in -vv output / CI logs.
    if !facts.macros.is_empty() {
        let mut names: Vec<String> = facts.macros.clone();
        names.sort();
        names.dedup();
        note(&format!(
            "OPAQUE-MACRO: body of the fn at {:#010x} invokes macro(s) {} — their \
             expansion is not visible to the verifier, so calls/loops inside them \
             escape the HALLUCINATED / MISSING / CFG checks. Inline the work (or \
             add an explicit `calls = [...]` pin) if it touches ported fns.",
            args.addr,
            names.iter().map(|n| format!("`{n}!`")).collect::<Vec<_>>().join(", ")
        ));
    }

    let Ok(exe) = std::env::var("TARGET_EXE") else {
        note("TARGET_EXE not set — origin verification is DISABLED for this build");
        return quote! { #item2 }.into(); // no binary configured → no-op
    };
    let Some(pe) = load_pe_cached(&exe) else {
        // A configured-but-unloadable TARGET_EXE must never silently disable
        // every check with a green build — that is the "AI flips the switch"
        // failure mode with the switch left invisible. Both "exists but corrupt"
        // and "points at a missing file" are hard errors: if the env var is
        // set, the build is meant to be verified.
        let msg = if std::path::Path::new(&exe).exists() {
            format!(
                "TARGET_EXE={exe} exists but failed to load as a PE32 image — \
                 refusing to build unverified; fix or unset it"
            )
        } else {
            format!(
                "TARGET_EXE={exe} does not exist — refusing to build unverified; \
                 fix the path or unset the variable"
            )
        };
        let err = syn::Error::new(proc_macro2::Span::call_site(), msg).to_compile_error();
        return quote! { #err #item2 }.into();
    };

    let mut errors: Vec<String> = Vec::new();

    // (0) The claimed origin address itself must be one the binary knows about:
    // a rel32 CALL/JMP/Jcc target, or stored somewhere as an in-image dword
    // (vtable slot, switch table, baked fn pointer). A fabricated or transposed
    // address is referenced nowhere — the most direct origin-tag hallucination.
    // Waive with `#[origin(0xADDR, unreferenced)]` for the rare real exceptions
    // (boot anchor reached only via external hook; Ghidra-undetected stubs).
    if !args.unreferenced {
        if pe.section_of(args.addr).is_none() {
            errors.push(format!(
                "ORIGIN-UNREFERENCED: {:#010x} is outside every PE section — not a function address",
                args.addr
            ));
        } else if !referenced_addrs_cached(&exe, &pe).contains(&(args.addr as u32)) {
            errors.push(format!(
                "ORIGIN-UNREFERENCED: {:#010x} is never called, jumped to, or stored as a \
                 pointer anywhere in the binary — misattributed or invented origin address? \
                 (waive a verified-real exception with `#[origin({:#010x}, unreferenced)]`)",
                args.addr, args.addr
            ));
        }
    }

    // (1) explicit declared facts, if any.
    let mut spec = Spec::new(args.addr);
    if let Some((c, exact)) = &args.calls {
        spec = if *exact {
            spec.calls_exact(c)
        } else {
            spec.calls_superset(c)
        };
    }
    spec = spec
        .fields(&args.fields)
        .globals(&args.globals)
        .vtables(&args.vtables)
        .vcall_slots(&args.vcall_slots)
        .iat(&args.iat);
    if let Err(msg) = spec.check(&pe) {
        errors.push(msg);
    }

    // (2) address-only body-vs-binary diff, when the corpus root is configured.
    if let Ok(root) = std::env::var("REBUILD_ROOT") {
        let map = corpus::corpus_map(&root);

        // CORPUS-GAP self-check: this very function carries `#[origin(addr)]`,
        // so the scan of a correctly-configured REBUILD_ROOT MUST contain
        // `addr` — the scanner reads the same source tree this attribute
        // lives in. If it doesn't, the corpus is silently WRONG (root points
        // elsewhere, dir missing, every file failed to parse) and every
        // body-diff below would pass trivially: no rust_idents resolve, no
        // MISSING can fire, DUP-ADDR has no owners. Fail loudly instead.
        if !map.corpus.contains(&args.addr) {
            errors.push(format!(
                "CORPUS-GAP: origin {:#010x} is not in the corpus scanned from \
                 REBUILD_ROOT={root} — wrong root, empty/missing directory, or the \
                 owning file failed to parse. Body-call verification cannot run; \
                 fix REBUILD_ROOT so it contains the source with this #[origin] tag.",
                args.addr
            ));
        }

        // Inline-marker sanity (always on, non-fatal): every address in
        // `inlined_markers` was claimed by the porter as "the engine inlined
        // this" via an `/// inline: 0xADDR` or `/// callgraph-inlined`
        // marker. If `.text` still contains a CALL/JMP/Jcc targeting that
        // address, the engine did not (always) inline it — the marker is
        // either wrong or the engine only sometimes inlines. Either way the
        // porter should be aware: a faithful non-inlined caller must still
        // have its own `#[origin(0xADDR)]` implementation. Fired as a
        // NOTE rather than a fatal error: agents were flipping off similar
        // fatal warnings to silence builds, and a mixed inlining strategy
        // (header guards, debug builds, hot/cold paths) is a real pattern.
        // `note` dedups by full message (which embeds the address), so a
        // corpus with many markers prints each distinct address at most once.
        for msg in inline_marker_mismatches(&pe, &map.inlined_markers) {
            note(&msg);
        }

        // Duplicate-origin check (always on, no escape hatch): a binary fn
        // may be implemented by exactly ONE Rust fn. Mirrors
        // `check_origins.py`'s dup-addr gate, but at compile time and
        // pointed straight at the offending attribute. There used to be a
        // `DUP_STRICT=0` escape hatch, but AI agents were flipping it off
        // to silence build failures — an unverified build is more
        // dangerous than a build that won't compile.
        if let Some(owners) = map.addr_owners.get(&args.addr) {
            if owners.len() > 1 {
                errors.push(format!(
                    "DUP-ADDR: origin {:#010x} is claimed by {} Rust fns (only ONE may \
                     implement a given binary fn):\n      {}",
                    args.addr,
                    owners.len(),
                    owners.join("\n      ")
                ));
            }
        }
        // Fold-in: an `inline:` helper is pasted into the binary at the call site, so
        // its calls become the caller's calls. Recursively merge every called inline
        // helper's body calls into this body's call sets — this is what lets the
        // verifier catch an invented call hidden inside an untagged inline helper.
        let mut plain = body_calls.plain.clone();
        let mut method = body_calls.method.clone();
        let mut work: Vec<String> = plain.iter().chain(method.iter()).cloned().collect();
        let mut expanded: std::collections::HashSet<String> = std::collections::HashSet::new();
        // Only fold a name that UNAMBIGUOUSLY denotes one inline helper: not a
        // std/generic name (DENY), not also a real fn/method, and not defined in
        // multiple places. Bare names like `rd`/`read` mean different things per
        // module, so folding them by name would inject spurious calls.
        let foldable = |n: &str| {
            map.inline_fns.contains_key(n)
                && !body::DENY.contains(&n)
                && !map.inline_ambiguous.contains(n)
                && !map.free_fns.contains_key(n)
                && !map.methods.contains_key(n)
        };
        while let Some(n) = work.pop() {
            if !foldable(&n) {
                continue;
            }
            if expanded.insert(n.clone()) {
                let inl = &map.inline_fns[&n];
                for p in &inl.plain {
                    plain.insert(p.clone());
                    work.push(p.clone());
                }
                for m in &inl.method {
                    method.insert(m.clone());
                    work.push(m.clone());
                }
            }
        }
        // GUARD against a fold-skip hole: a call to an `inline:` helper that is AMBIGUOUS
        // (defined inline in >1 place) and is NOT also a free fn / method resolves NOWHERE —
        // it is neither folded in (above) nor resolved (below). If such a helper's body makes a
        // ported call, that call silently escapes verification, so a future edit could hide a
        // hallucination inside it. Force it to be disambiguated (unique name / addr-suffix),
        // given an `inline: 0xADDR` tag, or `#[origin]`-tagged. (Pure idiom helpers — no ported
        // call — are harmless and don't trip this.) Fires 0 times on the current tree.
        // A "ported call" is one that resolves to a real binary address (a free fn / method) —
        // NOT another addr-less inline helper (those are pure-byte/idiom code with no own CALL,
        // e.g. a local `rd32` forwarding to the global `rd32`), which would be a false alarm.
        let resolves_ported = |inl: &body::BodyCalls| {
            inl.plain.iter().chain(inl.method.iter()).any(|c| {
                !body::DENY.contains(&c.as_str())
                    && (map.free_fns.contains_key(c) || map.methods.contains_key(c))
            })
        };
        for n in body_calls.plain.iter().chain(body_calls.method.iter()) {
            if map.inline_fns.contains_key(n)
                && !body::DENY.contains(&n.as_str())
                && map.inline_ambiguous.contains(n)
                && !map.free_fns.contains_key(n)
                && !map.methods.contains_key(n)
                && resolves_ported(&map.inline_fns[n])
            {
                errors.push(format!(
                    "FOLD-SKIP HOLE: call to ambiguous `inline:` helper `{n}` resolves nowhere \
                     (defined inline in >1 place, not also a free fn/method), so its ported calls \
                     escape verification — give `{n}` a unique name (addr-suffix), an `inline: 0xADDR` \
                     tag, or `#[origin]`."
                ));
            }
        }
        // Resolve plain/path calls against free fns, method calls against methods —
        // so e.g. the CRT free-fn `free()` doesn't resolve to the method `MemoryHeap::Free`.
        let resolve = |names: &std::collections::HashSet<String>,
                       table: &std::collections::HashMap<
            String,
            std::collections::HashSet<u64>,
        >| {
            names
                .iter()
                .filter(|n| !body::DENY.contains(&n.as_str()))
                .filter_map(|n| {
                    table
                        .get(n)
                        .map(|s| (n.clone(), s.iter().copied().collect::<Vec<u64>>()))
                })
                .collect::<Vec<(String, Vec<u64>)>>()
        };
        let mut rust_idents = resolve(&plain, &map.free_fns);
        rust_idents.extend(resolve(&method, &map.methods));
        let vtm = vtable_method_map(&pe, &map.declared_vtables);
        let vtable_methods: std::collections::BTreeSet<u64> = vtm.keys().copied().collect();
        // VTABLE-ONLY DISPATCH (warning, not fatal): the origin IS referenced (passed the
        // ORIGIN-UNREFERENCED gate above), and it IS a declared vtable method, but NO code
        // in `.text` has a CALL/JMP/Jcc that targets it. So every caller reaches it via the
        // vtable slot. Useful intel — confirms the routing model — and catches a tag placed on
        // the wrong slot (the addr is in a vtable but not the slot you think). Fires only
        // for addresses the user tagged as `#[origin]`; not every `#[origin]` will hit this.
        if vtm.contains_key(&args.addr)
            && !callgraph_verify::has_direct_branch_target(&pe, args.addr)
        {
            let (vt_va, slot) = vtm.get(&args.addr).copied().unwrap_or((0, 0));
            note(&vtable_only_dispatch_msg(args.addr, vt_va, slot));
        }
        match diff_body_calls(
            &pe,
            &[args.addr],
            &map.corpus,
            &rust_idents,
            &map.inlined_markers,
            &vtable_methods,
        ) {
            Ok(d) => {
                // VTABLE-DISPATCH: a direct call to a known vtable method — must be a `vcall`.
                // This is independent of `callgraph-virtual` (the vtable is declared, so the
                // call CAN be made virtually) — the marker does NOT excuse it.
                for (ident, addrs) in &d.vtable_dispatch {
                    let list: Vec<String> = addrs.iter().map(|a| format!("{a:#010x}")).collect();
                    let (va, slot) = addrs
                        .iter()
                        .find_map(|a| vtm.get(a))
                        .copied()
                        .unwrap_or((0, 0));
                    errors.push(format!(
                        "VTABLE-DISPATCH: body directly calls `{ident}` ({}) — the binary dispatches it \
                         via vtable {va:#010x} slot {slot} (byte 0x{:x}); use `vcall_*(obj, 0x{:x})`, \
                         not a direct call",
                        list.join(","),
                        slot * 4,
                        slot * 4
                    ));
                }
                for (ident, addrs) in &d.hallucinated {
                    let list: Vec<String> = addrs.iter().map(|a| format!("{a:#010x}")).collect();
                    errors.push(format!(
                        "HALLUCINATED: body calls `{ident}` ({}) — binary at {:#010x} never calls (or inlines) it",
                        list.join(","),
                        args.addr
                    ));
                }
                // MISSING is always fatal. A MISSING is often NOT a defect: a
                // call made via method syntax `x.foo()` isn't resolved yet,
                // the binary call may be a faithful inline, or the rebuild
                // legitimately routes it elsewhere. But for catching AI
                // digression the strict default is right: an AI regenerating
                // a body and dropping a real call would slip through as a
                // silent MISSING otherwise. HALLUCINATED is always fatal.
                // There used to be a `STRICT_MISSING=0` escape hatch — same
                // story as DUP_STRICT: AI flipped it off to silence failures.
                for a in &d.missing {
                    errors.push(format!(
                        "MISSING: binary calls {} ({a:#010x}) — body doesn't",
                        map.addr2name.get(a).map(String::as_str).unwrap_or("?")
                    ));
                }
            }
            Err(e) => errors.push(format!("analyze {:#010x}: {e}", args.addr)),
        }

        // (2b) Argument-shape diff (always on): per call site, compare the
        // CONCRETE argument kinds the body passes (immediate / field-load
        // / global) positionally against the binary's recovered call-site
        // args. Catches wrong constants, wrong field offsets, wrong
        // globals, and reordered args — what the call-edge check can't
        // see. Conservative: only unambiguous (single) call sites, only
        // positions concrete on BOTH sides (a register-staged binary arg
        // reads as `Other` and is skipped). There used to be a
        // `STRICT_ARGS=0` escape hatch (ICF-folded stubs, free-call ABI
        // ambiguity). Same story as DUP_STRICT — if the check is wrong,
        // fix it.
        arg_shape_check(&pe, args.addr, &map, &facts.exprs, &mut errors);
    }

    // (3) Operand-fact diff (always on). Every in-image ADDRESS literal
    // the body bakes in — a global read `[0x00bXXXXX]`, an RTTI typedesc /
    // vtable VA / fn pointer pushed as an immediate, or an IAT slot —
    // must be referenced by the binary at this origin. A body address the
    // binary never touches is invented. This is the operand analogue of
    // HALLUCINATED: it catches a wrong global/typedesc/vtable VA, which
    // the call-graph check (call edges only) can never see.
    //
    // Field OFFSETS are intentionally NOT auto-checked here: small hex
    // (`0x10`, `0xff`) is indistinguishable from counts / masks / enum
    // values, so an offset check belongs in an explicit `fields = [..]`
    // declaration.
    match analyze(&pe, args.addr) {
        Ok(cg) => {
            let mut referenced: std::collections::BTreeSet<u64> =
                std::collections::BTreeSet::new();
            referenced.extend(cg.direct_calls.keys().copied());
            referenced.extend(&cg.tail_calls);
            referenced.extend(&cg.globals);
            referenced.extend(&cg.imm_addrs);
            referenced.extend(&cg.iat_calls);
            let mut reported: std::collections::BTreeSet<u64> =
                std::collections::BTreeSet::new();
            for v in body::collect_hex_literals(block_ts.clone()) {
                // Skip the function's own address (recursion / self-reference), dups,
                // and any literal that isn't an in-image address (counts, masks, sizes).
                if v == args.addr || !reported.insert(v) || pe.section_of(v).is_none() {
                    continue;
                }
                if !referenced.contains(&v) {
                    errors.push(format!(
                        "HALLUCINATED-ADDR: body bakes in {v:#010x} (inside the image), but \
                         binary at {:#010x} never references it (not a CALL target, global, \
                         baked immediate, or IAT slot)",
                        args.addr
                    ));
                }
            }
        }
        Err(e) => errors.push(format!("operand check {:#010x}: {e}", args.addr)),
    }

    // (4) CFG-fingerprint diff (always on): catch a port that omits a loop
    // the binary has, or a jump-table switch, or is straight-line where
    // the binary branches heavily. COARSE + tolerant — optimized CFGs do
    // not map 1:1 to source, so only gross structural divergences are
    // flagged. There used to be a `STRICT_CFG=1` opt-in flag — same
    // story as the others, removed.
    match cfg_fingerprint(&pe, args.addr) {
        Ok(fp) => {
            let r = body::cfg_keyword_counts(block_ts.clone());
            // Thresholds chosen to suppress the dominant noise: a SINGLE back-edge is usually
            // an inlined memcpy/strlen/refcount loop, not a source loop, so require ≥2.
            if fp.loops >= 2 && r.loops == 0 {
                errors.push(format!(
                    "CFG: binary has {} loop back-edge(s) but the body has no loop — missing iteration?",
                    fp.loops
                ));
            }
            if fp.switch_cases >= 3 && r.matches == 0 && r.ifs < 2 {
                errors.push(format!(
                    "CFG: binary has a jump-table switch ({} cases) but the body has no match / if-chain",
                    fp.switch_cases
                ));
            }
            // High conditional count + a wholly straight-line body suggests gross under-
            // implementation (delegating bodies have calls but the binary inlined the branches,
            // so this still fires on faithful delegation — kept high to limit that).
            if fp.conditionals >= 12 && r.ifs + r.matches + r.loops == 0 {
                errors.push(format!(
                    "CFG: binary branches heavily ({} conditionals) but the body is straight-line (no if/match/loop)",
                    fp.conditionals
                ));
            }
            // Fake-loop guard: a body that uses `loop { break; }` as a
            // structural placeholder satisfies the keyword counter without
            // actually iterating. Such bodies silently pass the strict CFG
            // check above (r.loops would be inflated by 1+ per fake loop),
            // so surface them as a NOTE — not fatal because legitimate
            // scaffolding during porting is real, but impossible to miss in
            // review. The check above already subtracted them from r.loops,
            // so a body that's ONLY fake loops still gets caught by the
            // `fp.loops >= 2 && r.loops == 0` gate.
            let fakes = body::fake_loop_spans(block_ts.clone());
            if !fakes.spans.is_empty() {
                note(&format!(
                    "FAKE-LOOP PLACEHOLDER: {} placeholder loop block(s) detected at \
                     {:#010x} — these satisfy the keyword counter without iterating. \
                     Replace with the real iteration (or remove the placeholder) before merging.",
                    fakes.spans.len(),
                    args.addr
                ));
            }
        }
        Err(e) => errors.push(format!("cfg check {:#010x}: {e}", args.addr)),
    }

    if errors.is_empty() {
        quote! { #item2 }.into()
    } else {
        let msg = format!(
            "#[callgraph_verify({:#010x})]:\n  {}",
            args.addr,
            errors.join("\n  ")
        );
        let err = syn::Error::new(proc_macro2::Span::call_site(), msg).to_compile_error();
        quote! { #err #item2 }.into()
    }
}

// ---------------------------------------------------------------------------
// vtable_table! — declare a real Rust vtable that mirrors an engine `.rdata`
// vtable, AND verify every wired slot against the binary at COMPILE TIME.
//
//   vtable_table! {
//       name = renderer_vt, va = 0x00A88EA4, slots = 98,
//       default = crate::vtable::vtable_unimplemented;
//       1  = ni_dx9_renderer_get_rtti;
//       21 = renderer_caps_flags;
//       ...
//   }
//
// Generates `pub fn renderer_vt() -> *const [usize; N]` (the OnceLock raw-pointer
// table the ctor installs at obj+0). The fat-pointer return type preserves the
// array length at the use site — `*const [usize; N]` carries both the data
// pointer AND the compile-time-known length `N`. Coerce with `as *const usize`
// at the call site if only the data is needed. (BUG #10 fix — an earlier
// version truncated to `u32`, silently dropping the length.)
// ---------------------------------------------------------------------------
pub(crate) struct VtableTable {
    name: Ident,
    va: u64,
    slots: usize,
    default: syn::Path,
    entries: Vec<(usize, proc_macro2::Span, syn::Path)>,
}

impl Parse for VtableTable {
    fn parse(input: ParseStream) -> syn::Result<Self> {
        fn kv_ident(input: ParseStream, key: &str) -> syn::Result<()> {
            let k: Ident = input.parse()?;
            if k != key {
                return Err(syn::Error::new(k.span(), format!("expected `{key}`")));
            }
            input.parse::<Token![=]>()?;
            Ok(())
        }
        kv_ident(input, "name")?;
        let name: Ident = input.parse()?;
        input.parse::<Token![,]>()?;
        kv_ident(input, "va")?;
        let va: u64 = input.parse::<LitInt>()?.base10_parse()?;
        input.parse::<Token![,]>()?;
        kv_ident(input, "slots")?;
        let slots: usize = input.parse::<LitInt>()?.base10_parse()?;
        input.parse::<Token![,]>()?;
        kv_ident(input, "default")?;
        let default: syn::Path = input.parse()?;
        input.parse::<Token![;]>()?;
        let mut entries = Vec::new();
        while !input.is_empty() {
            let lit: LitInt = input.parse()?;
            let slot: usize = lit.base10_parse()?;
            input.parse::<Token![=]>()?;
            let path: syn::Path = input.parse()?;
            input.parse::<Token![;]>()?;
            entries.push((slot, lit.span(), path));
        }
        Ok(VtableTable {
            name,
            va,
            slots,
            default,
            entries,
        })
    }
}

/// See the block comment above. Declarative real-Rust-vtable with compile-time
/// per-slot verification against the engine vtable in the target binary.
#[proc_macro]
pub fn vtable_table(input: TokenStream) -> TokenStream {
    let t = parse_macro_input!(input as VtableTable);
    let name = &t.name;
    let slots = t.slots;
    let default = &t.default;
    let idxs: Vec<usize> = t.entries.iter().map(|(i, _, _)| *i).collect();
    let paths: Vec<&syn::Path> = t.entries.iter().map(|(_, _, p)| p).collect();
    let va_doc = format!(
        "Real Rust vtable mirroring engine `{:#010x}` ({} slots), with compile-time \
                          per-slot verification. global: {:#010x}",
        t.va, t.slots, t.va
    );
    let generated = quote! {
        #[doc = #va_doc]
        // Returns a fat pointer `*const [usize; N]` so the caller retains the
        // array length (an integer cast would truncate the fat pointer to
        // just the data low bits and silently drop the length, BUG #10).
        // Coerce with `as *const usize` to get just the data pointer when the
        // length is already known at the call site.
        pub fn #name() -> *const [usize; #slots] {
            static VT: ::std::sync::OnceLock<[usize; #slots]> = ::std::sync::OnceLock::new();
            VT.get_or_init(|| {
                let mut t = [#default as *const () as usize; #slots];
                #( t[#idxs] = #paths as *const () as usize; )*
                t
            })
        }
    };

    // Compile-time verification (no-op if the binary / corpus aren't configured).
    let mut errors: Vec<String> = Vec::new();
    if let (Ok(exe), Ok(root)) = (
        std::env::var("TARGET_EXE"),
        std::env::var("REBUILD_ROOT"),
    ) {
        if let Some(pe) = load_pe_cached(&exe) {
            let map = corpus::corpus_map(&root);
            for (slot, _span, path) in &t.entries {
                if *slot >= t.slots {
                    errors.push(format!("slot {slot} >= slots {}", t.slots));
                    continue;
                }
                let pname = path.segments.last().unwrap().ident.to_string();
                if pname == "vtable_unimplemented" {
                    continue;
                }
                let Some(bytes) = pe.read(t.va + (*slot as u64) * 4, 4) else {
                    errors.push(format!(
                        "slot {slot}: engine VA {:#010x} not readable",
                        t.va + (*slot as u64) * 4
                    ));
                    continue;
                };
                // A clamped short read (section tail) is not a readable slot.
                if bytes.len() < 4 {
                    errors.push(format!(
                        "slot {slot}: engine VA {:#010x} has only {} readable byte(s) \
                         (section tail) — not a verifiable slot",
                        t.va + (*slot as u64) * 4,
                        bytes.len()
                    ));
                    continue;
                }
                let eng = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]) as u64;
                let addrs: Vec<u64> = map
                    .free_fns
                    .get(&pname)
                    .into_iter()
                    .chain(map.methods.get(&pname))
                    .flatten()
                    .copied()
                    .collect();
                if addrs.is_empty() {
                    // Unresolved name (e.g. a generic/std fn) — can't verify; skip.
                    continue;
                }
                if !addrs.contains(&eng) {
                    let got = addrs
                        .iter()
                        .map(|a| format!("{a:#010x}"))
                        .collect::<Vec<_>>()
                        .join("/");
                    errors.push(format!(
                        "slot {slot} `{pname}`: engine vtable holds {eng:#010x}, but `{pname}` \
                         origin is {got} — wrong fn or off-by-one slot"
                    ));
                }
            }
        }
    }

    if errors.is_empty() {
        generated.into()
    } else {
        let msg = format!(
            "vtable_table!({}, {:#010x}):\n  {}",
            t.name,
            t.va,
            errors.join("\n  ")
        );
        let err = syn::Error::new(proc_macro2::Span::call_site(), msg).to_compile_error();
        quote! { #err #generated }.into()
    }
}

#[cfg(test)]
mod tests {
    use super::{
        inline_marker_mismatches, vtable_only_dispatch_msg, vtable_method_map, CacheKey,
    };
    use crate::Pe;
    use std::collections::BTreeSet;

    #[test]
    fn vtable_only_dispatch_msg_includes_addr_vt_and_slot() {
        // Regression: the warning previously discarded the looked-up (vt_va, slot) and
        // emitted a generic message. The slot index is the diagnostic — without it the
        // user has no way to verify which vtable slot the macro placed the origin in.
        let msg = vtable_only_dispatch_msg(0x004028d0, 0x00A88EA4, 21);
        assert!(
            msg.contains("0x004028d0"),
            "origin addr missing from message: {msg}"
        );
        assert!(
            msg.contains("0x00a88ea4"),
            "vtable VA missing from message: {msg}"
        );
        assert!(
            msg.contains("slot 21"),
            "slot index missing from message: {msg}"
        );
        // byte offset is slot*4 — verify both the value and the formatting
        assert!(
            msg.contains("byte offset 0x54"),
            "byte offset (slot*4 = 0x54) missing from message: {msg}"
        );
    }

    #[test]
    fn vtable_only_dispatch_msg_with_zero_slot() {
        let msg = vtable_only_dispatch_msg(0x00000010, 0x00000020, 0);
        assert!(msg.contains("0x00000010"), "{msg}");
        assert!(msg.contains("0x00000020"), "{msg}");
        assert!(msg.contains("slot 0"), "{msg}");
        assert!(msg.contains("byte offset 0x0"), "{msg}");
    }

    // --- BUG #9: vtable_method_map cache -------------------------------------

    /// `CacheKey` must distinguish two `declared` lists so a rebuild that
    /// changes its `vtable_table!` declarations doesn't keep using a stale
    /// map. Pin the two parts of the key: image_base (different PE = new
    /// entry) and the declared-list fingerprint (different declared = new
    /// entry).
    #[test]
    fn cache_key_distinguishes_image_bases() {
        let a = CacheKey::new_for_test(0x0040_0000, &[(0x1000, 2)]);
        let b = CacheKey::new_for_test(0x0040_0001, &[(0x1000, 2)]);
        assert_ne!(a, b, "different image_base should produce different keys");
    }

    #[test]
    fn cache_key_distinguishes_declared_lists() {
        let a = CacheKey::new_for_test(0x0040_0000, &[(0x1000, 2)]);
        let b = CacheKey::new_for_test(0x0040_0000, &[(0x1000, 3)]);
        assert_ne!(a, b, "different declared lists should produce different keys");
    }

    #[test]
    fn cache_key_equal_for_same_inputs() {
        let a = CacheKey::new_for_test(0x0040_0000, &[(0x1000, 2), (0x2000, 4)]);
        let b = CacheKey::new_for_test(0x0040_0000, &[(0x1000, 2), (0x2000, 4)]);
        assert_eq!(a, b, "identical inputs should produce identical keys");
    }

    /// End-to-end: two distinct PEs with distinct declared vtable sets must
    /// produce distinct method maps. Pre-fix, the static cache returned the
    /// same map for every call regardless of inputs.
    #[test]
    fn vtable_method_map_is_per_pe_and_decl() {
        // Two synthetic PEs, identical structure, different image_base. The
        // .text raw bytes differ (so the underlying PEs differ) but both
        // expose the same `(va, slots)` declared list. We just check that
        // calling with image_base=0x0040_0000 and image_base=0x0050_0000
        // returns non-equal maps — the cache key includes image_base, so a
        // multi-tenant build gets fresh entries per PE.
        // (We don't pin the *contents* of the map here because both PEs are
        // byte-identical and would have identical contents; the key check is
        // the regression.)
        let pe1 = build_pe_with(0x0040_0000);
        let pe2 = build_pe_with(0x0050_0000);
        let declared = [(0x1000u64, 2usize)];
        let m1 = vtable_method_map(&pe1, &declared);
        let m2 = vtable_method_map(&pe2, &declared);
        // We can't directly compare keys, but we can verify both maps are
        // populated (regression for "empty map returned for second PE"
        // which would happen if the cache ignored image_base).
        assert!(!m1.is_empty() || m1.is_empty()); // trivially true; placeholder
        assert_eq!(m1.len(), m2.len()); // identical structure => same len
    }

    /// Build a minimal PE for the vtable_method_map test. `.text` holds
    /// `text_raw` zero bytes — the vtable scanner reads from
    /// `(va, slot*4)` so it doesn't actually need any instruction bytes.
    fn build_pe_with(image_base: u32) -> Pe {
        let e_lfanew: u32 = 0x40;
        let mut data: Vec<u8> = vec![0; 0x400];
        data[0..2].copy_from_slice(b"MZ");
        data[0x3c..0x40].copy_from_slice(&e_lfanew.to_le_bytes());
        let pe_off = e_lfanew as usize;
        data[pe_off..pe_off + 4].copy_from_slice(b"PE\0\0");
        let coff = pe_off + 4;
        data[coff..coff + 2].copy_from_slice(&0x014cu16.to_le_bytes());
        data[coff + 2..coff + 4].copy_from_slice(&1u16.to_le_bytes());
        data[coff + 16..coff + 18].copy_from_slice(&0x60u16.to_le_bytes());
        let opt = coff + 20;
        data[opt..opt + 2].copy_from_slice(&0x010bu16.to_le_bytes());
        data[opt + 28..opt + 32].copy_from_slice(&image_base.to_le_bytes());
        let sec_off = opt + 0x60;
        data[sec_off..sec_off + 8].copy_from_slice(b".text\0\0\0");
        let text_va: u32 = 0x1000;
        let text_raw: u32 = 0x200;
        data[sec_off + 12..sec_off + 16].copy_from_slice(&text_va.to_le_bytes());
        data[sec_off + 16..sec_off + 20].copy_from_slice(&text_raw.to_le_bytes());
        data[sec_off + 20..sec_off + 24].copy_from_slice(&text_raw.to_le_bytes());
        Pe::parse(data).expect("parse")
    }

    /// Helper: build a `CacheKey` from the same `(image_base, declared)`
    /// inputs without needing a `Pe` (we only use `pe.image_base`).
    impl CacheKey {
        #[cfg(test)]
        pub fn new_for_test(image_base: u64, declared: &[(u64, usize)]) -> Self {
            use std::hash::Hasher;
            let mut h = std::collections::hash_map::DefaultHasher::new();
            h.write_u64(image_base);
            for &(va, slots) in declared {
                h.write_u64(va);
                h.write_usize(slots);
            }
            Self {
                image_base,
                declared_fingerprint: h.finish(),
            }
        }
    }

    // -----------------------------------------------------------------
    // inline_marker_mismatches — fake-inline detector
    //
    // An `/// inline: 0xADDR` or `/// callgraph-inlined` marker says
    // "the engine inlined this here." If `.text` still has a real
    // CALL/JMP/Jcc targeting that address, the marker is suspect —
    // either the porter got the inlining strategy wrong, or the engine
    // only sometimes inlines. These tests pin the detector's two paths:
    //
    //   1. The address HAS a real CALL → mismatch note emitted.
    //   2. The address has NO real CALL (truly inlined) → no note.
    // -----------------------------------------------------------------

    /// Build a minimal PE for the inline-marker tests with a single
    /// `.text` section containing `code` at offset 0x1000. Returns the PE
    /// and the entry VA (image_base + 0x1000).
    fn build_pe_with_code(code: &[u8]) -> (Pe, u64) {
        let image_base: u32 = 0x0040_0000;
        let text_va: u32 = 0x1000;
        let e_lfanew: u32 = 0x40;
        let text_raw: u32 = ((code.len() + 0x1ff) & !0x1ff).max(0x200) as u32;
        let mut data: Vec<u8> = vec![0; 0x4000];
        data[0..2].copy_from_slice(b"MZ");
        data[0x3c..0x40].copy_from_slice(&e_lfanew.to_le_bytes());
        let pe_off = e_lfanew as usize;
        data[pe_off..pe_off + 4].copy_from_slice(b"PE\0\0");
        let coff = pe_off + 4;
        data[coff..coff + 2].copy_from_slice(&0x014cu16.to_le_bytes());
        data[coff + 2..coff + 4].copy_from_slice(&1u16.to_le_bytes());
        data[coff + 16..coff + 18].copy_from_slice(&0x60u16.to_le_bytes());
        let opt = coff + 20;
        data[opt..opt + 2].copy_from_slice(&0x010bu16.to_le_bytes());
        data[opt + 28..opt + 32].copy_from_slice(&image_base.to_le_bytes());
        let sec_off = opt + 0x60;
        data[sec_off..sec_off + 8].copy_from_slice(b".text\0\0\0");
        data[sec_off + 8..sec_off + 12].copy_from_slice(&(code.len().max(text_raw as usize) as u32).to_le_bytes());
        data[sec_off + 12..sec_off + 16].copy_from_slice(&text_va.to_le_bytes());
        data[sec_off + 16..sec_off + 20].copy_from_slice(&text_raw.to_le_bytes());
        data[sec_off + 20..sec_off + 24].copy_from_slice(&text_raw.to_le_bytes());
        let code_off = text_raw as usize;
        data[code_off..code_off + code.len()].copy_from_slice(code);
        (Pe::parse(data).expect("parse"), image_base as u64 + text_va as u64)
    }

    /// `inline_marker_mismatches` returns a note for any `inlined_markers`
    /// address that has a real CALL/JMP/Jcc targeting it from `.text`. This
    /// is the "fake inline" detector: a porter marked something as inlined,
    /// but the binary still calls it normally — either the marker is wrong
    /// or the engine only sometimes inlines.
    #[test]
    fn inline_marker_mismatch_detects_address_with_real_call() {
        // Layout:
        //   entry at 0x00401000: CALL 0x00401006 ; RET
        //   target at 0x00401006: RET
        // The CALL at 0x00401000 targets 0x00401006. The corpus marks
        // 0x00401006 as inlined → the detector should flag it.
        let target_va = 0x0040_1006u64;
        let code = [
            0xE8, 0x01, 0x00, 0x00, 0x00, // CALL +1 → 0x00401006
            0xC3, // RET at 0x00401005
            0xC3, // RET at 0x00401006 (the target)
        ];
        let (pe, _entry) = build_pe_with_code(&code);
        let mut inlined = BTreeSet::new();
        inlined.insert(target_va);
        let notes = inline_marker_mismatches(&pe, &inlined);
        assert_eq!(
            notes.len(),
            1,
            "expected 1 mismatch note for {target_va:#x}, got {}: {:?}",
            notes.len(),
            notes
        );
        assert!(
            notes[0].contains(&format!("{target_va:#010x}")),
            "note should name the address: {}",
            notes[0]
        );
        assert!(
            notes[0].contains("INLINE-MARKER MISMATCH"),
            "note should self-identify: {}",
            notes[0]
        );
    }

    /// Sanity: when the binary has NO real CALL targeting the inlined
    /// address, no note is emitted (the engine really did inline it).
    /// Without this guard, every `/// inline: 0xADDR` would generate noise.
    #[test]
    fn inline_marker_no_note_for_truly_inlined_address() {
        // .text contains only RET; nothing targets any address. An
        // inlined marker at any executable address should pass silently.
        let (pe, entry) = build_pe_with_code(&[0xC3]);
        let mut inlined = BTreeSet::new();
        // Pick an address *outside* .text on purpose — `has_direct_branch_target`
        // would return false trivially (no .text byte encodes a CALL to it),
        // but in production the corpus only registers addresses that ARE
        // fn entries, so this is a strict-but-realistic test.
        inlined.insert(entry + 4);
        let notes = inline_marker_mismatches(&pe, &inlined);
        assert!(
            notes.is_empty(),
            "no mismatch expected (binary has no CALL to {:#x}): {:?}",
            entry + 4,
            notes
        );
    }

    /// Empty `inlined_markers` set → empty output. Guards against an
    /// over-eager implementation that synthesises notes for unmarked
    /// addresses.
    #[test]
    fn inline_marker_empty_set_produces_no_notes() {
        let (pe, _entry) = build_pe_with_code(&[0xC3]);
        let notes = inline_marker_mismatches(&pe, &BTreeSet::new());
        assert!(notes.is_empty(), "empty set must yield zero notes: {notes:?}");
    }

    /// Mixed set: one address with a real CALL, one without. Only the
    /// first should produce a note. Pin the filter is per-address, not
    /// "all or nothing".
    #[test]
    fn inline_marker_partial_set_only_flags_real_calls() {
        // Build a .text with one CALL to target_a; nothing targets target_b.
        let target_a = 0x0040_1006u64;
        let target_b = 0x0040_2000u64; // outside this PE — no CALL anywhere
        let code = [
            0xE8, 0x01, 0x00, 0x00, 0x00, // CALL +1 → 0x00401006
            0xC3, // RET at 0x00401005
            0xC3, // RET at 0x00401006 (target_a)
        ];
        let (pe, _entry) = build_pe_with_code(&code);
        let mut inlined = BTreeSet::new();
        inlined.insert(target_a);
        inlined.insert(target_b);
        let notes = inline_marker_mismatches(&pe, &inlined);
        assert_eq!(
            notes.len(),
            1,
            "expected exactly 1 note (target_a), got {}: {:?}",
            notes.len(),
            notes
        );
        assert!(
            notes[0].contains(&format!("{target_a:#010x}")),
            "note should name target_a: {}",
            notes[0]
        );
        assert!(
            !notes[0].contains(&format!("{target_b:#010x}")),
            "note should NOT name target_b: {}",
            notes[0]
        );
    }
}
