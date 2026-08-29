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
//!   * `STRICT_OPERANDS` — ON by default: diff the in-image ADDRESS literals
//!     the body bakes in (globals, RTTI typedescs, vtable VAs, fn pointers)
//!     against the binary's referenced-address set. A body address the
//!     binary never touches → `HALLUCINATED-ADDR`. Set to `0` to disable
//!     (the rebuild reads some globals directly that the original reaches
//!     through an accessor, so it can false-positive tree-wide).
//!   * `STRICT_ARGS`    — ON by default: per call site, diff the CONCRETE
//!     argument kinds the body passes (immediate / field-load / global)
//!     positionally against the binary's recovered call-site args → `ARG-SHAPE`.
//!     Catches wrong constants / field offsets / globals / reordering.
//!     Set to `0` to disable — false positives to triage: ICF-folded stubs
//!     (one address, heterogeneous callers) and convention-ambiguous free calls.
//!   * `STRICT_MISSING` — ON by default: make `MISSING` (binary calls something
//!     the body doesn't) fatal. Often a faithful inline, but for catching AI
//!     digression this is the stricter gate. Set to `0` to make non-fatal.
//!   * `DUP_STRICT`     — ON by default: a binary fn may be implemented by
//!     exactly ONE Rust fn. Multiple `#[origin]` claims on the same address
//!     are fatal at compile time. Set to `0` to disable.
//!   * `STRICT_CFG`     — opt-in: coarse control-flow fingerprint diff →
//!     `CFG`. Flags a body that omits a loop the binary has, omits a
//!     many-case jump-table switch, or is straight-line where the binary
//!     branches heavily. Tolerant + DIAGNOSTIC (unrolling / switch-as-if-chain
//!     / inlining cause noise); OFF by default.

use proc_macro::TokenStream;
use quote::quote;
use std::collections::HashMap;
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

fn load_pe_cached(path: &str) -> Option<Arc<Pe>> {
    static CACHE: OnceLock<Mutex<HashMap<String, Option<Arc<Pe>>>>> = OnceLock::new();
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
/// byte offset). Built once per compiler process (~one linear pass over the 8 MB
/// image); used by the ORIGIN-UNREFERENCED check. See `Pe::referenced_addrs`.
fn referenced_addrs_cached(pe: &Pe) -> &'static std::collections::HashSet<u32> {
    static SET: OnceLock<std::collections::HashSet<u32>> = OnceLock::new();
    SET.get_or_init(|| pe.referenced_addrs())
}

/// One-time stderr note when verification is silently disabled, so a bad
/// `TARGET_EXE` path can't masquerade as a clean build forever.
fn warn_once(msg: &str) {
    static DONE: OnceLock<()> = OnceLock::new();
    DONE.get_or_init(|| {
        eprintln!("callgraph_verify_macro: {msg}");
    });
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
/// the binary actually dispatches virtually. Built once per process.
fn vtable_method_map(pe: &Pe, declared: &[(u64, usize)]) -> &'static HashMap<u64, (u64, usize)> {
    static M: OnceLock<HashMap<u64, (u64, usize)>> = OnceLock::new();
    M.get_or_init(|| {
        let mut m = HashMap::new();
        for &(va, slots) in declared {
            for slot in 0..slots {
                if let Some(b) = pe.read(va + (slot as u64) * 4, 4) {
                    let a = u32::from_le_bytes([b[0], b[1], b[2], b[3]]) as u64;
                    if a != 0 {
                        m.entry(a).or_insert((va, slot));
                    }
                }
            }
        }
        m
    })
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
    item: proc_macro2::TokenStream,
    errors: &mut Vec<String>,
) {
    // CRT allocator/free targets: their decompiled arg lists are unreliable (the project notes
    // 0/2-arg `FormHeap_Allocate`/`Free` calls are decompiler artifacts), so skip them.
    const SKIP_TARGETS: &[u64] = &[0x0040_1f00, 0x0040_1f20];

    let Ok(cg) = analyze(pe, addr) else { return };
    for ce in body::collect_call_exprs(item) {
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
        if !ce.is_method && ecx_param {
            if let Some(a) = site.ecx {
                bin.push(a);
            }
        }
        if edx_param {
            if let Some(a) = site.edx {
                bin.push(a);
            }
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

/// Read a strictness flag from the environment. Returns `default` if unset,
/// returns `false` if set to "0" / "false" / "no" / "off" (case-insensitive),
/// otherwise `true`. Lets strict gates be flipped OFF explicitly without
/// requiring the variable to be set for the strict path.
fn env_flag(name: &str, default: bool) -> bool {
    match std::env::var(name).ok().as_deref() {
        None => default,
        Some(v) => !matches!(v.to_ascii_lowercase().as_str(), "0" | "false" | "no" | "off" | ""),
    }
}

fn verify_impl(attr: TokenStream, item: TokenStream) -> TokenStream {
    let args = parse_macro_input!(attr as Args);
    let body_calls = body::collect_call_idents(item.clone().into());
    let item2 = proc_macro2::TokenStream::from(item);

    let Ok(exe) = std::env::var("TARGET_EXE") else {
        warn_once("TARGET_EXE not set — origin verification is DISABLED for this build");
        return quote! { #item2 }.into(); // no binary configured → no-op
    };
    let Some(pe) = load_pe_cached(&exe) else {
        // Distinguish "binary absent" (gitignored checkout — legitimate no-op)
        // from "binary present but unloadable" (corrupt / wrong file): a broken
        // file must not silently disable every check with a green build.
        if std::path::Path::new(&exe).exists() {
            let msg = format!(
                "TARGET_EXE={exe} exists but failed to load as a PE32 image — \
                 origin verification would be silently disabled; fix or unset it"
            );
            let err = syn::Error::new(proc_macro2::Span::call_site(), msg).to_compile_error();
            return quote! { #err #item2 }.into();
        }
        warn_once("TARGET_EXE points to a missing file — origin verification is DISABLED for this build");
        return quote! { #item2 }.into();
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
        } else if !referenced_addrs_cached(&pe).contains(&(args.addr as u32)) {
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

        // Duplicate-origin check (ON by default via DUP_STRICT): a binary fn may be
        // implemented by exactly ONE Rust fn. Mirrors `check_origins.py`'s dup-addr
        // gate, but at compile time and pointed straight at the offending attribute.
        // Set DUP_STRICT=0 to allow dups (use during bulk-port before burndown).
        if env_flag("DUP_STRICT", true) {
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
            warn_once(&vtable_only_dispatch_msg(args.addr, vt_va, slot));
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
                // MISSING is FATAL by default (set STRICT_MISSING=0 to demote). A MISSING
                // is often NOT a defect: a call made via method syntax `x.foo()` isn't
                // resolved yet, the binary call may be a faithful inline, or the rebuild
                // legitimately routes it elsewhere (e.g. allocation through the single
                // Rust heap instead of a literal `form_heap_allocate` CALL, CRT/intrinsic
                // ops like `fmodf`). But for catching AI digression the strict default is
                // right: an AI regenerating a body and dropping a real call would slip
                // through as a silent MISSING otherwise. HALLUCINATED is always fatal —
                // that is the actual invented-code guard. The pure-byte `callgraph_verify`
                // tool reports the full MISSING worklist.
                if env_flag("STRICT_MISSING", true) {
                    for a in &d.missing {
                        errors.push(format!(
                            "MISSING: binary calls {} ({a:#010x}) — body doesn't",
                            map.addr2name.get(a).map(String::as_str).unwrap_or("?")
                        ));
                    }
                }
            }
            Err(e) => errors.push(format!("analyze {:#010x}: {e}", args.addr)),
        }

        // (2b) Argument-shape diff (ON by default via STRICT_ARGS): per call site,
        // compare the CONCRETE argument kinds the body passes (immediate / field-load /
        // global) positionally against the binary's recovered call-site args. Catches
        // wrong constants, wrong field offsets, wrong globals, and reordered args —
        // what the call-edge check can't see. Conservative: only unambiguous (single)
        // call sites, only positions concrete on BOTH sides (a register-staged binary
        // arg reads as `Other` and is skipped). Set STRICT_ARGS=0 to disable — known
        // false positives: ICF-folded stubs (one address, heterogeneous callers) and
        // convention-ambiguous free calls.
        if env_flag("STRICT_ARGS", true) {
            arg_shape_check(&pe, args.addr, &map, item2.clone(), &mut errors);
        }
    }

    // (3) Operand-fact diff (ON by default via STRICT_OPERANDS). Every in-image
    // ADDRESS literal the body bakes in — a global read `[0x00bXXXXX]`, an RTTI
    // typedesc / vtable VA / fn pointer pushed as an immediate, or an IAT slot —
    // must be referenced by the binary at this origin. A body address the binary
    // never touches is invented. This is the operand analogue of HALLUCINATED: it
    // catches a wrong global/typedesc/vtable VA, which the call-graph check (call
    // edges only) can never see.
    //
    // The rebuild legitimately reads some globals DIRECTLY that the original
    // reaches through an accessor CALL (the same reason MISSING is non-fatal
    // when STRICT_MISSING=0), so this can false-positive tree-wide. Set
    // STRICT_OPERANDS=0 to disable. Field OFFSETS are intentionally NOT
    // auto-checked here: small hex (`0x10`, `0xff`) is indistinguishable from
    // counts / masks / enum values, so an offset check belongs in an explicit
    // `fields = [..]` declaration.
    if env_flag("STRICT_OPERANDS", true) {
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
                for v in body::collect_hex_literals(item2.clone()) {
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
    }

    // (4) CFG-fingerprint diff (opt-in via STRICT_CFG): catch a port that omits a loop the
    // binary has, or a jump-table switch, or is straight-line where the binary branches heavily.
    // COARSE + tolerant — optimized CFGs do not map 1:1 to source, so only gross structural
    // divergences are flagged. Caveats: loop unrolling, switch lowered to an if-chain, and inlined
    // helpers can still produce noise — hence opt-in and diagnostic, not a clean always-on gate.
    if std::env::var_os("STRICT_CFG").is_some() {
        match cfg_fingerprint(&pe, args.addr) {
            Ok(fp) => {
                let r = body::cfg_keyword_counts(item2.clone());
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
            }
            Err(e) => errors.push(format!("cfg check {:#010x}: {e}", args.addr)),
        }
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
// Generates `pub fn renderer_vt() -> u32` (the OnceLock raw-pointer table the
// ctor installs at obj+0). For each `slot = path`, it resolves `path`'s origin
// address from the corpus and compares it to the engine vtable slot read from
// the PE (`engine[va + slot*4]`). A mismatch (wrong fn / off-by-one slot) is a
// `compile_error!`. `default` slots are the un-ported remainder (not checked).
// ---------------------------------------------------------------------------
struct VtableTable {
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
        pub fn #name() -> u32 {
            static VT: ::std::sync::OnceLock<[usize; #slots]> = ::std::sync::OnceLock::new();
            (VT.get_or_init(|| {
                let mut t = [#default as *const () as usize; #slots];
                #( t[#idxs] = #paths as *const () as usize; )*
                t
            }) as *const [usize; #slots]) as u32
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
    use super::vtable_only_dispatch_msg;

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
}
