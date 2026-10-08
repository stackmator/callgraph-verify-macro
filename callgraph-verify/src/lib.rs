//! Pure-byte call-graph + fact verifier for the Rust rebuild.
//!
//! When a rebuild function is tagged `origin: 0xADDR`, it claims to be a 1:1
//! port of the function at that VA in the target binary. This crate establishes
//! ground truth by disassembling the actual bytes (no Ghidra, no decompiled C)
//! and lets a port declare what it should structurally match:
//!
//!   * direct CALL targets   (the call graph)
//!   * struct field offsets  (`[reg+0xNN]` accesses)
//!   * global / static VAs    (`[0x00bXXXXX]` data refs)
//!   * vtable / immediate VAs (`MOV [esi],0x00a7e38c`)
//!   * virtual-call slots     (`CALL [reg+0x84]`)
//!   * IAT import targets     (`CALL [0x00a28xxx]`)
//!
//! Use the [`verify_callgraph!`] macro to turn declarations into `#[test]`s.

pub mod disasm;
pub mod pe;
pub mod skel;

pub use disasm::{analyze, reg_params, resolve_thunk, ArgKind, CallGraph, CallSite};
pub use pe::Pe;
pub use skel::{cfg_fingerprint, CfgFingerprint};

use std::collections::BTreeSet;

/// One declared expectation for a function, checked against the binary's facts.
#[derive(Default)]
pub struct Spec {
    pub addr: u64,
    calls: Option<(Vec<u64>, bool)>, // (declared, exact?)
    fields: Vec<u64>,
    globals: Vec<u64>,
    vtables: Vec<u64>, // in-image immediates (vtable VAs, fn ptrs, string addrs)
    vcall_slots: Vec<u64>,
    iat: Vec<u64>,
}

/// The cached `.text` instruction-start sets, keyed by the PE's unique id
/// plus `(image_base, text_rva, text_vsize)`. Each entry holds an `Arc` so the
/// cached set can be cloned out without holding the MutexGuard. The id (not
/// layout alone) is the key because two same-layout PEs with different bytes
/// must never share a set — the input-ignoring-cache class of BUG #9.
type TextStartsCache = std::sync::Mutex<
    std::collections::HashMap<(u64, u64, u32, u32), std::sync::OnceLock<TextStarts>>,
>;
type TextStarts = std::sync::Arc<std::collections::BTreeSet<u64>>;

/// The cached set of EVERY rel32 branch target (CALL/JMP/Jcc) whose opcode sits
/// at a real instruction start in `.text`, keyed by PE id + layout. Built in
/// ONE linear pass per PE instance so [`has_direct_branch_target`] is a hash
/// lookup — the per-target scan it replaced walked the whole (multi-MB)
/// `.text` blob on every call, making the macro's inline-marker and
/// vtable-dispatch checks O(fns × markers × |.text|) per build. NOTE: the
/// steady-state path must not touch the `.text` bytes at all — a content
/// fingerprint per call (an earlier draft hashed 4 MB every lookup) is just a
/// cheaper rescan and reproduces the same quadratic build time.
type BranchTargetsCache = std::sync::Mutex<
    std::collections::HashMap<(u64, u64, u32, u32), std::sync::OnceLock<BranchTargets>>,
>;
type BranchTargets = std::sync::Arc<std::collections::HashSet<u32>>;

fn branch_targets_cache() -> &'static BranchTargetsCache {
    static CACHE: std::sync::OnceLock<BranchTargetsCache> = std::sync::OnceLock::new();
    CACHE.get_or_init(|| std::sync::Mutex::new(std::collections::HashMap::new()))
}

fn text_starts_cache() -> &'static TextStartsCache {
    static CACHE: std::sync::OnceLock<TextStartsCache> = std::sync::OnceLock::new();
    CACHE.get_or_init(|| std::sync::Mutex::new(std::collections::HashMap::new()))
}

/// Decode the entire `.text` section once and return the set of VAs that are
/// the start of a valid x86 instruction. Used by [`has_direct_branch_target`]
/// to gate its byte-scan so a `0xE8` byte sitting inside some other
/// instruction's encoding (i.e. NOT at an instruction start) is rejected — the
/// call/jmp pattern there is a spurious coincidence, not a real branch.
///
/// Steady-state is lock-free: the cache stores `&'static OnceLock` values, and
/// once `get_or_init` has populated one, repeated `get()` calls return
/// `&'static BTreeSet`s without touching the mutex. The mutex is only acquired
/// on the very first request per `(image_base, text_rva, text_vsize)` triple.
fn text_instruction_starts(pe: &Pe) -> TextStarts {
    let key = || -> Option<(u64, u64, u32, u32)> {
        let text = pe.sections().iter().find(|s| s.name == ".text")?;
        Some((
            pe.id(),
            pe.image_base,
            text.virtual_address,
            text.virtual_size,
        ))
    };
    let key = match key() {
        Some(k) => k,
        None => {
            // No .text section: return an empty Arc.
            static EMPTY: std::sync::OnceLock<TextStarts> = std::sync::OnceLock::new();
            return EMPTY
                .get_or_init(|| std::sync::Arc::new(std::collections::BTreeSet::new()))
                .clone();
        }
    };
    let cache = text_starts_cache();
    // Fast path: lock-free read once the value exists. `Mutex::lock` returns
    // `LockResult<MutexGuard>`; we ignore poisoning — `OnceLock::get_or_init`
    // never panics inside the closure.
    let mut lock = cache.lock().unwrap_or_else(|e| e.into_inner());
    let entry = lock.entry(key).or_default();
    let once = entry.get_or_init(|| {
        use iced_x86::{Decoder, DecoderOptions};
        let text = pe
            .sections()
            .iter()
            .find(|s| s.name == ".text")
            .expect("key was Some");
        let text_va = pe.image_base + text.virtual_address as u64;
        let bytes = match pe.read(text_va, text.virtual_size as usize) {
            Some(b) => b,
            None => return std::sync::Arc::new(std::collections::BTreeSet::new()),
        };
        let mut dec = Decoder::with_ip(32, bytes, text_va, DecoderOptions::NONE);
        let mut starts = std::collections::BTreeSet::new();
        starts.insert(text_va);
        while dec.can_decode() {
            let ip = dec.ip();
            starts.insert(ip);
            let _ = dec.decode();
        }
        std::sync::Arc::new(starts)
    });
    once.clone()
}

/// Does ANY instruction in `.text` statically target `target` via a relative branch
/// (CALL/JMP/Jcc rel32)? Used by the macro to warn on vtable-only dispatch.
///
/// Implementation: the set of all such targets is built in ONE pass over `.text`
/// (cached per PE — see [`branch_targets_cache`]) and this call is a hash lookup.
/// The one-pass walk decodes `.text` once (also cached) to learn every valid
/// instruction start, then byte-scans for `0xE8`/`0xE9`/`0x0F 0x8x` and only
/// records a hit as a real branch if its opcode byte sits AT an instruction
/// start. Without that gate (BUG #3), a `0xE8` byte anywhere inside another
/// instruction's encoding was treated as a CALL, computing a junk rel32 target
/// that could coincidentally equal `target` — a false positive that suppressed
/// legitimate VTABLE-ONLY DISPATCH warnings.
pub fn has_direct_branch_target(pe: &Pe, target: u64) -> bool {
    all_branch_targets(pe).contains(&(target as u32))
}

/// Every rel32 branch target of `.text`, computed once per PE instance.
/// Accept-set identical to the per-target scan this replaces: rel32
/// CALL/JMP/Jcc opcodes gated on real instruction starts. Keyed by the PE's
/// unique id — the steady-state lookup never touches the `.text` bytes.
fn all_branch_targets(pe: &Pe) -> BranchTargets {
    let Some(text) = pe.sections().iter().find(|s| s.name == ".text") else {
        // No .text section: every lookup misses against an empty set.
        static EMPTY: std::sync::OnceLock<BranchTargets> = std::sync::OnceLock::new();
        return EMPTY
            .get_or_init(|| std::sync::Arc::new(std::collections::HashSet::new()))
            .clone();
    };
    let text_va = pe.image_base + text.virtual_address as u64;
    let key = (
        pe.id(),
        pe.image_base,
        text.virtual_address,
        text.virtual_size,
    );
    let cache = branch_targets_cache();
    let mut lock = cache.lock().unwrap_or_else(|e| e.into_inner());
    let entry = lock.entry(key).or_default();
    entry
        .get_or_init(|| {
            let blob = match pe.read(text_va, text.virtual_size as usize) {
                Some(b) => b,
                None => return std::sync::Arc::new(std::collections::HashSet::new()),
            };
            let starts = text_instruction_starts(pe);
            let mut targets = std::collections::HashSet::new();
            let mut i = 0;
            while i + 4 < blob.len() {
                let rel_at = match blob[i] {
                    0xE8 | 0xE9 => i + 1, // CALL rel32 / JMP rel32
                    0x0F if i + 6 <= blob.len() && (0x80..=0x8F).contains(&blob[i + 1]) => i + 2,
                    _ => {
                        i += 1;
                        continue;
                    }
                };
                // Gate: the branch opcode must sit at a real instruction start.
                // Spurious `0xE8` bytes inside other instructions are ignored.
                // (BUG #3 fix.)
                let ip_va = text_va + i as u64;
                if !starts.contains(&ip_va) {
                    i += 1;
                    continue;
                }
                if rel_at + 4 > blob.len() {
                    i += 1;
                    continue;
                }
                let rel = i32::from_le_bytes([
                    blob[rel_at],
                    blob[rel_at + 1],
                    blob[rel_at + 2],
                    blob[rel_at + 3],
                ]) as i64;
                let t = (text_va + (rel_at as u64 + 4)).wrapping_add(rel as u64) as u32;
                targets.insert(t);
                i += 1;
            }
            std::sync::Arc::new(targets)
        })
        .clone()
}

impl Spec {
    pub fn new(addr: u64) -> Spec {
        Spec {
            addr,
            ..Default::default()
        }
    }
    /// Declared CALL set must EQUAL the binary's (flags hallucinated + missing).
    pub fn calls_exact(mut self, t: &[u64]) -> Spec {
        self.calls = Some((t.to_vec(), true));
        self
    }
    /// No declared CALL may be absent (hallucination-only; tolerates inlined/unported).
    pub fn calls_superset(mut self, t: &[u64]) -> Spec {
        self.calls = Some((t.to_vec(), false));
        self
    }
    /// Each declared field offset must be touched by the binary (present-check).
    pub fn fields(mut self, t: &[u64]) -> Spec {
        self.fields = t.to_vec();
        self
    }
    pub fn globals(mut self, t: &[u64]) -> Spec {
        self.globals = t.to_vec();
        self
    }
    pub fn vtables(mut self, t: &[u64]) -> Spec {
        self.vtables = t.to_vec();
        self
    }
    pub fn vcall_slots(mut self, t: &[u64]) -> Spec {
        self.vcall_slots = t.to_vec();
        self
    }
    pub fn iat(mut self, t: &[u64]) -> Spec {
        self.iat = t.to_vec();
        self
    }

    /// Check this spec against the binary; `Err` lists every violation.
    pub fn check(&self, pe: &Pe) -> Result<(), String> {
        let cg = analyze(pe, self.addr)?;
        let mut v = Vec::new();

        if let Some((declared, exact)) = &self.calls {
            let real = cg.call_targets();
            let dset: BTreeSet<u64> = declared.iter().copied().collect();
            for h in dset.difference(&real) {
                v.push(format!(
                    "HALLUCINATED  declared CALL {h:#010x} — binary never directly calls it"
                ));
            }
            if *exact {
                for m in real.difference(&dset) {
                    v.push(format!(
                        "MISSING       binary CALLs {m:#010x} — not declared"
                    ));
                }
            }
        }
        // The rest are present-checks: a declared item the binary doesn't exhibit
        // is the hallucination; we don't require enumerating the binary's full set.
        present_check("field offset", &self.fields, &cg.field_offsets, &mut v);
        present_check("global", &self.globals, &cg.globals, &mut v);
        present_check("vtable/imm addr", &self.vtables, &cg.imm_addrs, &mut v);
        present_check("vcall slot", &self.vcall_slots, &cg.vcall_slots, &mut v);
        present_check("IAT import", &self.iat, &cg.iat_calls, &mut v);

        if v.is_empty() {
            Ok(())
        } else {
            Err(format!(
                "{:#010x}: {} violation(s) vs pure-byte ground truth:\n  {}\n  (indirect calls: {}, indirect jumps: {})",
                self.addr,
                v.len(),
                v.join("\n  "),
                cg.indirect_calls,
                cg.indirect_jumps,
            ))
        }
    }

    /// Load `<manifest_dir>/<exe>` and panic on any violation (for `#[test]`s).
    pub fn check_at(&self, manifest_dir: &str, exe: &str) {
        let path = std::path::Path::new(manifest_dir).join(exe);
        let pe = Pe::load(path.to_str().unwrap())
            .unwrap_or_else(|e| panic!("load {}: {e}", path.display()));
        if let Err(msg) = self.check(&pe) {
            panic!("{msg}");
        }
    }
}

fn present_check(kind: &str, declared: &[u64], real: &BTreeSet<u64>, out: &mut Vec<String>) {
    for d in declared {
        if !real.contains(d) {
            out.push(format!(
                "HALLUCINATED  declared {kind} {d:#x} — binary never references it"
            ));
        }
    }
}

/// Back-compat thin diff over direct calls only (used by the CLI / build gate).
#[derive(Debug)]
pub struct Diff {
    pub entry: u64,
    pub hallucinated: Vec<u64>,
    pub missing: Vec<u64>,
    pub indirect_calls: u32,
    pub indirect_jumps: u32,
}

impl Diff {
    pub fn is_clean(&self) -> bool {
        self.hallucinated.is_empty() && self.missing.is_empty()
    }
}

pub fn diff_calls(
    pe: &Pe,
    entry: u64,
    declared: &[u64],
    expect_complete: bool,
) -> Result<Diff, String> {
    let cg = analyze(pe, entry)?;
    let real = cg.call_targets();
    let dset: BTreeSet<u64> = declared.iter().copied().collect();
    Ok(Diff {
        entry,
        hallucinated: dset.difference(&real).copied().collect(),
        missing: if expect_complete {
            real.difference(&dset).copied().collect()
        } else {
            Vec::new()
        },
        indirect_calls: cg.indirect_calls,
        indirect_jumps: cg.indirect_jumps,
    })
}

/// Result of diffing a Rust function's *resolved body calls* against the binary.
pub struct CorpusDiff {
    pub addr: u64,
    /// Rust calls a ported fn the binary never calls (and didn't inline) — invented.
    pub hallucinated: Vec<(String, Vec<u64>)>,
    /// Rust calls a ported fn the binary inlines — reclassified faithful.
    pub inlined_ok: Vec<String>,
    /// Rust DIRECTLY calls a method the binary dispatches through a known (declared) vtable —
    /// the faithful form is a `vcall`. Once the vtable is declared, the call CAN be made
    /// virtually, so it MUST be one.
    pub vtable_dispatch: Vec<(String, Vec<u64>)>,
    /// Binary calls a ported fn the Rust body doesn't (often inlined; review).
    pub missing: Vec<u64>,
    pub indirect_calls: u32,
}

fn is_inlined_into(pe: &Pe, callee: u64, caller_fp: &BTreeSet<u64>) -> bool {
    match analyze(pe, callee) {
        Ok(cg) => {
            let fp = cg.footprint();
            // Footprint-subset is only meaningful evidence with >= 2 distinct
            // in-image references. A SINGLE shared global (an inlined refcount
            // accessor) or a single shared call target is a subset of almost any
            // caller that touches the same thing — that's coincidence, not
            // inlining, and accepting it would excuse an invented call. Trivial
            // single-element callees can't be footprint-confirmed, so the
            // faithful port reproduces the inlined work inside the caller —
            // it does not call the helper.
            fp.len() >= 2 && fp.is_subset(caller_fp)
        }
        Err(_) => false,
    }
}

/// Diff the calls a Rust body makes (already resolved to ported addresses) against
/// the binary's real call set at `own_addrs`. `corpus` is the set of all ported
/// origin addresses (only calls within it are diffable). Mirrors the logic of
/// `tools/analysis/verify_callgraph.py`, but on bytes instead of Ghidra `.asm`.
pub fn diff_body_calls(
    pe: &Pe,
    own_addrs: &[u64],
    corpus: &BTreeSet<u64>,
    rust_idents: &[(String, Vec<u64>)],
    vtable_methods: &BTreeSet<u64>,
    miss_satisfied: &BTreeSet<u64>,
) -> Result<CorpusDiff, String> {
    let primary = *own_addrs.first().ok_or("no origin address")?;
    let mut bin_calls = BTreeSet::new();
    let mut wide_extras = BTreeSet::new();
    let mut footprint = BTreeSet::new();
    let mut indirect = 0u32;
    let mut tail_targets: BTreeSet<u64> = BTreeSet::new();
    for &a in own_addrs {
        let cg = analyze(pe, a)?;
        bin_calls.extend(cg.call_targets());
        // A tail-call `JMP 0xADDR` out of the body is a real call edge (e.g. a
        // cache-wrapper that tail-calls the base getter), so count it as a call —
        // a faithful port spells it as an ordinary call.
        bin_calls.extend(&cg.tail_calls);
        tail_targets.extend(&cg.tail_calls);
        // Code-pointer immediates widen acceptance only (folded into
        // `bin_calls_wide` below, never into the MISSING requirement); staged here
        // so the walk stays single-pass.
        wide_extras.extend(
            cg.imm_addrs
                .iter()
                .copied()
                .filter(|&x| pe.is_executable_section_va(x)),
        );
        footprint.extend(cg.footprint());
        indirect += cg.indirect_calls;
    }
    // Wide acceptance set: `bin_calls` plus, per function, its executable-section
    // code-pointer immediates and one level of each tail-callee's direct calls.
    // - A code-pointer immediate (`PUSH 0xADDR` / `MOV reg,0xADDR` with ADDR in a
    //   section flagged EXECUTE/CODE) is a function the binary hands to a higher-order
    //   helper that then INVOKES it — a CRT `_EH_vector_constructor_iterator` over an
    //   element array, a `qsort` comparator, a registered callback, etc. A faithful
    //   port that spells the per-element / callback work as a direct call to that
    //   function is not a hallucination. The characteristics-based filter
    //   (`is_executable_section_va`, NOT the permissive `is_executable_va`) excludes
    //   `.rdata` vtable VAs and string addresses — those are data, not call targets.
    // - A tail-call `JMP G` transfers control to G, so the calls G makes are reachable
    //   as part of THIS function's execution. MSVC frequently splits a function across
    //   non-contiguous chunks linked by a `JMP`, or emits a tiny entry stub that
    //   tail-jumps to a shared body (e.g. `0x00590110` → `JMP 0x0058da00`, whose body
    //   `CALL 0x0058d1c0`; or the ICF-folded stubs that all `JMP 0x004524c0`). The
    //   decompiler shows that body inlined into the entry, so a faithful port spells
    //   those as ordinary calls.
    // Both folds only ever ADD acceptable spellings (HALLUCINATED direction). They must
    // NOT feed the MISSING requirement: the binary issues no CALL to an imm-addr, and
    // no CALL here to the tail target's callees — demanding them forces ports to
    // duplicate the tail target's body (previously misdiagnosed as E013 with an
    // unactionable "add the call" fix; the suggested call was already spelled).
    let mut bin_calls_wide = bin_calls.clone();
    bin_calls_wide.extend(wide_extras);
    for t in tail_targets {
        if let Ok(tcg) = analyze(pe, t) {
            bin_calls_wide.extend(tcg.call_targets());
        }
    }
    // Follow one level of jmp-thunks: a call to a `JMP X` thunk (tail-jump stub / ICF forwarder)
    // really targets X, so a faithful direct Rust call to X is not a hallucination.
    // Resolved over the WIDE set (as before this split) so acceptance is unchanged;
    // the results stay wide-only — a thunk is never itself a MISSING requirement.
    let thunked: Vec<u64> = bin_calls_wide
        .iter()
        .filter_map(|&t| resolve_thunk(pe, t))
        .collect();
    bin_calls_wide.extend(thunked);
    let own: BTreeSet<u64> = own_addrs.iter().copied().collect();
    let bin_ported: BTreeSet<u64> = bin_calls
        .intersection(corpus)
        .copied()
        .filter(|a| !own.contains(a))
        .collect();

    let (mut hallucinated, mut inlined_ok, mut vtable_dispatch, mut resolved) =
        (Vec::new(), Vec::new(), Vec::new(), BTreeSet::new());
    for (ident, addrs) in rust_idents {
        let aset: Vec<u64> = addrs.iter().copied().filter(|a| !own.contains(a)).collect();
        if aset.is_empty() {
            continue;
        }
        resolved.extend(&aset);
        // Satisfied-direction check reads the WIDE set: a body edge the binary
        // reaches only through a tail-jump or a higher-order immediate is faithful.
        // (`bin_calls` below stays narrow: MISSING must only require edges the binary
        // actually CALLs here.)
        if aset.iter().any(|a| bin_calls_wide.contains(a)) {
            continue; // satisfied — binary makes (one of) this call
        }
        if aset.iter().any(|a| is_inlined_into(pe, *a, &footprint)) {
            inlined_ok.push(ident.clone());
            continue; // faithful: binary inlined the callee (footprint-confirmed)
        }
        // Known (declared) vtable method the binary doesn't directly call → it is dispatched
        // virtually; the faithful form is a `vcall`. The vtable exists, so the call CAN and
        // MUST be virtual — no other form is faithful.
        if aset.iter().any(|a| vtable_methods.contains(a)) {
            vtable_dispatch.push((ident.clone(), aset));
            continue;
        }
        hallucinated.push((ident.clone(), aset));
    }
    // A MISSING is a binary call to a ported fn the body doesn't spell. But the
    // verifier can only SEE a spelling when the body call name resolves through
    // the strict table split + DENY filter — a qualified path `Self::m(..)` /
    // `Type::m(..)` denotes an impl method yet resolves against free_fns only,
    // and a generically-named ported fn (`mul`, `new`) is excluded outright, so
    // its MISSING would be UNSATISFIABLE no matter how faithfully the body
    // spells it. `miss_satisfied` (both tables, DENY-inclusive, split-agnostic)
    // marks those addresses as satisfiable-by-name. Used ONLY here — never to
    // excuse a HALLUCINATED, which keeps the strict split + DENY filter.
    let missing: Vec<u64> = bin_ported
        .difference(&resolved)
        .filter(|a| !miss_satisfied.contains(a))
        .copied()
        .collect();
    Ok(CorpusDiff {
        addr: primary,
        hallucinated,
        inlined_ok,
        vtable_dispatch,
        missing,
        indirect_calls: indirect,
    })
}

/// Declare expected facts for `origin:` functions and generate one `#[test]` per
/// function, checked against the real binary.
///
/// Two forms:
///
/// ```ignore
/// verify_callgraph! {
///     exe: "../../target.exe";
///
///     // 1) shorthand — direct calls only
///     fn set_name @ 0x006ff420 => exact [0x00401f00, 0x00401f20, 0x00984b6a];
///
///     // 2) block — any subset of clauses, each `;`-terminated
///     fn ni_node_ctor @ 0x0070b780 {
///         calls: superset [0x004b2d30];
///         fields: [0xbc, 0xc0, 0xc4, 0xc8];   // struct offsets it must touch
///         vtables: [0x00a7e38c];              // NiNode vtable VA installed
///         vcall_slots: [0x84];                // virtual call slot, if any
///     }
/// }
/// ```
///
/// CALL clauses: `exact` (equality) or `superset` (hallucination-only). The other
/// clauses are present-checks: each declared value must appear in the binary's
/// harvested set, else it's a hallucination.
#[macro_export]
macro_rules! verify_callgraph {
    (exe: $exe:expr; $($body:tt)*) => {
        $crate::verify_callgraph!(@each $exe; $($body)*);
    };

    // shorthand: direct calls, exact
    (@each $exe:expr;
        $(#[$m:meta])* fn $name:ident @ $addr:expr => exact [ $($t:expr),* $(,)? ] ; $($rest:tt)*) => {
        $(#[$m])*
        #[test]
        fn $name() {
            $crate::Spec::new($addr).calls_exact(&[$($t),*]).check_at(env!("CARGO_MANIFEST_DIR"), $exe);
        }
        $crate::verify_callgraph!(@each $exe; $($rest)*);
    };

    // shorthand: direct calls, superset
    (@each $exe:expr;
        $(#[$m:meta])* fn $name:ident @ $addr:expr => superset [ $($t:expr),* $(,)? ] ; $($rest:tt)*) => {
        $(#[$m])*
        #[test]
        fn $name() {
            $crate::Spec::new($addr).calls_superset(&[$($t),*]).check_at(env!("CARGO_MANIFEST_DIR"), $exe);
        }
        $crate::verify_callgraph!(@each $exe; $($rest)*);
    };

    // block form: any subset of `;`-terminated clauses
    (@each $exe:expr;
        $(#[$m:meta])* fn $name:ident @ $addr:literal { $($clauses:tt)* } $($rest:tt)*) => {
        $(#[$m])*
        #[test]
        fn $name() {
            let spec = $crate::Spec::new($addr);
            let spec = $crate::verify_callgraph!(@clauses spec; $($clauses)*);
            spec.check_at(env!("CARGO_MANIFEST_DIR"), $exe);
        }
        $crate::verify_callgraph!(@each $exe; $($rest)*);
    };

    (@each $exe:expr;) => {};

    // clause munchers — each consumes one `;`-terminated clause, returns the builder
    (@clauses $s:expr; calls: exact [ $($t:expr),* $(,)? ] ; $($r:tt)*) => {
        $crate::verify_callgraph!(@clauses $s.calls_exact(&[$($t),*]); $($r)*)
    };
    (@clauses $s:expr; calls: superset [ $($t:expr),* $(,)? ] ; $($r:tt)*) => {
        $crate::verify_callgraph!(@clauses $s.calls_superset(&[$($t),*]); $($r)*)
    };
    (@clauses $s:expr; fields: [ $($t:expr),* $(,)? ] ; $($r:tt)*) => {
        $crate::verify_callgraph!(@clauses $s.fields(&[$($t),*]); $($r)*)
    };
    (@clauses $s:expr; globals: [ $($t:expr),* $(,)? ] ; $($r:tt)*) => {
        $crate::verify_callgraph!(@clauses $s.globals(&[$($t),*]); $($r)*)
    };
    (@clauses $s:expr; vtables: [ $($t:expr),* $(,)? ] ; $($r:tt)*) => {
        $crate::verify_callgraph!(@clauses $s.vtables(&[$($t),*]); $($r)*)
    };
    (@clauses $s:expr; vcall_slots: [ $($t:expr),* $(,)? ] ; $($r:tt)*) => {
        $crate::verify_callgraph!(@clauses $s.vcall_slots(&[$($t),*]); $($r)*)
    };
    (@clauses $s:expr; iat: [ $($t:expr),* $(,)? ] ; $($r:tt)*) => {
        $crate::verify_callgraph!(@clauses $s.iat(&[$($t),*]); $($r)*)
    };
    (@clauses $s:expr;) => { $s };
}
