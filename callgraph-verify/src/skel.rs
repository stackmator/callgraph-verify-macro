//! Byte-derived **reference skeleton** emitter: turns a function's machine code into a
//! Rust-flavored structural outline — labeled basic blocks, ordered calls with their recovered
//! arguments, struct-field accesses (`rd`/`wr`), globals (`g`/`s`), and the branch / loop / switch
//! structure. It is NOT compilable Rust; it is a faithful *hint* for porting, generated from the
//! same byte-truth the gates verify against. Use it next to the naked asm and the Ghidra C: the
//! asm is ground truth, Ghidra C gives high-level naming, and this gives the byte-accurate call
//! order + arguments + offsets + control flow in the porter's target idiom.

use crate::disasm::{follow_jump_table, recover_call_site, ArgKind};
use crate::pe::Pe;
use iced_x86::{
    Decoder, DecoderOptions, FlowControl, Formatter, Instruction, Mnemonic, NasmFormatter, OpKind,
    Register,
};
use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write;

const MAX_SPAN: u64 = 0x10000;

/// Decode the whole function, returning every instruction by address plus the set of block
/// leaders (entry, every in-range branch/switch target, and the fallthrough after a conditional).
fn decode_all(pe: &Pe, entry: u64) -> (BTreeMap<u64, Instruction>, BTreeSet<u64>) {
    let (lo, hi) = (entry, entry.saturating_add(MAX_SPAN));
    let mut instrs: BTreeMap<u64, Instruction> = BTreeMap::new();
    let mut leaders: BTreeSet<u64> = BTreeSet::new();
    leaders.insert(entry);
    let mut work = vec![entry];
    let mut seen: BTreeSet<u64> = BTreeSet::new();

    while let Some(start) = work.pop() {
        if !seen.insert(start) {
            continue;
        }
        let Some(bytes) = pe.read(start, 32 * 64) else {
            continue;
        };
        let mut dec = Decoder::with_ip(32, bytes, start, DecoderOptions::NONE);
        let mut instr = Instruction::default();
        while dec.can_decode() {
            let ip = dec.ip();
            if ip != start && instrs.contains_key(&ip) {
                break;
            }
            dec.decode_out(&mut instr);
            if instr.is_invalid() {
                break;
            }
            instrs.insert(ip, instr);
            match instr.flow_control() {
                FlowControl::ConditionalBranch => {
                    let t = instr.near_branch_target();
                    let n = instr.next_ip();
                    if (lo..hi).contains(&t) {
                        leaders.insert(t);
                        work.push(t);
                    }
                    leaders.insert(n);
                    work.push(n);
                    break;
                }
                FlowControl::UnconditionalBranch => {
                    let t = instr.near_branch_target();
                    // Only follow JMPs whose target is BEFORE the JMP
                    // itself. A backward JMP within a structured function
                    // is a real back-edge (loop tail jumping to loop head);
                    // its target must be a leader so the dominance-based
                    // back-edge check at cfg_fingerprint:303-307 has a
                    // chance to count it (`dom[source].contains(target)`
                    // requires `target` to be in `starts`). A FORWARD JMP
                    // is either a fall-through to the next leader (already
                    // handled by `build_cfg`'s `leaders.contains(&addrs[idx])`
                    // check at line 203) or — the bug case — a tail-call
                    // into another function. Real-world instance: thunk
                    // `0x579210: jmp 0x5821f0` in noivilbo.exe, where
                    // 0x5821f0 is 36KB past the entry and the OLD
                    // `(lo..hi).contains(&t)` check followed it and
                    // counted the callee's loops, switches, and
                    // conditionals against the caller's CFG fingerprint
                    // (`fp.loops = 11` for a 1-instruction thunk). A
                    // forward JMP that the inner decoder hasn't already
                    // advanced past via fall-through is a tail-call, not
                    // intra-function control flow, and must NOT be
                    // decoded into this function's CFG.
                    //
                    // `cfg_fingerprint` itself counts the JMP as a
                    // back-edge iff `t <= b.start && dom[b].contains(t)`
                    // and as a return-equivalent otherwise, so a thunk
                    // (forward JMP, target not in dom) is correctly
                    // classified as a return-equivalent terminator.
                    if t < ip {
                        leaders.insert(t);
                        work.push(t);
                    }
                    break;
                }
                FlowControl::IndirectBranch => {
                    let mut cases = Vec::new();
                    follow_jump_table(&instr, pe, lo, hi, &mut cases);
                    for c in cases {
                        leaders.insert(c);
                        work.push(c);
                    }
                    break;
                }
                FlowControl::Return | FlowControl::Interrupt | FlowControl::Exception => break,
                _ => {}
            }
        }
    }
    (instrs, leaders)
}

/// A coarse, optimization-tolerant control-flow signature of a function, from its CFG.
#[derive(Debug, Default, Clone, Copy)]
pub struct CfgFingerprint {
    /// Natural-loop back-edges: a branch from block B to block T where T
    /// dominates B (every path from entry to B passes through T). The
    /// dominance check is what stops a function that has several
    /// `if (cond) goto epilog;` exits to a common tail from being reported
    /// as having multiple "loops" — those are forward jumps in source layout
    /// that look like back-edges once the compiler lays the tail at a lower
    /// address, but the tail doesn't dominate the `goto` sites, so they
    /// aren't iteration.
    pub loops: usize,
    /// Total case count across jump-table switches.
    pub switch_cases: usize,
    /// Conditional-branch terminators.
    pub conditionals: usize,
    /// Return / interrupt / tail-call terminators.
    pub returns: usize,
}

/// One basic block in the local CFG of a function: a leader plus all
/// instructions until the next leader or terminator, plus successors that
/// stay in-range. Used by both [`cfg_fingerprint`] (for the natural-loop
/// count) and [`emit_skeleton`] (for the labeled-block outline).
struct Block {
    start: u64,
    body: Vec<Instruction>,
    term: Option<Instruction>,
    /// In-range successor block starts. Out-of-range JMPs (tail calls) and
    /// the fall-through into the next leader are included so dominance can
    /// see the whole local flow graph.
    succ: Vec<u64>,
}

/// Build the local CFG of the function at `entry`: ordered blocks with
/// successors, restricted to VAs in `[entry, entry + MAX_SPAN)`.
fn build_cfg(pe: &Pe, entry: u64) -> (BTreeMap<u64, Instruction>, Vec<Block>) {
    let (_, _) = (entry, entry.saturating_add(MAX_SPAN));
    let (instrs, leaders) = decode_all(pe, entry);
    let addrs: Vec<u64> = instrs.keys().copied().collect();
    let lo = entry;
    let hi = entry.saturating_add(MAX_SPAN);
    let mut blocks: Vec<Block> = Vec::new();
    for &ld in &leaders {
        let mut idx = match addrs.binary_search(&ld) {
            Ok(i) => i,
            Err(_) => continue,
        };
        let mut body = Vec::new();
        let mut term = None;
        let mut succ = Vec::new();
        loop {
            let a = addrs[idx];
            let instr = instrs[&a];
            // IndirectCall is NOT a terminator: the callee returns and
            // execution continues at the next IP, so the call is
            // "synchronous" from a CFG perspective.
            let is_term = !matches!(
                instr.flow_control(),
                FlowControl::Next
                    | FlowControl::Call
                    | FlowControl::IndirectCall
                    | FlowControl::XbeginXabortXend
            );
            if is_term {
                match instr.flow_control() {
                    FlowControl::ConditionalBranch => {
                        let t = instr.near_branch_target();
                        if (lo..hi).contains(&t) {
                            succ.push(t);
                        }
                        let n = instr.next_ip();
                        if (lo..hi).contains(&n) {
                            succ.push(n);
                        }
                    }
                    FlowControl::UnconditionalBranch => {
                        let t = instr.near_branch_target();
                        if (lo..hi).contains(&t) {
                            succ.push(t);
                        }
                    }
                    FlowControl::IndirectBranch => {
                        // Switch / jump-table dispatch: every in-range
                        // case is a successor of this block. The
                        // dominator set can then see the indirect
                        // dispatch as a forward fan-out (no back-edge
                        // through a switch).
                        let mut cases = Vec::new();
                        follow_jump_table(&instr, pe, lo, hi, &mut cases);
                        for c in cases {
                            if (lo..hi).contains(&c) {
                                succ.push(c);
                            }
                        }
                    }
                    _ => {}
                }
                term = Some(instr);
                break;
            }
            body.push(instr);
            idx += 1;
            if idx >= addrs.len() {
                break;
            }
            if leaders.contains(&addrs[idx]) {
                succ.push(addrs[idx]);
                break;
            }
        }
        blocks.push(Block {
            start: ld,
            body,
            term,
            succ,
        });
    }
    blocks.sort_by_key(|b| b.start);
    (instrs, blocks)
}

/// Iterative dominator set computation on the local CFG: for each block `n`,
/// `dom[n]` is the set of blocks that appear on EVERY path from `entry` to
/// `n` (including `n` itself). Standard textbook algorithm — small enough
/// for the size of CFG we deal with here (max ~64KB). Blocks unreachable
/// from `entry` are kept in the map with an empty set so callers can detect
/// them, but in practice `decode_all` only follows reachable leaders so
/// unreachable blocks shouldn't appear.
fn dominators(entry: u64, blocks: &[Block]) -> BTreeMap<u64, BTreeSet<u64>> {
    let starts: BTreeSet<u64> = blocks.iter().map(|b| b.start).collect();
    let mut preds: BTreeMap<u64, BTreeSet<u64>> = BTreeMap::new();
    for b in blocks {
        for &s in &b.succ {
            if starts.contains(&s) {
                preds.entry(s).or_default().insert(b.start);
            }
        }
    }
    let mut dom: BTreeMap<u64, BTreeSet<u64>> = BTreeMap::new();
    if !starts.contains(&entry) {
        return dom;
    }
    let mut entry_set: BTreeSet<u64> = BTreeSet::new();
    entry_set.insert(entry);
    dom.insert(entry, entry_set.clone());
    for &s in &starts {
        if s != entry {
            dom.insert(s, starts.clone());
        }
    }
    let order: Vec<u64> = blocks.iter().map(|b| b.start).collect();
    loop {
        let mut changed = false;
        for &n in &order {
            if n == entry {
                continue;
            }
            let empty: BTreeSet<u64> = BTreeSet::new();
            let ps = preds.get(&n).unwrap_or(&empty);
            if ps.is_empty() {
                continue;
            }
            let first = ps.iter().next().unwrap();
            let mut new_dom = dom.get(first).cloned().unwrap_or_else(|| starts.clone());
            for &p in ps {
                let pd = dom.get(&p).cloned().unwrap_or_else(|| starts.clone());
                new_dom = new_dom.intersection(&pd).copied().collect();
            }
            new_dom.insert(n);
            if dom.get(&n) != Some(&new_dom) {
                dom.insert(n, new_dom);
                changed = true;
            }
        }
        if !changed {
            break;
        }
    }
    dom
}

/// Compute the coarse CFG fingerprint of the function at `entry`. Counts what is reasonably stable
/// across optimization (loops, jump-table switches) plus raw conditional/return counts; the caller
/// should compare these tolerantly (optimized CFGs do not map 1:1 to source).
pub fn cfg_fingerprint(pe: &Pe, entry: u64) -> Result<CfgFingerprint, String> {
    if !pe.is_executable_va(entry) {
        return Err(format!("{entry:#010x} is not inside any PE section"));
    }
    let (lo, hi) = (entry, entry.saturating_add(MAX_SPAN));
    let (instrs, blocks) = build_cfg(pe, entry);
    let dom = dominators(entry, &blocks);
    let mut fp = CfgFingerprint::default();
    for b in &blocks {
        let Some(instr) = b.term else {
            continue;
        };
        match instr.flow_control() {
            FlowControl::ConditionalBranch => {
                fp.conditionals += 1;
                let t = instr.near_branch_target();
                // Natural-loop back-edge: `t -> b.start` is a back-edge iff
                // `t` dominates `b.start` — every path from `entry` to
                // `b.start` passes through `t`. The textbook definition
                // gives "target dominates source", which is exactly
                // `dom[source].contains(target)`.
                if t <= b.start && dom.get(&b.start).is_some_and(|d| d.contains(&t)) {
                    fp.loops += 1;
                }
            }
            FlowControl::UnconditionalBranch => {
                let t = instr.near_branch_target();
                if t <= b.start && dom.get(&b.start).is_some_and(|d| d.contains(&t)) {
                    fp.loops += 1;
                } else {
                    // Out-of-function JMP — a tail call (the callee will RET
                    // for us). Count it as a return-equivalent so functions
                    // that consist entirely of tail calls (e.g. `return
                    // foo();` after inlining) aren't reported as
                    // terminator-less. The macro's CFG check keys off "any
                    // terminator at all"; missing tail-call JMPs would let
                    // it fire false positives for legitimate delegation.
                    fp.returns += 1;
                }
            }
            FlowControl::Return | FlowControl::Interrupt => fp.returns += 1,
            FlowControl::IndirectBranch => {
                let mut cases = Vec::new();
                follow_jump_table(&instr, pe, lo, hi, &mut cases);
                fp.switch_cases += cases.len();
            }
            _ => {}
        }
        let _ = &instrs;
    }
    Ok(fp)
}

/// Emit the reference skeleton for the function at `entry`.
pub fn emit_skeleton(pe: &Pe, entry: u64) -> Result<String, String> {
    if !pe.is_executable_va(entry) {
        return Err(format!("{entry:#010x} is not inside any PE section"));
    }
    let (instrs, blocks) = build_cfg(pe, entry);
    let _ = &instrs;

    // Loop heads = targets of a natural-loop back-edge (a branch from B to T
    // where T strictly precedes B AND T dominates B). The dominance test is
    // what excludes the false positives that the older `succ <= start` test
    // used to flag: an `if (cond) goto epilog;` that the compiler laid out
    // below its `if`s looks like a back-edge by address, but the epilog
    // doesn't dominate the `if` site, so it isn't a loop.
    let dom = dominators(entry, &blocks);
    let mut loop_heads: BTreeSet<u64> = BTreeSet::new();
    for b in &blocks {
        for &s in &b.succ {
            if s <= b.start && dom.get(&b.start).is_some_and(|d| d.contains(&s)) {
                loop_heads.insert(s);
            }
        }
    }
    // A label is worth printing if more than one block targets it, it's a loop head, or the entry.
    let mut target_count: BTreeMap<u64, u32> = BTreeMap::new();
    for b in &blocks {
        for &s in &b.succ {
            *target_count.entry(s).or_insert(0) += 1;
        }
    }

    let mut fmt = NasmFormatter::new();
    let mut out = String::new();
    let _ = writeln!(
        out,
        "// AUTO-GENERATED reference skeleton from bytes @ {entry:#010x} — NOT compilable; a faithful\n\
         // structural hint (ordered calls + recovered args, field accesses, globals, control flow).\n\
         unsafe fn sub_{entry:08x}(this: u32) {{"
    );

    let _ = &target_count; // (kept for potential label-pruning; every block is labeled for now)
    for b in &blocks {
        let tag = if loop_heads.contains(&b.start) {
            "  // loop head"
        } else {
            ""
        };
        let _ = writeln!(out, "  'L{:08x}: {{{tag}", b.start);
        let mut last_cmp: Option<Instruction> = None;
        let mut arg_base = 0usize; // recovered call args scan only since the previous call
        for (i, instr) in b.body.iter().enumerate() {
            if matches!(instr.mnemonic(), Mnemonic::Cmp | Mnemonic::Test) {
                last_cmp = Some(*instr);
            }
            if let Some(line) = render_instr(pe, instr, &b.body[arg_base..i]) {
                let _ = writeln!(out, "    {line}");
            }
            if matches!(
                instr.flow_control(),
                FlowControl::Call | FlowControl::IndirectCall
            ) {
                arg_base = i + 1;
            }
        }
        if let Some(t) = &b.term {
            let _ = writeln!(
                out,
                "    {}",
                render_terminator(t, last_cmp.as_ref(), &mut fmt)
            );
        }
        let _ = writeln!(out, "  }}");
    }
    let _ = writeln!(out, "}}");
    Ok(out)
}

/// Render the asm text of an instruction (for fallback comments / conditions).
fn asm(fmt: &mut NasmFormatter, instr: &Instruction) -> String {
    let mut s = String::new();
    fmt.format(instr, &mut s);
    s
}

fn reg(r: Register) -> String {
    format!("{r:?}").to_lowercase()
}

/// Render an `ArgKind` as a pseudo-Rust expression.
fn arg(a: &ArgKind) -> String {
    match a {
        ArgKind::Imm(v) if *v >= 0x1000 => format!("{v:#x}"),
        ArgKind::Imm(v) => format!("{v}"),
        ArgKind::Field(o) => format!("rd(_, {o:#x})"),
        ArgKind::Global(a) => format!("g({a:#010x})"),
        ArgKind::LocalAddr => "&local".to_string(),
        ArgKind::Other => "_".to_string(),
    }
}

/// Render a non-terminator instruction as a pseudo-Rust line, or `None` to omit it (a pure
/// register shuffle that carries no portable structural fact).
fn render_instr(pe: &Pe, instr: &Instruction, prior: &[Instruction]) -> Option<String> {
    match instr.flow_control() {
        FlowControl::Call => {
            let t = instr.near_branch_target();
            if t == 0 {
                return Some("(*indirect)();              // indirect call".to_string());
            }
            let cs = recover_call_site(pe, prior, t);
            let mut a: Vec<String> = Vec::new();
            if let Some(x) = cs.ecx {
                a.push(arg(&x));
            }
            if let Some(x) = cs.edx {
                a.push(arg(&x));
            }
            a.extend(cs.stack.iter().map(arg));
            return Some(format!("sub_{t:08x}({});", a.join(", ")));
        }
        FlowControl::IndirectCall => {
            return Some("(*vtbl[?])();              // indirect/virtual call".to_string())
        }
        _ => {}
    }
    // Memory store / load and globals — the portable field/global facts. Stack-local and bare
    // absolute accesses (prologue / locals) are omitted to keep the skeleton a skeleton.
    if instr.mnemonic() == Mnemonic::Mov {
        if instr.op0_kind() == OpKind::Memory {
            let src = match instr.op1_kind() {
                OpKind::Immediate8
                | OpKind::Immediate8to16
                | OpKind::Immediate8to32
                | OpKind::Immediate16
                | OpKind::Immediate32 => format!("{:#x}", instr.immediate(1)),
                OpKind::Register => reg(instr.op1_register()),
                _ => "_".to_string(),
            };
            return match mem_of(pe, instr) {
                Mem::Field(b, d) => Some(format!("wr({b}, {d:#x}, {src});")),
                Mem::Global(va) => Some(format!("s({va:#010x}, {src});")),
                Mem::Other => None,
            };
        }
        if instr.op1_kind() == OpKind::Memory && instr.op0_kind() == OpKind::Register {
            let dst = reg(instr.op0_register());
            return match mem_of(pe, instr) {
                Mem::Field(b, d) => Some(format!("let {dst} = rd({b}, {d:#x});")),
                Mem::Global(va) => Some(format!("let {dst} = g({va:#010x});")),
                Mem::Other => None,
            };
        }
    }
    None
}

/// Classified memory operand: a struct field `[reg+disp]`, an in-image global `[abs]`, or other
/// (stack local / unmapped absolute) which the skeleton omits.
enum Mem {
    Field(String, u64),
    Global(u64),
    Other,
}
fn mem_of(pe: &Pe, instr: &Instruction) -> Mem {
    let base = instr.memory_base();
    let disp = instr.memory_displacement64();
    if base == Register::None && instr.memory_index() == Register::None {
        if pe.section_of(disp).is_some() {
            return Mem::Global(disp);
        }
        return Mem::Other;
    }
    if base == Register::ESP || base == Register::EBP || base == Register::None {
        return Mem::Other;
    }
    Mem::Field(reg(base), disp)
}

/// Render a block terminator as pseudo-Rust control flow.
fn render_terminator(
    instr: &Instruction,
    last_cmp: Option<&Instruction>,
    fmt: &mut NasmFormatter,
) -> String {
    match instr.flow_control() {
        FlowControl::Return | FlowControl::Interrupt => "return;".to_string(),
        FlowControl::UnconditionalBranch => {
            format!("break 'L{:08x};   // jmp", instr.near_branch_target())
        }
        FlowControl::IndirectBranch => {
            format!("match _ {{ /* switch */ }}   // {}", asm(fmt, instr))
        }
        FlowControl::ConditionalBranch => {
            let cond = render_cond(instr, last_cmp, fmt);
            format!(
                "if {cond} {{ break 'L{:08x}; }}   // {}",
                instr.near_branch_target(),
                asm(fmt, instr)
            )
        }
        _ => format!("// {}", asm(fmt, instr)),
    }
}

/// Best-effort condition for a `Jcc`, using the preceding `CMP`/`TEST` operands.
fn render_cond(
    jcc: &Instruction,
    last_cmp: Option<&Instruction>,
    fmt: &mut NasmFormatter,
) -> String {
    let relop = match jcc.mnemonic() {
        Mnemonic::Je => "==",
        Mnemonic::Jne => "!=",
        Mnemonic::Jl | Mnemonic::Jb => "<",
        Mnemonic::Jle | Mnemonic::Jbe => "<=",
        Mnemonic::Jg | Mnemonic::Ja => ">",
        Mnemonic::Jge | Mnemonic::Jae => ">=",
        Mnemonic::Js => "< 0 //(sign)",
        Mnemonic::Jns => ">= 0 //(sign)",
        _ => "?",
    };
    match last_cmp {
        Some(c) if c.mnemonic() == Mnemonic::Test => {
            // TEST a,a ; Jz  → a == 0
            format!("(cond {} {relop} 0)", asm_operands(c, fmt))
        }
        Some(c) => {
            let ops = asm_operands(c, fmt);
            // "a, b" → "a <relop> b"
            if let Some((a, b)) = ops.split_once(", ") {
                format!("{a} {relop} {b}")
            } else {
                format!("({ops}) {relop} 0")
            }
        }
        None => format!("(flags) {relop} 0"),
    }
}

/// Operand text of an instruction (drops the mnemonic).
fn asm_operands(instr: &Instruction, fmt: &mut NasmFormatter) -> String {
    let s = asm(fmt, instr);
    s.split_once(' ').map(|x| x.1).unwrap_or(&s).to_string()
}
