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
                    if (lo..hi).contains(&t) {
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
    /// Back-edges (a branch to a block at/under its own start) — natural loops.
    pub loops: usize,
    /// Total case count across jump-table switches.
    pub switch_cases: usize,
    /// Conditional-branch terminators.
    pub conditionals: usize,
    /// Return / interrupt terminators.
    pub returns: usize,
}

/// Compute the coarse CFG fingerprint of the function at `entry`. Counts what is reasonably stable
/// across optimization (loops, jump-table switches) plus raw conditional/return counts; the caller
/// should compare these tolerantly (optimized CFGs do not map 1:1 to source).
pub fn cfg_fingerprint(pe: &Pe, entry: u64) -> Result<CfgFingerprint, String> {
    if !pe.is_executable_va(entry) {
        return Err(format!("{entry:#010x} is not inside any PE section"));
    }
    let (lo, hi) = (entry, entry.saturating_add(MAX_SPAN));
    let (instrs, leaders) = decode_all(pe, entry);
    let addrs: Vec<u64> = instrs.keys().copied().collect();
    let mut fp = CfgFingerprint::default();
    for &ld in &leaders {
        let mut idx = match addrs.binary_search(&ld) {
            Ok(i) => i,
            Err(_) => continue,
        };
        loop {
            let instr = instrs[&addrs[idx]];
            let is_term = !matches!(
                instr.flow_control(),
                FlowControl::Next | FlowControl::Call | FlowControl::XbeginXabortXend
            );
            if is_term {
                match instr.flow_control() {
                    FlowControl::ConditionalBranch => {
                        fp.conditionals += 1;
                        let t = instr.near_branch_target();
                        if t <= ld && leaders.contains(&t) {
                            fp.loops += 1;
                        }
                    }
                    FlowControl::UnconditionalBranch => {
                        let t = instr.near_branch_target();
                        if t <= ld && leaders.contains(&t) {
                            fp.loops += 1;
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
                break;
            }
            idx += 1;
            if idx >= addrs.len() || leaders.contains(&addrs[idx]) {
                break; // fell through into the next block (no own terminator)
            }
        }
    }
    Ok(fp)
}

/// Emit the reference skeleton for the function at `entry`.
pub fn emit_skeleton(pe: &Pe, entry: u64) -> Result<String, String> {
    if !pe.is_executable_va(entry) {
        return Err(format!("{entry:#010x} is not inside any PE section"));
    }
    let (instrs, leaders) = decode_all(pe, entry);
    let addrs: Vec<u64> = instrs.keys().copied().collect();

    // Build basic blocks: from each leader, consecutive instructions until the next leader or a
    // terminator. Record successors so we can spot back-edges (loops).
    struct Block {
        start: u64,
        body: Vec<Instruction>, // non-terminator instructions
        term: Option<Instruction>,
        succ: Vec<u64>, // in-range successor block starts
    }
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
            let is_term = !matches!(
                instr.flow_control(),
                FlowControl::Next | FlowControl::Call | FlowControl::XbeginXabortXend
            );
            if is_term {
                match instr.flow_control() {
                    FlowControl::ConditionalBranch => {
                        succ.push(instr.near_branch_target());
                        succ.push(instr.next_ip());
                    }
                    FlowControl::UnconditionalBranch => succ.push(instr.near_branch_target()),
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
                succ.push(addrs[idx]); // falls through into the next block
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

    // Loop heads = targets of a back-edge (successor addr <= the block's own start).
    let mut loop_heads: BTreeSet<u64> = BTreeSet::new();
    for b in &blocks {
        for &s in &b.succ {
            if s <= b.start && leaders.contains(&s) {
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
