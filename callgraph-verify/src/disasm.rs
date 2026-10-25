//! Recursive-descent function disassembly over real PE bytes (iced-x86).
//!
//! Given a function entry VA, we decode instructions and follow the function's
//! *intra-function* control flow (conditional branches + their fallthrough,
//! unconditional `JMP rel`) until every reachable path terminates at a `RET` /
//! interrupt / undecodable byte. Along the way we harvest, purely from the
//! decoded operands, every fact that lets us catch a rebuild hallucination:
//!
//!   * `direct_calls`  — targets of `CALL rel16/rel32` (the call graph proper)
//!   * `tail_calls`    — `JMP rel` leaving the body (a tail call into another fn)
//!   * `indirect_calls`/`indirect_jumps` — counts of register/memory dispatch
//!   * `vcall_slots`   — displacements of `CALL/JMP [reg+0xNN]` (vtable slots)
//!   * `iat_calls`     — absolute targets of `CALL [0x00a28xxx]` (IAT imports)
//!   * `field_offsets` — displacements of `[reg+0xNN]` accesses (struct fields),
//!     excluding ESP/EBP (those are stack locals/args)
//!   * `globals`       — absolute data addresses referenced as `[0x00bXXXXX]`
//!   * `imm_addrs`     — in-image immediates (`MOV [esi],0x00a7e38c` vtable VAs,
//!     function pointers, string-literal addresses)
//!
//! This is *structural* ground truth: no decompiler in the loop.

use crate::pe::Pe;
use iced_x86::{Decoder, DecoderOptions, FlowControl, Instruction, Mnemonic, OpKind, Register};
use std::collections::{BTreeMap, BTreeSet};

/// Upper bound on how far past the entry we follow control flow. Oblivion's
/// largest functions are a few KB; 64 KB stops a mis-decoded `JMP` from walking
/// the whole section.
const MAX_FN_SPAN: u64 = 0x10000;
/// `[reg+disp]` with disp below this is treated as a struct-field access; larger
/// displacements are almost certainly absolute addresses or noise.
const MAX_FIELD_OFFSET: u64 = 0x8000;

/// The recovered "kind" of a single call argument, harvested from the instruction that set it
/// up (a register load or a `PUSH`). Coarse on purpose — only the distinctions a faithful port
/// must preserve, and only those a short local scan can recover without false positives.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ArgKind {
    /// An immediate constant (`PUSH 0x10`, `MOV ECX,0`, `XOR ECX,ECX`).
    Imm(u64),
    /// A struct-field load `[reg+disp]` off a non-stack base (`PUSH [ESI+0xc]`).
    Field(u64),
    /// An absolute in-image data reference `[0x00bXXXXX]` (a global).
    Global(u64),
    /// Address of a stack local (`LEA ECX,[EBP-8]` / `LEA EAX,[ESP+4]`) — an out-param / temp.
    LocalAddr,
    /// Anything not confidently classified (a register value, computed expression, prior result).
    Other,
}

/// One direct call site with the argument set-up recovered by a short backward scan of its basic
/// block. `ecx`/`edx` are the fastcall/thiscall register args (the receiver lands in `ecx`); `stack`
/// is the pushed args in source (left-to-right) order. `None`/empty means "not recovered in-block".
#[derive(Debug, Clone, Default)]
pub struct CallSite {
    pub target: u64,
    pub ecx: Option<ArgKind>,
    pub edx: Option<ArgKind>,
    pub stack: Vec<ArgKind>,
}

#[derive(Debug, Default)]
pub struct CallGraph {
    pub entry: u64,
    /// Direct `CALL` targets → number of call sites hitting that target.
    pub direct_calls: BTreeMap<u64, u32>,
    /// Per-call-site recovered argument shapes (one entry per direct `CALL` instruction).
    pub call_sites: Vec<CallSite>,
    /// Direct `JMP rel` targets that leave the walked body (tail calls).
    pub tail_calls: BTreeSet<u64>,
    pub indirect_calls: u32,
    pub indirect_jumps: u32,
    /// vtable slot displacements seen in `CALL/JMP [reg+0xNN]`.
    pub vcall_slots: BTreeSet<u64>,
    /// IAT import slot addresses seen in `CALL [0x00a28xxx]`.
    pub iat_calls: BTreeSet<u64>,
    /// Struct-field displacements off a non-stack base register.
    pub field_offsets: BTreeSet<u64>,
    /// Absolute data addresses referenced as memory operands (globals).
    pub globals: BTreeSet<u64>,
    /// In-image immediate values (vtable VAs, fn pointers, string addresses).
    pub imm_addrs: BTreeSet<u64>,
    /// Highest instruction-end VA reached — the function's apparent extent.
    pub max_end: u64,
    pub decode_errors: u32,
    /// First few decode failures as `(ip, raw_bytes)`. Decoders hitting
    /// invalid opcodes is normal at padding/alignment/data boundaries, but a
    /// long run inside what is supposed to be a function usually means the
    /// entry VA is wrong, or the function crosses into embedded data. The
    /// hex bytes here are enough to tell which.
    pub decode_error_samples: Vec<(u64, Vec<u8>)>,
}

impl CallGraph {
    pub fn call_targets(&self) -> BTreeSet<u64> {
        self.direct_calls.keys().copied().collect()
    }

    /// Every in-image address this function references — call targets, tail-call
    /// JMPs, IAT slots, global data refs and baked immediates (vtable VAs / fn
    /// pointers / string addresses). Used to detect inlining: if callee C's whole
    /// footprint also appears in caller F's footprint, the binary pasted C's body
    /// into F, so a Rust call F→C is faithful (un-inlined), not hallucinated.
    pub fn footprint(&self) -> BTreeSet<u64> {
        let mut s: BTreeSet<u64> = self.direct_calls.keys().copied().collect();
        s.extend(&self.tail_calls);
        s.extend(&self.iat_calls);
        s.extend(&self.globals);
        s.extend(&self.imm_addrs);
        s
    }
}

/// Harvest every memory/immediate operand fact from one decoded instruction.
fn scan_operands(pe: &Pe, instr: &Instruction, cg: &mut CallGraph) {
    for i in 0..instr.op_count() {
        match instr.op_kind(i) {
            OpKind::Memory => {
                let base = instr.memory_base();
                let index = instr.memory_index();
                let disp = instr.memory_displacement64();
                if base == Register::None && index == Register::None {
                    // absolute `[0x...]` — a global/static data reference.
                    // Skip LEA: it computes an address without dereferencing, so
                    // the operand isn't a memory reference. (BUG #14)
                    if pe.section_of(disp).is_some() && instr.mnemonic() != Mnemonic::Lea {
                        cg.globals.insert(disp);
                    }
                } else if pe.section_of(disp).is_some()
                    && instr.mnemonic() != Mnemonic::Lea
                {
                    // Indexed `[base + index*scale + disp]` (or `[reg+disp]`)
                    // off a large in-image displacement — a table base, not a
                    // struct field (e.g. FALL.EXE `[eax*4+0x18F01]`). Record it
                    // as a global so bodies may bake the true address without
                    // tripping HALLUCINATED-ADDR. Small offsets miss
                    // `section_of` and fall through to the field branch below;
                    // LEA never dereferences (BUG #14), so it stays excluded.
                    cg.globals.insert(disp);
                } else if base != Register::None
                    && base != Register::ESP
                    && base != Register::EBP
                    && index == Register::None
                    && disp > 0
                    && disp < MAX_FIELD_OFFSET
                    // LEA computes an address (pointer math / &field), it doesn't
                    // dereference a struct field — skip it to avoid e.g. the
                    // `LEA EDX,[EAX+1]` of a strlen loop looking like field 0x1.
                    && instr.mnemonic() != Mnemonic::Lea
                {
                    // `[reg+0xNN]` off a non-stack base — a struct field access.
                    cg.field_offsets.insert(disp);
                }
            }
            OpKind::Immediate8
            | OpKind::Immediate8to16
            | OpKind::Immediate8to32
            | OpKind::Immediate16
            | OpKind::Immediate32 => {
                let v = instr.immediate(i);
                // In-image immediate = a baked address (vtable VA, fn ptr, string).
                if pe.section_of(v).is_some() {
                    cg.imm_addrs.insert(v);
                }
            }
            _ => {}
        }
    }
}

/// Classify operand `i` of `instr` as an argument kind (immediate / field / global / other).
fn classify_operand(pe: &Pe, instr: &Instruction, i: u32) -> ArgKind {
    match instr.op_kind(i) {
        OpKind::Immediate8
        | OpKind::Immediate8to16
        | OpKind::Immediate8to32
        | OpKind::Immediate16
        | OpKind::Immediate32 => ArgKind::Imm(instr.immediate(i)),
        OpKind::Memory => {
            let base = instr.memory_base();
            let index = instr.memory_index();
            let disp = instr.memory_displacement64();
            if base == Register::None && index == Register::None {
                if pe.section_of(disp).is_some() {
                    ArgKind::Global(disp)
                } else {
                    ArgKind::Other
                }
            } else if base != Register::ESP
                && base != Register::EBP
                && base != Register::None
                && index == Register::None
                && disp > 0
                && disp < MAX_FIELD_OFFSET
            {
                ArgKind::Field(disp)
            } else {
                ArgKind::Other
            }
        }
        _ => ArgKind::Other,
    }
}

/// Classify the *source* of a register-setup instruction (`MOV reg,src` / `LEA reg,src` /
/// `XOR reg,reg`). Returns the arg kind the register holds going into the following `CALL`.
fn classify_reg_src(pe: &Pe, instr: &Instruction) -> ArgKind {
    match instr.mnemonic() {
        Mnemonic::Lea => {
            let base = instr.memory_base();
            if base == Register::EBP || base == Register::ESP {
                ArgKind::LocalAddr
            } else {
                ArgKind::Other // lea of a field address — not distinguished in v1
            }
        }
        Mnemonic::Xor => ArgKind::Imm(0), // only called when op0==op1 (zero idiom)
        Mnemonic::Mov | Mnemonic::Movzx | Mnemonic::Movsx => classify_operand(pe, instr, 1),
        _ => ArgKind::Other,
    }
}

/// True if `instr` writes register `reg` as its destination (op0) via a recognized setup form.
fn writes_reg(instr: &Instruction, reg: Register) -> bool {
    if instr.op0_kind() != OpKind::Register || instr.op0_register() != reg {
        return false;
    }
    match instr.mnemonic() {
        Mnemonic::Mov | Mnemonic::Lea | Mnemonic::Movzx | Mnemonic::Movsx => true,
        // XOR reg,reg is the zero idiom only when both operands are the same register.
        Mnemonic::Xor => instr.op1_kind() == OpKind::Register && instr.op1_register() == reg,
        _ => false,
    }
}

/// Recover the argument shape of a `CALL` from the instructions preceding it in its basic block
/// (`buf` excludes the CALL itself). Scans backward: the first `PUSH`es encountered are the
/// left-to-right stack args (cdecl/stdcall push right-to-left, so backward order = source order),
/// and the first writes to ECX/EDX are the fastcall/thiscall register args.
pub(crate) fn recover_call_site(pe: &Pe, buf: &[Instruction], target: u64) -> CallSite {
    let mut cs = CallSite {
        target,
        ..Default::default()
    };
    for instr in buf.iter().rev().take(64) {
        // Stop at a prologue / frame boundary: an explicit ESP adjust (`sub esp,N`) or any
        // FS-relative access (SEH frame set-up). Argument pushes never precede these, so this
        // keeps callee-saved / SEH-cookie pushes out of the recovered argument list.
        if is_frame_boundary(instr) {
            break;
        }
        if instr.mnemonic() == Mnemonic::Push {
            cs.stack.push(classify_operand(pe, instr, 0));
        } else if cs.ecx.is_none() && writes_reg(instr, Register::ECX) {
            cs.ecx = Some(classify_reg_src(pe, instr));
        } else if cs.edx.is_none() && writes_reg(instr, Register::EDX) {
            cs.edx = Some(classify_reg_src(pe, instr));
        }
    }
    cs
}

/// A prologue / stack-frame boundary that argument set-up never precedes: an `ADD/SUB ESP,imm`
/// or any instruction touching FS-relative memory (the SEH frame).
fn is_frame_boundary(instr: &Instruction) -> bool {
    if matches!(instr.mnemonic(), Mnemonic::Add | Mnemonic::Sub)
        && instr.op0_kind() == OpKind::Register
        && instr.op0_register() == Register::ESP
    {
        return true;
    }
    (0..instr.op_count())
        .any(|i| instr.op_kind(i) == OpKind::Memory && instr.memory_segment() == Register::FS)
}

/// If `addr` is a one-instruction thunk (`JMP target`), return `target`. Callers often invoke a
/// function through such a thunk (a tail-jump stub, or `/OPT:ICF`-folded forwarder), so the byte
/// call edge points at the thunk, not the real callee — following it one level lets the call-graph
/// check see the true target.
pub fn resolve_thunk(pe: &Pe, addr: u64) -> Option<u64> {
    let bytes = pe.read(addr, 16)?;
    let mut dec = Decoder::with_ip(32, bytes, addr, DecoderOptions::NONE);
    if !dec.can_decode() {
        return None;
    }
    let instr = dec.decode();
    if instr.flow_control() == FlowControl::UnconditionalBranch {
        let t = instr.near_branch_target();
        if t != 0 {
            return Some(t);
        }
    }
    None
}

/// Does `instr` *read* `reg` (as a source register or a memory base/index)? Excludes the
/// destination register operand (op0) so a pure write like `MOV ECX,EAX` doesn't count as a read.
fn reads_reg(instr: &Instruction, reg: Register) -> bool {
    for i in 0..instr.op_count() {
        match instr.op_kind(i) {
            OpKind::Memory => {
                if instr.memory_base() == reg || instr.memory_index() == reg {
                    return true;
                }
            }
            OpKind::Register if i > 0 && instr.op_register(i) == reg => {
                return true;
            }
            _ => {}
        }
    }
    false
}

/// Heuristically determine whether the function at `addr` takes register parameters in ECX / EDX
/// (i.e. is thiscall/fastcall). Scans the entry block for a READ of the register before any write:
/// thiscall reads ECX (the `this`), fastcall also reads EDX, cdecl/stdcall read neither. Used to
/// align a caller's recovered register args to the callee's actual parameters (so a stray EDX in a
/// caller is not mistaken for an argument to a thiscall callee). Conservative: under-detection just
/// means a position is skipped, never a false mismatch.
pub fn reg_params(pe: &Pe, addr: u64) -> (bool, bool) {
    let Some(bytes) = pe.read(addr, 32 * 32) else {
        return (false, false);
    };
    let mut dec = Decoder::with_ip(32, bytes, addr, DecoderOptions::NONE);
    let mut instr = Instruction::default();
    let (mut ecx_written, mut edx_written) = (false, false);
    let (mut ecx_param, mut edx_param) = (false, false);
    let mut n = 0;
    while dec.can_decode() && n < 24 {
        dec.decode_out(&mut instr);
        if instr.is_invalid() {
            break;
        }
        if !ecx_written && reads_reg(&instr, Register::ECX) {
            ecx_param = true;
        }
        if !edx_written && reads_reg(&instr, Register::EDX) {
            edx_param = true;
        }
        if instr.op0_kind() == OpKind::Register {
            match instr.op0_register() {
                Register::ECX => ecx_written = true,
                Register::EDX => edx_written = true,
                _ => {}
            }
        }
        // A leaf that immediately forwards its incoming registers to another call is still
        // thiscall/fastcall even though iced-x86 cannot represent the implicit register use on
        // the CALL itself. Preserve untouched ECX/EDX on the first instruction so constructors
        // such as BSScissorTriShape (which forwards both registers to its base ctor) align stack
        // arguments correctly. Later calls retain the caller-saved rule below.
        if n == 0
            && matches!(instr.flow_control(), FlowControl::Call)
            && instr.near_branch_target() != instr.next_ip()
        {
            if !ecx_written {
                ecx_param = true;
            }
            if !edx_written {
                edx_param = true;
            }
        }
        // Per the x86 cdecl/fastcall/thiscall conventions, ECX and EDX are caller-saved:
        // any CALL in the entry block clobbers them, so a later READ of ECX/EDX is not
        // evidence that the callee takes that register as a parameter. Mark them written
        // across the CALL — without this, a stray `MOV EAX, [ECX]` after a prior CALL
        // would falsely set `ecx_param = true` and pollute ARG-SHAPE diffs.
        if matches!(instr.flow_control(), FlowControl::Call) {
            ecx_written = true;
            edx_written = true;
        }
        if !matches!(instr.flow_control(), FlowControl::Next | FlowControl::Call) {
            break;
        }
        n += 1;
    }
    (ecx_param, edx_param)
}

/// Walk the function at `entry` and return its facts, sourced purely from bytes.
pub fn analyze(pe: &Pe, entry: u64) -> Result<CallGraph, String> {
    if !pe.is_executable_va(entry) {
        return Err(format!(
            "{entry:#010x} is not inside any PE section of this image\n{}",
            pe.describe_sections(entry)
        ));
    }
    let mut cg = CallGraph {
        entry,
        ..Default::default()
    };
    let lo = entry;
    let hi = entry.saturating_add(MAX_FN_SPAN);

    let mut work = vec![entry];
    let mut seen: BTreeSet<u64> = BTreeSet::new();
    // Per-branch-target seed: when we encounter `Jcc target` / `JMP target` /
    // indirect-jump case, the args set up before the branch (PUSHes, MOV-to-ECX,
    // etc.) also apply to the target block's first CALL — the predecessor and
    // target share the same register/stack state at the branch instruction. The
    // outer loop resets `block_buf` when it pops a new `start`, so without this
    // seed map the target's calls would be processed with an empty `block_buf`
    // and `recover_call_site` would undercount arguments. (BUG #8 fix.)
    //
    // Multiple predecessors may push the same target — `entry().or_insert_with`
    // keeps the FIRST push, since the args are equivalent along either path up
    // to the branch instruction itself (the differing branches only affect the
    // value of flags, which `recover_call_site` doesn't read).
    let mut branch_seed: std::collections::HashMap<u64, Vec<Instruction>> =
        std::collections::HashMap::new();

    while let Some(start) = work.pop() {
        if !seen.insert(start) {
            continue;
        }
        let Some(bytes) = pe.read(start, 32 * 64) else {
            continue;
        };
        let mut dec = Decoder::with_ip(32, bytes, start, DecoderOptions::NONE);
        let mut instr = Instruction::default();
        // Straight-line instruction buffer for the current block, used to recover the argument
        // set-up preceding each CALL. Reset at block boundaries (branches) and after each call.
        // For non-entry `start`s, seed from the predecessor branch (see `branch_seed`).
        let mut block_buf: Vec<Instruction> = branch_seed.remove(&start).unwrap_or_default();

        loop {
            if !dec.can_decode() {
                break;
            }
            let ip = dec.ip();
            if ip != start && seen.contains(&ip) {
                break; // block already covered by another path
            }
            if ip > start {
                seen.insert(ip);
            }
            dec.decode_out(&mut instr);
            if instr.is_invalid() {
                cg.decode_errors += 1;
                // Keep up to 5 samples so the user can tell at a glance
                // whether the failures are padding (single 0x00/0xCC/0x90),
                // an aligned jump table (4 distinct bytes), or something
                // structural (random bytes that decode to nothing — entry
                // VA is probably wrong).
                if cg.decode_error_samples.len() < 5 {
                    let bytes = pe.read(ip, 8).unwrap_or(&[]).to_vec();
                    cg.decode_error_samples.push((ip, bytes));
                }
                break;
            }
            cg.max_end = cg.max_end.max(instr.next_ip());
            scan_operands(pe, &instr, &mut cg);
            block_buf.push(instr);

            match instr.flow_control() {
                FlowControl::Call => {
                    let t = instr.near_branch_target();
                    if t != 0 {
                        *cg.direct_calls.entry(t).or_insert(0) += 1;
                        let prior = &block_buf[..block_buf.len() - 1]; // exclude the CALL itself
                        let cs = recover_call_site(pe, prior, t);
                        cg.call_sites.push(cs);
                    }
                    block_buf.clear(); // args after a call start fresh
                }
                FlowControl::IndirectCall => {
                    cg.indirect_calls += 1;
                    record_indirect_target(&instr, pe, &mut cg);
                    block_buf.clear(); // an indirect call's args must not leak into the next call
                }
                FlowControl::ConditionalBranch => {
                    let t = instr.near_branch_target();
                    if (lo..hi).contains(&t) {
                        branch_seed.entry(t).or_insert_with(|| block_buf.clone());
                        work.push(t);
                    } else {
                        cg.tail_calls.insert(t);
                    }
                    // Don't clear `block_buf` here: the args set up before the
                    // conditional apply to BOTH the taken and the fallthrough
                    // paths (they share register/stack state at the branch).
                    // Clearing would make the fallthrough's first CALL recover
                    // an empty argument set. The buffer is reset by the next
                    // CALL we encounter (Call/IndirectCall arms above clear
                    // post-call) or by an explicit boundary.
                }
                FlowControl::UnconditionalBranch => {
                    let t = instr.near_branch_target();
                    if (lo..hi).contains(&t) {
                        branch_seed.entry(t).or_insert_with(|| block_buf.clone());
                        work.push(t);
                    } else {
                        cg.tail_calls.insert(t);
                    }
                    break;
                }
                FlowControl::IndirectBranch => {
                    cg.indirect_jumps += 1;
                    record_indirect_target(&instr, pe, &mut cg);
                    let mut cases: Vec<u64> = Vec::new();
                    follow_jump_table(&instr, pe, lo, hi, &mut cases);
                    for c in &cases {
                        branch_seed.entry(*c).or_insert_with(|| block_buf.clone());
                        work.push(*c);
                    }
                    break;
                }
                FlowControl::Return | FlowControl::Exception => break,
                // NOTE: `Interrupt` (`int n`) is deliberately NOT terminal:
                // DOS `int 21h` / DPMI `int 31h` are API calls that return
                // normally, so decoding must continue at `next_ip()`.
                // Treating them like `ret` truncated listings and hid
                // calls reachable only via post-`int` fallthrough.
                FlowControl::Next | FlowControl::Interrupt | FlowControl::XbeginXabortXend => {}
            }
        }
    }
    Ok(cg)
}

/// Addresses a tail-call target references (its globals, baked immediates,
/// and IAT slots), unioned over every `JMP`-out edge of `cg`.
///
/// A tail-call `JMP G` transfers control to G, so G's data references execute
/// as part of THIS function. The call-graph diff (`diff_body_calls`) already
/// counts a tail target's *callees* as acceptable spellings; this is the
/// address-side mirror for the HALLUCINATED-ADDR check: a port that
/// duplicates a shared tail body (e.g. a predicate tail-jumped into from two
/// origins) bakes the tail's addresses faithfully. Only ever ADDS acceptance
/// — a target that fails to analyze is skipped, never an error.
pub fn tail_referenced(pe: &Pe, cg: &CallGraph) -> BTreeSet<u64> {
    let mut out = BTreeSet::new();
    for t in &cg.tail_calls {
        if let Ok(tcg) = analyze(pe, *t) {
            out.extend(&tcg.globals);
            out.extend(&tcg.imm_addrs);
            out.extend(&tcg.iat_calls);
        }
    }
    out
}

/// Follow an MSVC-style `switch` jump table: `JMP dword ptr [idx*4 + TABLE_VA]`.
/// `TABLE_VA` (the operand displacement, an in-image .rdata address) holds an
/// array of u32 case addresses. We read entries until one falls outside the
/// function's `[lo, hi)` span — switch cases always point back into the function,
/// so that's a reliable terminator. Recovers the case bodies (and their `CALL`s)
/// that a plain recursive descent, unable to follow an indirect jump, would miss.
pub(crate) fn follow_jump_table(
    instr: &Instruction,
    pe: &Pe,
    lo: u64,
    hi: u64,
    work: &mut Vec<u64>,
) {
    for i in 0..instr.op_count() {
        if instr.op_kind(i) != OpKind::Memory {
            continue;
        }
        let disp = instr.memory_displacement64();
        // Need a scaled index (the case selector) and an in-image table base.
        if instr.memory_index() == Register::None || pe.section_of(disp).is_none() {
            return;
        }
        let mut k = 0u64;
        while k < 1024 {
            let Some(b) = pe.read(disp + k * 4, 4) else {
                break;
            };
            if b.len() < 4 {
                break;
            }
            let target = u32::from_le_bytes([b[0], b[1], b[2], b[3]]) as u64;
            if !(lo..hi).contains(&target) {
                break; // first entry outside the function ends the table
            }
            work.push(target);
            k += 1;
        }
        return;
    }
}

/// Classify an indirect `CALL`/`JMP [...]` target: `[reg+disp]` is a vtable slot
/// (record the displacement); `[abs]` in the IAT range is an import (record addr).
fn record_indirect_target(instr: &Instruction, pe: &Pe, cg: &mut CallGraph) {
    // The branch target operand is the (single) memory operand, if any.
    for i in 0..instr.op_count() {
        if instr.op_kind(i) == OpKind::Memory {
            let base = instr.memory_base();
            let disp = instr.memory_displacement64();
            if base == Register::None && instr.memory_index() == Register::None {
                if pe.section_of(disp).is_some() {
                    cg.iat_calls.insert(disp); // CALL [0x00a28xxx]
                }
            } else if base != Register::None && disp < MAX_FIELD_OFFSET {
                cg.vcall_slots.insert(disp); // CALL [reg+slot]
            }
            return;
        }
    }
}
