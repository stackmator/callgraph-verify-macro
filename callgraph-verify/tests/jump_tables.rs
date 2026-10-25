//! Jump-table harvest regression tests: no toolchain needed.
//!
//! Watcom-style switches lower the index scaling into a separate `shl` and
//! dispatch through a plain `[reg+TABLE]` with NO SIB index (e.g.
//! FALL.EXE `0x602c0`: `shl eax,2` then `jmp dword ptr cs:[eax+0x502D8]`).
//! `follow_jump_table` only followed SIB-indexed tables, so case bodies
//! reachable only through the table were invisible to the gate: bodies
//! calling them looked HALLUCINATED, and omitting them could never trip
//! MISSING. The fix recovers no-index tables too (plus fallthrough
//! coverage of the first case). These tests pin both shapes using a
//! hand-built PE32 -- no toolchain, runs everywhere including CI.
use callgraph_verify::{analyze, Pe};

/// Minimal PE32 image with one `.text` section. VA base is 0x401000;
/// `text[i]` lives at VA `0x401000 + i`.
fn build_pe(text: &[u8]) -> Vec<u8> {
    let image_base: u32 = 0x0040_0000;
    let text_va: u32 = 0x1000;
    let text_raw: u32 = 0x600;
    let e_lfanew: u32 = 0x40;
    let mut data: Vec<u8> = vec![0; 0x400 + text_raw as usize];
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
    let sec = opt + 0x60;
    data[sec..sec + 8].copy_from_slice(b".text\0\0\0");
    data[sec + 8..sec + 12].copy_from_slice(&text_raw.to_le_bytes());
    data[sec + 12..sec + 16].copy_from_slice(&text_va.to_le_bytes());
    data[sec + 16..sec + 20].copy_from_slice(&text_raw.to_le_bytes());
    data[sec + 20..sec + 24].copy_from_slice(&0x200u32.to_le_bytes());
    data[sec + 36..sec + 40].copy_from_slice(&0x60000020u32.to_le_bytes());
    data[0x200..0x200 + text.len()].copy_from_slice(text);
    data
}

const BASE: u32 = 0x401000;

/// Tiny assembler: tracks the current VA and patches rel32/rel8/jump-table
/// entries by construction, so no hand-computed offsets.
struct Asm {
    buf: Vec<u8>,
}

impl Asm {
    fn new() -> Self {
        Self { buf: vec![0; 0x600] }
    }
    fn bytes_at(&mut self, off: usize, b: &[u8]) {
        self.buf[off..off + b.len()].copy_from_slice(b);
    }
    /// absolute VA of buffer offset `off`.
    fn va_of(off: usize) -> u32 {
        BASE + off as u32
    }
    /// Emit `E8 rel32` calling `target` from the current end; returns start VA.
    fn emit_call(&mut self, at: usize, target_va: u32) -> u32 {
        let next = Self::va_of(at) + 5;
        let rel = target_va.wrapping_sub(next) as i32;
        self.buf[at] = 0xE8;
        self.buf[at + 1..at + 5].copy_from_slice(&rel.to_le_bytes());
        Self::va_of(at)
    }
    /// Emit `EB rel8` jumping to `target`; caller ensures it fits.
    fn emit_jmp8(&mut self, at: usize, target_va: u32) {
        let next = Self::va_of(at) + 2;
        let rel = target_va.wrapping_sub(next) as i32;
        assert!((-128..128).contains(&rel), "rel8 out of range");
        self.buf[at] = 0xEB;
        self.buf[at + 1] = rel as u8;
    }
    /// Emit `JA rel8` (77 cb) jumping to `target`.
    fn emit_ja(&mut self, at: usize, target_va: u32) {
        let next = Self::va_of(at) + 2;
        let rel = target_va.wrapping_sub(next) as i32;
        assert!((0..128).contains(&rel), "rel8 out of range");
        self.buf[at] = 0x77;
        self.buf[at + 1] = rel as u8;
    }
    /// Write a u32 jump-table entry.
    fn emit_u32(&mut self, at: usize, v: u32) {
        self.buf[at..at + 4].copy_from_slice(&v.to_le_bytes());
    }
    fn finish(self) -> Vec<u8> {
        build_pe(&self.buf)
    }
}

fn load_bytes(name: &str, bytes: &[u8]) -> Pe {
    let mut p = std::env::temp_dir();
    p.push(name);
    std::fs::write(&p, bytes).unwrap();
    Pe::load(p.to_str().unwrap()).expect("load synthetic PE")
}

/// Layout A (no-index Watcom form -- the 0x602c0 shape):
///   switch @0x401000: push ebp; mov ebp,esp; mov eax,[ebp+8];
///     cmp eax,2; ja DEFAULT; shl eax,2; jmp [eax+0x401040]
///   case0 @0x401014: call t0; jmp OUT
///   case1 @0x40101B: call t1; jmp OUT
///   case2 @0x401022: call t2; jmp OUT
///   DEFAULT @0x401029: mov eax,-1 (falls into OUT)
///   OUT @0x40102E: ret
///   TABLE @0x401040: [case0, case1, case2]
///   t0 @0x401100, t1 @0x401110, t2 @0x401120: ret
fn image_no_index_table() -> Vec<u8> {
    let mut a = Asm::new();
    // switch_fn @0x00.
    a.bytes_at(0x00, &[0x55, 0x89, 0xE5]);
    a.bytes_at(0x03, &[0x8B, 0x45, 0x08]);
    a.bytes_at(0x06, &[0x83, 0xF8, 0x02]);
    a.emit_ja(0x09, 0x401000 + 0x29); // -> DEFAULT
    a.bytes_at(0x0B, &[0xC1, 0xE0, 0x02]); // shl eax,2
                                          // jmp dword [eax+0x401040]: no SIB index.
    a.bytes_at(0x0E, &[0xFF, 0xA0, 0x40, 0x10, 0x40, 0x00]);
    // case bodies (contiguous, each ends with jmp OUT).
    let t0 = 0x100u32;
    let t1 = 0x110u32;
    let t2 = 0x120u32;
    let out = 0x2Eu32;
    a.emit_call(0x14, 0x401000 + t0);
    a.emit_jmp8(0x19, 0x401000 + out);
    a.emit_call(0x1B, 0x401000 + t1);
    a.emit_jmp8(0x20, 0x401000 + out);
    a.emit_call(0x22, 0x401000 + t2);
    a.emit_jmp8(0x27, 0x401000 + out);
    // DEFAULT @0x29: mov eax,-1 (falls into OUT).
    a.bytes_at(0x29, &[0xB8, 0xFF, 0xFF, 0xFF, 0xFF]);
    // OUT @0x2E.
    a.bytes_at(0x2E, &[0xC3]);
    // TABLE @0x40.
    a.emit_u32(0x40, 0x401014);
    a.emit_u32(0x44, 0x40101B);
    a.emit_u32(0x48, 0x401022);
    // targets.
    a.bytes_at(0x100, &[0xC3]);
    a.bytes_at(0x110, &[0xC3]);
    a.bytes_at(0x120, &[0xC3]);
    a.finish()
}

/// Layout B (SIB-indexed form -- the shape `follow_jump_table` handles):
///   switch @0x401200: push ebp; mov ebp,esp; mov eax,[ebp+8];
///     cmp eax,1; ja DEFAULT; jmp [eax*4+0x401440]
///   caseB0 @0x401212: call t3; jmp OUT
///   caseB1 @0x401219: call t4; jmp OUT
///   DEFAULT @0x40121F: mov eax,-1 (falls into OUT)
///   OUT @0x401224: ret
///   TABLE2 @0x401440: [caseB0, caseB1]
///   t3 @0x401500, t4 @0x401510: ret
fn image_sib_table() -> Vec<u8> {
    let mut a = Asm::new();
    const B: usize = 0x200; // function base (file offset within .text)
    a.bytes_at(B + 0x00, &[0x55, 0x89, 0xE5]);
    a.bytes_at(B + 0x03, &[0x8B, 0x45, 0x08]);
    a.bytes_at(B + 0x06, &[0x83, 0xF8, 0x01]);
    a.emit_ja(B + 0x09, 0x401000 + (B + 0x1F) as u32); // -> DEFAULT
    // jmp dword [eax*4+TABLE]: FF /4, mod=00 rm=100 (SIB follows),
    // SIB scale=2 index=eax base=101 (disp32-only, no base). 7 bytes.
    a.bytes_at(
        B + 0x0B,
        &[0xFF, 0x24, 0x85, 0x40, 0x14, 0x40, 0x00],
    );
    // caseB0.
    a.emit_call(B + 0x12, 0x401500); // -> t3
    a.emit_jmp8(B + 0x17, 0x401000 + (B + 0x24) as u32); // -> OUT
    // caseB1.
    a.emit_call(B + 0x19, 0x401510); // -> t4
    a.emit_jmp8(B + 0x1E, 0x401000 + (B + 0x24) as u32); // -> OUT
    // DEFAULT @B+0x1F: mov eax,-1 (falls into OUT).
    a.bytes_at(B + 0x1F, &[0xB8, 0xFF, 0xFF, 0xFF, 0xFF]);
    // OUT @B+0x24.
    a.bytes_at(B + 0x24, &[0xC3]);
    // TABLE2 @ file offset 0x640 == VA 0x401440.
    a.emit_u32(0x440, 0x401000 + (B + 0x12) as u32);
    a.emit_u32(0x444, 0x401000 + (B + 0x19) as u32);
    // t3/t4.
    a.bytes_at(0x500, &[0xC3]);
    a.bytes_at(0x510, &[0xC3]);
    a.finish()
}

#[test]
fn watcom_plain_index_table_recovers_case_calls() {
    let pe = load_bytes("jump_table_noindex.exe", &image_no_index_table());
    let cg = analyze(&pe, 0x401000).expect("analyze switch fn");
    assert_eq!(
        cg.indirect_jumps, 1,
        "expected exactly one indirect dispatch jump"
    );
    for target in [0x401100u64, 0x401110, 0x401120] {
        assert!(
            cg.direct_calls.contains_key(&target),
            "case call to {target:#x} missing from call set (found: {:?})",
            cg.direct_calls.keys().collect::<Vec<_>>(),
        );
    }
}

#[test]
fn sib_indexed_table_still_recovers_case_calls() {
    let pe = load_bytes("jump_table_sib.exe", &image_sib_table());
    let cg = analyze(&pe, 0x401200).expect("analyze SIB switch fn");
    assert_eq!(
        cg.indirect_jumps, 1,
        "expected exactly one indirect dispatch jump"
    );
    for target in [0x401500u64, 0x401510] {
        assert!(
            cg.direct_calls.contains_key(&target),
            "case call to {target:#x} missing from call set (found: {:?})",
            cg.direct_calls.keys().collect::<Vec<_>>(),
        );
    }
}
