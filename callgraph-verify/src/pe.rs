//! Minimal, dependency-free PE32 reader — just enough to map a virtual address
//! (VA) to file bytes. We deliberately hand-parse the headers instead of pulling
//! in `goblin`/`object`: the contract is "pure byte", and the only thing the
//! disassembler needs is `va -> &[machine code bytes]`.

use std::sync::atomic::{AtomicU64, Ordering};

/// A loaded PE image: the raw file plus the parsed section table.
pub struct Pe {
    data: Vec<u8>,
    pub image_base: u64,
    sections: Vec<Section>,
    /// Process-unique identity assigned at parse time. Whole-image derived
    /// caches (instruction starts, branch targets) key on this so two
    /// same-layout PEs with different bytes can never share an entry — the
    /// layout-only key they used before was the input-ignoring-cache class
    /// of BUG #9. In production the macro holds ONE `Arc<Pe>` per exe path,
    /// so one id per binary; tests that build many synthetic PEs each get
    /// their own entries.
    id: u64,
}

fn next_pe_id() -> u64 {
    static NEXT_ID: AtomicU64 = AtomicU64::new(1);
    NEXT_ID.fetch_add(1, Ordering::Relaxed)
}

#[derive(Clone, Debug)]
pub struct Section {
    pub name: String,
    pub virtual_address: u32, // RVA
    pub virtual_size: u32,
    pub raw_offset: u32,
    pub raw_size: u32,
    /// Section characteristics (PE32 section-table `Characteristics` field).
    /// Use [`Section::is_executable`] / [`Section::is_code`] to test the
    /// relevant flags without remembering the bit constants.
    pub characteristics: u32,
}

/// Standard PE32 section characteristics. Kept here so callers don't have
/// to memorize the bit values.
pub mod section_flags {
    /// 0x00000020 — section contains executable code (CNT_CODE).
    pub const CODE: u32 = 0x0000_0020;
    /// 0x02000000 — section can be discarded after load (.reloc, .debug).
    pub const DISCARDABLE: u32 = 0x0200_0000;
    /// 0x20000000 — section is executable (CNT_CODE in MEM_EXECUTE form).
    pub const EXECUTE: u32 = 0x2000_0000;
    /// 0x40000000 — section is readable.
    pub const READ: u32 = 0x4000_0000;
    /// 0x80000000 — section is writable (.data, .bss).
    pub const WRITE: u32 = 0x8000_0000;
}

impl Section {
    /// True if the section contains executable code (`.text`).
    /// Code sections carry either `MEM_EXECUTE` or `CNT_CODE` (typically both).
    pub fn is_executable(&self) -> bool {
        self.characteristics & (section_flags::EXECUTE | section_flags::CODE) != 0
    }
}

fn u16(d: &[u8], o: usize) -> u16 {
    u16::from_le_bytes([d[o], d[o + 1]])
}
fn u32(d: &[u8], o: usize) -> u32 {
    u32::from_le_bytes([d[o], d[o + 1], d[o + 2], d[o + 3]])
}

impl Pe {
    pub fn load(path: &str) -> Result<Pe, String> {
        let data = std::fs::read(path).map_err(|e| format!("read {path}: {e}"))?;
        Pe::parse(data)
    }

    pub fn parse(data: Vec<u8>) -> Result<Pe, String> {
        if data.len() < 0x40 || &data[0..2] != b"MZ" {
            return Err("not an MZ image".into());
        }
        let e_lfanew = u32(&data, 0x3c) as usize;
        if data.len() < e_lfanew + 24 || &data[e_lfanew..e_lfanew + 4] != b"PE\0\0" {
            return Err("bad PE signature".into());
        }
        let coff = e_lfanew + 4;
        let machine = u16(&data, coff);
        if machine != 0x014c {
            return Err(format!("expected i386 (0x14c), got {machine:#06x}"));
        }
        let num_sections = u16(&data, coff + 2) as usize;
        let opt_size = u16(&data, coff + 16) as usize;
        let opt = coff + 20;
        let magic = u16(&data, opt);
        if magic != 0x10b {
            return Err(format!("expected PE32 (0x10b), got {magic:#06x}"));
        }
        let image_base = u32(&data, opt + 28) as u64;

        let sec_table = opt + opt_size;
        let mut sections = Vec::with_capacity(num_sections);
        for i in 0..num_sections {
            let s = sec_table + i * 40;
            if s + 40 > data.len() {
                return Err("section table runs past EOF".into());
            }
            let raw_name = &data[s..s + 8];
            let end = raw_name.iter().position(|&b| b == 0).unwrap_or(8);
            sections.push(Section {
                name: String::from_utf8_lossy(&raw_name[..end]).into_owned(),
                virtual_size: u32(&data, s + 8),
                virtual_address: u32(&data, s + 12),
                raw_size: u32(&data, s + 16),
                raw_offset: u32(&data, s + 20),
                characteristics: u32(&data, s + 36),
            });
        }
        Ok(Pe {
            data,
            image_base,
            sections,
            id: next_pe_id(),
        })
    }

    /// Process-unique id assigned at parse time (see the field docs).
    pub fn id(&self) -> u64 {
        self.id
    }

    /// The section containing `va`, if any.
    pub fn section_of(&self, va: u64) -> Option<&Section> {
        let rva = va.checked_sub(self.image_base)? as u32;
        self.sections.iter().find(|s| {
            // Use the larger of virtual/raw size so the boundary check never
            // excludes a byte that is actually present on disk.
            let span = s.virtual_size.max(s.raw_size);
            rva >= s.virtual_address && rva < s.virtual_address + span
        })
    }

    /// Read up to `len` bytes of file data starting at virtual address `va`.
    /// Returns fewer bytes near the end of a section's raw data (never reads
    /// across a section boundary or into uninitialized/BSS tail).
    pub fn read(&self, va: u64, len: usize) -> Option<&[u8]> {
        let sec = self.section_of(va)?;
        let rva = (va - self.image_base) as u32;
        let off_in_sec = rva - sec.virtual_address;
        if off_in_sec >= sec.raw_size {
            return None; // inside virtual_size but past raw data (BSS) → no bytes
        }
        let file_off = (sec.raw_offset + off_in_sec) as usize;
        let avail = (sec.raw_size - off_in_sec) as usize;
        let take = len.min(avail).min(self.data.len().saturating_sub(file_off));
        Some(&self.data[file_off..file_off + take])
    }

    /// Iterate over all sections in the PE
    pub fn sections(&self) -> &[Section] {
        &self.sections
    }

    pub fn is_executable_va(&self, va: u64) -> bool {
        // A VA is "decodeable" iff it lies inside some section that has
        // readable bytes on disk. The PE32 `Characteristics` flags are
        // available via [`Section::is_executable`] for callers that
        // want the stricter check (e.g. to skip `.rdata` when enumerating
        // functions), but the disassembler's own gate stays permissive:
        // any section with bytes here is fair game, mirroring the
        // pre-flag-based behavior so synthetic / oddball PEs without
        // characteristic flags still decode. The OS loader rounds
        // sections to page granularity regardless, so a `CALL [0xABCD]`
        // into `.text` from inside `.text` works at runtime whether the
        // section is flagged executable or not.
        self.section_of(va).is_some()
    }

    /// True if `va` lies inside a section whose PE32 `Characteristics` mark it
    /// as code (`CNT_CODE` or `MEM_EXECUTE`) — the STRICT counterpart of
    /// [`Pe::is_executable_va`]. Use this when deciding whether an immediate /
    /// stored dword plausibly denotes a FUNCTION (it lives in `.text`), as
    /// opposed to data (a `.rdata` vtable VA, a string address) that merely
    /// happens to sit inside the image.
    pub fn is_executable_section_va(&self, va: u64) -> bool {
        self.section_of(va)
            .map(|s| s.is_executable())
            .unwrap_or(false)
    }

    /// The image's VA range `[image_base, end)` (end = highest section end).
    pub fn image_range(&self) -> (u64, u64) {
        let end = self
            .sections
            .iter()
            .map(|s| s.virtual_address as u64 + s.virtual_size.max(s.raw_size) as u64)
            .max()
            .unwrap_or(0);
        (self.image_base, self.image_base + end)
    }

    /// Every VA the image itself "knows about": targets of every `rel32` CALL /
    /// JMP / Jcc byte pattern in `.text`, plus every little-endian u32 (read at
    /// EVERY byte offset of every section's raw data) that lands inside the image
    /// — vtable slots, switch jump tables, baked function pointers, data refs.
    ///
    /// Purpose: catch a MISATTRIBUTED or invented `origin` address. A real
    /// function entry is always reachable somehow (called, tail-jumped, or its
    /// address stored in a table), so an address referenced NOWHERE cannot be
    /// one. Over-approximate by construction (a spurious `0xE8` inside another
    /// instruction adds a junk target; a random data dword may collide) — that
    /// only ever widens the accept set, so it can't false-positive a real entry.
    pub fn referenced_addrs(&self) -> std::collections::HashSet<u32> {
        let (lo, hi) = self.image_range();
        let mut out: std::collections::HashSet<u32> = std::collections::HashSet::new();
        for sec in &self.sections {
            let start = sec.raw_offset as usize;
            let end = (start + sec.raw_size as usize).min(self.data.len());
            if start >= end {
                continue;
            }
            let blob = &self.data[start..end];
            let sec_va = self.image_base + sec.virtual_address as u64;
            // rel32 branch targets — only meaningful in the code section.
            if sec.name == ".text" {
                for i in 0..blob.len().saturating_sub(4) {
                    let (op, rel_at) = match blob[i] {
                        0xE8 | 0xE9 => (blob[i], i + 1), // CALL rel32 / JMP rel32
                        0x0F if i + 6 <= blob.len() && (0x80..=0x8F).contains(&blob[i + 1]) => {
                            (blob[i + 1], i + 2) // Jcc rel32
                        }
                        _ => continue,
                    };
                    let _ = op;
                    if rel_at + 4 > blob.len() {
                        continue;
                    }
                    let rel = i32::from_le_bytes([
                        blob[rel_at],
                        blob[rel_at + 1],
                        blob[rel_at + 2],
                        blob[rel_at + 3],
                    ]) as i64;
                    let t = (sec_va + (rel_at as u64 + 4)).wrapping_add(rel as u64);
                    if (lo..hi).contains(&t) {
                        out.insert(t as u32);
                    }
                }
            }
            // Absolute in-image dwords at every offset (vtables, jump tables, fn ptrs).
            for w in blob.windows(4) {
                let v = u32::from_le_bytes([w[0], w[1], w[2], w[3]]) as u64;
                if (lo..hi).contains(&v) {
                    out.insert(v as u32);
                }
            }
        }
        out
    }
}
