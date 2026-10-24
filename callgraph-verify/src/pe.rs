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
        let sz = data.len();
        if sz < 0x40 || &data[0..2] != b"MZ" {
            return Err(format!(
                "not an MZ image: first 2 bytes are {:?} (expected b\"MZ\"), file size = {sz} bytes",
                &data[..data.len().min(2)]
            ));
        }
        let e_lfanew = u32(&data, 0x3c) as usize;
        if data.len() >= e_lfanew + 2 && &data[e_lfanew..e_lfanew + 2] == b"LE" {
            return parse_le(data, e_lfanew);
        }
        if data.len() < e_lfanew + 24 || &data[e_lfanew..e_lfanew + 4] != b"PE\0\0" {
            // Show the e_lfanew value, the bytes at that offset, and what's there.
            // That single line is enough to tell whether the user gave us an MZ
            // wrapped around something exotic (a DOS driver, a NE/LE binary)
            // or just a corrupted PE.
            let there = data
                .get(e_lfanew..e_lfanew + 4)
                .map(|s| format!("{:02x?}", s))
                .unwrap_or_else(|| "<past EOF>".into());
            return Err(format!(
                "bad PE signature: e_lfanew = {e_lfanew:#x}, bytes there = [{there}] (expected b\"PE\\0\\0\"); file size = {sz} bytes"
            ));
        }
        let coff = e_lfanew + 4;
        let machine = u16(&data, coff);
        if machine != 0x014c {
            return Err(format!(
                "unsupported machine {machine:#06x} (expected i386 = 0x014c); this crate only decodes 32-bit x86"
            ));
        }
        let num_sections = u16(&data, coff + 2) as usize;
        let opt_size = u16(&data, coff + 16) as usize;
        let opt = coff + 20;
        let magic = u16(&data, opt);
        if magic != 0x10b {
            return Err(format!(
                "unsupported optional-header magic {magic:#06x} (expected PE32 = 0x10b); PE32+ (64-bit) and ROM images are not handled"
            ));
        }
        let image_base = u32(&data, opt + 28) as u64;

        let sec_table = opt + opt_size;
        let mut sections = Vec::with_capacity(num_sections);
        for i in 0..num_sections {
            let s = sec_table + i * 40;
            if s + 40 > data.len() {
                return Err(format!(
                    "section table runs past EOF: section #{i} would start at file offset {s:#x} \
                     (e_lfanew={e_lfanew:#x} + opt_size={opt_size:#x} + {i}*40), \
                     but file size is only {sz} bytes — corrupt header or wrong format"
                ));
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

    /// Pretty-print every section as `name [RVA..RVA+size)` with the image base
    /// baked in, plus a hint pointing at the closest section to `va` (by VA
    /// distance) so the user can immediately tell whether they mistyped an
    /// address or used the wrong file.
    pub fn describe_sections(&self, va: u64) -> String {
        let mut s = String::new();
        let mut best: Option<(&Section, u64)> = None;
        for sec in &self.sections {
            let start = self.image_base + sec.virtual_address as u64;
            let span = sec.virtual_size.max(sec.raw_size) as u64;
            let end = start + span;
            s.push_str(&format!(
                "    {name:<8} [0x{start:08x}..0x{end:08x}) ({span} bytes){flag}\n",
                name = sec.name,
                start = start,
                end = end,
                span = span,
                flag = if sec.is_executable() { " code" } else { "" },
            ));
            let d = if va < start {
                start - va
            } else { va.saturating_sub(end) };
            if best.map(|(_, bd)| d < bd).unwrap_or(true) {
                best = Some((sec, d));
            }
        }
        if let Some((sec, d)) = best {
            s.push_str(&format!(
                "  closest section to {va:#010x}: {name} (distance {d:#x} bytes) — \
                 did you mean 0x{start:08x}?",
                name = sec.name,
                start = self.image_base + sec.virtual_address as u64,
            ));
        }
        s
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
    /// function entry is always reachable somehow (called, tail-jumped — long
    /// OR short form — or its address stored in a table), so an address
    /// referenced NOWHERE cannot be one. Over-approximate by construction
    /// (a spurious `0xE8` inside another instruction adds a junk target; a
    /// random data dword may collide) — that only ever widens the accept
    /// set, so it can't false-positive a real entry.
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
            // rel8/rel32 branch targets — only meaningful in the code section.
            if sec.name == ".text" {
                for i in 0..blob.len().saturating_sub(4) {
                    // `JMP short rel8` (0xEB): the scan used to index rel32
                    // branches only, so a function reached solely via short
                    // jump (e.g. FALL.EXE `0x9dbe2`, reached only by `EB F0`
                    // from `0x9dbeb`) was invisible to ORIGIN-UNREFERENCED.
                    // Over-approximate like the rest: a stray 0xEB only
                    // widens the set.
                    if blob[i] == 0xEB && i + 2 <= blob.len() {
                        let rel = blob[i + 1] as i8 as i64;
                        let t = (sec_va + i as u64 + 2).wrapping_add(rel as u64);
                        if (lo..hi).contains(&t) {
                            out.insert(t as u32);
                        }
                    }
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

/// DOS4GW Linear Executable (LE) support — Daggerfall's FALL.EXE etc. are
/// MZ+LE, not PE. We synthesize a PE-like image so the existing
/// disassembler works unchanged:
///
/// * `image_base = 0`, `virtual_address = object reloc base`
///   (entry VA = relocbase(obj1) + EIP, e.g. 0x10000+0x8DEB4 = 0x9DEB4).
/// * First executable object is named `.text` so the existing
///   `.text`-gated caches keep working; other objects become
///   `.textN` / `.dataN`.
/// * Page map entries are 4 bytes in LE: 24-bit big-endian physical page
///   number + 8-bit flags (0 = legal). All FALL.EXE pages are flag 0 and
///   sequential; iterated/zero pages are rejected for now.
/// * `datapage` header field is a file-absolute offset (proven by
///   datapage + pages*pagesize - (pagesize-lastpagesize) == file size).
/// * Fixups are NOT applied yet: direct CALL rel32 (the call graph) is
///   unaffected, but absolute `globals`/`imm_addrs` are pre-fixup bytes.
///   Call-graph + CFG gates are sound; treat globals/vtable facts as
///   best-effort until fixup application lands.
fn parse_le(data: Vec<u8>, le_off: usize) -> Result<Pe, String> {
    let sz = data.len();
    let need = le_off + 0xAC;
    if sz < need + 4 {
        return Err(format!(
            "truncated LE header: need {need:#x} bytes for header, file size = {sz} bytes"
        ));
    }
    let at32 = |o: usize| -> Result<u32, String> {
        if o + 4 > sz {
            return Err(format!("LE header read past EOF at {o:#x}"));
        }
        Ok(u32::from_le_bytes([data[o], data[o + 1], data[o + 2], data[o + 3]]))
    };
    let at16 = |o: usize| -> Result<u16, String> {
        if o + 2 > sz {
            return Err(format!("LE header read past EOF at {o:#x}"));
        }
        Ok(u16::from_le_bytes([data[o], data[o + 1]]))
    };
    let cpu = at16(le_off + 8)?;
    if cpu != 2 {
        return Err(format!(
            "unsupported LE cpu {cpu:#x} (expected 386 = 0x2); only 32-bit x86 LE is handled"
        ));
    }
    let numpages = at32(le_off + 0x14)? as usize;
    let pagesize = at32(le_off + 0x28)? as usize;
    let lastpagesize = at32(le_off + 0x2C)? as usize;
    let objtab_rel = at32(le_off + 0x40)? as usize;
    let objcnt = at32(le_off + 0x44)? as usize;
    let pagemap_rel = at32(le_off + 0x48)? as usize;
    let itermap = at32(le_off + 0x4C)?;
    let datapage_abs = at32(le_off + 0x80)? as usize;
    if !(512..=16384).contains(&pagesize) {
        return Err(format!("implausible LE pagesize {pagesize}"));
    }
    if numpages == 0 || numpages > 100_000 {
        return Err(format!("implausible LE page count {numpages}"));
    }
    if objcnt == 0 || objcnt > 100 {
        return Err(format!("implausible LE object count {objcnt}"));
    }
    if itermap != 0 {
        return Err(format!(
            "unsupported LE iterated-data map at {itermap:#x}: iterated pages not yet supported"
        ));
    }
    let objtab = le_off.checked_add(objtab_rel).ok_or("LE objtab overflow")?;
    let pagemap = le_off.checked_add(pagemap_rel).ok_or("LE pagemap overflow")?;
    if objtab + objcnt * 24 > sz {
        return Err(format!(
            "LE object table runs past EOF: objtab={objtab:#x} + {objcnt}*24, file size {sz:#x}"
        ));
    }
    if pagemap + numpages * 4 > sz {
        return Err(format!(
            "LE page map runs past EOF: pagemap={pagemap:#x} + {numpages}*4, file size {sz:#x}"
        ));
    }
    if datapage_abs >= sz {
        return Err(format!(
            "LE data pages offset {datapage_abs:#x} past EOF (file size {sz:#x})"
        ));
    }
    // Physical page N (1-based) lives at datapage + (N-1)*pagesize,
    // except the last physical page which is lastpagesize bytes.
    // Decode the whole map first so we can validate flags.
    let mut phys_of_logical: Vec<(u32, u8)> = Vec::with_capacity(numpages);
    for i in 0..numpages {
        let o = pagemap + i * 4;
        let b0 = data[o] as u32;
        let b1 = data[o + 1] as u32;
        let b2 = data[o + 2] as u32;
        let flags = data[o + 3];
        let page = (b0 << 16) | (b1 << 8) | b2;
        if flags != 0 {
            return Err(format!(
                "unsupported LE page {i} flags={flags:#x} (page={page}): only flag-0 legal pages are supported; iterated/zero pages TODO"
            ));
        }
        if page == 0 || page as usize > numpages {
            return Err(format!(
                "LE page map entry {i} has out-of-range physical page {page} (numpages={numpages})"
            ));
        }
        phys_of_logical.push((page, flags));
    }
    let mut new_data: Vec<u8> = Vec::new();
    let mut sections: Vec<Section> = Vec::with_capacity(objcnt);
    let mut exec_seen = 0usize;
    let mut data_seen = 0usize;
    for oi in 0..objcnt {
        let o = objtab + oi * 24;
        let vsize = u32::from_le_bytes([data[o], data[o + 1], data[o + 2], data[o + 3]]) as usize;
        let base =
            u32::from_le_bytes([data[o + 4], data[o + 5], data[o + 6], data[o + 7]]) as u32;
        let flags =
            u32::from_le_bytes([data[o + 8], data[o + 9], data[o + 10], data[o + 11]]);
        let page_idx =
            u32::from_le_bytes([data[o + 12], data[o + 13], data[o + 14], data[o + 15]])
                as usize;
        let page_cnt =
            u32::from_le_bytes([data[o + 16], data[o + 17], data[o + 18], data[o + 19]])
                as usize;
        if page_idx == 0 || page_idx - 1 + page_cnt > numpages {
            return Err(format!(
                "LE object {oi} page range [{page_idx}..{}) out of 1..={numpages}",
                page_idx + page_cnt
            ));
        }
        let start = new_data.len();
        for j in 0..page_cnt {
            let (phys, _) = phys_of_logical[page_idx - 1 + j];
            let is_last_phys = phys as usize == numpages;
            let plen = if is_last_phys { lastpagesize } else { pagesize };
            let foff = datapage_abs + (phys as usize - 1) * pagesize;
            if foff + plen > sz {
                return Err(format!(
                    "LE object {oi} page {j} (phys {phys}) file range [{foff:#x}..{:#x}) past EOF {sz:#x}",
                    foff + plen
                ));
            }
            new_data.extend_from_slice(&data[foff..foff + plen]);
        }
        let file_len = new_data.len() - start;
        let raw_size = vsize.min(file_len);
        // Drop padding beyond vsize (trailing bytes of the last page that
        // belong to no object); keep BSS tail virtual (read returns None).
        new_data.truncate(start + raw_size);
        let is_exec = flags & 0x4 != 0;
        let (name, characteristics) = if is_exec {
            let n = if exec_seen == 0 {
                ".text".to_string()
            } else {
                format!(".text{exec_seen}")
            };
            exec_seen += 1;
            (
                n,
                section_flags::CODE | section_flags::EXECUTE | section_flags::READ,
            )
        } else {
            let n = if data_seen == 0 {
                ".data".to_string()
            } else {
                format!(".data{data_seen}")
            };
            data_seen += 1;
            (
                n,
                section_flags::READ | section_flags::WRITE,
            )
        };
        sections.push(Section {
            name,
            virtual_address: base,
            virtual_size: vsize as u32,
            raw_offset: start as u32,
            raw_size: raw_size as u32,
            characteristics,
        });
    }
    Ok(Pe {
        data: new_data,
        image_base: 0,
        sections,
        id: next_pe_id(),
    })
}
