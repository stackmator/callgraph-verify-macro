//! Minimal, dependency-free PE32 reader — just enough to map a virtual address
//! (VA) to file bytes. We deliberately hand-parse the headers instead of pulling
//! in `goblin`/`object`: the contract is "pure byte", and the only thing the
//! disassembler needs is `va -> &[machine code bytes]`.

use std::collections::BTreeSet;
use std::sync::atomic::{AtomicU64, Ordering};

/// LE fixup-table outcome for one loaded image.
#[derive(Debug, Clone)]
pub enum FixupStatus {
    /// No LE fixup tables (PE binaries, or an LE with zeroed table offsets).
    Absent,
    /// Tables parsed; N internal-07 pairs absorbed (possibly zero: tables
    /// present but nothing absolute to relocate).
    Applied { pairs: usize },
    /// Tables present but held a record kind outside the proven grammar;
    /// the image stays pre-fixup (the historical behavior) with the reason
    /// recorded. Loud, not silent: the macro surfaces this as a NOTE once
    /// per build, and `fixup_post_images` is empty.
    Skipped { reason: String },
}

/// A loaded PE image: the raw file plus the parsed section table.
pub struct Pe {
    data: Vec<u8>,
    pub image_base: u64,
    sections: Vec<Section>,
    /// LE fixup absorption (07 absolute records only): `(pre, post)` content
    /// pairs for every patched dword — `pre` is the link-time dword in the
    /// file bytes (what `--asm` shows and the harvesters record), `post` is
    /// what DOS4GW maps at runtime. Always empty for PE (no LE fixup tables
    /// there). Powers the fixup-aware address accept-set: a body may bake
    /// the runtime value of an address the binary references pre-fixup.
    /// Call-graph/CFG ground truth stays pre-fixup (code objects are not
    /// relocated, so direct CALL rel32 is unaffected); only the data-address
    /// accept-set widens. 08 (self-relative) and 02 (selector) records are
    /// parsed and validated so the table walk stays proof-checked, but
    /// contribute no pairs (relative offsets are not addresses; selectors
    /// have no flat-model value).
    fixup_posts: Vec<(u64, u64)>,
    /// What happened with the LE fixup tables (see `FixupStatus`).
    fixup_status: FixupStatus,
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
        fixup_posts: Vec::new(),
        fixup_status: FixupStatus::Absent,
        id: next_pe_id(),
    })
}

    /// Process-unique id assigned at parse time (see the field docs).
    pub fn id(&self) -> u64 {
        self.id
    }

    /// Runtime (post-fixup) images of link-time (pre-fixup) addresses: for
    /// every `pre` in `pres` that an LE 07 fixup record patches, the mapped
    /// runtime value. Empty for PE (no fixup tables) and for binaries whose
    /// tables hold no 07 records. Used to widen address accept-sets (a body
    /// may bake the runtime value of a referenced address); never a demand.
    pub fn fixup_post_images(&self, pres: &BTreeSet<u64>) -> BTreeSet<u64> {
        let mut out = BTreeSet::new();
        if self.fixup_posts.is_empty() || pres.is_empty() {
            return out;
        }
        for &(pre, post) in &self.fixup_posts {
            if pres.contains(&pre) {
                out.insert(post);
            }
        }
        out
    }

    /// How many 07 absolute fixup records were absorbed at load (0 for PE
    /// and for LE binaries without absolute fixups). Diagnostic/test use.
    pub fn fixup_count(&self) -> usize {
        self.fixup_posts.len()
    }

    /// What happened with the LE fixup tables (see `FixupStatus`).
    pub fn fixup_status(&self) -> &FixupStatus {
        &self.fixup_status
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
/// * Fixups are absorbed, not applied: direct CALL rel32 (the call graph)
///   is unaffected, and absolute `globals`/`imm_addrs` harvest as pre-fixup
///   bytes — with post-fixup images accepted wherever a 07 record maps them
///   (`Pe::fixup_post_images`). Call-graph + CFG gates are sound; 08 records
///   are validated, 02 selectors skipped, and novel record kinds skip the
///   tables loudly (`FixupStatus::Skipped`) instead of failing the parse.
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
    // Retained for the fixup walk below: (reloc base, virtual size,
    // 1-based first logical page, page count).
    let mut objs: Vec<(u32, usize, usize, usize)> = Vec::with_capacity(objcnt);
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
        objs.push((base, vsize, page_idx, page_cnt));
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
    let (fixup_posts, fixup_status) = match collect_fixups(
        &data, le_off, &objs, numpages, pagesize, &sections, &new_data,
    ) {
        Ok(pairs) => {
            let n = pairs.len();
            (pairs, FixupStatus::Applied { pairs: n })
        }
        Err(e) if e.starts_with(NOVEL_FIXUP_PREFIX) => {
            (Vec::new(), FixupStatus::Skipped { reason: e })
        }
        Err(e) => return Err(e),
    };
    Ok(Pe {
        data: new_data,
        image_base: 0,
        sections,
        fixup_posts,
        fixup_status,
        id: next_pe_id(),
    })
}

/// Marker prefix for the one non-fatal fixup-walk failure: a record kind
/// outside the proven grammar (e.g. an import fixup another linker emits).
/// `parse_le` matches on this prefix and skips the tables loudly (image
/// stays pre-fixup, reason in `FixupStatus::Skipped`) instead of failing
/// the whole parse. Everything else the walk reports is corruption
/// (truncation, non-adjacent tables, out-of-range references) and stays
/// fatal — a broken file must not load.
const NOVEL_FIXUP_PREFIX: &str = "NOVEL-FIXUP-RECORD: ";

/// Read-only LE fixup walk: `(pre, post)` content pairs for every internal
/// 07 (absolute) record. The grammar mirrors the DOS4GW loader (dagger's
/// `apply_fixups`, proven against FALL.EXE's record tables): page table at
/// `le+0x68`, record table at `le+0x6C`, single-source or u8-counted source
/// lists, narrow (u16) or wide (u32) target offsets, and the wlink
/// page-straddler wrap (`0xFFFD/0xFFFE/0xFFFF` source offsets file under the
/// next page — unwrapped here). 08 (self-relative) records are parsed and
/// validated but contribute no pairs (a relative offset names no address);
/// 02 (16-bit selector) records are counted past (no flat-model value).
/// `pre` is read from the pre-fixup image (file bytes where present, zero
/// where the loader maps BSS); a record patching nowhere is malformed.
/// Zeroed table offsets mean "no tables" (empty walk, not an error).
#[allow(clippy::too_many_arguments)]
fn collect_fixups(
    data: &[u8],
    le_off: usize,
    objs: &[(u32, usize, usize, usize)],
    numpages: usize,
    pagesize: usize,
    sections: &[Section],
    image: &[u8],
) -> Result<Vec<(u64, u64)>, String> {
    let pre_of = |va: u64| -> Option<u32> {
        for s in sections {
            let lo = s.virtual_address as u64;
            let hi = lo + s.virtual_size as u64;
            if (lo..hi).contains(&va) {
                let off = s.raw_offset as u64 + (va - lo);
                if off + 4 <= s.raw_offset as u64 + s.raw_size as u64 {
                    let o = off as usize;
                    return Some(u32::from_le_bytes([
                        image[o],
                        image[o + 1],
                        image[o + 2],
                        image[o + 3],
                    ]));
                }
                // In virtual range but past raw data: loader-zeroed BSS.
                return Some(0);
            }
        }
        None
    };
    let at32 = |o: usize| -> Result<u32, String> {
        if o + 4 > data.len() {
            return Err(format!("LE fixup header read past EOF at {o:#x}"));
        }
        Ok(u32::from_le_bytes([data[o], data[o + 1], data[o + 2], data[o + 3]]))
    };
    let fpt_field = le_off
        .checked_add(0x68)
        .ok_or("LE fixup page-table field overflow")?;
    let frt_field = le_off
        .checked_add(0x6C)
        .ok_or("LE fixup record-table field overflow")?;
    let fpt = le_off
        .checked_add(at32(fpt_field)? as usize)
        .ok_or("LE fixup page-table offset overflow")?;
    let frt = le_off
        .checked_add(at32(frt_field)? as usize)
        .ok_or("LE fixup record-table offset overflow")?;
    if fpt == le_off && frt == le_off {
        // Zeroed table offsets: the linker emitted no fixup tables.
        return Ok(Vec::new());
    }
    let tab_len = (numpages + 1)
        .checked_mul(4)
        .ok_or("LE fixup page-table size overflow")?;
    // Structural proof both offsets are right: the (numpages+1)-entry table
    // abuts the record table exactly.
    if fpt.checked_add(tab_len) != Some(frt) {
        return Err(format!(
            "LE fixup tables not adjacent: pagetab={fpt:#x} + {tab_len:#x} != rectab={frt:#x}"
        ));
    }
    if frt > data.len() {
        return Err(format!(
            "LE fixup record table {frt:#x} past EOF (file size {:#x})",
            data.len()
        ));
    }
    let mut bounds: Vec<(usize, usize)> = Vec::with_capacity(numpages);
    let mut prev = 0usize;
    let mut first = true;
    for i in 0..=numpages {
        let e = at32(fpt + i * 4)? as usize;
        if !first && e < prev {
            return Err(format!(
                "LE fixup page table not monotonic at page {i}: {e:#x} < {prev:#x}"
            ));
        }
        first = false;
        prev = e;
        if i < numpages {
            bounds.push((e, 0));
        } else if frt.checked_add(e).map_or(true, |end| end > data.len()) {
            return Err(format!(
                "LE fixup record table end {e:#x} past EOF (file size {:#x})",
                data.len()
            ));
        }
        if i > 0 {
            bounds[i - 1].1 = e;
        }
    }
    let mut out: Vec<(u64, u64)> = Vec::new();
    for (pi, (start, end)) in bounds.iter().enumerate() {
        let lp = pi + 1; // logical pages are 1-based
        let (obase, _, opage, _) = objs
            .iter()
            .find(|(_, _, p, c)| lp >= *p && lp < p + c)
            .ok_or(format!("LE fixup page {lp} belongs to no object"))?;
        let lin_base = (*obase as usize)
            .checked_add((lp - opage) * pagesize)
            .ok_or(format!("LE fixup page {lp} linear base overflow"))?;
        let mut p = frt
            .checked_add(*start)
            .ok_or("LE fixup record offset overflow")?;
        let pend = frt
            .checked_add(*end)
            .ok_or("LE fixup record end overflow")?;
        while p < pend {
            let rec_off = p - frt;
            let st = *data.get(p).ok_or(format!(
                "LE fixup record {rec_off:#x} (page {lp}) truncated: missing srctype"
            ))?;
            let fl = *data.get(p + 1).ok_or(format!(
                "LE fixup record {rec_off:#x} (page {lp}) truncated: missing tgtflags"
            ))?;
            p += 2;
            let mut srcs: Vec<u16> = Vec::new();
            if st & 0x20 != 0 {
                let cnt = *data.get(p).ok_or(format!(
                    "LE fixup record {rec_off:#x} (page {lp}) truncated: missing source count"
                ))?;
                p += 1;
                for _ in 0..cnt {
                    if p + 2 > pend || p + 2 > data.len() {
                        return Err(format!(
                            "LE fixup record {rec_off:#x} (page {lp}) source runs past page end"
                        ));
                    }
                    srcs.push(u16::from_le_bytes([data[p], data[p + 1]]));
                    p += 2;
                }
            } else {
                if p + 2 > pend || p + 2 > data.len() {
                    return Err(format!(
                        "LE fixup record {rec_off:#x} (page {lp}) source runs past page end"
                    ));
                }
                srcs.push(u16::from_le_bytes([data[p], data[p + 1]]));
                p += 2;
            }
            let low4 = st & 0x0F;
            let is_sel = (st == 0x02 || st == 0x22) && fl == 0x00;
            let is_off = (low4 == 7 || low4 == 8)
                && (st & 0xD0) == 0
                && (fl == 0x00 || fl == 0x10);
            if !is_sel && !is_off {
                // Novelty, not corruption (see NOVEL_FIXUP_PREFIX): the
                // tables may belong to a linker dialect with fixup kinds
                // beyond the proven grammar (e.g. import fixups). The
                // caller skips the tables loudly instead of failing.
                return Err(format!(
                    "{NOVEL_FIXUP_PREFIX}record {rec_off:#x} (page {lp}): srctype=0x{st:02X} tgtflags=0x{fl:02X}"
                ));
            }
            if p + 1 > pend || p + 1 > data.len() {
                return Err(format!(
                    "LE fixup record {rec_off:#x} (page {lp}) truncated: missing target object"
                ));
            }
            let obj = data[p] as usize;
            p += 1;
            if obj < 1 || obj > objs.len() {
                return Err(format!(
                    "LE fixup record {rec_off:#x} (page {lp}) has bad target object {obj}"
                ));
            }
            let wide = fl & 0x10 != 0;
            let toff: u32 = if is_sel {
                0
            } else if wide {
                if p + 4 > pend || p + 4 > data.len() {
                    return Err(format!(
                        "LE fixup record {rec_off:#x} (page {lp}) truncated: missing wide target offset"
                    ));
                }
                let v = u32::from_le_bytes([data[p], data[p + 1], data[p + 2], data[p + 3]]);
                p += 4;
                v
            } else {
                if p + 2 > pend || p + 2 > data.len() {
                    return Err(format!(
                        "LE fixup record {rec_off:#x} (page {lp}) truncated: missing narrow target offset"
                    ));
                }
                let v = u16::from_le_bytes([data[p], data[p + 1]]) as u32;
                p += 2;
                v
            };
            let target = objs[obj - 1].0.wrapping_add(toff);
            for s in srcs {
                // Source offsets are page-relative, but a patched dword may
                // straddle a page boundary: wlink files the record under the
                // page holding the dword's final byte with the offset wrapped.
                let loc = if (s as usize) < pagesize {
                    lin_base.checked_add(s as usize)
                } else if s >= 0xFFFD {
                    lin_base
                        .checked_add(s as usize)
                        .and_then(|l| l.checked_sub(0x1_0000))
                } else {
                    None
                };
                let loc = loc.ok_or(format!(
                    "LE fixup record {rec_off:#x} (page {lp}) bad source offset {s:#x} (pagesize {pagesize:#x})"
                ))?;
                let pre = pre_of(loc as u64).ok_or(format!(
                    "LE fixup record {rec_off:#x} (page {lp}) location {loc:#x} outside image"
                ))?;
                if is_sel {
                    continue; // deferred: no flat-model value (see field docs)
                }
                if low4 == 7 {
                    out.push((pre as u64, target as u64));
                }
                // 08 self-relative: validated, not stored (a relative
                // offset is not an address).
            }
        }
        if p != pend {
            return Err(format!(
                "LE fixup page {lp} consumed to {:#x}, expected end {:#x}",
                p - frt,
                pend - frt
            ));
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Minimal hand-built LE: MZ + LE header, one executable object
    /// (base 0x10000, one 0x1000 page), page map, fixup tables, one data
    /// page. The page holds `mov eax,[0x10400]; ret` plus three patched
    /// dwords; the record table holds one narrow 07, one narrow 08, and
    /// one source-list 07 (wide). Returns the raw file bytes.
    fn build_fixup_le() -> Vec<u8> {
        let le_off = 0x40usize;
        let pagesize = 0x1000usize;
        let mut data = vec![0u8; 0x1400];
        data[0..2].copy_from_slice(b"MZ");
        data[0x3c..0x40].copy_from_slice(&(le_off as u32).to_le_bytes());
        data[le_off..le_off + 2].copy_from_slice(b"LE");
        data[le_off + 8..le_off + 10].copy_from_slice(&2u16.to_le_bytes()); // cpu = 386
        data[le_off + 0x14..le_off + 0x18].copy_from_slice(&1u32.to_le_bytes()); // numpages
        data[le_off + 0x28..le_off + 0x2C]
            .copy_from_slice(&(pagesize as u32).to_le_bytes()); // pagesize
        data[le_off + 0x2C..le_off + 0x30]
            .copy_from_slice(&(pagesize as u32).to_le_bytes()); // lastpagesize
        data[le_off + 0x40..le_off + 0x44].copy_from_slice(&0x1C0u32.to_le_bytes()); // objtab_rel
        data[le_off + 0x44..le_off + 0x48].copy_from_slice(&1u32.to_le_bytes()); // objcnt
        data[le_off + 0x48..le_off + 0x4C].copy_from_slice(&0x1D8u32.to_le_bytes()); // pagemap_rel
        data[le_off + 0x4C..le_off + 0x50].copy_from_slice(&0u32.to_le_bytes()); // itermap
        data[le_off + 0x68..le_off + 0x6C].copy_from_slice(&0x2C0u32.to_le_bytes()); // fpt_rel
        data[le_off + 0x6C..le_off + 0x70].copy_from_slice(&0x2C8u32.to_le_bytes()); // frt_rel
        data[le_off + 0x80..le_off + 0x84].copy_from_slice(&0x400u32.to_le_bytes()); // datapage_abs
        // Object table: vsize, base, flags(exec), page_idx, page_cnt, 12 reserved.
        let o = 0x200usize;
        data[o..o + 4].copy_from_slice(&0x1000u32.to_le_bytes());
        data[o + 4..o + 8].copy_from_slice(&0x10000u32.to_le_bytes());
        data[o + 8..o + 12].copy_from_slice(&0x4u32.to_le_bytes());
        data[o + 12..o + 16].copy_from_slice(&1u32.to_le_bytes());
        data[o + 16..o + 20].copy_from_slice(&1u32.to_le_bytes());
        // Page map: physical page 1, flags 0.
        data[0x218..0x21C].copy_from_slice(&[0x00, 0x00, 0x01, 0x00]);
        // Fixup page table: page 1 owns [0..26).
        data[0x300..0x304].copy_from_slice(&0u32.to_le_bytes());
        data[0x304..0x308].copy_from_slice(&26u32.to_le_bytes());
        // Record 1 (7 bytes @0x308): 07 narrow absolute, src 0x10, obj 1,
        // toff 0x500 → loc 0x10010 (pre 0x10400), post 0x10500.
        data[0x308..0x30F].copy_from_slice(&[0x07, 0x00, 0x10, 0x00, 0x01, 0x00, 0x05]);
        // Record 2 (7 bytes @0x30F): 08 narrow self-relative, src 0x21
        // (CALL rel32 at 0x20), obj 1, toff 0x100 → validated only, no pair.
        data[0x30F..0x316].copy_from_slice(&[0x08, 0x00, 0x21, 0x00, 0x01, 0x00, 0x01]);
        // Record 3 (12 bytes @0x316): 07 wide absolute, source-list
        // [0x30, 0x34], obj 1, toff 0x600 → locs 0x10030/0x10034
        // (pres 0x10410/0x10420), post 0x10600.
        data[0x316..0x322].copy_from_slice(&[
            0x27, 0x10, 0x02, 0x30, 0x00, 0x34, 0x00, 0x01, 0x00, 0x06, 0x00, 0x00,
        ]);
        // Data page: `mov eax,[0x10400]; ret`, patched dwords, CALL stub.
        let pg = 0x400usize;
        data[pg..pg + 6].copy_from_slice(&[0xA1, 0x00, 0x04, 0x01, 0x00, 0xC3]);
        data[pg + 0x10..pg + 0x14].copy_from_slice(&0x10400u32.to_le_bytes());
        data[pg + 0x20..pg + 0x25].copy_from_slice(&[0xE8, 0x00, 0x00, 0x00, 0x00]);
        data[pg + 0x30..pg + 0x34].copy_from_slice(&0x10410u32.to_le_bytes());
        data[pg + 0x34..pg + 0x38].copy_from_slice(&0x10420u32.to_le_bytes());
        data
    }

    #[test]
    fn le_fixup_07_pairs_absorbed() {
        let pe = Pe::parse(build_fixup_le()).expect("parse synthetic LE");
        assert_eq!(pe.fixup_count(), 3, "one narrow 07 + two listed 07 dwords");
        let got = pe.fixup_post_images(&[0x10400].into_iter().collect());
        assert_eq!(got, [0x10500].into_iter().collect());
        let got = pe.fixup_post_images(&[0x10410, 0x10420].into_iter().collect());
        assert_eq!(got, [0x10600].into_iter().collect());
        // Unknown pres map to nothing; 08 records contribute no pairs.
        let got = pe.fixup_post_images(&[0x99999].into_iter().collect());
        assert!(got.is_empty());
    }

    #[test]
    fn le_fixup_post_global_passes_spec() {
        use crate::{analyze, Spec};
        let pe = Pe::parse(build_fixup_le()).expect("parse synthetic LE");
        let cg = analyze(&pe, 0x10000).expect("analyze synthetic fn");
        assert!(cg.globals.contains(&0x10400), "{cg:?}");
        // Pre-fixup value: always accepted.
        Spec::new(0x10000).globals(&[0x10400]).check(&pe).expect("pre global");
        // Post-fixup image of the referenced pre value: accepted (the fix).
        Spec::new(0x10000).globals(&[0x10500]).check(&pe).expect("post global");
        // An address referenced nowhere, pre or post: still rejected.
        assert!(Spec::new(0x10000).globals(&[0x10999]).check(&pe).is_err());
    }

    #[test]
    fn le_fixup_unknown_record_skips_loudly() {
        use super::FixupStatus;
        let mut data = build_fixup_le();
        data[0x308] = 0x09; // bogus srctype on record 1
        // Novelty skips the tables (image stays pre-fixup) — it must NOT
        // fail the parse, and the reason must be recorded, not silent.
        let pe = Pe::parse(data).expect("novel fixup kind must skip, not fail");
        assert_eq!(pe.fixup_count(), 0);
        match pe.fixup_status() {
            FixupStatus::Skipped { reason } => {
                assert!(reason.contains("srctype=0x09"), "{reason}")
            }
            other => panic!("expected Skipped, got {other:?}"),
        }
    }

    #[test]
    fn le_fixup_tables_must_be_adjacent() {
        let mut data = build_fixup_le();
        data[0x40 + 0x68..0x40 + 0x6C].copy_from_slice(&0x2C4u32.to_le_bytes());
        match Pe::parse(data) {
            Ok(_) => panic!("moved page table must fail"),
            Err(err) => assert!(err.contains("not adjacent"), "{err}"),
        }
    }
}
