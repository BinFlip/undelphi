//! Executable-format dispatch for Delphi / C++Builder / FPC binaries.
//!
//! Wraps `goblin` to parse PE / PE+ / Mach-O / ELF once, producing a context
//! that lets downstream parsers (DVCLAL, PACKAGEINFO, VMT scan, TPF0) work
//! against the same pre-indexed section and segment table regardless of
//! format. All slicing borrows from the caller's byte buffer.
//!
//! Only the subset relevant to Delphi metadata extraction is tracked:
//!
//! - Read-only data range (where `.rdata` / `__const` / `.rodata` lives — the
//!   home of strings, RTTI, VMTs).
//! - Resource range on PE (`.rsrc`). On Mach-O / ELF the equivalent lives
//!   inside a user data segment and is located by magic-byte scan, not by
//!   name.
//! - VA ↔ file-offset mapping, so pointers embedded in RTTI / VMT records can
//!   be translated back to byte offsets.
//!
//! See `RESEARCH.md` §9 (PE), §10 (Mach-O / ELF) for the format-level context.

use core::fmt;

use goblin::{
    Object,
    elf::{program_header::PT_LOAD, section_header::SHT_NOBITS},
    mach::Mach,
    pe::PE,
};

/// Detected executable format.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BinaryFormat {
    /// ELF — Linux / FreeBSD / Android.
    Elf,
    /// Mach-O — macOS / iOS. Both 32- and 64-bit variants covered.
    MachO,
    /// PE (Portable Executable) — Windows. Both `PE32` and `PE32+` covered.
    Pe,
    /// Unrecognized container. Magic-byte scanning can still find some markers.
    Unknown,
}

/// A contiguous byte range within the binary, with its virtual address.
#[derive(Debug, Clone, Copy)]
pub struct SectionRange {
    /// File offset in bytes.
    pub offset: usize,
    /// Size in bytes.
    pub size: usize,
    /// Virtual address when the image is loaded.
    pub va: u64,
}

/// Delphi / FPC-relevant section locations, populated during
/// [`BinaryContext::new`].
#[derive(Debug, Default)]
pub struct DelphiSections {
    /// Read-only data range (`.rdata` on PE; `.rodata` on ELF; any section
    /// matching `__const` / `__cstring` on Mach-O). Where RTTI and string
    /// literals live.
    pub rodata: Option<SectionRange>,
    /// PE resource-directory range (`.rsrc`). `None` outside of PE.
    pub rsrc: Option<SectionRange>,
    /// Text / code range. Used for VMT validation: VMT function pointers must
    /// target an executable range.
    pub text: Option<SectionRange>,
    /// All sections that may contain class metadata (VMTs, RTTI). Ordered
    /// from "most likely clean data" to "code-adjacent" so scanners that
    /// want to stop at the first hit get the cleanest candidates first.
    /// On PE this is roughly `.rdata` → `.text`; on Mach-O the `__const`
    /// and `__DATA_CONST.__const` sections first, then `__text`.
    pub scan_targets: Vec<SectionRange>,
    /// Free-Pascal internal resources section (`.fpc.resources` on ELF/PE
    /// or `fpc.resources` within the Mach-O `__DATA` segment). `None` on
    /// Delphi / C++Builder output and on FPC binaries built with the
    /// winlikeresources compile-time option.
    pub fpc_resources: Option<SectionRange>,
}

/// Parsed binary context. Parses the container exactly once.
///
/// All fields are `pub(crate)` to let downstream modules slice cheaply without
/// going through accessors in hot paths. The borrow contract is enforced
/// by the lifetime parameter.
pub struct BinaryContext<'a> {
    data: &'a [u8],
    format: BinaryFormat,
    sections: DelphiSections,
    /// `(segment_va, file_offset, size)` triples covering the loaded image.
    /// Built from ELF `PT_LOAD` headers, Mach-O segments, or PE sections.
    /// Pre-sorted by `segment_va` so [`BinaryContext::va_to_file`] can binary
    /// search.
    segments: Vec<(u64, u64, u64)>,
    /// Cached pointer width inferred from the parsed container, populated in
    /// [`BinaryContext::new`] so accessors don't re-parse the binary.
    pointer_size: Option<usize>,
    /// The goblin-parsed PE, retained so downstream modules (e.g. resources)
    /// can use goblin's structural types instead of re-rolling their own.
    /// `None` for non-PE containers or unparseable PE input.
    pub(crate) pe: Option<PE<'a>>,
}

impl<'a> fmt::Debug for BinaryContext<'a> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("BinaryContext")
            .field("format", &self.format)
            .field("data_len", &self.data.len())
            .field("sections", &self.sections)
            .field("segments", &self.segments.len())
            .field("pointer_size", &self.pointer_size)
            .field("pe_parsed", &self.pe.is_some())
            .finish()
    }
}

impl<'a> BinaryContext<'a> {
    /// Parse a binary, populating format, section, and segment tables.
    ///
    /// Always succeeds — returns an empty context for garbage input so that
    /// heuristic scans can still run.
    pub fn new(data: &'a [u8]) -> Self {
        let format = detect_format(data);
        let mut sections = DelphiSections::default();
        let mut segments = Vec::new();
        let mut pe_holder: Option<PE<'a>> = None;
        let mut pointer_size: Option<usize> = None;

        if let Ok(obj) = Object::parse(data) {
            match obj {
                Object::Elf(elf) => {
                    pointer_size = Some(if elf.is_64 { 8 } else { 4 });
                    for sh in &elf.section_headers {
                        let Some(name) = elf.shdr_strtab.get_at(sh.sh_name) else {
                            continue;
                        };
                        if sh.sh_type == SHT_NOBITS || sh.sh_size == 0 {
                            continue;
                        }
                        let range = SectionRange {
                            offset: sh.sh_offset as usize,
                            size: sh.sh_size as usize,
                            va: sh.sh_addr,
                        };
                        match name {
                            ".rodata" | ".rdata" => {
                                sections.rodata = Some(range);
                                sections.scan_targets.push(range);
                            }
                            ".text" => {
                                sections.text = Some(range);
                                sections.scan_targets.push(range);
                            }
                            ".data" | ".data.rel.ro" => {
                                // FPC may emit VMTs in .data or
                                // .data.rel.ro (ELF). Worth scanning.
                                sections.scan_targets.push(range);
                            }
                            ".fpc.resources" => {
                                sections.fpc_resources = Some(range);
                            }
                            _ => {}
                        }
                    }
                    for phdr in &elf.program_headers {
                        if phdr.p_type == PT_LOAD && phdr.p_filesz > 0 {
                            segments.push((phdr.p_vaddr, phdr.p_offset, phdr.p_filesz));
                        }
                    }
                }
                Object::Mach(Mach::Binary(ref macho)) => {
                    pointer_size = Some(if macho.is_64 { 8 } else { 4 });
                    for seg in &macho.segments {
                        if seg.filesize > 0 {
                            segments.push((seg.vmaddr, seg.fileoff, seg.filesize));
                        }
                        for (section, _) in seg.sections().unwrap_or_default() {
                            let name = section.name().unwrap_or("");
                            if section.size == 0 {
                                continue;
                            }
                            let range = SectionRange {
                                offset: section.offset as usize,
                                size: section.size as usize,
                                va: section.addr,
                            };
                            match name {
                                "__const" | "__cstring" | "__data" => {
                                    // Mach-O splits constant data across
                                    // `__TEXT.__const`, `__DATA_CONST.__const`,
                                    // and `__DATA.__data`; FPC may place
                                    // VMTs in any of them. Track all as
                                    // scan targets.
                                    if sections.rodata.is_none() {
                                        sections.rodata = Some(range);
                                    }
                                    sections.scan_targets.push(range);
                                }
                                "__text" => {
                                    sections.text = Some(range);
                                    sections.scan_targets.push(range);
                                }
                                "fpc.resources" => {
                                    sections.fpc_resources = Some(range);
                                }
                                _ => {}
                            }
                        }
                    }
                }
                Object::PE(pe) => {
                    pointer_size = Some(if pe.is_64 { 8 } else { 4 });
                    let image_base = pe.image_base;
                    // Copy out only what we need before moving `pe` into the
                    // holder at function end. Iteration here is read-only.
                    for section in &pe.sections {
                        let va = image_base + section.virtual_address as u64;
                        let file_off = section.pointer_to_raw_data as u64;
                        let size = section.size_of_raw_data as u64;
                        if size > 0 {
                            segments.push((va, file_off, size));
                        }
                        let Ok(name) = section.name() else { continue };
                        if size == 0 {
                            continue;
                        }
                        let range = SectionRange {
                            offset: section.pointer_to_raw_data as usize,
                            size: section.size_of_raw_data as usize,
                            va,
                        };
                        match name {
                            // Classic Delphi uses upper-case section names
                            // (`CODE`, `DATA`, `BSS`). Modern Delphi and FPC
                            // use lowercase. Accept both.
                            ".rdata" => {
                                sections.rodata = Some(range);
                                sections.scan_targets.push(range);
                            }
                            ".rsrc" => sections.rsrc = Some(range),
                            ".text" | "CODE" => {
                                sections.text = Some(range);
                                sections.scan_targets.push(range);
                            }
                            ".data" | "DATA" => {
                                // Classic Delphi sometimes emits VMTs in
                                // the writable data section. Scan it too.
                                sections.scan_targets.push(range);
                            }
                            ".fpc.resources" => {
                                sections.fpc_resources = Some(range);
                            }
                            _ => {}
                        }
                    }
                    pe_holder = Some(pe);
                }
                _ => {}
            }
        }

        // Pre-sort segments so `va_to_file` can binary-search.
        segments.sort_unstable_by_key(|&(seg_va, _, _)| seg_va);

        Self {
            data,
            format,
            sections,
            segments,
            pointer_size,
            pe: pe_holder,
        }
    }

    /// The original byte buffer.
    #[inline]
    pub fn data(&self) -> &'a [u8] {
        self.data
    }

    /// The detected container format.
    #[inline]
    pub fn format(&self) -> BinaryFormat {
        self.format
    }

    /// Key sections found by name.
    #[inline]
    pub fn sections(&self) -> &DelphiSections {
        &self.sections
    }

    /// Slice the binary covered by a [`SectionRange`].
    pub fn section_data(&self, range: &SectionRange) -> Option<&'a [u8]> {
        self.data
            .get(range.offset..range.offset.checked_add(range.size)?)
    }

    /// Translate a virtual address to a file offset.
    ///
    /// `segments` is sorted by `segment_va` at construction time, so this is
    /// O(log n). Hot path — called once per pointer dereference during VMT /
    /// RTTI walks.
    pub fn va_to_file(&self, va: u64) -> Option<usize> {
        // `partition_point` gives the count of segments whose start VA is
        // `<= va`. The candidate that could contain `va` is therefore the
        // last one in that prefix — if any.
        let idx = self
            .segments
            .partition_point(|&(seg_va, _, _)| seg_va <= va);
        if idx == 0 {
            return None;
        }
        let (seg_va, file_off, size) = self.segments[idx - 1];
        if va >= seg_va && va < seg_va + size {
            usize::try_from(va - seg_va + file_off).ok()
        } else {
            None
        }
    }

    /// Any segments were registered (i.e. the binary was parseable).
    #[inline]
    pub fn has_segments(&self) -> bool {
        !self.segments.is_empty()
    }

    /// Pointer width in bytes, inferred from the parsed container.
    ///
    /// Returns `None` when the container could not be parsed by goblin;
    /// callers that want to scan anyway can fall back to trying both 4 and 8.
    /// Cached at construction — this is a field read.
    #[inline]
    pub fn pointer_size(&self) -> Option<usize> {
        self.pointer_size
    }

    /// Sections that can reasonably contain VMTs / RTTI.
    ///
    /// Delphi typically places class metadata in the code section (`CODE`
    /// / `.text`), because the compiler emits VMTs as initialised data
    /// that is read-only at runtime and lives alongside function bodies.
    /// FPC/Lazarus does the same in `.text` on Windows PE but uses
    /// `.rodata` on ELF and `__const`/`__text` on Mach-O.
    ///
    /// The list returned is ordered `rodata` → `text` so that scanners
    /// which stop at the first validated VMT get the cleanest candidates
    /// first when a dedicated read-only section is present.
    #[inline]
    pub fn scan_ranges(&self) -> &[SectionRange] {
        &self.sections.scan_targets
    }
}

/// Cheap magic-byte check to classify a binary's container.
pub fn detect_format(data: &[u8]) -> BinaryFormat {
    if data.len() < 4 {
        return BinaryFormat::Unknown;
    }
    match data[..4] {
        [0x7f, b'E', b'L', b'F'] => BinaryFormat::Elf,
        // Mach-O 32/64-bit LE/BE, fat binaries.
        [0xfe, 0xed, 0xfa, 0xce]
        | [0xce, 0xfa, 0xed, 0xfe]
        | [0xfe, 0xed, 0xfa, 0xcf]
        | [0xcf, 0xfa, 0xed, 0xfe]
        | [0xca, 0xfe, 0xba, 0xbe]
        | [0xbe, 0xba, 0xfe, 0xca] => BinaryFormat::MachO,
        [b'M', b'Z', _, _] => BinaryFormat::Pe,
        _ => BinaryFormat::Unknown,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detect_format_from_magics() {
        assert_eq!(detect_format(b"\x7fELF...."), BinaryFormat::Elf);
        assert_eq!(detect_format(b"MZ\x00\x00"), BinaryFormat::Pe);
        assert_eq!(detect_format(b"\xcf\xfa\xed\xfe"), BinaryFormat::MachO);
        assert_eq!(detect_format(b"ZZZZ"), BinaryFormat::Unknown);
        assert_eq!(detect_format(b""), BinaryFormat::Unknown);
    }

    #[test]
    fn empty_context_is_safe() {
        let ctx = BinaryContext::new(b"");
        assert_eq!(ctx.format(), BinaryFormat::Unknown);
        assert!(ctx.sections().rodata.is_none());
        assert!(!ctx.has_segments());
    }
}
