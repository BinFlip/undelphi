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

use std::fmt;

use goblin::{
    Object,
    elf::{
        header::{self as elf_header, EM_386, EM_AARCH64, EM_ARM, EM_X86_64},
        program_header::PT_LOAD,
        section_header::SHT_NOBITS,
    },
    mach::{Mach, cputype as mach_cpu},
    pe::{
        PE,
        header::{COFF_MACHINE_ARM, COFF_MACHINE_ARM64, COFF_MACHINE_X86, COFF_MACHINE_X86_64},
    },
};

use crate::detection::{TargetArch, TargetOs};

/// Detected executable format, including bitness when known.
///
/// Use the `is_*` helpers to write code that is robust to future variants:
///
/// ```
/// use undelphi::formats::BinaryFormat;
/// let f = BinaryFormat::Pe64;
/// assert!(f.is_pe() && f.is_64bit());
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum BinaryFormat {
    /// 32-bit ELF — Linux / FreeBSD / Android (i386, ARM).
    Elf32,
    /// 64-bit ELF — Linux / FreeBSD / Android (x86_64, AArch64).
    Elf64,
    /// 32-bit Mach-O — older macOS / iOS.
    MachO32,
    /// 64-bit Mach-O — modern macOS / iOS.
    MachO64,
    /// 32-bit PE (`PE32`).
    Pe32,
    /// 64-bit PE (`PE32+`).
    Pe64,
    /// A recognised container magic was present but bitness could not be
    /// determined from the magic alone (typically the goblin parse failed
    /// before headers could be walked). Heuristic scans still ran.
    Unknown,
}

impl BinaryFormat {
    /// `true` for any PE flavour ([`Pe32`](Self::Pe32) or
    /// [`Pe64`](Self::Pe64)).
    #[inline]
    pub fn is_pe(self) -> bool {
        matches!(self, BinaryFormat::Pe32 | BinaryFormat::Pe64)
    }

    /// `true` for any ELF flavour.
    #[inline]
    pub fn is_elf(self) -> bool {
        matches!(self, BinaryFormat::Elf32 | BinaryFormat::Elf64)
    }

    /// `true` for any Mach-O flavour.
    #[inline]
    pub fn is_macho(self) -> bool {
        matches!(self, BinaryFormat::MachO32 | BinaryFormat::MachO64)
    }

    /// Pointer width in bytes (`4`, `8`, or `None` when bitness wasn't
    /// determined from the container).
    #[inline]
    pub fn bitness(self) -> Option<u8> {
        match self {
            BinaryFormat::Elf32 | BinaryFormat::MachO32 | BinaryFormat::Pe32 => Some(4),
            BinaryFormat::Elf64 | BinaryFormat::MachO64 | BinaryFormat::Pe64 => Some(8),
            BinaryFormat::Unknown => None,
        }
    }

    /// `true` when bitness is known and is 64-bit.
    #[inline]
    pub fn is_64bit(self) -> bool {
        self.bitness() == Some(8)
    }
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
    /// Whether goblin successfully parsed the container. `false` either
    /// because the input lacks a recognised magic, or because the magic is
    /// present but the headers walked off the end of the slice. Used by
    /// [`crate::DelphiBinary::parse`] to distinguish "not Delphi" from
    /// "truncated container".
    container_parsed: bool,
    /// Target OS inferred from container metadata (PE → Windows, Mach-O →
    /// Darwin, ELF → Linux/Android via `EI_OSABI`). `Unknown` when the
    /// container couldn't be parsed.
    target_os: TargetOs,
    /// Target architecture inferred from container metadata (PE
    /// `Machine`, ELF `e_machine`, Mach-O `cputype`). `Unknown` when the
    /// container couldn't be parsed.
    target_arch: TargetArch,
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
        let mut format = detect_format(data);
        let mut sections = DelphiSections::default();
        let mut segments = Vec::new();
        let mut pe_holder: Option<PE<'a>> = None;
        let mut pointer_size: Option<usize> = None;
        let mut container_parsed = false;
        let mut target_os = TargetOs::Unknown;
        let mut target_arch = TargetArch::Unknown;

        if let Ok(obj) = Object::parse(data) {
            container_parsed = matches!(
                obj,
                Object::Elf(_) | Object::Mach(Mach::Binary(_)) | Object::PE(_)
            );
            // Refine format with the bitness goblin recovered, plus
            // target-os and arch.
            format = match &obj {
                Object::Elf(e) => {
                    target_os = elf_target_os(e.header.e_ident[elf_header::EI_OSABI]);
                    target_arch = elf_target_arch(e.header.e_machine);
                    if e.is_64 {
                        BinaryFormat::Elf64
                    } else {
                        BinaryFormat::Elf32
                    }
                }
                Object::Mach(Mach::Binary(m)) => {
                    target_os = TargetOs::Darwin;
                    target_arch = mach_target_arch(m.header.cputype());
                    if m.is_64 {
                        BinaryFormat::MachO64
                    } else {
                        BinaryFormat::MachO32
                    }
                }
                Object::PE(p) => {
                    target_os = TargetOs::Windows;
                    target_arch = pe_target_arch(p.header.coff_header.machine);
                    if p.is_64 {
                        BinaryFormat::Pe64
                    } else {
                        BinaryFormat::Pe32
                    }
                }
                _ => format,
            };
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
                        let va = image_base.saturating_add(section.virtual_address as u64);
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
            container_parsed,
            target_os,
            target_arch,
            pe: pe_holder,
        }
    }

    /// Target OS inferred from container metadata (independent of the
    /// compiler build-string). `TargetOs::Unknown` when the container
    /// couldn't be parsed. Mach-O always reports `Darwin` — distinguishing
    /// macOS from iOS requires a build-string match.
    #[inline]
    pub fn target_os(&self) -> TargetOs {
        self.target_os
    }

    /// Target architecture inferred from container metadata.
    /// `TargetArch::Unknown` when the container couldn't be parsed or the
    /// machine code didn't map onto a tracked variant.
    #[inline]
    pub fn target_arch(&self) -> TargetArch {
        self.target_arch
    }

    /// Whether `va` lies inside the binary's primary code section (PE
    /// `.text` / `CODE`, ELF `.text`, Mach-O `__text`). Used by walkers
    /// that need to validate function-pointer candidates without an
    /// explicit count.
    pub fn is_code_va(&self, va: u64) -> bool {
        let Some(t) = self.sections.text else {
            return false;
        };
        let Some(end) = t.va.checked_add(t.size as u64) else {
            return false;
        };
        va >= t.va && va < end
    }

    /// Whether the underlying container (PE / ELF / Mach-O) parsed cleanly.
    ///
    /// `false` either because the input has no recognised container magic,
    /// or because the magic is there but the headers are truncated /
    /// malformed. `BinaryContext::new` is infallible — heuristic scans still
    /// run on garbage input — so callers that want to discriminate "not
    /// Delphi" from "broken executable" should consult this flag.
    #[inline]
    pub fn container_parsed(&self) -> bool {
        self.container_parsed
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
        let prev = idx.checked_sub(1)?;
        let &(seg_va, file_off, size) = self.segments.get(prev)?;
        let seg_end = seg_va.checked_add(size)?;
        if va >= seg_va && va < seg_end {
            let rel = va.checked_sub(seg_va)?;
            let abs = rel.checked_add(file_off)?;
            usize::try_from(abs).ok()
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

fn elf_target_os(ei_osabi: u8) -> TargetOs {
    // ELF OSABI codes from the SysV ABI spec; only the ones we actually
    // see on real Delphi/FPC ELF output are mapped explicitly. `0`
    // (SYSV) is the Linux default, since Linux toolchains usually leave
    // OSABI unset.
    match ei_osabi {
        elf_header::ELFOSABI_LINUX | elf_header::ELFOSABI_NONE => TargetOs::Linux,
        _ => TargetOs::Linux,
    }
}

fn elf_target_arch(e_machine: u16) -> TargetArch {
    match e_machine {
        EM_386 => TargetArch::X86,
        EM_X86_64 => TargetArch::X86_64,
        EM_ARM => TargetArch::Arm,
        EM_AARCH64 => TargetArch::Aarch64,
        _ => TargetArch::Unknown,
    }
}

fn mach_target_arch(cputype: u32) -> TargetArch {
    match cputype {
        mach_cpu::CPU_TYPE_X86 => TargetArch::X86,
        mach_cpu::CPU_TYPE_X86_64 => TargetArch::X86_64,
        mach_cpu::CPU_TYPE_ARM => TargetArch::Arm,
        mach_cpu::CPU_TYPE_ARM64 => TargetArch::Aarch64,
        _ => TargetArch::Unknown,
    }
}

fn pe_target_arch(machine: u16) -> TargetArch {
    match machine {
        COFF_MACHINE_X86 => TargetArch::X86,
        COFF_MACHINE_X86_64 => TargetArch::X86_64,
        COFF_MACHINE_ARM => TargetArch::Arm,
        COFF_MACHINE_ARM64 => TargetArch::Aarch64,
        _ => TargetArch::Unknown,
    }
}

/// Cheap magic-byte check to classify a binary's container.
///
/// Bitness cannot always be determined from the magic alone (the ELF and
/// PE magics are bitness-agnostic; only Mach-O encodes it in the magic).
/// The result is refined to the precise variant in
/// [`BinaryContext::new`] once goblin walks the headers; for the known
/// magics where bitness isn't yet established, this returns the 32-bit
/// variant as a placeholder.
pub fn detect_format(data: &[u8]) -> BinaryFormat {
    let Some(magic) = data.get(..4) else {
        return BinaryFormat::Unknown;
    };
    match magic {
        [0x7f, b'E', b'L', b'F'] => BinaryFormat::Elf32,
        // Mach-O 32-bit LE/BE.
        [0xfe, 0xed, 0xfa, 0xce] | [0xce, 0xfa, 0xed, 0xfe] => BinaryFormat::MachO32,
        // Mach-O 64-bit LE/BE.
        [0xfe, 0xed, 0xfa, 0xcf] | [0xcf, 0xfa, 0xed, 0xfe] => BinaryFormat::MachO64,
        // Fat / universal binaries — bitness mixed; report 32 as placeholder.
        [0xca, 0xfe, 0xba, 0xbe] | [0xbe, 0xba, 0xfe, 0xca] => BinaryFormat::MachO32,
        [b'M', b'Z', _, _] => BinaryFormat::Pe32,
        _ => BinaryFormat::Unknown,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detect_format_from_magics() {
        assert_eq!(detect_format(b"\x7fELF...."), BinaryFormat::Elf32);
        assert_eq!(detect_format(b"MZ\x00\x00"), BinaryFormat::Pe32);
        assert_eq!(detect_format(b"\xcf\xfa\xed\xfe"), BinaryFormat::MachO64);
        assert_eq!(detect_format(b"\xfe\xed\xfa\xce"), BinaryFormat::MachO32);
        assert_eq!(detect_format(b"ZZZZ"), BinaryFormat::Unknown);
        assert_eq!(detect_format(b""), BinaryFormat::Unknown);
    }

    #[test]
    fn binary_format_helpers() {
        assert!(BinaryFormat::Pe64.is_pe());
        assert!(BinaryFormat::Pe64.is_64bit());
        assert!(!BinaryFormat::Pe32.is_64bit());
        assert!(BinaryFormat::Elf32.is_elf());
        assert!(BinaryFormat::MachO64.is_macho());
        assert_eq!(BinaryFormat::Pe32.bitness(), Some(4));
        assert_eq!(BinaryFormat::Unknown.bitness(), None);
    }

    #[test]
    fn empty_context_is_safe() {
        let ctx = BinaryContext::new(b"");
        assert_eq!(ctx.format(), BinaryFormat::Unknown);
        assert!(ctx.sections().rodata.is_none());
        assert!(!ctx.has_segments());
    }
}
