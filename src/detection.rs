//! Toolchain detection for Delphi / C++Builder / Free Pascal compiled binaries.
//!
//! Identification combines several independent signals. No single one is
//! decisive — Embarcadero and FPC both emit different markers, and common
//! packers (UPX, Themida, Enigma) strip some of them while leaving others
//! intact. Each detected signal contributes to a confidence level.
//!
//! ## Signals used
//!
//! | Signal | Confidence on its own | Version recovered |
//! |--------|-----------------------|-------------------|
//! | Embarcadero build-string (`Embarcadero Delphi for Win64 compiler version 36.0 ...`) | High | yes |
//! | FPC build-string (`FPC 3.2.2 [...] for i386 - Win32`) | High | yes |
//! | `DVCLAL` resource present | High | no |
//! | `PACKAGEINFO` resource present | High | no |
//! | `SOFTWARE\Borland\Delphi\RTL` registry path (pre-XE2) | Medium | no (era only: D2–D2005) |
//! | Namespaced VCL/RTL unit (`Vcl.Controls`, …) (XE2+) | Medium | no (era only: XE2+) |
//! | Many `TPF0` occurrences | Medium | no |
//!
//! See `RESEARCH.md` §2 for the full identification strategy.

use core::str;

use crate::formats::BinaryContext;

/// Confidence level for toolchain identification.
///
/// Orderable so callers can use comparison operators to gate behavior.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Confidence {
    /// No Delphi/FPC indicators found.
    None,
    /// Only heuristic string patterns matched; may be a false positive on a
    /// binary that happens to embed Delphi-looking literals.
    Low,
    /// TPF0 form resources or partial markers present; compiler build-string
    /// not recovered.
    Medium,
    /// Build-string found, or DVCLAL/PACKAGEINFO resource located. Strongly
    /// confirmed Delphi/C++Builder/FPC output.
    High,
}

/// The identified toolchain family.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Compiler {
    /// Embarcadero / CodeGear / Borland Delphi (`dcc32` / `dcc64` / `dccosx` / etc.).
    Delphi,
    /// Embarcadero C++Builder. Emits the same VCL/FMX metadata as Delphi.
    CppBuilder,
    /// Free Pascal Compiler (`fpc`), including Lazarus builds.
    FreePascal,
}

/// The target architecture the binary was compiled for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TargetArch {
    /// 32-bit x86.
    X86,
    /// 64-bit x86.
    X86_64,
    /// 32-bit ARM.
    Arm,
    /// 64-bit ARM (AArch64).
    Aarch64,
    /// Unknown or not explicitly stated in the build-string.
    Unknown,
}

/// The target operating system the binary was compiled for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TargetOs {
    /// Windows (PE / PE+).
    Windows,
    /// macOS / iOS / Darwin (Mach-O).
    Darwin,
    /// Linux (ELF).
    Linux,
    /// Android (ELF).
    Android,
    /// iOS simulator or device.
    Ios,
    /// Other / unknown.
    Unknown,
}

/// Which marker in the binary produced the `CompilerInfo`.
///
/// `BuildString` matches carry an exact compiler version; the legacy-marker
/// matches do not, but still pin the compiler family and era.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DetectionSource {
    /// Full Embarcadero or FPC build-string matched. Exact version is known.
    BuildString,
    /// Legacy `SOFTWARE\Borland\Delphi\RTL` registry path. Emitted by the
    /// Delphi RTL from roughly Delphi 2 through Delphi 7 / Delphi 2005.
    /// Indicates pre-XE2 (non-namespaced) Delphi.
    BorlandRegistry,
    /// Namespaced RTL/VCL unit name (`Vcl.Controls`, `System.SysUtils`, …).
    /// The namespace-prefixed form was introduced with Delphi XE2, so a hit
    /// here indicates XE2 or later.
    NamespacedUnits,
}

/// Compiler build fingerprint extracted from the binary's read-only data.
///
/// Strings borrow from the input byte buffer.
#[derive(Debug, Clone)]
pub struct CompilerInfo<'a> {
    /// Which toolchain emitted the binary.
    pub compiler: Compiler,
    /// Raw version string captured from the build marker, e.g. `"36.0"` (Delphi)
    /// or `"3.2.2"` (FPC). `None` if the version substring could not be isolated
    /// (always `None` for legacy-marker matches).
    pub version: Option<&'a str>,
    /// The marker substring as it appears in the binary. For build-string
    /// matches this is the full `Embarcadero …` / `FPC …` line; for legacy
    /// matches it is the specific substring that triggered identification.
    pub raw: &'a str,
    /// Target architecture the build-string advertises (`Unknown` for legacy
    /// markers that don't encode the target).
    pub arch: TargetArch,
    /// Target OS the build-string advertises.
    pub os: TargetOs,
    /// Which marker family produced this identification.
    pub source: DetectionSource,
}

impl<'a> CompilerInfo<'a> {
    /// Translate the raw compiler version string into a marketing release
    /// name, when recognised.
    ///
    /// Delphi compiler version → RAD Studio release mapping:
    ///
    /// | dcc version | RAD Studio / Delphi |
    /// |-------------|---------------------|
    /// | 36.x        | Delphi 12 Athens    |
    /// | 35.x        | Delphi 11 Alexandria |
    /// | 34.x        | Delphi 10.4 Sydney  |
    /// | 33.x        | Delphi 10.3 Rio     |
    /// | 32.x        | Delphi 10.2 Tokyo   |
    /// | 31.x        | Delphi 10.1 Berlin  |
    /// | 30.x        | Delphi 10 Seattle   |
    /// | 29.x        | Delphi XE8          |
    /// | 28.x        | Delphi XE7          |
    /// | 27.x        | Delphi XE6          |
    /// | 26.x        | Delphi XE5          |
    /// | 25.x        | Delphi XE4          |
    /// | 24.x        | Delphi XE3          |
    /// | 23.x        | Delphi XE2          |
    /// | 22.x        | Delphi XE           |
    /// | 21.x        | Delphi 2010         |
    /// | 20.x        | Delphi 2009         |
    /// | 19.x        | Delphi 2007         |
    /// | 18.x        | Delphi 2006         |
    /// | 17.x        | Delphi 2005         |
    ///
    /// For FPC we return `"FPC X.Y.Z"` verbatim since FPC doesn't use
    /// marketing release names.
    pub fn product_name(&self) -> Option<String> {
        let version = self.version?;
        match self.compiler {
            Compiler::Delphi | Compiler::CppBuilder => delphi_product_name(version),
            Compiler::FreePascal => Some(format!("Free Pascal {}", version)),
        }
    }
}

fn delphi_product_name(version: &str) -> Option<String> {
    // Split at '.' and parse the major.
    let major: u32 = version.split('.').next()?.parse().ok()?;
    let name = match major {
        36 => "Delphi 12 Athens",
        35 => "Delphi 11 Alexandria",
        34 => "Delphi 10.4 Sydney",
        33 => "Delphi 10.3 Rio",
        32 => "Delphi 10.2 Tokyo",
        31 => "Delphi 10.1 Berlin",
        30 => "Delphi 10 Seattle",
        29 => "Delphi XE8",
        28 => "Delphi XE7",
        27 => "Delphi XE6",
        26 => "Delphi XE5",
        25 => "Delphi XE4",
        24 => "Delphi XE3",
        23 => "Delphi XE2",
        22 => "Delphi XE",
        21 => "Delphi 2010",
        20 => "Delphi 2009",
        19 => "Delphi 2007",
        18 => "Delphi 2006",
        17 => "Delphi 2005",
        16 => "Delphi 8 (.NET)",
        15 => "Delphi 7",
        14 => "Delphi 6",
        13 => "Delphi 5",
        12 => "Delphi 4",
        11 => "Delphi 3",
        10 => "Delphi 2",
        9 => "Delphi 1",
        _ => return None,
    };
    Some(name.to_owned())
}

/// FPC build-string prefix: `"FPC "`.
const FPC_PREFIX: &[u8] = b"FPC ";

/// Delphi / C++Builder build-string prefix: `"Embarcadero "`.
const EMBARCADERO_PREFIX: &[u8] = b"Embarcadero ";

/// Scan the binary for a compiler build-string.
///
/// Walks the whole byte buffer looking for either the Embarcadero or the FPC
/// marker. The first complete match wins. Returns `None` if neither marker is
/// present.
///
/// The returned `CompilerInfo` borrows from the original buffer — no
/// allocation happens in this path.
pub fn scan_build_string<'a>(data: &'a [u8]) -> Option<CompilerInfo<'a>> {
    // Try Embarcadero first (typically earlier in the `.rdata` segment).
    if let Some(info) = find_embarcadero(data) {
        return Some(info);
    }
    find_fpc(data)
}

/// Locate an `Embarcadero Delphi/C++Builder for <target> compiler version <ver> (<build>)` line.
fn find_embarcadero<'a>(data: &'a [u8]) -> Option<CompilerInfo<'a>> {
    let start = find_bytes(data, EMBARCADERO_PREFIX)?;

    // Extend to a printable-ASCII run of up to 256 bytes.
    let end = start
        + (start..data.len().min(start + 256))
            .take_while(|&i| is_printable_ascii(data[i]))
            .count();
    let raw = str::from_utf8(&data[start..end]).ok()?;

    // Expected prefixes:
    //   "Embarcadero Delphi for Win64 compiler version 36.0 (29.0.55362.2017)"
    //   "Embarcadero Delphi for Win32 compiler version 29.0 (...)"
    //   "Embarcadero C++ for Win64 compiler version ..." (C++Builder)
    //   "Embarcadero C++Builder ..."
    let rest = raw.strip_prefix("Embarcadero ")?;
    let (compiler, after_comp) = if let Some(r) = rest.strip_prefix("Delphi ") {
        (Compiler::Delphi, r)
    } else if let Some(r) = rest.strip_prefix("C++Builder ") {
        (Compiler::CppBuilder, r)
    } else if let Some(r) = rest.strip_prefix("C++ ") {
        (Compiler::CppBuilder, r)
    } else {
        // Unknown Embarcadero product variant — count as Delphi, leave rest as-is.
        (Compiler::Delphi, rest)
    };

    let (os, arch) = parse_embarcadero_target(after_comp);

    // "compiler version X.Y" substring — grab the token after it.
    let version = after_comp
        .split_once("compiler version ")
        .and_then(|(_, tail)| tail.split_whitespace().next());

    Some(CompilerInfo {
        compiler,
        version,
        raw,
        arch,
        os,
        source: DetectionSource::BuildString,
    })
}

/// Decode the `for <target>` portion of an Embarcadero build-string.
fn parse_embarcadero_target(after_compiler_name: &str) -> (TargetOs, TargetArch) {
    let Some(rest) = after_compiler_name.strip_prefix("for ") else {
        return (TargetOs::Unknown, TargetArch::Unknown);
    };
    let target = rest.split_whitespace().next().unwrap_or("");
    match target {
        "Win32" => (TargetOs::Windows, TargetArch::X86),
        "Win64" => (TargetOs::Windows, TargetArch::X86_64),
        "OSX32" => (TargetOs::Darwin, TargetArch::X86),
        "OSX64" | "macOS64" => (TargetOs::Darwin, TargetArch::X86_64),
        "iOSDevice" | "iOS" => (TargetOs::Ios, TargetArch::Arm),
        "iOSDevice64" => (TargetOs::Ios, TargetArch::Aarch64),
        "Android" => (TargetOs::Android, TargetArch::Arm),
        "Android64" => (TargetOs::Android, TargetArch::Aarch64),
        "Linux64" => (TargetOs::Linux, TargetArch::X86_64),
        _ => (TargetOs::Unknown, TargetArch::Unknown),
    }
}

/// Locate an `FPC M.m.p [YYYY/MM/DD] for <arch> - <OS>` line.
fn find_fpc<'a>(data: &'a [u8]) -> Option<CompilerInfo<'a>> {
    // Scan for every candidate, not just the first — many FPC-built binaries
    // embed multiple FPC strings in `.rodata`. We want the first complete one.
    let mut cursor = 0usize;
    while let Some(rel) = find_bytes(&data[cursor..], FPC_PREFIX) {
        let start = cursor + rel;
        let end = start
            + (start..data.len().min(start + 160))
                .take_while(|&i| is_printable_ascii(data[i]))
                .count();
        if let Ok(raw) = str::from_utf8(&data[start..end])
            && let Some(info) = parse_fpc_line(raw)
        {
            return Some(info);
        }
        cursor = start + FPC_PREFIX.len();
    }
    None
}

fn parse_fpc_line<'a>(raw: &'a str) -> Option<CompilerInfo<'a>> {
    // "FPC 3.2.2 [2021/05/15] for i386 - Win32"
    let rest = raw.strip_prefix("FPC ")?;
    let (version, tail) = rest.split_once(' ')?;
    if !version.chars().next()?.is_ascii_digit() {
        return None;
    }
    // Expect `[YYYY/MM/DD] for <arch> - <OS>` after the version.
    let after_date = tail.split_once("] for ").map(|(_, r)| r)?;
    let (arch_tok, os_tok) = after_date.split_once(" - ")?;
    let os_tok = os_tok.split_whitespace().next()?;

    let arch = match arch_tok {
        "i386" => TargetArch::X86,
        "x86_64" => TargetArch::X86_64,
        "aarch64" => TargetArch::Aarch64,
        "arm" => TargetArch::Arm,
        _ => TargetArch::Unknown,
    };
    let os = match os_tok {
        "Win32" | "Win64" => TargetOs::Windows,
        "Linux" => TargetOs::Linux,
        "Darwin" => TargetOs::Darwin,
        "Android" => TargetOs::Android,
        "iPhoneSim" | "iOS" => TargetOs::Ios,
        _ => TargetOs::Unknown,
    };

    Some(CompilerInfo {
        compiler: Compiler::FreePascal,
        version: Some(version),
        raw,
        arch,
        os,
        source: DetectionSource::BuildString,
    })
}

/// Legacy Delphi RTL registry-path marker. Present from roughly Delphi 2
/// through Delphi 2005 (pre-namespaced era). The full path is unique enough
/// to be used as a compiler-family signature on its own.
const BORLAND_RTL_MARKER: &[u8] = b"SOFTWARE\\Borland\\Delphi\\RTL";

/// Canonical namespaced VCL/RTL unit names introduced in Delphi XE2. Any one
/// of these substrings is a strong signature for XE2+-era Delphi because
/// non-Delphi binaries don't encode Pascal unit names in this form.
const NAMESPACED_MARKERS: &[&[u8]] = &[
    b"Vcl.Controls",
    b"Vcl.Forms",
    b"Vcl.Graphics",
    b"System.SysUtils",
    b"System.Classes",
];

/// Locate a legacy `SOFTWARE\Borland\Delphi\RTL` registry path.
///
/// A hit identifies the binary as Delphi without a specific version. The
/// returned `raw` borrows the exact matched substring.
fn find_borland_registry<'a>(data: &'a [u8]) -> Option<CompilerInfo<'a>> {
    let start = find_bytes(data, BORLAND_RTL_MARKER)?;
    let end = start + BORLAND_RTL_MARKER.len();
    let raw = str::from_utf8(&data[start..end]).ok()?;
    Some(CompilerInfo {
        compiler: Compiler::Delphi,
        version: None,
        raw,
        arch: TargetArch::Unknown,
        os: TargetOs::Unknown,
        source: DetectionSource::BorlandRegistry,
    })
}

/// Locate a namespaced VCL/RTL unit name.
///
/// A hit identifies the binary as XE2-or-later Delphi. The returned `raw`
/// borrows the exact matched substring.
fn find_namespaced_units<'a>(data: &'a [u8]) -> Option<CompilerInfo<'a>> {
    for marker in NAMESPACED_MARKERS {
        if let Some(start) = find_bytes(data, marker) {
            let end = start + marker.len();
            let raw = str::from_utf8(&data[start..end]).ok()?;
            return Some(CompilerInfo {
                compiler: Compiler::Delphi,
                version: None,
                raw,
                arch: TargetArch::Unknown,
                os: TargetOs::Unknown,
                source: DetectionSource::NamespacedUnits,
            });
        }
    }
    None
}

/// Full compiler identification: try the exact build-string first, then fall
/// back to legacy markers (Borland registry path, namespaced VCL units).
///
/// This is what `DelphiBinary::parse` calls. Prefer `scan_build_string` only
/// when the strict-semantic guarantee matters (e.g. for downstream code that
/// requires a known version).
pub fn scan_compiler<'a>(data: &'a [u8]) -> Option<CompilerInfo<'a>> {
    if let Some(info) = scan_build_string(data) {
        return Some(info);
    }
    // Prefer the more specific legacy marker. Binaries that have both the
    // namespaced-unit signature *and* the `Borland\Delphi` registry path
    // are extremely rare (Embarcadero dropped the registry path around XE2).
    // Try Borland first anyway because it's the tighter substring.
    if let Some(info) = find_borland_registry(data) {
        return Some(info);
    }
    find_namespaced_units(data)
}

/// Count `TPF0` magic occurrences in the binary. Used as a medium-confidence
/// heuristic when build-strings have been stripped.
pub fn count_tpf0(data: &[u8]) -> usize {
    count_bytes(data, b"TPF0")
}

/// Run the full scan on a [`BinaryContext`] and summarize signals.
///
/// Both `compiler_info` and `tpf0_count` are gathered in one pass so callers
/// don't have to re-scan the binary buffer. Scans are limited to the
/// sections that can plausibly carry the markers (read-only data for
/// strings, resource section for TPF0) when those sections are known —
/// avoids walking megabytes of `.text` / overlay data on large binaries.
/// Falls back to the full buffer when no narrower range is available.
pub fn analyze<'a>(ctx: &BinaryContext<'a>) -> DetectionReport<'a> {
    let compiler_info = scan_compiler_in_ctx(ctx);
    let tpf0 = count_tpf0_in_ctx(ctx);
    let confidence = match compiler_info.as_ref().map(|c| c.source) {
        Some(DetectionSource::BuildString) => Confidence::High,
        Some(DetectionSource::BorlandRegistry | DetectionSource::NamespacedUnits) => {
            Confidence::Medium
        }
        None if tpf0 > 0 => Confidence::Medium,
        None => Confidence::None,
    };
    DetectionReport {
        confidence,
        compiler_info,
        tpf0_count: tpf0,
    }
}

/// Compiler-marker scan restricted to read-only data when available.
fn scan_compiler_in_ctx<'a>(ctx: &BinaryContext<'a>) -> Option<CompilerInfo<'a>> {
    if let Some(rodata) = ctx.sections().rodata
        && let Some(slice) = ctx.section_data(&rodata)
        && let Some(info) = scan_compiler(slice)
    {
        return Some(info);
    }
    scan_compiler(ctx.data())
}

/// TPF0-magic count summed across the sections that can carry form
/// streams: PE resources (`.rsrc`), FPC internal resources, and read-only
/// data (FPC/Lazarus PE builds frequently inline form bodies in `.rdata`
/// rather than the resource directory). Falls back to a full-buffer scan
/// when none of those sections were located, so unknown-format binaries
/// still get a heuristic count.
fn count_tpf0_in_ctx(ctx: &BinaryContext<'_>) -> usize {
    let s = ctx.sections();
    let mut had_section = false;
    let mut total = 0usize;
    for opt in [s.rsrc, s.fpc_resources, s.rodata] {
        if let Some(range) = opt
            && let Some(slice) = ctx.section_data(&range)
        {
            had_section = true;
            total += count_tpf0(slice);
        }
    }
    if had_section {
        total
    } else {
        count_tpf0(ctx.data())
    }
}

/// High-level detection summary, used by `DelphiBinary::parse`.
#[derive(Debug, Clone)]
pub struct DetectionReport<'a> {
    /// Overall confidence.
    pub confidence: Confidence,
    /// Full compiler fingerprint when a marker matched. Borrows from the
    /// input byte buffer.
    pub compiler_info: Option<CompilerInfo<'a>>,
    /// Number of TPF0 magic occurrences found in the binary.
    pub tpf0_count: usize,
}

/// Find the first occurrence of `needle` in `haystack`, returning its offset.
fn find_bytes(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || needle.len() > haystack.len() {
        return None;
    }
    haystack.windows(needle.len()).position(|w| w == needle)
}

/// Count non-overlapping occurrences of `needle` in `haystack`.
fn count_bytes(haystack: &[u8], needle: &[u8]) -> usize {
    if needle.is_empty() || needle.len() > haystack.len() {
        return 0;
    }
    let mut n = 0usize;
    let mut i = 0usize;
    let last = haystack.len() - needle.len();
    while i <= last {
        if &haystack[i..i + needle.len()] == needle {
            n += 1;
            i += needle.len();
        } else {
            i += 1;
        }
    }
    n
}

fn is_printable_ascii(b: u8) -> bool {
    (0x20..=0x7e).contains(&b)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_delphi_12_win64_marker() {
        let blob = b"garbage...Embarcadero Delphi for Win64 compiler version 36.0 (29.0.55362.2017)\x00trailing";
        let info = scan_build_string(blob).expect("should detect delphi");
        assert_eq!(info.compiler, Compiler::Delphi);
        assert_eq!(info.version, Some("36.0"));
        assert_eq!(info.os, TargetOs::Windows);
        assert_eq!(info.arch, TargetArch::X86_64);
    }

    #[test]
    fn parses_fpc_win32_marker() {
        let blob = b"\x00\x00FPC 3.2.2 [2021/05/15] for i386 - Win32\x00\x00";
        let info = scan_build_string(blob).expect("should detect fpc");
        assert_eq!(info.compiler, Compiler::FreePascal);
        assert_eq!(info.version, Some("3.2.2"));
        assert_eq!(info.arch, TargetArch::X86);
        assert_eq!(info.os, TargetOs::Windows);
    }

    #[test]
    fn parses_fpc_darwin_aarch64_marker() {
        let blob = b"FPC 3.2.2 [2021/05/16] for aarch64 - Darwin\x00";
        let info = scan_build_string(blob).expect("should detect fpc");
        assert_eq!(info.arch, TargetArch::Aarch64);
        assert_eq!(info.os, TargetOs::Darwin);
    }

    #[test]
    fn rejects_non_delphi_buffer() {
        let blob = b"Hello, World!\nThis binary has nothing to do with Delphi or Pascal.";
        assert!(scan_build_string(blob).is_none());
        assert!(scan_compiler(blob).is_none());
        assert_eq!(count_tpf0(blob), 0);
    }

    #[test]
    fn tpf0_counting_skips_partial_matches() {
        let blob = b"TPF0 foo TPF0TPF1 TPF0";
        // Three legitimate TPF0 occurrences, one TPF1 that must be ignored.
        assert_eq!(count_tpf0(blob), 3);
    }

    #[test]
    fn borland_registry_fallback_identifies_pre_xe2_delphi() {
        // `scan_build_string` strict semantics — no build-string, no hit.
        let blob = b"random prefix SOFTWARE\\Borland\\Delphi\\RTL trailing bytes";
        assert!(scan_build_string(blob).is_none());

        // `scan_compiler` cascades into the legacy marker.
        let info = scan_compiler(blob).expect("should fall back to borland marker");
        assert_eq!(info.compiler, Compiler::Delphi);
        assert_eq!(info.source, DetectionSource::BorlandRegistry);
        assert_eq!(info.version, None);
        assert_eq!(info.raw, "SOFTWARE\\Borland\\Delphi\\RTL");
    }

    #[test]
    fn namespaced_units_fallback_identifies_xe2plus_delphi() {
        let blob = b"\x00blob with Vcl.Controls unit name embedded\x00";
        assert!(scan_build_string(blob).is_none());

        let info = scan_compiler(blob).expect("should fall back to namespaced marker");
        assert_eq!(info.compiler, Compiler::Delphi);
        assert_eq!(info.source, DetectionSource::NamespacedUnits);
        assert_eq!(info.version, None);
        assert_eq!(info.raw, "Vcl.Controls");
    }

    #[test]
    fn build_string_wins_over_legacy_marker() {
        // A binary with BOTH a build-string and a Borland registry path must
        // report the build-string match (higher information content).
        let blob = b"SOFTWARE\\Borland\\Delphi\\RTL plus Embarcadero Delphi for Win32 compiler version 26.0 (build)";
        let info = scan_compiler(blob).expect("should detect via build-string");
        assert_eq!(info.source, DetectionSource::BuildString);
        assert_eq!(info.version, Some("26.0"));
    }
}
