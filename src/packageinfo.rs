//! `PACKAGEINFO` resource parser.
//!
//! Every Delphi / C++Builder executable that uses the VCL or FMX libraries
//! embeds a `PACKAGEINFO` resource of type `RT_RCDATA` that lists the units
//! compiled into the binary and the packages it requires at load time.
//!
//! Layout (all integers little-endian, all strings NUL-terminated ASCII),
//! verbatim from `reference/pythia/pythia/core/structures.py:66-83`:
//!
//! ```text
//! packageinfo {
//!     Flags          u32
//!     RequiresCount  u32
//!     Requires[RequiresCount] {
//!         HashCode   u8
//!         Name       CString
//!     }
//!     ContainsCount  u32
//!     Contains[ContainsCount] {
//!         Flags      u8
//!         HashCode   u8
//!         Name       CString
//!     }
//! }
//! ```
//!
//! Notes:
//!
//! - The outer `Flags` is a bitfield of `pfXxx` package-level flags
//!   (designtime / runtime / weak-packaging etc.). The individual bit
//!   definitions are not yet documented here — this iteration only surfaces
//!   the value as-is.
//! - The per-unit `Flags` byte carries `ufMainUnit`, `ufPackageUnit`,
//!   `ufWeakUnit`, `ufImplicitUnit`, etc.
//! - `HashCode` is a compiler-emitted check digit. We expose it but do not
//!   verify it.

use std::str;

/// Parsed PACKAGEINFO resource. All strings borrow from the resource
/// body provided to [`parse`].
#[derive(Debug, Clone)]
pub struct PackageInfo<'a> {
    /// Package-level flags (`pfXxx`).
    pub flags: u32,
    /// Names of packages this binary requires (BPL dependencies).
    pub requires: Vec<RequiredPackage<'a>>,
    /// Units linked into this binary.
    pub contains: Vec<ContainedUnit<'a>>,
}

/// One entry of the PACKAGEINFO `Requires` list.
#[derive(Debug, Clone, Copy)]
pub struct RequiredPackage<'a> {
    /// Compiler-emitted check digit.
    pub hash: u8,
    /// Package name (e.g. `rtl110.bpl` without the extension, or `rtl`).
    pub name: &'a str,
}

/// One entry of the PACKAGEINFO `Contains` list.
#[derive(Debug, Clone, Copy)]
pub struct ContainedUnit<'a> {
    /// Per-unit flags byte.
    pub flags: u8,
    /// Compiler-emitted check digit.
    pub hash: u8,
    /// Fully qualified unit name (e.g. `System.SysUtils`).
    pub name: &'a str,
}

/// Parse a PACKAGEINFO resource body.
///
/// Returns `None` on any structural error: truncation, non-ASCII name, or
/// impossible count. The parser deliberately does not allocate for strings —
/// every `name` is a slice of the input buffer.
pub fn parse<'a>(raw: &'a [u8]) -> Option<PackageInfo<'a>> {
    let mut cur = Cursor::new(raw);
    let flags = cur.read_u32()?;
    let requires_count = cur.read_u32()? as usize;
    // Plausibility guard — a resource with millions of entries is garbage.
    if requires_count > 65_536 {
        return None;
    }
    let mut requires = Vec::with_capacity(requires_count);
    for _ in 0..requires_count {
        let hash = cur.read_u8()?;
        let name = cur.read_cstr_ascii()?;
        requires.push(RequiredPackage { hash, name });
    }

    let contains_count = cur.read_u32()? as usize;
    if contains_count > 65_536 {
        return None;
    }
    let mut contains = Vec::with_capacity(contains_count);
    for _ in 0..contains_count {
        let flags_b = cur.read_u8()?;
        let hash = cur.read_u8()?;
        let name = cur.read_cstr_ascii()?;
        contains.push(ContainedUnit {
            flags: flags_b,
            hash,
            name,
        });
    }

    Some(PackageInfo {
        flags,
        requires,
        contains,
    })
}

struct Cursor<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Cursor<'a> {
    fn new(buf: &'a [u8]) -> Self {
        Self { buf, pos: 0 }
    }

    fn read_u8(&mut self) -> Option<u8> {
        let b = *self.buf.get(self.pos)?;
        self.pos = self.pos.checked_add(1)?;
        Some(b)
    }

    fn read_u32(&mut self) -> Option<u32> {
        let end = self.pos.checked_add(4)?;
        let bytes = self.buf.get(self.pos..end)?;
        self.pos = end;
        Some(u32::from_le_bytes(bytes.try_into().ok()?))
    }

    /// Read a zero-terminated ASCII string and advance past the terminator.
    fn read_cstr_ascii(&mut self) -> Option<&'a str> {
        let start = self.pos;
        let tail = self.buf.get(start..)?;
        let rel = tail.iter().position(|&b| b == 0)?;
        let end = start.checked_add(rel)?;
        let bytes = self.buf.get(start..end)?;
        self.pos = end.checked_add(1)?;
        str::from_utf8(bytes).ok()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_synthetic_packageinfo() {
        // Minimal synthetic resource: 1 require, 2 contains.
        let mut raw = Vec::new();
        raw.extend_from_slice(&0x0000_0001u32.to_le_bytes()); // Flags
        raw.extend_from_slice(&1u32.to_le_bytes()); // RequiresCount
        raw.push(0x11); // hash
        raw.extend_from_slice(b"rtl\0");
        raw.extend_from_slice(&2u32.to_le_bytes()); // ContainsCount
        raw.push(0x01); // flags
        raw.push(0x22); // hash
        raw.extend_from_slice(b"System.SysUtils\0");
        raw.push(0x00); // flags
        raw.push(0x33); // hash
        raw.extend_from_slice(b"Main\0");

        let pkg = parse(&raw).expect("should parse");
        assert_eq!(pkg.flags, 1);
        assert_eq!(pkg.requires.len(), 1);
        assert_eq!(pkg.requires[0].name, "rtl");
        assert_eq!(pkg.requires[0].hash, 0x11);
        assert_eq!(pkg.contains.len(), 2);
        assert_eq!(pkg.contains[0].name, "System.SysUtils");
        assert_eq!(pkg.contains[0].flags, 0x01);
        assert_eq!(pkg.contains[1].name, "Main");
    }

    #[test]
    fn rejects_implausible_counts() {
        // Claim 1 billion requires in a 12-byte buffer.
        let mut raw = Vec::new();
        raw.extend_from_slice(&0u32.to_le_bytes());
        raw.extend_from_slice(&1_000_000_000u32.to_le_bytes());
        raw.extend_from_slice(&0u32.to_le_bytes());
        assert!(parse(&raw).is_none());
    }

    #[test]
    fn rejects_truncated_buffer() {
        assert!(parse(&[]).is_none());
        assert!(parse(&[0u8; 3]).is_none());
    }
}
