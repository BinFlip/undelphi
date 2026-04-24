//! Virtual Method Table (VMT) scanner and header parser.
//!
//! Every Delphi / C++Builder / FPC class has a VMT in the binary's
//! initialized-data payload. The VMT is the single most structural data
//! item in a Delphi/FPC binary — every class instance carries a pointer to
//! it, and every class-metadata table (RTTI, fields, methods, interfaces,
//! init) is reached through it. See `RESEARCH.md` §4 for background.
//!
//! ## Two flavors
//!
//! Delphi and FPC use **different VMT layouts**. The first 11 metadata
//! fields are the same *set* (InstanceSize, Parent, ClassName, MethodTable,
//! FieldTable, TypeInfo, InitTable, AutoTable, IntfTable, DynamicTable) but
//! their *order* differs, and FPC prefixes the table with the instance
//! size instead of a self-pointer.
//!
//! ### Delphi / C++Builder layout
//!
//! ```text
//!   +0*ptr   vmtSelfPtr       → points to VMT base + N×ptr (N header slots)
//!   +1*ptr   vmtIntfTable
//!   +2*ptr   vmtAutoTable
//!   +3*ptr   vmtInitTable
//!   +4*ptr   vmtTypeInfo
//!   +5*ptr   vmtFieldTable
//!   +6*ptr   vmtMethodTable
//!   +7*ptr   vmtDynamicTable
//!   +8*ptr   vmtClassName     → short-string (length-prefixed ASCII)
//!   +9*ptr   vmtInstanceSize
//!  +10*ptr   vmtParent        → parent VMT base VA, or 0 for TObject
//!  +N*ptr   ← start of virtual method pointers (N varies by Delphi version)
//! ```
//!
//! Source: `reference/pythia/pythia/core/structures.py:346-380`;
//! `reference/DelphiHelper/DelphiHelper/core/DelphiClass.py:29-41,180-234`.
//!
//! ### FPC layout (`rtl/inc/objpash.inc:75-90`)
//!
//! ```text
//!   +0*ptr   vmtInstanceSize
//!   +1*ptr   vmtInstanceSize2   (negative copy / msize; sanity-check slot)
//!   +2*ptr   vmtParent          → parent VMT base VA
//!   +3*ptr   vmtClassName       → short-string
//!   +4*ptr   vmtDynamicTable
//!   +5*ptr   vmtMethodTable
//!   +6*ptr   vmtFieldTable
//!   +7*ptr   vmtTypeInfo
//!   +8*ptr   vmtInitTable
//!   +9*ptr   vmtAutoTable
//!  +10*ptr   vmtIntfTable
//!  +11*ptr   vmtMsgStrPtr
//!  +12*ptr   ← start of virtual method pointers
//! ```
//!
//! ## Detection
//!
//! For Delphi-flavored VMTs we apply ESET DelphiHelper's shape-test:
//! `vmtSelfPtr` must target `base + N*ptr` for some `N ∈ [5, 30]`. For FPC
//! we have no self-pointer; instead we require:
//!
//! - `vmtInstanceSize` in `[pointer_size, 16 MiB]`
//! - `vmtInstanceSize2 == (uint)(-vmtInstanceSize)` truncated, OR zero
//!   (sanity-check observed in FPC-compiled binaries)
//! - `vmtParent` is 0 or a pointer into a readable segment
//! - `vmtClassName` points at a short-string with printable-ASCII body
//!
//! At every offset the scanner tries Delphi first, then FPC.
//!
//! ## Allocation
//!
//! The class-name slice returned by [`Vmt::class_name`] is a direct slice
//! of the caller's binary buffer; no string copy happens in the hot path.

use core::str;
use std::collections::HashSet;

use crate::{
    formats::{BinaryContext, BinaryFormat, SectionRange},
    limits::{MAX_CLASS_NAME_BYTES, MAX_INSTANCE_SIZE_BYTES},
    util::{read_ptr, read_short_string_at_va},
};

/// VMT flavor — distinguishes the Delphi field order from the FPC field order.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VmtFlavor {
    /// Delphi / C++Builder convention (vmtSelfPtr at offset 0).
    Delphi,
    /// Free Pascal / Lazarus convention (vmtInstanceSize at offset 0).
    Fpc,
}

/// Decoded VMT header fields. Pointer-sized values are widened to `u64`.
#[derive(Debug, Clone, Copy)]
pub struct Vmt<'a> {
    /// Which Pascal dialect produced this VMT.
    pub flavor: VmtFlavor,
    /// Pointer width of this VMT in bytes (4 or 8).
    pub pointer_size: u8,
    /// For Delphi: header slot count inferred from `vmtSelfPtr`. For FPC:
    /// `0` (not available — FPC VMTs have no self-pointer).
    pub header_slot_count: u8,

    /// Virtual address of the VMT base.
    pub va: u64,
    /// File offset of the VMT base.
    pub file_offset: usize,

    /// For Delphi: value of the `vmtSelfPtr` slot. For FPC: `0`.
    pub self_ptr: u64,
    /// VA of the interface table, or `0` if none.
    pub intf_table: u64,
    /// VA of the auto-dispatch table (mostly unused).
    pub auto_table: u64,
    /// VA of the init (managed-fields) table.
    pub init_table: u64,
    /// VA of the RTTI `PTypeInfo` record for this class.
    pub type_info: u64,
    /// VA of the field table.
    pub field_table: u64,
    /// VA of the published-method table.
    pub method_table: u64,
    /// VA of the dynamic-dispatch table.
    pub dynamic_table: u64,
    /// VA of the class-name short-string.
    pub class_name_ptr: u64,
    /// Instance size in bytes.
    pub instance_size: u32,
    /// VA of the parent class's VMT base, or `0` for root classes.
    pub parent_vmt: u64,

    /// Class-name short-string body; borrows from the input buffer.
    pub class_name: &'a [u8],
}

impl<'a> Vmt<'a> {
    /// Class name as `&str`, or `None` if not UTF-8. In practice Delphi /
    /// FPC class names are always ASCII.
    #[inline]
    pub fn class_name_str(&self) -> Option<&'a str> {
        str::from_utf8(self.class_name).ok()
    }
}

/// Delphi shape bounds (slot count of `vmtSelfPtr − base` divided by pointer width).
const DELPHI_MIN_HEADER_SLOTS: u64 = 5;
const DELPHI_MAX_HEADER_SLOTS: u64 = 30;

/// Minimum number of pointer-sized slots needed to parse an FPC header.
/// We read fields 0 through 10 (IntfTable), so we need at least 11 slots.
const FPC_MIN_SLOTS: usize = 11;

/// Scan the binary for VMT candidates, returning every validated VMT.
///
/// Covers both Delphi and FPC flavors at every pointer-aligned offset.
pub fn scan<'a>(ctx: &BinaryContext<'a>) -> Vec<Vmt<'a>> {
    let ranges = ctx.scan_ranges();
    if ranges.is_empty() {
        return Vec::new();
    }

    let widths: &[usize] = match ctx.pointer_size() {
        Some(4) => &[4],
        Some(8) => &[8],
        _ if ctx.format() == BinaryFormat::Unknown => &[],
        _ => &[4, 8],
    };

    let mut out = Vec::new();
    let mut seen_va: HashSet<u64> = HashSet::new();

    for range in ranges {
        let Some(bytes) = ctx.section_data(range) else {
            continue;
        };
        for &psize in widths {
            let min_header = 11 * psize;
            if bytes.len() < min_header {
                continue;
            }
            let mut i = 0usize;
            while i + min_header <= bytes.len() {
                if let Some(vmt) = try_parse_delphi(ctx, range, bytes, i, psize) {
                    if seen_va.insert(vmt.va) {
                        out.push(vmt);
                    }
                } else if let Some(vmt) = try_parse_fpc(ctx, range, bytes, i, psize)
                    && seen_va.insert(vmt.va)
                {
                    out.push(vmt);
                }
                i += psize;
            }
        }
    }
    out
}

fn try_parse_delphi<'a>(
    ctx: &BinaryContext<'a>,
    range: &SectionRange,
    bytes: &'a [u8],
    off: usize,
    psize: usize,
) -> Option<Vmt<'a>> {
    if off + 11 * psize > bytes.len() {
        return None;
    }
    let base_va = range.va + off as u64;

    let self_ptr = read_ptr(bytes, off, psize)?;
    if self_ptr <= base_va {
        return None;
    }
    let header_bytes = self_ptr - base_va;
    if !header_bytes.is_multiple_of(psize as u64) {
        return None;
    }
    let slots = header_bytes / (psize as u64);
    if !(DELPHI_MIN_HEADER_SLOTS..=DELPHI_MAX_HEADER_SLOTS).contains(&slots) {
        return None;
    }

    let intf_table = read_ptr(bytes, off + psize, psize)?;
    let auto_table = read_ptr(bytes, off + 2 * psize, psize)?;
    let init_table = read_ptr(bytes, off + 3 * psize, psize)?;
    let type_info = read_ptr(bytes, off + 4 * psize, psize)?;
    let field_table = read_ptr(bytes, off + 5 * psize, psize)?;
    let method_table = read_ptr(bytes, off + 6 * psize, psize)?;
    let dynamic_table = read_ptr(bytes, off + 7 * psize, psize)?;
    let class_name_ptr = read_ptr(bytes, off + 8 * psize, psize)?;
    let instance_size_raw = read_ptr(bytes, off + 9 * psize, psize)?;
    let parent_vmt = read_ptr(bytes, off + 10 * psize, psize)?;

    if !is_plausible_instance_size(instance_size_raw, psize) {
        return None;
    }
    let instance_size = instance_size_raw as u32;

    let class_name = read_short_string_at_va(ctx, class_name_ptr)?;
    if !is_plausible_class_name(class_name) {
        return None;
    }

    Some(Vmt {
        flavor: VmtFlavor::Delphi,
        pointer_size: psize as u8,
        header_slot_count: slots as u8,
        va: base_va,
        file_offset: range.offset + off,
        self_ptr,
        intf_table,
        auto_table,
        init_table,
        type_info,
        field_table,
        method_table,
        dynamic_table,
        class_name_ptr,
        instance_size,
        parent_vmt,
        class_name,
    })
}

fn try_parse_fpc<'a>(
    ctx: &BinaryContext<'a>,
    range: &SectionRange,
    bytes: &'a [u8],
    off: usize,
    psize: usize,
) -> Option<Vmt<'a>> {
    if off + FPC_MIN_SLOTS * psize > bytes.len() {
        return None;
    }
    let base_va = range.va + off as u64;

    let instance_size_raw = read_ptr(bytes, off, psize)?;
    if !is_plausible_instance_size(instance_size_raw, psize) {
        return None;
    }
    let instance_size = instance_size_raw as u32;

    // Field 1: `vmtInstanceSize2` — FPC stores `-vmtInstanceSize` here,
    // truncated to pointer width. Required for validation; this is the
    // main discriminator that keeps FPC false-positive rates acceptable.
    let size2 = read_ptr(bytes, off + psize, psize)?;
    let expected_neg = match psize {
        4 => (!(instance_size as u64)).wrapping_add(1) & 0xFFFF_FFFF,
        _ => (!instance_size_raw).wrapping_add(1),
    };
    if size2 != expected_neg {
        return None;
    }

    // Field 2: parent VMT.
    let parent_vmt = read_ptr(bytes, off + 2 * psize, psize)?;

    // Field 3: class name short-string.
    let class_name_ptr = read_ptr(bytes, off + 3 * psize, psize)?;
    let class_name = read_short_string_at_va(ctx, class_name_ptr)?;
    if !is_plausible_class_name(class_name) {
        return None;
    }

    // Field 4..10: tables. We accept any value; these are used downstream.
    let dynamic_table = read_ptr(bytes, off + 4 * psize, psize)?;
    let method_table = read_ptr(bytes, off + 5 * psize, psize)?;
    let field_table = read_ptr(bytes, off + 6 * psize, psize)?;
    let type_info = read_ptr(bytes, off + 7 * psize, psize)?;
    let init_table = read_ptr(bytes, off + 8 * psize, psize)?;
    let auto_table = read_ptr(bytes, off + 9 * psize, psize)?;
    let intf_table = read_ptr(bytes, off + 10 * psize, psize)?;

    Some(Vmt {
        flavor: VmtFlavor::Fpc,
        pointer_size: psize as u8,
        header_slot_count: 0,
        va: base_va,
        file_offset: range.offset + off,
        self_ptr: 0,
        intf_table,
        auto_table,
        init_table,
        type_info,
        field_table,
        method_table,
        dynamic_table,
        class_name_ptr,
        instance_size,
        parent_vmt,
        class_name,
    })
}

#[inline]
fn is_plausible_instance_size(raw: u64, psize: usize) -> bool {
    raw >= psize as u64 && raw <= MAX_INSTANCE_SIZE_BYTES
}

fn is_plausible_class_name(name: &[u8]) -> bool {
    // Length cap is empirically grounded — see [`MAX_CLASS_NAME_BYTES`].
    if name.is_empty() || name.len() > MAX_CLASS_NAME_BYTES {
        return false;
    }
    // Delphi / FPC class names are Pascal identifiers — possibly with
    // generics / namespace punctuation. Anything else is prose.
    if !name.iter().all(|&b| is_identifier_byte(b)) {
        return false;
    }
    // Must start with an uppercase letter, underscore, or `@` (compiler-
    // synthesised names). Historically every Delphi / FPC class starts
    // with `T` / `I` / `E` / `C`, but we accept any upper-case letter.
    let first = name[0];
    first.is_ascii_uppercase() || first == b'_' || first == b'@'
}

fn is_identifier_byte(b: u8) -> bool {
    b.is_ascii_alphanumeric()
        || matches!(
            b,
            b'_' | b'.' | b'<' | b'>' | b',' | b':' | b'&' | b'@' | b' '
        )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn class_name_plausibility_rejects_control_chars() {
        assert!(is_plausible_class_name(b"TComponent"));
        assert!(is_plausible_class_name(b"TComparer<System.TPair>"));
        assert!(!is_plausible_class_name(b""));
        assert!(!is_plausible_class_name(b"\x00hello"));
        assert!(!is_plausible_class_name(b"\x80name"));
    }
}
