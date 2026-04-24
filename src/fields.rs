//! Published-field table decoder.
//!
//! Reads the table referenced by `vmtFieldTable`. Delphi emits either the
//! legacy layout (a single count + entries that index into a separate
//! field-classes table) or the modern layout (post-2010 extended RTTI,
//! one self-contained entry per field with a direct `PPTypeInfo` pointer).
//! FPC emits yet another shape.
//!
//! ## Delphi legacy layout
//!
//! Source: `reference/pythia/pythia/core/structures.py:291-300,317-323`.
//!
//! ```text
//!   Header:           u16     (entry count — if zero, layout is modern)
//!   FieldTypesPtr:    ptr     (points at a separate array of class VMTs)
//!   entries[Header]:
//!     Offset:       u32       (instance-relative byte offset)
//!     TypeIndex:    u16       (index into the class-types table)
//!     Name:         ShortString
//! ```
//!
//! ## Delphi modern layout
//!
//! Triggered when the first `u16` is `0`. Source: `structures.py:302-315`.
//!
//! ```text
//!   unk2:          [u8; 4]    (4 zero/meta bytes)
//!   NumFields:     u16
//!   entries[NumFields]:
//!     unk1:        u8
//!     TypeInfoPtr: ptr        (PPTypeInfo — direct pointer)
//!     Offset:      u32
//!     Name:        ShortString
//!     NumExtra:    u16
//!     Extra:       [u8; NumExtra - 2]
//! ```
//!
//! ## FPC layout
//!
//! Source: `reference/fpc-source/rtl/objpas/typinfo.pp:214-250`.
//!
//! ```text
//!   TVmtFieldTable:
//!     Count:     u16
//!     ClassTab:  ptr         (PVmtFieldClassTab — array of PClass)
//!     Fields:    TVmtFieldEntry[Count]
//!
//!   TVmtFieldEntry (variable size):
//!     FieldOffset: SizeUInt  (ptr-sized)
//!     TypeIndex:   u16
//!     Name:        ShortString
//! ```
//!
//! ## Allocation
//!
//! The field-name slice borrows from the caller's byte buffer.

use core::str;

use crate::{
    formats::{BinaryContext, BinaryFormat},
    limits::{MAX_FIELDS_PER_CLASS, MAX_IDENTIFIER_BYTES},
    util::{read_ptr, read_short_string_at_file, read_u16, read_u32},
    vmt::{Vmt, VmtFlavor},
};

/// One published field of a class.
#[derive(Debug, Clone, Copy)]
pub struct Field<'a> {
    /// Byte offset of the field within the instance (relative to the
    /// object's start).
    pub offset: u32,
    /// Either a raw `PPTypeInfo` VA (modern Delphi / FPC) or a table-index
    /// into the class-types array (legacy Delphi).
    pub type_ref: FieldTypeRef,
    /// Field name; borrows from the input buffer.
    pub name: &'a [u8],
}

impl<'a> Field<'a> {
    /// Name as `&str`.
    pub fn name_str(&self) -> &'a str {
        str::from_utf8(self.name).unwrap_or("<non-ascii>")
    }
}

/// How a field's type is referenced.
#[derive(Debug, Clone, Copy)]
pub enum FieldTypeRef {
    /// Direct `PPTypeInfo` VA (modern Delphi / FPC).
    TypeInfoPtr(u64),
    /// Index into the class-types table (legacy Delphi).
    TypeIndex(u16),
}

/// Decode every published field of `vmt`.
pub fn iter_fields<'a>(ctx: &BinaryContext<'a>, vmt: &Vmt<'a>) -> Vec<Field<'a>> {
    if vmt.field_table == 0 {
        return Vec::new();
    }
    match vmt.flavor {
        VmtFlavor::Delphi => iter_delphi(ctx, vmt).unwrap_or_default(),
        VmtFlavor::Fpc => iter_fpc(ctx, vmt).unwrap_or_default(),
    }
}

fn iter_delphi<'a>(ctx: &BinaryContext<'a>, vmt: &Vmt<'a>) -> Option<Vec<Field<'a>>> {
    let base_off = ctx.va_to_file(vmt.field_table)?;
    let data = ctx.data();
    let header = read_u16(data, base_off)?;
    let psize = vmt.pointer_size as usize;
    if header == 0 {
        // Modern layout.
        read_modern_delphi(data, base_off + 2, psize)
    } else {
        // Legacy layout.
        read_legacy_delphi(data, base_off, header as usize, psize)
    }
}

fn read_legacy_delphi(
    data: &[u8],
    base_off: usize,
    count: usize,
    psize: usize,
) -> Option<Vec<Field<'_>>> {
    // Header: u16 count + ptr fieldtypes_ptr.
    // Layout: [count:u16][fieldtypes_ptr:ptr][entries...]
    // Earlier field-types table is referenced by pythia but we don't
    // dereference it — we return the index so callers can resolve it if
    // they want.
    if count == 0 || count > MAX_FIELDS_PER_CLASS {
        return Some(Vec::new());
    }
    let mut cursor = base_off + 2 + psize;
    let mut out = Vec::with_capacity(count);
    for _ in 0..count {
        let offset = read_u32(data, cursor)?;
        let type_index = read_u16(data, cursor + 4)?;
        let name = read_short_string_at_file(data, cursor + 6)?;
        if !is_plausible_name(name) {
            return None;
        }
        out.push(Field {
            offset,
            type_ref: FieldTypeRef::TypeIndex(type_index),
            name,
        });
        cursor += 6 + 1 + name.len();
    }
    Some(out)
}

fn read_modern_delphi(data: &[u8], after_header: usize, psize: usize) -> Option<Vec<Field<'_>>> {
    // After the 2-byte header=0 marker, pythia documents 4 bytes of
    // unk2 before NumFields. Some Delphi versions don't emit the unk2 —
    // empirically the count is sometimes at +0 and sometimes at +4.
    // Probe both offsets and accept whichever yields a plausible count.
    for unk2_skip in [4usize, 0usize] {
        let count_off = after_header + unk2_skip;
        let Some(count) = read_u16(data, count_off) else {
            continue;
        };
        let count = count as usize;
        if count == 0 || count > MAX_FIELDS_PER_CLASS {
            continue;
        }
        let Some(fields) = try_modern_entries(data, count_off + 2, count, psize) else {
            continue;
        };
        return Some(fields);
    }
    None
}

fn try_modern_entries(
    data: &[u8],
    entries_off: usize,
    count: usize,
    psize: usize,
) -> Option<Vec<Field<'_>>> {
    let mut cursor = entries_off;
    let mut out = Vec::with_capacity(count);
    for _ in 0..count {
        // Layout per pythia `field_entry_modern`:
        //   unk1:   u8
        //   typeinfo_ptr: ptr
        //   offset: u32
        //   name:   ShortString
        //   num_extra: u16
        //   extra: [num_extra - 2] bytes
        let _unk1 = *data.get(cursor)?;
        let type_ref_va = read_ptr(data, cursor + 1, psize)?;
        let offset = read_u32(data, cursor + 1 + psize)?;
        let name_off = cursor + 1 + psize + 4;
        let name = read_short_string_at_file(data, name_off)?;
        if !is_plausible_name(name) {
            return None;
        }
        let after_name = name_off + 1 + name.len();
        let num_extra = read_u16(data, after_name)? as usize;
        if num_extra < 2 {
            return None;
        }
        let record_size = (1 + psize + 4) + 1 + name.len() + num_extra;
        out.push(Field {
            offset,
            type_ref: FieldTypeRef::TypeInfoPtr(type_ref_va),
            name,
        });
        cursor += record_size;
    }
    Some(out)
}

fn iter_fpc<'a>(ctx: &BinaryContext<'a>, vmt: &Vmt<'a>) -> Option<Vec<Field<'a>>> {
    let base_off = ctx.va_to_file(vmt.field_table)?;
    let data = ctx.data();
    let psize = vmt.pointer_size as usize;
    let count = read_u16(data, base_off)? as usize;
    if count == 0 || count > MAX_FIELDS_PER_CLASS {
        return Some(Vec::new());
    }
    // On Mach-O / ELF with FPC's `FPC_REQUIRES_PROPER_ALIGNMENT` (enabled
    // on non-x86 targets), the `ClassTab: pointer` field is pointer-aligned
    // after the `Count: u16`, which inserts `ptr_size - 2` bytes of padding.
    // On PE packs are kept.
    let needs_alignment = ptr_aligned_on_non_x86(ctx);
    let classtab_off = if needs_alignment {
        align_up(base_off + 2, psize)
    } else {
        base_off + 2
    };
    let mut cursor = classtab_off + psize;
    let mut out = Vec::with_capacity(count);
    for _ in 0..count {
        if needs_alignment {
            cursor = align_up(cursor, psize);
        }
        let offset = read_ptr(data, cursor, psize)? as u32;
        let type_index = read_u16(data, cursor + psize)?;
        let name = read_short_string_at_file(data, cursor + psize + 2)?;
        if !is_plausible_name(name) {
            return None;
        }
        out.push(Field {
            offset,
            type_ref: FieldTypeRef::TypeIndex(type_index),
            name,
        });
        cursor += psize + 2 + 1 + name.len();
    }
    Some(out)
}

fn ptr_aligned_on_non_x86(ctx: &BinaryContext<'_>) -> bool {
    // Mach-O and ELF binaries on ARM / ARM64 get FPC's proper-alignment
    // mode. We approximate by "not PE" since Mach-O on ARM is our main
    // case. PE (Windows) always uses x86/x86-64 where FPC keeps packed.
    ctx.format() != BinaryFormat::Pe
}

#[inline]
fn align_up(off: usize, to: usize) -> usize {
    let rem = off % to;
    if rem == 0 { off } else { off + (to - rem) }
}

fn is_plausible_name(name: &[u8]) -> bool {
    if name.is_empty() || name.len() > MAX_IDENTIFIER_BYTES {
        return false;
    }
    // Pascal identifier or `F`-prefixed field.
    name.iter().all(|&b| b.is_ascii_alphanumeric() || b == b'_')
}
