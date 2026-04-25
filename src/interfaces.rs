//! Interface-table iterator.
//!
//! Delphi and FPC use **different** interface table layouts.
//!
//! ## Delphi layout
//!
//! Source: `reference/pythia/pythia/core/structures.py:273-283`. The table
//! itself is length-prefixed; each entry inlines a 16-byte GUID followed by
//! three pointer-sized slots.
//!
//! ```text
//!   NumEntries: u32
//!   entries[NumEntries]:
//!     Guid:      [u8; 16]        (inline, as `{D1 : D2 : D3 : D4[]}`)
//!     VtablePtr: ptr
//!     IOffset:   u32             (classic Delphi kept this 32-bit)
//!     GetterPtr: ptr
//! ```
//!
//! On 64-bit Delphi the 3 pointer slots grow to 8 bytes each and `IOffset`
//! becomes a 4-byte field (still 32-bit), often padded to 8 bytes. The
//! implementation below auto-computes entry size from the slot layout.
//!
//! ## FPC layout
//!
//! Source: `reference/fpc-source/rtl/inc/objpash.inc:183-208` — FPC's
//! `tinterfaceentry` and `tinterfacetable`.
//!
//! ```text
//!   EntryCount: SizeUInt         (ptr-sized, NOT u32)
//!   entries[EntryCount]:
//!     IIDRef:           ptr      (pointer to PGuid — two-level indirection)
//!     VTable:           ptr
//!     IOffset:          sizeuint (ptr-sized, union with IOffsetAsCodePtr)
//!     IIDStrRef:        ptr      (pointer to PShortString)
//!     IType:            u8       (one-byte enum, then padding)
//! ```
//!
//! FPC's entry is variant-laid-out: the first three fields are always
//! present; `IIDStrRef` and `IType` are part of the Corba-interface
//! overlay. Classic COM-interface entries only include the first three
//! fields, with `IIDRef` pointing at a usable GUID. We decode the
//! first-three-fields prefix and fetch the GUID via `IIDRef`.

use std::fmt;

use crate::{
    formats::BinaryContext,
    limits::{MAX_INTERFACES_PER_CLASS, MAX_INTERFACES_PER_CLASS_FPC, MAX_METHODS_PER_CLASS},
    util::{read_ptr, read_short_string_at_va, read_u32},
    vmt::{Vmt, VmtFlavor},
};

/// A 128-bit GUID, stored in the Microsoft canonical record form.
///
/// Formatting matches Delphi's `GuidToString` / Microsoft's
/// `StringFromGUID2`: `{D1-D2-D3-D4[0..2]-D4[2..8]}`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Guid {
    /// First 32-bit component (little-endian).
    pub data1: u32,
    /// Next 16-bit component (little-endian).
    pub data2: u16,
    /// Next 16-bit component (little-endian).
    pub data3: u16,
    /// Final 8 bytes (big-endian when rendered as a string).
    pub data4: [u8; 8],
}

impl Guid {
    /// Construct from 16 little-endian bytes — equivalent to
    /// [`From<[u8; 16]>`](#impl-From%3C%5Bu8%3B+16%5D%3E-for-Guid),
    /// kept for backwards compatibility with code that holds a `&[u8; 16]`.
    #[inline]
    pub fn from_bytes(bytes: &[u8; 16]) -> Self {
        Self::from(*bytes)
    }

    /// Render as `{XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX}` (Microsoft /
    /// Delphi format), allocating a `String`. Equivalent to
    /// `format!("{guid}")`. Prefer the `Display` impl in hot paths to
    /// avoid the allocation.
    pub fn to_string_delphi(&self) -> String {
        self.to_string()
    }
}

impl From<[u8; 16]> for Guid {
    /// Construct a `Guid` from 16 little-endian bytes — the on-disk
    /// layout used by both Delphi (`TGuid` literal) and FPC.
    fn from(bytes: [u8; 16]) -> Self {
        Self {
            data1: u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]),
            data2: u16::from_le_bytes([bytes[4], bytes[5]]),
            data3: u16::from_le_bytes([bytes[6], bytes[7]]),
            data4: [
                bytes[8], bytes[9], bytes[10], bytes[11], bytes[12], bytes[13], bytes[14],
                bytes[15],
            ],
        }
    }
}

impl fmt::Display for Guid {
    /// Writes `{XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX}` directly to the
    /// formatter — no intermediate `String` allocation.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let d = &self.data4;
        write!(
            f,
            "{{{:08X}-{:04X}-{:04X}-{:02X}{:02X}-{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}}}",
            self.data1, self.data2, self.data3, d[0], d[1], d[2], d[3], d[4], d[5], d[6], d[7]
        )
    }
}

/// One interface entry on a class.
///
/// `iid_str` is only populated for FPC-flavor entries; Delphi uses COM
/// interfaces exclusively and doesn't emit the Corba-name slot.
#[derive(Debug, Clone)]
pub struct InterfaceEntry<'a> {
    /// Interface GUID (COM IID). All-zero when this is a Corba interface
    /// identified by [`Self::iid_str`] instead.
    pub guid: Guid,
    /// VA of the interface-dispatch vtable.
    pub vtable_va: u64,
    /// Offset relative to the instance (Delphi) or the VMT (FPC), depending
    /// on flavor. Exposed for downstream analysis; this library doesn't
    /// interpret it further in this iteration.
    pub offset: u64,
    /// VA of an optional "getter" function that fetches the interface by
    /// running custom Pascal code (used when the class implements the
    /// interface via `implements` delegation rather than a direct vtable).
    /// `0` when not applicable.
    pub getter_va: u64,
    /// For FPC Corba interfaces: the textual IID (e.g. `"ISomething"`).
    /// Resolved via `IIDStrRef: ^PShortString`. `None` on Delphi or when
    /// the indirection couldn't be followed.
    pub(crate) iid_str: Option<&'a [u8]>,
}

/// One method on an interface — produced by
/// [`crate::DelphiBinary::interface_methods`].
#[derive(Debug, Clone)]
pub struct InterfaceMethod<'a> {
    /// Slot index within the interface's vtable (0 = first method).
    pub slot_index: u16,
    /// Absolute VA of the method's code entry point — read off the
    /// interface's `vtable_va` array. Subtract the image base for an RVA.
    pub code_va: u64,
    /// Method name when the interface RTTI carries one (FPC `tkInterface`
    /// records do; classic Delphi COM interfaces do not). Lossily decoded.
    pub name: Option<&'a str>,
}

impl<'a> InterfaceEntry<'a> {
    /// For FPC Corba interfaces: the textual IID (e.g. `"ISomething"`),
    /// lossily decoded. `None` on Delphi binaries or when the indirection
    /// couldn't be followed.
    #[inline]
    pub fn iid_str(&self) -> Option<&'a str> {
        self.iid_str
            .map(|b| core::str::from_utf8(b).unwrap_or("<non-ascii>"))
    }

    /// Raw IID-string bytes for FPC Corba interfaces. `None` on Delphi or
    /// when the indirection couldn't be followed.
    #[inline]
    pub fn iid_str_bytes(&self) -> Option<&'a [u8]> {
        self.iid_str
    }
}

impl<'a> InterfaceMethod<'a> {
    /// Walk an interface's method-pointer array and return one entry
    /// per slot. The count is recovered by reading pointer-sized
    /// slots from `entry.vtable_va` and stopping at the first slot
    /// that does not contain a plausible code VA (zero, unmapped, or
    /// outside the binary's primary code section).
    ///
    /// `pointer_size` is the binary's pointer width (4 or 8). Names
    /// are always `None` here — names live in `tkInterface` RTTI which
    /// this walker doesn't consult; callers wanting names should go
    /// through [`crate::DelphiBinary::interface_methods`], which
    /// merges the RTTI index in.
    ///
    /// Hard-capped at [`MAX_METHODS_PER_CLASS`] to keep adversarial
    /// input from forcing pathological scans.
    pub fn iter(
        ctx: &BinaryContext<'a>,
        entry: &InterfaceEntry<'a>,
        pointer_size: usize,
    ) -> Vec<Self> {
        if entry.vtable_va == 0 || pointer_size == 0 {
            return Vec::new();
        }
        let Some(base_off) = ctx.va_to_file(entry.vtable_va) else {
            return Vec::new();
        };
        let data = ctx.data();
        let mut out = Vec::new();
        for slot in 0..MAX_METHODS_PER_CLASS {
            let Some(off) = slot
                .checked_mul(pointer_size)
                .and_then(|n| base_off.checked_add(n))
            else {
                break;
            };
            let Some(va) = read_ptr(data, off, pointer_size) else {
                break;
            };
            if va == 0 || !ctx.is_code_va(va) {
                break;
            }
            out.push(InterfaceMethod {
                slot_index: slot as u16,
                code_va: va,
                name: None,
            });
        }
        out
    }
}

impl<'a> InterfaceEntry<'a> {
    /// Decode every interface entry declared on `vmt`. Returns an
    /// empty vector when the class has no interface table or the
    /// table is malformed.
    pub fn iter(ctx: &BinaryContext<'a>, vmt: &Vmt<'a>) -> Vec<Self> {
        if vmt.intf_table == 0 {
            return Vec::new();
        }
        let result = match vmt.flavor {
            VmtFlavor::Delphi => iter_delphi(ctx, vmt),
            VmtFlavor::Fpc => iter_fpc(ctx, vmt),
        };
        result.unwrap_or_else(|| {
            crate::__undelphi_trace_warn!(
                vmt_va = vmt.va,
                intf_table = vmt.intf_table,
                "InterfaceEntry::iter: interface-table walk bailed out"
            );
            Vec::new()
        })
    }
}

fn iter_delphi<'a>(ctx: &BinaryContext<'a>, vmt: &Vmt<'a>) -> Option<Vec<InterfaceEntry<'a>>> {
    let base_off = ctx.va_to_file(vmt.intf_table)?;
    let data = ctx.data();
    let count = read_u32(data, base_off)? as usize;
    if count == 0 || count > MAX_INTERFACES_PER_CLASS {
        return Some(Vec::new());
    }

    let psize = vmt.pointer_size as usize;
    if psize < 4 {
        return None;
    }
    // Entry layout on 32-bit Delphi: GUID(16) + VTable(4) + IOffset(4) + Getter(4) = 28.
    // Entry layout on 64-bit Delphi: GUID(16) + VTable(8) + IOffset(8) + Getter(8) = 40.
    // The `IOffset` field is typed as `Integer`/`Longint` in Delphi source
    // but the record is pointer-aligned, so on 64-bit it occupies 8 bytes.
    // Verified empirically against HeidiSQL's `TInterfacedObject` entry.
    let offset_slot = psize;
    let entry_size = 16usize
        .checked_add(psize)?
        .checked_add(offset_slot)?
        .checked_add(psize)?;
    // After the 4-byte NumEntries header, pad to pointer alignment so
    // the first GUID's `Data1` lands on an aligned boundary.
    let entries_start = base_off
        .checked_add(4)?
        .checked_add(psize.checked_sub(4)?)?;

    let mut out = Vec::with_capacity(count);
    let mut cursor = entries_start;
    for _ in 0..count {
        let guid_end = cursor.checked_add(16)?;
        let guid_bytes = data.get(cursor..guid_end)?;
        let guid = Guid::from_bytes(guid_bytes.try_into().ok()?);
        let vtable_off = guid_end;
        let offset_off = vtable_off.checked_add(psize)?;
        let getter_off = offset_off.checked_add(offset_slot)?;
        let vtable_va = read_ptr(data, vtable_off, psize)?;
        let offset = read_ptr(data, offset_off, offset_slot)?;
        let getter_va = read_ptr(data, getter_off, psize)?;
        out.push(InterfaceEntry {
            guid,
            vtable_va,
            offset,
            getter_va,
            iid_str: None,
        });
        cursor = cursor.checked_add(entry_size)?;
    }
    Some(out)
}

fn iter_fpc<'a>(ctx: &BinaryContext<'a>, vmt: &Vmt<'a>) -> Option<Vec<InterfaceEntry<'a>>> {
    let base_off = ctx.va_to_file(vmt.intf_table)?;
    let data = ctx.data();
    let psize = vmt.pointer_size as usize;
    // `EntryCount` is `SizeUInt` (pointer-sized) per objpash.inc:206.
    let count = read_ptr(data, base_off, psize)? as usize;
    if count == 0 || count > MAX_INTERFACES_PER_CLASS_FPC {
        return Some(Vec::new());
    }

    // FPC entry: IIDRef (ptr) + VTable (ptr) + IOffset (ptr) + IIDStrRef (ptr) + IType (byte + padding).
    // Size varies because of the trailing one-byte enum. In practice FPC
    // emits records of size `round_up(4*ptr + 1, ptr)` = 5*ptr on both 32
    // and 64 bit, giving 20/40-byte entries.
    let entry_size = psize.checked_mul(5)?;

    let mut out = Vec::with_capacity(count);
    let mut cursor = base_off.checked_add(psize)?;
    for _ in 0..count {
        let iid_ref = read_ptr(data, cursor, psize)?;
        let vtable_off = cursor.checked_add(psize)?;
        let ioffset_off = vtable_off.checked_add(psize)?;
        let iid_str_ref_off = ioffset_off.checked_add(psize)?;
        let vtable_va = read_ptr(data, vtable_off, psize)?;
        let ioffset = read_ptr(data, ioffset_off, psize)?;
        let iid_str_ref = read_ptr(data, iid_str_ref_off, psize)?;

        // IIDRef is ^PGuid — dereference twice:
        //   deref_1 = *IIDRef  → a PGuid (VA of the 16-byte GUID)
        //   bytes at deref_1 = the GUID itself.
        // If we can't follow the indirection the entry is malformed —
        // skip rather than emit a null GUID that would later be
        // mistaken for a real `IID_NULL`.
        let Some(guid) = read_fpc_iid(ctx, iid_ref, psize) else {
            cursor = cursor.checked_add(entry_size)?;
            continue;
        };

        // IIDStrRef is ^PShortString — deref once to get the PShortString
        // VA, then read the short-string body. Per objpash.inc:200.
        let iid_str = read_fpc_iid_str(ctx, iid_str_ref, psize);

        out.push(InterfaceEntry {
            guid,
            vtable_va,
            offset: ioffset,
            getter_va: 0,
            iid_str,
        });
        cursor = cursor.checked_add(entry_size)?;
    }
    Some(out)
}

/// Follow `IIDStrRef: ^PShortString` two levels of indirection to recover
/// the Corba interface name.
fn read_fpc_iid_str<'a>(
    ctx: &BinaryContext<'a>,
    iid_str_ref_va: u64,
    ptr_size: usize,
) -> Option<&'a [u8]> {
    if iid_str_ref_va == 0 {
        return None;
    }
    let outer_off = ctx.va_to_file(iid_str_ref_va)?;
    let data = ctx.data();
    let pstr_va = read_ptr(data, outer_off, ptr_size)?;
    read_short_string_at_va(ctx, pstr_va)
}

fn read_fpc_iid(ctx: &BinaryContext<'_>, iid_ref_va: u64, ptr_size: usize) -> Option<Guid> {
    if iid_ref_va == 0 {
        return None;
    }
    let first_off = ctx.va_to_file(iid_ref_va)?;
    let data = ctx.data();
    let guid_va = read_ptr(data, first_off, ptr_size)?;
    let guid_off = ctx.va_to_file(guid_va)?;
    let guid_end = guid_off.checked_add(16)?;
    let guid_bytes = data.get(guid_off..guid_end)?;
    Some(Guid::from_bytes(guid_bytes.try_into().ok()?))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn guid_renders_canonical_form() {
        // The IUnknown IID: {00000000-0000-0000-C000-000000000046}
        let g = Guid {
            data1: 0,
            data2: 0,
            data3: 0,
            data4: [0xC0, 0, 0, 0, 0, 0, 0, 0x46],
        };
        assert_eq!(
            g.to_string_delphi(),
            "{00000000-0000-0000-C000-000000000046}"
        );
    }

    #[test]
    fn guid_from_bytes_matches_record() {
        let bytes = [
            0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF, 0x01, 0x23, 0x45, 0x67, 0x89, 0xAB,
            0xCD, 0xEF,
        ];
        let g = Guid::from_bytes(&bytes);
        assert_eq!(g.data1, 0x67452301);
        assert_eq!(g.data2, 0xAB89);
        assert_eq!(g.data3, 0xEFCD);
        assert_eq!(g.data4, [0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF]);
    }
}
