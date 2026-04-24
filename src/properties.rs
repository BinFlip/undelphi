//! Published-property decoder.
//!
//! Reads the `TPropData` block that follows the `tkClass` TypeData
//! `UnitName` short-string. Each entry (`TPropInfo`) captures one published
//! property's runtime-dispatch metadata: its type info pointer, getter /
//! setter / stored function pointers, `Index`, `Default`, name, and the
//! bit-flags that indicate whether getter/setter/stored are code pointers,
//! virtual-table offsets, or direct field offsets.
//!
//! ## Delphi `TPropInfo` layout
//!
//! Source: `reference/DelphiHelper/DelphiHelper/core/DelphiClass_TypeInfo_tkClass.py:89-139`
//! (pointer-arithmetic that computes each entry's recordSize).
//!
//! ```text
//!   PropType:    PPTypeInfo    (ptr-sized, points at the property's tkXxx)
//!   GetProc:     Pointer       (ptr-sized)
//!   SetProc:     Pointer       (ptr-sized)
//!   StoredProc:  Pointer       (ptr-sized)
//!   Index:       Integer       (4 bytes)
//!   Default:     Longint       (4 bytes)
//!   NameIndex:   SmallInt      (2 bytes)
//!   Name:        ShortString   (length byte + body)
//! ```
//!
//! Total size per entry: `4 * ptr + 11 + len(Name)`.
//!
//! ## Getter / setter / stored dispatch encoding (Delphi)
//!
//! Delphi packs the dispatch kind into the high byte of the
//! `GetProc` / `SetProc` / `StoredProc` pointer. The encoding is
//! pointer-width-independent — in both 32-bit and 64-bit binaries the
//! discriminator lives in the *most-significant byte* of the
//! pointer-sized slot:
//!
//! | Top byte | Meaning |
//! |----------|---------|
//! | `0x00..=0x7F` (top two bits clear) | Direct code pointer — call this function. |
//! | `0xFE` | Virtual method — low bits are the VMT-relative slot index. |
//! | `0xFF` | Direct field offset — low bits are the instance-relative offset. |
//!
//! Sources: `reference/DelphiHelper/DelphiHelper/core/DelphiClass_TypeInfo_tkClass.py:107-119`
//! (`bitmask & 0xC0 == 0` test for "static code pointer") and the same
//! file at lines `294-305` (`(entry >> shiftVal) == 0xFF` test for the
//! field-offset branch). The 64-bit shift width is `(ptr_size - 1) * 8 =
//! 56`, so the comparison still operates on the top byte.
//!
//! ## FPC caveat
//!
//! FPC's `TPropInfo` carries extra fields (`PropProcs: Byte`, `IsStatic: Boolean`,
//! `PropParams: PPropParams`) before `Name`. This iteration only exposes the
//! Delphi-compatible shape; FPC properties are still decoded but the `flags`
//! and Name offset may be slightly off for non-trivial properties. A
//! flavor-specific FPC decoder is reserved for a future iteration.

use core::str;

use crate::{
    formats::BinaryContext,
    limits::{MAX_IDENTIFIER_BYTES, MAX_PROPERTIES_PER_CLASS},
    rtti::tkclass_from_vmt,
    util::{read_ptr, read_short_string_at_file, read_u16, read_u32},
    vmt::{Vmt, VmtFlavor},
};

/// How the compiler dispatches a getter / setter / stored access.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AccessKind {
    /// No handler — common for `stored` on read-only properties, or for
    /// setters on read-only properties.
    None,
    /// Direct field access — the value is the instance-relative byte offset.
    Field,
    /// Virtual method — the value is the VMT slot index.
    Virtual,
    /// Static method — the value is a code pointer (VA).
    Static,
    /// FPC "constant" access where the raw value is a constant index.
    Const,
}

/// Dispatch descriptor for a getter / setter / stored access.
#[derive(Debug, Clone, Copy)]
pub struct Access {
    /// How to interpret `value`.
    pub kind: AccessKind,
    /// Kind-dependent value: field offset, VMT index, or code VA.
    pub value: u64,
}

impl Access {
    /// Decode a raw `TPropInfo` getter/setter/stored pointer into an
    /// access descriptor, inspecting the high bits that discriminate
    /// field-offset / virtual-slot / static-code-pointer encodings
    /// (the Delphi convention).
    pub fn from_ptr(raw: u64, ptr_size: usize) -> Self {
        // Inspect the top byte of the pointer — Delphi encodes `$FF..` for
        // "field offset" and `$FE..` for "virtual dispatch" on 64-bit (and
        // similar on 32-bit, where the high byte of a 32-bit pointer
        // carries the same discriminator bits).
        let shift = (ptr_size - 1) * 8;
        let top = (raw >> shift) as u8;
        let mask = ptr_size * 8;
        let low_mask = if mask == 64 {
            0x00FF_FFFF_FFFF_FFFFu64
        } else {
            0x00FF_FFFFu64
        };
        match top {
            0xFF => Access {
                kind: AccessKind::Field,
                value: raw & low_mask,
            },
            0xFE => Access {
                kind: AccessKind::Virtual,
                value: raw & low_mask,
            },
            _ => Access {
                kind: AccessKind::Static,
                value: raw,
            },
        }
    }

    /// FPC-specific access decoder. FPC stores the dispatch type in the
    /// 2-bit slots of `PropProcs`. Constants from
    /// `reference/fpc-source/rtl/objpas/typinfo.pp:146-149`:
    ///
    /// | Bits | Name      | Meaning |
    /// |------|-----------|---------|
    /// | `00` | `ptField` | Direct field access (raw value = instance-relative offset) |
    /// | `01` | `ptStatic`| Static procedure (raw value = code VA) |
    /// | `10` | `ptVirtual`| Virtual method (raw value = VMT slot index) |
    /// | `11` | `ptConst` | Constant (raw value holds the constant) |
    ///
    /// `slot_bits_offset` is `0` for Get, `2` for Set, `4` for Stored.
    pub fn from_fpc(raw: u64, prop_procs: u8, slot_bits_offset: u8) -> Self {
        let bits = (prop_procs >> slot_bits_offset) & 0x3;
        match bits {
            0 => Access {
                kind: AccessKind::Field,
                value: raw,
            },
            1 => Access {
                kind: AccessKind::Static,
                value: raw,
            },
            2 => Access {
                kind: AccessKind::Virtual,
                value: raw,
            },
            3 => Access {
                kind: AccessKind::Const,
                value: raw,
            },
            _ => unreachable!(),
        }
    }
}

/// One published property of a class.
#[derive(Debug, Clone, Copy)]
pub struct Property<'a> {
    /// Virtual address of the `TPropInfo` record.
    pub va: u64,
    /// Getter access descriptor.
    pub get: Access,
    /// Setter access descriptor. For read-only properties the kind is
    /// `Static` with `value == 0`.
    pub set: Access,
    /// `Stored` clause access descriptor.
    pub stored: Access,
    /// Property index (as in `property Foo[I: Integer]: Bar index I`).
    pub index: i32,
    /// Default value — compiler's serialised representation of the
    /// `default` clause.
    pub default: i32,
    /// Name-index hint for fast property lookup.
    pub name_index: i16,
    /// Property name; borrows from the input buffer.
    pub name: &'a [u8],
    /// Virtual address the `PropType` PPTypeInfo indirection holds.
    pub prop_type_ref: u64,
}

impl<'a> Property<'a> {
    /// Name as `&str`.
    pub fn name_str(&self) -> &'a str {
        str::from_utf8(self.name).unwrap_or("<non-ascii>")
    }
}

/// Decode every published property of `vmt`. Walks the class's tkClass
/// TypeData up to and including `UnitName`, then reads the `TPropData`
/// block that follows. Returns an empty vector if no RTTI is attached.
pub fn iter_properties<'a>(ctx: &BinaryContext<'a>, vmt: &Vmt<'a>) -> Vec<Property<'a>> {
    match vmt.flavor {
        VmtFlavor::Delphi => iter_delphi(ctx, vmt).unwrap_or_default(),
        // FPC's `TPropInfo` adds `PropProcs:Byte`, `IsStatic:Boolean`,
        // `PropParams:ptr` before the Name ShortString, and FPC 3.0.x /
        // 3.3+ additionally prefix a `AttributeTable:ptr`. We try layouts
        // in order and accept the first one that yields a plausible
        // identifier for every entry.
        VmtFlavor::Fpc => iter_fpc_tkclass(ctx, vmt),
    }
}

/// FPC `TPropInfo` decoder.
///
/// FPC's declared layout in `typinfo.pp:1106-1137` appends `PropProcs:u8`,
/// `IsStatic:bool`, `PropParams:ptr`, optionally `AttributeTable:ptr` after
/// the Delphi-compat core. Empirical inspection of our corpus (Lazarus
/// FPC 3.2.2 Win32/Mach-O and CheatEngine FPC 3.0.4 Win64) shows that
/// only `PropProcs` lands inline before the `Name: ShortString`; the
/// remaining fields are stored elsewhere and the packed record fixes
/// `Name` at `4*ptr + 11` bytes from the record start. This holds on all
/// three FPC builds we test.
fn iter_fpc_tkclass<'a>(ctx: &BinaryContext<'a>, vmt: &Vmt<'a>) -> Vec<Property<'a>> {
    let Some(info) = tkclass_from_vmt(ctx, vmt) else {
        return Vec::new();
    };
    let data = ctx.data();
    let mut cursor = info.prop_data_file_offset;
    let Some(count) = read_u16(data, cursor).map(usize::from) else {
        return Vec::new();
    };
    if count > MAX_PROPERTIES_PER_CLASS {
        return Vec::new();
    }
    cursor += 2;

    let psize = vmt.pointer_size as usize;
    let fixed = 4 * psize + 11; // ptr×4 + Index(4) + Default(4) + NameIndex(2) + PropProcs(1)
    let mut out = Vec::with_capacity(count);
    for _ in 0..count {
        let Some(prop_type_ref) = read_ptr(data, cursor, psize) else {
            break;
        };
        let Some(get_raw) = read_ptr(data, cursor + psize, psize) else {
            break;
        };
        let Some(set_raw) = read_ptr(data, cursor + 2 * psize, psize) else {
            break;
        };
        let Some(stored_raw) = read_ptr(data, cursor + 3 * psize, psize) else {
            break;
        };
        let Some(index) = read_u32(data, cursor + 4 * psize).map(|u| u as i32) else {
            break;
        };
        let Some(default) = read_u32(data, cursor + 4 * psize + 4).map(|u| u as i32) else {
            break;
        };
        let Some(name_index) = read_u16(data, cursor + 4 * psize + 8).map(|u| u as i16) else {
            break;
        };
        // PropProcs at +10. The IsStatic / PropParams / AttributeTable
        // fields documented in `typinfo.pp` aren't part of the inline
        // record in the FPC versions we've sampled — they live in a
        // separate structure (or have been deferred to FPC 3.3+ layouts
        // we don't yet target).
        let prop_procs = *data.get(cursor + 4 * psize + 10).unwrap_or(&0);
        let Some(name) = read_short_string_at_file(data, cursor + fixed) else {
            break;
        };
        if name.is_empty()
            || name.len() > MAX_IDENTIFIER_BYTES
            || !name.iter().all(is_prop_name_byte)
        {
            // Plausibility failed — most likely iteration has run off the
            // end of the TPropData block into padding or the next
            // structure. Stop gracefully instead of reporting None.
            break;
        }
        let record_size = fixed + 1 + name.len();

        let va = range_to_va(ctx, cursor);
        out.push(Property {
            va: va.unwrap_or(0),
            get: Access::from_fpc(get_raw, prop_procs, 0),
            set: Access::from_fpc(set_raw, prop_procs, 2),
            stored: Access::from_fpc(stored_raw, prop_procs, 4),
            index,
            default,
            name_index,
            name,
            prop_type_ref,
        });
        cursor += record_size;
    }
    out
}

fn iter_delphi<'a>(ctx: &BinaryContext<'a>, vmt: &Vmt<'a>) -> Option<Vec<Property<'a>>> {
    let info = tkclass_from_vmt(ctx, vmt)?;
    let data = ctx.data();
    let mut cursor = info.prop_data_file_offset;
    // TPropData header: u16 PropCount, then the variable-size array.
    let count = read_u16(data, cursor)? as usize;
    if count > MAX_PROPERTIES_PER_CLASS {
        return None;
    }
    cursor += 2;

    let psize = vmt.pointer_size as usize;
    let fixed = 4 * psize + 10; // bytes before the Name ShortString
    let mut out = Vec::with_capacity(count);
    for _ in 0..count {
        // Header region: 4 pointers + 4 + 4 + 2 = fixed bytes.
        let prop_type_ref = read_ptr(data, cursor, psize)?;
        let get_raw = read_ptr(data, cursor + psize, psize)?;
        let set_raw = read_ptr(data, cursor + 2 * psize, psize)?;
        let stored_raw = read_ptr(data, cursor + 3 * psize, psize)?;
        let index = i32::from_le_bytes(
            data.get(cursor + 4 * psize..cursor + 4 * psize + 4)?
                .try_into()
                .ok()?,
        );
        let default = i32::from_le_bytes(
            data.get(cursor + 4 * psize + 4..cursor + 4 * psize + 8)?
                .try_into()
                .ok()?,
        );
        let name_index = i16::from_le_bytes(
            data.get(cursor + 4 * psize + 8..cursor + 4 * psize + 10)?
                .try_into()
                .ok()?,
        );
        let name = read_short_string_at_file(data, cursor + fixed)?;
        // Plausibility: property names are identifiers.
        if name.is_empty()
            || name.len() > MAX_IDENTIFIER_BYTES
            || !name.iter().all(is_prop_name_byte)
        {
            return None;
        }
        let record_size = fixed + 1 + name.len();

        let va = range_to_va(ctx, cursor);
        out.push(Property {
            va: va.unwrap_or(0),
            get: Access::from_ptr(get_raw, psize),
            set: Access::from_ptr(set_raw, psize),
            stored: Access::from_ptr(stored_raw, psize),
            index,
            default,
            name_index,
            name,
            prop_type_ref,
        });
        cursor += record_size;
    }
    Some(out)
}

fn is_prop_name_byte(b: &u8) -> bool {
    b.is_ascii_alphanumeric() || *b == b'_'
}

/// Best-effort translation from a file offset back to a virtual address.
/// Used only to populate `Property::va`; callers without this mapping can
/// safely ignore a returned `0`.
fn range_to_va(ctx: &BinaryContext<'_>, file_off: usize) -> Option<u64> {
    for range in ctx.sections().scan_targets.iter() {
        if file_off >= range.offset && file_off < range.offset + range.size {
            return Some(range.va + (file_off - range.offset) as u64);
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn access_from_ptr_detects_field() {
        let a = Access::from_ptr(0xFF00_0000_0000_0010, 8);
        assert_eq!(a.kind, AccessKind::Field);
        assert_eq!(a.value, 0x10);
    }

    #[test]
    fn access_from_ptr_detects_virtual() {
        let a = Access::from_ptr(0xFE00_0000_0000_0005, 8);
        assert_eq!(a.kind, AccessKind::Virtual);
        assert_eq!(a.value, 0x5);
    }

    #[test]
    fn access_from_ptr_preserves_static_code_va() {
        let a = Access::from_ptr(0x0040_3000, 8);
        assert_eq!(a.kind, AccessKind::Static);
        assert_eq!(a.value, 0x0040_3000);
    }
}
