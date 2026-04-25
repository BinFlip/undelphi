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

use std::str;

use crate::{
    formats::BinaryContext,
    limits::{MAX_IDENTIFIER_BYTES, MAX_PROPERTIES_PER_CLASS},
    rtti::TkClassInfo,
    util::{read_ptr, read_short_string_at_file, read_u16, read_u32},
    vmt::{Vmt, VmtFlavor},
    vtable::VirtualMethodEntry,
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
///
/// `value` is interpreted by `kind`:
///
/// - [`AccessKind::Static`] — `value` is an absolute code VA. Subtract the
///   image base for an RVA.
/// - [`AccessKind::Field`] — `value` is the instance-relative byte offset
///   of the backing field.
/// - [`AccessKind::Virtual`] — `value` is a **VMT slot index**, *not* a
///   VA. Resolve against the class's virtual-method table to get a code
///   VA. [`Access::resolve`] does this for you.
/// - [`AccessKind::Const`] — `value` is a constant (FPC-only).
/// - [`AccessKind::None`] — no handler.
#[derive(Debug, Clone, Copy)]
pub struct Access {
    /// How to interpret `value`.
    pub kind: AccessKind,
    /// Kind-dependent value: field offset, VMT slot index, code VA, or
    /// constant. See the type-level docs for the per-kind meaning.
    pub value: u64,
}

/// Result of resolving an [`Access`] against a class's virtual-method table.
///
/// Returned by [`Access::resolve`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AccessTarget {
    /// Absolute code VA — for [`AccessKind::Static`] and successfully
    /// resolved [`AccessKind::Virtual`] entries.
    CodeVa(u64),
    /// Instance-relative field offset — for [`AccessKind::Field`].
    FieldOffset(u32),
    /// FPC constant value — for [`AccessKind::Const`].
    Constant(u64),
    /// Virtual slot whose VMT lookup didn't land on a code pointer.
    /// Returned only when resolution fails — the caller can still attempt
    /// their own lookup.
    UnresolvedSlot(u16),
    /// No handler ([`AccessKind::None`]).
    Missing,
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
        let shift = ptr_size.saturating_sub(1).saturating_mul(8);
        let top = (raw.wrapping_shr(shift as u32)) as u8;
        let mask = ptr_size.saturating_mul(8);
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

    /// Resolve this access against a class's virtual-method table, hiding
    /// the slot-index lookup the consumer would otherwise do by hand.
    ///
    /// Pass `virtual_methods` from
    /// [`crate::DelphiBinary::virtual_methods`]. For batch resolution,
    /// callers can index the slice once into a `HashMap<slot, code_va>`
    /// instead of calling this repeatedly.
    pub fn resolve(&self, virtual_methods: &[VirtualMethodEntry]) -> AccessTarget {
        match self.kind {
            AccessKind::None => AccessTarget::Missing,
            AccessKind::Static => AccessTarget::CodeVa(self.value),
            AccessKind::Field => AccessTarget::FieldOffset((self.value & 0xFFFF_FFFF) as u32),
            AccessKind::Const => AccessTarget::Constant(self.value),
            AccessKind::Virtual => {
                let slot = self.value as u16;
                match virtual_methods
                    .iter()
                    .find(|v| v.slot as u16 == slot)
                    .map(|v| v.code_va)
                {
                    Some(va) => AccessTarget::CodeVa(va),
                    None => AccessTarget::UnresolvedSlot(slot),
                }
            }
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
    pub(crate) name: &'a [u8],
    /// Virtual address the `PropType` PPTypeInfo indirection holds.
    pub prop_type_ref: u64,
}

impl<'a> Property<'a> {
    /// Property name as `&str`, lossily decoded. Pascal identifiers are
    /// ASCII in practice; non-UTF-8 bytes fall back to `"<non-ascii>"`.
    #[inline]
    pub fn name(&self) -> &'a str {
        str::from_utf8(self.name).unwrap_or("<non-ascii>")
    }

    /// Raw property name bytes (borrows from the input buffer).
    #[inline]
    pub fn name_bytes(&self) -> &'a [u8] {
        self.name
    }
}

impl<'a> Property<'a> {
    /// Decode every published property declared on `vmt`.
    ///
    /// Walks the class's `tkClass` TypeData up to and including
    /// `UnitName`, then reads the `TPropData` block that follows.
    /// Returns an empty vector if no RTTI is attached or the table is
    /// malformed.
    pub fn iter(ctx: &BinaryContext<'a>, vmt: &Vmt<'a>) -> Vec<Self> {
        match vmt.flavor {
            VmtFlavor::Delphi => iter_delphi(ctx, vmt).unwrap_or_else(|| {
                crate::__undelphi_trace_warn!(
                    vmt_va = vmt.va,
                    type_info = vmt.type_info,
                    "Property::iter: TPropData walk bailed out"
                );
                Vec::new()
            }),
            // FPC's `TPropInfo` adds `PropProcs:Byte`, `IsStatic:Boolean`,
            // `PropParams:ptr` before the Name ShortString, and FPC 3.0.x /
            // 3.3+ additionally prefix a `AttributeTable:ptr`. We try
            // layouts in order and accept the first one that yields a
            // plausible identifier for every entry.
            VmtFlavor::Fpc => iter_fpc_tkclass(ctx, vmt),
        }
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
    let Some(info) = TkClassInfo::from_vmt(ctx, vmt) else {
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
    let Some(start) = cursor.checked_add(2) else {
        return Vec::new();
    };
    cursor = start;

    let psize = vmt.pointer_size as usize;
    // ptr×4 + Index(4) + Default(4) + NameIndex(2) + PropProcs(1)
    let Some(fixed) = psize.checked_mul(4).and_then(|n| n.checked_add(11)) else {
        return Vec::new();
    };
    let mut out = Vec::with_capacity(count);
    for _ in 0..count {
        let Some(prop_type_ref) = read_ptr(data, cursor, psize) else {
            break;
        };
        let Some(get_off) = cursor.checked_add(psize) else {
            break;
        };
        let Some(set_off) = get_off.checked_add(psize) else {
            break;
        };
        let Some(stored_off) = set_off.checked_add(psize) else {
            break;
        };
        let Some(get_raw) = read_ptr(data, get_off, psize) else {
            break;
        };
        let Some(set_raw) = read_ptr(data, set_off, psize) else {
            break;
        };
        let Some(stored_raw) = read_ptr(data, stored_off, psize) else {
            break;
        };
        let Some(index_off) = stored_off.checked_add(psize) else {
            break;
        };
        let Some(default_off) = index_off.checked_add(4) else {
            break;
        };
        let Some(name_index_off) = default_off.checked_add(4) else {
            break;
        };
        let Some(prop_procs_off) = name_index_off.checked_add(2) else {
            break;
        };
        let Some(name_off) = cursor.checked_add(fixed) else {
            break;
        };
        let Some(index) = read_u32(data, index_off).map(|u| u as i32) else {
            break;
        };
        let Some(default) = read_u32(data, default_off).map(|u| u as i32) else {
            break;
        };
        let Some(name_index) = read_u16(data, name_index_off).map(|u| u as i16) else {
            break;
        };
        // PropProcs at +10. The IsStatic / PropParams / AttributeTable
        // fields documented in `typinfo.pp` aren't part of the inline
        // record in the FPC versions we've sampled — they live in a
        // separate structure (or have been deferred to FPC 3.3+ layouts
        // we don't yet target). A truncated record here means the table
        // is malformed; surface it as a stop rather than guessing 0.
        let Some(&prop_procs) = data.get(prop_procs_off) else {
            break;
        };
        let Some(name) = read_short_string_at_file(data, name_off) else {
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
        let Some(record_size) = fixed.checked_add(1).and_then(|n| n.checked_add(name.len())) else {
            break;
        };

        // Property::va is documented to be 0 when the file offset can't
        // be translated back to a VA — that happens for synthetic
        // sections we don't track, not for malformed input.
        let va = range_to_va(ctx, cursor).unwrap_or(0);
        out.push(Property {
            va,
            get: Access::from_fpc(get_raw, prop_procs, 0),
            set: Access::from_fpc(set_raw, prop_procs, 2),
            stored: Access::from_fpc(stored_raw, prop_procs, 4),
            index,
            default,
            name_index,
            name,
            prop_type_ref,
        });
        let Some(next) = cursor.checked_add(record_size) else {
            break;
        };
        cursor = next;
    }
    out
}

fn iter_delphi<'a>(ctx: &BinaryContext<'a>, vmt: &Vmt<'a>) -> Option<Vec<Property<'a>>> {
    let info = TkClassInfo::from_vmt(ctx, vmt)?;
    let data = ctx.data();
    let mut cursor = info.prop_data_file_offset;
    // TPropData header: u16 PropCount, then the variable-size array.
    let count = read_u16(data, cursor)? as usize;
    if count > MAX_PROPERTIES_PER_CLASS {
        return None;
    }
    cursor = cursor.checked_add(2)?;

    let psize = vmt.pointer_size as usize;
    // bytes before the Name ShortString: ptr×4 + Index(4) + Default(4) + NameIndex(2)
    let fixed = psize.checked_mul(4)?.checked_add(10)?;
    let mut out = Vec::with_capacity(count);
    for _ in 0..count {
        // Header region: 4 pointers + 4 + 4 + 2 = fixed bytes.
        let prop_type_ref = read_ptr(data, cursor, psize)?;
        let get_off = cursor.checked_add(psize)?;
        let set_off = get_off.checked_add(psize)?;
        let stored_off = set_off.checked_add(psize)?;
        let index_off = stored_off.checked_add(psize)?;
        let default_off = index_off.checked_add(4)?;
        let name_index_off = default_off.checked_add(4)?;
        let name_off = cursor.checked_add(fixed)?;
        let get_raw = read_ptr(data, get_off, psize)?;
        let set_raw = read_ptr(data, set_off, psize)?;
        let stored_raw = read_ptr(data, stored_off, psize)?;
        let index_end = index_off.checked_add(4)?;
        let default_end = default_off.checked_add(4)?;
        let name_index_end = name_index_off.checked_add(2)?;
        let index = i32::from_le_bytes(data.get(index_off..index_end)?.try_into().ok()?);
        let default = i32::from_le_bytes(data.get(default_off..default_end)?.try_into().ok()?);
        let name_index =
            i16::from_le_bytes(data.get(name_index_off..name_index_end)?.try_into().ok()?);
        let name = read_short_string_at_file(data, name_off)?;
        // Plausibility: property names are identifiers.
        if name.is_empty()
            || name.len() > MAX_IDENTIFIER_BYTES
            || !name.iter().all(is_prop_name_byte)
        {
            return None;
        }
        let record_size = fixed.checked_add(1)?.checked_add(name.len())?;

        // Property::va is documented to be 0 when the file offset can't
        // be translated back to a VA — that happens for synthetic
        // sections we don't track, not for malformed input.
        let va = range_to_va(ctx, cursor).unwrap_or(0);
        out.push(Property {
            va,
            get: Access::from_ptr(get_raw, psize),
            set: Access::from_ptr(set_raw, psize),
            stored: Access::from_ptr(stored_raw, psize),
            index,
            default,
            name_index,
            name,
            prop_type_ref,
        });
        cursor = cursor.checked_add(record_size)?;
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
        let range_end = range.offset.checked_add(range.size)?;
        if file_off >= range.offset && file_off < range_end {
            let rel = file_off.checked_sub(range.offset)?;
            return range.va.checked_add(rel as u64);
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
