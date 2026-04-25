//! Extended RTTI blocks introduced with Delphi 2010 (`{$RTTI EXPLICIT ...}`).
//!
//! Classic RTTI (this crate's [`crate::properties`], [`crate::methods`])
//! only covers members declared `published`. Extended RTTI extends
//! coverage to `private` / `protected` / `public` declarations by
//! emitting auxiliary blocks that sit after the classic tables. Each
//! extended entry carries:
//!
//! - A `Visibility` flag — private / protected / public / published.
//! - A pointer to a `TPropInfo` / `TVmtMethodExEntry` / `TVmtFieldExEntry`
//!   record (the underlying classic record is reused; the entry here
//!   adds visibility + attribute metadata).
//! - A packed block of attribute-table bytes that follow.
//!
//! ## Property-table extended block
//!
//! Source: `reference/DelphiHelper/DelphiHelper/core/DelphiClass_TypeInfo_tkClass.py:66-88`.
//!
//! ```text
//!   PropCountEx: u16            (not always present — sniff for plausible count)
//!   entries[PropCountEx]:
//!     Flags:        u8          (low 2 bits = Visibility, upper bits reserved)
//!     Info:         PPropInfo   (pointer to a TPropInfo record elsewhere)
//!     ExtraLen:     u16         (byte-size of the trailing attribute payload)
//!     Extra:        [u8; ExtraLen - 2]
//! ```
//!
//! ## Attribute-table entries
//!
//! Delphi's attribute block is a **sequence of variable-size entries
//! packed back-to-back** (no leading count — the block size is
//! `ExtraLen − 2` and entries are parsed sequentially until exhausted).
//! Each entry is:
//!
//! ```text
//!   AttrType:  PPTypeInfo   (ptr-sized)
//!   AttrCtor:  CodePointer  (ptr-sized)
//!   ArgLen:    u16
//!   ArgData:   [u8; ArgLen]
//! ```
//!
//! `ArgData` packs the attribute-constructor arguments in the order they
//! appear in the attribute declaration. Primitive types use their natural
//! encoding; strings are `u16 length` + body; enums / sets are raw ordinals.
//!
//! Note: this differs from FPC's `TAttributeEntry`
//! (`reference/fpc-source/rtl/objpas/typinfo.pp:273-289`) which adds a
//! third `AttrProc` pointer. We use the Delphi layout here because it
//! matches our empirical corpus; an FPC-flavor variant can be added
//! when needed.

use crate::{
    classes::Class,
    formats::BinaryContext,
    limits::{MAX_EXTENDED_PROPERTIES_PER_CLASS, MAX_IDENTIFIER_BYTES},
    properties::{Access, Property},
    rtti::TkClassInfo,
    util::{read_ptr, read_short_string_at_file, read_u16},
};

/// Member visibility class.
///
/// Matches Delphi's `TMemberVisibility` (`System.TypInfo`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Visibility {
    /// `private`.
    Private = 0,
    /// `protected`.
    Protected = 1,
    /// `public`.
    Public = 2,
    /// `published`.
    Published = 3,
    /// Out-of-range byte.
    Unknown = 0xff,
}

impl Visibility {
    fn from_flags(b: u8) -> Self {
        match b & 0x03 {
            0 => Visibility::Private,
            1 => Visibility::Protected,
            2 => Visibility::Public,
            3 => Visibility::Published,
            _ => Visibility::Unknown,
        }
    }
}

/// One entry in the extended-RTTI property table.
///
/// Implements [`Deref<Target = Property>`](std::ops::Deref), so
/// `ep.name()`, `ep.get`, `ep.prop_type_ref`, and every other [`Property`]
/// accessor work directly without going through `ep.info.…`.
#[derive(Debug, Clone)]
pub struct ExtendedProperty<'a> {
    /// Visibility of this property.
    pub visibility: Visibility,
    /// Raw flags byte (low 2 bits = visibility; upper bits reserved).
    pub flags: u8,
    /// Resolved property record (the same layout as `TPropInfo` from
    /// classic RTTI, but reached through an indirection). Most callers can
    /// ignore this field and access `Property` members directly via the
    /// [`Deref`](std::ops::Deref) impl.
    pub info: Property<'a>,
    /// Raw attribute-table bytes trailing the header. Empty when no
    /// attributes are declared.
    pub attributes_raw: &'a [u8],
}

impl<'a> core::ops::Deref for ExtendedProperty<'a> {
    type Target = Property<'a>;

    #[inline]
    fn deref(&self) -> &Self::Target {
        &self.info
    }
}

/// One entry from an RTTI attribute table.
#[derive(Debug, Clone, Copy)]
pub struct AttributeEntry<'a> {
    /// VA of the attribute class's `PPTypeInfo`. This is a *data* pointer,
    /// not a code pointer.
    pub attr_type_ref: u64,
    /// Absolute VA of the attribute class's constructor — a *code*
    /// pointer. Use this as a disassembler-naming hint (e.g. label as
    /// `<AttrClass>.Create`). Subtract the image base for an RVA.
    pub attr_ctor: u64,
    /// Raw bytes of the constructor arguments as packed by the compiler.
    /// See module docs for the encoding; a common case is a `u16`-prefixed
    /// Pascal string when the attribute takes one string arg.
    pub arg_data: &'a [u8],
}

impl<'a> AttributeEntry<'a> {
    /// Interpret `arg_data` as a single `u16`-prefixed string argument,
    /// when it matches that shape. Returns `None` otherwise.
    pub fn arg_as_string(&self) -> Option<&'a [u8]> {
        let len_bytes = self.arg_data.get(..2)?;
        let len = u16::from_le_bytes(len_bytes.try_into().ok()?) as usize;
        let total = len.checked_add(2)?;
        if self.arg_data.len() != total {
            return None;
        }
        let body = self.arg_data.get(2..)?;
        if body.iter().all(|&b| (0x20..=0x7e).contains(&b)) {
            Some(body)
        } else {
            None
        }
    }
}

impl<'a> AttributeEntry<'a> {
    /// Decode every entry of an attribute block at `bytes`. Entries
    /// are variable-size; iteration stops when the cursor would
    /// overrun the provided slice. Returns the list plus the byte
    /// length consumed.
    pub fn decode_block(bytes: &'a [u8], ptr_size: usize) -> (Vec<Self>, usize) {
        decode_attribute_block(bytes, ptr_size)
    }
}

fn decode_attribute_block<'a>(
    bytes: &'a [u8],
    ptr_size: usize,
) -> (Vec<AttributeEntry<'a>>, usize) {
    let mut cursor = 0usize;
    let mut out = Vec::new();
    while let Some((entry, advance)) = decode_one_attribute(bytes, cursor, ptr_size) {
        out.push(entry);
        cursor = advance;
    }
    (out, cursor)
}

/// Decode a single attribute entry at `cursor`. Returns the entry and the
/// cursor position one byte past it, or `None` when any read overruns.
fn decode_one_attribute<'a>(
    bytes: &'a [u8],
    cursor: usize,
    ptr_size: usize,
) -> Option<(AttributeEntry<'a>, usize)> {
    let attr_type_ref = read_ptr(bytes, cursor, ptr_size)?;
    let attr_ctor_off = cursor.checked_add(ptr_size)?;
    let arg_len_off = attr_ctor_off.checked_add(ptr_size)?;
    let arg_start = arg_len_off.checked_add(2)?;
    let attr_ctor = read_ptr(bytes, attr_ctor_off, ptr_size)?;
    let arg_len = read_u16(bytes, arg_len_off).map(usize::from)?;
    let arg_end = arg_start.checked_add(arg_len)?;
    let arg_data = bytes.get(arg_start..arg_end)?;
    Some((
        AttributeEntry {
            attr_type_ref,
            attr_ctor,
            arg_data,
        },
        arg_end,
    ))
}

impl<'a> ExtendedProperty<'a> {
    /// Walk the extended-RTTI property block for `class`. Returns an
    /// empty vector when no extended block is present (older Delphi
    /// versions, or classes compiled without the `{$RTTI}` directive).
    pub fn iter(ctx: &BinaryContext<'a>, class: &Class<'a>) -> Vec<Self> {
        let tk = match TkClassInfo::from_vmt(ctx, &class.vmt) {
            Some(v) => v,
            None => return Vec::new(),
        };
        // Re-walk classic properties to advance past them, then try the
        // extended block.
        let data = ctx.data();
        let psize = class.vmt.pointer_size as usize;
        let Some(classic_count) = read_u16(data, tk.prop_data_file_offset).map(usize::from) else {
            return Vec::new();
        };
        let Some(fixed) = psize.checked_mul(4).and_then(|n| n.checked_add(10)) else {
            return Vec::new();
        };
        let Some(mut cursor) = tk.prop_data_file_offset.checked_add(2) else {
            return Vec::new();
        };
        for _ in 0..classic_count {
            let Some(name_off) = cursor.checked_add(fixed) else {
                return Vec::new();
            };
            let Some(name) = read_short_string_at_file(data, name_off) else {
                return Vec::new();
            };
            if name.is_empty() || name.len() > MAX_IDENTIFIER_BYTES {
                return Vec::new();
            }
            let Some(advance) = fixed.checked_add(1).and_then(|n| n.checked_add(name.len())) else {
                return Vec::new();
            };
            let Some(next) = cursor.checked_add(advance) else {
                return Vec::new();
            };
            cursor = next;
        }

        // Extended block starts here. Read u16 count.
        let Some(ext_count) = read_u16(data, cursor).map(usize::from) else {
            return Vec::new();
        };
        if ext_count == 0 || ext_count > MAX_EXTENDED_PROPERTIES_PER_CLASS {
            return Vec::new();
        }
        let Some(after_ext_count) = cursor.checked_add(2) else {
            return Vec::new();
        };
        cursor = after_ext_count;

        let mut out = Vec::with_capacity(ext_count);
        for _ in 0..ext_count {
            // Entry header: Flags:u8, PPropInfo:ptr, ExtraLen:u16, Extra.
            let Some(&flags) = data.get(cursor) else {
                break;
            };
            let Some(info_ptr_off) = cursor.checked_add(1) else {
                break;
            };
            let info_ptr = match read_ptr(data, info_ptr_off, psize) {
                Some(v) => v,
                None => break,
            };
            let Some(extra_len_off) = info_ptr_off.checked_add(psize) else {
                break;
            };
            let Some(extra_len) = read_u16(data, extra_len_off).map(usize::from) else {
                break;
            };
            let Some(attr_start) = extra_len_off.checked_add(2) else {
                break;
            };
            if extra_len < 2 {
                break;
            }
            let Some(attrs_len) = extra_len.checked_sub(2) else {
                break;
            };
            let Some(attr_end) = attr_start.checked_add(attrs_len) else {
                break;
            };
            let Some(attributes_raw) = data.get(attr_start..attr_end) else {
                break;
            };
            let Some(advance) = 1usize
                .checked_add(psize)
                .and_then(|n| n.checked_add(extra_len))
            else {
                break;
            };
            let Some(next_cursor) = cursor.checked_add(advance) else {
                break;
            };

            // Dereference info_ptr to a TPropInfo and decode it.
            let Some(prop) = decode_prop_info_at(ctx, info_ptr, psize) else {
                // Skip entries we can't dereference — some records point at
                // Ancestor classes that live outside our scanned region.
                cursor = next_cursor;
                continue;
            };

            out.push(ExtendedProperty {
                visibility: Visibility::from_flags(flags),
                flags,
                info: prop,
                attributes_raw,
            });
            cursor = next_cursor;
        }
        out
    }
}

/// Decode a standalone TPropInfo at `va` (used by extended RTTI, which
/// holds pointers to TPropInfo records that may live anywhere in the
/// binary — not necessarily in the classic TPropData list).
fn decode_prop_info_at<'a>(ctx: &BinaryContext<'a>, va: u64, psize: usize) -> Option<Property<'a>> {
    if va == 0 {
        return None;
    }
    let file_off = ctx.va_to_file(va)?;
    let data = ctx.data();
    let get_off = file_off.checked_add(psize)?;
    let set_off = get_off.checked_add(psize)?;
    let stored_off = set_off.checked_add(psize)?;
    let index_off = stored_off.checked_add(psize)?;
    let default_off = index_off.checked_add(4)?;
    let name_index_off = default_off.checked_add(4)?;
    let name_off = name_index_off.checked_add(2)?;
    let prop_type_ref = read_ptr(data, file_off, psize)?;
    let get_raw = read_ptr(data, get_off, psize)?;
    let set_raw = read_ptr(data, set_off, psize)?;
    let stored_raw = read_ptr(data, stored_off, psize)?;
    let index_end = index_off.checked_add(4)?;
    let default_end = default_off.checked_add(4)?;
    let name_index_end = name_index_off.checked_add(2)?;
    let index = i32::from_le_bytes(data.get(index_off..index_end)?.try_into().ok()?);
    let default = i32::from_le_bytes(data.get(default_off..default_end)?.try_into().ok()?);
    let name_index = i16::from_le_bytes(data.get(name_index_off..name_index_end)?.try_into().ok()?);
    let name = read_short_string_at_file(data, name_off)?;
    if name.is_empty() || name.len() > MAX_IDENTIFIER_BYTES || !name.iter().all(is_ident_byte) {
        return None;
    }
    Some(Property {
        va,
        get: Access::from_ptr(get_raw, psize),
        set: Access::from_ptr(set_raw, psize),
        stored: Access::from_ptr(stored_raw, psize),
        index,
        default,
        name_index,
        name,
        prop_type_ref,
    })
}

fn is_ident_byte(b: &u8) -> bool {
    b.is_ascii_alphanumeric() || *b == b'_'
}

impl<'a> AttributeEntry<'a> {
    /// Walk the class attribute table at `va` (typically the
    /// `TkClassInfo` `AttributeTable` pointer, for newer Delphi
    /// versions that emit one).
    pub fn iter_at(ctx: &BinaryContext<'a>, va: u64, ptr_size: usize) -> Vec<Self> {
        iter_class_attributes(ctx, va, ptr_size)
    }
}

fn iter_class_attributes<'a>(
    ctx: &BinaryContext<'a>,
    va: u64,
    ptr_size: usize,
) -> Vec<AttributeEntry<'a>> {
    if va == 0 {
        return Vec::new();
    }
    let Some(file_off) = ctx.va_to_file(va) else {
        return Vec::new();
    };
    let data = ctx.data();
    // The block extends until we've consumed its declared count. Read a
    // reasonable upper bound for decoding.
    let Some(remaining) = data.len().checked_sub(file_off) else {
        return Vec::new();
    };
    let cap = 4096usize.min(remaining);
    let Some(end) = file_off.checked_add(cap) else {
        return Vec::new();
    };
    let Some(slice) = data.get(file_off..end) else {
        return Vec::new();
    };
    decode_attribute_block(slice, ptr_size).0
}

/// Find the file offset of the class-level attribute block by walking
/// past the classic `TPropData` and the extended-property block.
///
/// Modern Delphi RTTI (XE3+) emits the class-level `AttrData` immediately
/// after the extended-property block. The block is a `u16` length
/// followed by `length - 2` bytes of packed attribute entries (same
/// shape as the per-property attribute payloads — see [`decode_attribute_block`]).
///
/// Returns `None` for binaries that don't emit extended RTTI (older
/// Delphi, or `{$RTTI EXPLICIT}` directives that disable it).
pub fn class_attribute_block_offset<'a>(
    ctx: &BinaryContext<'a>,
    class: &Class<'a>,
) -> Option<usize> {
    let tk = TkClassInfo::from_vmt(ctx, &class.vmt)?;
    let data = ctx.data();
    let psize = class.vmt.pointer_size as usize;

    // Walk past the classic TPropData entries.
    let classic_count = read_u16(data, tk.prop_data_file_offset)? as usize;
    let max_classic = MAX_EXTENDED_PROPERTIES_PER_CLASS.checked_mul(4)?;
    if classic_count > max_classic {
        return None;
    }
    let fixed = psize.checked_mul(4)?.checked_add(10)?;
    let mut cursor = tk.prop_data_file_offset.checked_add(2)?;
    for _ in 0..classic_count {
        let name_off = cursor.checked_add(fixed)?;
        let name = read_short_string_at_file(data, name_off)?;
        if name.is_empty() || name.len() > MAX_IDENTIFIER_BYTES {
            return None;
        }
        let advance = fixed.checked_add(1)?.checked_add(name.len())?;
        cursor = cursor.checked_add(advance)?;
    }

    // Walk past the extended-property block, if any. Some classes have
    // no extended RTTI; the u16 we read here will be either a real
    // ext_count (followed by entries) or the leading u16 of the
    // class-level AttrData block. We can't tell without trying both.
    //
    // Heuristic: try to walk as if it's the extended-property block.
    // If every entry's `extra_len` stays within plausible bounds and we
    // land on a position where the next u16 is a plausible AttrData
    // length, we accept it. Otherwise treat the original u16 as the
    // AttrData length directly.
    let ext_marker = read_u16(data, cursor)? as usize;
    let mut after_ext = cursor.checked_add(2)?;
    let mut ext_walk_ok = true;
    if ext_marker > 0 && ext_marker <= MAX_EXTENDED_PROPERTIES_PER_CLASS {
        // Tentatively walk as ext-property block.
        let mut probe = after_ext;
        for _ in 0..ext_marker {
            // Each entry: u8 flags + ptr info + u16 extra_len + extra.
            if data.get(probe).is_none() {
                ext_walk_ok = false;
                break;
            }
            let Some(extra_len_off) = probe.checked_add(1).and_then(|n| n.checked_add(psize))
            else {
                ext_walk_ok = false;
                break;
            };
            let extra_len = match read_u16(data, extra_len_off) {
                Some(v) => v as usize,
                None => {
                    ext_walk_ok = false;
                    break;
                }
            };
            if !(2..=0x4000).contains(&extra_len) {
                ext_walk_ok = false;
                break;
            }
            let Some(advance) = 1usize
                .checked_add(psize)
                .and_then(|n| n.checked_add(extra_len))
            else {
                ext_walk_ok = false;
                break;
            };
            let Some(next) = probe.checked_add(advance) else {
                ext_walk_ok = false;
                break;
            };
            probe = next;
        }
        if ext_walk_ok {
            after_ext = probe;
        }
    }

    Some(
        if ext_walk_ok && ext_marker > 0 && ext_marker <= MAX_EXTENDED_PROPERTIES_PER_CLASS {
            after_ext
        } else {
            // Treat the u16 we just read as the AttrData length directly,
            // i.e. the attribute block starts at `cursor`.
            cursor
        },
    )
}

impl<'a> AttributeEntry<'a> {
    /// Decode the class-level attribute block — finds the offset via
    /// [`class_attribute_block_offset`] and decodes the `u16`-prefixed
    /// packed attribute entries that follow. Returns an empty vector
    /// when the binary doesn't carry an `AttrData` trailer for this
    /// class.
    pub fn iter_class(ctx: &BinaryContext<'a>, class: &Class<'a>) -> Vec<Self> {
        let psize = class.vmt.pointer_size as usize;
        let Some(off) = class_attribute_block_offset(ctx, class) else {
            return Vec::new();
        };
        let data = ctx.data();
        // AttrData layout: `u16 length` (counting itself), then
        // `length - 2` bytes of packed attribute entries.
        let Some(length) = read_u16(data, off).map(usize::from) else {
            return Vec::new();
        };
        if length < 2 {
            return Vec::new();
        }
        let Some(body_len) = length.checked_sub(2) else {
            return Vec::new();
        };
        if body_len > 0x4000 {
            return Vec::new();
        }
        let Some(body_start) = off.checked_add(2) else {
            return Vec::new();
        };
        let Some(body_end) = body_start.checked_add(body_len) else {
            return Vec::new();
        };
        let Some(body) = data.get(body_start..body_end) else {
            return Vec::new();
        };
        decode_attribute_block(body, psize).0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn visibility_bits() {
        assert_eq!(Visibility::from_flags(0), Visibility::Private);
        assert_eq!(Visibility::from_flags(1), Visibility::Protected);
        assert_eq!(Visibility::from_flags(2), Visibility::Public);
        assert_eq!(Visibility::from_flags(3), Visibility::Published);
        assert_eq!(Visibility::from_flags(0x82), Visibility::Public);
    }

    #[test]
    fn empty_attribute_block_decodes_trivially() {
        // A zero-byte slice should yield no entries.
        let (entries, consumed) = decode_attribute_block(&[], 8);
        assert!(entries.is_empty());
        assert_eq!(consumed, 0);
    }
}
