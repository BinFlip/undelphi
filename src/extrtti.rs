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
    rtti::tkclass_from_vmt,
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
#[derive(Debug, Clone)]
pub struct ExtendedProperty<'a> {
    /// Visibility of this property.
    pub visibility: Visibility,
    /// Raw flags byte (low 2 bits = visibility; upper bits reserved).
    pub flags: u8,
    /// Resolved property record (the same layout as `TPropInfo` from
    /// classic RTTI, but reached through an indirection).
    pub info: Property<'a>,
    /// Raw attribute-table bytes trailing the header. Empty when no
    /// attributes are declared.
    pub attributes_raw: &'a [u8],
}

/// One entry from an RTTI attribute table.
#[derive(Debug, Clone, Copy)]
pub struct AttributeEntry<'a> {
    /// VA of the attribute class's `PPTypeInfo`.
    pub attr_type_ref: u64,
    /// VA of the attribute class's constructor.
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
        if self.arg_data.len() < 2 {
            return None;
        }
        let len = u16::from_le_bytes([self.arg_data[0], self.arg_data[1]]) as usize;
        if self.arg_data.len() != 2 + len {
            return None;
        }
        let body = &self.arg_data[2..];
        if body.iter().all(|&b| (0x20..=0x7e).contains(&b)) {
            Some(body)
        } else {
            None
        }
    }
}

/// Decode every entry of an attribute block at `bytes`.
///
/// Entries are variable-size; iteration stops when the cursor would
/// overrun the provided slice. Returns the list plus the byte length
/// consumed.
pub fn decode_attribute_block<'a>(
    bytes: &'a [u8],
    ptr_size: usize,
) -> (Vec<AttributeEntry<'a>>, usize) {
    let mut cursor = 0usize;
    let mut out = Vec::new();
    loop {
        let Some(attr_type_ref) = read_ptr(bytes, cursor, ptr_size) else {
            break;
        };
        let Some(attr_ctor) = read_ptr(bytes, cursor + ptr_size, ptr_size) else {
            break;
        };
        let Some(arg_len) = read_u16(bytes, cursor + 2 * ptr_size).map(usize::from) else {
            break;
        };
        let arg_start = cursor + 2 * ptr_size + 2;
        let Some(arg_data) = bytes.get(arg_start..arg_start + arg_len) else {
            break;
        };
        out.push(AttributeEntry {
            attr_type_ref,
            attr_ctor,
            arg_data,
        });
        cursor = arg_start + arg_len;
    }
    (out, cursor)
}

/// Walk the extended-RTTI property block for `class`. Returns an empty
/// vector when no extended block is present (older Delphi versions, or
/// classes compiled without the `{$RTTI}` directive).
pub fn iter_extended_properties<'a>(
    ctx: &BinaryContext<'a>,
    class: &Class<'a>,
) -> Vec<ExtendedProperty<'a>> {
    let tk = match tkclass_from_vmt(ctx, &class.vmt) {
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
    let fixed = 4 * psize + 10;
    let mut cursor = tk.prop_data_file_offset + 2;
    for _ in 0..classic_count {
        let Some(name) = read_short_string_at_file(data, cursor + fixed) else {
            return Vec::new();
        };
        if name.is_empty() || name.len() > MAX_IDENTIFIER_BYTES {
            return Vec::new();
        }
        cursor += fixed + 1 + name.len();
    }

    // Extended block starts here. Read u16 count.
    let Some(ext_count) = read_u16(data, cursor).map(usize::from) else {
        return Vec::new();
    };
    if ext_count == 0 || ext_count > MAX_EXTENDED_PROPERTIES_PER_CLASS {
        return Vec::new();
    }
    cursor += 2;

    let mut out = Vec::with_capacity(ext_count);
    for _ in 0..ext_count {
        // Entry header: Flags:u8, PPropInfo:ptr, ExtraLen:u16, Extra.
        let Some(&flags) = data.get(cursor) else {
            break;
        };
        let info_ptr = match read_ptr(data, cursor + 1, psize) {
            Some(v) => v,
            None => break,
        };
        let Some(extra_len) = read_u16(data, cursor + 1 + psize).map(usize::from) else {
            break;
        };
        let attr_start = cursor + 1 + psize + 2;
        if extra_len < 2 {
            break;
        }
        let attrs_len = extra_len - 2;
        let Some(attributes_raw) = data.get(attr_start..attr_start + attrs_len) else {
            break;
        };

        // Dereference info_ptr to a TPropInfo and decode it.
        let Some(prop) = decode_prop_info_at(ctx, info_ptr, psize) else {
            // Skip entries we can't dereference — some records point at
            // Ancestor classes that live outside our scanned region.
            cursor += 1 + psize + extra_len;
            continue;
        };

        out.push(ExtendedProperty {
            visibility: Visibility::from_flags(flags),
            flags,
            info: prop,
            attributes_raw,
        });
        cursor += 1 + psize + extra_len;
    }
    out
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
    let prop_type_ref = read_ptr(data, file_off, psize)?;
    let get_raw = read_ptr(data, file_off + psize, psize)?;
    let set_raw = read_ptr(data, file_off + 2 * psize, psize)?;
    let stored_raw = read_ptr(data, file_off + 3 * psize, psize)?;
    let index = i32::from_le_bytes(
        data.get(file_off + 4 * psize..file_off + 4 * psize + 4)?
            .try_into()
            .ok()?,
    );
    let default = i32::from_le_bytes(
        data.get(file_off + 4 * psize + 4..file_off + 4 * psize + 8)?
            .try_into()
            .ok()?,
    );
    let name_index = i16::from_le_bytes(
        data.get(file_off + 4 * psize + 8..file_off + 4 * psize + 10)?
            .try_into()
            .ok()?,
    );
    let name = read_short_string_at_file(data, file_off + 4 * psize + 10)?;
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

/// Walk the class attribute table at `va` (typically `TkClassInfo`'s
/// AttributeTable pointer, for newer Delphi versions that emit one).
pub fn iter_class_attributes<'a>(
    ctx: &BinaryContext<'a>,
    _class: &Class<'a>,
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
    let Some(slice) = data.get(file_off..file_off + 4096.min(data.len() - file_off)) else {
        return Vec::new();
    };
    decode_attribute_block(slice, ptr_size).0
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
