//! Minimal RTTI (`PTypeInfo`) decoder, focused on the `tkClass` branch.
//!
//! This iteration extracts the class's **unit name** from the
//! `vmtTypeInfo → tkClass → UnitName` record. Fields and properties (the
//! rest of `tkClass` and its `TPropData` tail) are reserved for iteration 4.
//!
//! ## Layout (Delphi and FPC share the tkClass shape)
//!
//! `vmtTypeInfo` points at a `PTypeInfo` record, laid out as:
//!
//! ```text
//!   +0         Kind: u8                       (must equal tkClass = 7)
//!   +1         NameLen: u8
//!   +2..N      Name: [u8; NameLen]            (class name, matches vmtClassName)
//!   <TypeData starts at +2+NameLen>
//!   +0         ClassType: ptr                 (points back to VMT base)
//!   +ptr       ParentInfo: PPTypeInfo         (pointer-to-pointer-to-parent-TypeInfo)
//!   +2*ptr     PropCount: i16                 (classic tkClass property count)
//!   +2*ptr+2   UnitName: ShortString          (unit that declared this class)
//!   +...       TPropData: PropCount: u16      (a second, potentially-different count)
//!   +...       array[TPropData.PropCount] of TPropInfo   (deferred)
//! ```
//!
//! Source: `reference/DelphiHelper/DelphiHelper/core/DelphiClass_TypeInfo_tkClass.py:28-54`
//! for the Delphi-side pointer arithmetic; `reference/fpc-source/rtl/objpas/typinfo.pp:799-806`
//! for the FPC-side record layout. They agree.
//!
//! ## TTypeKind values
//!
//! **Delphi and FPC use incompatible `TTypeKind` enums.** Delphi orders
//! them as `tkUnknown, tkInteger, tkChar, tkEnumeration, tkFloat, tkString,
//! tkSet, tkClass, tkMethod, …` (so `tkClass == 7`). FPC reorders to
//! `tkUnknown, tkInteger, tkChar, tkEnumeration, tkFloat, tkSet, tkMethod,
//! tkSString, tkLString, tkAString, tkWString, tkVariant, tkArray, tkRecord,
//! tkInterface, tkClass, …` (so `tkClass == 15`). Sources:
//!
//! - Delphi: `reference/pythia/pythia/core/structures.py:11-34`
//! - FPC: `reference/fpc-source/rtl/inc/rttih.inc:29-34`
//!
//! This module honors the `VmtFlavor` tag and dispatches to the right
//! expected byte when validating `tkClass`.

use std::str;

use crate::{
    detection::TargetArch,
    formats::BinaryContext,
    interfaces::Guid,
    limits::{MAX_ENUM_RANGE, MAX_IDENTIFIER_BYTES, MAX_METHOD_PARAMS, MAX_RECORD_MANAGED_FIELDS},
    util::{deref_va, read_ptr, read_short_string_at_file, read_short_string_at_va, read_u16},
    vmt::{Vmt, VmtFlavor},
};

/// Raw byte value of `tkClass` per-flavor.
pub const fn tkclass_byte(flavor: VmtFlavor) -> u8 {
    match flavor {
        VmtFlavor::Delphi => 7,
        VmtFlavor::Fpc => 15,
    }
}

// Compile-time check the per-flavor `tkClass` byte values against the
// authoritative source files we mirror under `reference/`. Drift here
// would silently misclassify VMTs.
const _: () = {
    assert!(tkclass_byte(VmtFlavor::Delphi) == 7); // pythia/structures.py:19
    assert!(tkclass_byte(VmtFlavor::Fpc) == 15); // fpc-source/rtl/inc/rttih.inc:32
};

/// Map a raw TTypeKind byte to the unified [`TypeKind`] enum, given the
/// flavor that emitted the binary. Because FPC reorders the enum, the
/// same byte value means different things in each flavor.
pub fn classify_kind_byte(byte: u8, flavor: VmtFlavor) -> TypeKind {
    match flavor {
        VmtFlavor::Delphi => TypeKind::from_u8(byte),
        VmtFlavor::Fpc => fpc_kind_from_byte(byte),
    }
}

/// FPC ordering (from `reference/fpc-source/rtl/inc/rttih.inc:29-34`):
/// `tkUnknown, tkInteger, tkChar, tkEnumeration, tkFloat, tkSet, tkMethod,
/// tkSString, tkLString, tkAString, tkWString, tkVariant, tkArray,
/// tkRecord, tkInterface, tkClass, tkObject, tkWChar, tkBool, tkInt64,
/// tkQWord, tkDynArray, tkInterfaceRaw, tkProcVar, tkUString, tkUChar,
/// tkHelper, tkFile, tkClassRef, tkPointer`.
fn fpc_kind_from_byte(byte: u8) -> TypeKind {
    match byte {
        0 => TypeKind::Unknown,
        1 => TypeKind::Integer,
        2 => TypeKind::Char,
        3 => TypeKind::Enumeration,
        4 => TypeKind::Float,
        5 => TypeKind::Set,
        6 => TypeKind::Method,
        7 => TypeKind::String,  // FPC tkSString
        8 => TypeKind::LString, // FPC tkLString
        9 => TypeKind::LString, // FPC tkAString — treat as AnsiString-like
        10 => TypeKind::WString,
        11 => TypeKind::Variant,
        12 => TypeKind::Array,
        13 => TypeKind::Record,
        14 => TypeKind::Interface,
        15 => TypeKind::Class,
        // 16 is tkObject — no Delphi equivalent; closest is Class.
        16 => TypeKind::Class,
        17 => TypeKind::WChar,
        // 18 is tkBool — Delphi doesn't have a dedicated kind (booleans
        // are enumerations in Delphi), so map to Enumeration.
        18 => TypeKind::Enumeration,
        19 => TypeKind::Int64,
        20 => TypeKind::Int64, // tkQWord
        21 => TypeKind::DynArray,
        22 => TypeKind::Interface, // tkInterfaceRaw
        23 => TypeKind::Procedure, // tkProcVar
        24 => TypeKind::UString,
        25 => TypeKind::WChar, // tkUChar
        // tkHelper / tkFile have no Delphi equivalent.
        26 | 27 => TypeKind::Unknown,
        28 => TypeKind::ClassRef,
        29 => TypeKind::Pointer,
        _ => TypeKind::Unknown,
    }
}

/// The Delphi `TTypeKind` enumeration. FPC's enum is **different** — see
/// module docs — and we do not expose it as a single shared type because
/// the semantic overlap is too small for a unified `TypeKind` to be honest.
/// When you need FPC values, dispatch on `VmtFlavor` and compare the raw
/// byte directly (or use [`tkclass_byte`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum TypeKind {
    /// Unknown / not a valid type info.
    Unknown = 0,
    /// Signed / unsigned integer types (`Integer`, `Byte`, …).
    Integer = 1,
    /// Single-byte character types.
    Char = 2,
    /// User-declared enumerations.
    Enumeration = 3,
    /// Single / double / extended float types.
    Float = 4,
    /// `ShortString`.
    String = 5,
    /// Pascal set types.
    Set = 6,
    /// Classes / `TObject` hierarchy.
    Class = 7,
    /// Method-of-object pointers.
    Method = 8,
    /// Wide character.
    WChar = 9,
    /// `AnsiString` / `RawByteString`.
    LString = 10,
    /// `WideString` (COM-style BSTR).
    WString = 11,
    /// `Variant` / `OleVariant`.
    Variant = 12,
    /// Static array types.
    Array = 13,
    /// `record` types.
    Record = 14,
    /// COM-style interfaces.
    Interface = 15,
    /// 64-bit integer types.
    Int64 = 16,
    /// Dynamic arrays.
    DynArray = 17,
    /// `UnicodeString` (Delphi 2009+).
    UString = 18,
    /// Class references (metaclasses).
    ClassRef = 19,
    /// Typed pointers.
    Pointer = 20,
    /// Procedure types.
    Procedure = 21,
    /// Managed records (Delphi 10.4+).
    MRecord = 22,
}

impl TypeKind {
    /// Decode a raw byte. Values outside the documented range map to
    /// [`TypeKind::Unknown`] rather than causing a parse failure.
    pub fn from_u8(b: u8) -> Self {
        match b {
            1 => TypeKind::Integer,
            2 => TypeKind::Char,
            3 => TypeKind::Enumeration,
            4 => TypeKind::Float,
            5 => TypeKind::String,
            6 => TypeKind::Set,
            7 => TypeKind::Class,
            8 => TypeKind::Method,
            9 => TypeKind::WChar,
            10 => TypeKind::LString,
            11 => TypeKind::WString,
            12 => TypeKind::Variant,
            13 => TypeKind::Array,
            14 => TypeKind::Record,
            15 => TypeKind::Interface,
            16 => TypeKind::Int64,
            17 => TypeKind::DynArray,
            18 => TypeKind::UString,
            19 => TypeKind::ClassRef,
            20 => TypeKind::Pointer,
            21 => TypeKind::Procedure,
            22 => TypeKind::MRecord,
            _ => TypeKind::Unknown,
        }
    }
}

/// Partially-parsed `tkClass` TypeInfo record.
///
/// Only the fields covered by iteration 3 are exposed. `prop_count` is the
/// count advertised by the TypeData header; walking the actual property
/// array lands in iteration 4.
#[derive(Debug, Clone, Copy)]
pub struct TkClassInfo<'a> {
    /// VA of the PTypeInfo record this was parsed from.
    pub type_info_va: u64,
    /// The Kind byte. Always [`TypeKind::Class`] in this struct, but kept
    /// so callers can distinguish error paths.
    pub kind: TypeKind,
    /// Class name as it appears in the PTypeInfo header (should match the
    /// VMT's own `class_name`).
    pub(crate) class_name: &'a [u8],
    /// VA the TypeData's `ClassType` slot points at (should equal the VMT
    /// base address).
    pub class_type_va: u64,
    /// VA the TypeData's `ParentInfo` slot holds. This is a `PPTypeInfo` —
    /// a pointer to a pointer to the parent's PTypeInfo record.
    pub parent_info_va: u64,
    /// Published-property count advertised by the TypeData header.
    /// **Note:** the RTTI stream then carries a `TPropData` block whose own
    /// `PropCount` may differ (ancestry-aware vs self-only semantics —
    /// open question, see `RESEARCH.md §14`).
    pub prop_count: i16,
    /// Unit name as a short-string body.
    pub(crate) unit_name: &'a [u8],
    /// File offset where the `TPropData` block starts (needed by iteration
    /// 4 when walking property entries).
    pub prop_data_file_offset: usize,
}

impl<'a> TkClassInfo<'a> {
    /// Class name as `&str`, lossily decoded.
    #[inline]
    pub fn class_name(&self) -> &'a str {
        str::from_utf8(self.class_name).unwrap_or("<non-ascii>")
    }
    /// Raw class-name bytes.
    #[inline]
    pub fn class_name_bytes(&self) -> &'a [u8] {
        self.class_name
    }
    /// Unit name as `&str`, lossily decoded.
    #[inline]
    pub fn unit_name(&self) -> &'a str {
        str::from_utf8(self.unit_name).unwrap_or("<non-ascii>")
    }
    /// Raw unit-name bytes (short-string body).
    #[inline]
    pub fn unit_name_bytes(&self) -> &'a [u8] {
        self.unit_name
    }
}

impl<'a> TkClassInfo<'a> {
    /// Decode the `tkClass` TypeInfo record referenced by a class's VMT.
    ///
    /// Returns `None` when `vmtTypeInfo` is null, the VA cannot be
    /// translated, the Kind byte is not the `tkClass` value for this
    /// flavor, or any length read fails.
    pub fn from_vmt(ctx: &BinaryContext<'a>, vmt: &Vmt<'a>) -> Option<Self> {
        if vmt.type_info == 0 {
            return None;
        }
        Self::from_va(ctx, vmt.type_info, vmt.pointer_size as usize, vmt.flavor)
    }

    /// Resolve a `ParentInfo` (`PPTypeInfo`) value into the parent
    /// class's `tkClass` record.
    pub fn from_parent_info(
        ctx: &BinaryContext<'a>,
        parent_info_va: u64,
        ptr_size: usize,
        flavor: VmtFlavor,
    ) -> Option<Self> {
        let type_info_va = deref_va(ctx, parent_info_va, ptr_size)?;
        Self::from_va(ctx, type_info_va, ptr_size, flavor)
    }

    /// Decode a `tkClass` TypeInfo at an arbitrary VA, given the flavor
    /// that produced the binary (determines which byte value to expect
    /// for `tkClass`).
    pub fn from_va(
        ctx: &BinaryContext<'a>,
        type_info_va: u64,
        ptr_size: usize,
        flavor: VmtFlavor,
    ) -> Option<Self> {
        let file_off = ctx.va_to_file(type_info_va)?;
        let data = ctx.data();

        let kind_byte = *data.get(file_off)?;
        if kind_byte != tkclass_byte(flavor) {
            return None;
        }
        // Always tag as Delphi's TypeKind::Class — callers who need the
        // raw byte use `kind_byte` directly.
        let kind = TypeKind::Class;

        let class_name_off = file_off.checked_add(1)?;
        let class_name = read_short_string_at_file(data, class_name_off)?;
        let mut type_data_off = file_off.checked_add(2)?.checked_add(class_name.len())?;

        // On Mach-O / ELF targets with `FPC_REQUIRES_PROPER_ALIGNMENT`
        // the first TypeData field is pointer-aligned after the preceding
        // `Name: ShortString`. Windows PE packs.
        // Source: `reference/fpc-source/rtl/objpas/typinfo.pp:867-871`.
        if ptr_size > 1 && !ctx.format().is_pe() {
            let rem = type_data_off.checked_rem(ptr_size)?;
            if rem != 0 {
                let pad = ptr_size.checked_sub(rem)?;
                type_data_off = type_data_off.checked_add(pad)?;
            }
        }

        let class_type_va = read_ptr(data, type_data_off, ptr_size)?;
        let parent_info_va_off = type_data_off.checked_add(ptr_size)?;
        let parent_info_va = read_ptr(data, parent_info_va_off, ptr_size)?;
        let prop_count_off = parent_info_va_off.checked_add(ptr_size)?;
        let prop_count = read_u16(data, prop_count_off)? as i16;
        let unit_name_off = prop_count_off.checked_add(2)?;
        let unit_name = read_short_string_at_file(data, unit_name_off)?;

        if !is_plausible_identifier(class_name) || !is_plausible_identifier(unit_name) {
            return None;
        }

        let prop_data_file_offset = unit_name_off.checked_add(1)?.checked_add(unit_name.len())?;

        Some(Self {
            type_info_va,
            kind,
            class_name,
            class_type_va,
            parent_info_va,
            prop_count,
            unit_name,
            prop_data_file_offset,
        })
    }
}

/// Minimal identifier sanity check — same rules as [`crate::vmt`] class
/// names but allows lowercase (unit names conventionally begin with a
/// capital but `SysInit`/`system`/etc. can appear lower).
fn is_plausible_identifier(name: &[u8]) -> bool {
    if name.is_empty() || name.len() > MAX_IDENTIFIER_BYTES {
        return false;
    }
    name.iter().all(|&b| {
        b.is_ascii_alphanumeric()
            || matches!(
                b,
                b'_' | b'.' | b'<' | b'>' | b',' | b':' | b'&' | b'@' | b' '
            )
    })
}

/// A minimally-decoded RTTI type record: its Kind byte, classified Kind,
/// and name. Used to render declared types for properties / fields /
/// method return values without having to know the full per-Kind layout.
#[derive(Debug, Clone, Copy)]
pub struct TypeHeader<'a> {
    /// Virtual address of the PTypeInfo record.
    pub va: u64,
    /// Raw Kind byte as it appears on disk.
    pub kind_byte: u8,
    /// Kind mapped through the flavor into the unified [`TypeKind`] enum.
    pub kind: TypeKind,
    pub(crate) name: &'a [u8],
}

impl<'a> TypeHeader<'a> {
    /// Type name as `&str`, lossily decoded.
    #[inline]
    pub fn name(&self) -> &'a str {
        str::from_utf8(self.name).unwrap_or("<non-ascii>")
    }

    /// Raw type-name bytes, borrowed from the input.
    #[inline]
    pub fn name_bytes(&self) -> &'a [u8] {
        self.name
    }

    /// Decode the type header (Kind + Name) at a `PTypeInfo` VA.
    pub fn from_va(ctx: &BinaryContext<'a>, type_info_va: u64, flavor: VmtFlavor) -> Option<Self> {
        if type_info_va == 0 {
            return None;
        }
        let file_off = ctx.va_to_file(type_info_va)?;
        let data = ctx.data();
        let kind_byte = *data.get(file_off)?;
        let kind = classify_kind_byte(kind_byte, flavor);
        let name_off = file_off.checked_add(1)?;
        let name = read_short_string_at_file(data, name_off)?;
        if !is_plausible_identifier(name) {
            return None;
        }
        Some(Self {
            va: type_info_va,
            kind_byte,
            kind,
            name,
        })
    }

    /// Follow a `PPTypeInfo` (pointer-to-pointer-to-PTypeInfo)
    /// indirection and return the target type header. Delphi's
    /// `PropType` field in `TPropInfo` is stored as a `PPTypeInfo`.
    pub fn from_pptr(
        ctx: &BinaryContext<'a>,
        pptr_va: u64,
        ptr_size: usize,
        flavor: VmtFlavor,
    ) -> Option<Self> {
        let type_info_va = Self::deref_pptypeinfo(ctx, pptr_va, ptr_size)?;
        Self::from_va(ctx, type_info_va, flavor)
    }

    /// Dereference a `PPTypeInfo` VA once, returning the `PTypeInfo` VA
    /// it points at. Returns `None` when either VA is null or unmapped.
    #[inline]
    pub fn deref_pptypeinfo(ctx: &BinaryContext<'_>, pp_va: u64, ptr_size: usize) -> Option<u64> {
        deref_va(ctx, pp_va, ptr_size)
    }
}

/// Storage width of an ordinal / enumeration type.
///
/// Source: `reference/pythia/pythia/core/structures.py:49-56`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OrdinalType {
    /// Signed 8-bit.
    SByte,
    /// Unsigned 8-bit.
    UByte,
    /// Signed 16-bit.
    SWord,
    /// Unsigned 16-bit.
    UWord,
    /// Signed 32-bit.
    SLong,
    /// Unsigned 32-bit.
    ULong,
    /// Unknown byte value — falls through gracefully.
    Unknown(u8),
}

impl OrdinalType {
    fn from_u8(b: u8) -> Self {
        match b {
            0 => OrdinalType::SByte,
            1 => OrdinalType::UByte,
            2 => OrdinalType::SWord,
            3 => OrdinalType::UWord,
            4 => OrdinalType::SLong,
            5 => OrdinalType::ULong,
            o => OrdinalType::Unknown(o),
        }
    }

    /// Storage width in bytes of this ordinal.
    pub fn size(self) -> usize {
        match self {
            OrdinalType::SByte | OrdinalType::UByte => 1,
            OrdinalType::SWord | OrdinalType::UWord => 2,
            OrdinalType::SLong | OrdinalType::ULong => 4,
            OrdinalType::Unknown(_) => 0,
        }
    }
}

/// Partially-decoded `tkEnumeration` type info.
///
/// Source layout: `reference/pythia/pythia/core/structures.py:104-112`.
#[derive(Debug, Clone)]
pub struct EnumInfo<'a> {
    /// Header of the enumeration type.
    pub header: TypeHeader<'a>,
    /// Storage width (determines how enum literals are encoded on disk).
    pub ord: OrdinalType,
    /// Minimum ordinal value (usually `0`).
    pub min: i32,
    /// Maximum ordinal value (i.e. the highest element's index).
    pub max: i32,
    /// VA of the enumeration's base-type `PPTypeInfo` (for sub-ranged
    /// enum types; `0` for top-level enum declarations).
    pub base_type_ref: u64,
    /// Enumeration element names in declaration order.
    pub values: Vec<&'a [u8]>,
    pub(crate) unit_name: Option<&'a [u8]>,
}

impl<'a> EnumInfo<'a> {
    /// Unit name the enumeration was declared in, as `&str`, lossily
    /// decoded.
    #[inline]
    pub fn unit_name(&self) -> Option<&'a str> {
        self.unit_name
            .map(|b| str::from_utf8(b).unwrap_or("<non-ascii>"))
    }
    /// Raw unit-name bytes.
    #[inline]
    pub fn unit_name_bytes(&self) -> Option<&'a [u8]> {
        self.unit_name
    }
}

impl<'a> EnumInfo<'a> {
    /// Decode a `tkEnumeration` record at `type_info_va`.
    pub fn from_va(ctx: &BinaryContext<'a>, type_info_va: u64, flavor: VmtFlavor) -> Option<Self> {
        let header = TypeHeader::from_va(ctx, type_info_va, flavor)?;
        if header.kind != TypeKind::Enumeration {
            return None;
        }
        let data = ctx.data();
        let file_off = ctx.va_to_file(type_info_va)?;
        let mut cursor = file_off.checked_add(2)?.checked_add(header.name.len())?;

        // `OrdType: u8` lives at the start of the tkEnumeration TypeData.
        let ord_byte = *data.get(cursor)?;
        let ord = OrdinalType::from_u8(ord_byte);
        cursor = cursor.checked_add(1)?;

        let min_end = cursor.checked_add(4)?;
        let min = i32::from_le_bytes(data.get(cursor..min_end)?.try_into().ok()?);
        cursor = min_end;
        let max_end = cursor.checked_add(4)?;
        let max = i32::from_le_bytes(data.get(cursor..max_end)?.try_into().ok()?);
        cursor = max_end;
        // BaseTypePtr is a PPTypeInfo. We require a known pointer size
        // from the parsed container; bail rather than guessing.
        let ptr_size = ctx.pointer_size()?.min(8);
        let bt_end = cursor.checked_add(ptr_size)?;
        let base_type_ref = match ptr_size {
            8 => u64::from_le_bytes(data.get(cursor..bt_end)?.try_into().ok()?),
            _ => {
                let four_end = cursor.checked_add(4)?;
                u32::from_le_bytes(data.get(cursor..four_end)?.try_into().ok()?) as u64
            }
        };
        cursor = bt_end;

        // Plausibility: enum index range must be small. i64 arithmetic
        // avoids overflow on extreme min/max from misaligned RTTI.
        let range = (max as i64).checked_sub(min as i64)?;
        if !(0..=MAX_ENUM_RANGE).contains(&range) {
            return None;
        }
        let count = range.checked_add(1)? as usize;
        let mut values = Vec::with_capacity(count);
        for _ in 0..count {
            let name = read_short_string_at_file(data, cursor)?;
            if !is_plausible_identifier(name) {
                return None;
            }
            cursor = cursor.checked_add(1)?.checked_add(name.len())?;
            values.push(name);
        }
        // Trailing UnitName ShortString.
        let unit_name = read_short_string_at_file(data, cursor);

        Some(Self {
            header,
            ord,
            min,
            max,
            base_type_ref,
            values,
            unit_name,
        })
    }
}

/// Width of the `Single` / `Double` / `Extended` / `Comp` / `Currency`
/// float types. Stored as a single byte at `+0` of `tkFloat` TypeData.
///
/// Source: `reference/pythia/pythia/core/structures.py:58-64`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FloatType {
    /// 4-byte IEEE 754.
    Single,
    /// 8-byte IEEE 754.
    Double,
    /// 10-byte Intel 80-bit extended precision.
    Extended,
    /// 8-byte Int64 scaled — historical Borland "Comp" type.
    Comp,
    /// 8-byte Int64 scaled by 10 000 — Delphi `Currency`.
    Currency,
    /// Unknown discriminator byte.
    Unknown(u8),
}

impl FloatType {
    fn from_u8(b: u8) -> Self {
        match b {
            0 => FloatType::Single,
            1 => FloatType::Double,
            2 => FloatType::Extended,
            3 => FloatType::Comp,
            4 => FloatType::Currency,
            other => FloatType::Unknown(other),
        }
    }
}

/// `tkInteger` / `tkChar` / `tkWChar` — bounded ordinal types.
#[derive(Debug, Clone, Copy)]
pub struct OrdinalInfo<'a> {
    /// Type header (Kind + Name).
    pub header: TypeHeader<'a>,
    /// Storage width discriminator.
    pub ord: OrdinalType,
    /// Minimum value (interpreted per `ord.size()` and signedness).
    pub min: i32,
    /// Maximum value.
    pub max: i32,
}

/// `tkFloat` — floating-point types.
#[derive(Debug, Clone, Copy)]
pub struct FloatInfo<'a> {
    /// Type header.
    pub header: TypeHeader<'a>,
    /// Which float width this is.
    pub float_type: FloatType,
}

/// `tkSet` — set-of-enumeration types.
#[derive(Debug, Clone, Copy)]
pub struct SetInfo<'a> {
    /// Header (name + Kind).
    pub header: TypeHeader<'a>,
    /// VA of the base-type pointer. Dereference once to reach the element
    /// enumeration's `PTypeInfo`.
    pub comp_type_ref: u64,
    /// Convenience: the resolved element type header if the pointer was
    /// walkable. `None` when the indirection fails.
    pub element_type: Option<TypeHeader<'a>>,
}

/// `tkClassRef` — `class of TSomething` metaclass references.
#[derive(Debug, Clone, Copy)]
pub struct ClassRefInfo<'a> {
    /// Header.
    pub header: TypeHeader<'a>,
    /// VA of the referenced class's `PPTypeInfo`.
    pub instance_type_ref: u64,
    /// Resolved instance type header, if the indirection succeeded.
    pub instance_type: Option<TypeHeader<'a>>,
}

/// `tkDynArray` — dynamic array types.
#[derive(Debug, Clone, Copy)]
pub struct DynArrayInfo<'a> {
    /// Header.
    pub header: TypeHeader<'a>,
    /// Size of one element in bytes.
    pub elem_size: u32,
    /// Element type VA (non-zero only for managed element types — strings,
    /// interfaces, other dynamic arrays, etc.). Null for plain scalar
    /// element types. See `DynArrayInfo::elem_type_any` for the unified
    /// element-type view.
    pub elem_type_ref_managed: u64,
    /// Element type VA emitted for *all* element types on modern Delphi.
    pub elem_type_ref_any: u64,
    /// Resolved element type header if either VA points at a usable record.
    pub element_type: Option<TypeHeader<'a>>,
    pub(crate) unit_name: Option<&'a [u8]>,
}

impl<'a> DynArrayInfo<'a> {
    /// Unit name as `&str`, lossily decoded.
    #[inline]
    pub fn unit_name(&self) -> Option<&'a str> {
        self.unit_name
            .map(|b| str::from_utf8(b).unwrap_or("<non-ascii>"))
    }
    /// Raw unit-name bytes.
    #[inline]
    pub fn unit_name_bytes(&self) -> Option<&'a [u8]> {
        self.unit_name
    }
}

/// `tkInterface` — COM-style interface types.
#[derive(Debug, Clone, Copy)]
pub struct InterfaceTypeInfo<'a> {
    /// Header.
    pub header: TypeHeader<'a>,
    /// Parent interface's `PPTypeInfo` VA.
    pub parent_ref: u64,
    /// Parent interface header if the indirection succeeded.
    pub parent_type: Option<TypeHeader<'a>>,
    /// Interface flags byte (bit 0 = HasGuid, etc.).
    pub flags: u8,
    /// Interface GUID.
    pub guid: Guid,
    pub(crate) unit_name: Option<&'a [u8]>,
}

impl<'a> InterfaceTypeInfo<'a> {
    /// Unit name as `&str`, lossily decoded.
    #[inline]
    pub fn unit_name(&self) -> Option<&'a str> {
        self.unit_name
            .map(|b| str::from_utf8(b).unwrap_or("<non-ascii>"))
    }
    /// Raw unit-name bytes.
    #[inline]
    pub fn unit_name_bytes(&self) -> Option<&'a [u8]> {
        self.unit_name
    }
}

/// One entry in a `tkRecord` managed-fields list.
#[derive(Debug, Clone, Copy)]
pub struct RecordManagedField<'a> {
    /// Field-type `PPTypeInfo` VA.
    pub type_ref: u64,
    /// Byte offset within the record.
    pub offset: u64,
    /// Resolved field-type header if the indirection succeeded.
    pub field_type: Option<TypeHeader<'a>>,
}

/// `tkRecord` — value-type record definition.
#[derive(Debug, Clone)]
pub struct RecordInfo<'a> {
    /// Header.
    pub header: TypeHeader<'a>,
    /// Total record size in bytes.
    pub record_size: u32,
    /// Managed-field entries (references that need refcount management —
    /// strings, dynamic arrays, interfaces, other records with managed
    /// members).
    pub managed_fields: Vec<RecordManagedField<'a>>,
}

/// Sum type that wraps whichever per-Kind decoder matched.
///
/// `decode_type_detail` returns this, so callers can match on Kind without
/// pre-dispatching.
#[derive(Debug, Clone)]
pub enum TypeDetail<'a> {
    /// tkClass — full class record including unit + published-property count.
    Class(TkClassInfo<'a>),
    /// tkEnumeration — element names + bounds.
    Enumeration(EnumInfo<'a>),
    /// tkInteger / tkChar / tkWChar.
    Ordinal(OrdinalInfo<'a>),
    /// tkFloat.
    Float(FloatInfo<'a>),
    /// tkSet.
    Set(SetInfo<'a>),
    /// tkClassRef.
    ClassRef(ClassRefInfo<'a>),
    /// tkDynArray.
    DynArray(DynArrayInfo<'a>),
    /// tkInterface.
    Interface(InterfaceTypeInfo<'a>),
    /// tkRecord.
    Record(RecordInfo<'a>),
    /// tkMethod — method-of-object pointer (event handlers).
    Method(MethodInfo<'a>),
    /// tkProcedure — first-class procedure reference.
    Procedure(ProcedureInfo<'a>),
    /// tkLString / tkUString / tkWString — string RTTI with code page.
    String(StringInfo<'a>),
    /// Known Kind but not yet a dedicated decoder — just the header.
    Other(TypeHeader<'a>),
}

impl<'a> TypeDetail<'a> {
    /// Copy of the contained header regardless of variant.
    pub fn header(&self) -> TypeHeader<'a> {
        match self {
            TypeDetail::Class(x) => TypeHeader {
                va: x.type_info_va,
                kind_byte: tkclass_byte(VmtFlavor::Delphi),
                kind: TypeKind::Class,
                name: x.class_name,
            },
            TypeDetail::Enumeration(x) => x.header,
            TypeDetail::Ordinal(x) => x.header,
            TypeDetail::Float(x) => x.header,
            TypeDetail::Set(x) => x.header,
            TypeDetail::ClassRef(x) => x.header,
            TypeDetail::DynArray(x) => x.header,
            TypeDetail::Interface(x) => x.header,
            TypeDetail::Record(x) => x.header,
            TypeDetail::Method(x) => x.header,
            TypeDetail::Procedure(x) => x.header,
            TypeDetail::String(x) => x.header,
            TypeDetail::Other(x) => *x,
        }
    }
}

impl<'a> TypeDetail<'a> {
    /// Dispatcher — decode whichever Kind is stored at `type_info_va`,
    /// returning the rich per-Kind variant.
    pub fn from_va(ctx: &BinaryContext<'a>, type_info_va: u64, flavor: VmtFlavor) -> Option<Self> {
        let header = TypeHeader::from_va(ctx, type_info_va, flavor)?;
        let ptr_size = ctx.pointer_size().unwrap_or(8);
        let detail = match header.kind {
            TypeKind::Class => {
                Self::Class(TkClassInfo::from_va(ctx, type_info_va, ptr_size, flavor)?)
            }
            TypeKind::Enumeration => {
                Self::Enumeration(EnumInfo::from_va(ctx, type_info_va, flavor)?)
            }
            TypeKind::Integer | TypeKind::Char | TypeKind::WChar => {
                Self::Ordinal(OrdinalInfo::from_va(ctx, type_info_va, flavor)?)
            }
            TypeKind::Float => Self::Float(FloatInfo::from_va(ctx, type_info_va, flavor)?),
            TypeKind::Set => Self::Set(SetInfo::from_va(ctx, type_info_va, flavor)?),
            TypeKind::ClassRef => Self::ClassRef(ClassRefInfo::from_va(ctx, type_info_va, flavor)?),
            TypeKind::DynArray => Self::DynArray(DynArrayInfo::from_va(ctx, type_info_va, flavor)?),
            TypeKind::Interface => {
                Self::Interface(InterfaceTypeInfo::from_va(ctx, type_info_va, flavor)?)
            }
            TypeKind::Record => Self::Record(RecordInfo::from_va(ctx, type_info_va, flavor)?),
            TypeKind::Method => Self::Method(MethodInfo::from_va(ctx, type_info_va, flavor)?),
            TypeKind::Procedure => {
                Self::Procedure(ProcedureInfo::from_va(ctx, type_info_va, flavor)?)
            }
            TypeKind::LString | TypeKind::UString | TypeKind::WString => {
                Self::String(StringInfo::from_va(ctx, type_info_va, flavor)?)
            }
            _ => Self::Other(header),
        };
        Some(detail)
    }
}

impl<'a> OrdinalInfo<'a> {
    /// Decode a `tkInteger` / `tkChar` / `tkWChar` record.
    pub fn from_va(ctx: &BinaryContext<'a>, type_info_va: u64, flavor: VmtFlavor) -> Option<Self> {
        let header = TypeHeader::from_va(ctx, type_info_va, flavor)?;
        if !matches!(
            header.kind,
            TypeKind::Integer | TypeKind::Char | TypeKind::WChar
        ) {
            return None;
        }
        let data = ctx.data();
        let off = ctx
            .va_to_file(type_info_va)?
            .checked_add(2)?
            .checked_add(header.name.len())?;
        let ord = OrdinalType::from_u8(*data.get(off)?);
        let min_start = off.checked_add(1)?;
        let min_end = off.checked_add(5)?;
        let max_end = off.checked_add(9)?;
        let min = i32::from_le_bytes(data.get(min_start..min_end)?.try_into().ok()?);
        let max = i32::from_le_bytes(data.get(min_end..max_end)?.try_into().ok()?);
        Some(Self {
            header,
            ord,
            min,
            max,
        })
    }
}

impl<'a> FloatInfo<'a> {
    /// Decode a `tkFloat` record.
    pub fn from_va(ctx: &BinaryContext<'a>, type_info_va: u64, flavor: VmtFlavor) -> Option<Self> {
        let header = TypeHeader::from_va(ctx, type_info_va, flavor)?;
        if header.kind != TypeKind::Float {
            return None;
        }
        let data = ctx.data();
        let off = ctx
            .va_to_file(type_info_va)?
            .checked_add(2)?
            .checked_add(header.name.len())?;
        let float_type = FloatType::from_u8(*data.get(off)?);
        Some(Self { header, float_type })
    }
}

impl<'a> SetInfo<'a> {
    /// Decode a `tkSet` record and resolve the element-enumeration
    /// type, if reachable.
    pub fn from_va(ctx: &BinaryContext<'a>, type_info_va: u64, flavor: VmtFlavor) -> Option<Self> {
        let header = TypeHeader::from_va(ctx, type_info_va, flavor)?;
        if header.kind != TypeKind::Set {
            return None;
        }
        let data = ctx.data();
        let ptr_size = ctx.pointer_size()?;
        // tkSet TypeData = { OrdType:u8, CompType:PPTypeInfo, ... }.
        // We only need the CompType pointer; skip the ordinal byte.
        let off = ctx
            .va_to_file(type_info_va)?
            .checked_add(2)?
            .checked_add(header.name.len())?
            .checked_add(1)?;
        let comp_type_ref = read_ptr(data, off, ptr_size)?;
        let element_type = TypeHeader::from_pptr(ctx, comp_type_ref, ptr_size, flavor);
        Some(Self {
            header,
            comp_type_ref,
            element_type,
        })
    }
}

impl<'a> ClassRefInfo<'a> {
    /// Decode a `tkClassRef` record.
    pub fn from_va(ctx: &BinaryContext<'a>, type_info_va: u64, flavor: VmtFlavor) -> Option<Self> {
        let header = TypeHeader::from_va(ctx, type_info_va, flavor)?;
        if header.kind != TypeKind::ClassRef {
            return None;
        }
        let data = ctx.data();
        let ptr_size = ctx.pointer_size()?;
        let off = ctx
            .va_to_file(type_info_va)?
            .checked_add(2)?
            .checked_add(header.name.len())?;
        let instance_type_ref = read_ptr(data, off, ptr_size)?;
        let instance_type = TypeHeader::from_pptr(ctx, instance_type_ref, ptr_size, flavor);
        Some(Self {
            header,
            instance_type_ref,
            instance_type,
        })
    }
}

impl<'a> DynArrayInfo<'a> {
    /// Decode a `tkDynArray` record.
    pub fn from_va(ctx: &BinaryContext<'a>, type_info_va: u64, flavor: VmtFlavor) -> Option<Self> {
        let header = TypeHeader::from_va(ctx, type_info_va, flavor)?;
        if header.kind != TypeKind::DynArray {
            return None;
        }
        let data = ctx.data();
        let ptr_size = ctx.pointer_size()?;
        let mut off = ctx
            .va_to_file(type_info_va)?
            .checked_add(2)?
            .checked_add(header.name.len())?;
        let elem_size_end = off.checked_add(4)?;
        let elem_size = i32::from_le_bytes(data.get(off..elem_size_end)?.try_into().ok()?) as u32;
        off = elem_size_end;
        let elem_type_ref_managed = read_ptr(data, off, ptr_size)?;
        off = off.checked_add(ptr_size)?;
        // VarType index skipped.
        off = off.checked_add(4)?;
        let elem_type_ref_any = read_ptr(data, off, ptr_size)?;
        off = off.checked_add(ptr_size)?;
        let unit_name = read_short_string_at_file(data, off);
        // Pick whichever pointer resolves — `elem_type_ref_any` is
        // emitted on modern Delphi/FPC even for non-managed elements;
        // the managed variant can be null.
        let element_type = if elem_type_ref_any != 0 {
            TypeHeader::from_pptr(ctx, elem_type_ref_any, ptr_size, flavor)
        } else {
            TypeHeader::from_pptr(ctx, elem_type_ref_managed, ptr_size, flavor)
        };
        Some(Self {
            header,
            elem_size,
            elem_type_ref_managed,
            elem_type_ref_any,
            element_type,
            unit_name,
        })
    }
}

impl<'a> InterfaceTypeInfo<'a> {
    /// Decode a `tkInterface` record.
    pub fn from_va(ctx: &BinaryContext<'a>, type_info_va: u64, flavor: VmtFlavor) -> Option<Self> {
        let header = TypeHeader::from_va(ctx, type_info_va, flavor)?;
        if header.kind != TypeKind::Interface {
            return None;
        }
        let data = ctx.data();
        let ptr_size = ctx.pointer_size()?;
        let mut off = ctx
            .va_to_file(type_info_va)?
            .checked_add(2)?
            .checked_add(header.name.len())?;
        let parent_ref = read_ptr(data, off, ptr_size)?;
        off = off.checked_add(ptr_size)?;
        let flags = *data.get(off)?;
        off = off.checked_add(1)?;
        let guid_end = off.checked_add(16)?;
        let guid_bytes: [u8; 16] = data.get(off..guid_end)?.try_into().ok()?;
        let guid = Guid::from(guid_bytes);
        off = guid_end;
        let unit_name = read_short_string_at_file(data, off);
        let parent_type = TypeHeader::from_pptr(ctx, parent_ref, ptr_size, flavor);
        Some(Self {
            header,
            parent_ref,
            parent_type,
            flags,
            guid,
            unit_name,
        })
    }
}

/// Method kind — matches Delphi's `TMethodKind` and FPC's mkXxx constants
/// in `typinfo.pp`. Source: `reference/pythia/pythia/core/structures.py:36-47`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum MethodKind {
    /// `procedure` — no result.
    Procedure = 0,
    /// `function` — has a result value.
    Function = 1,
    /// `constructor`.
    Constructor = 2,
    /// `destructor`.
    Destructor = 3,
    /// `class procedure`.
    ClassProcedure = 4,
    /// `class function`.
    ClassFunction = 5,
    /// `class constructor` (Delphi 2010+).
    ClassConstructor = 6,
    /// Operator overload.
    OperatorOverload = 7,
    /// `safecall procedure`.
    SafeProcedure = 8,
    /// `safecall function`.
    SafeFunction = 9,
    /// Unknown / out-of-range byte.
    Unknown = 0xff,
}

impl MethodKind {
    fn from_u8(b: u8) -> Self {
        match b {
            0 => MethodKind::Procedure,
            1 => MethodKind::Function,
            2 => MethodKind::Constructor,
            3 => MethodKind::Destructor,
            4 => MethodKind::ClassProcedure,
            5 => MethodKind::ClassFunction,
            6 => MethodKind::ClassConstructor,
            7 => MethodKind::OperatorOverload,
            8 => MethodKind::SafeProcedure,
            9 => MethodKind::SafeFunction,
            _ => MethodKind::Unknown,
        }
    }
}

/// One formal parameter of a method-of-object or procedure type.
#[derive(Debug, Clone, Copy)]
pub struct MethodParam<'a> {
    /// `Flags` byte — `pfVar`, `pfConst`, `pfArray`, `pfOut`, `pfResult`, etc.
    /// We expose the raw byte; see Embarcadero DocWiki "TParamFlag".
    pub flags: u8,
    pub(crate) name: &'a [u8],
    pub(crate) type_name: &'a [u8],
}

impl<'a> MethodParam<'a> {
    /// Parameter name as `&str`, lossily decoded.
    #[inline]
    pub fn name(&self) -> &'a str {
        str::from_utf8(self.name).unwrap_or("<non-ascii>")
    }
    /// Raw parameter name bytes.
    #[inline]
    pub fn name_bytes(&self) -> &'a [u8] {
        self.name
    }
    /// Parameter type name as `&str`, lossily decoded. Unlike class RTTI,
    /// method RTTI stores the parameter's type as a textual identifier
    /// rather than a `PPTypeInfo`.
    #[inline]
    pub fn type_name(&self) -> &'a str {
        str::from_utf8(self.type_name).unwrap_or("<non-ascii>")
    }
    /// Raw parameter type-name bytes.
    #[inline]
    pub fn type_name_bytes(&self) -> &'a [u8] {
        self.type_name
    }
}

/// `tkMethod` — method-of-object pointer signature.
///
/// Example: `TNotifyEvent = procedure(Sender: TObject) of object`.
///
/// Layout (from `reference/pythia/pythia/core/structures.py:204-214`):
///
/// ```text
///   MethodType: u8            // Procedure / Function / etc.
///   NumParams:  u8
///   Params:     array[NumParams]
///     ParamFlags: u8
///     ParamName:  ShortString
///     TypeName:   ShortString
/// ```
#[derive(Debug, Clone)]
pub struct MethodInfo<'a> {
    /// Type header.
    pub header: TypeHeader<'a>,
    /// Method kind (procedure / function / constructor / …).
    pub kind: MethodKind,
    /// Formal parameter list in declaration order.
    pub params: Vec<MethodParam<'a>>,
    /// Return-type name when [`MethodKind::Function`] / related; empty otherwise.
    pub result_type: Option<&'a [u8]>,
}

/// `tkProcedure` — first-class reference-to-procedure type.
#[derive(Debug, Clone)]
pub struct ProcedureInfo<'a> {
    /// Type header.
    pub header: TypeHeader<'a>,
}

/// `tkLString` / `tkUString` / `tkWString` — string RTTI record.
///
/// Source: `reference/pythia/pythia/core/structures.py:196-202`.
#[derive(Debug, Clone, Copy)]
pub struct StringInfo<'a> {
    /// Type header.
    pub header: TypeHeader<'a>,
    /// Code page for `AnsiString` / `RawByteString` variants. `0`
    /// indicates "use default ANSI code page"; `1200` is UTF-16;
    /// `65001` is UTF-8.
    pub code_page: u16,
}

impl<'a> MethodInfo<'a> {
    /// Decode a `tkMethod` record.
    pub fn from_va(ctx: &BinaryContext<'a>, type_info_va: u64, flavor: VmtFlavor) -> Option<Self> {
        let header = TypeHeader::from_va(ctx, type_info_va, flavor)?;
        if header.kind != TypeKind::Method {
            return None;
        }
        let data = ctx.data();
        let mut cursor = ctx
            .va_to_file(type_info_va)?
            .checked_add(2)?
            .checked_add(header.name.len())?;
        let kind = MethodKind::from_u8(*data.get(cursor)?);
        cursor = cursor.checked_add(1)?;
        let num_params = *data.get(cursor)? as usize;
        cursor = cursor.checked_add(1)?;
        if num_params > MAX_METHOD_PARAMS {
            return None;
        }
        let mut params = Vec::with_capacity(num_params);
        for _ in 0..num_params {
            let flags = *data.get(cursor)?;
            cursor = cursor.checked_add(1)?;
            let name = read_short_string_at_file(data, cursor)?;
            cursor = cursor.checked_add(1)?.checked_add(name.len())?;
            let type_name = read_short_string_at_file(data, cursor)?;
            cursor = cursor.checked_add(1)?.checked_add(type_name.len())?;
            params.push(MethodParam {
                flags,
                name,
                type_name,
            });
        }
        let result_type = if matches!(
            kind,
            MethodKind::Function | MethodKind::ClassFunction | MethodKind::SafeFunction
        ) {
            read_short_string_at_file(data, cursor)
        } else {
            None
        };
        Some(Self {
            header,
            kind,
            params,
            result_type,
        })
    }
}

impl<'a> ProcedureInfo<'a> {
    /// Decode a `tkProcedure` record. Modern-RTTI-only — older
    /// binaries emit just the header with no parameter info.
    pub fn from_va(ctx: &BinaryContext<'a>, type_info_va: u64, flavor: VmtFlavor) -> Option<Self> {
        let header = TypeHeader::from_va(ctx, type_info_va, flavor)?;
        if header.kind != TypeKind::Procedure {
            return None;
        }
        Some(Self { header })
    }
}

impl<'a> StringInfo<'a> {
    /// Decode a `tkLString` / `tkUString` / `tkWString` record to
    /// recover the code page.
    pub fn from_va(ctx: &BinaryContext<'a>, type_info_va: u64, flavor: VmtFlavor) -> Option<Self> {
        let header = TypeHeader::from_va(ctx, type_info_va, flavor)?;
        if !matches!(
            header.kind,
            TypeKind::LString | TypeKind::UString | TypeKind::WString
        ) {
            return None;
        }
        let data = ctx.data();
        let off = ctx
            .va_to_file(type_info_va)?
            .checked_add(2)?
            .checked_add(header.name.len())?;
        // Pythia records 6 unknown bytes before the code page;
        // empirically on modern Delphi the bytes are (u16 elem-size,
        // 4 reserved) but we only need the code page. Read `u16` at
        // +6. If the slice walks off EOF the type record is
        // truncated — surface a `None` rather than misreporting code
        // page 0 (which is valid metadata for legacy ANSI strings,
        // so 0 must mean "actually 0").
        let code_page_start = off.checked_add(6)?;
        let code_page_end = code_page_start.checked_add(2)?;
        let code_page =
            u16::from_le_bytes(data.get(code_page_start..code_page_end)?.try_into().ok()?);
        Some(Self { header, code_page })
    }
}

impl<'a> RecordInfo<'a> {
    /// Decode a `tkRecord` record including its managed-field entries.
    ///
    /// Accepts records with an empty on-disk name — the compiler
    /// emits `vmtInitTable` as a synthetic `tkRecord` with no name
    /// whose sole purpose is to enumerate the host class's managed
    /// fields. [`TypeHeader::from_va`] rejects empty names, so we
    /// read the header directly here.
    pub fn from_va(ctx: &BinaryContext<'a>, type_info_va: u64, flavor: VmtFlavor) -> Option<Self> {
        let data = ctx.data();
        let file_off = ctx.va_to_file(type_info_va)?;
        let kind_byte = *data.get(file_off)?;
        if kind_byte
            != match flavor {
                VmtFlavor::Delphi => 14, // Delphi tkRecord
                VmtFlavor::Fpc => 13,    // FPC tkRecord
            }
        {
            return None;
        }
        let name_off = file_off.checked_add(1)?;
        let name = read_short_string_at_file(data, name_off)?;
        let header = TypeHeader {
            va: type_info_va,
            kind_byte,
            kind: TypeKind::Record,
            name,
        };
        let ptr_size = ctx.pointer_size()?;
        let mut off = file_off.checked_add(2)?.checked_add(name.len())?;
        let record_size_end = off.checked_add(4)?;
        let record_size =
            i32::from_le_bytes(data.get(off..record_size_end)?.try_into().ok()?) as u32;
        off = record_size_end;
        let num_managed_end = off.checked_add(4)?;
        let num_managed =
            i32::from_le_bytes(data.get(off..num_managed_end)?.try_into().ok()?) as usize;
        off = num_managed_end;
        if num_managed > MAX_RECORD_MANAGED_FIELDS {
            return None;
        }
        let mut managed_fields = Vec::with_capacity(num_managed);
        for _ in 0..num_managed {
            let type_ref = read_ptr(data, off, ptr_size)?;
            off = off.checked_add(ptr_size)?;
            let offset = read_ptr(data, off, ptr_size)?;
            off = off.checked_add(ptr_size)?;
            let field_type = TypeHeader::from_pptr(ctx, type_ref, ptr_size, flavor);
            managed_fields.push(RecordManagedField {
                type_ref,
                offset,
                field_type,
            });
        }
        Some(Self {
            header,
            record_size,
            managed_fields,
        })
    }
}

/// Sweep the binary's read-only data for every FPC `tkInterface` record
/// and index them by GUID. Used by
/// [`crate::DelphiBinary::interface_methods`] to recover per-method
/// names: the per-class `InterfaceEntry` carries the GUID but no
/// pointer to the tkInterface PTypeInfo, so we have to find it by
/// scanning.
///
/// On Delphi binaries this returns an empty map — Delphi's classic
/// `tkInterface` doesn't carry a method table. (Modern extended RTTI
/// does, on a different layout, not yet supported.)
///
/// False-positive guard: each candidate is fully decoded and the GUID
/// must be non-zero before it's accepted.
pub fn scan_fpc_tkinterface_index(ctx: &BinaryContext<'_>) -> std::collections::HashMap<Guid, u64> {
    let mut idx = std::collections::HashMap::new();
    let Some(_) = ctx.pointer_size() else {
        return idx;
    };
    // FPC `tkInterface` kind byte is 14 (per `fpc_kind_from_byte`).
    const FPC_TK_INTERFACE: u8 = 14;
    for range in ctx.scan_ranges() {
        let Some(slice) = ctx.section_data(range) else {
            continue;
        };
        let mut i = 0usize;
        while i < slice.len() {
            if slice.get(i).copied() == Some(FPC_TK_INTERFACE)
                && let Some(va) = range.va.checked_add(i as u64)
                && let Some(info) = InterfaceTypeInfo::from_va(ctx, va, VmtFlavor::Fpc)
                && (info.guid.data1 != 0
                    || info.guid.data2 != 0
                    || info.guid.data3 != 0
                    || info.guid.data4 != [0; 8])
            {
                idx.entry(info.guid).or_insert(va);
            }
            let Some(next) = i.checked_add(1) else {
                break;
            };
            i = next;
        }
    }
    idx
}

/// Header of an FPC `TIntfMethodTable`. The body is a sequence of
/// [`IntfMethodEntry`] records reachable via [`Self::entries`].
///
/// Source: `reference/fpc-source/rtl/objpas/typinfo.pp:429-443`.
#[derive(Debug, Clone)]
pub struct IntfMethodTable<'a> {
    method_count: u16,
    rtti_count: u16,
    entries: Vec<IntfMethodEntry<'a>>,
}

impl<'a> IntfMethodTable<'a> {
    /// Decode the method table referenced by an FPC `tkInterface`
    /// `PTypeInfo` record at `tkintf_va`.
    ///
    /// Returns `None` when the layout doesn't parse cleanly. The
    /// header (`method_count`, `rtti_count`) is recovered even when
    /// per-method names are absent — `rtti_count == 0xFFFF` means
    /// the compiler emitted no per-method records, so
    /// [`Self::entries`] will be empty in that case.
    pub fn from_tkinterface(ctx: &BinaryContext<'a>, tkintf_va: u64) -> Option<Self> {
        let header = TypeHeader::from_va(ctx, tkintf_va, VmtFlavor::Fpc)?;
        if header.kind != TypeKind::Interface {
            return None;
        }
        let ptr_size = ctx.pointer_size()?;
        let data = ctx.data();

        // FPC's `aligntoptr` is a no-op on architectures without
        // `FPC_REQUIRES_PROPER_ALIGNMENT` (i.e. x86 / x86_64 in any
        // container). It only inserts padding on ARM / AArch64 etc.
        let needs_alignment = !matches!(ctx.target_arch(), TargetArch::X86 | TargetArch::X86_64);

        // Walk past kind(1), namelen(1), name, parent_ref(ptr),
        // flags(1), guid(16), unit_name(shortstring) → reach
        // PropertyTable start.
        let file_off = ctx.va_to_file(tkintf_va)?;
        let after_name = file_off.checked_add(2)?.checked_add(header.name.len())?;
        let after_parent = after_name.checked_add(ptr_size)?;
        let after_flags = after_parent.checked_add(1)?;
        let after_guid = after_flags.checked_add(16)?;
        let unit_name_len = *data.get(after_guid)? as usize;
        let after_unit_name = after_guid.checked_add(1)?.checked_add(unit_name_len)?;

        // PropertyTable starts here.
        let prop_table_off = align_to_ptr(after_unit_name, ptr_size, needs_alignment)?;

        // TPropData: u16 count, then variable-length entries. We bail
        // on non-empty published-property tables — interfaces with
        // published properties are vanishingly rare, and walking past
        // them needs a flavor-specific TPropInfo decoder we don't
        // duplicate here.
        let prop_count = read_u16(data, prop_table_off)? as usize;
        if prop_count != 0 {
            return None;
        }
        let after_prop_data = prop_table_off.checked_add(2)?;

        // MethodTable starts at aligntoptr(PropertyTable.Tail).
        let method_table_off = align_to_ptr(after_prop_data, ptr_size, needs_alignment)?;

        // TIntfMethodTable: u16 count, u16 rtti_count.
        let method_count = read_u16(data, method_table_off)?;
        let rtti_count = read_u16(data, method_table_off.checked_add(2)?)?;

        if method_count as usize > MAX_INTF_METHODS {
            return None;
        }

        // `rtti_count == 0xFFFF` is the documented "no per-method RTTI"
        // sentinel — the compiler knows the slot count but emitted no
        // metadata for any individual method.
        if rtti_count == u16::MAX || rtti_count == 0 {
            return Some(Self {
                method_count,
                rtti_count,
                entries: Vec::new(),
            });
        }

        let entries_start = method_table_off.checked_add(4)?;
        let mut entry_off = align_to_ptr(entries_start, ptr_size, needs_alignment)?;

        let walk_count = rtti_count.min(method_count) as usize;
        let mut entries = Vec::with_capacity(walk_count);
        for slot in 0..walk_count {
            // TIntfMethodEntry layout (no HAVE_INVOKEHELPER on the
            // platforms we target):
            //   ResultType: PPTypeInfo  (ptr)
            //   CC: u8
            //   Kind: u8
            //   ParamCount: u16
            //   StackSize: SizeInt      (ptr-sized)
            //   NamePtr: PShortString   (ptr)
            let cc_off = entry_off.checked_add(ptr_size)?;
            let kind_off = cc_off.checked_add(1)?;
            let param_count_off = kind_off.checked_add(1)?;
            let stack_size_off = param_count_off.checked_add(2)?;
            let name_ptr_off = stack_size_off.checked_add(ptr_size)?;

            let result_type_ref = read_ptr(data, entry_off, ptr_size)?;
            let calling_convention = *data.get(cc_off)?;
            let kind_byte = *data.get(kind_off)?;
            let param_count = read_u16(data, param_count_off)?;
            let stack_size = read_ptr(data, stack_size_off, ptr_size)?;
            let name_ptr = read_ptr(data, name_ptr_off, ptr_size)?;
            let name = read_short_string_at_va(ctx, name_ptr)?;

            entries.push(IntfMethodEntry {
                slot: slot as u16,
                result_type_ref,
                calling_convention,
                kind_byte,
                kind: MethodKind::from_u8(kind_byte),
                param_count,
                stack_size,
                name,
            });

            // Bail on parametered methods (the inline
            // `TVmtMethodParam` walker would duplicate the method-RTTI
            // decoder); the partial list up to the first parametered
            // method is still useful for naming purposes.
            if param_count != 0 {
                break;
            }
            let after_entry_base = name_ptr_off.checked_add(ptr_size)?;
            // ResultLocs is present when ResultType is non-null.
            let after_entry = if result_type_ref != 0 {
                after_entry_base.checked_add(ptr_size)?
            } else {
                after_entry_base
            };
            entry_off = align_to_ptr(after_entry, ptr_size, needs_alignment)?;
        }

        Some(Self {
            method_count,
            rtti_count,
            entries,
        })
    }

    /// Total number of slots in the interface's vtable (matches the
    /// Delphi `Methods` count).
    #[inline]
    pub fn method_count(&self) -> u16 {
        self.method_count
    }

    /// Number of entries that carry per-method RTTI metadata. Equal
    /// to [`Self::method_count`] when full RTTI was emitted; `0xFFFF`
    /// when the compiler emitted no per-method records (interfaces
    /// declared without `{$M+}` mode in their source unit). When the
    /// sentinel is set, [`Self::entries`] returns an empty slice —
    /// the vtable still has `method_count` slots, but their names
    /// are not recoverable from this RTTI.
    #[inline]
    pub fn rtti_count(&self) -> u16 {
        self.rtti_count
    }

    /// Per-method RTTI records, one per slot. Empty when
    /// `rtti_count == 0xFFFF`.
    #[inline]
    pub fn entries(&self) -> &[IntfMethodEntry<'a>] {
        &self.entries
    }
}

/// One entry in an FPC `tkInterface` method table.
///
/// Source: `reference/fpc-source/rtl/objpas/typinfo.pp:398-427`
/// (`TIntfMethodEntry`). We don't decode parameters here — the entry
/// is variable-length, and we bail past entries that declare any
/// parameter so the simple shape stays clean.
#[derive(Debug, Clone, Copy)]
pub struct IntfMethodEntry<'a> {
    slot: u16,
    result_type_ref: u64,
    calling_convention: u8,
    kind_byte: u8,
    kind: MethodKind,
    param_count: u16,
    stack_size: u64,
    name: &'a [u8],
}

impl<'a> IntfMethodEntry<'a> {
    /// Slot index within the interface's vtable.
    #[inline]
    pub fn slot(&self) -> u16 {
        self.slot
    }

    /// Method name as `&str`, lossily decoded.
    #[inline]
    pub fn name(&self) -> &'a str {
        str::from_utf8(self.name).unwrap_or("<non-ascii>")
    }

    /// Raw method-name bytes (the on-disk shortstring body).
    #[inline]
    pub fn name_bytes(&self) -> &'a [u8] {
        self.name
    }

    /// `PPTypeInfo` VA of the result type, or `0` for procedures.
    #[inline]
    pub fn result_type_ref(&self) -> u64 {
        self.result_type_ref
    }

    /// Calling-convention byte (`TCallConv`).
    #[inline]
    pub fn calling_convention(&self) -> u8 {
        self.calling_convention
    }

    /// Raw method-kind byte (`TMethodKind`).
    #[inline]
    pub fn kind_byte(&self) -> u8 {
        self.kind_byte
    }

    /// Method kind mapped through [`MethodKind`].
    #[inline]
    pub fn kind(&self) -> MethodKind {
        self.kind
    }

    /// Number of formal parameters declared in source. When non-zero
    /// the parameter records aren't decoded; future iterations may
    /// expose them.
    #[inline]
    pub fn param_count(&self) -> u16 {
        self.param_count
    }

    /// Stack-bytes consumed by the call (FPC
    /// `TIntfMethodEntry.StackSize`).
    #[inline]
    pub fn stack_size(&self) -> u64 {
        self.stack_size
    }
}

/// Pointer-align `off` to the next multiple of `ptr_size`. When
/// `apply_alignment` is `false` (Windows PE, where FPC packs records),
/// returns `off` unchanged.
fn align_to_ptr(off: usize, ptr_size: usize, apply_alignment: bool) -> Option<usize> {
    if !apply_alignment || ptr_size == 0 {
        return Some(off);
    }
    let rem = off.checked_rem(ptr_size)?;
    if rem == 0 {
        Some(off)
    } else {
        let pad = ptr_size.checked_sub(rem)?;
        off.checked_add(pad)
    }
}

/// Hard cap on FPC interface method-table entries — guards against
/// adversarially-large `Count` fields.
const MAX_INTF_METHODS: usize = 1024;

#[cfg(test)]
mod tests {
    use super::*;

    /// Lock every documented Delphi TTypeKind byte against
    /// `reference/pythia/pythia/core/structures.py:11-34`.
    /// If a future refactor renumbers or drops a variant, this test
    /// flags it before silent misdecoding ships.
    #[test]
    fn delphi_tkkind_bytes_match_pythia() {
        let cases: &[(u8, TypeKind)] = &[
            (0, TypeKind::Unknown),
            (1, TypeKind::Integer),
            (2, TypeKind::Char),
            (3, TypeKind::Enumeration),
            (4, TypeKind::Float),
            (5, TypeKind::String),
            (6, TypeKind::Set),
            (7, TypeKind::Class),
            (8, TypeKind::Method),
            (9, TypeKind::WChar),
            (10, TypeKind::LString),
            (11, TypeKind::WString),
            (12, TypeKind::Variant),
            (13, TypeKind::Array),
            (14, TypeKind::Record),
            (15, TypeKind::Interface),
            (16, TypeKind::Int64),
            (17, TypeKind::DynArray),
            (18, TypeKind::UString),
            (19, TypeKind::ClassRef),
            (20, TypeKind::Pointer),
            (21, TypeKind::Procedure),
            (22, TypeKind::MRecord), // Delphi 10.4+; not in pythia table
        ];
        for &(byte, kind) in cases {
            assert_eq!(TypeKind::from_u8(byte), kind, "byte {byte}");
            assert_eq!(
                classify_kind_byte(byte, VmtFlavor::Delphi),
                kind,
                "byte {byte} via classify_kind_byte"
            );
        }
    }

    /// Lock the FPC TTypeKind ordering from
    /// `reference/fpc-source/rtl/inc/rttih.inc:29-34`. FPC reorders the
    /// enum vs Delphi (e.g. tkClass is 15 in FPC vs 7 in Delphi); the
    /// table below is the authoritative byte → kind translation we use
    /// when classifying FPC RTTI records.
    #[test]
    fn fpc_tkkind_bytes_match_rttih_inc() {
        let cases: &[(u8, TypeKind)] = &[
            (0, TypeKind::Unknown),
            (1, TypeKind::Integer),
            (2, TypeKind::Char),
            (3, TypeKind::Enumeration),
            (4, TypeKind::Float),
            (5, TypeKind::Set),
            (6, TypeKind::Method),
            (10, TypeKind::WString),
            (11, TypeKind::Variant),
            (13, TypeKind::Record),
            (14, TypeKind::Interface),
            (15, TypeKind::Class),
            (17, TypeKind::WChar),
            (19, TypeKind::Int64),
            (21, TypeKind::DynArray),
            (24, TypeKind::UString),
            (28, TypeKind::ClassRef),
            (29, TypeKind::Pointer),
        ];
        for &(byte, kind) in cases {
            assert_eq!(
                classify_kind_byte(byte, VmtFlavor::Fpc),
                kind,
                "FPC byte {byte}"
            );
        }
    }

    #[test]
    fn type_kind_decodes_all_documented_values() {
        assert_eq!(TypeKind::from_u8(0), TypeKind::Unknown);
        assert_eq!(TypeKind::from_u8(7), TypeKind::Class);
        assert_eq!(TypeKind::from_u8(15), TypeKind::Interface);
        assert_eq!(TypeKind::from_u8(17), TypeKind::DynArray);
        assert_eq!(TypeKind::from_u8(18), TypeKind::UString);
        assert_eq!(TypeKind::from_u8(22), TypeKind::MRecord);
        assert_eq!(TypeKind::from_u8(99), TypeKind::Unknown);
    }

    #[test]
    fn identifier_plausibility() {
        assert!(is_plausible_identifier(b"TComponent"));
        assert!(is_plausible_identifier(b"System.SysUtils"));
        assert!(is_plausible_identifier(b"Vcl.Forms"));
        assert!(is_plausible_identifier(b"TComparer<System.TPair>"));
        assert!(!is_plausible_identifier(b""));
        assert!(!is_plausible_identifier(b"hello\x00world"));
    }
}
