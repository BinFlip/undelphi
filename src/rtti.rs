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

use core::str;

use crate::{
    formats::{BinaryContext, BinaryFormat},
    interfaces::Guid,
    limits::{MAX_ENUM_RANGE, MAX_IDENTIFIER_BYTES, MAX_METHOD_PARAMS, MAX_RECORD_MANAGED_FIELDS},
    util::{deref_va, read_ptr, read_short_string_at_file, read_u16},
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
    pub class_name: &'a [u8],
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
    pub unit_name: &'a [u8],
    /// File offset where the `TPropData` block starts (needed by iteration
    /// 4 when walking property entries).
    pub prop_data_file_offset: usize,
}

impl<'a> TkClassInfo<'a> {
    /// Class name as `&str`, if ASCII.
    #[inline]
    pub fn class_name_str(&self) -> Option<&'a str> {
        str::from_utf8(self.class_name).ok()
    }

    /// Unit name as `&str`, if ASCII.
    #[inline]
    pub fn unit_name_str(&self) -> Option<&'a str> {
        str::from_utf8(self.unit_name).ok()
    }
}

/// Decode the `tkClass` TypeInfo record referenced by a class's VMT.
///
/// Returns `None` when `vmtTypeInfo` is null, the VA cannot be translated,
/// the Kind byte is not the `tkClass` value for this flavor, or any length
/// read fails.
pub fn tkclass_from_vmt<'a>(ctx: &BinaryContext<'a>, vmt: &Vmt<'a>) -> Option<TkClassInfo<'a>> {
    if vmt.type_info == 0 {
        return None;
    }
    decode_tkclass(ctx, vmt.type_info, vmt.pointer_size as usize, vmt.flavor)
}

/// Decode a `tkClass` TypeInfo at an arbitrary VA, given the flavor that
/// produced the binary (determines which byte value to expect for
/// `tkClass`).
pub fn decode_tkclass<'a>(
    ctx: &BinaryContext<'a>,
    type_info_va: u64,
    ptr_size: usize,
    flavor: VmtFlavor,
) -> Option<TkClassInfo<'a>> {
    let file_off = ctx.va_to_file(type_info_va)?;
    let data = ctx.data();

    let kind_byte = *data.get(file_off)?;
    if kind_byte != tkclass_byte(flavor) {
        return None;
    }
    // Always tag as Delphi's TypeKind::Class in the returned struct —
    // callers who need the raw byte use `kind_byte` directly.
    let kind = TypeKind::Class;

    let class_name = read_short_string_at_file(data, file_off + 1)?;
    let mut type_data_off = file_off + 2 + class_name.len();

    // On Mach-O and ELF targets FPC sets `FPC_REQUIRES_PROPER_ALIGNMENT`,
    // which turns off the `packed` attribute on `TTypeData`. The first
    // TypeData field is pointer-sized (`ClassType: TClass`), so it gets
    // aligned to a pointer boundary after the preceding `Name: ShortString`.
    // Windows PE (x86 and x86-64) uses packed records, so no padding.
    // Source: `reference/fpc-source/rtl/objpas/typinfo.pp:867-871`.
    if ptr_size > 1 && ctx.format() != BinaryFormat::Pe {
        let rem = type_data_off % ptr_size;
        if rem != 0 {
            type_data_off += ptr_size - rem;
        }
    }

    // TypeData for tkClass.
    let class_type_va = read_ptr(data, type_data_off, ptr_size)?;
    let parent_info_va = read_ptr(data, type_data_off + ptr_size, ptr_size)?;
    let prop_count_off = type_data_off + 2 * ptr_size;
    let prop_count = read_u16(data, prop_count_off)? as i16;
    let unit_name_off = prop_count_off + 2;
    let unit_name = read_short_string_at_file(data, unit_name_off)?;

    // Validate that the class name looks plausible (identifier-like) so we
    // don't return garbage from a misaligned TypeInfo.
    if !is_plausible_identifier(class_name) {
        return None;
    }
    if !is_plausible_identifier(unit_name) {
        return None;
    }

    let prop_data_file_offset = unit_name_off + 1 + unit_name.len();

    Some(TkClassInfo {
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
    /// Type name slice borrowed from the input.
    pub name: &'a [u8],
}

impl<'a> TypeHeader<'a> {
    /// Name as `&str`, or `"<non-ascii>"` when bytes are unusual.
    pub fn name_str(&self) -> &'a str {
        str::from_utf8(self.name).unwrap_or("<non-ascii>")
    }
}

/// Decode the type header (Kind + Name) at a `PTypeInfo` VA.
pub fn decode_type_header<'a>(
    ctx: &BinaryContext<'a>,
    type_info_va: u64,
    flavor: VmtFlavor,
) -> Option<TypeHeader<'a>> {
    if type_info_va == 0 {
        return None;
    }
    let file_off = ctx.va_to_file(type_info_va)?;
    let data = ctx.data();
    let kind_byte = *data.get(file_off)?;
    let kind = classify_kind_byte(kind_byte, flavor);
    let name = read_short_string_at_file(data, file_off + 1)?;
    if !is_plausible_identifier(name) {
        return None;
    }
    Some(TypeHeader {
        va: type_info_va,
        kind_byte,
        kind,
        name,
    })
}

/// Follow a `PPTypeInfo` (pointer-to-pointer-to-PTypeInfo) indirection and
/// return the target type header. Delphi's `PropType` field in
/// `TPropInfo` is stored as a PPTypeInfo.
pub fn decode_type_header_from_pptr<'a>(
    ctx: &BinaryContext<'a>,
    pptr_va: u64,
    ptr_size: usize,
    flavor: VmtFlavor,
) -> Option<TypeHeader<'a>> {
    let type_info_va = deref_pptypeinfo(ctx, pptr_va, ptr_size)?;
    decode_type_header(ctx, type_info_va, flavor)
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
    /// Unit name the enumeration was declared in.
    pub unit_name: Option<&'a [u8]>,
}

/// Decode a `tkEnumeration` record.
pub fn decode_tkenum<'a>(
    ctx: &BinaryContext<'a>,
    type_info_va: u64,
    flavor: VmtFlavor,
) -> Option<EnumInfo<'a>> {
    let header = decode_type_header(ctx, type_info_va, flavor)?;
    if header.kind != TypeKind::Enumeration {
        return None;
    }
    let data = ctx.data();
    let file_off = ctx.va_to_file(type_info_va)?;
    let mut cursor = file_off + 2 + header.name.len();

    // `OrdType: u8` lives at the start of the tkEnumeration TypeData.
    let ord_byte = *data.get(cursor)?;
    let ord = OrdinalType::from_u8(ord_byte);
    cursor += 1;

    let min = i32::from_le_bytes(data.get(cursor..cursor + 4)?.try_into().ok()?);
    cursor += 4;
    let max = i32::from_le_bytes(data.get(cursor..cursor + 4)?.try_into().ok()?);
    cursor += 4;
    // BaseTypePtr is a PPTypeInfo.
    let ptr_size = (ctx.pointer_size().unwrap_or(4)).min(8);
    let base_type_ref = match ptr_size {
        8 => u64::from_le_bytes(data.get(cursor..cursor + 8)?.try_into().ok()?),
        _ => u32::from_le_bytes(data.get(cursor..cursor + 4)?.try_into().ok()?) as u64,
    };
    cursor += ptr_size;

    // Plausibility: enum index range must be small.  Use i64 arithmetic
    // to avoid overflow when `min` / `max` happen to be extreme values
    // from a misaligned RTTI fragment.
    let range = (max as i64).checked_sub(min as i64).unwrap_or(i64::MAX);
    if !(0..=MAX_ENUM_RANGE).contains(&range) {
        return None;
    }
    let count = (range + 1) as usize;
    let mut values = Vec::with_capacity(count);
    for _ in 0..count {
        let name = read_short_string_at_file(data, cursor)?;
        if !is_plausible_identifier(name) {
            return None;
        }
        cursor += 1 + name.len();
        values.push(name);
    }
    // Trailing UnitName ShortString.
    let unit_name = read_short_string_at_file(data, cursor);

    Some(EnumInfo {
        header,
        ord,
        min,
        max,
        base_type_ref,
        values,
        unit_name,
    })
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
    /// Unit name.
    pub unit_name: Option<&'a [u8]>,
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
    /// Unit name.
    pub unit_name: Option<&'a [u8]>,
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

/// Dispatcher — decode whichever Kind is stored at `type_info_va`.
pub fn decode_type_detail<'a>(
    ctx: &BinaryContext<'a>,
    type_info_va: u64,
    flavor: VmtFlavor,
) -> Option<TypeDetail<'a>> {
    let header = decode_type_header(ctx, type_info_va, flavor)?;
    let ptr_size = ctx.pointer_size().unwrap_or(8);
    let detail = match header.kind {
        TypeKind::Class => TypeDetail::Class(decode_tkclass(ctx, type_info_va, ptr_size, flavor)?),
        TypeKind::Enumeration => TypeDetail::Enumeration(decode_tkenum(ctx, type_info_va, flavor)?),
        TypeKind::Integer | TypeKind::Char | TypeKind::WChar => {
            TypeDetail::Ordinal(decode_tkordinal(ctx, type_info_va, flavor)?)
        }
        TypeKind::Float => TypeDetail::Float(decode_tkfloat(ctx, type_info_va, flavor)?),
        TypeKind::Set => TypeDetail::Set(decode_tkset(ctx, type_info_va, flavor)?),
        TypeKind::ClassRef => TypeDetail::ClassRef(decode_tkclassref(ctx, type_info_va, flavor)?),
        TypeKind::DynArray => TypeDetail::DynArray(decode_tkdynarray(ctx, type_info_va, flavor)?),
        TypeKind::Interface => {
            TypeDetail::Interface(decode_tkinterface(ctx, type_info_va, flavor)?)
        }
        TypeKind::Record => TypeDetail::Record(decode_tkrecord(ctx, type_info_va, flavor)?),
        TypeKind::Method => TypeDetail::Method(decode_tkmethod(ctx, type_info_va, flavor)?),
        TypeKind::Procedure => {
            TypeDetail::Procedure(decode_tkprocedure(ctx, type_info_va, flavor)?)
        }
        TypeKind::LString | TypeKind::UString | TypeKind::WString => {
            TypeDetail::String(decode_tkstring(ctx, type_info_va, flavor)?)
        }
        _ => TypeDetail::Other(header),
    };
    Some(detail)
}

/// Decode a tkInteger / tkChar / tkWChar record.
pub fn decode_tkordinal<'a>(
    ctx: &BinaryContext<'a>,
    type_info_va: u64,
    flavor: VmtFlavor,
) -> Option<OrdinalInfo<'a>> {
    let header = decode_type_header(ctx, type_info_va, flavor)?;
    if !matches!(
        header.kind,
        TypeKind::Integer | TypeKind::Char | TypeKind::WChar
    ) {
        return None;
    }
    let data = ctx.data();
    let off = ctx.va_to_file(type_info_va)? + 2 + header.name.len();
    let ord = OrdinalType::from_u8(*data.get(off)?);
    let min = i32::from_le_bytes(data.get(off + 1..off + 5)?.try_into().ok()?);
    let max = i32::from_le_bytes(data.get(off + 5..off + 9)?.try_into().ok()?);
    Some(OrdinalInfo {
        header,
        ord,
        min,
        max,
    })
}

/// Decode a tkFloat record.
pub fn decode_tkfloat<'a>(
    ctx: &BinaryContext<'a>,
    type_info_va: u64,
    flavor: VmtFlavor,
) -> Option<FloatInfo<'a>> {
    let header = decode_type_header(ctx, type_info_va, flavor)?;
    if header.kind != TypeKind::Float {
        return None;
    }
    let data = ctx.data();
    let off = ctx.va_to_file(type_info_va)? + 2 + header.name.len();
    let float_type = FloatType::from_u8(*data.get(off)?);
    Some(FloatInfo { header, float_type })
}

/// Decode a tkSet record and resolve the element enumeration type, if
/// possible.
pub fn decode_tkset<'a>(
    ctx: &BinaryContext<'a>,
    type_info_va: u64,
    flavor: VmtFlavor,
) -> Option<SetInfo<'a>> {
    let header = decode_type_header(ctx, type_info_va, flavor)?;
    if header.kind != TypeKind::Set {
        return None;
    }
    let data = ctx.data();
    let ptr_size = ctx.pointer_size().unwrap_or(8);
    // tkSet TypeData = { OrdType:u8, CompType:PPTypeInfo, [Name:ShortString for modern] }.
    // We only need the CompType pointer; skip the ordinal byte.
    let off = ctx.va_to_file(type_info_va)? + 2 + header.name.len() + 1;
    let comp_type_ref = read_ptr(data, off, ptr_size)?;
    let element_type = decode_type_header_from_pptr(ctx, comp_type_ref, ptr_size, flavor);
    Some(SetInfo {
        header,
        comp_type_ref,
        element_type,
    })
}

/// Decode a tkClassRef record.
pub fn decode_tkclassref<'a>(
    ctx: &BinaryContext<'a>,
    type_info_va: u64,
    flavor: VmtFlavor,
) -> Option<ClassRefInfo<'a>> {
    let header = decode_type_header(ctx, type_info_va, flavor)?;
    if header.kind != TypeKind::ClassRef {
        return None;
    }
    let data = ctx.data();
    let ptr_size = ctx.pointer_size().unwrap_or(8);
    let off = ctx.va_to_file(type_info_va)? + 2 + header.name.len();
    let instance_type_ref = read_ptr(data, off, ptr_size)?;
    let instance_type = decode_type_header_from_pptr(ctx, instance_type_ref, ptr_size, flavor);
    Some(ClassRefInfo {
        header,
        instance_type_ref,
        instance_type,
    })
}

/// Decode a tkDynArray record.
pub fn decode_tkdynarray<'a>(
    ctx: &BinaryContext<'a>,
    type_info_va: u64,
    flavor: VmtFlavor,
) -> Option<DynArrayInfo<'a>> {
    let header = decode_type_header(ctx, type_info_va, flavor)?;
    if header.kind != TypeKind::DynArray {
        return None;
    }
    let data = ctx.data();
    let ptr_size = ctx.pointer_size().unwrap_or(8);
    let mut off = ctx.va_to_file(type_info_va)? + 2 + header.name.len();
    let elem_size = i32::from_le_bytes(data.get(off..off + 4)?.try_into().ok()?) as u32;
    off += 4;
    let elem_type_ref_managed = read_ptr(data, off, ptr_size)?;
    off += ptr_size;
    // VarType index skipped.
    off += 4;
    let elem_type_ref_any = read_ptr(data, off, ptr_size)?;
    off += ptr_size;
    let unit_name = read_short_string_at_file(data, off);
    // Pick whichever pointer resolves — elem_type_ref_any is emitted on
    // modern Delphi/FPC even for non-managed elements; the managed
    // variant can be null.
    let element_type = if elem_type_ref_any != 0 {
        decode_type_header_from_pptr(ctx, elem_type_ref_any, ptr_size, flavor)
    } else {
        decode_type_header_from_pptr(ctx, elem_type_ref_managed, ptr_size, flavor)
    };
    Some(DynArrayInfo {
        header,
        elem_size,
        elem_type_ref_managed,
        elem_type_ref_any,
        element_type,
        unit_name,
    })
}

/// Decode a tkInterface record.
pub fn decode_tkinterface<'a>(
    ctx: &BinaryContext<'a>,
    type_info_va: u64,
    flavor: VmtFlavor,
) -> Option<InterfaceTypeInfo<'a>> {
    let header = decode_type_header(ctx, type_info_va, flavor)?;
    if header.kind != TypeKind::Interface {
        return None;
    }
    let data = ctx.data();
    let ptr_size = ctx.pointer_size().unwrap_or(8);
    let mut off = ctx.va_to_file(type_info_va)? + 2 + header.name.len();
    let parent_ref = read_ptr(data, off, ptr_size)?;
    off += ptr_size;
    let flags = *data.get(off)?;
    off += 1;
    let guid_bytes: [u8; 16] = data.get(off..off + 16)?.try_into().ok()?;
    let guid = Guid::from_bytes(&guid_bytes);
    off += 16;
    let unit_name = read_short_string_at_file(data, off);
    let parent_type = decode_type_header_from_pptr(ctx, parent_ref, ptr_size, flavor);
    Some(InterfaceTypeInfo {
        header,
        parent_ref,
        parent_type,
        flags,
        guid,
        unit_name,
    })
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
    /// Parameter name; borrows from the input.
    pub name: &'a [u8],
    /// Parameter type name; borrows from the input. Unlike class RTTI,
    /// method RTTI stores the parameter's type as a textual identifier
    /// rather than a PPTypeInfo.
    pub type_name: &'a [u8],
}

impl<'a> MethodParam<'a> {
    /// Name as `&str`.
    pub fn name_str(&self) -> &'a str {
        str::from_utf8(self.name).unwrap_or("<non-ascii>")
    }
    /// Type name as `&str`.
    pub fn type_name_str(&self) -> &'a str {
        str::from_utf8(self.type_name).unwrap_or("<non-ascii>")
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

/// Decode a tkMethod record.
pub fn decode_tkmethod<'a>(
    ctx: &BinaryContext<'a>,
    type_info_va: u64,
    flavor: VmtFlavor,
) -> Option<MethodInfo<'a>> {
    let header = decode_type_header(ctx, type_info_va, flavor)?;
    if header.kind != TypeKind::Method {
        return None;
    }
    let data = ctx.data();
    let mut cursor = ctx.va_to_file(type_info_va)? + 2 + header.name.len();
    let kind = MethodKind::from_u8(*data.get(cursor)?);
    cursor += 1;
    let num_params = *data.get(cursor)? as usize;
    cursor += 1;
    if num_params > MAX_METHOD_PARAMS {
        return None;
    }
    let mut params = Vec::with_capacity(num_params);
    for _ in 0..num_params {
        let flags = *data.get(cursor)?;
        cursor += 1;
        let name = read_short_string_at_file(data, cursor)?;
        cursor += 1 + name.len();
        let type_name = read_short_string_at_file(data, cursor)?;
        cursor += 1 + type_name.len();
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
    Some(MethodInfo {
        header,
        kind,
        params,
        result_type,
    })
}

/// Decode a tkProcedure record. Modern-RTTI-only — older binaries emit
/// just the header with no parameter info.
pub fn decode_tkprocedure<'a>(
    ctx: &BinaryContext<'a>,
    type_info_va: u64,
    flavor: VmtFlavor,
) -> Option<ProcedureInfo<'a>> {
    let header = decode_type_header(ctx, type_info_va, flavor)?;
    if header.kind != TypeKind::Procedure {
        return None;
    }
    Some(ProcedureInfo { header })
}

/// Decode a tkLString / tkUString / tkWString record to recover the code page.
pub fn decode_tkstring<'a>(
    ctx: &BinaryContext<'a>,
    type_info_va: u64,
    flavor: VmtFlavor,
) -> Option<StringInfo<'a>> {
    let header = decode_type_header(ctx, type_info_va, flavor)?;
    if !matches!(
        header.kind,
        TypeKind::LString | TypeKind::UString | TypeKind::WString
    ) {
        return None;
    }
    let data = ctx.data();
    let off = ctx.va_to_file(type_info_va)? + 2 + header.name.len();
    // Pythia records 6 unknown bytes before the code page; empirically on
    // modern Delphi the bytes are (u16 elem-size, 4 reserved) but we only
    // need the code-page. Read `u16` at +6.
    let code_page_off = off + 6;
    let code_page = data
        .get(code_page_off..code_page_off + 2)
        .and_then(|s| <[u8; 2]>::try_from(s).ok())
        .map(u16::from_le_bytes)
        .unwrap_or(0);
    Some(StringInfo { header, code_page })
}

/// Decode a tkRecord record including its managed-field entries.
///
/// Accepts records with an empty on-disk name — the compiler emits
/// `vmtInitTable` as a synthetic tkRecord with no name whose sole purpose
/// is to enumerate the host class's managed fields. `decode_type_header`
/// rejects empty names, so we read the header directly here.
pub fn decode_tkrecord<'a>(
    ctx: &BinaryContext<'a>,
    type_info_va: u64,
    flavor: VmtFlavor,
) -> Option<RecordInfo<'a>> {
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
    let name = read_short_string_at_file(data, file_off + 1)?;
    let header = TypeHeader {
        va: type_info_va,
        kind_byte,
        kind: TypeKind::Record,
        name,
    };
    let ptr_size = ctx.pointer_size().unwrap_or(8);
    let mut off = file_off + 2 + name.len();
    let record_size = i32::from_le_bytes(data.get(off..off + 4)?.try_into().ok()?) as u32;
    off += 4;
    let num_managed = i32::from_le_bytes(data.get(off..off + 4)?.try_into().ok()?) as usize;
    off += 4;
    if num_managed > MAX_RECORD_MANAGED_FIELDS {
        return None;
    }
    let mut managed_fields = Vec::with_capacity(num_managed);
    for _ in 0..num_managed {
        let type_ref = read_ptr(data, off, ptr_size)?;
        off += ptr_size;
        let offset = read_ptr(data, off, ptr_size)?;
        off += ptr_size;
        let field_type = decode_type_header_from_pptr(ctx, type_ref, ptr_size, flavor);
        managed_fields.push(RecordManagedField {
            type_ref,
            offset,
            field_type,
        });
    }
    Some(RecordInfo {
        header,
        record_size,
        managed_fields,
    })
}

/// Dereference a `PPTypeInfo` VA once, returning the TypeInfo VA it points
/// at. Returns `None` when either VA is null or unmapped.
pub fn deref_pptypeinfo(ctx: &BinaryContext<'_>, pp_va: u64, ptr_size: usize) -> Option<u64> {
    deref_va(ctx, pp_va, ptr_size)
}

/// Look up a [`TkClassInfo`] by resolving a `ParentInfo` (PPTypeInfo) value.
pub fn tkclass_from_parent_info<'a>(
    ctx: &BinaryContext<'a>,
    parent_info_va: u64,
    ptr_size: usize,
    flavor: VmtFlavor,
) -> Option<TkClassInfo<'a>> {
    let type_info_va = deref_pptypeinfo(ctx, parent_info_va, ptr_size)?;
    decode_tkclass(ctx, type_info_va, ptr_size, flavor)
}

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
