//! Binary DFM / FMX / LFM / XFM form stream parser (TPF0 signature).
//!
//! Delphi and FPC / Lazarus store compiled form definitions as binary
//! streams embedded as `RT_RCDATA` resources inside PE/Mach-O/ELF output.
//! The format carries the full object tree of a form: component type
//! names, component instance names, every published property, event-handler
//! name bindings, and arbitrary binary blobs (icons, pre-compiled scripts,
//! PNG/JPEG previews, small dropped files).
//!
//! ## On-disk format (authoritative source: FPC `TBinaryObjectReader`)
//!
//! File references below point at `reference/fpc-source/rtl/objpas/classes/reader.inc`
//! and `.../classesh.inc:1690-1693` (the `TValueType` enum declaration).
//!
//! ```text
//! stream := "TPF0"  object*
//!
//! object := prefix?  class_name  object_name  properties  children
//!
//! prefix  := (byte with high nibble == 0xF0) [+ child-position int if ffChildPos set]
//!
//! class_name   := ShortString
//! object_name  := ShortString
//! properties   := (prop)* terminated by empty property-name ShortString
//! children     := (object)* terminated by empty class-name ShortString
//!
//! prop := prop_name:ShortString  value_type:u8  value
//!
//! value depends on value_type — see [`TValueType`] below.
//! ```
//!
//! ShortString means one length byte followed by `length` bytes. Length 0
//! means the empty string, which is the terminator for property and child
//! lists.
//!
//! ## Allocation
//!
//! Every `&[u8]` held by the returned types is a slice into the caller's
//! resource buffer. Names, string literals, and embedded binary blobs
//! never get copied — the parser only allocates the result `Vec`s and
//! the recursive `DfmObject` tree itself.

use core::str;

/// TPF0 signature (first four bytes of every binary DFM/FMX/LFM/XFM stream).
pub const TPF0_MAGIC: &[u8; 4] = b"TPF0";

/// TPF1 — newer variant carrying unit-qualified class names (`UnitName.ClassName`).
pub const TPF1_MAGIC: &[u8; 4] = b"TPF1";

/// Binary stream-filer value types — verbatim from FPC
/// `rtl/objpas/classes/classesh.inc:1690-1693`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum ValueType {
    /// `0` — null value / list terminator / property-name terminator.
    Null = 0,
    /// `1` — nested list. Subsequent values until a `vaNull` byte.
    List = 1,
    /// `2` — signed 8-bit integer.
    Int8 = 2,
    /// `3` — signed 16-bit integer.
    Int16 = 3,
    /// `4` — signed 32-bit integer.
    Int32 = 4,
    /// `5` — 10-byte Extended float.
    Extended = 5,
    /// `6` — ShortString (byte length + body).
    String = 6,
    /// `7` — identifier (same on-disk shape as `String`).
    Ident = 7,
    /// `8` — boolean false (0 bytes).
    False = 8,
    /// `9` — boolean true (0 bytes).
    True = 9,
    /// `10` — binary blob (`u32` length + bytes).
    Binary = 10,
    /// `11` — set (sequence of identifier ShortStrings terminated by an empty one).
    Set = 11,
    /// `12` — `AnsiString` literal (`u32` length + bytes).
    LString = 12,
    /// `13` — `nil` sentinel (0 bytes).
    Nil = 13,
    /// `14` — collection (sequence of property lists terminated by `vaNull`).
    Collection = 14,
    /// `15` — 4-byte `Single` float.
    Single = 15,
    /// `16` — 8-byte `Currency` (Int64 × 10_000).
    Currency = 16,
    /// `17` — 8-byte `TDateTime` (double-precision float).
    Date = 17,
    /// `18` — `WideString` (`u32` length + `length × 2` UTF-16 bytes).
    WString = 18,
    /// `19` — signed 64-bit integer.
    Int64 = 19,
    /// `20` — UTF-8 string (`u32` length + bytes).
    Utf8String = 20,
    /// `21` — `UnicodeString` (`u32` length + `length × 2` UTF-16 bytes).
    UString = 21,
    /// `22` — unsigned 64-bit integer.
    QWord = 22,
    /// `23` — 8-byte `Double`.
    Double = 23,
    /// Any byte outside the documented range — graceful fallback instead of panic.
    Unknown = 0xff,
}

impl ValueType {
    /// Decode a raw byte, returning `Unknown` for unrecognised values.
    pub fn from_u8(b: u8) -> Self {
        match b {
            0 => ValueType::Null,
            1 => ValueType::List,
            2 => ValueType::Int8,
            3 => ValueType::Int16,
            4 => ValueType::Int32,
            5 => ValueType::Extended,
            6 => ValueType::String,
            7 => ValueType::Ident,
            8 => ValueType::False,
            9 => ValueType::True,
            10 => ValueType::Binary,
            11 => ValueType::Set,
            12 => ValueType::LString,
            13 => ValueType::Nil,
            14 => ValueType::Collection,
            15 => ValueType::Single,
            16 => ValueType::Currency,
            17 => ValueType::Date,
            18 => ValueType::WString,
            19 => ValueType::Int64,
            20 => ValueType::Utf8String,
            21 => ValueType::UString,
            22 => ValueType::QWord,
            23 => ValueType::Double,
            _ => ValueType::Unknown,
        }
    }
}

/// Filer flags carried by the optional component prefix byte.
///
/// Source: FPC `TFilerFlag` in `classesh.inc:1695-1696`.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct FilerFlags {
    /// Component inherits from an ancestor form.
    pub inherited_: bool,
    /// Component has a child-position integer appended.
    pub child_pos: bool,
    /// Component is a DFM inline (sub-form).
    pub inline_: bool,
}

impl FilerFlags {
    fn from_low_nibble(nibble: u8) -> Self {
        Self {
            inherited_: (nibble & 0x01) != 0,
            child_pos: (nibble & 0x02) != 0,
            inline_: (nibble & 0x04) != 0,
        }
    }
}

/// A DFM object (form, frame, control, data-module, or nested component).
#[derive(Debug, Clone)]
pub struct DfmObject<'a> {
    /// Filer flags from the component prefix, if any.
    pub flags: FilerFlags,
    /// Optional child position integer when `flags.child_pos` is set.
    pub child_pos: Option<i32>,
    /// Class name without any `.`-prefix unit qualification (e.g. `TButton`).
    pub class_name: &'a [u8],
    /// Optional unit-name prefix if the file is TPF1 (e.g. `Vcl.StdCtrls`).
    pub unit_name: Option<&'a [u8]>,
    /// Instance name (e.g. `Button1`). May be empty.
    pub object_name: &'a [u8],
    /// Published properties in declaration order.
    pub properties: Vec<DfmProperty<'a>>,
    /// Nested child components in declaration order.
    pub children: Vec<DfmObject<'a>>,
}

impl<'a> DfmObject<'a> {
    /// Class name as `&str` (falls back to `"<non-ascii>"` for odd bytes).
    pub fn class_name_str(&self) -> &'a str {
        str::from_utf8(self.class_name).unwrap_or("<non-ascii>")
    }
    /// Instance name as `&str`.
    pub fn object_name_str(&self) -> &'a str {
        str::from_utf8(self.object_name).unwrap_or("<non-ascii>")
    }
    /// Total component count in this sub-tree (including the root).
    pub fn component_count(&self) -> usize {
        1 + self
            .children
            .iter()
            .map(DfmObject::component_count)
            .sum::<usize>()
    }
    /// Depth-first iterator over every descendant including self.
    pub fn walk(&'a self) -> DfmWalk<'a> {
        DfmWalk { stack: vec![self] }
    }
}

/// A single property in a DFM stream.
#[derive(Debug, Clone)]
pub struct DfmProperty<'a> {
    /// Property name (e.g. `Caption`).
    pub name: &'a [u8],
    /// Decoded value.
    pub value: DfmValue<'a>,
}

impl<'a> DfmProperty<'a> {
    /// Name as `&str`.
    pub fn name_str(&self) -> &'a str {
        str::from_utf8(self.name).unwrap_or("<non-ascii>")
    }
}

/// Decoded value of a DFM property.
#[derive(Debug, Clone)]
pub enum DfmValue<'a> {
    /// `vaNull` — no value.
    Null,
    /// `vaNil` — nil pointer sentinel.
    Nil,
    /// `vaFalse` / `vaTrue`.
    Bool(bool),
    /// `vaInt8` / `vaInt16` / `vaInt32` collapsed to `i32` (preserving sign).
    Int(i32),
    /// `vaInt64`.
    Int64(i64),
    /// `vaQWord`.
    UInt64(u64),
    /// `vaSingle`.
    Single(f32),
    /// `vaDouble` / `vaDate` (both are 8-byte doubles).
    Double(f64),
    /// `vaExtended` — 10-byte Intel extended. Stored as raw bytes; decoding
    /// to `f64` would lose precision.
    Extended([u8; 10]),
    /// `vaCurrency` — `Int64` scaled by 10 000.
    Currency(i64),
    /// `vaString` / `vaIdent` / `vaLString` / `vaUtf8String` — byte slice
    /// into the buffer.
    String(&'a [u8]),
    /// `vaWString` / `vaUString` — raw UTF-16LE bytes (2-byte units), caller
    /// can decode if needed.
    Utf16(&'a [u8]),
    /// `vaBinary` — arbitrary bytes.
    Binary(&'a [u8]),
    /// `vaSet` — a set represented as the enabled identifier names.
    Set(Vec<&'a [u8]>),
    /// `vaList` — list of values.
    List(Vec<DfmValue<'a>>),
    /// `vaCollection` — list of property-bag items, each a `Vec<DfmProperty>`.
    Collection(Vec<Vec<DfmProperty<'a>>>),
    /// Unknown tag byte — no further bytes are consumed; recorded for diagnostics.
    Unknown {
        /// Raw tag byte.
        tag: u8,
        /// Best-effort empty slice (no data consumed when tag is unknown).
        body: &'a [u8],
    },
}

/// Depth-first walker over a parsed DFM tree.
#[derive(Debug)]
pub struct DfmWalk<'a> {
    stack: Vec<&'a DfmObject<'a>>,
}

impl<'a> Iterator for DfmWalk<'a> {
    type Item = &'a DfmObject<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        let obj = self.stack.pop()?;
        // Push children in reverse so the first child is visited first.
        for c in obj.children.iter().rev() {
            self.stack.push(c);
        }
        Some(obj)
    }
}

/// Parse a TPF0 / TPF1 stream.
///
/// Returns the root object when the stream parses cleanly. Returns `None`
/// for malformed streams (truncation, unexpected tag byte in a structural
/// slot). Stream versions other than TPF0/TPF1 return `None`.
pub fn parse(stream: &[u8]) -> Option<DfmObject<'_>> {
    if stream.len() < 4 {
        return None;
    }
    let magic = &stream[..4];
    let version_is_1 = match magic {
        b if b == TPF0_MAGIC => false,
        b if b == TPF1_MAGIC => true,
        _ => return None,
    };
    let mut cur = Cursor::new(stream, 4);
    read_object(&mut cur, version_is_1)
}

/// Same as [`parse`], but accepts a stream missing the TPF0/TPF1 magic.
/// Useful for feeding the parser data you've already identified by other
/// means.
pub fn parse_body(body: &[u8], version_is_1: bool) -> Option<DfmObject<'_>> {
    let mut cur = Cursor::new(body, 0);
    read_object(&mut cur, version_is_1)
}

struct Cursor<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Cursor<'a> {
    fn new(buf: &'a [u8], pos: usize) -> Self {
        Self { buf, pos }
    }

    fn read_u8(&mut self) -> Option<u8> {
        let b = *self.buf.get(self.pos)?;
        self.pos += 1;
        Some(b)
    }

    fn peek_u8(&self) -> Option<u8> {
        self.buf.get(self.pos).copied()
    }

    fn read_u16(&mut self) -> Option<u16> {
        let slice = self.buf.get(self.pos..self.pos + 2)?;
        self.pos += 2;
        Some(u16::from_le_bytes(slice.try_into().ok()?))
    }

    fn read_u32(&mut self) -> Option<u32> {
        let slice = self.buf.get(self.pos..self.pos + 4)?;
        self.pos += 4;
        Some(u32::from_le_bytes(slice.try_into().ok()?))
    }

    fn read_i32(&mut self) -> Option<i32> {
        self.read_u32().map(|v| v as i32)
    }

    fn read_i64(&mut self) -> Option<i64> {
        let slice = self.buf.get(self.pos..self.pos + 8)?;
        self.pos += 8;
        Some(i64::from_le_bytes(slice.try_into().ok()?))
    }

    fn read_u64(&mut self) -> Option<u64> {
        let slice = self.buf.get(self.pos..self.pos + 8)?;
        self.pos += 8;
        Some(u64::from_le_bytes(slice.try_into().ok()?))
    }

    fn read_f32(&mut self) -> Option<f32> {
        self.read_u32().map(f32::from_bits)
    }

    fn read_f64(&mut self) -> Option<f64> {
        self.read_u64().map(f64::from_bits)
    }

    /// Read a ShortString (byte length + body). Returns an empty slice for
    /// length 0.
    fn read_short_string(&mut self) -> Option<&'a [u8]> {
        let len = self.read_u8()? as usize;
        let slice = self.buf.get(self.pos..self.pos + len)?;
        self.pos += len;
        Some(slice)
    }

    fn read_bytes(&mut self, n: usize) -> Option<&'a [u8]> {
        let slice = self.buf.get(self.pos..self.pos + n)?;
        self.pos += n;
        Some(slice)
    }
}

fn read_object<'a>(cur: &mut Cursor<'a>, version_is_1: bool) -> Option<DfmObject<'a>> {
    // Optional prefix byte with high nibble == 0xF0.
    let mut flags = FilerFlags::default();
    let mut child_pos: Option<i32> = None;
    if let Some(b) = cur.peek_u8()
        && (b & 0xF0) == 0xF0
    {
        cur.read_u8();
        flags = FilerFlags::from_low_nibble(b & 0x0F);
        if flags.child_pos {
            // Position carried as a tagged value (vaInt8/16/32).
            let vt = cur.read_u8()?;
            let pos = match ValueType::from_u8(vt) {
                ValueType::Int8 => cur.read_u8()? as i8 as i32,
                ValueType::Int16 => cur.read_u16()? as i16 as i32,
                ValueType::Int32 => cur.read_i32()?,
                _ => return None,
            };
            child_pos = Some(pos);
        }
    }

    // ClassName, optionally unit-qualified in TPF1 (we split on the last '.').
    let raw_class = cur.read_short_string()?;
    if raw_class.is_empty() {
        // Empty class name marks end-of-children to the caller.
        return None;
    }
    let (unit_name, class_name) =
        if version_is_1 && let Some(pos) = raw_class.iter().rposition(|&b| b == b'.') {
            (Some(&raw_class[..pos]), &raw_class[pos + 1..])
        } else {
            (None, raw_class)
        };

    let object_name = cur.read_short_string()?;

    let properties = read_properties(cur)?;
    let children = read_children(cur, version_is_1)?;

    Some(DfmObject {
        flags,
        child_pos,
        class_name,
        unit_name,
        object_name,
        properties,
        children,
    })
}

fn read_properties<'a>(cur: &mut Cursor<'a>) -> Option<Vec<DfmProperty<'a>>> {
    let mut out = Vec::new();
    loop {
        let name = cur.read_short_string()?;
        if name.is_empty() {
            break;
        }
        let value = read_value(cur)?;
        out.push(DfmProperty { name, value });
    }
    Some(out)
}

fn read_children<'a>(cur: &mut Cursor<'a>, version_is_1: bool) -> Option<Vec<DfmObject<'a>>> {
    let mut out = Vec::new();
    loop {
        // Peek to detect the empty-class-name terminator. Because children may
        // carry a prefix byte, we look at the next thing the child reader
        // would see — a prefix, or a ShortString length.
        //
        // The cleanest termination rule: if the next byte is 0, it's an
        // empty ShortString that terminates the child list. Consume it.
        match cur.peek_u8() {
            Some(0) => {
                cur.read_u8();
                break;
            }
            None => return None, // truncated stream
            _ => {}
        }
        let child = read_object(cur, version_is_1)?;
        out.push(child);
    }
    Some(out)
}

fn read_value<'a>(cur: &mut Cursor<'a>) -> Option<DfmValue<'a>> {
    let tag = cur.read_u8()?;
    Some(match ValueType::from_u8(tag) {
        ValueType::Null => DfmValue::Null,
        ValueType::Nil => DfmValue::Nil,
        ValueType::False => DfmValue::Bool(false),
        ValueType::True => DfmValue::Bool(true),
        ValueType::Int8 => DfmValue::Int(cur.read_u8()? as i8 as i32),
        ValueType::Int16 => DfmValue::Int(cur.read_u16()? as i16 as i32),
        ValueType::Int32 => DfmValue::Int(cur.read_i32()?),
        ValueType::Int64 => DfmValue::Int64(cur.read_i64()?),
        ValueType::QWord => DfmValue::UInt64(cur.read_u64()?),
        ValueType::Single => DfmValue::Single(cur.read_f32()?),
        ValueType::Double | ValueType::Date => DfmValue::Double(cur.read_f64()?),
        ValueType::Currency => DfmValue::Currency(cur.read_i64()?),
        ValueType::Extended => {
            let bytes = cur.read_bytes(10)?;
            let mut buf = [0u8; 10];
            buf.copy_from_slice(bytes);
            DfmValue::Extended(buf)
        }
        ValueType::String | ValueType::Ident => DfmValue::String(cur.read_short_string()?),
        ValueType::LString | ValueType::Utf8String => {
            let len = cur.read_u32()? as usize;
            DfmValue::String(cur.read_bytes(len)?)
        }
        ValueType::WString | ValueType::UString => {
            // `length` is a character count; bytes = 2 × count.
            let count = cur.read_u32()? as usize;
            DfmValue::Utf16(cur.read_bytes(count.checked_mul(2)?)?)
        }
        ValueType::Binary => {
            let len = cur.read_u32()? as usize;
            DfmValue::Binary(cur.read_bytes(len)?)
        }
        ValueType::Set => {
            let mut items = Vec::new();
            loop {
                let s = cur.read_short_string()?;
                if s.is_empty() {
                    break;
                }
                items.push(s);
            }
            DfmValue::Set(items)
        }
        ValueType::List => {
            let mut items = Vec::new();
            loop {
                if cur.peek_u8()? == 0 {
                    cur.read_u8();
                    break;
                }
                items.push(read_value(cur)?);
            }
            DfmValue::List(items)
        }
        ValueType::Collection => {
            // Per FPC `writer.inc:618-635` (TWriter.WriteCollection): each
            // item is wrapped `WriteListBegin (vaList=1) … WriteListEnd
            // (vaNull=0)`, and the whole collection ends with a final
            // `WriteListEnd`. FPC `reader.inc:548-560` also allows an
            // optional `vaInt{8,16,32}` order prefix BEFORE the `vaList`
            // for positioned items. The grammar is therefore:
            //
            //   collection := value_tag(vaCollection=14)
            //                 item*
            //                 vaNull
            //   item       := order_int? vaList=1 property* vaNull
            //
            // The terminating `vaNull` of each item doubles as the empty
            // property-name terminator consumed by `read_properties`.
            let mut items = Vec::new();
            loop {
                match cur.peek_u8()? {
                    0 => {
                        cur.read_u8();
                        break;
                    }
                    b => {
                        // Optional leading order integer.
                        let vt = ValueType::from_u8(b);
                        if matches!(vt, ValueType::Int8 | ValueType::Int16 | ValueType::Int32) {
                            cur.read_u8();
                            match vt {
                                ValueType::Int8 => {
                                    cur.read_u8()?;
                                }
                                ValueType::Int16 => {
                                    cur.read_u16()?;
                                }
                                ValueType::Int32 => {
                                    cur.read_i32()?;
                                }
                                _ => {}
                            }
                        }
                        // Each item starts with a `vaList` (tag byte 1).
                        // Without consuming it we would treat that byte as
                        // the first property-name length and misalign the
                        // rest of the stream.
                        let list_tag = cur.read_u8()?;
                        if list_tag != ValueType::List as u8 {
                            return None;
                        }
                        items.push(read_properties(cur)?);
                    }
                }
            }
            DfmValue::Collection(items)
        }
        ValueType::Unknown => DfmValue::Unknown { tag, body: &[] },
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn build_min_stream() -> Vec<u8> {
        // Construct a minimal TPF0 stream:
        //   "TPF0" | TButton\0Button1\0 | Caption:vaString 'Hi' | end-of-props |
        //   (no children) | end-of-children (the 0 byte)
        let mut s = Vec::new();
        s.extend_from_slice(b"TPF0");
        // ClassName
        s.push(7);
        s.extend_from_slice(b"TButton");
        // ObjectName
        s.push(7);
        s.extend_from_slice(b"Button1");
        // Property name
        s.push(7);
        s.extend_from_slice(b"Caption");
        s.push(ValueType::String as u8);
        s.push(2);
        s.extend_from_slice(b"Hi");
        // Terminate property list
        s.push(0);
        // No children: zero byte terminates children list.
        s.push(0);
        s
    }

    #[test]
    fn parses_trivial_stream() {
        let stream = build_min_stream();
        let obj = parse(&stream).expect("should parse");
        assert_eq!(obj.class_name, b"TButton");
        assert_eq!(obj.object_name, b"Button1");
        assert_eq!(obj.properties.len(), 1);
        assert_eq!(obj.properties[0].name, b"Caption");
        match &obj.properties[0].value {
            DfmValue::String(s) => assert_eq!(*s, b"Hi"),
            other => panic!("expected string value, got {other:?}"),
        }
        assert!(obj.children.is_empty());
    }

    /// Regression: TPF0 Collection properties wrap each item in
    /// `vaList … vaNull` per FPC writer.inc:618-635. We used to skip the
    /// `vaList` byte, which caused the parser to misalign on the next item
    /// and return `None` for real-world forms containing
    /// `TVirtualStringTree.Columns`, `TStatusBar.Panels`, etc.
    #[test]
    fn parses_collection_with_va_list_item_wrapper() {
        let mut s = Vec::new();
        s.extend_from_slice(b"TPF0");
        // Root: TForm F, one property `Panels` (Collection), no children.
        s.push(5);
        s.extend_from_slice(b"TForm");
        s.push(1);
        s.extend_from_slice(b"F");

        // Property name: Panels
        s.push(6);
        s.extend_from_slice(b"Panels");
        s.push(ValueType::Collection as u8);

        // Item 1: vaList + props { Width = Int8 10 } + vaNull
        s.push(ValueType::List as u8);
        s.push(5);
        s.extend_from_slice(b"Width");
        s.push(ValueType::Int8 as u8);
        s.push(10);
        s.push(0); // empty prop name terminates item 1

        // Item 2: vaList + props { Caption = String 'hi' } + vaNull
        s.push(ValueType::List as u8);
        s.push(7);
        s.extend_from_slice(b"Caption");
        s.push(ValueType::String as u8);
        s.push(2);
        s.extend_from_slice(b"hi");
        s.push(0); // empty prop name terminates item 2

        s.push(0); // outer vaNull — ends the collection

        s.push(0); // end of root props
        s.push(0); // end of root children

        let obj = parse(&s).expect("collection with vaList items should parse");
        assert_eq!(obj.properties.len(), 1);
        assert_eq!(obj.properties[0].name, b"Panels");
        let items = match &obj.properties[0].value {
            DfmValue::Collection(v) => v,
            other => panic!("expected Collection, got {other:?}"),
        };
        assert_eq!(items.len(), 2);
        assert_eq!(items[0][0].name, b"Width");
        assert!(matches!(items[0][0].value, DfmValue::Int(10)));
        assert_eq!(items[1][0].name, b"Caption");
        assert!(matches!(items[1][0].value, DfmValue::String(b"hi")));
    }

    #[test]
    fn collection_without_va_list_wrapper_is_rejected() {
        // A stream that omits the `vaList` byte before item properties is
        // malformed and must not silently parse (otherwise we would misalign
        // the rest of the stream and produce garbage).
        let mut s = Vec::new();
        s.extend_from_slice(b"TPF0");
        s.push(1);
        s.extend_from_slice(b"C");
        s.push(1);
        s.extend_from_slice(b"c");
        s.push(1);
        s.extend_from_slice(b"P");
        s.push(ValueType::Collection as u8);
        // Missing vaList here — go straight into a property
        s.push(5);
        s.extend_from_slice(b"Width");
        s.push(ValueType::Int8 as u8);
        s.push(1);
        s.push(0);
        s.push(0);
        s.push(0);
        s.push(0);
        assert!(parse(&s).is_none());
    }

    #[test]
    fn parses_nested_child() {
        // Same as build_min_stream, but with one child TEdit inside.
        let mut s = Vec::new();
        s.extend_from_slice(b"TPF0");
        // Root: TForm Form1, no props
        s.push(5);
        s.extend_from_slice(b"TForm");
        s.push(5);
        s.extend_from_slice(b"Form1");
        s.push(0); // end of props

        // Child: TEdit Edit1, prop Text:'x'
        s.push(5);
        s.extend_from_slice(b"TEdit");
        s.push(5);
        s.extend_from_slice(b"Edit1");
        s.push(4);
        s.extend_from_slice(b"Text");
        s.push(ValueType::String as u8);
        s.push(1);
        s.extend_from_slice(b"x");
        s.push(0); // end of child props
        s.push(0); // end of child children

        s.push(0); // end of root children

        let obj = parse(&s).unwrap();
        assert_eq!(obj.class_name, b"TForm");
        assert_eq!(obj.children.len(), 1);
        assert_eq!(obj.children[0].class_name, b"TEdit");
        assert_eq!(obj.component_count(), 2);
        // Walk iterator exercises the DFS.
        let walked: Vec<_> = obj.walk().map(|o| o.class_name_str()).collect();
        assert_eq!(walked, vec!["TForm", "TEdit"]);
    }

    #[test]
    fn rejects_missing_magic() {
        let bytes = b"NOTDFM\0\0";
        assert!(parse(bytes).is_none());
    }

    #[test]
    fn value_type_from_u8_handles_unknowns() {
        assert_eq!(ValueType::from_u8(23), ValueType::Double);
        assert_eq!(ValueType::from_u8(255), ValueType::Unknown);
    }

    /// Lock the TPF0 `TValueType` byte ordering against the authoritative
    /// FPC declaration in
    /// `reference/fpc-source/rtl/objpas/classes/classesh.inc:1690-1693`.
    /// A drift here would silently misdecode every form stream — every
    /// component property would land on the wrong arm of `read_value`.
    #[test]
    fn value_type_bytes_match_fpc_classesh_inc() {
        let cases: &[(u8, ValueType)] = &[
            (0, ValueType::Null),
            (1, ValueType::List),
            (2, ValueType::Int8),
            (3, ValueType::Int16),
            (4, ValueType::Int32),
            (5, ValueType::Extended),
            (6, ValueType::String),
            (7, ValueType::Ident),
            (8, ValueType::False),
            (9, ValueType::True),
            (10, ValueType::Binary),
            (11, ValueType::Set),
            (12, ValueType::LString),
            (13, ValueType::Nil),
            (14, ValueType::Collection),
            (15, ValueType::Single),
            (16, ValueType::Currency),
            (17, ValueType::Date),
            (18, ValueType::WString),
            (19, ValueType::Int64),
            (20, ValueType::Utf8String),
            (21, ValueType::UString),
            (22, ValueType::QWord),
            (23, ValueType::Double),
            (24, ValueType::Unknown),
            (255, ValueType::Unknown),
        ];
        for &(byte, vt) in cases {
            assert_eq!(ValueType::from_u8(byte), vt, "byte {byte}");
        }
    }
}
