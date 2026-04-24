//! Pretty-print DFM property values against their declared types.
//!
//! By itself, [`crate::dfm::DfmValue`] captures the raw on-disk
//! representation — `Int(2)` for `Align = alBottom`, `Int(7)` for
//! `BorderIcons = [biSystemMenu, biMinimize, biMaximize, biHelp]`. To
//! render those values symbolically we need to cross-reference the
//! declared property type from RTTI. This module provides a small helper
//! that, given a resolved `TypeDetail`, returns a human-readable string
//! for a `DfmValue`.
//!
//! All string construction allocates. Callers that need to avoid
//! allocation can use the `DfmValue` fields directly — this helper is
//! for presentation only.

use crate::{
    dfm::DfmValue,
    rtti::{EnumInfo, TypeDetail, TypeHeader},
};

/// Pretty-print a DFM value, using the declared type to resolve
/// enumeration ordinals and set bitmaps into their symbolic names.
///
/// `detail` is the resolved property type — typically from
/// `DelphiBinary::property_type_detail`. When `detail` is `None` or the
/// type doesn't meaningfully refine the value, the returned string is the
/// same as a plain `Debug` render of `value`.
pub fn render_value(value: &DfmValue<'_>, detail: Option<&TypeDetail<'_>>) -> String {
    match (value, detail) {
        // Int value + Enumeration type → resolve to element name(s).
        (DfmValue::Int(i), Some(TypeDetail::Enumeration(e))) => render_enum_ordinal(*i, e),

        // Int value + Set type. We have the element-type header from RTTI but
        // not the resolved EnumInfo, so we fall back to a hex bitmap. Callers
        // that have already decoded the element enum should use
        // [`render_set_mask_with_enum`] directly.
        (DfmValue::Int(mask), Some(TypeDetail::Set(_))) => format!("set:0x{:x}", *mask as u32),

        // Set-of-identifiers value (already names, but prettier rendering).
        (DfmValue::Set(items), _) => {
            let parts: Vec<_> = items
                .iter()
                .map(|b| String::from_utf8_lossy(b).into_owned())
                .collect();
            format!("[{}]", parts.join(", "))
        }

        // List → recurse per element.
        (DfmValue::List(items), _) => {
            let parts: Vec<_> = items.iter().map(|v| render_value(v, None)).collect();
            format!("({})", parts.join(", "))
        }

        _ => default_render(value),
    }
}

/// Produce just an enumeration value name for an ordinal, or fall back to
/// a numeric rendering if out of range.
pub fn render_enum_ordinal(i: i32, info: &EnumInfo<'_>) -> String {
    if i >= info.min && i <= info.max {
        let idx = (i - info.min) as usize;
        if let Some(name) = info.values.get(idx) {
            return String::from_utf8_lossy(name).into_owned();
        }
    }
    format!("{} (out-of-range for {}..{})", i, info.min, info.max)
}

/// Render a set value whose element enumeration has already been decoded.
pub fn render_set_mask_with_enum(mask: u32, enum_info: &EnumInfo<'_>) -> String {
    let mut names = Vec::new();
    for ord in 0..=31 {
        if (mask >> ord) & 1 == 1 && ord >= enum_info.min && ord <= enum_info.max {
            let idx = (ord - enum_info.min) as usize;
            if let Some(n) = enum_info.values.get(idx) {
                names.push(String::from_utf8_lossy(n).into_owned());
            }
        }
    }
    if names.is_empty() {
        "[]".to_string()
    } else {
        format!("[{}]", names.join(", "))
    }
}

/// Render the type portion of a property (e.g. `TCaption [UString]`).
pub fn render_type_label(header: &TypeHeader<'_>) -> String {
    format!("{} [{:?}]", header.name_str(), header.kind)
}

fn default_render(v: &DfmValue<'_>) -> String {
    match v {
        DfmValue::Null => "(null)".into(),
        DfmValue::Nil => "(nil)".into(),
        DfmValue::Bool(b) => b.to_string(),
        DfmValue::Int(i) => i.to_string(),
        DfmValue::Int64(i) => i.to_string(),
        DfmValue::UInt64(i) => i.to_string(),
        DfmValue::Single(f) => format!("{:.6}f", f),
        DfmValue::Double(f) => format!("{:.6}", f),
        DfmValue::Extended(_) => "<extended>".into(),
        DfmValue::Currency(c) => format!("{:.4}$", (*c as f64) / 10_000.0),
        DfmValue::String(s) => format!("{:?}", String::from_utf8_lossy(s)),
        DfmValue::Utf16(b) => {
            let iter = (0..b.len() / 2).map(|i| u16::from_le_bytes([b[i * 2], b[i * 2 + 1]]));
            let decoded: String = char::decode_utf16(iter).filter_map(Result::ok).collect();
            format!("{:?} (utf-16, {} bytes)", decoded, b.len())
        }
        DfmValue::Binary(b) => {
            // Show the first few bytes so malware-analyst eyes can spot
            // common magic sequences (e.g. 0x89 'P' 'N' 'G' = PNG).
            let prefix: Vec<String> = b.iter().take(8).map(|x| format!("{:02x}", x)).collect();
            format!("<binary {} bytes, leading={}>", b.len(), prefix.join(" "))
        }
        DfmValue::Set(items) => {
            let names: Vec<_> = items.iter().map(|s| String::from_utf8_lossy(s)).collect();
            format!("[{}]", names.join(", "))
        }
        DfmValue::List(items) => {
            let parts: Vec<_> = items.iter().map(|v| default_render(v)).collect();
            format!("({})", parts.join(", "))
        }
        DfmValue::Collection(items) => format!("<collection, {} items>", items.len()),
        DfmValue::Unknown { tag, body } => {
            format!("<unknown tag 0x{:02x}, {} bytes>", tag, body.len())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rtti::{OrdinalType, TypeKind};

    #[test]
    fn render_int_with_enum_context() {
        // Synthetic TAlign = alClient (ord=5).
        let values: Vec<&[u8]> = vec![
            b"alNone",
            b"alTop",
            b"alBottom",
            b"alLeft",
            b"alRight",
            b"alClient",
            b"alCustom",
        ];
        let enum_info = EnumInfo {
            header: TypeHeader {
                va: 0,
                kind_byte: 3,
                kind: TypeKind::Enumeration,
                name: b"TAlign",
            },
            ord: OrdinalType::UByte,
            min: 0,
            max: 6,
            base_type_ref: 0,
            values,
            unit_name: None,
        };
        let detail = TypeDetail::Enumeration(enum_info);
        let rendered = render_value(&DfmValue::Int(5), Some(&detail));
        assert_eq!(rendered, "alClient");
    }

    #[test]
    fn render_int_out_of_range_falls_back() {
        let enum_info = EnumInfo {
            header: TypeHeader {
                va: 0,
                kind_byte: 3,
                kind: TypeKind::Enumeration,
                name: b"TFoo",
            },
            ord: OrdinalType::UByte,
            min: 0,
            max: 2,
            base_type_ref: 0,
            values: vec![b"a", b"b", b"c"],
            unit_name: None,
        };
        let detail = TypeDetail::Enumeration(enum_info);
        let rendered = render_value(&DfmValue::Int(99), Some(&detail));
        assert!(rendered.contains("out-of-range"), "got {rendered}");
    }

    #[test]
    fn render_set_with_enum_context() {
        let enum_info = EnumInfo {
            header: TypeHeader {
                va: 0,
                kind_byte: 3,
                kind: TypeKind::Enumeration,
                name: b"TAnchor",
            },
            ord: OrdinalType::UByte,
            min: 0,
            max: 3,
            base_type_ref: 0,
            values: vec![b"akLeft", b"akTop", b"akRight", b"akBottom"],
            unit_name: None,
        };
        // Mask 0b0011 = akLeft + akTop.
        assert_eq!(
            render_set_mask_with_enum(0b0011, &enum_info),
            "[akLeft, akTop]"
        );
    }
}
