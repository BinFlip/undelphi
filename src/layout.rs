//! Instance memory-layout reconstruction.
//!
//! Given a class, fuses its published-field table, init (managed-fields)
//! table, and declared `InstanceSize` into a single byte-by-byte layout
//! description. Useful for reverse-engineering instance struct shape.
//!
//! Every Delphi / FPC instance starts with a single pointer-sized slot
//! for the VMT pointer. Published and private/protected field offsets
//! then populate the rest up to `InstanceSize`. Unnamed gaps show where
//! non-published fields live (their offsets aren't in the RTTI).

use std::collections::BTreeMap;

use crate::{DelphiBinary, classes::Class, fields::FieldTypeRef};

/// One entry in the reconstructed instance layout.
#[derive(Debug, Clone)]
pub struct LayoutEntry {
    /// Byte offset within the instance.
    pub offset: u32,
    /// Byte size occupied. For fields we know the declared type size;
    /// for `VmtSlot` entries it's `pointer_size`; for `Gap` entries it's
    /// the number of bytes between known fields.
    pub size: u32,
    /// Layout-entry category.
    pub kind: LayoutKind,
}

/// Category of a layout entry.
#[derive(Debug, Clone)]
pub enum LayoutKind {
    /// The mandatory VMT pointer at offset 0.
    VmtSlot,
    /// A published / extended-RTTI field we could name.
    NamedField {
        /// Field name.
        name: String,
        /// Resolved type name, when the field's `TypeInfoPtr` decoded.
        type_name: Option<String>,
        /// `true` if this field is also listed in the class's init table
        /// (managed ref-counted type — string, interface, dynarray, …).
        managed: bool,
    },
    /// A byte range between known fields that we can't attribute — either
    /// non-published instance data, or padding.
    Gap,
    /// A managed-field entry from the init table with no matching named
    /// field (the class keeps the field private).
    ManagedOnly {
        /// Resolved type name from the managed-field entry.
        type_name: Option<String>,
    },
}

/// Reconstruct the memory layout of an instance of `class`.
pub fn reconstruct<'a>(bin: &DelphiBinary<'a>, class: &Class<'a>) -> Vec<LayoutEntry> {
    let psize = class.pointer_size() as u32;
    let total = class.instance_size();
    let mut out = Vec::new();

    // Gather named fields.
    let named_fields = bin.fields(class);
    // Gather managed-field offsets (subset of fields, by offset).
    let init = bin.init_table(class);
    let managed_offsets: BTreeMap<u64, Option<String>> = init
        .map(|r| {
            r.managed_fields
                .into_iter()
                .map(|f| {
                    let ty = f.field_type.map(|h| h.name_str().to_owned());
                    (f.offset, ty)
                })
                .collect()
        })
        .unwrap_or_default();

    // Build a sorted map offset → entry.
    let mut slots: BTreeMap<u32, LayoutKind> = Default::default();
    slots.insert(0, LayoutKind::VmtSlot);
    for f in &named_fields {
        let type_name = bin
            .field_type(class, f)
            .map(|h| h.name_str().to_owned())
            .or_else(|| match f.type_ref {
                FieldTypeRef::TypeIndex(i) => Some(format!("<type-index {i}>")),
                FieldTypeRef::TypeInfoPtr(p) => Some(format!("<typeinfo 0x{:x}>", p)),
            });
        let managed = managed_offsets.contains_key(&(f.offset as u64));
        slots.insert(
            f.offset,
            LayoutKind::NamedField {
                name: f.name_str().to_owned(),
                type_name,
                managed,
            },
        );
    }
    for (off, ty) in &managed_offsets {
        let off32 = *off as u32;
        slots
            .entry(off32)
            .or_insert_with(|| LayoutKind::ManagedOnly {
                type_name: ty.clone(),
            });
    }

    // Walk sorted slots, emitting Gap entries where consecutive slots don't
    // touch.
    let mut prev_end: u32 = 0;
    for (off, kind) in &slots {
        if *off > prev_end {
            out.push(LayoutEntry {
                offset: prev_end,
                size: off - prev_end,
                kind: LayoutKind::Gap,
            });
        }
        let size = match kind {
            LayoutKind::VmtSlot => psize,
            LayoutKind::NamedField { managed: _, .. } | LayoutKind::ManagedOnly { .. } => {
                // Without type-size lookup we don't know the exact size of a
                // field; conservatively treat it as pointer-sized which is
                // the most common case for class-typed fields.
                psize
            }
            LayoutKind::Gap => 0,
        };
        out.push(LayoutEntry {
            offset: *off,
            size,
            kind: kind.clone(),
        });
        prev_end = off + size;
    }
    if prev_end < total {
        out.push(LayoutEntry {
            offset: prev_end,
            size: total - prev_end,
            kind: LayoutKind::Gap,
        });
    }
    out
}
