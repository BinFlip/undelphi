//! Decoders for two of the VMT's auxiliary tables that carry runtime
//! metadata beyond the method / field / interface / type-info tables
//! already covered by dedicated modules: the init (managed-fields) table
//! and the dynamic-dispatch table.
//!
//! ## Init table (`vmtInitTable`)
//!
//! This slot points at a `PTypeInfo` whose `Kind` is `tkRecord` and
//! whose managed-fields list names every instance offset that carries a
//! ref-counted reference (strings, interfaces, dynamic arrays, other
//! managed records). The runtime consumes this table during
//! `AfterConstruction` and `Destroy` to initialise and finalise those
//! fields. Decoding it is a straight reuse of
//! [`crate::rtti::decode_tkrecord`].
//!
//! Source: FPC `rtl/inc/rtti.inc` — `InitializeArray` / `FinalizeArray`.
//!
//! ## Dynamic-dispatch table (`vmtDynamicTable`)
//!
//! Dynamic methods are declared with `dynamic;` or `message <ID>;` and
//! their dispatch goes through a separate lookup table rather than the
//! virtual method pointer array — the point being that derived classes
//! don't grow the VMT for every dynamic method.
//!
//! On-disk layout (both Delphi and FPC):
//!
//! ```text
//!   Count:     u16
//!   Indexes:   [i16; Count]    (message ID per slot)
//!   Handlers:  [ptr; Count]    (code pointer per slot, same order)
//! ```
//!
//! The indexes come first so the runtime can do a tight binary search on
//! a packed i16 array without touching the handler pointers.
//!
//! The returned vectors contain plain values (no borrowed slices), so
//! they don't carry the input lifetime.

use crate::{
    formats::BinaryContext,
    limits::MAX_DYNAMIC_SLOTS_PER_CLASS,
    rtti::{RecordInfo, decode_tkrecord},
    util::{read_ptr, read_u16},
    vmt::Vmt,
};

/// Decode the init (managed-fields) table. Returns `None` when
/// `vmtInitTable` is null or the pointed-at record can't be decoded.
pub fn decode_init_table<'a>(ctx: &BinaryContext<'a>, vmt: &Vmt<'a>) -> Option<RecordInfo<'a>> {
    if vmt.init_table == 0 {
        return None;
    }
    decode_tkrecord(ctx, vmt.init_table, vmt.flavor)
}

/// One entry in the dynamic-dispatch table.
#[derive(Debug, Clone, Copy)]
pub struct DynamicSlot {
    /// Dispatch index (message ID for `message` declarations, or a
    /// compiler-assigned negative index for plain `dynamic` methods).
    pub index: i16,
    /// Code VA of the handler.
    pub handler_va: u64,
}

/// Decode the dynamic-dispatch table.
pub fn decode_dynamic_table(ctx: &BinaryContext<'_>, vmt: &Vmt<'_>) -> Vec<DynamicSlot> {
    if vmt.dynamic_table == 0 {
        return Vec::new();
    }
    let Some(file_off) = ctx.va_to_file(vmt.dynamic_table) else {
        return Vec::new();
    };
    let data = ctx.data();
    let Some(count) = read_u16(data, file_off).map(usize::from) else {
        return Vec::new();
    };
    if count == 0 || count > MAX_DYNAMIC_SLOTS_PER_CLASS {
        return Vec::new();
    }
    let psize = vmt.pointer_size as usize;
    let mut out = Vec::with_capacity(count);
    let indexes_off = file_off + 2;
    let handlers_off = indexes_off + count * 2;
    for i in 0..count {
        let Some(index) = read_u16(data, indexes_off + i * 2).map(|u| u as i16) else {
            break;
        };
        let Some(handler_va) = read_ptr(data, handlers_off + i * psize, psize) else {
            break;
        };
        out.push(DynamicSlot { index, handler_va });
    }
    out
}
