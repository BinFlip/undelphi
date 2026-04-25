//! Published-method table iterator.
//!
//! Delphi and FPC use **different on-disk layouts** for the method table.
//! Iteration dispatches on the VMT's `flavor` tag set by
//! [`crate::vmt::scan`]. Names are slices borrowed from the binary.
//!
//! ## Delphi layout
//!
//! Source: `reference/DelphiHelper/DelphiHelper/core/DelphiClass_MethodTable.py:36-49`,
//! cross-checked with `reference/pythia/pythia/core/structures.py:331-343`.
//!
//! ```text
//!   Count: u16
//!   entries[Count]:
//!     Size:     u16           (byte-size of this whole entry, incl. Size)
//!     CodeAddr: ptr           (4 on 32-bit, 8 on 64-bit)
//!     Name:     ShortString   (length-prefixed, inline)
//!     <trailing bytes used by modern Delphi for arg typeinfo — unparsed here>
//! ```
//!
//! ## FPC layout
//!
//! Source: `reference/fpc-source/rtl/objpas/typinfo.pp:445-468`
//! (`TVmtMethodEntry`, `TVmtMethodTable`).
//!
//! ```text
//!   Count: u32                (LongWord, fixed 4 bytes even on 64-bit)
//!   entries[Count]:
//!     NamePtr:  PShortString  (ptr — follow for the ShortString body)
//!     CodeAddr: CodePointer
//! ```
//!
//! Extended FPC tables (`TVmtMethodExTable`) carry parameter metadata after
//! the basic entry; they are referenced through the method table trailer
//! and decoded in iteration 4.

use std::str;

use crate::{
    formats::BinaryContext,
    limits::{MAX_METHODS_PER_CLASS, MAX_METHODS_PER_CLASS_FPC},
    util::{read_ptr, read_short_string_at_file, read_short_string_at_va, read_u16, read_u32},
    vmt::{Vmt, VmtFlavor},
};

/// One published method.
#[derive(Debug, Clone, Copy)]
pub struct MethodEntry<'a> {
    /// Method name (short-string body, borrowed from the input).
    pub(crate) name: &'a [u8],
    /// Virtual address of the method's code entry point.
    ///
    /// This is an absolute VA. For PE consumers operating in RVA space,
    /// subtract the image base.
    pub code_va: u64,
    /// Extra bytes trailing the bare entry, when the compiler emitted an
    /// extended `TVmtMethodExEntry` record (modern Delphi / FPC). Empty
    /// when the entry is classic bare shape.
    pub trailer: &'a [u8],
}

impl<'a> MethodEntry<'a> {
    /// Method name as `&str`, lossily decoded. Pascal identifiers are ASCII
    /// in practice; non-UTF-8 bytes fall back to `"<non-ascii>"`.
    #[inline]
    pub fn name(&self) -> &'a str {
        str::from_utf8(self.name).unwrap_or("<non-ascii>")
    }

    /// Raw method name bytes (short-string body, borrowed from the input).
    #[inline]
    pub fn name_bytes(&self) -> &'a [u8] {
        self.name
    }
}

impl<'a> MethodEntry<'a> {
    /// Collect all published methods declared on `vmt`. Returns an
    /// empty vector if the class has no method table or the table is
    /// malformed.
    pub fn iter(ctx: &BinaryContext<'a>, vmt: &Vmt<'a>) -> Vec<Self> {
        if vmt.method_table == 0 {
            return Vec::new();
        }
        let result = match vmt.flavor {
            VmtFlavor::Delphi => iter_delphi(ctx, vmt),
            VmtFlavor::Fpc => iter_fpc(ctx, vmt),
        };
        result.unwrap_or_else(|| {
            crate::__undelphi_trace_warn!(
                vmt_va = vmt.va,
                method_table = vmt.method_table,
                "MethodEntry::iter: method-table walk bailed out"
            );
            Vec::new()
        })
    }
}

fn iter_delphi<'a>(ctx: &BinaryContext<'a>, vmt: &Vmt<'a>) -> Option<Vec<MethodEntry<'a>>> {
    let base_off = ctx.va_to_file(vmt.method_table)?;
    let data = ctx.data();
    let count = read_u16(data, base_off)? as usize;
    if count == 0 || count > MAX_METHODS_PER_CLASS {
        return Some(Vec::new());
    }

    let psize = vmt.pointer_size as usize;
    let mut out = Vec::with_capacity(count);
    let mut cursor = base_off.checked_add(2)?;

    for _ in 0..count {
        let size = read_u16(data, cursor)? as usize;
        if size == 0 {
            // Guard against malformed tables that would loop forever.
            break;
        }
        let code_off = cursor.checked_add(2)?;
        let code_va = read_ptr(data, code_off, psize)?;
        let name_off = code_off.checked_add(psize)?;
        let name = read_short_string_at_file(data, name_off)?;
        // Bare entry = 2 (Size u16) + psize (CodeAddr) + 1 (name length byte) + name bytes.
        // Anything beyond that is the modern extended-RTTI trailer.
        let bare = 2usize
            .checked_add(psize)?
            .checked_add(1)?
            .checked_add(name.len())?;
        let trailer = if size > bare {
            let trailer_start = cursor.checked_add(bare)?;
            let trailer_end = cursor.checked_add(size)?;
            // If the entry's declared size walks past EOF, the table is
            // malformed — surface the parse failure rather than silently
            // truncating the trailer to empty.
            data.get(trailer_start..trailer_end)?
        } else {
            &[]
        };
        out.push(MethodEntry {
            name,
            code_va,
            trailer,
        });
        cursor = cursor.checked_add(size)?;
    }
    Some(out)
}

fn iter_fpc<'a>(ctx: &BinaryContext<'a>, vmt: &Vmt<'a>) -> Option<Vec<MethodEntry<'a>>> {
    let base_off = ctx.va_to_file(vmt.method_table)?;
    let data = ctx.data();
    // FPC's `TVmtMethodTable.Count` is `LongWord` (u32) regardless of
    // pointer width — see `typinfo.pp:455-467`.
    let count = read_u32(data, base_off)? as usize;
    if count == 0 || count > MAX_METHODS_PER_CLASS_FPC {
        return Some(Vec::new());
    }

    let psize = vmt.pointer_size as usize;
    let entries_off = base_off.checked_add(4)?;
    let entry_size = psize.checked_mul(2)?;
    let mut out = Vec::with_capacity(count);

    for i in 0..count {
        let off = entries_off.checked_add(i.checked_mul(entry_size)?)?;
        let name_ptr_va = read_ptr(data, off, psize)?;
        let code_va = read_ptr(data, off.checked_add(psize)?, psize)?;
        let Some(name) = read_short_string_at_va(ctx, name_ptr_va) else {
            continue;
        };
        // FPC's TVmtMethodEntry is fixed-size — no trailer.
        out.push(MethodEntry {
            name,
            code_va,
            trailer: &[],
        });
    }
    Some(out)
}
