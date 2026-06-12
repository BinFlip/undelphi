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

    /// Convert this method's absolute code VA to an RVA by subtracting
    /// `image_base`.
    #[inline]
    pub fn method_rva(&self, image_base: u64) -> Option<u64> {
        self.code_va.checked_sub(image_base)
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

/// One entry from the **extended-method section** of a Delphi
/// `vmtMethodTable`.
///
/// Modern Delphi (2010+) appends a second section after the published-method
/// entries: a `u16` `ExCount` followed by `ExCount` records of
/// `{ EntryPtr: ptr; Flags: u16; VirtualIndex: i16 }`. Each `EntryPtr`
/// points at a `{ Len: u16; CodeAddr: ptr; Name: ShortString; Tail }`
/// record whose `Tail` carries the full method signature — emitted by
/// default extended RTTI, *without* requiring `{$METHODINFO ON}`. This is
/// the primary signature source for Delphi 2010+ binaries.
///
/// Source: `reference/IDR64/IDCGen.cpp::OutputMethodTable` (ExCount loop)
/// and `OutputVmtMethodEntry`.
#[derive(Debug, Clone, Copy)]
pub struct DelphiExtMethod<'a> {
    /// Method name (short-string body, borrowed from the input).
    pub(crate) name: &'a [u8],
    /// Method code entry-point VA.
    pub code_va: u64,
    /// Raw entry flags word. The bit layout is not the FPC
    /// `RTTIFlagVisibilityMask` scheme, so it is surfaced verbatim rather
    /// than decoded into a visibility class.
    pub flags: u16,
    /// VMT slot index for virtual methods (`-1` / large unsigned for
    /// non-virtual; stored as a signed `i16`).
    pub vmt_index: i16,
    /// The signature trailer bytes (same layout as
    /// [`MethodEntry::trailer`]); empty when the entry has no tail.
    pub trailer: &'a [u8],
}

impl<'a> DelphiExtMethod<'a> {
    /// Method name as `&str`, lossily decoded.
    #[inline]
    pub fn name(&self) -> &'a str {
        str::from_utf8(self.name).unwrap_or("<non-ascii>")
    }

    /// Raw method-name bytes, borrowed from the input.
    #[inline]
    pub fn name_bytes(&self) -> &'a [u8] {
        self.name
    }

    /// Walk the extended-method section of a Delphi `vmtMethodTable`.
    ///
    /// Returns an empty vector for FPC VMTs, for classes with no method
    /// table, and for pre-2010 Delphi (which has no extended section).
    pub fn iter(ctx: &BinaryContext<'a>, vmt: &Vmt<'a>) -> Vec<Self> {
        if vmt.method_table == 0 || vmt.flavor != VmtFlavor::Delphi {
            return Vec::new();
        }
        iter_delphi_extended(ctx, vmt).unwrap_or_else(|| {
            crate::__undelphi_trace_warn!(
                vmt_va = vmt.va,
                method_table = vmt.method_table,
                "DelphiExtMethod::iter: extended-method walk bailed out"
            );
            Vec::new()
        })
    }
}

/// Whether `name` looks like a Pascal method identifier: non-empty, leading
/// letter or `_`, then alphanumerics / `_`. Used to reject garbage read past
/// the published-method section on compilers with no extended section.
fn is_plausible_method_name(name: &[u8]) -> bool {
    let Some(&first) = name.first() else {
        return false;
    };
    if !(first.is_ascii_alphabetic() || first == b'_') {
        return false;
    }
    name.iter().all(|&b| b.is_ascii_alphanumeric() || b == b'_')
}

fn iter_delphi_extended<'a>(
    ctx: &BinaryContext<'a>,
    vmt: &Vmt<'a>,
) -> Option<Vec<DelphiExtMethod<'a>>> {
    let base_off = ctx.va_to_file(vmt.method_table)?;
    let data = ctx.data();
    let count = read_u16(data, base_off)? as usize;
    if count > MAX_METHODS_PER_CLASS {
        return Some(Vec::new());
    }
    let psize = vmt.pointer_size as usize;

    // Skip the published-method entries to land on `ExCount`.
    let mut cursor = base_off.checked_add(2)?;
    for _ in 0..count {
        let size = read_u16(data, cursor)? as usize;
        if size == 0 {
            return Some(Vec::new());
        }
        cursor = cursor.checked_add(size)?;
    }

    let ex_count = read_u16(data, cursor)? as usize;
    if ex_count == 0 || ex_count > MAX_METHODS_PER_CLASS {
        return Some(Vec::new());
    }
    let mut entry_cursor = cursor.checked_add(2)?;
    // Each extended record: EntryPtr(ptr) + Flags(u16) + VirtualIndex(u16).
    let ex_record_size = psize.checked_add(4)?;
    let mut out = Vec::with_capacity(ex_count);

    for _ in 0..ex_count {
        let entry_ptr_va = read_ptr(data, entry_cursor, psize)?;
        let flags = read_u16(data, entry_cursor.checked_add(psize)?)?;
        let vmt_index = read_u16(data, entry_cursor.checked_add(psize)?.checked_add(2)?)? as i16;
        entry_cursor = entry_cursor.checked_add(ex_record_size)?;

        // Follow EntryPtr to the {Len, CodeAddr, Name, Tail} record. A
        // bad pointer skips this entry rather than failing the whole walk.
        let Some(eoff) = ctx.va_to_file(entry_ptr_va) else {
            continue;
        };
        let Some(elen) = read_u16(data, eoff).map(usize::from) else {
            continue;
        };
        let code_off = eoff.checked_add(2)?;
        let Some(code_va) = read_ptr(data, code_off, psize) else {
            continue;
        };
        let name_off = code_off.checked_add(psize)?;
        let Some(name) = read_short_string_at_file(data, name_off) else {
            continue;
        };
        // Pre-2010 Delphi has no extended section: the `ExCount` we read is
        // then unrelated data and the "entries" are garbage. Require a
        // plausible Pascal method identifier to reject those false hits
        // (e.g. Delphi 7's `LA.exe`, which otherwise yields one empty-named
        // spurious signature).
        if !is_plausible_method_name(name) {
            continue;
        }
        let bare = 2usize
            .checked_add(psize)?
            .checked_add(1)?
            .checked_add(name.len())?;
        let trailer = if elen > bare {
            let start = eoff.checked_add(bare)?;
            let end = eoff.checked_add(elen)?;
            data.get(start..end).unwrap_or(&[])
        } else {
            &[]
        };
        out.push(DelphiExtMethod {
            name,
            code_va,
            flags,
            vmt_index,
            trailer,
        });
    }
    Some(out)
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn method_rva_subtracts_image_base() {
        let method = MethodEntry {
            name: b"Click",
            code_va: 0x401234,
            trailer: &[],
        };
        assert_eq!(method.method_rva(0x400000), Some(0x1234));
        assert_eq!(method.method_rva(0x500000), None);
    }
}
