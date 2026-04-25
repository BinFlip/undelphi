//! Shared low-level readers used by the RTTI / methods / interfaces
//! modules. The returned slices borrow from the binary context's
//! underlying byte buffer.
//!
//! Every offset arithmetic here uses [`usize::checked_add`] /
//! [`usize::checked_sub`] so adversarial inputs (e.g. an enormous length
//! field on disk) cannot overflow into a panic in debug builds or a
//! wrap-around in release builds. The result is a clean `None`
//! propagated up to the caller.

use crate::formats::BinaryContext;

/// Read a little-endian pointer of `size` bytes (4 or 8) at a file offset.
pub(crate) fn read_ptr(bytes: &[u8], off: usize, size: usize) -> Option<u64> {
    match size {
        4 => {
            let end = off.checked_add(4)?;
            let slice = bytes.get(off..end)?;
            Some(u32::from_le_bytes(slice.try_into().ok()?) as u64)
        }
        8 => {
            let end = off.checked_add(8)?;
            let slice = bytes.get(off..end)?;
            Some(u64::from_le_bytes(slice.try_into().ok()?))
        }
        _ => None,
    }
}

/// Read an unsigned little-endian `u16` at a file offset.
#[inline]
pub(crate) fn read_u16(bytes: &[u8], off: usize) -> Option<u16> {
    let end = off.checked_add(2)?;
    let slice = bytes.get(off..end)?;
    Some(u16::from_le_bytes(slice.try_into().ok()?))
}

/// Read an unsigned little-endian `u32` at a file offset.
#[inline]
pub(crate) fn read_u32(bytes: &[u8], off: usize) -> Option<u32> {
    let end = off.checked_add(4)?;
    let slice = bytes.get(off..end)?;
    Some(u32::from_le_bytes(slice.try_into().ok()?))
}

/// Resolve `va` to a file offset and read a short-string's body.
///
/// Returns the bytes of the string, excluding the length-byte prefix.
pub(crate) fn read_short_string_at_va<'a>(ctx: &BinaryContext<'a>, va: u64) -> Option<&'a [u8]> {
    if va == 0 {
        return None;
    }
    let off = ctx.va_to_file(va)?;
    read_short_string_at_file(ctx.data(), off)
}

/// Read a short-string starting at `off` within `data`. Returns the body
/// slice (no length byte).
pub(crate) fn read_short_string_at_file(data: &[u8], off: usize) -> Option<&[u8]> {
    let len = *data.get(off)? as usize;
    let body_start = off.checked_add(1)?;
    let body_end = body_start.checked_add(len)?;
    data.get(body_start..body_end)
}

/// Read a pointer at `va`, then interpret the result as another VA. Used by
/// FPC's double-indirection fields (PShortString, PPGuid, etc.).
pub(crate) fn deref_va(ctx: &BinaryContext<'_>, va: u64, ptr_size: usize) -> Option<u64> {
    if va == 0 {
        return None;
    }
    let off = ctx.va_to_file(va)?;
    read_ptr(ctx.data(), off, ptr_size)
}
