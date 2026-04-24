//! Virtual-method-table function-pointer array decoder.
//!
//! A class's VMT header is followed by an array of `pointer_size` function
//! pointers — one per user-declared virtual method slot. The slot count is
//! not stored anywhere explicitly; the canonical way to bound it is "up
//! to the next class's VMT base". ESET's `DelphiHelper` and `pythia` both
//! derive the count this way.
//!
//! ## Approach
//!
//! For each class `C`:
//!
//! 1. Take the starting VA as `C.self_ptr` (the header's `vmtSelfPtr`
//!    target, which *is* the first slot of the virtual method pointer
//!    array — see `reference/pythia/pythia/README.md:44-48`).
//! 2. Take the ending VA as the smallest VMT-base VA strictly greater than
//!    `C.self_ptr` across all discovered classes (when one exists). If no
//!    class follows, clamp to a conservative 2 KiB budget.
//! 3. Walk pointer-sized slots until the end, reading each as a code
//!    address. Stop early if a slot is zero or doesn't point into a
//!    readable segment — that typically marks a RTTI/data fragment we
//!    shouldn't cross into.
//!
//! ## Allocation note
//!
//! The returned `VirtualMethodEntry` records are `Copy`; no heap allocation
//! happens on the hot path beyond the result `Vec`.

use crate::{classes::ClassSet, formats::BinaryContext, util::read_ptr, vmt::Vmt};

/// One entry in the virtual-function-pointer array.
#[derive(Debug, Clone, Copy)]
pub struct VirtualMethodEntry {
    /// Zero-based slot index within the array (matches the Delphi `vtXxx`
    /// convention where `vt0` is the first user-declared slot).
    pub slot: usize,
    /// Virtual address of the method pointer's storage location.
    pub slot_va: u64,
    /// The code address the slot points at (the actual function entry).
    pub code_va: u64,
}

/// Walk the virtual-method array following `vmt`.
///
/// `upper_bound_va` is the first VA at which another class's VMT begins;
/// slots at or beyond that boundary are not read. Pass `None` to use a
/// default 2 KiB budget.
pub fn iter_virtual_methods<'a>(
    ctx: &BinaryContext<'a>,
    vmt: &Vmt<'a>,
    upper_bound_va: Option<u64>,
) -> Vec<VirtualMethodEntry> {
    if vmt.self_ptr == 0 {
        return Vec::new();
    }
    let psize = vmt.pointer_size as usize;
    let start_va = vmt.self_ptr;
    let end_va = upper_bound_va.unwrap_or(start_va + 2048).max(start_va);
    if end_va <= start_va {
        return Vec::new();
    }
    let max_slots = ((end_va - start_va) as usize) / psize;
    if max_slots == 0 {
        return Vec::new();
    }

    let Some(start_file) = ctx.va_to_file(start_va) else {
        return Vec::new();
    };
    let data = ctx.data();
    let mut out = Vec::with_capacity(max_slots);
    for slot in 0..max_slots {
        let off = start_file + slot * psize;
        let Some(code_va) = read_ptr(data, off, psize) else {
            break;
        };
        if code_va == 0 {
            // A null slot usually means we've walked off the end of the
            // array into padding or an unrelated record.
            break;
        }
        // Validate: the code pointer should resolve into the image.
        if ctx.va_to_file(code_va).is_none() {
            break;
        }
        let slot_va = start_va + (slot * psize) as u64;
        out.push(VirtualMethodEntry {
            slot,
            slot_va,
            code_va,
        });
    }
    out
}

/// Given a class set, compute the tightest VA upper-bound for a class's
/// virtual-method array (the next class's VMT base, or the self_ptr that
/// follows this one, whichever is smaller).
pub fn upper_bound_for(set: &ClassSet<'_>, vmt: &Vmt<'_>) -> Option<u64> {
    let mut best: Option<u64> = None;
    for c in set.iter() {
        // The next VMT header we could bump into is some class's `va`.
        // Also the self_ptr target of earlier classes can sit between our
        // self_ptr and the next VMT header — use whichever is closer.
        let candidates = [c.vmt.va, c.vmt.self_ptr];
        for &va in &candidates {
            if va > vmt.self_ptr {
                match best {
                    Some(cur) if va >= cur => {}
                    _ => best = Some(va),
                }
            }
        }
    }
    best
}
