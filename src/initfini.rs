//! Per-unit initialization / finalization procedure tables.
//!
//! Both Delphi and FPC walk a per-unit table at startup. Names like
//! `Vcl.Forms.Initialization` are the most natural labels a disassembler
//! can hang off, since the program-entry trace passes through every one
//! of them.
//!
//! ## FPC layout
//!
//! Source: `reference/fpc-source/rtl/inc/system.inc:1132-1149` and
//! `systemh.inc:722-733`.
//!
//! ```text
//! INITFINAL (global symbol):
//!   TableCount: ALUUInt        // pointer-sized
//!   InitCount:  ALUUInt        // pointer-sized
//!   Procs[TableCount]:
//!     InitProc:    ptr
//!     FinalProc:   ptr
//!     UnitNamePtr: ptr        // when FPC_INITFINAL_HASUNITNAME (modern FPC)
//! ```
//!
//! `UnitNamePtr` points at a `ShortString` body (length-prefixed).
//!
//! ## Delphi
//!
//! Delphi compilers inline per-unit `initialization` / `finalization`
//! calls into the entry-point startup sequence rather than emitting a
//! discoverable runtime table. The public `PACKAGEINFO` resource
//! exposes only the unit *list* (without VAs); recovering the actual
//! procedure addresses would require disassembling the program
//! entry point, which is outside this crate's scope. Delphi binaries
//! therefore return an empty vector from
//! [`iter_unit_init_procs`] — by design, not a missing feature.
//! Consumers that want the unit list can read
//! [`crate::DelphiBinary::package_info`] directly.
//!
//! ## Strategy
//!
//! The table's location is recovered in two passes:
//!
//! 1. **Symbol lookup.** Goblin parses the binary's symbol table
//!    (ELF `.symtab` / Mach-O `LC_SYMTAB` / PE COFF symbols) when
//!    present. The table is a global named `INITFINAL` (FPC) — we look
//!    for that, plus the Mach-O-leading-underscore variant
//!    (`_INITFINAL`) and the FPC-namespaced form (`FPC_INITFINAL`).
//! 2. **Heuristic shape scan.** When the binary is stripped, we scan
//!    the data sections for the distinctive TableCount/InitCount header
//!    followed by N pointer-pairs that all resolve to plausible code
//!    VAs. Stripped binaries are common enough to warrant this fallback.

use std::str;

use goblin::{Object, mach::Mach};

use crate::{
    formats::BinaryContext,
    util::{read_ptr, read_short_string_at_va},
};

/// Hard limit on the number of units we'll trust in any one table —
/// guards against pathologically large counts in adversarial input.
const MAX_UNITS_PER_TABLE: usize = 4096;

/// One unit's init / finalize procedures.
#[derive(Debug, Clone)]
pub struct UnitInitProc<'a> {
    /// Unit name (e.g. `System.SysUtils`), lossily decoded. `"<unknown>"`
    /// when the FPC build didn't emit `FPC_INITFINAL_HASUNITNAME` or the
    /// indirection couldn't be followed.
    pub unit_name: &'a str,
    /// Absolute VA of the unit's `initialization` procedure, or `None`
    /// when the unit declares no `initialization` block. Subtract the
    /// image base for an RVA.
    pub init_va: Option<u64>,
    /// Absolute VA of the unit's `finalization` procedure, or `None`.
    pub finalize_va: Option<u64>,
}

/// Walk the FPC `INITFINAL` table for per-unit init / finalize VAs.
///
/// Returns an empty vector for Delphi-compiled binaries (by design;
/// Delphi inlines unit init into the entry point — see module docs)
/// and for FPC binaries where neither the symbol lookup nor the
/// heuristic shape scan locates a plausible table.
pub fn iter_unit_init_procs<'a>(ctx: &BinaryContext<'a>) -> Vec<UnitInitProc<'a>> {
    let Some(ptr_size) = ctx.pointer_size() else {
        return Vec::new();
    };
    if let Some(va) = locate_initfinal_via_symbol(ctx)
        && let Some(out) = walk_initfinal(ctx, va, ptr_size)
    {
        return out;
    }
    if let Some(out) = locate_initfinal_via_scan(ctx, ptr_size) {
        return out;
    }
    Vec::new()
}

/// Look up `INITFINAL` (and aliases) in the binary's symbol table.
fn locate_initfinal_via_symbol(ctx: &BinaryContext<'_>) -> Option<u64> {
    const NAMES: &[&str] = &["INITFINAL", "_INITFINAL", "FPC_INITFINAL"];
    let Ok(obj) = Object::parse(ctx.data()) else {
        return None;
    };
    match obj {
        Object::Elf(elf) => {
            for sym in elf.syms.iter().chain(elf.dynsyms.iter()) {
                let Some(name) = elf.strtab.get_at(sym.st_name) else {
                    continue;
                };
                if NAMES.contains(&name) && sym.st_value != 0 {
                    return Some(sym.st_value);
                }
            }
            None
        }
        Object::Mach(Mach::Binary(macho)) => {
            for sym in macho.symbols.as_ref()?.iter().flatten() {
                let (name, nlist) = sym;
                if NAMES.contains(&name) && nlist.n_value != 0 {
                    return Some(nlist.n_value);
                }
            }
            None
        }
        Object::PE(pe) => {
            // PE COFF symbols are rare in modern toolchains (they're a
            // build-tools artefact, not a runtime artefact), and goblin
            // 0.10 doesn't expose them on `PE`. Fall through to the
            // exports table — Delphi packages export their unit init
            // procs by name in some configurations.
            for export in &pe.exports {
                let Some(name) = export.name else { continue };
                if NAMES.contains(&name) {
                    return pe.image_base.checked_add(export.rva as u64);
                }
            }
            None
        }
        _ => None,
    }
}

/// Decode a candidate INITFINAL table at `va`. Returns `None` if the
/// header looks implausible.
fn walk_initfinal<'a>(
    ctx: &BinaryContext<'a>,
    va: u64,
    ptr_size: usize,
) -> Option<Vec<UnitInitProc<'a>>> {
    let base_off = ctx.va_to_file(va)?;
    let data = ctx.data();
    let count = read_ptr(data, base_off, ptr_size)? as usize;
    if count == 0 || count > MAX_UNITS_PER_TABLE {
        return None;
    }
    // Skip InitCount (also pointer-sized, runtime progress field).
    let two_ptr = ptr_size.checked_mul(2)?;
    let mut cursor = base_off.checked_add(two_ptr)?;

    // Probe shape: with-unit-names is 3 pointers per entry; without is 2.
    let with_names = probe_with_names(ctx, data, cursor, count, ptr_size);
    let entry_size = if with_names {
        ptr_size.checked_mul(3)?
    } else {
        two_ptr
    };

    let mut out = Vec::with_capacity(count);
    for _ in 0..count {
        let init_raw = read_ptr(data, cursor, ptr_size)?;
        let final_off = cursor.checked_add(ptr_size)?;
        let final_raw = read_ptr(data, final_off, ptr_size)?;
        let init_va = (init_raw != 0).then_some(init_raw);
        let finalize_va = (final_raw != 0).then_some(final_raw);
        let unit_name = if with_names {
            let name_off = cursor.checked_add(two_ptr)?;
            let name_ptr = read_ptr(data, name_off, ptr_size)?;
            // The name pointer is the only thing we read indirectly here.
            // If it doesn't resolve, this entry is malformed — surface
            // the failure rather than emit an empty name.
            let name_bytes = read_short_string_at_va(ctx, name_ptr)?;
            str::from_utf8(name_bytes).unwrap_or("<non-ascii>")
        } else {
            "<unknown>"
        };
        out.push(UnitInitProc {
            unit_name,
            init_va,
            finalize_va,
        });
        cursor = cursor.checked_add(entry_size)?;
    }
    Some(out)
}

/// Probe the first `count` entries to decide between the with-names and
/// without-names FPC variants. With-names entries have a third pointer
/// that resolves to a readable shortstring; without-names entries don't
/// have a third pointer at all (the next bytes belong to the following
/// entry's init proc).
fn probe_with_names(
    ctx: &BinaryContext<'_>,
    data: &[u8],
    entries_off: usize,
    count: usize,
    ptr_size: usize,
) -> bool {
    // Sample up to 4 entries at the with-names stride and see if every
    // candidate name pointer resolves to a plausible shortstring.
    let probe_n = count.min(4);
    if probe_n == 0 {
        return false;
    }
    let Some(stride) = ptr_size.checked_mul(3) else {
        return false;
    };
    let Some(two_ptr) = ptr_size.checked_mul(2) else {
        return false;
    };
    for i in 0..probe_n {
        let Some(off) = i
            .checked_mul(stride)
            .and_then(|n| entries_off.checked_add(n))
            .and_then(|n| n.checked_add(two_ptr))
        else {
            return false;
        };
        let Some(name_ptr) = read_ptr(data, off, ptr_size) else {
            return false;
        };
        if name_ptr == 0 {
            return false;
        }
        let Some(bytes) = read_short_string_at_va(ctx, name_ptr) else {
            return false;
        };
        if bytes.is_empty() || !looks_like_unit_name(bytes) {
            return false;
        }
    }
    true
}

fn looks_like_unit_name(bytes: &[u8]) -> bool {
    bytes.len() <= 255
        && bytes
            .iter()
            .all(|b| b.is_ascii_alphanumeric() || *b == b'_' || *b == b'.')
}

/// Heuristic shape scan: sweep the binary's data sections for a
/// pointer-aligned `(count, init_count, then count plausible entries)`
/// layout. Used when the symbol table didn't surface the table
/// (stripped binaries).
///
/// Conservative: requires every init / finalize VA to either be zero
/// or a plausible code VA, AND requires `count == init_count` (the
/// canonical layout where the table has been fully initialised at link
/// time, before the runtime starts mutating `init_count`).
fn locate_initfinal_via_scan<'a>(
    ctx: &BinaryContext<'a>,
    ptr_size: usize,
) -> Option<Vec<UnitInitProc<'a>>> {
    let four_ptr = ptr_size.checked_mul(4)?;
    let two_ptr = ptr_size.checked_mul(2)?;
    for range in ctx.scan_ranges() {
        let Some(slice) = ctx.section_data(range) else {
            continue;
        };
        // Walk pointer-aligned offsets.
        let mut off = 0usize;
        while let Some(window_end) = off.checked_add(four_ptr) {
            if window_end > slice.len() {
                break;
            }
            let Some(count_raw) = read_ptr(slice, off, ptr_size) else {
                break;
            };
            let count = count_raw as usize;
            let Some(init_count_off) = off.checked_add(ptr_size) else {
                break;
            };
            let Some(init_count_raw) = read_ptr(slice, init_count_off, ptr_size) else {
                break;
            };
            let init_count = init_count_raw as usize;
            let Some(entries_off) = off.checked_add(two_ptr) else {
                break;
            };
            if (2..=MAX_UNITS_PER_TABLE).contains(&count)
                && count == init_count
                && entries_look_plausible(ctx, slice, entries_off, count, ptr_size)
            {
                let Some(header_va) = range.va.checked_add(off as u64) else {
                    break;
                };
                if ctx.va_to_file(header_va).is_some()
                    && let Some(out) = walk_initfinal(ctx, header_va, ptr_size)
                    && !out.is_empty()
                {
                    return Some(out);
                }
            }
            let Some(next) = off.checked_add(ptr_size) else {
                break;
            };
            off = next;
        }
    }
    None
}

fn entries_look_plausible(
    ctx: &BinaryContext<'_>,
    slice: &[u8],
    entries_off: usize,
    count: usize,
    ptr_size: usize,
) -> bool {
    // Test up to 4 entries: each `(init, final)` must have at least one
    // pointer that is either 0 or a code VA, and at least one entry in
    // total must have a non-zero pointer (a fully-zero "table" is
    // garbage).
    let Some(stride2) = ptr_size.checked_mul(2) else {
        return false;
    };
    let Some(stride3) = ptr_size.checked_mul(3) else {
        return false;
    };
    for stride in [stride3, stride2] {
        let probe_n = count.min(4);
        let mut any_nonzero = false;
        let mut all_ok = true;
        for i in 0..probe_n {
            let Some(base) = i
                .checked_mul(stride)
                .and_then(|n| entries_off.checked_add(n))
            else {
                all_ok = false;
                break;
            };
            let Some(base_end) = base.checked_add(stride2) else {
                all_ok = false;
                break;
            };
            if base_end > slice.len() {
                all_ok = false;
                break;
            }
            let Some(init_va) = read_ptr(slice, base, ptr_size) else {
                all_ok = false;
                break;
            };
            let Some(final_off) = base.checked_add(ptr_size) else {
                all_ok = false;
                break;
            };
            let Some(final_va) = read_ptr(slice, final_off, ptr_size) else {
                all_ok = false;
                break;
            };
            for va in [init_va, final_va] {
                if va != 0 && !ctx.is_code_va(va) {
                    all_ok = false;
                    break;
                }
                if va != 0 {
                    any_nonzero = true;
                }
            }
            if !all_ok {
                break;
            }
        }
        if all_ok && any_nonzero {
            return true;
        }
    }
    false
}
