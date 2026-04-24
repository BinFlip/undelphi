//! Plausibility caps applied across the parser.
//!
//! Every parser in this crate that reads a length / count from the binary
//! checks the value against a cap before allocating or iterating. Without
//! caps, a misaligned read that interprets random data as a count would
//! easily request gigabytes of allocation or run the parser into garbage
//! for thousands of iterations. The caps below are the single source of
//! truth — modules consume them via `crate::limits::*` rather than
//! redeclaring inline literals.
//!
//! ## How the values were chosen
//!
//! Every cap is grounded in **either** an empirical maximum measured by
//! `examples/cap_audit.rs` against the sample corpus under
//! `tests/samples/`, **or** an authoritative value cited from
//! `reference/`. Headroom over the empirical max is generous (typically
//! 4–10×) because the corpus is small and a future Delphi/FPC binary may
//! legitimately exceed today's max. The audit run informing these
//! constants was captured during Phase 4 of the cleanup work; re-run
//! `cargo run --release --example cap_audit` to refresh.
//!
//! ## When to tighten / loosen
//!
//! - **Tighten** when a new audit run shows you have ≥10× headroom
//!   AND no plausible Delphi/FPC RTL extension would push the value up.
//! - **Loosen** the moment a real binary fails to parse because the cap
//!   rejected legit data — empirical reality always wins. Update the
//!   `Empirical max` line in the doc-comment when you do.

// ---------------------------------------------------------------------------
// Identifier shape
// ---------------------------------------------------------------------------

/// Maximum class-name byte length, including generics.
///
/// Set to the **physical maximum** a `ShortString` can encode (`255` —
/// the length prefix is a `u8`). Empirical max in the current corpus is
/// 128 bytes (`TEnumerator<System.Generics.Collections.TPair<System.
/// Messaging.TMessageListener,System.Messaging.TMessageManager.
/// TListenerData>>` in heidisql_x64, 2026-04 cap_audit run) — the cap
/// previously matched that exactly with **zero headroom**, which would
/// silently reject the next deeper level of generic nesting. 255 is the
/// largest value that can ever land in a `ShortString` body, so any
/// further loosening would require changing the on-disk format.
pub const MAX_CLASS_NAME_BYTES: usize = 255;

/// Maximum identifier byte length applied to unit names, field names,
/// property names, enum element names, etc. Same physical-maximum
/// reasoning as [`MAX_CLASS_NAME_BYTES`].
pub const MAX_IDENTIFIER_BYTES: usize = 255;

// ---------------------------------------------------------------------------
// VMT shape
// ---------------------------------------------------------------------------

/// Minimum number of pointer-sized slots between a Delphi VMT base and the
/// `vmtSelfPtr` target. Sourced verbatim from ESET DelphiHelper's
/// shape-test in
/// `reference/DelphiHelper/DelphiHelper/core/DelphiClass.py:163-167`
/// (`offset / processorWordSize < 5` rejects the candidate). The header
/// cannot be shorter than the 5-pointer minimum across the Delphi version
/// range we target.
pub const DELPHI_MIN_HEADER_SLOTS: u64 = 5;

/// Maximum number of pointer-sized header slots. Same source line range
/// as [`DELPHI_MIN_HEADER_SLOTS`] (`offset / processorWordSize > 30`
/// rejects the candidate). 30 slots covers Delphi 1 → Delphi 12 Athens
/// with margin.
pub const DELPHI_MAX_HEADER_SLOTS: u64 = 30;

/// Maximum plausible instance size, in bytes. Empirical max in corpus:
/// 286 968 B (`TSynFoxproSyn` in heidisql_x64). 4 MiB gives ~14× headroom
/// while still rejecting the multi-gigabyte values a misaligned read
/// would yield on a 64-bit pointer slot.
pub const MAX_INSTANCE_SIZE_BYTES: u64 = 4 * 1024 * 1024;

// ---------------------------------------------------------------------------
// Per-class table sizes
// ---------------------------------------------------------------------------

/// Maximum entries in a Delphi published-method table.
/// Empirical max: 321 (`TMainForm` in heidisql_x64). 1024 leaves ~3.2×
/// headroom; tighter than the historical 4096 because the audit shows no
/// legit class comes close.
pub const MAX_METHODS_PER_CLASS: usize = 1024;

/// Maximum entries in an FPC published-method table. FPC's `LongWord`
/// count theoretically allows up to 4 billion; we cap considerably lower
/// for the same misalignment-rejection reason. 4096 vs Delphi's 1024
/// because FPC component libraries (LCL) historically pack more methods.
pub const MAX_METHODS_PER_CLASS_FPC: usize = 4096;

/// Maximum entries in a published-field table. Empirical max: 612
/// (`TMainForm` in heidisql_macOS). 4096 retains the historical cap; the
/// audit doesn't justify aggressive tightening because FPC fields can be
/// substantially larger than Delphi's.
pub const MAX_FIELDS_PER_CLASS: usize = 4096;

/// Maximum entries in a `TPropData` block (classic published-property
/// table). Empirical max: 234 (`TVirtualStringTree` in heidisql_x64).
/// 1024 leaves ~4.4× headroom.
pub const MAX_PROPERTIES_PER_CLASS: usize = 1024;

/// Maximum entries in the extended-RTTI property table.
/// Empirical max: 238 (`TVirtualStringTree` in heidisql_x64).
pub const MAX_EXTENDED_PROPERTIES_PER_CLASS: usize = 1024;

/// Maximum entries in a Delphi interface table. Empirical max: 7
/// (`TFDPhysCommand` in heidisql_x64). 256 leaves enormous headroom; we
/// keep it that high because no class in our corpus exercises COM-heavy
/// inheritance.
pub const MAX_INTERFACES_PER_CLASS: usize = 256;

/// Maximum entries in an FPC interface table.
pub const MAX_INTERFACES_PER_CLASS_FPC: usize = 1024;

/// Maximum entries in a dynamic-dispatch / message handler table.
/// Empirical max: 123 (`TWinControl` in heidisql_x64). 512 ≈ 4× headroom.
pub const MAX_DYNAMIC_SLOTS_PER_CLASS: usize = 512;

/// Maximum entries in the init-table managed-fields list (the synthetic
/// `tkRecord` reachable through `vmtInitTable`). Empirical max: 32
/// (`TFLACfile` in lightalloy / Delphi 7). 256 keeps headroom for classes
/// holding many string / interface / dynamic-array fields.
pub const MAX_INIT_MANAGED_FIELDS: usize = 256;

// ---------------------------------------------------------------------------
// Per-Kind RTTI sizes
// ---------------------------------------------------------------------------

/// Maximum formal parameters in a `tkMethod` record. Empirical max: 10
/// (`TLVDataFindEvent` in doublecmd). Pascal language limit is 255 but
/// real-world events are tiny. 32 caps misalignment rejection cheaply.
pub const MAX_METHOD_PARAMS: usize = 32;

/// Maximum range (`max - min`) of a `tkEnumeration`. Empirical max: 67
/// (`TThemedScrollBar` in heidisql_xe5_unpacked). 512 ≈ 7.6× headroom.
pub const MAX_ENUM_RANGE: i64 = 512;

/// Maximum entries in a `tkRecord` managed-fields list. Empirical max:
/// 13 (`TFormatSettings` in heidisql_xe5_unpacked). 256 ≈ 20× headroom.
pub const MAX_RECORD_MANAGED_FIELDS: usize = 256;

// ---------------------------------------------------------------------------
// FPC resources
// ---------------------------------------------------------------------------

/// Maximum siblings under a single node of the FPC internal-resources
/// tree. Not audited (the resource walker doesn't expose per-node
/// sibling counts), so we keep the historical 32 768 — generous enough
/// that legitimate trees never approach it.
pub const MAX_FPC_RESOURCE_SIBLINGS: usize = 32_768;
