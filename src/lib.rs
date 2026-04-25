//! # undelphi: Delphi / C++Builder / Free Pascal binary parser
//!
//! A Rust library for statically analyzing compiled Delphi,
//! C++Builder, and Free Pascal / Lazarus binaries. Given an arbitrary byte
//! slice, `undelphi` identifies whether the binary was produced by one of
//! these toolchains and extracts the rich metadata that their runtimes
//! embed in every executable.
//!
//! ## Motivation
//!
//! Delphi / FPC binaries are unusually rich targets for static analysis.
//! Unlike C/C++ output, stripped Delphi binaries still carry:
//!
//! - **Published class names and unit names** (via the `vmtClassName` field
//!   and `tkClass` RTTI records).
//! - **Published property names, getters, setters, defaults** (the VCL /
//!   Object Inspector depends on these at runtime).
//! - **Form definitions** — entire UI trees, including embedded binaries
//!   (icons, images, scripts) — inside `TPF0` resource streams.
//! - **Package dependency graph** via `PACKAGEINFO`.
//! - **Compiler version** (Delphi 12 Athens reports itself as
//!   `Embarcadero Delphi for Win64 compiler version 36.0`; FPC reports as
//!   `FPC 3.2.2 [2021/05/15] for i386 - Win32`).
//! - **Interface GUIDs**, **virtual method tables**, **dynamic dispatch
//!   tables**, **init/finalization tables**.
//!
//! This metadata survives stripping because the VCL runtime depends on it
//! for form streaming, property inspection, interface dispatch, and package
//! loading. See `RESEARCH.md` for the detailed research notes that inform
//! this crate.
//!
//! ## Feature overview
//!
//! - **Toolchain identification** — Embarcadero Delphi / C++Builder or
//!   Free Pascal / Lazarus; product release name (e.g. `Delphi 12 Athens`);
//!   DVCLAL edition (Personal / Professional / Enterprise).
//! - **Container support** — Windows PE32 / PE32+, macOS Mach-O, Linux ELF.
//! - **Class discovery** — VMT shape-test scanner for both Delphi and FPC
//!   layouts on 32-bit and 64-bit, automatic parent-chain resolution,
//!   indexed by class name and by VMT VA.
//! - **RTTI decoding** — per-Kind decoders for `tkClass`, `tkEnumeration`,
//!   `tkInteger`, `tkChar`, `tkFloat`, `tkSet`, `tkClassRef`, `tkDynArray`,
//!   `tkInterface`, `tkRecord`, `tkMethod`, `tkProcedure`, `tkLString` /
//!   `tkUString` / `tkWString`.
//! - **Class metadata** — published properties (classic + extended-RTTI with
//!   visibility flags), published fields, published methods, virtual method
//!   pointer table, init (managed-fields) table, dynamic / message
//!   dispatch table, interface table with GUID and Corba IIDStr.
//! - **Attributes** — `[attribute]` annotation decoding with constructor
//!   argument extraction (string / integer / raw bytes).
//! - **Form streams** — full TPF0 / TPF1 parser with the complete
//!   `TValueType` set; recursive component tree; symbolic value rendering
//!   against declared RTTI types (e.g. `Align = alClient` instead of
//!   `Align = 2`).
//! - **Package metadata** — `DVCLAL` + `PACKAGEINFO` resource decoders; PE
//!   resource directory walker; Free-Pascal internal-resources
//!   (`fpc.resources` / `.fpc.resources`) tree walker.
//! - **Cross-references** — interface implementors, DFM class
//!   instantiations, event-handler bindings, per-unit aggregate stats,
//!   external-parent reports.
//! - **Instance memory layout** — byte-by-byte reconstruction with
//!   managed-field markers and gap-fill.
//!
//! ## Virtual addresses: code vs data, and RVA conversion
//!
//! Every `…_va` field this crate exposes is an **absolute virtual
//! address** — the value that would appear in the loaded image. PE
//! consumers operating in RVA space must subtract the image base.
//!
//! Fields fall into two categories:
//!
//! | Field | Kind |
//! |-------|------|
//! | [`MethodEntry::code_va`](crate::methods::MethodEntry::code_va) | code (function entry point) |
//! | [`vtable::VirtualMethodEntry::code_va`](crate::vtable::VirtualMethodEntry::code_va) | code |
//! | [`vmttables::DynamicSlot::handler_va`](crate::vmttables::DynamicSlot::handler_va) | code |
//! | [`InterfaceEntry::getter_va`](crate::interfaces::InterfaceEntry::getter_va) | code |
//! | [`InterfaceEntry::vtable_va`](crate::interfaces::InterfaceEntry::vtable_va) | data (pointer-array) |
//! | [`extrtti::AttributeEntry::attr_ctor`](crate::extrtti::AttributeEntry::attr_ctor) | code |
//! | [`extrtti::AttributeEntry::attr_type_ref`](crate::extrtti::AttributeEntry::attr_type_ref) | data (`PPTypeInfo`) |
//! | [`Access::value`](crate::properties::Access::value) when `kind == AccessKind::Static` | code |
//! | [`Access::value`](crate::properties::Access::value) when `kind == AccessKind::Virtual` | **VMT slot index** — *not* a VA. Resolve with [`Access::resolve`](crate::properties::Access::resolve) |
//! | [`Class::vmt_va`](crate::classes::Class::vmt_va) | data (VMT base) |
//! | [`vtable::VirtualMethodEntry::slot_va`](crate::vtable::VirtualMethodEntry::slot_va) | data (slot storage in VMT) |
//! | [`Property::prop_type_ref`](crate::properties::Property::prop_type_ref) | data (`PPTypeInfo`) |
//!
//! For a complete enumeration of code entrypoints, see
//! [`DelphiBinary::code_entrypoints`].
//!
//! ## Robustness contract
//!
//! Every parser in this crate treats its input as untrusted: parsers
//! return `Option<T>` / empty `Vec`s on malformed or adversarial input
//! rather than panic. The `clippy::unwrap_used` / `clippy::expect_used`
//! / `clippy::panic` lints are denied crate-wide in library code; the
//! `tests/malformed.rs` regression suite exercises every public
//! entrypoint against truncated / all-zero / all-0xFF / randomised /
//! impossible-length inputs.
//!
//! ## Quick start
//!
//! ```no_run
//! use undelphi::DelphiBinary;
//!
//! let bytes = std::fs::read("my_app.exe").unwrap();
//! if let Ok(bin) = DelphiBinary::parse(&bytes) {
//!     if let Some(info) = bin.compiler() {
//!         println!("Compiler: {:?} v{:?} ({:?} {:?})", info.compiler, info.version, info.os, info.arch);
//!     }
//!     if let Some(ed) = bin.edition() {
//!         println!("Edition: {:?}", ed);
//!     }
//!     if let Some(pkg) = bin.package_info() {
//!         println!("{} units, {} required packages",
//!             pkg.contains.len(), pkg.requires.len());
//!     }
//! }
//! ```

// This crate is used for malware analysis: every input byte is
// adversarial and must not be allowed to panic the parser.
#![deny(
    missing_docs,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::arithmetic_side_effects,
    clippy::indexing_slicing
)]
#![cfg_attr(
    test,
    allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        clippy::arithmetic_side_effects,
        clippy::indexing_slicing
    )
)]

pub mod blobs;
pub mod classes;
pub mod detection;
pub mod dfm;
pub mod dvclal;
pub mod entrypoints;
pub mod extrtti;
pub mod fields;
pub mod formats;
pub mod fpcresources;
pub mod initfini;
pub mod interfaces;
pub mod layout;
pub mod limits;
pub mod methods;
pub mod packageinfo;
pub mod properties;
pub mod render;
pub mod resources;
pub mod rtti;
pub mod vmt;
pub mod vmttables;
pub mod vtable;
pub mod xref;

pub(crate) mod util;

/// Emit a warning event when the `tracing` feature is enabled. No-op
/// otherwise — keeps `tracing` strictly opt-in.
#[macro_export]
#[doc(hidden)]
macro_rules! __undelphi_trace_warn {
    ($($arg:tt)*) => {
        #[cfg(feature = "tracing")]
        {
            ::tracing::warn!($($arg)*);
        }
    };
}

use std::{collections::HashSet, fmt, sync::OnceLock};

use crate::{
    blobs::{EmbeddedBlob, catalog as catalog_blobs},
    classes::{Class, ClassSet},
    detection::{Compiler, CompilerInfo, Confidence, DetectionReport, TargetArch, TargetOs},
    dfm::DfmObject,
    dvclal::Edition,
    fields::Field,
    formats::{BinaryContext, BinaryFormat},
    interfaces::InterfaceEntry,
    methods::MethodEntry,
    packageinfo::PackageInfo,
    properties::Property,
    resources::{find_rcdata, iter_rcdata_named},
    rtti::TkClassInfo,
};

/// Why [`DelphiBinary::parse`] failed.
///
/// Use this to decide log severity. `NotRecognized` is the common, quiet
/// case — non-Delphi binaries land here. The other variants represent
/// actually broken or unfamiliar input and are usually worth surfacing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum ParseError {
    /// Container parsed cleanly but no Delphi / C++Builder / FPC markers
    /// were found. Expected on non-Delphi binaries; safe to ignore.
    NotRecognized,
    /// A recognised container magic (`MZ`, `\x7fELF`, Mach-O) is present
    /// but goblin failed to walk the headers. Either the file is truncated
    /// or the headers are deliberately malformed (some packers do this).
    TruncatedContainer,
    /// The input does not start with any container magic this crate knows
    /// how to handle. Heuristic scans still ran but found nothing.
    UnrecognizedFormat,
}

impl fmt::Display for ParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ParseError::NotRecognized => f.write_str("no Delphi / C++Builder / FPC markers found"),
            ParseError::TruncatedContainer => {
                f.write_str("container magic present but headers could not be parsed")
            }
            ParseError::UnrecognizedFormat => {
                f.write_str("input has no recognised container magic")
            }
        }
    }
}

impl std::error::Error for ParseError {}

/// A parsed Delphi / C++Builder / FPC binary.
///
/// Created via [`DelphiBinary::parse`]. Owns a borrowed reference to the
/// input byte slice; everything returned by accessor methods ultimately
/// points back into that slice.
#[derive(Debug)]
pub struct DelphiBinary<'a> {
    ctx: BinaryContext<'a>,
    confidence: Confidence,
    compiler: Option<CompilerInfo<'a>>,
    edition: Option<Edition>,
    package_info: Option<PackageInfo<'a>>,
    tpf0_count: usize,
    classes: ClassSet<'a>,
    /// Lazy-initialised list of every parsed DFM/FMX/LFM/XFM form. Built on
    /// first call to [`DelphiBinary::forms`] and reused by every later call
    /// (including the xref views, which would otherwise re-parse every form
    /// on every access).
    forms_cache: OnceLock<Vec<(String, DfmObject<'a>)>>,
    /// Lazy-initialised binary-wide index of FPC `tkInterface` records,
    /// keyed by GUID. Built on first call to
    /// [`DelphiBinary::interface_methods`] and reused thereafter.
    /// Empty on Delphi binaries (Delphi's classic `tkInterface` doesn't
    /// carry the method-name table this index is for).
    tkinterface_index: OnceLock<std::collections::HashMap<interfaces::Guid, u64>>,
}

impl<'a> DelphiBinary<'a> {
    /// Analyze a byte slice.
    ///
    /// Runs detection in order of decreasing reliability:
    ///
    /// 1. Embarcadero / FPC build-string scan (High confidence).
    /// 2. `DVCLAL` resource lookup via the PE resource walker (High).
    /// 3. `PACKAGEINFO` resource lookup (High).
    /// 4. `TPF0` occurrence count (Medium).
    ///
    /// A match at any level above `Low` succeeds. Otherwise the call returns
    /// a [`ParseError`] describing why detection failed:
    ///
    /// - [`ParseError::NotRecognized`] — the input is a valid container but
    ///   carries no Delphi/FPC markers. Expected on non-Delphi binaries; safe
    ///   to swallow without logging.
    /// - [`ParseError::TruncatedContainer`] — a recognised container magic is
    ///   present but goblin failed to walk the headers (truncated PE / ELF /
    ///   Mach-O). Worth logging.
    /// - [`ParseError::UnrecognizedFormat`] — the input has no known
    ///   container magic at all. Worth logging if you expected an executable.
    pub fn parse(data: &'a [u8]) -> Result<Self, ParseError> {
        let ctx = BinaryContext::new(data);
        let DetectionReport {
            mut confidence,
            compiler_info: compiler,
            tpf0_count,
        } = detection::analyze(&ctx);

        let edition = find_rcdata(&ctx, "DVCLAL").and_then(|e| dvclal::decode(e.data));
        if edition.is_some() {
            confidence = Confidence::High;
        }

        let package_info =
            find_rcdata(&ctx, "PACKAGEINFO").and_then(|e| packageinfo::parse(e.data));
        if package_info.is_some() {
            confidence = Confidence::High;
        }

        let classes = ClassSet::from_ctx(&ctx);
        // Finding any VMTs is independent structural proof — elevate
        // confidence so that stripped FPC/Mach-O binaries (which lack
        // DVCLAL / PACKAGEINFO / build-strings) can still be detected.
        if !classes.is_empty() && confidence < Confidence::Medium {
            confidence = Confidence::Medium;
        }

        if confidence == Confidence::None {
            return Err(if ctx.format() == BinaryFormat::Unknown {
                ParseError::UnrecognizedFormat
            } else if !ctx.container_parsed() {
                ParseError::TruncatedContainer
            } else {
                ParseError::NotRecognized
            });
        }

        Ok(Self {
            ctx,
            confidence,
            compiler,
            edition,
            package_info,
            tpf0_count,
            classes,
            forms_cache: OnceLock::new(),
            tkinterface_index: OnceLock::new(),
        })
    }

    /// Detected executable container format.
    #[inline]
    pub fn format(&self) -> BinaryFormat {
        self.ctx.format()
    }

    /// Overall confidence in the detection.
    #[inline]
    pub fn confidence(&self) -> Confidence {
        self.confidence
    }

    /// Parsed compiler build string, when present.
    #[inline]
    pub fn compiler(&self) -> Option<&CompilerInfo<'a>> {
        self.compiler.as_ref()
    }

    /// Compiler family (Delphi / C++Builder / FPC), if identified.
    #[inline]
    pub fn compiler_kind(&self) -> Option<Compiler> {
        self.compiler.as_ref().map(|c| c.compiler)
    }

    /// Target operating system. Prefers the value from the parsed compiler
    /// build-string when available; otherwise falls back to container-level
    /// inference (PE → Windows, Mach-O → Darwin, ELF → Linux).
    pub fn target_os(&self) -> TargetOs {
        if let Some(info) = &self.compiler
            && info.os != TargetOs::Unknown
        {
            return info.os;
        }
        self.ctx.target_os()
    }

    /// Target architecture. Prefers the value from the parsed compiler
    /// build-string when available; otherwise falls back to the
    /// container-level machine code (PE `Machine`, ELF `e_machine`,
    /// Mach-O `cputype`).
    pub fn target_arch(&self) -> TargetArch {
        if let Some(info) = &self.compiler
            && info.arch != TargetArch::Unknown
        {
            return info.arch;
        }
        self.ctx.target_arch()
    }

    /// Delphi / C++Builder SKU (Personal / Professional / Enterprise), if the
    /// `DVCLAL` resource is present and decodable.
    #[inline]
    pub fn edition(&self) -> Option<Edition> {
        self.edition
    }

    /// Parsed PACKAGEINFO resource, if present.
    #[inline]
    pub fn package_info(&self) -> Option<&PackageInfo<'a>> {
        self.package_info.as_ref()
    }

    /// Number of `TPF0` magic occurrences — a proxy for the number of form
    /// resources embedded in the binary.
    #[inline]
    pub fn tpf0_count(&self) -> usize {
        self.tpf0_count
    }

    /// All classes discovered by scanning VMTs in the read-only-data section.
    #[inline]
    pub fn classes(&self) -> &ClassSet<'a> {
        &self.classes
    }

    /// Decode the `tkClass` RTTI record referenced by `class.vmt.type_info`.
    ///
    /// Returns `None` when the class carries no RTTI (stripped, or compiled
    /// without `{$M+}` equivalent), when the record cannot be parsed, or
    /// when the Kind byte is not `tkClass`.
    pub fn tkclass(&self, class: &Class<'a>) -> Option<TkClassInfo<'a>> {
        TkClassInfo::from_vmt(&self.ctx, &class.vmt)
    }

    /// Unit name of the class (the Pascal unit the class was declared in),
    /// extracted from the `tkClass` RTTI. Returns `None` when no RTTI.
    pub fn unit_name(&self, class: &Class<'a>) -> Option<&'a str> {
        self.tkclass(class).map(|c| c.unit_name())
    }

    /// Decode the class's published-method table.
    ///
    /// Returns an empty vector when the class has no method table.
    pub fn methods(&self, class: &Class<'a>) -> Vec<MethodEntry<'a>> {
        MethodEntry::iter(&self.ctx, &class.vmt)
    }

    /// Decode the class's interface table.
    pub fn interfaces(&self, class: &Class<'a>) -> Vec<InterfaceEntry<'a>> {
        InterfaceEntry::iter(&self.ctx, &class.vmt)
    }

    /// Iterate the method-pointer array referenced by an
    /// [`InterfaceEntry::vtable_va`], populating method names from
    /// the matching `tkInterface` RTTI when reachable.
    ///
    /// Slot count + code VAs come from a vtable walk that terminates
    /// at the first slot that doesn't contain a plausible code VA
    /// (zero, unmapped, or outside the binary's `.text` / `__text` /
    /// `CODE` section) — works on both Delphi and FPC, including
    /// stripped binaries.
    ///
    /// Method *names* come from a binary-wide index of FPC
    /// `tkInterface` RTTI records keyed by GUID, built lazily on
    /// first call. Delphi's classic `tkInterface` records don't
    /// carry method names, so on Delphi binaries the `name` field
    /// stays `None`.
    pub fn interface_methods(
        &self,
        entry: &InterfaceEntry<'a>,
    ) -> Vec<interfaces::InterfaceMethod<'a>> {
        let ptr_size = self.ctx.pointer_size().unwrap_or(
            self.classes
                .iter()
                .next()
                .map_or(0, |c| c.pointer_size() as usize),
        );
        if ptr_size == 0 {
            return Vec::new();
        }
        let mut methods = interfaces::InterfaceMethod::iter(&self.ctx, entry, ptr_size);
        // Try to populate names from the FPC tkInterface index.
        let index = self
            .tkinterface_index
            .get_or_init(|| rtti::scan_fpc_tkinterface_index(&self.ctx));
        if let Some(&tkintf_va) = index.get(&entry.guid)
            && let Some(table) = rtti::IntfMethodTable::from_tkinterface(&self.ctx, tkintf_va)
        {
            for rtti_entry in table.entries() {
                if let Some(m) = methods.get_mut(rtti_entry.slot() as usize) {
                    m.name = Some(rtti_entry.name());
                }
            }
        }
        methods
    }

    /// Decode the virtual-method-pointer array that follows the class's
    /// VMT header. One entry per user-declared (or inherited) virtual
    /// method slot.
    pub fn virtual_methods(&self, class: &Class<'a>) -> Vec<vtable::VirtualMethodEntry> {
        let bound = vtable::VirtualMethodEntry::upper_bound_for(&self.classes, &class.vmt);
        vtable::VirtualMethodEntry::iter(&self.ctx, &class.vmt, bound)
    }

    /// Decode the class's init (managed-fields) table — the list of
    /// instance offsets the runtime needs to refcount-manage.
    pub fn init_table(&self, class: &Class<'a>) -> Option<rtti::RecordInfo<'a>> {
        rtti::RecordInfo::from_init_table(&self.ctx, &class.vmt)
    }

    /// Decode the class's dynamic-dispatch table (message handlers +
    /// `dynamic` method slots).
    pub fn dynamic_slots(&self, class: &Class<'a>) -> Vec<vmttables::DynamicSlot> {
        vmttables::DynamicSlot::iter(&self.ctx, &class.vmt)
    }

    /// Walk the extended-RTTI property table for `class` — includes
    /// non-published members (private / protected / public) with their
    /// visibility flags and attached attribute bytes.
    pub fn extended_properties(&self, class: &Class<'a>) -> Vec<extrtti::ExtendedProperty<'a>> {
        extrtti::ExtendedProperty::iter(&self.ctx, class)
    }

    /// Walk the FPC `INITFINAL` table to recover per-unit
    /// `initialization` / `finalization` procedure VAs.
    ///
    /// Located via symbol lookup (`INITFINAL` / `_INITFINAL` /
    /// `FPC_INITFINAL` in ELF symtab, Mach-O `LC_SYMTAB`, or PE export
    /// table) with a heuristic shape scan over data sections as a
    /// fallback for stripped builds. See [`initfini`] for layout
    /// details.
    ///
    /// Delphi binaries return an empty vector: the Delphi RTL inlines
    /// per-unit init/finalize calls directly into the entry-point
    /// startup sequence rather than emitting a discoverable table, so
    /// recovering them statically would require disassembly of the
    /// program entry point — outside this crate's scope. Delphi
    /// consumers that need the unit *list* (without VAs) can read it
    /// from [`DelphiBinary::package_info`].
    pub fn unit_init_procs(&self) -> Vec<initfini::UnitInitProc<'a>> {
        initfini::iter_unit_init_procs(&self.ctx)
    }

    /// Aggregate every code address this crate can confidently label —
    /// published methods, virtual-method slots, dynamic-message handlers,
    /// interface getters and methods, property accessors (with
    /// `AccessKind::Virtual` slots resolved to code VAs), attribute
    /// constructors, and unit init / finalize procedures.
    ///
    /// Duplicates are emitted across [`entrypoints::EntrypointKind`]
    /// variants when the same VA is reached via more than one path; the
    /// caller dedups by their preferred priority.
    ///
    /// See the
    /// [`entrypoints`] module docs for kind semantics. This is the
    /// one-stop helper meant to replace the ~100 LoC of glue every
    /// disassembler-driving consumer would otherwise write.
    pub fn code_entrypoints(&'a self) -> Vec<entrypoints::CodeEntrypoint<'a>> {
        entrypoints::collect(self)
    }

    /// Decode the class-level attribute table for `class`, when one is
    /// present.
    ///
    /// Walks past the classic `TPropData` and the extended-property
    /// block to find the `AttrData` trailer, then decodes its packed
    /// attribute entries. The walker is layout-driven, not
    /// flavor-gated: it returns whatever the trailer actually contains.
    /// In practice that means:
    ///
    /// - Modern Delphi (XE3+) classes that declare `[Attribute]`
    ///   annotations: returns the decoded entries.
    /// - Older Delphi, classes compiled with `{$RTTI EXPLICIT}`
    ///   suppression, or FPC < 3.3 (no `PROVIDE_ATTR_TABLE`): returns
    ///   an empty vector — the trailer either isn't there or has a
    ///   shape we don't recognise.
    /// - Classes with no attributes: returns an empty vector.
    pub fn class_attributes(&self, class: &Class<'a>) -> Vec<extrtti::AttributeEntry<'a>> {
        extrtti::AttributeEntry::iter_class(&self.ctx, class)
    }

    /// Look up a published method by name on `class`, walking the
    /// ancestry chain so inherited handlers are found. Returns the
    /// method's code VA, or `None` when unresolved.
    pub fn resolve_event_handler(&self, class: &Class<'a>, method_name: &str) -> Option<u64> {
        let mut walker: Option<&Class<'a>> = Some(class);
        while let Some(c) = walker {
            for m in self.methods(c) {
                if m.name().eq_ignore_ascii_case(method_name) {
                    return Some(m.code_va);
                }
            }
            walker = c.parent_index.and_then(|idx| self.classes.get(idx));
        }
        None
    }

    /// Decode the class's published-property table.
    ///
    /// Iterates the `TPropData` block that follows the class's tkClass
    /// TypeData `UnitName`. Returns an empty vector when the class has no
    /// RTTI (stripped binary, or class compiled without `{$M+}`).
    pub fn properties(&self, class: &Class<'a>) -> Vec<Property<'a>> {
        Property::iter(&self.ctx, &class.vmt)
    }

    /// Resolve the declared type of a property from its `PropType` pointer.
    ///
    /// Returns `None` when the pointer is null or the referenced type info
    /// cannot be decoded (e.g. stripped or modern-extended RTTI we don't
    /// yet walk).
    pub fn property_type(
        &self,
        class: &Class<'a>,
        prop: &Property<'a>,
    ) -> Option<rtti::TypeHeader<'a>> {
        rtti::TypeHeader::from_pptr(
            &self.ctx,
            prop.prop_type_ref,
            class.vmt.pointer_size as usize,
            class.vmt.flavor,
        )
    }

    /// Resolve the declared type of a field from its `TypeInfoPtr`.
    pub fn field_type(&self, class: &Class<'a>, field: &Field<'a>) -> Option<rtti::TypeHeader<'a>> {
        match field.type_ref {
            fields::FieldTypeRef::TypeInfoPtr(pptr) => rtti::TypeHeader::from_pptr(
                &self.ctx,
                pptr,
                class.vmt.pointer_size as usize,
                class.vmt.flavor,
            ),
            fields::FieldTypeRef::TypeIndex(_) => None, // legacy: would need field-classes table
        }
    }

    /// Decode an enumeration type at `type_info_va` into its element
    /// names and min/max bounds.
    pub fn decode_enum(
        &self,
        type_info_va: u64,
        flavor: detection::Compiler,
    ) -> Option<rtti::EnumInfo<'a>> {
        let flavor = match flavor {
            detection::Compiler::FreePascal => vmt::VmtFlavor::Fpc,
            _ => vmt::VmtFlavor::Delphi,
        };
        rtti::EnumInfo::from_va(&self.ctx, type_info_va, flavor)
    }

    /// Pick the `VmtFlavor` matching this binary's toolchain.
    pub fn flavor(&self) -> vmt::VmtFlavor {
        match self.compiler_kind() {
            Some(detection::Compiler::FreePascal) => vmt::VmtFlavor::Fpc,
            _ => vmt::VmtFlavor::Delphi,
        }
    }

    /// Full per-Kind RTTI decode for the type referenced by a property's
    /// `PropType` pointer.
    pub fn property_type_detail(
        &self,
        class: &Class<'a>,
        prop: &Property<'a>,
    ) -> Option<rtti::TypeDetail<'a>> {
        let ptr_size = class.vmt.pointer_size as usize;
        let type_info_va =
            rtti::TypeHeader::deref_pptypeinfo(&self.ctx, prop.prop_type_ref, ptr_size)?;
        rtti::TypeDetail::from_va(&self.ctx, type_info_va, class.vmt.flavor)
    }

    /// Full per-Kind RTTI decode for the type referenced by a field.
    pub fn field_type_detail(
        &self,
        class: &Class<'a>,
        field: &Field<'a>,
    ) -> Option<rtti::TypeDetail<'a>> {
        let ptr_size = class.vmt.pointer_size as usize;
        match field.type_ref {
            fields::FieldTypeRef::TypeInfoPtr(pptr) => {
                let type_info_va = rtti::TypeHeader::deref_pptypeinfo(&self.ctx, pptr, ptr_size)?;
                rtti::TypeDetail::from_va(&self.ctx, type_info_va, class.vmt.flavor)
            }
            fields::FieldTypeRef::TypeIndex(_) => None,
        }
    }

    /// Decode the class's published-field table.
    ///
    /// Returns an empty vector when the class declares no published fields
    /// (many classes don't) or the table is malformed.
    pub fn fields(&self, class: &Class<'a>) -> Vec<Field<'a>> {
        Field::iter(&self.ctx, &class.vmt)
    }

    /// Decode every DFM / FMX / LFM / XFM form stream embedded as a
    /// resource. Combines two source paths:
    ///
    /// - PE `RT_RCDATA` resources (Delphi / C++Builder / FPC Windows).
    /// - FPC internal-resources tree (Mach-O / ELF, plus some FPC builds
    ///   on Windows that disable `FPC_HAS_WINLIKERESOURCES`).
    ///
    /// A raw `TPF0` / `TPF1` magic-byte fallback for stripped or
    /// unconventionally-packaged binaries is tracked in `TODO.md` but not
    /// yet implemented.
    ///
    /// Duplicates are de-duplicated by resource name. The result is cached
    /// on `self`, so repeated calls (e.g. from multiple `xref::*` views)
    /// don't re-walk and re-parse every resource.
    pub fn forms(&self) -> &[(String, DfmObject<'a>)] {
        self.forms_cache.get_or_init(|| self.extract_forms())
    }

    fn extract_forms(&self) -> Vec<(String, DfmObject<'a>)> {
        let mut out: Vec<(String, DfmObject<'a>)> = Vec::new();
        let mut seen_names: HashSet<String> = HashSet::new();

        // 1. PE RCDATA.
        for (name, body) in iter_rcdata_named(&self.ctx) {
            let Some(magic) = body.data.get(..4) else {
                continue;
            };
            if magic != dfm::TPF0_MAGIC && magic != dfm::TPF1_MAGIC {
                continue;
            }
            if let Some(obj) = DfmObject::parse(body.data)
                && seen_names.insert(name.clone())
            {
                out.push((name, obj));
            }
        }

        // 2. FPC tree.
        for r in fpcresources::iter_rcdata(&self.ctx) {
            let Some(magic) = r.data.get(..4) else {
                continue;
            };
            if magic != dfm::TPF0_MAGIC && magic != dfm::TPF1_MAGIC {
                continue;
            }
            let name = r
                .name
                .clone()
                .unwrap_or_else(|| format!("#{}", r.name_id.unwrap_or(0)));
            if let Some(obj) = DfmObject::parse(r.data)
                && seen_names.insert(name.clone())
            {
                out.push((name, obj));
            }
        }

        out
    }

    /// Walk every parsed form and surface every embedded `vaBinary` blob,
    /// classified by magic bytes (PNG / JPEG / ZIP / PE / Mach-O / ICO /
    /// BMP / etc. — see [`blobs::BlobKind`]).
    ///
    /// Useful for malware triage: every blob carries the form resource it
    /// came from, the dotted path of the component property that holds it,
    /// the blob bytes (borrowed from the input), and a magic-byte
    /// classification.
    ///
    /// Allocates a `Vec<EmbeddedBlob>`. Each blob carries borrowed
    /// references into the cached form tree (`component`, `property`),
    /// so consumers can attach blobs to their owning components without
    /// re-walking. The blob payloads themselves are not copied.
    pub fn blobs(&self) -> Vec<EmbeddedBlob<'a, '_>> {
        catalog_blobs(self.forms())
    }

    /// Access the low-level binary context (sections, VA mapping, segments).
    #[inline]
    pub fn ctx(&self) -> &BinaryContext<'a> {
        &self.ctx
    }
}

const _: fn() = || {
    fn assert_send_sync<T: Send + Sync>() {}
    assert_send_sync::<DelphiBinary<'_>>();
};
