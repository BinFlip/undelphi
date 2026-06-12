# Changelog

## 0.3.0

Capability release. The headline is **`DelphiBinary::types()`**, a complete
RTTI type dictionary, plus **method-signature decoding** and a wave of new
per-Kind RTTI detail. Two real decoding bugs affecting FPC on x86-64 ELF /
Mach-O and FPC event-type signatures are fixed. Container coverage gains its
first Linux ELF and macOS x86-64 Mach-O test binaries.

### Added

- **`DelphiBinary::types()`** — enumerate every RTTI type record in the
  binary, not just the ones hanging off a class. It runs a transitive
  closure over `PPTypeInfo` references (class parents, property / field
  types, method-signature param/return types, extended-property types, enum
  base types, set/array/dynarray element types, pointer targets, record
  fields, interface parents) and then, on Delphi, a **self-cell pass** (every
  Delphi `PTypeInfo` is preceded by a self-referencing `PPTypeInfo` cell —
  the `vmtSelfPtr` analogue) that recovers types referenced only from code.
  Reaches ~97 % of all `PTypeInfo` in a Delphi image (e.g. the enum
  dictionary on HeidiSQL 12 grows from ~250 to ~880). Returns
  `Vec<TypeDetail>`; bounded by `limits::MAX_RTTI_TYPES`.
- **Method signatures** — `DelphiBinary::method_signatures(class)` returns an
  era-tagged `signatures::SignatureReport` (`Decoded` / `Absent` /
  `Unsupported`) of `MethodSignature` (name, `MethodKind`, `CallConv`, ordered
  `MethodParam`s with name / resolved type / `ParamMode`, return type, code
  VA). Sources: the Delphi 2010+ extended-method section of the
  `vmtMethodTable` (the primary source) and the published-method trailer
  (`{$METHODINFO ON}`). New `signatures` module.
- **New / richer RTTI decoders** (all reachable via `types()` and
  `rtti::TypeDetail`):
  - `tkPointer` and `tkArray` now decode (`TypeDetail::Pointer` / `Array`
    with `PointerInfo` / `ArrayInfo` and their target / element types).
  - `RecordInfo::fields` — the full Delphi 2010+ record field table (every
    field's name, resolved type, offset, and visibility flags), not just
    managed fields. New `rtti::RecordField`.
  - `ProcedureInfo` now decodes its inline `TProcedureSignature` (calling
    convention, parameters, return type) instead of just the header. New
    `rtti::SignatureParam`.
  - `MethodInfo::param_type_refs` / `result_type_ref` — the modern `tkMethod`
    per-parameter `PPTypeInfo` references (cross-validated against the
    name-based parameter types).
  - `TypeDetail::referenced_pptrs()` — the onward type references a record
    points at.
- **`forms()` raw-magic fallback** — when the PE `RT_RCDATA` and FPC
  internal-resources passes find nothing, `forms()` now scans for `TPF0` /
  `TPF1` streams and re-parses each candidate, recovering forms from stripped
  or unconventionally-packaged binaries. New `dfm::scan_streams`.
- `detection::TargetArch::fpc_requires_proper_alignment()`.
- `examples/corpus_scan` — a re-runnable bulk triage / regression tool that
  reports parse outcomes, compiler / format histograms, and extraction
  anomalies across a directory tree.
- First Linux ELF (`doublecmd` gtk2 x86-64, FPC) and macOS x86-64 Mach-O
  (`doublecmd` cocoa, FPC) test binaries, with integration tests.

### Fixed

- **FPC `TTypeData` alignment on x86-64 ELF / Mach-O.** The decoder gated
  natural-alignment on "is this *not* PE?" rather than on the architecture,
  so it inserted phantom padding on x86-64 ELF / Mach-O (which FPC packs).
  Every unit name and field table on those targets decoded to garbage. Now
  keyed on `TargetArch` (`FPC_REQUIRES_PROPER_ALIGNMENT` is an
  ARM/AArch64/PPC/SPARC property). Recovers ~2 500 unit names and the field
  tables on the new ELF / Mach-O x86-64 test binaries.
- **FPC `tkMethod` parameter flags.** FPC's `TParamFlag` is a 12-element set
  (2 bytes); Delphi's is 7 (1 byte). The decoder read 1 byte for both,
  shifting every following field and garbling FPC event-type signatures
  (`TNotifyEvent` etc.). Now flavor-dependent.

### Breaking changes

- **`rtti::TypeDetail` is now `#[non_exhaustive]`** and gains `Pointer` and
  `Array` variants. Exhaustive matches must add a wildcard arm. Marking the
  enum non-exhaustive means future per-Kind decoders won't be breaking.
- **New public fields** on existing structs: `rtti::RecordInfo::fields`,
  `rtti::MethodInfo::{param_type_refs, result_type_ref}`, and several fields
  on `rtti::ProcedureInfo` (previously header-only). Struct patterns that
  destructure these without `..` need updating; field reads and the parser
  output are unaffected.

## 0.2.1

Ergonomic release driven by downstream-consumer feedback. This version keeps
the public API additive and leaves the larger `AccessTarget` narrowing for a
future breaking release.

### Added

- PE image-base and VA-to-RVA helpers: `DelphiBinary::image_base`,
  `DelphiBinary::va_to_rva`, `BinaryContext::image_base`, and
  `BinaryContext::va_to_rva`.
- Method and entrypoint RVA helpers: `DelphiBinary::method_rva`,
  `MethodEntry::method_rva`, `InterfaceMethod::method_rva`, and
  `CodeEntrypoint::rva`.
- Stable `as_str()` labels and `Display` impls for `Confidence`, `Compiler`,
  `TargetArch`, `TargetOs`, `DetectionSource`, `Edition`, and
  `EntrypointKind`.
- Batched class-member accessors: `properties_with_types`,
  `fields_with_types`, `interfaces_with_methods`, and
  `class_attributes_with_string_args`.
- Handle-based class lookup helpers: `DelphiBinary::class_by_index` and
  `DelphiBinary::parent_class`.
- DFM value helpers: `DfmValue::kind_str()` and strict text decoding via
  `DfmValue::as_text_strict()`.

## 0.2.0

Major API revision. Most existing call sites need small migrations
(see "Breaking changes"); in exchange the crate gains a single
aggregated entrypoint for disassembler-driving consumers, hides the
raw-bytes/`&str` distinction behind a consistent accessor pattern, and
exposes interface-method, class-attribute, and unit init/finalize
walkers that weren't reachable before.

### Breaking changes

- **`DelphiBinary::parse` now returns `Result<Self, ParseError>`**
  instead of `Option<Self>`. Variants: `NotRecognized` (the quiet
  no-Delphi-markers case — safe to ignore), `TruncatedContainer`
  (recognised magic but malformed headers — worth logging), and
  `UnrecognizedFormat` (no known container magic at all). `ParseError`
  implements `Display` and `std::error::Error`.
- **Name accessors return `&str` by default**, lossily decoded with a
  `"<non-ascii>"` fallback. Affected: `MethodEntry`, `Property`,
  `Field`, `DfmObject`, `DfmProperty`, `Vmt`, `TkClassInfo`,
  `TypeHeader`, `MethodParam`, `EnumInfo`, `DynArrayInfo`,
  `InterfaceTypeInfo`, `InterfaceEntry`. The raw `&[u8]` byte-fields
  are now hidden; use the `*_bytes()` companion accessors when you
  need the raw bytes. Migration: `foo.name_str()` → `foo.name()`,
  `foo.class_name_str()` → `foo.class_name()`, etc.
- **`BinaryFormat` is split by bitness.** `Pe` / `Elf` / `MachO` are
  replaced by `Pe32` / `Pe64` / `Elf32` / `Elf64` / `MachO32` /
  `MachO64`. Use the `is_pe()` / `is_elf()` / `is_macho()` /
  `is_64bit()` / `bitness()` helpers for variant-agnostic code. The
  enum is `#[non_exhaustive]`.
- **`DelphiBinary` is now `Send + Sync`.** `forms_cache` switched
  from `std::cell::OnceCell` to `std::sync::OnceLock`, which unblocks
  holding `&bin` across `.await` points in async runtimes.
- **`EmbeddedBlob` carries borrowed component / property
  references** (`component: &DfmObject`, `property: &DfmProperty`)
  instead of `String` fields. The dotted `path` remains as a
  precomputed `String`; `property_name` is now the method
  `b.property_name()`.

### Aggregated entrypoint

- **`bin.code_entrypoints()`** — single call producing every code VA
  the crate can confidently label, tagged by `EntrypointKind`
  (`PublishedMethod`, `VmtSlot`, `DynamicMessage`, `InterfaceGetter`,
  `InterfaceMethod`, `PropertyGetter`, `PropertySetter`,
  `PropertyStored`, `AttributeCtor`, `UnitInit`, `UnitFinalize`) and
  carrying a `name_hint` like `TForm1.Button1Click`. Replaces ~10
  separate walks for disassembler-driving consumers; resolves
  `AccessKind::Virtual` slot indices to code VAs internally.

### New walkers

- **`bin.interface_methods(entry)`** — walks an interface's vtable
  pointer-by-pointer, terminating at the first slot that doesn't
  contain a plausible code VA. Slot count + code VAs are recovered
  on every Delphi and FPC binary, including stripped builds. Method
  *names* are populated when the `tkInterface` RTTI carries
  per-method records — recovered via a binary-wide GUID-keyed
  RTTI index built lazily on first call. The new
  [`rtti::IntfMethodTable`] / [`rtti::IntfMethodEntry`] types expose
  the parsed table directly when needed.
- **`bin.class_attributes(class)`** — walks past the classic
  `TPropData` and the extended-property block to find the modern
  `AttrData` trailer, then decodes its packed `[attribute]`
  entries. Layout-driven; returns whatever the trailer actually
  contains regardless of compiler family.
- **`bin.unit_init_procs()`** — locates the FPC `INITFINAL` table via
  symbol lookup (`INITFINAL` / `_INITFINAL` / `FPC_INITFINAL` across
  ELF symtab, Mach-O `LC_SYMTAB`, and PE exports), with a heuristic
  shape scan over data sections as a fallback for stripped builds.
  Returns `Vec<UnitInitProc { unit_name, init_va, finalize_va }>`.
  Delphi-compiled binaries return empty by design — Delphi inlines
  unit init into the entry-point startup sequence; consumers wanting
  the unit list use [`DelphiBinary::package_info`] instead.

### Ergonomics

- `Access::resolve(virtual_methods)` returning a new `AccessTarget`
  enum (`CodeVa` / `FieldOffset` / `Constant` / `UnresolvedSlot` /
  `Missing`). Hides the VMT slot-index → VA lookup.
- `Class::parent(&self, set)` — resolves `parent_index` against a
  `ClassSet`.
- `ClassSet::iter_with_parents()` — yields
  `(class, Option<&Class>)` pairs.
- `DfmValue::as_text()` — unifies `String` and `Utf16` variants
  behind a single `Cow<'_, str>` accessor.
- `DfmValue::as_f64()` — decodes the 10-byte Intel 80-bit extended
  (lossy).
- `DfmObject::walk_with_path()` — depth-first walker yielding
  `(dotted_path, &DfmObject)`.
- `FormFlavor` enum (`Tpf0` / `Tpf1`) on `DfmObject`.
- `Deref<Target = Property>` on `ExtendedProperty`. `ep.name()` now
  works without going through `ep.info.…`.
- `Display` impls on `Guid` (no `String` allocation, in hot paths)
  and `BlobKind`. `Guid` also gains `Hash`, `PartialOrd`, `Ord`.
- `bin.target_os()` / `bin.target_arch()` — fall back to
  container-level inference (PE → Windows, Mach-O → Darwin, ELF →
  Linux; arch from PE `Machine` / ELF `e_machine` / Mach-O
  `cputype`) when the compiler build-string is absent.
- `bin.ctx().container_parsed()` — whether goblin walked the
  container cleanly. Drives `ParseError::TruncatedContainer`.
- `bin.ctx().is_code_va(va)` — whether `va` lies inside the binary's
  primary code section. Used by `interface_methods` and the
  `unit_init_procs` heuristic.

### Documentation

- Top-level module docs gained a code-vs-data VA classification
  table and the "subtract image base for RVA" note.

### Optional features

- **`tracing`** (off by default). Sub-parsers (`iter_methods`,
  `iter_properties`, `iter_fields`, `iter_interfaces`, `dfm::parse`)
  emit `warn!` events when they bail out on truncated or malformed
  input. Lets consumers distinguish "no methods declared" from
  "method table corrupt" without changing return types.

## 0.1.0

Initial release.
