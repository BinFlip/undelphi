# Changelog

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
