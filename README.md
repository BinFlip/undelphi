# undelphi

[![Crates.io](https://img.shields.io/crates/v/undelphi.svg)](https://crates.io/crates/undelphi)
[![License: Apache-2.0](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](LICENSE)

Rust static-analysis library for compiled **Delphi**,
**C++Builder**, and **Free Pascal / Lazarus** binaries. Identifies the
toolchain, recovers full class hierarchies and per-class RTTI, parses
embedded form streams, and surfaces every blob and cross-reference the
runtime metadata makes reachable — without executing the binary.

```rust
use undelphi::DelphiBinary;

let bytes = std::fs::read("my_app.exe")?;
if let Ok(bin) = DelphiBinary::parse(&bytes) {
    if let Some(info) = bin.compiler() {
        println!("{:?} {} on {:?}/{:?}", info.compiler, info.raw, info.os, info.arch);
    }
    println!("{} classes, {} forms", bin.classes().len(), bin.forms().len());
}
```

## What it extracts

### Toolchain identification

| Signal | Confidence | Recovers |
| --- | --- | --- |
| Embarcadero build-string (`Embarcadero Delphi for Win64 compiler version 36.0 …`) | High | exact compiler version → marketing release name (e.g. *Delphi 12 Athens*), target OS, target arch |
| FPC build-string (`FPC 3.2.2 [2021/05/15] for i386 - Win32`) | High | FPC version, target OS, target arch |
| `DVCLAL` resource | High | SKU (Personal / Professional / Enterprise) |
| `PACKAGEINFO` resource | High | unit list + required-package list |
| `SOFTWARE\Borland\Delphi\RTL` registry path | Medium | pre-XE2 Delphi (era only) |
| Namespaced unit names (`Vcl.Controls`, `System.SysUtils`, …) | Medium | XE2-or-later Delphi (era only) |
| `TPF0` magic-byte count | Medium | non-zero ⇒ binary is form-bearing |
| Validated VMT scan | Medium | non-empty ⇒ structurally Delphi/FPC even if every string was stripped |

### Class discovery

- **VMT shape-test scanner** for both Delphi and FPC layouts on 32-bit and
  64-bit, across Windows PE / macOS Mach-O / Linux ELF.
- **Parent-chain resolution** with FPC `PClass`-style indirection
  fallback. Detects external-parent classes (`vmtParent` pointing into a
  dependency package's VMTs) so BPL runtime packages report cleanly as
  `roots=0, external=N` instead of a sea of orphans.
- **Indexed lookups** by class name and by VMT virtual address.
- Class-tree rendering, ancestry walks (cycle-safe), child enumeration,
  max-depth, root/orphan/external counts.

### Per-class metadata

For every discovered class:

- **Published methods** — name + code VA, plus the modern-Delphi extended
  trailer.
- **Published fields** — name, instance-relative offset, resolved
  `PPTypeInfo` for the field type. Both Delphi legacy and modern field-
  table layouts plus FPC's `TVmtFieldTable`.
- **Published properties** — full `TPropInfo`: PropType pointer, get/set/
  stored access (Delphi field/virtual/static or FPC `ptField`/`ptStatic`/
  `ptVirtual`/`ptConst`), Index, Default, NameIndex.
- **Implemented interfaces** — IID GUID (canonical formatting), vtable
  VA, instance offset, getter VA. FPC Corba interfaces additionally
  surface the `IIDStr` name.
- **Virtual-method-pointer table** — one entry per slot, automatically
  bounded by the next class's VMT base.
- **Init (managed-fields) table** — every offset the runtime ref-count-
  manages (strings, interfaces, dynamic arrays, managed records).
- **Dynamic-dispatch table** — `dynamic` and `message` slots with their
  IDs and handler VAs.

### RTTI per-Kind decoders

Full structural decode for every type kind we've seen in the wild:

`tkClass` · `tkEnumeration` · `tkInteger` · `tkChar` · `tkWChar` ·
`tkFloat` · `tkSet` · `tkClassRef` · `tkDynArray` · `tkInterface` ·
`tkRecord` · `tkMethod` · `tkProcedure` · `tkLString` · `tkUString` ·
`tkWString`.

The `decode_type_detail` dispatcher follows a property's or field's
`PPTypeInfo` indirection and returns a `TypeDetail` enum so callers can
match on Kind without pre-dispatching. Delphi and FPC byte values are
both honoured (FPC reorders the `TTypeKind` enum — `tkClass` is `7` in
Delphi, `15` in FPC; both verified against `reference/`).

### Extended RTTI (Delphi 2010+)

- Per-member **visibility** flags (private / protected / public /
  published) for properties beyond the classic published-only set.
- **Attribute-table** decoder with constructor-argument extraction
  (string / integer / raw bytes).

### Form streams

Full **TPF0** *and* **TPF1** binary form-stream parser. Sources walked:

1. PE `RT_RCDATA` resources (Delphi / C++Builder / FPC Windows).
2. FPC internal-resources tree (`fpc.resources` / `.fpc.resources` —
   Mach-O, ELF, and FPC PE builds without `FPC_HAS_WINLIKERESOURCES`).

Recursive component tree, every documented `TValueType` (Null, List,
Int8/16/32/64, QWord, Single, Double, Currency, Date, Extended, String,
Ident, LString, WString, UString, Utf8String, Binary, Set, Collection,
Nil, True, False), filer flags (`ffInherited`, `ffChildPos`, `ffInline`),
and the awkward Collection-with-`vaList`-wrapper grammar (verified
against FPC `writer.inc` and reproduced under regression test).

A symbolic `render` module pretty-prints raw values against their
declared RTTI types (e.g. `Align = alClient` instead of `Align = 2`,
`BorderIcons = [biSystemMenu, biMaximize]` instead of `BorderIcons = 7`).

### Embedded blob extraction

`bin.blobs()` walks every parsed form, surfaces every `vaBinary` leaf,
and classifies it by magic bytes:

ICO · CUR · BMP · PNG · JPEG · GIF · WebP · TIFF · ZIP · GZIP · 7Z · RAR
· PDF · PE · ELF · Mach-O · WAV · MP3 · WMF/EMF · RIFF · ShortString.

Each `EmbeddedBlob` carries the originating form resource, the dotted
component path, the property name, the leading-byte classification, and
the raw byte slice (borrowed from the input). Useful for malware triage
— drops a triage-ready inventory of every dropped icon, embedded
script, packed payload, or stowaway PE in the binary's form streams.

```rust
use undelphi::DelphiBinary;

let bin = DelphiBinary::parse(&bytes).unwrap();
for blob in bin.blobs() {
    println!("{:>6} bytes  {:?}  {}.{}",
        blob.data.len(), blob.kind, blob.path, blob.property_name());
}
```

### Cross-references

Built on top of the already-extracted metadata, no extra binary scanning:

- **Interface implementors** — `BTreeMap<GUID, [class names]>`.
- **DFM class instantiations** — `BTreeMap<TButton, [forms that
  use it]>`.
- **Event-handler bindings** — every `OnClick` / `OnCreate` / etc. in
  every form, with the resolved code VA when the handler can be linked
  to a published method (walks the class's ancestry chain).
- **Per-unit aggregate stats** — class count, total fields / methods /
  properties / interfaces, total instance bytes per declaring unit.
- **External-parent report** — list of locally-declared classes that
  inherit from a dependency package's exported VMTs.

### Instance memory layout

Byte-by-byte reconstruction of an instance for a given class — fuses the
published-field table, init-table managed-field offsets, and declared
`InstanceSize`. Marks named fields, gaps (private/non-published members
or padding), and managed-only entries (ref-counted fields the class
keeps private).

## Supported targets

| Toolchain | Versions | Containers |
| --- | --- | --- |
| Embarcadero / Borland Delphi | Delphi 2 → Delphi 12 Athens (`dcc` v9 → v36) | PE32 / PE32+, Mach-O, ELF |
| Embarcadero C++Builder | parsed identically to Delphi (same VCL/FMX RTTI) | PE32 / PE32+ |
| Free Pascal / Lazarus | FPC 1.0 → FPC 3.2+ (incl. trunk-shaped 3.3) | PE32 / PE32+, Mach-O, ELF |
| Arch | x86, x86_64, ARM, AArch64 | (per the build-string and / or container header) |

Verified against an in-tree corpus of 11 real-world binaries spanning
HeidiSQL (Delphi 12 Win64, Delphi XE5 Win32, FPC Lazarus aarch64-Darwin),
Cheat Engine (FPC Win64), Double Commander (FPC Win32), DelphiLint
(Delphi 12 BPL), Light Alloy (Delphi 7 Win32), and IDR (Delphi
unspecified Win64). See [`SAMPLES.md`](SAMPLES.md) for the full corpus
catalog including provenance and download commands.

## Performance

On a 25 MB Delphi 12 Athens PE (`heidisql.exe` — 2 661 classes, 42 form
resources, hundreds of thousands of VA dereferences), full parse +
`forms()` + every `xref::*` view runs in ~100 ms in release mode on a
contemporary laptop.

## Examples

- [`examples/dump.rs`](examples/dump.rs) — exhaustive metadata dumper
  for a single binary. Print every fact this crate knows how to
  extract:

  ```sh
  cargo run --release --example dump -- path/to/binary.exe
  ```

Licensed under the [Apache License, Version 2.0](LICENSE). Sample
binaries under `tests/samples/` retain their respective upstream
licenses; see [`SAMPLES.md`](SAMPLES.md) for per-sample provenance.
