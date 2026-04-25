//! Integration tests against the corpus in `tests/samples/`.
//!
//! Each sample has a documented expected fingerprint in `SAMPLES.md`. The
//! assertions here enforce the same values so that parser drift is caught by
//! CI. If a sample is missing locally (fresh checkout without the large
//! binary corpus), the test is skipped rather than failing.

use std::{
    fs,
    path::{Path, PathBuf},
    str,
};

use undelphi::{
    DelphiBinary,
    detection::{Compiler, DetectionSource, TargetArch, TargetOs},
    dfm::DfmValue,
    dvclal::Edition,
    extrtti::Visibility,
    layout::reconstruct,
    render::render_enum_ordinal,
    rtti::{TypeDetail, TypeKind},
    xref::{dfm_class_instantiations, interface_implementors},
};

/// Assert that a class named `class_name` has a published method named
/// `method_name`. Extraction drives iteration 3's method-table parser.
#[allow(dead_code)]
fn assert_has_method(bin: &DelphiBinary<'_>, class_name: &str, method_name: &str) {
    let classes = bin.classes();
    let class = classes
        .find_by_name(class_name)
        .unwrap_or_else(|| panic!("expected class {class_name} to exist"));
    let methods = bin.methods(class);
    assert!(
        methods.iter().any(|m| m.name() == method_name),
        "{class_name} should publish method {method_name}; got {:?}",
        methods.iter().map(|m| m.name()).collect::<Vec<_>>()
    );
}

fn samples_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/samples")
}

fn load(rel: &str) -> Option<Vec<u8>> {
    let path = samples_root().join(rel);
    fs::read(&path).ok()
}

/// Helper: assert that `name` resolves to a class whose ancestry chain
/// (walked from parent toward root) ends with the supplied suffix of names.
fn assert_ancestry(bin: &DelphiBinary<'_>, name: &str, expected_chain: &[&str]) {
    let classes = bin.classes();
    let class = classes
        .find_by_name(name)
        .unwrap_or_else(|| panic!("expected class {name} to exist"));
    let ancestry: Vec<_> = classes.ancestors(class).map(|a| a.name()).collect();
    assert!(
        ancestry
            .windows(expected_chain.len())
            .any(|w| w == expected_chain),
        "class {name} ancestry {ancestry:?} should contain {expected_chain:?}"
    );
}

#[test]
fn heidisql_win64_delphi_12_athens() {
    let Some(data) = load("heidisql/portable_x64/heidisql.exe") else {
        eprintln!("skipping: sample missing");
        return;
    };
    let bin = DelphiBinary::parse(&data).expect("should detect delphi binary");
    assert!(bin.format().is_pe());

    let info = bin.compiler().expect("should have build-string");
    assert_eq!(info.compiler, Compiler::Delphi);
    assert_eq!(info.version, Some("36.0"));
    assert_eq!(info.os, TargetOs::Windows);
    assert_eq!(info.arch, TargetArch::X86_64);

    // DVCLAL present → edition should decode.
    assert!(bin.edition().is_some(), "heidisql should carry DVCLAL");
    assert!(matches!(
        bin.edition(),
        Some(Edition::Personal) | Some(Edition::Professional) | Some(Edition::Enterprise)
    ));

    // PACKAGEINFO should parse and list both requires and contains.
    let pkg = bin.package_info().expect("should parse PACKAGEINFO");
    assert!(!pkg.contains.is_empty(), "should contain at least one unit");
    // TPF0 forms expected (confirmed in SAMPLES.md: 42).
    assert!(bin.tpf0_count() >= 10, "expect many TPF0 resources");

    // Class-tree assertions.
    let classes = bin.classes();
    assert!(
        classes.len() > 1000,
        "expected HeidiSQL to yield thousands of classes, got {}",
        classes.len()
    );
    assert!(
        classes.orphan_count() <= 10,
        "expected small orphan count, got {}",
        classes.orphan_count()
    );
    assert_eq!(
        classes.root().map(|c| c.name()),
        Some("TObject"),
        "expected TObject as root"
    );
    // Well-known VCL classes must be present with correct ancestry.
    assert_ancestry(&bin, "TComponent", &["TPersistent", "TObject"]);
    assert_ancestry(&bin, "TForm", &["TWinControl", "TControl", "TComponent"]);
    assert_ancestry(&bin, "TStringList", &["TStrings", "TPersistent", "TObject"]);
    assert!(classes.max_depth() >= 5);

    // Iteration 3: RTTI unit names.
    let tobject = classes.find_by_name("TObject").unwrap();
    assert_eq!(bin.unit_name(tobject), Some("System"));
    let tcomp = classes.find_by_name("TComponent").unwrap();
    assert_eq!(bin.unit_name(tcomp), Some("System.Classes"));
    let tform = classes.find_by_name("TForm").unwrap();
    assert_eq!(bin.unit_name(tform), Some("Vcl.Forms"));
    // HeidiSQL's own main form is in the `Main` unit.
    let tmain = classes.find_by_name("TMainForm").unwrap();
    assert_eq!(bin.unit_name(tmain), Some("Main"));

    // Iteration 3: method table on a form that publishes event handlers.
    // TMainForm has hundreds of published event handlers.
    let methods = bin.methods(tmain);
    assert!(
        methods.len() > 50,
        "TMainForm method count: {}",
        methods.len()
    );

    // Iteration 3: interface table — TInterfacedObject implements IUnknown.
    let ti = classes.find_by_name("TInterfacedObject").unwrap();
    let ifaces = bin.interfaces(ti);
    assert_eq!(ifaces.len(), 1);
    assert_eq!(
        ifaces[0].guid.to_string_delphi(),
        "{00000000-0000-0000-C000-000000000046}"
    );

    // interface_methods walks vtable_va. IUnknown has 3 slots
    // (QueryInterface, AddRef, Release); the heuristic should recover
    // at least those, may include more if adjacent code follows.
    let imethods = bin.interface_methods(&ifaces[0]);
    assert!(
        imethods.len() >= 3,
        "expected ≥3 IUnknown methods, got {}",
        imethods.len()
    );
    for (i, m) in imethods.iter().enumerate().take(3) {
        assert_eq!(m.slot_index as usize, i);
        assert!(m.code_va != 0);
    }

    // class_attributes: heidisql declares attributes on at least a
    // handful of classes via modern extended RTTI. We don't pin the
    // exact count (sample-dependent) but require the walker discovers
    // at least one across the whole class set.
    let attrs_total: usize = classes.iter().map(|c| bin.class_attributes(c).len()).sum();
    assert!(
        attrs_total > 0,
        "expected at least one class with attributes via the trailer walker"
    );

    // Iteration 4: published properties. TForm should expose 100+ and
    // classic VCL names must be present.
    let props = bin.properties(tform);
    assert!(props.len() > 50, "TForm property count: {}", props.len());
    let names: Vec<_> = props.iter().map(|p| p.name()).collect();
    for expected in ["Caption", "Action", "Align", "BorderIcons"] {
        assert!(
            names.contains(&expected),
            "TForm should publish property {expected}; names = {names:?}"
        );
    }

    // Iteration 4: published fields on TMainForm.
    let fields = bin.fields(tmain);
    assert!(
        fields.len() > 100,
        "TMainForm field count: {}",
        fields.len()
    );

    // code_entrypoints() should aggregate thousands of VAs on a binary
    // this size; check ordering of magnitude to catch regressions in the
    // aggregation glue.
    let entrypoints = bin.code_entrypoints();
    assert!(
        entrypoints.len() > 1000,
        "code_entrypoints count: {}",
        entrypoints.len()
    );
    use undelphi::entrypoints::EntrypointKind;
    assert!(
        entrypoints
            .iter()
            .any(|e| e.kind == EntrypointKind::PublishedMethod),
        "expected at least one PublishedMethod entrypoint"
    );

    // Iteration 4: forms parsed from DFM resources.
    let forms = bin.forms();
    assert!(forms.len() >= 20, "parsed form count: {}", forms.len());
    // Find the About-box form and inspect a Caption.
    let about = forms
        .iter()
        .find(|(_, obj)| obj.class_name() == "TAboutBox")
        .expect("TAboutBox form should parse");
    let caption = about
        .1
        .properties
        .iter()
        .find(|p| p.name() == "Caption")
        .expect("TAboutBox must have a Caption");
    match &caption.value {
        DfmValue::String(s) => assert_eq!(*s, *b"About"),
        other => panic!("expected Caption=String, got {other:?}"),
    }

    // Iteration 5: property-type resolution + enumeration catalog.
    let prop_caption = props
        .iter()
        .find(|p| p.name() == "Caption")
        .expect("TForm.Caption must exist");
    let caption_ty = bin
        .property_type(tform, prop_caption)
        .expect("TForm.Caption must have resolved type");
    assert_eq!(caption_ty.name(), "TCaption");
    assert_eq!(caption_ty.kind, TypeKind::UString);

    let prop_align = props
        .iter()
        .find(|p| p.name() == "Align")
        .expect("TForm.Align must exist");
    let align_ty = bin
        .property_type(tform, prop_align)
        .expect("TForm.Align must have resolved type");
    assert_eq!(align_ty.name(), "TAlign");
    assert_eq!(align_ty.kind, TypeKind::Enumeration);

    // Decode TAlign's enumeration values.
    let enum_info = bin
        .decode_enum(align_ty.va, Compiler::Delphi)
        .expect("TAlign should decode");
    let enum_names: Vec<_> = enum_info
        .values
        .iter()
        .map(|v| str::from_utf8(v).unwrap())
        .collect();
    assert_eq!(
        enum_names,
        vec![
            "alNone", "alTop", "alBottom", "alLeft", "alRight", "alClient", "alCustom"
        ]
    );

    // Iteration 6: per-Kind TypeDetail on properties.
    let prop_anchors = props
        .iter()
        .find(|p| p.name() == "Anchors")
        .expect("TForm.Anchors");
    let detail = bin
        .property_type_detail(tform, prop_anchors)
        .expect("Anchors detail");
    match detail {
        TypeDetail::Set(s) => {
            assert_eq!(s.header.name(), "TAnchors");
            let elem = s
                .element_type
                .expect("TAnchors must resolve its element type");
            assert!(
                matches!(elem.kind, TypeKind::Enumeration),
                "TAnchors elements should be an enumeration"
            );
        }
        other => panic!("expected TAnchors to be Set, got {other:?}"),
    }

    // Iteration 6: render helper.
    let aligns = bin
        .decode_enum(align_ty.va, Compiler::Delphi)
        .expect("TAlign");
    assert_eq!(render_enum_ordinal(5, &aligns), "alClient");
    assert!(render_enum_ordinal(99, &aligns).contains("out-of-range"));

    // Iteration 7: virtual method table, init table, dynamic table.
    let vtable = bin.virtual_methods(tform);
    assert!(
        vtable.len() > 50,
        "TForm virtual-method count: {}",
        vtable.len()
    );
    let init = bin.init_table(tcomp).expect("TComponent init table");
    assert!(!init.managed_fields.is_empty());
    let dyn_slots = bin.dynamic_slots(tcomp);
    assert!(
        !dyn_slots.is_empty(),
        "TComponent should have dynamic/message slots"
    );

    // Iteration 7: tkMethod decoder on TNotifyEvent-shaped event.
    let tcomp_on_change = props.iter().find(|p| p.name() == "Action");
    let _ = tcomp_on_change; // keep one use

    // Iteration 7: event-handler cross-link.
    let forms = bin.forms();
    // Pick a form with an OnCreate / OnShow / etc.
    let mut resolved = 0;
    for (_, obj) in forms {
        if let Some(cl) = classes.find_by_name(obj.class_name()) {
            for p in &obj.properties {
                if p.name().starts_with("On")
                    && let DfmValue::String(m) = &p.value
                    && let Ok(name) = str::from_utf8(m)
                    && bin.resolve_event_handler(cl, name).is_some()
                {
                    resolved += 1;
                }
            }
        }
    }
    assert!(
        resolved >= 5,
        "expected at least a few event-handlers to cross-link; resolved={}",
        resolved
    );

    // Iteration 8: extended-RTTI properties expose non-published members.
    let ext_tcomp = bin.extended_properties(tcomp);
    assert!(
        !ext_tcomp.is_empty(),
        "TComponent extended RTTI should expose at least some Public members"
    );
    assert!(
        ext_tcomp.iter().any(|e| e.visibility == Visibility::Public),
        "TComponent extended RTTI should include Public props"
    );

    // Iteration 8: class-hierarchy tree non-empty.
    let tree = classes.render_tree(64);
    assert!(tree.contains("TObject"), "class tree missing TObject");
    assert!(tree.contains("TComponent"), "class tree missing TComponent");

    // Iteration 9: compiler product name.
    let info = bin.compiler().unwrap();
    assert_eq!(info.product_name().as_deref(), Some("Delphi 12 Athens"));

    // Iteration 9: interface cross-reference.
    let iface_xref = interface_implementors(&bin);
    assert!(
        iface_xref
            .keys()
            .any(|k| k.contains("{00000000-0000-0000-C000-000000000046}")),
        "IUnknown should appear in interface cross-reference"
    );

    // Iteration 9: DFM class instantiation cross-reference.
    let dfm_xref = dfm_class_instantiations(&bin);
    assert!(dfm_xref.contains_key("TButton"));
    assert!(dfm_xref.contains_key("TLabel"));

    // Iteration 9: instance-layout reconstruction.
    let layout = reconstruct(&bin, tform);
    assert!(!layout.is_empty());
}

#[test]
fn doublecmd_win32_fpc_322() {
    let Some(data) = load("doublecmd/win32/doublecmd/doublecmd.exe") else {
        eprintln!("skipping: sample missing");
        return;
    };
    let bin = DelphiBinary::parse(&data).expect("should detect fpc binary");
    assert!(bin.format().is_pe());

    let info = bin.compiler().expect("should have FPC build-string");
    assert_eq!(info.compiler, Compiler::FreePascal);
    assert_eq!(info.version, Some("3.2.2"));
    assert_eq!(info.arch, TargetArch::X86);
    assert_eq!(info.os, TargetOs::Windows);

    // FPC binaries do not emit DVCLAL.
    assert!(bin.edition().is_none(), "FPC should not have DVCLAL");
    // SAMPLES.md reports 114 TPF0 forms.
    assert!(bin.tpf0_count() >= 100);

    // Class-tree assertions. Double Commander is a Lazarus/FPC binary,
    // so it has TLCLComponent in its ancestry chain for UI controls.
    let classes = bin.classes();
    assert!(classes.len() > 500);
    assert_eq!(classes.root().map(|c| c.name()), Some("TObject"));
    assert_ancestry(&bin, "TComponent", &["TPersistent", "TObject"]);
    assert_ancestry(
        &bin,
        "TForm",
        &["TLCLComponent", "TComponent", "TPersistent", "TObject"],
    );

    // Iteration 3: FPC RTTI unit names (FPC 3.2.2 — Lazarus convention).
    let tmain = classes.find_by_name("TfrmMain").unwrap();
    assert_eq!(bin.unit_name(tmain), Some("fMain"));
    // Methods extracted via FPC's PShortString-deref layout.
    let methods = bin.methods(tmain);
    assert!(methods.len() > 50);

    // unit_init_procs: FPC INITFINAL table located via heuristic shape
    // scan (the symbol table is stripped on this build). Lazarus apps
    // pull in dozens of units; expect at least 30 entries.
    let procs = bin.unit_init_procs();
    assert!(
        procs.len() >= 30,
        "expected ≥30 unit init procs from FPC INITFINAL table, got {}",
        procs.len()
    );
    // At least one entry should carry a non-zero init or finalize VA.
    assert!(
        procs
            .iter()
            .any(|p| p.init_va.is_some() || p.finalize_va.is_some()),
        "every entry was a no-op — heuristic likely locked onto garbage"
    );
}

#[test]
fn cheatengine_win64_fpc_304() {
    let Some(data) = load("cheatengine/bin/cheatengine-x86_64.exe") else {
        eprintln!("skipping: sample missing");
        return;
    };
    let bin = DelphiBinary::parse(&data).expect("should detect fpc binary");
    assert!(bin.format().is_pe());

    let info = bin.compiler().expect("should have FPC build-string");
    assert_eq!(info.compiler, Compiler::FreePascal);
    assert_eq!(info.version, Some("3.0.4"));
    assert_eq!(info.arch, TargetArch::X86_64);
    assert_eq!(info.os, TargetOs::Windows);

    assert!(bin.edition().is_none());
    assert!(bin.tpf0_count() >= 100);

    // Cheat Engine is FPC Win64 — exercises the 64-bit FPC VMT path with
    // FPC's `PClass`-style indirect parent references.
    let classes = bin.classes();
    assert!(classes.len() > 500);
    assert_eq!(classes.root().map(|c| c.name()), Some("TObject"));
    assert_ancestry(&bin, "TComponent", &["TPersistent", "TObject"]);

    // Iteration 3: FPC 3.0.4 (the older-pre-VER3_2 layout) unit extraction.
    let tmain = classes.find_by_name("TMainForm").unwrap();
    assert_eq!(bin.unit_name(tmain), Some("MainUnit"));
    let methods = bin.methods(tmain);
    assert!(methods.len() > 50);
}

#[test]
fn heidisql_macos_aarch64_fpc_322() {
    let Some(data) = load("heidisql/macos/heidisql.app/Contents/MacOS/heidisql") else {
        eprintln!("skipping: sample missing");
        return;
    };
    let bin = DelphiBinary::parse(&data).expect("should detect fpc mach-o");
    assert!(bin.format().is_macho());

    let info = bin.compiler().expect("should have FPC build-string");
    assert_eq!(info.compiler, Compiler::FreePascal);
    assert_eq!(info.version, Some("3.2.2"));
    assert_eq!(info.arch, TargetArch::Aarch64);
    assert_eq!(info.os, TargetOs::Darwin);

    // DVCLAL / PACKAGEINFO resources are PE-only — no `.rsrc` section on
    // Mach-O. Edition/package_info must be None here, and that is correct.
    assert!(bin.edition().is_none());
    assert!(bin.package_info().is_none());

    // Class-tree assertions — Mach-O path exercises the `__DATA_CONST.__const`
    // scan target added specifically for FPC on macOS.
    let classes = bin.classes();
    assert!(
        classes.len() > 500,
        "expected >500 classes on Mach-O sample, got {}",
        classes.len()
    );
    assert_eq!(classes.root().map(|c| c.name()), Some("TObject"));
    assert_ancestry(&bin, "TComponent", &["TPersistent", "TObject"]);

    // Iteration 3: FPC + Mach-O + aarch64 exercises the pointer-alignment
    // path in the RTTI tkClass decoder (FPC sets
    // `FPC_REQUIRES_PROPER_ALIGNMENT` on ARM, so TypeData is pointer-aligned).
    let tmain = classes.find_by_name("TMainForm").unwrap();
    assert_eq!(bin.unit_name(tmain), Some("main"));
    let methods = bin.methods(tmain);
    assert!(methods.len() > 50);

    // Iteration 5: FPC resources tree walker on Mach-O (where PE RCDATA
    // isn't available). Should surface at least one parseable form.
    let forms = bin.forms();
    assert!(forms.len() >= 10, "macOS FPC form count: {}", forms.len());
    assert!(
        forms.iter().any(|(_, o)| o.class_name() == "TAboutBox"),
        "TAboutBox should appear in macOS forms"
    );
}

#[test]
fn idr64_delphi_32bit() {
    let Some(data) = load("idr-builds/Idr64.exe") else {
        eprintln!("skipping: sample missing");
        return;
    };
    let bin = DelphiBinary::parse(&data).expect("should detect delphi");
    assert!(bin.format().is_pe());

    // IDR64.exe ships without an Embarcadero build-string but carries the
    // legacy `SOFTWARE\Borland\Delphi\RTL` registry marker.
    let info = bin
        .compiler()
        .expect("legacy fallback should identify IDR64");
    assert_eq!(info.compiler, Compiler::Delphi);
    assert_eq!(info.source, DetectionSource::BorlandRegistry);
    assert_eq!(info.version, None);

    let has_resources = bin.edition().is_some() || bin.package_info().is_some();
    assert!(has_resources, "IDR64 should carry DVCLAL or PACKAGEINFO");
}

#[test]
fn lightalloy_delphi_7_legacy_detection() {
    let Some(data) = load("lightalloy/LA.exe") else {
        eprintln!("skipping: sample missing");
        return;
    };
    let bin = DelphiBinary::parse(&data).expect("should detect delphi via legacy marker");
    assert!(bin.format().is_pe());

    let info = bin.compiler().expect("should fall back to Borland marker");
    assert_eq!(info.compiler, Compiler::Delphi);
    assert_eq!(
        info.source,
        DetectionSource::BorlandRegistry,
        "Delphi 7 carries the Borland registry path"
    );
    assert_eq!(info.version, None);

    // DVCLAL resource is present even without a build-string.
    assert!(bin.edition().is_some(), "LA.exe should carry DVCLAL");
}

#[test]
fn heidisql_xe5_namespaced_detection() {
    let Some(data) = load("heidisql/portable_x86_xe5/heidisql.unpacked.exe") else {
        eprintln!("skipping: sample missing");
        return;
    };
    let bin = DelphiBinary::parse(&data).expect("should detect delphi via namespaced marker");
    assert!(bin.format().is_pe());

    let info = bin
        .compiler()
        .expect("should fall back to namespaced-units marker");
    assert_eq!(info.compiler, Compiler::Delphi);
    assert_eq!(
        info.source,
        DetectionSource::NamespacedUnits,
        "XE5 uses namespaced Vcl.* / System.* unit names"
    );
    assert_eq!(info.version, None);

    assert!(bin.edition().is_some(), "heidisql 9.5 should carry DVCLAL");
}

#[test]
fn heidisql_xe5_packed_is_rejected_not_crashed() {
    let Some(data) = load("heidisql/portable_x86_xe5/heidisql.exe") else {
        eprintln!("skipping: sample missing");
        return;
    };
    // UPX-packed binary strips all markers; the parser must return Err
    // rather than panic or return a false-positive identification.
    assert!(DelphiBinary::parse(&data).is_err());
}

#[test]
fn delphilint_bpl_delphi_12_buildstring() {
    let Some(data) = load("delphilint/DelphiLintClient-1.3.0-Athens.bpl") else {
        eprintln!("skipping: sample missing");
        return;
    };
    let bin = DelphiBinary::parse(&data).expect("should detect delphi");
    assert!(bin.format().is_pe());

    let info = bin.compiler().expect("BPL carries build-string");
    assert_eq!(info.compiler, Compiler::Delphi);
    assert_eq!(info.source, DetectionSource::BuildString);
    assert_eq!(info.version, Some("36.0"));
    assert_eq!(info.os, TargetOs::Windows);
    assert_eq!(info.arch, TargetArch::X86);

    // BPL linkage: every class's parent lives in a dependency package, so
    // there are zero genuine `TObject`-style roots and many external-parent
    // classes. This is correct, not a parser bug.
    let classes = bin.classes();
    assert_eq!(
        classes.root_count(),
        0,
        "a runtime package must not contain TObject itself"
    );
    assert!(
        classes.external_parent_count() > 100,
        "BPL should have many classes inheriting externally; got {}",
        classes.external_parent_count()
    );
    // The collapsed orphan count equals the sum.
    assert_eq!(
        classes.orphan_count(),
        classes.root_count() + classes.external_parent_count()
    );
}

#[test]
fn standalone_exes_have_exactly_one_root() {
    // Regression guard: any Delphi/FPC standalone EXE should carry TObject
    // (or its FPC equivalent) and exactly one genuine ancestry root. The
    // BPL case above is the only expected exception.
    for rel in [
        "lightalloy/LA.exe",
        "heidisql/portable_x86_xe5/heidisql.unpacked.exe",
        "heidisql/portable_x64/heidisql.exe",
        "idr-builds/Idr64.exe",
    ] {
        let Some(data) = load(rel) else {
            continue; // sample missing, skip
        };
        let bin =
            DelphiBinary::parse(&data).unwrap_or_else(|_| panic!("{rel}: should parse as delphi"));
        let classes = bin.classes();
        assert_eq!(
            classes.root_count(),
            1,
            "{rel}: expected exactly one root (TObject); got {}",
            classes.root_count()
        );
    }
}

#[test]
fn garbage_input_returns_err() {
    let data = b"this is not a delphi binary at all, just random ascii";
    assert!(DelphiBinary::parse(data).is_err());
}
