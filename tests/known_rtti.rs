//! Golden tests against controlled fixtures with known ground truth.
//!
//! The binaries under `tests/samples/known-rtti/` are compiled from
//! `tests/fixtures/known-rtti/known.pas`, whose every type and member is
//! known exactly, so these tests assert *precise* extraction (exact enum
//! values, record fields, property types, ancestry, event signatures) rather
//! than the order-of-magnitude checks the real-world corpus is limited to.
//!
//! If `known.pas` changes, update these assertions in lockstep.

#![allow(
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic,
    clippy::unwrap_used
)]

use std::{fs, path::Path};

use undelphi::{
    DelphiBinary,
    detection::Compiler,
    rtti::TypeDetail,
};

fn load(rel: &str) -> Option<Vec<u8>> {
    fs::read(Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/samples").join(rel)).ok()
}

/// Assert the exact RTTI we expect from `known.pas`, for one compiled
/// variant. Shared between the win32 and win64 fixtures — the extracted
/// model must be identical across pointer widths.
fn assert_known_rtti(data: &[u8]) {
    let bin = DelphiBinary::parse(data).expect("should parse as FPC");
    assert_eq!(bin.compiler().map(|c| c.compiler), Some(Compiler::FreePascal));

    let classes = bin.classes();

    // TShape : TPersistent — three published properties, exact types.
    let tshape = classes.find_by_name("TShape").expect("TShape");
    assert_eq!(classes.ancestors(tshape).next().map(|a| a.name()), Some("TPersistent"));
    let shape_props: Vec<(String, Option<String>)> = bin
        .properties_with_types(tshape)
        .iter()
        .map(|p| (p.property.name().to_string(), p.ty.map(|h| h.name().to_string())))
        .collect();
    assert_eq!(
        shape_props,
        vec![
            ("Name".into(), Some("AnsiString".into())),
            ("Color".into(), Some("TColor".into())),
            ("Visible".into(), Some("Boolean".into())),
        ],
        "TShape published properties"
    );

    // TButton : TShape — two properties + a published method.
    let tbutton = classes.find_by_name("TButton").expect("TButton");
    assert_eq!(classes.ancestors(tbutton).next().map(|a| a.name()), Some("TShape"));
    let btn_props: Vec<(String, Option<String>)> = bin
        .properties_with_types(tbutton)
        .iter()
        .map(|p| (p.property.name().to_string(), p.ty.map(|h| h.name().to_string())))
        .collect();
    assert_eq!(
        btn_props,
        vec![
            ("Width".into(), Some("LongInt".into())),
            ("OnProgress".into(), Some("TProgressEvent".into())),
        ],
        "TButton published properties"
    );
    let btn_methods: Vec<&str> = bin.methods(tbutton).iter().map(|m| m.name()).collect();
    assert_eq!(btn_methods, vec!["Click"], "TButton published methods");

    // tkEnumeration — exact value names, declaration order.
    let tcolor = bin
        .types()
        .into_iter()
        .find_map(|t| match t {
            TypeDetail::Enumeration(e) if e.header.name() == "TColor" => Some(e),
            _ => None,
        })
        .expect("TColor enum");
    let values: Vec<String> = tcolor
        .values
        .iter()
        .map(|v| String::from_utf8_lossy(v).to_string())
        .collect();
    assert_eq!(values, ["clRed", "clGreen", "clBlue", "clAlpha"], "TColor values");

    // tkMethod — the event signature, exactly (FPC emits an explicit hidden
    // Self as the first parameter).
    let event = bin
        .types()
        .into_iter()
        .find_map(|t| match t {
            TypeDetail::Method(m) if m.header.name() == "TProgressEvent" => Some(m),
            _ => None,
        })
        .expect("TProgressEvent");
    let sig: Vec<(String, String)> = event
        .params
        .iter()
        .map(|p| (p.name().to_string(), p.type_name().to_string()))
        .collect();
    assert_eq!(
        sig,
        vec![
            ("$self".into(), "Pointer".into()),
            ("Sender".into(), "TObject".into()),
            ("Percent".into(), "LongInt".into()),
        ],
        "TProgressEvent signature"
    );
}

#[test]
fn known_rtti_fpc_win32() {
    let Some(data) = load("known-rtti/known.win32.exe") else {
        eprintln!("skipping: fixture missing");
        return;
    };
    assert_known_rtti(&data);
}

#[test]
fn known_rtti_fpc_win64() {
    let Some(data) = load("known-rtti/known.win64.exe") else {
        eprintln!("skipping: fixture missing");
        return;
    };
    assert_known_rtti(&data);
}

/// FPC 3.0.4 (the `cheatengine`-era version) differs from 3.2.2: classes,
/// ancestry, and published methods decode identically, but published
/// **property types** don't resolve — the 3.0.4 `TPropInfo` layout differs
/// from 3.2.2 (the `prop_type_ref` reads a non-null but non-resolving VA).
/// This test pins the version-stable subset and documents the difference;
/// fixing 3.0.4 property-type resolution is tracked in `TODO.md`.
#[test]
fn known_rtti_fpc304_win32_subset() {
    let Some(data) = load("known-rtti/known304.win32.exe") else {
        eprintln!("skipping: fixture missing");
        return;
    };
    let bin = DelphiBinary::parse(&data).expect("should parse as FPC");
    assert_eq!(bin.compiler().and_then(|c| c.version), Some("3.0.4"));
    let classes = bin.classes();

    let tshape = classes.find_by_name("TShape").expect("TShape");
    assert_eq!(classes.ancestors(tshape).next().map(|a| a.name()), Some("TPersistent"));
    // Property names decode; types are the documented 3.0.4 gap.
    let names: Vec<&str> = bin.properties(tshape).iter().map(|p| p.name()).collect();
    assert_eq!(names, vec!["Name", "Color", "Visible"], "TShape property names");

    let tbutton = classes.find_by_name("TButton").expect("TButton");
    assert_eq!(classes.ancestors(tbutton).next().map(|a| a.name()), Some("TShape"));
    let methods: Vec<&str> = bin.methods(tbutton).iter().map(|m| m.name()).collect();
    assert_eq!(methods, vec!["Click"], "TButton published methods");
}
