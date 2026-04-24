//! Dump **every** metadata fact this crate can extract for a single
//! Delphi / C++Builder / FPC binary.
//!
//! Usage: `cargo run --release --example dump -- path/to/binary.exe`
//!
//! Output is intentionally exhaustive. If we know it, we print it.

use std::{cmp::Reverse, collections::BTreeMap, env, fmt::Write as _, fs, process, str};

use undelphi::{
    DelphiBinary,
    blobs::{EmbeddedBlob, catalog as catalog_blobs},
    classes::Class,
    dfm::{DfmObject, DfmProperty, DfmValue},
    extrtti::decode_attribute_block,
    fields::FieldTypeRef,
    layout::{LayoutKind, reconstruct},
    render::{render_enum_ordinal, render_set_mask_with_enum, render_type_label, render_value},
    rtti::{
        TkClassInfo, TypeDetail, TypeKind, decode_tkenum, decode_type_detail,
        decode_type_header_from_pptr, deref_pptypeinfo,
    },
    vmt::VmtFlavor,
    xref::{
        dfm_class_instantiations, event_bindings, events_by_method, external_class_refs,
        interface_implementors, unit_stats,
    },
};

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() != 2 {
        eprintln!("usage: dump <path-to-binary>");
        process::exit(2);
    }
    let data = match fs::read(&args[1]) {
        Ok(d) => d,
        Err(e) => {
            eprintln!("read error: {e}");
            process::exit(1);
        }
    };
    let Some(bin) = DelphiBinary::parse(&data) else {
        eprintln!("not a recognised Delphi/C++Builder/FPC binary");
        process::exit(1);
    };

    print_overview(&bin, &args[1], data.len());
    print_packageinfo(&bin);
    print_class_tree(&bin);
    print_classes_full(&bin);
    print_forms(&bin);
    print_enum_catalog(&bin);
    print_interface_xref(&bin);
    print_dfm_class_xref(&bin);
    print_unit_summary(&bin);
    print_external_refs(&bin);
    print_event_bindings(&bin);
    print_blob_catalog(&bin);
}

fn print_class_tree(bin: &DelphiBinary<'_>) {
    let tree = bin.classes().render_tree(256);
    if tree.is_empty() {
        return;
    }
    section_header("class hierarchy tree");
    // Indent + print
    for line in tree.lines() {
        println!("  {}", line);
    }
}

fn print_overview(bin: &DelphiBinary<'_>, path: &str, size: usize) {
    let ctx = bin.ctx();
    section_header("overview");
    println!("path:              {}", path);
    println!("size:              {} bytes", size);
    println!("format:            {:?}", bin.format());
    println!("confidence:        {:?}", bin.confidence());
    println!("tpf0 magic count:  {}", bin.tpf0_count());

    if let Some(info) = bin.compiler() {
        println!("compiler:          {:?}", info.compiler);
        println!("detection source:  {:?}", info.source);
        if let Some(v) = info.version {
            println!("version:           {}", v);
        }
        if let Some(name) = info.product_name() {
            println!("product:           {}", name);
        }
        println!("target os:         {:?}", info.os);
        println!("target arch:       {:?}", info.arch);
        println!("build string:      {}", info.raw);
    } else {
        println!("compiler:          (no compiler marker found)");
    }
    if let Some(ed) = bin.edition() {
        println!("edition (DVCLAL):  {:?}", ed);
    }

    let secs = ctx.sections();
    println!("\nsections:");
    if let Some(r) = secs.rodata {
        println!(
            "  rodata   VA=0x{:x} size=0x{:x} file=0x{:x}",
            r.va, r.size, r.offset
        );
    }
    if let Some(t) = secs.text {
        println!(
            "  text     VA=0x{:x} size=0x{:x} file=0x{:x}",
            t.va, t.size, t.offset
        );
    }
    if let Some(r) = secs.rsrc {
        println!(
            "  rsrc     VA=0x{:x} size=0x{:x} file=0x{:x}",
            r.va, r.size, r.offset
        );
    }
    if let Some(r) = secs.fpc_resources {
        println!(
            "  fpc_res  VA=0x{:x} size=0x{:x} file=0x{:x}",
            r.va, r.size, r.offset
        );
    }
    println!("  scan_targets: {} section(s)", secs.scan_targets.len());
}

fn print_packageinfo(bin: &DelphiBinary<'_>) {
    let Some(pkg) = bin.package_info() else {
        return;
    };
    section_header("packageinfo resource");
    println!("flags:         0x{:08x}", pkg.flags);
    println!("requires ({}):", pkg.requires.len());
    for r in &pkg.requires {
        println!("  0x{:02x}  {}", r.hash, r.name);
    }
    println!("contains ({}):", pkg.contains.len());
    for u in &pkg.contains {
        println!(
            "  flags=0x{:02x} hash=0x{:02x}  {}",
            u.flags, u.hash, u.name
        );
    }
}

fn print_classes_full(bin: &DelphiBinary<'_>) {
    let classes = bin.classes();
    let flavor = bin.flavor();
    section_header(&format!(
        "classes — {} found (roots={}, external-parent={}, max-depth={})",
        classes.len(),
        classes.root_count(),
        classes.external_parent_count(),
        classes.max_depth()
    ));

    let mut by_unit: BTreeMap<String, Vec<&Class<'_>>> = Default::default();
    for c in classes.iter() {
        let u = bin.unit_name(c).unwrap_or("<unknown>").to_string();
        by_unit.entry(u).or_default().push(c);
    }
    for (unit, clist) in &by_unit {
        println!("\n  === unit {} — {} classes ===", unit, clist.len());
        for c in clist {
            print_one_class(bin, c, flavor);
        }
    }
}

fn print_one_class<'a>(bin: &DelphiBinary<'a>, class: &Class<'a>, flavor: VmtFlavor) {
    let classes = bin.classes();
    let ancestry: Vec<_> = classes.ancestors(class).map(|a| a.name()).collect();
    let chain = if ancestry.is_empty() {
        "(root)".to_string()
    } else {
        ancestry.join(" -> ")
    };
    println!(
        "\n  {} — size={}B, vmt=0x{:x}, ptrsize={}B  (parents: {})",
        class.name(),
        class.instance_size(),
        class.vmt_va(),
        class.pointer_size(),
        chain
    );
    if let Some(tk) = bin.tkclass(class) {
        print_tkclass_detail(&tk);
    }

    // Fields — with per-Kind resolved type detail where possible
    let fields = bin.fields(class);
    if !fields.is_empty() {
        println!("    fields ({}):", fields.len());
        for f in &fields {
            let ty_label = match bin.field_type_detail(class, f) {
                Some(detail) => render_detail_inline(&detail),
                None => match bin.field_type(class, f) {
                    Some(h) => render_type_label(&h),
                    None => format!("{:?}", f.type_ref),
                },
            };
            println!(
                "      +0x{:06x}  {:<36} : {}",
                f.offset,
                f.name_str(),
                ty_label
            );
        }
    }

    // Published methods
    let methods = bin.methods(class);
    if !methods.is_empty() {
        println!("    published methods ({}):", methods.len());
        for m in &methods {
            println!("      0x{:08x}  {}", m.code_va, m.name_str());
        }
    }

    // Interfaces
    let ifaces = bin.interfaces(class);
    if !ifaces.is_empty() {
        println!("    interfaces ({}):", ifaces.len());
        for i in &ifaces {
            let iid_str = i
                .iid_str
                .map(|b| String::from_utf8_lossy(b).into_owned())
                .filter(|s| !s.is_empty());
            let name_part = match iid_str {
                Some(s) => format!(" (iid_str={})", s),
                None => String::new(),
            };
            println!(
                "      {}{}  vtable=0x{:x}  offset={}  getter=0x{:x}",
                i.guid.to_string_delphi(),
                name_part,
                i.vtable_va,
                i.offset,
                i.getter_va
            );
        }
    }

    // Virtual method table
    let vtable = bin.virtual_methods(class);
    if !vtable.is_empty() {
        println!("    virtual methods ({}):", vtable.len());
        for v in &vtable {
            println!(
                "      slot {:3}  slot_va=0x{:x}  code=0x{:x}",
                v.slot, v.slot_va, v.code_va
            );
        }
    }

    // Init table (managed-field layout)
    if let Some(init) = bin.init_table(class)
        && !init.managed_fields.is_empty()
    {
        println!(
            "    init table: record_size={} managed_fields={}",
            init.record_size,
            init.managed_fields.len()
        );
        for (i, f) in init.managed_fields.iter().enumerate() {
            let ty = f
                .field_type
                .map(|h| format!("{} [{:?}]", h.name_str(), h.kind))
                .unwrap_or_else(|| format!("0x{:x}", f.type_ref));
            println!("      [{}] +0x{:x}  {}", i, f.offset, ty);
        }
    }

    // Dynamic-dispatch table
    let dyn_slots = bin.dynamic_slots(class);
    if !dyn_slots.is_empty() {
        println!("    dynamic / message slots ({}):", dyn_slots.len());
        for d in &dyn_slots {
            println!("      msgid={:>6}  handler=0x{:x}", d.index, d.handler_va);
        }
    }

    // Extended-RTTI property table (beyond-published visibility).
    let ext = bin.extended_properties(class);
    if !ext.is_empty() {
        println!("    extended-RTTI properties ({}):", ext.len());
        let psize = class.pointer_size() as usize;
        for e in &ext {
            let mut line = format!("      [{:?}] {:<32}", e.visibility, e.info.name_str());
            if !e.attributes_raw.is_empty() {
                let (attrs, _) = decode_attribute_block(e.attributes_raw, psize);
                if !attrs.is_empty() {
                    let _ = write!(line, "  attrs=[");
                    for (i, ae) in attrs.iter().enumerate() {
                        if i > 0 {
                            let _ = write!(line, ", ");
                        }
                        let ty = decode_type_header_from_pptr(
                            bin.ctx(),
                            ae.attr_type_ref,
                            psize,
                            bin.flavor(),
                        )
                        .map(|h| h.name_str().to_owned())
                        .unwrap_or_else(|| format!("0x{:x}", ae.attr_type_ref));
                        let arg = if let Some(s) = ae.arg_as_string() {
                            format!("({:?})", String::from_utf8_lossy(s))
                        } else if ae.arg_data.len() == 4 {
                            let v = u32::from_le_bytes(ae.arg_data.try_into().unwrap());
                            format!("({})", v)
                        } else if ae.arg_data.len() == 1 {
                            format!("({})", ae.arg_data[0])
                        } else if ae.arg_data.is_empty() {
                            String::new()
                        } else {
                            format!("(<{} bytes>)", ae.arg_data.len())
                        };
                        let _ = write!(line, "{}{}", ty, arg);
                    }
                    let _ = write!(line, "]");
                } else {
                    let _ = write!(line, "  attrs=<{}B raw>", e.attributes_raw.len());
                }
            }
            println!("{}", line);
        }
    }

    // Reconstructed instance memory layout (combines VMT slot + fields +
    // managed-field markers, with gap fill to instance_size).
    if class.instance_size() > class.pointer_size() as u32 {
        let entries = reconstruct(bin, class);
        if entries.iter().any(|e| {
            matches!(
                e.kind,
                LayoutKind::NamedField { .. } | LayoutKind::ManagedOnly { .. }
            )
        }) {
            println!("    instance layout ({}B):", class.instance_size());
            for e in &entries {
                match &e.kind {
                    LayoutKind::VmtSlot => {
                        println!("      +0x{:04x}  {:>5}B  [vmt]", e.offset, e.size)
                    }
                    LayoutKind::NamedField {
                        name,
                        type_name,
                        managed,
                    } => {
                        let ty = type_name.as_deref().unwrap_or("?");
                        let m = if *managed { " [managed]" } else { "" };
                        println!(
                            "      +0x{:04x}  {:>5}B  {} : {}{}",
                            e.offset, e.size, name, ty, m
                        );
                    }
                    LayoutKind::ManagedOnly { type_name } => {
                        let ty = type_name.as_deref().unwrap_or("?");
                        println!(
                            "      +0x{:04x}  {:>5}B  <managed-only> : {}",
                            e.offset, e.size, ty
                        );
                    }
                    LayoutKind::Gap => println!("      +0x{:04x}  {:>5}B  <gap>", e.offset, e.size),
                }
            }
        }
    }

    // Properties with per-kind RTTI detail inline.
    let props = bin.properties(class);
    if !props.is_empty() {
        println!("    published properties ({}):", props.len());
        for p in &props {
            let ty_label = match bin.property_type_detail(class, p) {
                Some(detail) => render_detail_inline(&detail),
                None => "?".to_string(),
            };
            println!(
                "      {:<32} : {:<50}  get={:?}:0x{:x}  set={:?}:0x{:x}  index={}  default={}",
                p.name_str(),
                ty_label,
                p.get.kind,
                p.get.value,
                p.set.kind,
                p.set.value,
                p.index,
                p.default
            );
        }
    }

    let _ = flavor;
}

/// Compact inline rendering of a [`TypeDetail`] — `Name [Kind]` plus a
/// one-liner of the type-specific payload.
fn render_detail_inline(detail: &TypeDetail<'_>) -> String {
    let h = detail.header();
    let base = format!("{} [{:?}]", h.name_str(), h.kind);
    match detail {
        TypeDetail::Class(x) => format!(
            "{} unit={} propcount={}",
            base,
            x.unit_name_str().unwrap_or("?"),
            x.prop_count
        ),
        TypeDetail::Enumeration(x) => {
            let names: Vec<_> = x
                .values
                .iter()
                .map(|v| String::from_utf8_lossy(v).into_owned())
                .collect();
            format!("{} {{{}..{}}} [{}]", base, x.min, x.max, names.join(","))
        }
        TypeDetail::Ordinal(x) => format!("{} ord={:?} [{}..{}]", base, x.ord, x.min, x.max),
        TypeDetail::Float(x) => format!("{} ({:?})", base, x.float_type),
        TypeDetail::Set(x) => {
            let elem = x
                .element_type
                .map(|h| h.name_str().to_string())
                .unwrap_or_else(|| "?".into());
            format!("{} of={}", base, elem)
        }
        TypeDetail::ClassRef(x) => {
            let inst = x
                .instance_type
                .map(|h| h.name_str().to_string())
                .unwrap_or_else(|| "?".into());
            format!("{} of={}", base, inst)
        }
        TypeDetail::DynArray(x) => {
            let elem = x
                .element_type
                .map(|h| h.name_str().to_string())
                .unwrap_or_else(|| "?".into());
            format!(
                "{} elem={} elemsz={} unit={}",
                base,
                elem,
                x.elem_size,
                x.unit_name
                    .map(|u| String::from_utf8_lossy(u).into_owned())
                    .unwrap_or_else(|| "?".into())
            )
        }
        TypeDetail::Interface(x) => format!(
            "{} parent={} guid={} flags=0x{:02x} unit={}",
            base,
            x.parent_type
                .map(|h| h.name_str().to_string())
                .unwrap_or_else(|| "?".into()),
            x.guid.to_string_delphi(),
            x.flags,
            x.unit_name
                .map(|u| String::from_utf8_lossy(u).into_owned())
                .unwrap_or_else(|| "?".into())
        ),
        TypeDetail::Record(x) => format!(
            "{} size={} managed_fields={}",
            base,
            x.record_size,
            x.managed_fields.len()
        ),
        TypeDetail::Method(x) => {
            let params: Vec<_> = x
                .params
                .iter()
                .map(|p| format!("{}:{}", p.name_str(), p.type_name_str()))
                .collect();
            let ret = x
                .result_type
                .map(|b| format!(":{}", String::from_utf8_lossy(b)))
                .unwrap_or_default();
            format!("{} {:?}({}){}", base, x.kind, params.join(", "), ret)
        }
        TypeDetail::Procedure(_) => base,
        TypeDetail::String(x) => format!("{} codepage={}", base, x.code_page),
        TypeDetail::Other(_) => base,
    }
}

fn print_tkclass_detail(tk: &TkClassInfo<'_>) {
    println!(
        "    RTTI tkClass: unit={} prop_count={} parent_info_va=0x{:x} class_type_va=0x{:x}",
        tk.unit_name_str().unwrap_or("?"),
        tk.prop_count,
        tk.parent_info_va,
        tk.class_type_va
    );
}

fn print_forms(bin: &DelphiBinary<'_>) {
    let forms = bin.forms();
    section_header(&format!("forms — {} parsed from resources", forms.len()));
    for (name, obj) in forms {
        println!(
            "\n  resource {} → {}:{}  ({} components)",
            name,
            obj.class_name_str(),
            obj.object_name_str(),
            obj.component_count()
        );
        print_dfm_object(bin, obj, 1);
    }
}

fn print_dfm_object(bin: &DelphiBinary<'_>, obj: &DfmObject<'_>, depth: usize) {
    let indent = "  ".repeat(depth + 1);
    println!(
        "{}<object {}:{}>{}",
        indent,
        obj.class_name_str(),
        obj.object_name_str(),
        if obj.properties.is_empty() && obj.children.is_empty() {
            " (empty)"
        } else {
            ""
        }
    );
    // Try to resolve the component's class via the class set so we can
    // look up each property's declared type for symbolic rendering, and
    // cross-link event handlers to the method-table entry that carries
    // the code VA.
    let cls = bin.classes().find_by_name(obj.class_name_str());
    for p in &obj.properties {
        let rendered = render_property_value(bin, cls, p);
        let name = p.name_str();
        let handler_link = if name.starts_with("On")
            && let DfmValue::String(method) = &p.value
            && let Ok(method_name) = str::from_utf8(method)
            && let Some(cl) = cls
            && let Some(va) = bin.resolve_event_handler(cl, method_name)
        {
            format!("  → 0x{:x}", va)
        } else if name.starts_with("On")
            && let DfmValue::String(method) = &p.value
        {
            // Handler was referenced but couldn't be resolved — still log
            // that it's an event handler for clarity.
            let _ = method;
            String::new()
        } else {
            String::new()
        };
        println!("{}  {} = {}{}", indent, name, rendered, handler_link);
    }
    for c in &obj.children {
        print_dfm_object(bin, c, depth + 1);
    }
}

/// Render a DFM property value, consulting RTTI to resolve enum/set names
/// when the declaring class's class set exposes the property.
fn render_property_value<'a>(
    bin: &DelphiBinary<'a>,
    class: Option<&Class<'a>>,
    prop: &DfmProperty<'_>,
) -> String {
    // Walk from class → property with matching name → resolved type.
    if let Some(cls) = class {
        // Walk ancestry so inherited properties are found.
        let mut walker: Option<&Class<'_>> = Some(cls);
        while let Some(c) = walker {
            for rp in bin.properties(c) {
                if rp.name_str().eq_ignore_ascii_case(prop.name_str())
                    && let Some(detail) = bin.property_type_detail(c, &rp)
                {
                    return render_value_with_detail(bin, &prop.value, &detail);
                }
            }
            walker = c.parent_index.and_then(|idx| bin.classes().get(idx));
        }
    }
    render_value(&prop.value, None)
}

fn render_value_with_detail(
    bin: &DelphiBinary<'_>,
    value: &DfmValue<'_>,
    detail: &TypeDetail<'_>,
) -> String {
    match (value, detail) {
        (DfmValue::Int(i), TypeDetail::Enumeration(e)) => render_enum_ordinal(*i, e),
        (DfmValue::Int(mask), TypeDetail::Set(s)) => {
            // Resolve the set's element enumeration to render names.
            let Some(elem_header) = s.element_type else {
                return format!("0x{:x}", mask);
            };
            // Follow the element header to decode the enum.
            if let Some(enum_info) = decode_tkenum(bin.ctx(), elem_header.va, bin.flavor()) {
                render_set_mask_with_enum(*mask as u32, &enum_info)
            } else {
                format!("set 0x{:x}", mask)
            }
        }
        _ => render_value(value, Some(detail)),
    }
}

fn print_enum_catalog(bin: &DelphiBinary<'_>) {
    let flavor = bin.flavor();
    let ctx = bin.ctx();
    let mut seen: BTreeMap<u64, String> = Default::default();
    for class in bin.classes().iter() {
        for p in bin.properties(class) {
            if let Some(th) = bin.property_type(class, &p)
                && matches!(th.kind, TypeKind::Enumeration)
            {
                seen.entry(th.va)
                    .or_insert_with(|| th.name_str().to_owned());
            }
        }
    }
    if seen.is_empty() {
        return;
    }
    section_header(&format!("enumeration types — {} distinct", seen.len()));
    for (va, name) in &seen {
        let Some(info) = decode_tkenum(ctx, *va, flavor) else {
            continue;
        };
        let names: Vec<_> = info
            .values
            .iter()
            .map(|v| String::from_utf8_lossy(v).into_owned())
            .collect();
        println!(
            "  {:<28} [{}..{}] ord={:?} unit={}  = {{{}}}",
            name,
            info.min,
            info.max,
            info.ord,
            info.unit_name
                .map(|u| String::from_utf8_lossy(u).into_owned())
                .unwrap_or_else(|| "?".into()),
            names.join(", ")
        );
    }

    // Also walk every field type that's a Record, DynArray, Interface, or
    // ClassRef and print their rich RTTI so the dump reveals the full type
    // graph.
    let mut rich_types: BTreeMap<u64, TypeDetail<'_>> = Default::default();
    for class in bin.classes().iter() {
        for f in bin.fields(class) {
            if let FieldTypeRef::TypeInfoPtr(pptr) = f.type_ref
                && let Some(ti_va) = deref_pptypeinfo(ctx, pptr, class.pointer_size() as usize)
                && let Some(detail) = decode_type_detail(ctx, ti_va, flavor)
                && matches!(
                    detail,
                    TypeDetail::Record(_)
                        | TypeDetail::DynArray(_)
                        | TypeDetail::Interface(_)
                        | TypeDetail::ClassRef(_)
                )
            {
                rich_types.entry(detail.header().va).or_insert(detail);
            }
        }
    }
    if !rich_types.is_empty() {
        section_header(&format!(
            "record / dynarray / interface / classref types — {} distinct",
            rich_types.len()
        ));
        for detail in rich_types.values() {
            println!("  {}", render_detail_inline(detail));
            if let TypeDetail::Record(r) = detail {
                for (i, f) in r.managed_fields.iter().enumerate() {
                    let ty = f
                        .field_type
                        .map(|h| h.name_str().to_string())
                        .unwrap_or_else(|| format!("0x{:x}", f.type_ref));
                    println!("      [{}] +0x{:x}  {}", i, f.offset, ty);
                }
            }
        }
    }
}

fn section_header(title: &str) {
    println!("\n==================================================");
    println!(" {}", title);
    println!("==================================================");
}

fn print_interface_xref(bin: &DelphiBinary<'_>) {
    let xref = interface_implementors(bin);
    if xref.is_empty() {
        return;
    }
    section_header(&format!(
        "interface implementors — {} distinct interfaces",
        xref.len()
    ));
    for (iface, classes) in &xref {
        println!("\n  {} — {} implementors", iface, classes.len());
        for c in classes.iter().take(20) {
            println!("    {}", c);
        }
        if classes.len() > 20 {
            println!("    ... {} more", classes.len() - 20);
        }
    }
}

fn print_dfm_class_xref(bin: &DelphiBinary<'_>) {
    let xref = dfm_class_instantiations(bin);
    if xref.is_empty() {
        return;
    }
    section_header(&format!(
        "DFM class instantiations — {} distinct component classes",
        xref.len()
    ));
    let mut entries: Vec<_> = xref.iter().collect();
    entries.sort_by_key(|(_, v)| Reverse(v.len()));
    for (class_name, forms) in entries.iter().take(60) {
        println!(
            "  {:<40} {:>5} uses  (first forms: {})",
            class_name,
            forms.len(),
            forms.iter().take(5).cloned().collect::<Vec<_>>().join(", ")
        );
    }
    if entries.len() > 60 {
        println!("  ... {} more classes", entries.len() - 60);
    }
}

fn print_unit_summary(bin: &DelphiBinary<'_>) {
    let stats = unit_stats(bin);
    if stats.is_empty() {
        return;
    }
    section_header(&format!("per-unit summary — {} units", stats.len()));
    println!(
        "  {:<34} {:>7} {:>7} {:>7} {:>7} {:>7} {:>11}",
        "unit", "classes", "fields", "meths", "props", "ifaces", "inst bytes"
    );
    for s in &stats {
        println!(
            "  {:<34} {:>7} {:>7} {:>7} {:>7} {:>7} {:>11}",
            s.name,
            s.classes,
            s.fields,
            s.methods,
            s.properties,
            s.interfaces,
            s.total_instance_bytes
        );
    }
}

fn print_external_refs(bin: &DelphiBinary<'_>) {
    let ext = external_class_refs(bin);
    if ext.is_empty() {
        return;
    }
    section_header(&format!(
        "external class references — {} classes inherit from out-of-image parents",
        ext.len()
    ));
    for e in &ext {
        println!(
            "  {:<40} unit={:<30} parent_vmt=0x{:x}",
            e.local_class, e.local_unit, e.external_parent_va
        );
    }
}

fn print_event_bindings(bin: &DelphiBinary<'_>) {
    let all = event_bindings(bin);
    if all.is_empty() {
        return;
    }
    section_header(&format!(
        "DFM event bindings — {} total bindings across all forms",
        all.len()
    ));
    let by_method = events_by_method(bin);
    println!("  {} distinct target methods", by_method.len());
    // Top-50 most-bound methods.
    let mut ranked: Vec<_> = by_method.iter().collect();
    ranked.sort_by_key(|(_, v)| Reverse(v.len()));
    for (method, bindings) in ranked.iter().take(50) {
        let va = bindings
            .iter()
            .find_map(|b| b.code_va)
            .map(|v| format!("0x{:x}", v))
            .unwrap_or_else(|| "?".to_owned());
        println!("\n  {}  (VA {}, {} bindings)", method, va, bindings.len());
        for b in bindings.iter().take(10) {
            println!(
                "    {}.{}  event={}",
                b.form_resource, b.component_path, b.event_name
            );
        }
        if bindings.len() > 10 {
            println!("    ... {} more", bindings.len() - 10);
        }
    }
    if ranked.len() > 50 {
        println!("\n  ... {} more methods", ranked.len() - 50);
    }
}

fn print_blob_catalog(bin: &DelphiBinary<'_>) {
    let forms = bin.forms();
    let blobs = catalog_blobs(forms);
    if blobs.is_empty() {
        return;
    }
    section_header(&format!("DFM embedded binaries — {} blobs", blobs.len()));
    // Group by kind.
    let mut by_kind: BTreeMap<&'static str, Vec<&EmbeddedBlob<'_>>> = Default::default();
    for b in &blobs {
        by_kind.entry(b.kind.label()).or_default().push(b);
    }
    for (kind, list) in &by_kind {
        let total_size: usize = list.iter().map(|b| b.data.len()).sum();
        println!(
            "\n  {} — {} blobs, {} bytes total",
            kind,
            list.len(),
            total_size
        );
        for b in list.iter().take(20) {
            println!(
                "    [{}B]  {}.{}  ({})",
                b.data.len(),
                b.path,
                b.property_name,
                b.form_resource
            );
        }
        if list.len() > 20 {
            println!("    ... {} more", list.len() - 20);
        }
    }
}
