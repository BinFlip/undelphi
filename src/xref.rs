//! Cross-references derived from the already-extracted metadata.
//!
//! Builds analysis views that answer questions like "which classes
//! implement `IUnknown`?" or "which forms instantiate a `TButton`?" by
//! walking the `ClassSet`, `interfaces(...)`, and parsed-DFM tree.
//!
//! These views are built on-demand from existing data — no extra binary
//! scanning required. They allocate, which is the point: returning owned
//! maps keyed by GUID or class-name is much more useful than forcing
//! callers to re-walk the corpus.

use std::{
    collections::{BTreeMap, HashMap},
    str,
};

use crate::{
    DelphiBinary,
    dfm::{DfmObject, DfmValue},
    interfaces::Guid,
};

/// For each interface GUID seen across the binary, record which classes
/// implement it (referenced by class name for readability).
pub fn interface_implementors(bin: &DelphiBinary<'_>) -> BTreeMap<String, Vec<String>> {
    let mut out: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for class in bin.classes().iter() {
        for ie in bin.interfaces(class) {
            let key = format_interface_key(&ie.guid, ie.iid_str);
            out.entry(key).or_default().push(class.name().to_owned());
        }
    }
    out
}

/// For each class name referenced by any form or nested component in the
/// binary's parsed DFM/LFM resources, record the forms that instantiate
/// it. The result is keyed by component class name (e.g. `TButton`) and
/// maps to the list of form names (e.g. `AboutBox`, `MainForm`).
pub fn dfm_class_instantiations(bin: &DelphiBinary<'_>) -> BTreeMap<String, Vec<String>> {
    let mut out: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for (_, root) in bin.forms() {
        let root_name = root.object_name_str().to_owned();
        walk_dfm(root, &root_name, &mut out);
    }
    out
}

fn walk_dfm(obj: &DfmObject<'_>, form_name: &str, out: &mut BTreeMap<String, Vec<String>>) {
    let class_name = obj.class_name_str().to_owned();
    out.entry(class_name)
        .or_default()
        .push(form_name.to_owned());
    for child in &obj.children {
        walk_dfm(child, form_name, out);
    }
}

/// Per-unit aggregate statistics.
#[derive(Debug, Clone, Default)]
pub struct UnitStats {
    /// Unit name.
    pub name: String,
    /// Number of classes declared in this unit.
    pub classes: usize,
    /// Total published fields across those classes.
    pub fields: usize,
    /// Total published methods across those classes.
    pub methods: usize,
    /// Total published properties across those classes.
    pub properties: usize,
    /// Total published interfaces implemented across those classes.
    pub interfaces: usize,
    /// Sum of instance sizes (bytes) across those classes.
    pub total_instance_bytes: u64,
}

/// Compute per-unit statistics for every unit the class set references.
pub fn unit_stats(bin: &DelphiBinary<'_>) -> Vec<UnitStats> {
    let mut by_unit: HashMap<String, UnitStats> = HashMap::new();
    for c in bin.classes().iter() {
        let unit = bin.unit_name(c).unwrap_or("<unknown>").to_owned();
        let entry = by_unit.entry(unit.clone()).or_insert_with(|| UnitStats {
            name: unit.clone(),
            ..Default::default()
        });
        entry.classes += 1;
        entry.fields += bin.fields(c).len();
        entry.methods += bin.methods(c).len();
        entry.properties += bin.properties(c).len();
        entry.interfaces += bin.interfaces(c).len();
        entry.total_instance_bytes += c.instance_size() as u64;
    }
    let mut out: Vec<UnitStats> = by_unit.into_values().collect();
    out.sort_by(|a, b| b.classes.cmp(&a.classes).then(a.name.cmp(&b.name)));
    out
}

/// A class whose `vmtParent` pointer doesn't resolve inside the scanned
/// image — it inherits from a class exported by an external package.
#[derive(Debug, Clone)]
pub struct ExternalClassRef {
    /// Name of the local class that inherits externally.
    pub local_class: String,
    /// Local class's declaring unit.
    pub local_unit: String,
    /// Unresolved parent VMT VA.
    pub external_parent_va: u64,
}

/// List every class whose parent pointer isn't in our class set (root
/// classes excluded — those legitimately have no parent).
pub fn external_class_refs(bin: &DelphiBinary<'_>) -> Vec<ExternalClassRef> {
    let classes = bin.classes();
    let mut out = Vec::new();
    for c in classes.iter() {
        if c.parent_index.is_some() {
            continue;
        }
        if c.vmt.parent_vmt == 0 {
            continue; // genuine root
        }
        out.push(ExternalClassRef {
            local_class: c.name().to_owned(),
            local_unit: bin.unit_name(c).unwrap_or("<unknown>").to_owned(),
            external_parent_va: c.vmt.parent_vmt,
        });
    }
    out.sort_by(|a, b| a.local_class.cmp(&b.local_class));
    out
}

/// One entry in the DFM event-handler reverse map.
#[derive(Debug, Clone)]
pub struct HandlerBinding {
    /// Form resource name.
    pub form_resource: String,
    /// Dotted path to the component carrying the event
    /// (e.g. `MainForm.btnAbout`).
    pub component_path: String,
    /// Event property name (`OnClick`, `OnCreate`, …).
    pub event_name: String,
    /// Name of the method the event binds to.
    pub method_name: String,
    /// Resolved code VA when cross-linking succeeded.
    pub code_va: Option<u64>,
}

/// For every DFM event property in every form, record the binding.
/// Rendered two ways by the dump: (a) grouped by binding, (b) grouped by
/// method-name (the reverse view — "what calls this method?").
pub fn event_bindings(bin: &DelphiBinary<'_>) -> Vec<HandlerBinding> {
    let forms = bin.forms();
    let mut out = Vec::new();
    for (resource, root) in forms {
        let root_path = root.object_name_str().to_owned();
        collect_bindings(bin, root, resource, &root_path, &mut out);
    }
    out
}

fn collect_bindings(
    bin: &DelphiBinary<'_>,
    obj: &DfmObject<'_>,
    resource: &str,
    path: &str,
    out: &mut Vec<HandlerBinding>,
) {
    let cls = bin.classes().find_by_name(obj.class_name_str());
    for p in &obj.properties {
        let name = p.name_str();
        if !name.starts_with("On") {
            continue;
        }
        let DfmValue::String(method) = &p.value else {
            continue;
        };
        let Ok(method_name) = str::from_utf8(method) else {
            continue;
        };
        let code_va = cls.and_then(|c| bin.resolve_event_handler(c, method_name));
        out.push(HandlerBinding {
            form_resource: resource.to_owned(),
            component_path: path.to_owned(),
            event_name: name.to_owned(),
            method_name: method_name.to_owned(),
            code_va,
        });
    }
    for child in &obj.children {
        let child_path = if child.object_name_str().is_empty() {
            format!("{}.{}", path, child.class_name_str())
        } else {
            format!("{}.{}", path, child.object_name_str())
        };
        collect_bindings(bin, child, resource, &child_path, out);
    }
}

/// Pivot `event_bindings()` into a map keyed by method name →
/// list of events that bind to it.
pub fn events_by_method(bin: &DelphiBinary<'_>) -> BTreeMap<String, Vec<HandlerBinding>> {
    let mut by_method: BTreeMap<String, Vec<HandlerBinding>> = BTreeMap::new();
    for b in event_bindings(bin) {
        by_method.entry(b.method_name.clone()).or_default().push(b);
    }
    by_method
}

/// Format an interface key. Non-zero GUID → canonical form; otherwise the
/// Corba IID-string when available; else `<anonymous>`.
fn format_interface_key(guid: &Guid, iid_str: Option<&[u8]>) -> String {
    let zero =
        guid.data1 == 0 && guid.data2 == 0 && guid.data3 == 0 && guid.data4.iter().all(|&b| b == 0);
    if !zero {
        guid.to_string_delphi()
    } else if let Some(s) = iid_str {
        String::from_utf8_lossy(s).into_owned()
    } else {
        "<anonymous>".to_owned()
    }
}
