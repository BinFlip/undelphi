//! Aggregated code-entrypoint enumeration.
//!
//! Disassembler-driving consumers want a single call that produces every
//! VA we can confidently label as a function entry point — published
//! methods, virtual-method slots, dynamic-message handlers, interface
//! getters, property getters/setters/stored functions, attribute
//! constructors, unit init / finalize procedures.
//!
//! Building this list by hand requires walking ~10 different APIs and
//! understanding the slot-index → VA lookup for `AccessKind::Virtual`.
//! [`DelphiBinary::code_entrypoints`](crate::DelphiBinary::code_entrypoints)
//! does it once.
//!
//! Duplicates across kinds are emitted, since a method reached via both
//! its published-table entry and its VMT slot is the same byte address
//! but warrants a different label depending on consumer priority. Dedup
//! is the consumer's job.

use crate::{
    DelphiBinary,
    classes::Class,
    properties::{Access, AccessKind, AccessTarget},
    vtable::VirtualMethodEntry,
};

/// Why a code VA is being labelled.
///
/// Used as a hint for naming and as a way to group entries by source.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EntrypointKind {
    /// Reached through a class's published-method table (`MethodEntry`).
    PublishedMethod,
    /// Reached through a class's virtual-method-pointer array
    /// (`VirtualMethodEntry`).
    VmtSlot,
    /// Reached through a class's dynamic-dispatch table (`DynamicSlot`).
    DynamicMessage,
    /// Reached through a class's interface getter (`InterfaceEntry::getter_va`).
    InterfaceGetter,
    /// Reached through an interface vtable pointer
    /// (`InterfaceMethod::code_va`).
    InterfaceMethod,
    /// A property's getter function (static or virtual-resolved).
    PropertyGetter,
    /// A property's setter function (static or virtual-resolved).
    PropertySetter,
    /// A property's `stored` function (static or virtual-resolved).
    PropertyStored,
    /// Constructor of an `[attribute]` annotation
    /// (`AttributeEntry::attr_ctor`).
    AttributeCtor,
    /// A unit's `initialization` procedure
    /// (`UnitInitProc::init_va`).
    UnitInit,
    /// A unit's `finalization` procedure
    /// (`UnitInitProc::finalize_va`).
    UnitFinalize,
}

/// One labelled code entry point.
#[derive(Debug, Clone)]
pub struct CodeEntrypoint<'a> {
    /// Absolute VA. Subtract the image base for an RVA.
    pub va: u64,
    /// What kind of entry point this is — naming hint.
    pub kind: EntrypointKind,
    /// Owning class, when applicable.
    pub class: Option<&'a Class<'a>>,
    /// Suggested label, e.g. `TForm1.Button1Click`. Borrowed where
    /// possible, owned where the kind requires synthesising the name.
    pub name_hint: String,
}

impl<'a> CodeEntrypoint<'a> {
    fn new(va: u64, kind: EntrypointKind, class: Option<&'a Class<'a>>, name_hint: String) -> Self {
        Self {
            va,
            kind,
            class,
            name_hint,
        }
    }
}

/// Collect every code VA the crate can confidently label.
///
/// Walks every class's published methods, VMT slots, dynamic-message
/// slots, interface getters, property getters/setters/stored, plus the
/// global unit init/finalize table. Produces duplicates across kinds —
/// dedup is the caller's job, since they typically have a kind-priority.
pub fn collect<'a>(bin: &'a DelphiBinary<'a>) -> Vec<CodeEntrypoint<'a>> {
    let mut out: Vec<CodeEntrypoint<'a>> = Vec::new();

    for class in bin.classes().iter() {
        let class_name = class.name();

        // Published methods.
        for m in bin.methods(class) {
            out.push(CodeEntrypoint::new(
                m.code_va,
                EntrypointKind::PublishedMethod,
                Some(class),
                format!("{}.{}", class_name, m.name()),
            ));
        }

        // Virtual-method slots.
        let vmethods = bin.virtual_methods(class);
        for v in &vmethods {
            out.push(CodeEntrypoint::new(
                v.code_va,
                EntrypointKind::VmtSlot,
                Some(class),
                format!("{}.vmt[{}]", class_name, v.slot),
            ));
        }

        // Dynamic-dispatch slots.
        for d in bin.dynamic_slots(class) {
            out.push(CodeEntrypoint::new(
                d.handler_va,
                EntrypointKind::DynamicMessage,
                Some(class),
                format!("{}.dyn[idx={}]", class_name, d.index),
            ));
        }

        // Interfaces — getter and (when known) per-method pointers.
        for entry in bin.interfaces(class) {
            if entry.getter_va != 0 {
                out.push(CodeEntrypoint::new(
                    entry.getter_va,
                    EntrypointKind::InterfaceGetter,
                    Some(class),
                    format!("{}.intfgetter[{}]", class_name, entry.guid),
                ));
            }
            for im in bin.interface_methods(&entry) {
                out.push(CodeEntrypoint::new(
                    im.code_va,
                    EntrypointKind::InterfaceMethod,
                    Some(class),
                    match im.name {
                        Some(name) => format!("{}.intf[{}].{}", class_name, entry.guid, name),
                        None => {
                            format!("{}.intf[{}].slot{}", class_name, entry.guid, im.slot_index)
                        }
                    },
                ));
            }
        }

        // Published-property accessors.
        for p in bin.properties(class) {
            push_property_access(
                &mut out,
                class,
                class_name,
                p.name(),
                p.get,
                EntrypointKind::PropertyGetter,
                &vmethods,
            );
            push_property_access(
                &mut out,
                class,
                class_name,
                p.name(),
                p.set,
                EntrypointKind::PropertySetter,
                &vmethods,
            );
            push_property_access(
                &mut out,
                class,
                class_name,
                p.name(),
                p.stored,
                EntrypointKind::PropertyStored,
                &vmethods,
            );
        }

        // Extended-RTTI properties (private/protected/public).
        for ep in bin.extended_properties(class) {
            push_property_access(
                &mut out,
                class,
                class_name,
                ep.name(),
                ep.get,
                EntrypointKind::PropertyGetter,
                &vmethods,
            );
            push_property_access(
                &mut out,
                class,
                class_name,
                ep.name(),
                ep.set,
                EntrypointKind::PropertySetter,
                &vmethods,
            );
            push_property_access(
                &mut out,
                class,
                class_name,
                ep.name(),
                ep.stored,
                EntrypointKind::PropertyStored,
                &vmethods,
            );
        }

        // Class-level [attribute] constructors. Returns empty in v0.2.0
        // (see DelphiBinary::class_attributes); the call is here so the
        // helper picks them up automatically once the table-VA extractor
        // lands.
        for attr in bin.class_attributes(class) {
            out.push(CodeEntrypoint::new(
                attr.attr_ctor,
                EntrypointKind::AttributeCtor,
                Some(class),
                format!("{}.attr_ctor@0x{:x}", class_name, attr.attr_type_ref),
            ));
        }
    }

    // Unit-level init / finalize. Returns empty in v0.2.0; included for
    // forward-compatibility.
    for unit in bin.unit_init_procs() {
        if let Some(va) = unit.init_va {
            out.push(CodeEntrypoint::new(
                va,
                EntrypointKind::UnitInit,
                None,
                format!("{}.Initialization", unit.unit_name),
            ));
        }
        if let Some(va) = unit.finalize_va {
            out.push(CodeEntrypoint::new(
                va,
                EntrypointKind::UnitFinalize,
                None,
                format!("{}.Finalization", unit.unit_name),
            ));
        }
    }

    out
}

fn push_property_access<'a>(
    out: &mut Vec<CodeEntrypoint<'a>>,
    class: &'a Class<'a>,
    class_name: &str,
    prop_name: &str,
    access: Access,
    kind: EntrypointKind,
    vmethods: &[VirtualMethodEntry],
) {
    let suffix = match kind {
        EntrypointKind::PropertyGetter => "Get",
        EntrypointKind::PropertySetter => "Set",
        EntrypointKind::PropertyStored => "Stored",
        _ => "?",
    };

    match access.kind {
        AccessKind::Static => out.push(CodeEntrypoint::new(
            access.value,
            kind,
            Some(class),
            format!("{}.{}{}", class_name, prop_name, suffix),
        )),
        AccessKind::Virtual => {
            if let AccessTarget::CodeVa(va) = access.resolve(vmethods) {
                out.push(CodeEntrypoint::new(
                    va,
                    kind,
                    Some(class),
                    format!("{}.{}{}", class_name, prop_name, suffix),
                ));
            }
        }
        // Field / Const / None: not a code address.
        _ => {}
    }
}
