//! Class extraction built on top of [`crate::vmt`].
//!
//! The [`ClassSet`] wraps the list of VMTs found by the scanner, indexes
//! them by VMT base VA (which is the value Delphi's `vmtParent` slot holds —
//! per ESET DelphiHelper's `__ResolveParent`), and resolves parent → child
//! relationships. Class-name strings still point back at the caller's
//! byte buffer.
//!
//! The `Class` API deliberately stays thin in this iteration. Per-class
//! properties (from the field / method / RTTI tables) land in iteration 3;
//! see `RESEARCH.md §13.4` for the delivery plan.

use std::collections::{BTreeMap, HashMap, HashSet};

use crate::{
    formats::BinaryContext,
    vmt::{self, Vmt},
};

/// A single class, discovered by scanning VMTs.
#[derive(Debug, Clone, Copy)]
pub struct Class<'a> {
    /// Decoded VMT header.
    pub vmt: Vmt<'a>,
    /// Index of the parent class within the [`ClassSet`], or `None` if the
    /// parent VMT could not be resolved (root class `TObject`, or the
    /// parent lies outside the scanned region).
    pub parent_index: Option<usize>,
}

impl<'a> Class<'a> {
    /// Class name as `&str`, falling back to `"<non-ascii>"` if the bytes are
    /// not UTF-8. Delphi names are always ASCII in practice.
    pub fn name(&self) -> &'a str {
        self.vmt.class_name_str().unwrap_or("<non-ascii>")
    }

    /// Instance size in bytes.
    #[inline]
    pub fn instance_size(&self) -> u32 {
        self.vmt.instance_size
    }

    /// Virtual address of the VMT base.
    #[inline]
    pub fn vmt_va(&self) -> u64 {
        self.vmt.va
    }

    /// Pointer width of this class's VMT in bytes.
    #[inline]
    pub fn pointer_size(&self) -> u8 {
        self.vmt.pointer_size
    }

    /// Header slot count inferred from the VMT's `vmtSelfPtr` value.
    #[inline]
    pub fn header_slots(&self) -> u8 {
        self.vmt.header_slot_count
    }

    /// Whether the class declares any interfaces (interface table pointer
    /// is non-zero).
    #[inline]
    pub fn has_interfaces(&self) -> bool {
        self.vmt.intf_table != 0
    }

    /// Whether the class has any published methods.
    #[inline]
    pub fn has_method_table(&self) -> bool {
        self.vmt.method_table != 0
    }

    /// Whether the class has any published fields.
    #[inline]
    pub fn has_field_table(&self) -> bool {
        self.vmt.field_table != 0
    }

    /// Whether the class has an RTTI `PTypeInfo` record.
    #[inline]
    pub fn has_type_info(&self) -> bool {
        self.vmt.type_info != 0
    }
}

/// Ordered collection of classes discovered in a binary, indexed for fast
/// parent / ancestor queries.
#[derive(Debug)]
pub struct ClassSet<'a> {
    classes: Vec<Class<'a>>,
    by_vmt_va: HashMap<u64, usize>,
    by_name: HashMap<&'a str, usize>,
}

impl<'a> ClassSet<'a> {
    /// Scan `ctx` and build a complete class set.
    ///
    /// This runs the VMT scanner from [`crate::vmt::scan`] and resolves
    /// parent relationships in a second pass.
    pub fn from_ctx(ctx: &BinaryContext<'a>) -> Self {
        let vmts = vmt::scan(ctx);
        Self::from_vmts_with_ctx(vmts, Some(ctx))
    }

    /// Build a class set from a pre-computed VMT list, without the binary
    /// context. Used by unit tests; production callers should use
    /// [`Self::from_ctx`] so that FPC's indirect parent references can be
    /// dereferenced.
    pub fn from_vmts(vmts: Vec<Vmt<'a>>) -> Self {
        Self::from_vmts_with_ctx(vmts, None)
    }

    fn from_vmts_with_ctx(vmts: Vec<Vmt<'a>>, ctx: Option<&BinaryContext<'a>>) -> Self {
        // First pass: build the by-VMT-VA index so parent resolution can
        // look up in it. Delphi's `vmtParent` holds the parent's VMT base
        // VA directly; FPC sometimes emits a `PClass` indirection instead
        // (a pointer that *points at* the parent VMT base), which is why
        // we also try a one-level dereference below.
        let mut by_vmt_va: HashMap<u64, usize> = HashMap::with_capacity(vmts.len());
        for (i, v) in vmts.iter().enumerate() {
            by_vmt_va.insert(v.va, i);
        }

        let mut classes = Vec::with_capacity(vmts.len());
        let mut by_name: HashMap<&'a str, usize> = HashMap::with_capacity(vmts.len());
        for (i, vmt) in vmts.into_iter().enumerate() {
            let parent_index = resolve_parent(&vmt, &by_vmt_va, ctx);
            let class = Class { vmt, parent_index };
            if let Some(name) = class.vmt.class_name_str() {
                by_name.entry(name).or_insert(i);
            }
            classes.push(class);
        }

        Self {
            classes,
            by_vmt_va,
            by_name,
        }
    }

    /// Number of classes discovered.
    #[inline]
    pub fn len(&self) -> usize {
        self.classes.len()
    }

    /// Whether any classes were discovered.
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.classes.is_empty()
    }

    /// Iterate all classes in discovery order.
    #[inline]
    pub fn iter(&self) -> impl Iterator<Item = &Class<'a>> {
        self.classes.iter()
    }

    /// Access a class by its index. Panics on out-of-bounds.
    #[inline]
    pub fn get(&self, index: usize) -> Option<&Class<'a>> {
        self.classes.get(index)
    }

    /// Look up a class by its exact name (case-sensitive). Delphi class names
    /// are case-sensitive in the VMT.
    #[inline]
    pub fn find_by_name(&self, name: &str) -> Option<&Class<'a>> {
        self.by_name.get(name).and_then(|&i| self.classes.get(i))
    }

    /// Look up a class by its VMT base VA.
    #[inline]
    pub fn find_by_vmt_va(&self, va: u64) -> Option<&Class<'a>> {
        self.by_vmt_va.get(&va).and_then(|&i| self.classes.get(i))
    }

    /// Root `TObject`, if present (the class whose parent chain terminates
    /// at a null `vmtParent`). Multiple root candidates can exist in a
    /// heavily packed binary where VMT fragments survive — the first found
    /// wins.
    pub fn root(&self) -> Option<&Class<'a>> {
        self.classes.iter().find(|c| c.parent_index.is_none())
    }

    /// Iterate the ancestry chain of a class, starting with its immediate
    /// parent and walking toward `TObject`. Protects against cycles.
    pub fn ancestors(&'a self, class: &'a Class<'a>) -> Ancestors<'a> {
        Ancestors {
            set: self,
            current: class.parent_index,
            visited: HashSet::new(),
        }
    }

    /// Iterate direct children of `class`. Cost is linear in the class set
    /// size; callers that need children for many classes should build their
    /// own adjacency table.
    pub fn children<'b>(&'b self, class: &'b Class<'a>) -> impl Iterator<Item = &'b Class<'a>> {
        let target = class.vmt.va;
        self.classes
            .iter()
            .filter(move |c| c.vmt.parent_vmt == target)
    }

    /// Count classes with no parent index — the sum of genuine roots and
    /// classes whose parent VMT points outside the scanned set. For a clean
    /// standalone EXE this is typically `1` (just `TObject`); for a BPL
    /// runtime package it is much higher because every class imports its
    /// parent from a dependency package. Prefer [`Self::root_count`] and
    /// [`Self::external_parent_count`] when you need to tell the two apart.
    pub fn orphan_count(&self) -> usize {
        self.classes
            .iter()
            .filter(|c| c.parent_index.is_none())
            .count()
    }

    /// Count classes whose `vmtParent` is null — genuine ancestry roots like
    /// Delphi's `TObject`. Typically `1` for a standalone EXE and `0` for a
    /// BPL (whose `TObject` lives in `rtl*.bpl`).
    pub fn root_count(&self) -> usize {
        self.classes
            .iter()
            .filter(|c| c.vmt.parent_vmt == 0)
            .count()
    }

    /// Count classes with a non-null `vmtParent` that doesn't resolve to any
    /// VMT in the scanned set. These inherit from a class exported by a
    /// dependency package — the expected shape for BPL runtime packages.
    pub fn external_parent_count(&self) -> usize {
        self.classes
            .iter()
            .filter(|c| c.parent_index.is_none() && c.vmt.parent_vmt != 0)
            .count()
    }

    /// Build adjacency mapping from parent-index to a vector of child
    /// indices. Useful for tree rendering. O(n) construction.
    pub fn child_map(&self) -> BTreeMap<usize, Vec<usize>> {
        let mut map: BTreeMap<usize, Vec<usize>> = Default::default();
        for (i, c) in self.classes.iter().enumerate() {
            if let Some(p) = c.parent_index {
                map.entry(p).or_default().push(i);
            }
        }
        map
    }

    /// Roots — classes with no in-set parent (i.e. `TObject` and stragglers).
    pub fn roots(&self) -> Vec<usize> {
        self.classes
            .iter()
            .enumerate()
            .filter_map(|(i, c)| c.parent_index.is_none().then_some(i))
            .collect()
    }

    /// Render an indented ASCII tree of the class hierarchy. `max_children`
    /// caps how many children of each node are printed to keep output
    /// bounded on huge binaries.
    pub fn render_tree(&self, max_children: usize) -> String {
        let child_map = self.child_map();
        let mut out = String::new();
        for root in self.roots() {
            render_tree_node(self, &child_map, root, 0, max_children, &mut out);
        }
        out
    }

    /// Maximum depth of the class tree (root = depth 0).
    pub fn max_depth(&self) -> usize {
        let mut best = 0;
        for i in 0..self.classes.len() {
            let mut depth = 0;
            let mut node = self.classes[i].parent_index;
            let mut visited = 0;
            while let Some(idx) = node {
                depth += 1;
                visited += 1;
                if visited > self.classes.len() {
                    break; // cycle guard
                }
                node = self.classes[idx].parent_index;
            }
            if depth > best {
                best = depth;
            }
        }
        best
    }
}

/// Resolve the parent pointer of `vmt` to a class index.
///
/// Tries, in order:
/// 1. Null `vmtParent` → `None` (a root class).
/// 2. Direct match in the `by_vmt_va` index (Delphi and simple FPC).
/// 3. (FPC only) Dereference the parent pointer once through the binary
///    context and match the target (FPC's `PClass`-style indirection).
fn resolve_parent<'a>(
    vmt: &Vmt<'a>,
    by_vmt_va: &HashMap<u64, usize>,
    ctx: Option<&BinaryContext<'a>>,
) -> Option<usize> {
    if vmt.parent_vmt == 0 {
        return None;
    }
    if let Some(&idx) = by_vmt_va.get(&vmt.parent_vmt) {
        return Some(idx);
    }
    // FPC indirection fallback: read a pointer at parent_vmt and look that up.
    let ctx = ctx?;
    let psize = vmt.pointer_size as usize;
    let file_off = ctx.va_to_file(vmt.parent_vmt)?;
    let data = ctx.data();
    let slice = data.get(file_off..file_off + psize)?;
    let deref = match psize {
        4 => u32::from_le_bytes(slice.try_into().ok()?) as u64,
        8 => u64::from_le_bytes(slice.try_into().ok()?),
        _ => return None,
    };
    by_vmt_va.get(&deref).copied()
}

fn render_tree_node(
    set: &ClassSet<'_>,
    child_map: &BTreeMap<usize, Vec<usize>>,
    idx: usize,
    depth: usize,
    max_children: usize,
    out: &mut String,
) {
    use std::fmt::Write;
    let Some(class) = set.classes.get(idx) else {
        return;
    };
    let pad = "  ".repeat(depth);
    let _ = writeln!(
        out,
        "{}└─ {}  size={}B  vmt=0x{:x}",
        pad,
        class.name(),
        class.instance_size(),
        class.vmt_va()
    );
    if let Some(children) = child_map.get(&idx) {
        let shown = children.len().min(max_children);
        for &child in &children[..shown] {
            render_tree_node(set, child_map, child, depth + 1, max_children, out);
        }
        if children.len() > shown {
            let _ = writeln!(out, "{}  ... {} more children", pad, children.len() - shown);
        }
    }
}

/// Iterator over a class's ancestry chain.
#[derive(Debug)]
pub struct Ancestors<'a> {
    set: &'a ClassSet<'a>,
    current: Option<usize>,
    visited: HashSet<usize>,
}

impl<'a> Iterator for Ancestors<'a> {
    type Item = &'a Class<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        let idx = self.current?;
        // Cycle guard: stop the moment we revisit any index. A well-formed
        // chain cannot revisit a class (a class is not its own ancestor).
        if !self.visited.insert(idx) {
            return None;
        }
        let class = self.set.classes.get(idx)?;
        self.current = class.parent_index;
        Some(class)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vmt::{Vmt, VmtFlavor};

    /// Build a VMT stub with the given VMT base VA and parent VMT VA.
    fn stub_vmt(name: &'static str, va: u64, parent_vmt: u64) -> Vmt<'static> {
        let slots: u64 = 22;
        let psize: u64 = 4;
        Vmt {
            flavor: VmtFlavor::Delphi,
            pointer_size: psize as u8,
            header_slot_count: slots as u8,
            va,
            file_offset: 0,
            self_ptr: va + slots * psize,
            intf_table: 0,
            auto_table: 0,
            init_table: 0,
            type_info: 0,
            field_table: 0,
            method_table: 0,
            dynamic_table: 0,
            class_name_ptr: 0,
            instance_size: 16,
            parent_vmt,
            class_name: name.as_bytes(),
        }
    }

    #[test]
    fn resolves_parent_chain() {
        let vmts = vec![
            stub_vmt("TObject", 0x1000, 0),
            stub_vmt("TPersistent", 0x2000, 0x1000),
            stub_vmt("TComponent", 0x3000, 0x2000),
        ];
        let set = ClassSet::from_vmts(vmts);
        assert_eq!(set.len(), 3);
        assert_eq!(set.root().map(|c| c.name()), Some("TObject"));
        let tcomp = set.find_by_name("TComponent").expect("TComponent found");
        let ancestors: Vec<_> = set.ancestors(tcomp).map(|c| c.name()).collect();
        assert_eq!(ancestors, vec!["TPersistent", "TObject"]);
        assert_eq!(set.max_depth(), 2);
        assert_eq!(set.orphan_count(), 1);
        assert_eq!(set.root_count(), 1);
        assert_eq!(set.external_parent_count(), 0);
    }

    #[test]
    fn bpl_style_external_parents_are_categorised_separately() {
        // Simulate a BPL: no local TObject; every class's parent points into
        // a thunk address outside the set. `orphan_count` stays `N`, but
        // the split API reports `roots=0, external_parent=N`.
        let vmts = vec![
            stub_vmt("TAnalyzerImpl", 0x10000, 0xA000), // thunk into vcl290.bpl
            stub_vmt("TCurrentAnalysis", 0x11000, 0xA000),
            stub_vmt("TArrayUtils", 0x12000, 0xA000),
        ];
        let set = ClassSet::from_vmts(vmts);
        assert_eq!(set.len(), 3);
        assert_eq!(set.orphan_count(), 3);
        assert_eq!(set.root_count(), 0);
        assert_eq!(set.external_parent_count(), 3);
    }

    #[test]
    fn ancestors_iterator_handles_cycle() {
        // Intentionally malformed: A's parent is B, B's parent is A.
        let vmts = vec![stub_vmt("A", 0x1000, 0x2000), stub_vmt("B", 0x2000, 0x1000)];
        let set = ClassSet::from_vmts(vmts);
        let a = set.find_by_name("A").unwrap();
        // Cycle guard yields each member of the cycle exactly once, then stops.
        let names: Vec<_> = set.ancestors(a).map(|c| c.name()).collect();
        assert_eq!(names, vec!["B", "A"]);
    }

    #[test]
    fn ancestors_iterator_handles_self_loop() {
        // Self-loop: A's parent is itself.
        let vmts = vec![stub_vmt("A", 0x1000, 0x1000)];
        let set = ClassSet::from_vmts(vmts);
        let a = set.find_by_name("A").unwrap();
        let names: Vec<_> = set.ancestors(a).map(|c| c.name()).collect();
        assert_eq!(names, vec!["A"]);
    }

    #[test]
    fn find_by_vmt_va_works() {
        let vmts = vec![stub_vmt("TFoo", 0xDEAD, 0)];
        let set = ClassSet::from_vmts(vmts);
        assert_eq!(set.find_by_vmt_va(0xDEAD).map(|c| c.name()), Some("TFoo"));
        assert!(set.find_by_vmt_va(0xBEEF).is_none());
    }
}
