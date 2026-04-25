//! Free Pascal internal-resources section walker.
//!
//! On non-PE-RCDATA targets (Mach-O, ELF, and any FPC build that disables
//! `FPC_HAS_WINLIKERESOURCES`), FPC stores resources as a custom tree of
//! `TResInfoNode` records inside a section named
//!
//! - `fpc.resources` in the Mach-O `__DATA` segment
//! - `.fpc.resources` on ELF / PE
//!
//! Authoritative source: `reference/fpc-source/rtl/inc/intres.inc:30-45`.
//! The on-disk structures are:
//!
//! ```text
//! TResHdr (packed):
//!   rootptr:     ptr           pointer to root TResInfoNode
//!   count:       u32           total number of resources
//!   usedhandles: u32           runtime field (initialised to 0 on disk)
//!   handles:     ptr           runtime handles array (null on disk)
//!
//! TResInfoNode (packed):
//!   nameid:       ptr          name pointer, OR an integer ID in the low bits
//!                              (a value ≤ 65535 is an ID)
//!   ncounthandle: u32          count of named sub-entries (interior node)
//!                              OR resource handle (leaf)
//!   idcountsize:  u32          count of ID sub-entries (interior node)
//!                              OR resource size in bytes (leaf)
//!   subptr:       ptr          pointer to first sub-node (interior)
//!                              OR pointer to resource bytes (leaf)
//! ```
//!
//! Tree shape: `root → type_node → name_node → language_node → data`.
//! `name_node` identifiers can be either strings (Pascal-style
//! NUL-terminated `PAnsiChar`) or integer IDs. Per FPC's `BinSearchRes`
//! convention, named entries precede ID entries in each sibling list, so
//! iterating `ncount + idcount` entries from `subptr` visits everything.
//!
//! ## Language nodes
//!
//! A language node's `subptr` points directly at the resource bytes, and
//! its `idcountsize` holds the byte length. We stop at the first language
//! level we find — that's sufficient to expose every resource's body.
//!
//! ## Allocation
//!
//! Resource-body slices are borrowed directly from the binary.

use std::str;

use crate::{formats::BinaryContext, limits::MAX_FPC_RESOURCE_SIBLINGS, util::read_ptr};

/// Resource type identifiers.
pub mod rt {
    /// `RT_CURSOR`.
    pub const CURSOR: u32 = 1;
    /// `RT_ICON`.
    pub const ICON: u32 = 3;
    /// `RT_RCDATA` — custom binary resource (Delphi form streams live here).
    pub const RCDATA: u32 = 10;
    /// `RT_GROUP_CURSOR`.
    pub const GROUP_CURSOR: u32 = 12;
    /// `RT_GROUP_ICON`.
    pub const GROUP_ICON: u32 = 14;
    /// `RT_VERSION`.
    pub const VERSION: u32 = 16;
    /// `RT_MANIFEST`.
    pub const MANIFEST: u32 = 24;
}

/// A single resource located in the FPC resources tree.
#[derive(Debug, Clone)]
pub struct FpcResource<'a> {
    /// Resource type ID (e.g. [`rt::RCDATA`]).
    pub type_id: u32,
    /// String name of the resource if the name entry was a `PAnsiChar`,
    /// otherwise `None` and [`Self::name_id`] is populated instead.
    pub name: Option<String>,
    /// Integer ID of the resource when `name` is `None`.
    pub name_id: Option<u32>,
    /// Language ID.
    pub language: u32,
    /// Resource bytes; borrowed from the input.
    pub data: &'a [u8],
}

/// Walk the FPC resources tree and return every resource under `type_id`.
pub fn iter_type<'a>(ctx: &BinaryContext<'a>, type_id: u32) -> Vec<FpcResource<'a>> {
    let Some(section) = ctx.sections().fpc_resources else {
        return Vec::new();
    };
    let Some(section_bytes) = ctx.section_data(&section) else {
        return Vec::new();
    };
    // We require a valid pointer size. If the container parse failed
    // we cannot reliably decode the resource tree — bail.
    let Some(ptr_size) = ctx.pointer_size() else {
        return Vec::new();
    };
    // The TResHdr sits at the start of the section — rootptr is its first
    // pointer-sized field.
    let root_va = match read_ptr(section_bytes, 0, ptr_size) {
        Some(v) => v,
        None => return Vec::new(),
    };

    let mut out = Vec::new();
    // Read the root node and its type-level children.
    let Some(root) = read_node(ctx, root_va, ptr_size) else {
        return out;
    };
    let type_total = (root.ncount as usize).saturating_add(root.idcount as usize);
    for type_node in iter_siblings(ctx, root.subptr, type_total, ptr_size) {
        if !type_node.name_or_id_is_integer() || type_node.name_or_id as u32 != type_id {
            continue;
        }
        let name_total = (type_node.ncount as usize).saturating_add(type_node.idcount as usize);
        for name_node in iter_siblings(ctx, type_node.subptr, name_total, ptr_size) {
            let lang_total = (name_node.ncount as usize).saturating_add(name_node.idcount as usize);
            for lang_node in iter_siblings(ctx, name_node.subptr, lang_total, ptr_size) {
                // Leaf: subptr → bytes, idcountsize → length.
                let Some(body) = slice_resource_body(ctx, lang_node.subptr, lang_node.idcountsize)
                else {
                    continue;
                };
                out.push(FpcResource {
                    type_id,
                    name: name_node.name_string(ctx),
                    name_id: name_node.name_as_integer(),
                    language: lang_node.name_or_id as u32,
                    data: body,
                });
            }
        }
    }
    out
}

/// Convenience — enumerate every `RT_RCDATA` resource.
#[inline]
pub fn iter_rcdata<'a>(ctx: &BinaryContext<'a>) -> Vec<FpcResource<'a>> {
    iter_type(ctx, rt::RCDATA)
}

struct Node {
    name_or_id: u64,
    ncount: u32,
    idcount: u32,
    subptr: u64,
    idcountsize: u32,
}

impl Node {
    fn node_byte_size(ptr_size: usize) -> Option<usize> {
        ptr_size
            .checked_add(4)?
            .checked_add(4)?
            .checked_add(ptr_size)
    }

    fn name_or_id_is_integer(&self) -> bool {
        self.name_or_id <= 0xFFFF
    }

    fn name_as_integer(&self) -> Option<u32> {
        if self.name_or_id <= 0xFFFF {
            Some(self.name_or_id as u32)
        } else {
            None
        }
    }

    fn name_string(&self, ctx: &BinaryContext<'_>) -> Option<String> {
        if self.name_or_id <= 0xFFFF {
            return None;
        }
        let off = ctx.va_to_file(self.name_or_id)?;
        let data = ctx.data();
        // Null-terminated C string.
        let tail = data.get(off..)?;
        let rel = tail.iter().position(|&b| b == 0)?;
        let end = off.checked_add(rel)?;
        let bytes = data.get(off..end)?;
        str::from_utf8(bytes).ok().map(str::to_owned)
    }
}

fn read_node(ctx: &BinaryContext<'_>, va: u64, ptr_size: usize) -> Option<Node> {
    let off = ctx.va_to_file(va)?;
    let data = ctx.data();
    let name_or_id = read_ptr(data, off, ptr_size)?;
    let ncount_off = off.checked_add(ptr_size)?;
    let idcount_off = ncount_off.checked_add(4)?;
    let subptr_off = idcount_off.checked_add(4)?;
    let ncount_end = ncount_off.checked_add(4)?;
    let idcount_end = idcount_off.checked_add(4)?;
    let ncount = u32::from_le_bytes(data.get(ncount_off..ncount_end)?.try_into().ok()?);
    let idcount = u32::from_le_bytes(data.get(idcount_off..idcount_end)?.try_into().ok()?);
    let subptr = read_ptr(data, subptr_off, ptr_size)?;
    Some(Node {
        name_or_id,
        ncount,
        idcount,
        subptr,
        idcountsize: idcount,
    })
}

/// Iterate `count` sibling [`Node`]s starting at `first_va`, with each
/// node laid out contiguously at `node_byte_size` strides.
fn iter_siblings(
    ctx: &BinaryContext<'_>,
    first_va: u64,
    count: usize,
    ptr_size: usize,
) -> Vec<Node> {
    if first_va == 0 || count > MAX_FPC_RESOURCE_SIBLINGS {
        return Vec::new();
    }
    let Some(stride) = Node::node_byte_size(ptr_size) else {
        return Vec::new();
    };
    let stride = stride as u64;
    let mut out = Vec::with_capacity(count);
    for i in 0..count {
        let Some(offset) = (i as u64).checked_mul(stride) else {
            break;
        };
        let Some(va) = first_va.checked_add(offset) else {
            break;
        };
        let Some(node) = read_node(ctx, va, ptr_size) else {
            break;
        };
        out.push(node);
    }
    out
}

fn slice_resource_body<'a>(ctx: &BinaryContext<'a>, data_va: u64, size: u32) -> Option<&'a [u8]> {
    if data_va == 0 {
        return None;
    }
    let off = ctx.va_to_file(data_va)?;
    let end = off.checked_add(size as usize)?;
    ctx.data().get(off..end)
}
