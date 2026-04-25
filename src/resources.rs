//! Named-resource lookup on top of `goblin::pe::resource`.
//!
//! Delphi / C++Builder store DVCLAL, PACKAGEINFO, and every form resource
//! under `RT_RCDATA` with ASCII (upper-case) string names. Goblin parses the
//! resource tree and exposes `ImageResourceDirectory`, `ResourceEntry`, and
//! `ResourceDataEntry` structural types, plus a `find_by_id` on numeric
//! entries. It does **not** ship a find-by-name helper, so this module
//! provides one: walk the named entries at the `RT_RCDATA` type sub-tree,
//! decode each entry's UTF-16LE name, and return the matching leaf's bytes.
//!
//! The returned slice borrows from the caller's binary buffer.

use goblin::{
    error::Result as GoblinResult,
    pe::resource::{
        ImageResourceDirectory, RT_RCDATA, ResourceDataEntry, ResourceEntry, ResourceEntryIterator,
    },
};
use scroll::{LE, Pread};

use crate::formats::BinaryContext;

/// A located resource body.
#[derive(Debug, Clone, Copy)]
pub struct ResourceBody<'a> {
    /// Raw bytes of the resource payload.
    pub data: &'a [u8],
    /// Language/sub-language identifier of the language-level entry chosen.
    pub language: u32,
}

/// Look up an RT_RCDATA resource by its ASCII name (case-insensitive).
///
/// Returns `None` if the binary has no resource section, no `RT_RCDATA`
/// branch, or no entry matching `name`. Picks the neutral-language entry
/// when available, otherwise the first language.
pub fn find_rcdata<'a>(ctx: &BinaryContext<'a>, name: &str) -> Option<ResourceBody<'a>> {
    let pe = ctx.pe.as_ref()?;
    let rdir = pe.resource_data?;
    let rsrc = ctx.sections().rsrc?;
    let rsrc_bytes = ctx.section_data(&rsrc)?;

    // Level 0 → level 1: find the RT_RCDATA subtree.
    let type_entry = rdir.entries().find_map(|e| {
        let e = e.ok()?;
        (e.id() == Some(RT_RCDATA) && e.data_is_directory()).then_some(e)
    })?;

    // Level 1 → level 2: iterate named entries under RT_RCDATA, match by name.
    let name_entry = iter_subdir_entries(rsrc_bytes, type_entry.offset_to_directory() as usize)
        .ok()?
        .find_map(|e| {
            let e = e.ok()?;
            if !e.name_is_string() || !e.data_is_directory() {
                return None;
            }
            let candidate = read_name(rsrc_bytes, e.name_offset() as usize)?;
            candidate.eq_ignore_ascii_case(name).then_some(e)
        })?;

    // Level 2 → level 3: pick a language-level leaf.
    let (language, data_entry) =
        pick_language(rsrc_bytes, name_entry.offset_to_directory() as usize)?;

    resolve_data(ctx, &data_entry, language)
}

/// Enumerate every named RT_RCDATA entry in the binary, pairing its name
/// with the resource body. Used by the DFM finder (TPF0 streams) in later
/// iterations.
pub fn iter_rcdata_named<'a>(ctx: &BinaryContext<'a>) -> Vec<(String, ResourceBody<'a>)> {
    let Some(pe) = ctx.pe.as_ref() else {
        return Vec::new();
    };
    let Some(rdir) = pe.resource_data else {
        return Vec::new();
    };
    let Some(rsrc) = ctx.sections().rsrc else {
        return Vec::new();
    };
    let Some(rsrc_bytes) = ctx.section_data(&rsrc) else {
        return Vec::new();
    };

    let Some(type_entry) = rdir.entries().find_map(|e| {
        let e = e.ok()?;
        (e.id() == Some(RT_RCDATA) && e.data_is_directory()).then_some(e)
    }) else {
        return Vec::new();
    };

    let mut out = Vec::new();
    let iter = match iter_subdir_entries(rsrc_bytes, type_entry.offset_to_directory() as usize) {
        Ok(it) => it,
        Err(_) => return out,
    };
    for item in iter {
        let Ok(entry) = item else { continue };
        if !entry.name_is_string() || !entry.data_is_directory() {
            continue;
        }
        let Some(name) = read_name(rsrc_bytes, entry.name_offset() as usize) else {
            continue;
        };
        let Some((lang, data_entry)) =
            pick_language(rsrc_bytes, entry.offset_to_directory() as usize)
        else {
            continue;
        };
        let Some(body) = resolve_data(ctx, &data_entry, lang) else {
            continue;
        };
        out.push((name, body));
    }
    out
}

/// Iterate the entries of a sub-directory at `dir_off` within the `.rsrc`
/// section bytes. Uses goblin's `ImageResourceDirectory` to parse the
/// 16-byte header, then its `next_iter` to produce the entry iterator.
fn iter_subdir_entries<'a>(
    rsrc_bytes: &'a [u8],
    dir_off: usize,
) -> GoblinResult<ResourceEntryIterator<'a>> {
    let mut off = dir_off;
    let dir: ImageResourceDirectory = rsrc_bytes.gread_with(&mut off, LE)?;
    dir.next_iter(off, rsrc_bytes)
}

/// Pick a language-level leaf. Prefer LANG_NEUTRAL (`0`); fall back to first.
/// Returns `(language, data_entry)` where `data_entry` is parsed via goblin.
fn pick_language(rsrc_bytes: &[u8], dir_off: usize) -> Option<(u32, ResourceDataEntry)> {
    let mut fallback: Option<(u32, ResourceEntry)> = None;
    let entries = iter_subdir_entries(rsrc_bytes, dir_off).ok()?;
    for item in entries {
        let Ok(e) = item else { continue };
        if e.data_is_directory() {
            continue;
        }
        let lang = e.name_offset(); // leaf entries use name_or_id as language id
        if lang == 0 {
            let off = e.offset_to_data()? as usize;
            let de: ResourceDataEntry = rsrc_bytes.pread_with(off, LE).ok()?;
            return Some((0, de));
        }
        if fallback.is_none() {
            fallback = Some((lang, e));
        }
    }
    let (lang, e) = fallback?;
    let off = e.offset_to_data()? as usize;
    let de: ResourceDataEntry = rsrc_bytes.pread_with(off, LE).ok()?;
    Some((lang, de))
}

/// Decode a UTF-16LE length-prefixed name string at `off` within `rsrc_bytes`.
/// Allocates a `String` for the comparison path; string-name lookup is a
/// cold path so the allocation is acceptable.
fn read_name(rsrc_bytes: &[u8], off: usize) -> Option<String> {
    let len_end = off.checked_add(2)?;
    let len_bytes = rsrc_bytes.get(off..len_end)?;
    let len = u16::from_le_bytes(len_bytes.try_into().ok()?) as usize;
    let body_bytes = len.checked_mul(2)?;
    let body_end = len_end.checked_add(body_bytes)?;
    let body = rsrc_bytes.get(len_end..body_end)?;
    let iter = body
        .chunks_exact(2)
        .filter_map(|c| <[u8; 2]>::try_from(c).ok().map(u16::from_le_bytes));
    Some(char::decode_utf16(iter).filter_map(Result::ok).collect())
}

/// Resolve an RVA-based `ResourceDataEntry` into a slice of the full binary.
fn resolve_data<'a>(
    ctx: &BinaryContext<'a>,
    de: &ResourceDataEntry,
    language: u32,
) -> Option<ResourceBody<'a>> {
    let pe = ctx.pe.as_ref()?;
    let va = pe.image_base.checked_add(de.offset_to_data as u64)?;
    let file_off = ctx.va_to_file(va)?;
    let size = de.size as usize;
    let end = file_off.checked_add(size)?;
    let data = ctx.data().get(file_off..end)?;
    Some(ResourceBody { data, language })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn read_name_decodes_pe_resource_string() {
        // "DVCLAL": length=6, then 6 UTF-16LE code units.
        let mut buf = vec![6, 0];
        for c in "DVCLAL".chars() {
            buf.extend_from_slice(&[c as u8, 0]);
        }
        assert_eq!(read_name(&buf, 0).as_deref(), Some("DVCLAL"));
    }

    #[test]
    fn read_name_rejects_truncation() {
        // Claim 100 chars but only 4 bytes of data.
        let buf = [100u8, 0, b'A', 0];
        assert_eq!(read_name(&buf, 0), None);
    }
}
