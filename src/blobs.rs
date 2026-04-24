//! Embedded-binary extraction from DFM streams.
//!
//! Delphi forms routinely carry icons, bitmaps, pre-compiled scripts,
//! PNG/JPEG previews, and sometimes wholesale dropped binaries packed
//! into a `Binary` property value. For malware triage these blobs are
//! the most direct indicator of what a dropper carries.
//!
//! This module walks every parsed DFM, surfaces every [`DfmValue::Binary`]
//! leaf, and classifies it by magic bytes.

use crate::dfm::{DfmObject, DfmValue};

/// One blob extracted from a DFM property.
#[derive(Debug, Clone)]
pub struct EmbeddedBlob<'a> {
    /// Resource name that contained the root form (e.g. `TMAINFORM`).
    pub form_resource: String,
    /// Path of the component this property belongs to, e.g.
    /// `MainForm.btnAbout.Icon`.
    pub path: String,
    /// Name of the property carrying this blob.
    pub property_name: String,
    /// Format identified from the first 16 bytes.
    pub kind: BlobKind,
    /// Raw blob bytes; borrowed from the input binary.
    pub data: &'a [u8],
}

/// Format classification for an embedded blob — derived from magic bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BlobKind {
    /// Windows Icon (`00 00 01 00`).
    Icon,
    /// Windows Cursor (`00 00 02 00`).
    Cursor,
    /// Windows Bitmap (`BM`).
    Bitmap,
    /// PNG (`\x89PNG\r\n\x1a\n`).
    Png,
    /// JPEG SOI / JFIF / EXIF (`\xff\xd8\xff`).
    Jpeg,
    /// GIF87a / GIF89a (`GIF8`).
    Gif,
    /// WebP (`RIFF....WEBP`).
    WebP,
    /// TIFF (`II*\0` or `MM\0*`).
    Tiff,
    /// ZIP / DOCX / XLSX / JAR (`PK\x03\x04`).
    Zip,
    /// GZIP (`\x1f\x8b`).
    Gzip,
    /// 7z (`7z\xbc\xaf\x27\x1c`).
    SevenZip,
    /// RAR v4 (`Rar!\x1a\x07\0`) or v5 (`Rar!\x1a\x07\x01\0`).
    Rar,
    /// PDF (`%PDF-`).
    Pdf,
    /// Windows PE executable (`MZ` at `0`).
    Pe,
    /// ELF executable (`\x7fELF`).
    Elf,
    /// Mach-O 64-bit executable (LE).
    MachO,
    /// Windows WAV (`RIFF....WAVE`).
    Wav,
    /// MP3 (`ID3` or 0xFF 0xFB).
    Mp3,
    /// WMF / EMF (`\xd7\xcd\xc6\x9a` or EMR_HEADER).
    Metafile,
    /// RIFF container (unrecognised subtype).
    Riff,
    /// Delphi `tkRecord` / blob whose first bytes look like a short-string.
    ShortString,
    /// Binary whose first bytes don't match any known magic.
    Unknown,
}

impl BlobKind {
    /// Identify a blob from its leading bytes.
    pub fn from_bytes(b: &[u8]) -> Self {
        // Order: longer magics first to disambiguate.
        if b.starts_with(b"\x89PNG\r\n\x1a\n") {
            return BlobKind::Png;
        }
        if b.starts_with(b"7z\xbc\xaf\x27\x1c") {
            return BlobKind::SevenZip;
        }
        if b.starts_with(b"Rar!\x1a\x07") {
            return BlobKind::Rar;
        }
        if b.starts_with(b"%PDF-") {
            return BlobKind::Pdf;
        }
        if b.starts_with(b"GIF87a") || b.starts_with(b"GIF89a") {
            return BlobKind::Gif;
        }
        if b.starts_with(b"PK\x03\x04")
            || b.starts_with(b"PK\x05\x06")
            || b.starts_with(b"PK\x07\x08")
        {
            return BlobKind::Zip;
        }
        if b.starts_with(b"\x7fELF") {
            return BlobKind::Elf;
        }
        if b.starts_with(b"\xcf\xfa\xed\xfe") || b.starts_with(b"\xfe\xed\xfa\xcf") {
            return BlobKind::MachO;
        }
        if b.starts_with(b"RIFF") && b.len() >= 12 {
            let sub = &b[8..12];
            if sub == b"WAVE" {
                return BlobKind::Wav;
            }
            if sub == b"WEBP" {
                return BlobKind::WebP;
            }
            return BlobKind::Riff;
        }
        if b.starts_with(b"\xff\xd8\xff") {
            return BlobKind::Jpeg;
        }
        if b.starts_with(b"ID3") || (b.len() >= 2 && b[0] == 0xff && b[1] & 0xe0 == 0xe0) {
            return BlobKind::Mp3;
        }
        if b.starts_with(b"\x1f\x8b") {
            return BlobKind::Gzip;
        }
        if b.starts_with(b"BM") && b.len() >= 6 {
            return BlobKind::Bitmap;
        }
        if b.starts_with(b"II*\0") || b.starts_with(b"MM\0*") {
            return BlobKind::Tiff;
        }
        if b.starts_with(b"\xd7\xcd\xc6\x9a") {
            return BlobKind::Metafile;
        }
        if b.len() >= 4 && b[0] == 0 && b[1] == 0 && b[3] == 0 {
            match b[2] {
                1 => return BlobKind::Icon,
                2 => return BlobKind::Cursor,
                _ => {}
            }
        }
        if b.starts_with(b"MZ") && b.len() >= 0x40 {
            return BlobKind::Pe;
        }
        if let Some(&len) = b.first()
            && (len as usize) < b.len()
            && len > 0
            && b[1..=len as usize]
                .iter()
                .all(|&c| (0x20..=0x7e).contains(&c))
        {
            return BlobKind::ShortString;
        }
        BlobKind::Unknown
    }

    /// Human-readable label for this format.
    pub fn label(&self) -> &'static str {
        match self {
            BlobKind::Icon => "ICO",
            BlobKind::Cursor => "CUR",
            BlobKind::Bitmap => "BMP",
            BlobKind::Png => "PNG",
            BlobKind::Jpeg => "JPEG",
            BlobKind::Gif => "GIF",
            BlobKind::WebP => "WEBP",
            BlobKind::Tiff => "TIFF",
            BlobKind::Zip => "ZIP",
            BlobKind::Gzip => "GZIP",
            BlobKind::SevenZip => "7Z",
            BlobKind::Rar => "RAR",
            BlobKind::Pdf => "PDF",
            BlobKind::Pe => "PE",
            BlobKind::Elf => "ELF",
            BlobKind::MachO => "Mach-O",
            BlobKind::Wav => "WAV",
            BlobKind::Mp3 => "MP3",
            BlobKind::Metafile => "WMF/EMF",
            BlobKind::Riff => "RIFF",
            BlobKind::ShortString => "ShortString",
            BlobKind::Unknown => "?",
        }
    }
}

/// Enumerate every embedded-binary value across every parsed form.
///
/// Takes the pre-extracted forms list so the caller controls lifetime.
/// Typical call: `catalog(bin.forms())`. Returned blob bytes borrow
/// directly from the input binary's lifetime `'a`, independent of the
/// shorter lifetime of the borrow into the forms slice.
pub fn catalog<'a>(forms: &[(String, DfmObject<'a>)]) -> Vec<EmbeddedBlob<'a>> {
    let mut out = Vec::new();
    for (name, root) in forms {
        let root_path = root.object_name_str().to_owned();
        walk(root, name, &root_path, &mut out);
    }
    out
}

fn walk<'a>(obj: &DfmObject<'a>, form_resource: &str, path: &str, out: &mut Vec<EmbeddedBlob<'a>>) {
    for p in &obj.properties {
        if let DfmValue::Binary(data) = &p.value {
            out.push(EmbeddedBlob {
                form_resource: form_resource.to_owned(),
                path: path.to_owned(),
                property_name: p.name_str().to_owned(),
                kind: BlobKind::from_bytes(data),
                data,
            });
        }
    }
    for child in &obj.children {
        let child_path = if child.object_name_str().is_empty() {
            format!("{}.{}", path, child.class_name_str())
        } else {
            format!("{}.{}", path, child.object_name_str())
        };
        walk(child, form_resource, &child_path, out);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn magic_bytes() {
        assert_eq!(
            BlobKind::from_bytes(b"\x89PNG\r\n\x1a\n\0\0"),
            BlobKind::Png
        );
        assert_eq!(BlobKind::from_bytes(b"\xff\xd8\xff\xe0"), BlobKind::Jpeg);
        assert_eq!(BlobKind::from_bytes(b"PK\x03\x04xxx"), BlobKind::Zip);
        assert_eq!(BlobKind::from_bytes(b"GIF89a........"), BlobKind::Gif);
        assert_eq!(BlobKind::from_bytes(b"BM....."), BlobKind::Bitmap);
        assert_eq!(BlobKind::from_bytes(b"RIFF\0\0\0\0WAVE...."), BlobKind::Wav);
        assert_eq!(
            BlobKind::from_bytes(b"\x00\x00\x01\x00stuff"),
            BlobKind::Icon
        );
        assert_eq!(BlobKind::from_bytes(b"randombytes"), BlobKind::Unknown);
    }
}
