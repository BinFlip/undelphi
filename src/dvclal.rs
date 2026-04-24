//! `DVCLAL` resource decoder.
//!
//! Every Delphi / C++Builder executable that uses the VCL or FMX libraries
//! embeds a 16-byte `DVCLAL` (Delphi Visual Component Library Access License)
//! resource of type `RT_RCDATA`. The value encodes which SKU of the compiler
//! produced the binary.
//!
//! Values are taken verbatim from the community-verified table in
//! `RESEARCH.md §3.1`:
//!
//! | Edition | 16 bytes (hex) |
//! |---------|----------------|
//! | Personal | `23 78 5D 23 B6 A5 F3 19 43 F3 40 02 26 D1 11 C7` |
//! | Professional | `A2 8C DF 98 7B 3C 3A 79 26 71 3F 09 0F 2A 25 17` |
//! | Enterprise | `26 3D 4F 38 C2 82 37 B8 F3 24 42 03 17 9B 3A 83` |
//!
//! Starter / Community read as Personal; Ultimate / Architect read as
//! Enterprise.
//!
//! The raw resource bytes are provided by the caller — use the PE resource
//! walker in [`crate::resources`] to locate them.

/// The Delphi / C++Builder SKU that produced this binary.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Edition {
    /// Personal / Starter / Community edition.
    Personal,
    /// Professional edition.
    Professional,
    /// Enterprise / Ultimate / Architect edition.
    Enterprise,
}

const DVCLAL_PERSONAL: [u8; 16] = [
    0x23, 0x78, 0x5D, 0x23, 0xB6, 0xA5, 0xF3, 0x19, 0x43, 0xF3, 0x40, 0x02, 0x26, 0xD1, 0x11, 0xC7,
];

const DVCLAL_PROFESSIONAL: [u8; 16] = [
    0xA2, 0x8C, 0xDF, 0x98, 0x7B, 0x3C, 0x3A, 0x79, 0x26, 0x71, 0x3F, 0x09, 0x0F, 0x2A, 0x25, 0x17,
];

const DVCLAL_ENTERPRISE: [u8; 16] = [
    0x26, 0x3D, 0x4F, 0x38, 0xC2, 0x82, 0x37, 0xB8, 0xF3, 0x24, 0x42, 0x03, 0x17, 0x9B, 0x3A, 0x83,
];

/// Decode a `DVCLAL` resource body.
///
/// Returns `None` if the buffer is not exactly 16 bytes or does not match any
/// known signature.
pub fn decode(raw: &[u8]) -> Option<Edition> {
    if raw.len() != 16 {
        return None;
    }
    let bytes: &[u8; 16] = raw.try_into().ok()?;
    match *bytes {
        DVCLAL_PERSONAL => Some(Edition::Personal),
        DVCLAL_PROFESSIONAL => Some(Edition::Professional),
        DVCLAL_ENTERPRISE => Some(Edition::Enterprise),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decodes_known_editions() {
        assert_eq!(decode(&DVCLAL_PERSONAL), Some(Edition::Personal));
        assert_eq!(decode(&DVCLAL_PROFESSIONAL), Some(Edition::Professional));
        assert_eq!(decode(&DVCLAL_ENTERPRISE), Some(Edition::Enterprise));
    }

    #[test]
    fn rejects_wrong_length() {
        assert_eq!(decode(&[0; 15]), None);
        assert_eq!(decode(&[0; 17]), None);
    }

    #[test]
    fn rejects_unknown_signature() {
        assert_eq!(decode(&[0xab; 16]), None);
    }
}
