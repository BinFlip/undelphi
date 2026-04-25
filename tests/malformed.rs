//! Malformed-input regression tests.
//!
//! These exercise every public parser entry-point against truncated,
//! all-zero, all-0xFF, huge-length, cyclic, and otherwise-adversarial
//! inputs. The library must return `None` / empty results rather than
//! panic or infinite-loop under any of these conditions.
//!
//! The tests intentionally use no `#[should_panic]` — we expect clean
//! returns.

use undelphi::{
    DelphiBinary, dfm::DfmObject, dvclal, extrtti::AttributeEntry, formats::BinaryContext,
    fpcresources, packageinfo,
};

#[test]
fn parse_empty() {
    assert!(DelphiBinary::parse(&[]).is_err());
}

#[test]
fn parse_tiny_garbage() {
    for len in 0..64 {
        let v = vec![0u8; len];
        let _ = DelphiBinary::parse(&v);
        let v = vec![0xffu8; len];
        let _ = DelphiBinary::parse(&v);
    }
}

#[test]
fn parse_random_pattern_never_panics() {
    // Deterministic LCG so failures reproduce.
    let mut state = 0xdead_beefu64;
    let mut buf = vec![0u8; 65_536];
    for b in &mut buf {
        state = state
            .wrapping_mul(6_364_136_223_846_793_005)
            .wrapping_add(1);
        *b = (state >> 33) as u8;
    }
    let _ = DelphiBinary::parse(&buf);
}

#[test]
fn parse_only_magic_bytes() {
    // Magic-only prefixes — every container detector must handle the
    // "valid magic, no further structure" case.
    let cases: &[&[u8]] = &[
        b"\x7fELF",
        b"MZ\0\0",
        b"\xcf\xfa\xed\xfe",
        b"\xfe\xed\xfa\xcf",
    ];
    for case in cases {
        let mut v = case.to_vec();
        v.resize(256, 0);
        let _ = DelphiBinary::parse(&v);
    }
}

#[test]
fn dvclal_rejects_bad_lengths() {
    assert!(dvclal::decode(&[]).is_none());
    assert!(dvclal::decode(&[0; 1]).is_none());
    assert!(dvclal::decode(&[0; 15]).is_none());
    assert!(dvclal::decode(&[0; 17]).is_none());
    assert!(dvclal::decode(&[0; 1024]).is_none());
}

#[test]
fn dvclal_rejects_unknown_signature() {
    for seed in 0..32u8 {
        let v: [u8; 16] = [seed; 16];
        assert!(dvclal::decode(&v).is_none());
    }
}

#[test]
fn packageinfo_rejects_truncated() {
    for len in 0..12 {
        let v = vec![0u8; len];
        assert!(packageinfo::parse(&v).is_none());
    }
}

#[test]
fn packageinfo_rejects_implausible_counts() {
    // Claim 1 billion requires in a 16-byte buffer.
    let mut v = Vec::new();
    v.extend_from_slice(&0u32.to_le_bytes()); // flags
    v.extend_from_slice(&1_000_000_000u32.to_le_bytes()); // requires count
    v.extend_from_slice(&0u32.to_le_bytes());
    assert!(packageinfo::parse(&v).is_none());
}

#[test]
fn packageinfo_random_bytes_never_panics() {
    let mut state = 0x1234_5678u64;
    for _ in 0..256 {
        state = state
            .wrapping_mul(6_364_136_223_846_793_005)
            .wrapping_add(1);
        let len = (state & 0x1fff) as usize;
        let mut buf = vec![0u8; len];
        for b in &mut buf {
            state = state
                .wrapping_mul(6_364_136_223_846_793_005)
                .wrapping_add(1);
            *b = (state >> 33) as u8;
        }
        let _ = packageinfo::parse(&buf);
    }
}

/// Regression: `packageinfo::Cursor::read_cstr_ascii` used to panic on
/// `self.buf[start..]` when the cursor had advanced past the buffer end.
/// Construct a buffer that claims one `Requires` entry but supplies only
/// the `hash` byte — the cstr read then runs against `pos == buf.len()`.
#[test]
fn packageinfo_cstr_at_buffer_end_does_not_panic() {
    let mut v = Vec::new();
    v.extend_from_slice(&0u32.to_le_bytes()); // flags
    v.extend_from_slice(&1u32.to_le_bytes()); // requires count = 1
    v.push(0xAB); // hash byte; no name bytes follow at all
    assert!(packageinfo::parse(&v).is_none());
}

/// Regression: same panic shape, but the cstr starts inside the buffer
/// without ever finding a NUL terminator (runs off the end).
#[test]
fn packageinfo_cstr_unterminated_does_not_panic() {
    let mut v = Vec::new();
    v.extend_from_slice(&0u32.to_le_bytes());
    v.extend_from_slice(&1u32.to_le_bytes());
    v.push(0xAB);
    v.extend_from_slice(b"unterminated_name_no_null");
    assert!(packageinfo::parse(&v).is_none());
}

#[test]
fn dfm_rejects_non_magic() {
    let cases: &[&[u8]] = &[b"", b"TP", b"TPF", b"NOTF", b"TPF2", b"\0\0\0\0"];
    for case in cases {
        assert!(DfmObject::parse(case).is_none());
    }
}

#[test]
fn dfm_random_trailing_bytes_dont_panic() {
    let mut state = 0xabcd_ef01u64;
    for _ in 0..256 {
        let mut buf = b"TPF0".to_vec();
        state = state
            .wrapping_mul(6_364_136_223_846_793_005)
            .wrapping_add(1);
        let len = (state & 0xfff) as usize;
        for _ in 0..len {
            state = state
                .wrapping_mul(6_364_136_223_846_793_005)
                .wrapping_add(1);
            buf.push((state >> 33) as u8);
        }
        let _ = DfmObject::parse(&buf);
        let _ = DfmObject::parse_body(&buf[4..], false);
        let _ = DfmObject::parse_body(&buf[4..], true);
    }
}

#[test]
fn dfm_truncated_after_header() {
    // Valid magic + class-name length byte that claims more bytes than exist.
    let bad = b"TPF0\xff\x00";
    assert!(DfmObject::parse(bad).is_none());
}

#[test]
fn fpc_resources_on_non_fpc_binary_is_empty() {
    // An empty context has no fpc.resources section; iter_rcdata must
    // return empty without panicking.
    let ctx = BinaryContext::new(&[]);
    assert!(fpcresources::iter_rcdata(&ctx).is_empty());
    assert!(fpcresources::iter_type(&ctx, 999).is_empty());
}

#[test]
fn attribute_block_handles_truncation() {
    // Too small to hold a single entry.
    for len in 0..17 {
        let v = vec![0u8; len];
        let (entries, consumed) = AttributeEntry::decode_block(&v, 8);
        assert!(entries.is_empty());
        assert!(consumed <= v.len());
    }
}

#[test]
fn attribute_block_handles_huge_arg_len() {
    // Declare ArgLen = 0xFFFF but only 5 bytes of body.
    // ptr ptr u16 body — 8 + 8 + 2 + 5 = 23 bytes.
    let mut v = Vec::new();
    v.extend_from_slice(&0u64.to_le_bytes()); // AttrType
    v.extend_from_slice(&0u64.to_le_bytes()); // AttrCtor
    v.extend_from_slice(&0xffffu16.to_le_bytes()); // ArgLen
    v.extend_from_slice(b"\x00\x00\x00\x00\x00");
    let (entries, _) = AttributeEntry::decode_block(&v, 8);
    // Must not panic, and must not yield the bogus entry because the
    // declared body overruns.
    assert!(entries.is_empty());
}

#[test]
fn dfm_claims_all_value_types_without_panic() {
    // Build a minimal TPF0 stream then feed every tag byte 0..255 as a
    // property value; the parser should reject cleanly without panic.
    for tag in 0..=255u8 {
        let mut s = Vec::new();
        s.extend_from_slice(b"TPF0");
        s.push(4);
        s.extend_from_slice(b"TObj"); // class
        s.push(0); // object name (empty)
        s.push(4);
        s.extend_from_slice(b"Prop"); // property name
        s.push(tag); // the value type byte
        // No value payload — so most types will fail truncation checks.
        // The parser must return None without panicking.
        s.push(0); // end props
        s.push(0); // end children
        let _ = DfmObject::parse(&s);
    }
}
