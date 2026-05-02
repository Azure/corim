// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Tests for `#[derive(CborTagChoiceDeserialize)]` codegen.
//!
//! Mirrors the structure of `cbor_tag_choice_ser_tests.rs`: small ad-hoc
//! enums exercise one variant kind each, plus a mixed enum that covers
//! the real shape (e.g. `MeasuredElement`, `ClassIdChoice`).

#![allow(dead_code)] // each enum exercises one variant kind; only Deserialize is tested

use corim::cbor;
use corim_macros::{CborTagChoiceDeserialize, CborTagChoiceSerialize};

// ---------------------------------------------------------------------------
// Plain tagged variant — non-bytes inner
// ---------------------------------------------------------------------------

#[derive(Debug, PartialEq, CborTagChoiceSerialize, CborTagChoiceDeserialize)]
enum TaggedString {
    #[cbor(tag = 554)]
    PkixKey(String),
}

#[test]
fn tag_with_string_inner_round_trip() {
    let v = TaggedString::PkixKey("hello".into());
    let bytes = cbor::encode(&v).unwrap();
    let decoded: TaggedString = cbor::decode(&bytes).unwrap();
    assert_eq!(decoded, v);
}

// ---------------------------------------------------------------------------
// Tagged + bytes — Vec<u8>
// ---------------------------------------------------------------------------

#[derive(Debug, PartialEq, CborTagChoiceSerialize, CborTagChoiceDeserialize)]
enum TaggedBytesVec {
    #[cbor(tag = 111, bytes)]
    Oid(Vec<u8>),
}

#[test]
fn tag_bytes_vec_round_trip() {
    let v = TaggedBytesVec::Oid(vec![0x55, 0x04, 0x03]);
    let bytes = cbor::encode(&v).unwrap();
    let decoded: TaggedBytesVec = cbor::decode(&bytes).unwrap();
    assert_eq!(decoded, v);
}

// ---------------------------------------------------------------------------
// Tagged + bytes — fixed-size array
// ---------------------------------------------------------------------------

#[derive(Debug, PartialEq, CborTagChoiceSerialize, CborTagChoiceDeserialize)]
enum TaggedBytesArray {
    #[cbor(tag = 37, bytes)]
    Uuid([u8; 16]),
}

#[test]
fn tag_bytes_array_round_trip() {
    let v = TaggedBytesArray::Uuid([0xAA; 16]);
    let bytes = cbor::encode(&v).unwrap();
    let decoded: TaggedBytesArray = cbor::decode(&bytes).unwrap();
    assert_eq!(decoded, v);
}

#[test]
fn tag_bytes_array_wrong_length_errors() {
    // Encode a 15-byte bstr under tag 37 manually.
    let bytes: Vec<u8> = {
        let mut out = vec![0xd8, 0x25, 0x4f]; // tag 37, bstr(15)
        out.extend_from_slice(&[0xAA; 15]);
        out
    };
    let err = cbor::decode::<TaggedBytesArray>(&bytes).unwrap_err();
    let msg = format!("{}", err);
    assert!(
        msg.contains("requires 16 bytes, got 15 bytes"),
        "got: {msg}"
    );
}

#[test]
fn tag_bytes_inner_not_bstr_errors() {
    // Encode tag 37 wrapping an integer instead of bytes.
    let bytes = vec![0xd8, 0x25, 0x05]; // tag 37, uint(5)
    let err = cbor::decode::<TaggedBytesArray>(&bytes).unwrap_err();
    let msg = format!("{}", err);
    assert!(msg.contains("must wrap bstr"), "got: {msg}");
}

// ---------------------------------------------------------------------------
// Inline text and uint
// ---------------------------------------------------------------------------

#[derive(Debug, PartialEq, CborTagChoiceSerialize, CborTagChoiceDeserialize)]
enum InlineText {
    #[cbor(text)]
    Name(String),
}

#[test]
fn inline_text_round_trip() {
    let v = InlineText::Name("acme".into());
    let bytes = cbor::encode(&v).unwrap();
    let decoded: InlineText = cbor::decode(&bytes).unwrap();
    assert_eq!(decoded, v);
}

#[derive(Debug, PartialEq, CborTagChoiceSerialize, CborTagChoiceDeserialize)]
enum InlineUint {
    #[cbor(uint)]
    Code(u64),
}

#[test]
fn inline_uint_round_trip() {
    for val in [0, 1, 23, 24, 255, 256, 65535, 65536, u64::MAX] {
        let v = InlineUint::Code(val);
        let bytes = cbor::encode(&v).unwrap();
        let decoded: InlineUint = cbor::decode(&bytes).unwrap();
        assert_eq!(decoded, v, "round-trip failed for {val}");
    }
}

#[test]
fn inline_uint_negative_errors() {
    // CBOR negative integer (-1 = 0x20).
    let bytes = vec![0x20];
    let err = cbor::decode::<InlineUint>(&bytes).unwrap_err();
    let msg = format!("{}", err);
    assert!(msg.contains("requires unsigned integer"), "got: {msg}");
}

// ---------------------------------------------------------------------------
// Mixed enum — the shape of MeasuredElement
// ---------------------------------------------------------------------------

#[derive(Debug, PartialEq, CborTagChoiceSerialize, CborTagChoiceDeserialize)]
enum MeasuredElementShape {
    #[cbor(tag = 111, bytes)]
    Oid(Vec<u8>),
    #[cbor(tag = 37, bytes)]
    Uuid([u8; 16]),
    #[cbor(uint)]
    Uint(u64),
    #[cbor(text)]
    Text(String),
}

#[test]
fn mixed_round_trip_all_kinds() {
    let cases = [
        MeasuredElementShape::Oid(vec![0x55, 0x04]),
        MeasuredElementShape::Uuid([0xCC; 16]),
        MeasuredElementShape::Uint(42),
        MeasuredElementShape::Text("firmware".into()),
    ];
    for v in cases {
        let bytes = cbor::encode(&v).unwrap();
        let decoded: MeasuredElementShape = cbor::decode(&bytes).unwrap();
        assert_eq!(decoded, v);
    }
}

// ---------------------------------------------------------------------------
// accept_bare = "uuid_16" interop relaxation
// ---------------------------------------------------------------------------

#[derive(Debug, PartialEq, CborTagChoiceSerialize, CborTagChoiceDeserialize)]
enum WithBareUuid {
    #[cbor(tag = 37, bytes, accept_bare = "uuid_16")]
    Uuid([u8; 16]),
    #[cbor(tag = 554)]
    Other(String),
}

#[test]
fn bare_16_byte_bstr_routes_to_uuid_variant() {
    // 0x50 = bstr(16); no tag prefix.
    let mut bytes = vec![0x50];
    bytes.extend_from_slice(&[0xBB; 16]);
    let decoded: WithBareUuid = cbor::decode(&bytes).unwrap();
    assert_eq!(decoded, WithBareUuid::Uuid([0xBB; 16]));
}

#[test]
fn bare_8_byte_bstr_without_catch_all_errors() {
    // Without `catch_bare_bytes` on a sibling, a non-16-byte bare bstr is rejected.
    let mut bytes = vec![0x48]; // bstr(8)
    bytes.extend_from_slice(&[0xCC; 8]);
    let err = cbor::decode::<WithBareUuid>(&bytes).unwrap_err();
    let msg = format!("{}", err);
    assert!(msg.contains("expected one of"), "got: {msg}");
}

// ---------------------------------------------------------------------------
// catch_bare_bytes catch-all
// ---------------------------------------------------------------------------

#[derive(Debug, PartialEq, CborTagChoiceSerialize, CborTagChoiceDeserialize)]
enum ClassIdShape {
    #[cbor(tag = 111, bytes)]
    Oid(Vec<u8>),
    #[cbor(tag = 37, bytes, accept_bare = "uuid_16")]
    Uuid([u8; 16]),
    #[cbor(tag = 560, bytes, catch_bare_bytes)]
    Bytes(Vec<u8>),
}

#[test]
fn catch_bare_routes_arbitrary_bstr_to_bytes() {
    // 7-byte bare bstr — not 16, so accept_bare won't take it. Lands in catch-all.
    let mut bytes = vec![0x47]; // bstr(7)
    bytes.extend_from_slice(&[0xDD; 7]);
    let decoded: ClassIdShape = cbor::decode(&bytes).unwrap();
    assert_eq!(decoded, ClassIdShape::Bytes(vec![0xDD; 7]));
}

#[test]
fn catch_bare_does_not_steal_uuid_route() {
    // 16-byte bare bstr should still route to UUID, not the catch-all.
    let mut bytes = vec![0x50];
    bytes.extend_from_slice(&[0xEE; 16]);
    let decoded: ClassIdShape = cbor::decode(&bytes).unwrap();
    assert_eq!(decoded, ClassIdShape::Uuid([0xEE; 16]));
}

#[test]
fn tagged_paths_take_precedence_over_bare() {
    // #6.560(bstr(2)) — fully tagged form, must land in Bytes via the tag arm.
    let bytes = vec![0xd9, 0x02, 0x30, 0x42, 0x01, 0x02];
    let decoded: ClassIdShape = cbor::decode(&bytes).unwrap();
    assert_eq!(decoded, ClassIdShape::Bytes(vec![0x01, 0x02]));
}

// ---------------------------------------------------------------------------
// Wrong outer shape — error message lists accepted shapes
// ---------------------------------------------------------------------------

#[test]
fn unknown_shape_lists_accepted_shapes_in_error() {
    // Bool is not a tag-choice shape we accept.
    let bytes = vec![0xf5]; // CBOR true
    let err = cbor::decode::<MeasuredElementShape>(&bytes).unwrap_err();
    let msg = format!("{}", err);
    assert!(msg.contains("expected one of"), "got: {msg}");
    assert!(msg.contains("MeasuredElementShape"), "got: {msg}");
    // The four shapes: tagged 111, tagged 37, uint, tstr
    assert!(msg.contains("#6.111"), "got: {msg}");
    assert!(msg.contains("#6.37"), "got: {msg}");
    assert!(msg.contains("uint"), "got: {msg}");
    assert!(msg.contains("tstr"), "got: {msg}");
}

#[test]
fn unknown_tag_errors() {
    // Tag 999 — none of our variants claim it.
    let bytes = vec![0xd9, 0x03, 0xe7, 0x40]; // tag 999, bstr(0)
    let err = cbor::decode::<MeasuredElementShape>(&bytes).unwrap_err();
    let msg = format!("{}", err);
    assert!(msg.contains("expected one of"), "got: {msg}");
}

// ---------------------------------------------------------------------------
// custom_validate hook
// ---------------------------------------------------------------------------

fn validate_min_length(v: &WithValidate) -> Result<(), String> {
    let WithValidate::Data(b) = v;
    if b.len() < 4 {
        return Err(format!("data must be >=4 bytes, got {}", b.len()));
    }
    Ok(())
}

#[derive(Debug, PartialEq, CborTagChoiceSerialize, CborTagChoiceDeserialize)]
#[cbor(custom_validate = "validate_min_length")]
enum WithValidate {
    #[cbor(tag = 100, bytes)]
    Data(Vec<u8>),
}

#[test]
fn custom_validate_passes_when_ok() {
    let v = WithValidate::Data(vec![0x01, 0x02, 0x03, 0x04]);
    let bytes = cbor::encode(&v).unwrap();
    let decoded: WithValidate = cbor::decode(&bytes).unwrap();
    assert_eq!(decoded, v);
}

#[test]
fn custom_validate_rejects_when_fail() {
    let v = WithValidate::Data(vec![0x01, 0x02]); // only 2 bytes
    let bytes = cbor::encode(&v).unwrap();
    let err = cbor::decode::<WithValidate>(&bytes).unwrap_err();
    let msg = format!("{}", err);
    assert!(msg.contains("data must be >=4 bytes, got 2"), "got: {msg}");
}

// ---------------------------------------------------------------------------
// `#[cbor(tag = N, text)]` — strict tagged-text shape (the CryptoKey case)
// ---------------------------------------------------------------------------

#[derive(Debug, PartialEq, CborTagChoiceSerialize, CborTagChoiceDeserialize)]
enum TaggedText {
    #[cbor(tag = 554, text)]
    PkixKey(String),
}

#[test]
fn tag_text_round_trip() {
    let v = TaggedText::PkixKey("acme".into());
    let bytes = cbor::encode(&v).unwrap();
    let decoded: TaggedText = cbor::decode(&bytes).unwrap();
    assert_eq!(decoded, v);
}

#[test]
fn tag_text_inner_must_be_tstr() {
    // #6.554(bstr) — wrong inner type; hand-written code would reject, and so
    // must the macro. Without #[cbor(tag = N, text)] the macro would silently
    // accept this via `from_value::<String>(&Value::Bytes(...))`.
    let bytes = vec![0xd9, 0x02, 0x2a, 0x41, 0x01]; // tag 554, bstr(1), 0x01
    let err = cbor::decode::<TaggedText>(&bytes).unwrap_err();
    let msg = format!("{}", err);
    assert!(
        msg.contains("must wrap tstr") && msg.contains("TaggedText::PkixKey"),
        "got: {msg}"
    );
}

#[test]
fn tag_text_inner_int_rejected() {
    let bytes = vec![0xd9, 0x02, 0x2a, 0x05]; // tag 554, uint(5)
    let err = cbor::decode::<TaggedText>(&bytes).unwrap_err();
    let msg = format!("{}", err);
    assert!(msg.contains("must wrap tstr"), "got: {msg}");
}

// ---------------------------------------------------------------------------
// Sanity: macro byte-output equals manually written round-trip
// ---------------------------------------------------------------------------

#[test]
fn macro_round_trip_matches_handwritten_pattern() {
    // Exercises the same bytes a hand-written impl would produce / consume.
    let v = ClassIdShape::Uuid([
        0x31, 0xfb, 0x5a, 0xbf, 0x02, 0x3e, 0x49, 0x92, 0xaa, 0x4e, 0x95, 0xf9, 0xc1, 0x50, 0x3b,
        0xfa,
    ]);
    let macro_bytes = cbor::encode(&v).unwrap();
    let expected = vec![
        0xd8, 0x25, 0x50, 0x31, 0xfb, 0x5a, 0xbf, 0x02, 0x3e, 0x49, 0x92, 0xaa, 0x4e, 0x95, 0xf9,
        0xc1, 0x50, 0x3b, 0xfa,
    ];
    assert_eq!(macro_bytes, expected);
    let decoded: ClassIdShape = cbor::decode(&macro_bytes).unwrap();
    assert_eq!(decoded, v);
}
