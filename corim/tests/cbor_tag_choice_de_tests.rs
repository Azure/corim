// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Tests for `#[derive(CborTagChoiceDeserialize)]` codegen.
//!
//! Mirrors the structure of `cbor_tag_choice_ser_tests.rs`: small ad-hoc
//! enums exercise one variant kind each, plus a mixed enum that covers
//! the real shape (e.g. `MeasuredElement`, `ClassIdChoice`).

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

// ===========================================================================
// Negative-decode tests for the type-choice enums in `types/common.rs`,
// `types/measurement.rs`, `types/corim.rs`. Each test crafts a `Value`
// shape that is structurally valid CBOR but violates the CDDL of the
// target type-choice enum, and asserts the decoder rejects it with a
// helpful error message.
//
// They directly exercise the codegen produced by
// `#[derive(CborTagChoiceDeserialize)]`.
// ===========================================================================

use corim::cbor::value::Value;
use corim::types::common::{
    ClassIdChoice, CryptoKey, GroupIdChoice, InstanceIdChoice, MeasuredElement, TagIdChoice,
};
use corim::types::corim::{ConciseTagChoice, CorimId, CorimLocator, ProfileChoice};
use corim::types::measurement::{
    DigestAlg, IntRangeChoice, IntegrityRegisters, IpAddr, MacAddr, RawValueChoice, SvnChoice,
};
use corim::types::tags::{
    TAG_BYTES, TAG_CERT_PATH_THUMBPRINT, TAG_CERT_THUMBPRINT, TAG_COMID, TAG_COSE_KEY, TAG_COSWID,
    TAG_COTL, TAG_INT_RANGE, TAG_KEY_THUMBPRINT, TAG_MASKED_RAW_VALUE, TAG_OID,
    TAG_PKIX_ASN1DER_CERT, TAG_PKIX_BASE64_CERT, TAG_PKIX_BASE64_CERT_PATH, TAG_PKIX_BASE64_KEY,
    TAG_UEID, TAG_UUID,
};

/// Encode `val` as CBOR, then try to decode as `T`. Return the rendered error.
fn decode_err<T: serde::de::DeserializeOwned + std::fmt::Debug>(val: &Value) -> String {
    let bytes = corim::cbor::encode(val).unwrap();
    corim::cbor::decode::<T>(&bytes).unwrap_err().to_string()
}

// ---- TagIdChoice ----

#[test]
fn tag_id_uuid_inner_must_be_bytes() {
    let v = Value::Tag(TAG_UUID, Box::new(Value::Text("not-bytes".into())));
    let err = decode_err::<TagIdChoice>(&v);
    assert!(err.contains("bstr"), "got: {err}");
}

#[test]
fn tag_id_rejects_unrelated_value_kinds() {
    let v = Value::Integer(42);
    let err = decode_err::<TagIdChoice>(&v);
    assert!(err.contains("expected"), "got: {err}");
}

// ---- ClassIdChoice ----

#[test]
fn class_id_oid_inner_must_be_bytes() {
    let v = Value::Tag(TAG_OID, Box::new(Value::Text("not-bytes".into())));
    let err = decode_err::<ClassIdChoice>(&v);
    assert!(err.contains("bstr"), "got: {err}");
}

#[test]
fn class_id_uuid_inner_must_be_16_bytes() {
    let v = Value::Tag(TAG_UUID, Box::new(Value::Bytes(vec![0; 8])));
    let err = decode_err::<ClassIdChoice>(&v);
    assert!(err.contains("got 8 bytes"), "got: {err}");
}

#[test]
fn class_id_uuid_inner_must_be_bytes_kind() {
    let v = Value::Tag(TAG_UUID, Box::new(Value::Text("x".into())));
    let err = decode_err::<ClassIdChoice>(&v);
    assert!(err.contains("bstr"), "got: {err}");
}

#[test]
fn class_id_bytes_tag_inner_must_be_bytes() {
    let v = Value::Tag(TAG_BYTES, Box::new(Value::Integer(1)));
    let err = decode_err::<ClassIdChoice>(&v);
    assert!(err.contains("bstr"), "got: {err}");
}

#[test]
fn class_id_unknown_tag_rejected() {
    let v = Value::Tag(999, Box::new(Value::Bytes(vec![1])));
    let err = decode_err::<ClassIdChoice>(&v);
    assert!(err.contains("expected"), "got: {err}");
}

// ---- InstanceIdChoice ----

#[test]
fn instance_id_ueid_inner_must_be_bytes() {
    let v = Value::Tag(TAG_UEID, Box::new(Value::Text("x".into())));
    let err = decode_err::<InstanceIdChoice>(&v);
    assert!(err.contains("bstr"), "got: {err}");
}

#[test]
fn instance_id_ueid_size_must_be_7_to_33() {
    let v = Value::Tag(TAG_UEID, Box::new(Value::Bytes(vec![0; 3])));
    let err = decode_err::<InstanceIdChoice>(&v);
    assert!(err.contains("7-33"), "got: {err}");
}

#[test]
fn instance_id_pkix_key_must_be_text() {
    let v = Value::Tag(TAG_PKIX_BASE64_KEY, Box::new(Value::Bytes(vec![1])));
    let err = decode_err::<InstanceIdChoice>(&v);
    assert!(err.contains("tstr"), "got: {err}");
}

#[test]
fn instance_id_pkix_cert_must_be_text() {
    let v = Value::Tag(TAG_PKIX_BASE64_CERT, Box::new(Value::Bytes(vec![1])));
    let err = decode_err::<InstanceIdChoice>(&v);
    assert!(err.contains("tstr"), "got: {err}");
}

#[test]
fn instance_id_cose_key_must_be_bytes() {
    let v = Value::Tag(TAG_COSE_KEY, Box::new(Value::Text("x".into())));
    let err = decode_err::<InstanceIdChoice>(&v);
    assert!(err.contains("bstr"), "got: {err}");
}

#[test]
fn instance_id_key_thumbprint_must_be_array() {
    let v = Value::Tag(TAG_KEY_THUMBPRINT, Box::new(Value::Text("x".into())));
    let err = decode_err::<InstanceIdChoice>(&v);
    assert!(err.contains("[alg, val]"), "got: {err}");
}

#[test]
fn instance_id_cert_thumbprint_must_be_array() {
    let v = Value::Tag(TAG_CERT_THUMBPRINT, Box::new(Value::Text("x".into())));
    let err = decode_err::<InstanceIdChoice>(&v);
    assert!(err.contains("[alg, val]"), "got: {err}");
}

#[test]
fn instance_id_asn1_cert_must_be_bytes() {
    let v = Value::Tag(TAG_PKIX_ASN1DER_CERT, Box::new(Value::Text("x".into())));
    let err = decode_err::<InstanceIdChoice>(&v);
    assert!(err.contains("bstr"), "got: {err}");
}

#[test]
fn instance_id_bytes_tag_must_be_bytes() {
    let v = Value::Tag(TAG_BYTES, Box::new(Value::Integer(1)));
    let err = decode_err::<InstanceIdChoice>(&v);
    assert!(err.contains("bstr"), "got: {err}");
}

#[test]
fn instance_id_unknown_value_rejected() {
    let v = Value::Integer(42);
    let err = decode_err::<InstanceIdChoice>(&v);
    assert!(err.contains("expected"), "got: {err}");
}

// ---- GroupIdChoice ----

#[test]
fn group_id_uuid_must_be_bytes_kind() {
    let v = Value::Tag(TAG_UUID, Box::new(Value::Text("x".into())));
    let err = decode_err::<GroupIdChoice>(&v);
    assert!(err.contains("bstr"), "got: {err}");
}

#[test]
fn group_id_uuid_must_be_16_bytes() {
    let v = Value::Tag(TAG_UUID, Box::new(Value::Bytes(vec![0; 8])));
    let err = decode_err::<GroupIdChoice>(&v);
    assert!(err.contains("got 8 bytes"), "got: {err}");
}

#[test]
fn group_id_bytes_tag_must_be_bytes() {
    let v = Value::Tag(TAG_BYTES, Box::new(Value::Integer(1)));
    let err = decode_err::<GroupIdChoice>(&v);
    assert!(err.contains("bstr"), "got: {err}");
}

#[test]
fn group_id_text_value_rejected() {
    let v = Value::Text("nope".into());
    let err = decode_err::<GroupIdChoice>(&v);
    assert!(err.contains("expected"), "got: {err}");
}

// ---- MeasuredElement ----

#[test]
fn measured_element_negative_int_rejected() {
    let v = Value::Integer(-1);
    let err = decode_err::<MeasuredElement>(&v);
    assert!(err.contains("unsigned"), "got: {err}");
}

#[test]
fn measured_element_bool_rejected() {
    let v = Value::Bool(true);
    let err = decode_err::<MeasuredElement>(&v);
    assert!(err.contains("expected"), "got: {err}");
}

// ---- CryptoKey ----

#[test]
fn crypto_key_pkix_key_must_be_text() {
    let v = Value::Tag(TAG_PKIX_BASE64_KEY, Box::new(Value::Bytes(vec![1])));
    let err = decode_err::<CryptoKey>(&v);
    assert!(err.contains("tstr"), "got: {err}");
}

#[test]
fn crypto_key_pkix_cert_must_be_text() {
    let v = Value::Tag(TAG_PKIX_BASE64_CERT, Box::new(Value::Bytes(vec![1])));
    let err = decode_err::<CryptoKey>(&v);
    assert!(err.contains("tstr"), "got: {err}");
}

#[test]
fn crypto_key_pkix_cert_path_must_be_text() {
    let v = Value::Tag(TAG_PKIX_BASE64_CERT_PATH, Box::new(Value::Bytes(vec![1])));
    let err = decode_err::<CryptoKey>(&v);
    assert!(err.contains("tstr"), "got: {err}");
}

#[test]
fn crypto_key_cose_key_must_be_bytes() {
    let v = Value::Tag(TAG_COSE_KEY, Box::new(Value::Text("x".into())));
    let err = decode_err::<CryptoKey>(&v);
    assert!(err.contains("bstr"), "got: {err}");
}

#[test]
fn crypto_key_asn1_cert_must_be_bytes() {
    let v = Value::Tag(TAG_PKIX_ASN1DER_CERT, Box::new(Value::Text("x".into())));
    let err = decode_err::<CryptoKey>(&v);
    assert!(err.contains("bstr"), "got: {err}");
}

#[test]
fn crypto_key_bytes_tag_must_be_bytes() {
    let v = Value::Tag(TAG_BYTES, Box::new(Value::Integer(1)));
    let err = decode_err::<CryptoKey>(&v);
    assert!(err.contains("bstr"), "got: {err}");
}

#[test]
fn crypto_key_bare_int_rejected() {
    let v = Value::Integer(42);
    let err = decode_err::<CryptoKey>(&v);
    assert!(err.contains("expected"), "got: {err}");
}

#[test]
fn crypto_key_key_thumbprint_must_be_array() {
    let v = Value::Tag(TAG_KEY_THUMBPRINT, Box::new(Value::Text("x".into())));
    let err = decode_err::<CryptoKey>(&v);
    assert!(err.contains("[alg, val]"), "got: {err}");
}

#[test]
fn crypto_key_cert_thumbprint_must_be_array() {
    let v = Value::Tag(TAG_CERT_THUMBPRINT, Box::new(Value::Text("x".into())));
    let err = decode_err::<CryptoKey>(&v);
    assert!(err.contains("[alg, val]"), "got: {err}");
}

#[test]
fn crypto_key_cert_path_thumbprint_must_be_array() {
    let v = Value::Tag(TAG_CERT_PATH_THUMBPRINT, Box::new(Value::Text("x".into())));
    let err = decode_err::<CryptoKey>(&v);
    assert!(err.contains("[alg, val]"), "got: {err}");
}

// ---- Digest array shape (used inside CryptoKey thumbprints) ----

#[test]
fn digest_array_extra_element_rejected() {
    let v = Value::Tag(
        TAG_KEY_THUMBPRINT,
        Box::new(Value::Array(vec![
            Value::Integer(7),
            Value::Bytes(vec![0xAA; 32]),
            Value::Integer(0),
        ])),
    );
    let err = decode_err::<CryptoKey>(&v);
    assert!(
        err.contains("digest") || err.contains("[alg, val]"),
        "got: {err}"
    );
}

#[test]
fn digest_text_alg_accepted() {
    // Per the README "Decode interop relaxations" — text alg IDs are accepted.
    let v = Value::Tag(
        TAG_KEY_THUMBPRINT,
        Box::new(Value::Array(vec![
            Value::Text("sha-256".into()),
            Value::Bytes(vec![0]),
        ])),
    );
    let bytes = corim::cbor::encode(&v).unwrap();
    let key: CryptoKey = corim::cbor::decode(&bytes).unwrap();
    match key {
        CryptoKey::KeyThumbprint(d) => assert!(matches!(d.alg(), DigestAlg::Text(_))),
        other => panic!("expected KeyThumbprint, got {:?}", other),
    }
}

#[test]
fn digest_non_bytes_val_rejected() {
    let v = Value::Tag(
        TAG_KEY_THUMBPRINT,
        Box::new(Value::Array(vec![
            Value::Integer(7),
            Value::Text("not-bytes".into()),
        ])),
    );
    let err = decode_err::<CryptoKey>(&v);
    assert!(err.contains("val"), "got: {err}");
}

// ---- SvnChoice / MacAddr / IpAddr / IntRangeChoice / RawValueChoice ----

#[test]
fn svn_choice_text_rejected() {
    let v = Value::Text("not-a-svn".into());
    let err = decode_err::<SvnChoice>(&v);
    assert!(err.contains("expected"), "got: {err}");
}

#[test]
fn mac_addr_wrong_length_rejected() {
    let v = Value::Bytes(vec![0; 4]);
    let err = decode_err::<MacAddr>(&v);
    assert!(err.contains("6 or 8"), "got: {err}");
}

#[test]
fn mac_addr_non_bytes_rejected() {
    let v = Value::Text("not-bytes".into());
    let err = decode_err::<MacAddr>(&v);
    assert!(err.contains("bytes"), "got: {err}");
}

#[test]
fn ip_addr_wrong_length_rejected() {
    let v = Value::Bytes(vec![0; 8]);
    let err = decode_err::<IpAddr>(&v);
    assert!(err.contains("4 or 16"), "got: {err}");
}

#[test]
fn ip_addr_non_bytes_rejected() {
    let v = Value::Text("not-bytes".into());
    let err = decode_err::<IpAddr>(&v);
    assert!(err.contains("bytes"), "got: {err}");
}

#[test]
fn int_range_tag_inner_must_be_array() {
    let v = Value::Tag(TAG_INT_RANGE, Box::new(Value::Text("x".into())));
    let err = decode_err::<IntRangeChoice>(&v);
    assert!(err.contains("[min, max]"), "got: {err}");
}

#[test]
fn int_range_text_value_rejected() {
    let v = Value::Text("nope".into());
    let err = decode_err::<IntRangeChoice>(&v);
    assert!(err.contains("expected"), "got: {err}");
}

#[test]
fn raw_value_bytes_tag_inner_must_be_bytes() {
    let v = Value::Tag(TAG_BYTES, Box::new(Value::Integer(1)));
    let err = decode_err::<RawValueChoice>(&v);
    assert!(err.contains("bytes"), "got: {err}");
}

#[test]
fn raw_value_masked_tag_inner_must_be_pair() {
    let v = Value::Tag(TAG_MASKED_RAW_VALUE, Box::new(Value::Text("x".into())));
    let err = decode_err::<RawValueChoice>(&v);
    assert!(err.contains("[value, mask]"), "got: {err}");
}

#[test]
fn raw_value_unrelated_tag_rejected() {
    let v = Value::Integer(42);
    let err = decode_err::<RawValueChoice>(&v);
    assert!(err.contains("expected"), "got: {err}");
}

// ---- IntegrityRegisters ----

#[test]
fn integrity_register_id_bool_key_rejected() {
    let v = Value::Map(vec![(
        Value::Bool(true),
        Value::Array(vec![Value::Array(vec![
            Value::Integer(7),
            Value::Bytes(vec![0xAA; 32]),
        ])]),
    )]);
    let err = decode_err::<IntegrityRegisters>(&v);
    assert!(err.contains("uint or text"), "got: {err}");
}

#[test]
fn integrity_registers_non_map_rejected() {
    let v = Value::Array(vec![]);
    let err = decode_err::<IntegrityRegisters>(&v);
    assert!(err.contains("map"), "got: {err}");
}

#[test]
fn integrity_registers_non_array_digests_rejected() {
    let v = Value::Map(vec![(Value::Integer(0), Value::Text("not-array".into()))]);
    let err = decode_err::<IntegrityRegisters>(&v);
    assert!(err.contains("array"), "got: {err}");
}

#[test]
fn integrity_registers_bad_digest_format_rejected() {
    let v = Value::Map(vec![(
        Value::Integer(0),
        Value::Array(vec![Value::Text("not-a-pair".into())]),
    )]);
    let err = decode_err::<IntegrityRegisters>(&v);
    assert!(err.contains("digest"), "got: {err}");
}

#[test]
fn integrity_registers_bad_digest_alg_rejected() {
    let v = Value::Map(vec![(
        Value::Integer(0),
        Value::Array(vec![Value::Array(vec![
            Value::Text("not-int".into()),
            Value::Bytes(vec![0]),
        ])]),
    )]);
    let err = decode_err::<IntegrityRegisters>(&v);
    assert!(err.contains("alg"), "got: {err}");
}

#[test]
fn integrity_registers_bad_digest_val_rejected() {
    let v = Value::Map(vec![(
        Value::Integer(0),
        Value::Array(vec![Value::Array(vec![
            Value::Integer(7),
            Value::Text("not-bytes".into()),
        ])]),
    )]);
    let err = decode_err::<IntegrityRegisters>(&v);
    assert!(err.contains("val"), "got: {err}");
}

// ---- CorimLocator / ConciseTagChoice / ProfileChoice / CorimId ----

#[test]
fn corim_locator_href_array_items_must_be_text_or_uri_tag() {
    let v = Value::Map(vec![(
        Value::Integer(0),
        Value::Array(vec![Value::Integer(42)]),
    )]);
    let err = decode_err::<CorimLocator>(&v);
    // The deserializer accepts both bare text and #6.32(text); the rejection
    // message wording differs accordingly.
    assert!(
        err.contains("text") || err.contains("URI") || err.contains("string"),
        "got: {err}"
    );
}

#[test]
fn corim_locator_href_wrong_kind_rejected() {
    let v = Value::Map(vec![(Value::Integer(0), Value::Integer(42))]);
    let err = decode_err::<CorimLocator>(&v);
    assert!(
        err.contains("expected") || err.contains("href"),
        "got: {err}"
    );
}

#[test]
fn corim_locator_thumbprint_empty_array_rejected() {
    let v = Value::Map(vec![
        (Value::Integer(0), Value::Text("https://x.com".into())),
        (Value::Integer(1), Value::Array(vec![])),
    ]);
    let err = decode_err::<CorimLocator>(&v);
    assert!(
        err.contains("array") || err.contains("thumbprint"),
        "got: {err}"
    );
}

#[test]
fn concise_tag_choice_bare_text_rejected() {
    let v = Value::Text("not-tagged".into());
    let err = decode_err::<ConciseTagChoice>(&v);
    assert!(
        err.contains("tagged") || err.contains("expected"),
        "got: {err}"
    );
}

#[test]
fn concise_tag_choice_comid_inner_must_be_bytes() {
    let v = Value::Tag(TAG_COMID, Box::new(Value::Text("x".into())));
    let err = decode_err::<ConciseTagChoice>(&v);
    assert!(err.contains("bytes"), "got: {err}");
}

#[test]
fn concise_tag_choice_coswid_inner_must_be_bytes() {
    let v = Value::Tag(TAG_COSWID, Box::new(Value::Text("x".into())));
    let err = decode_err::<ConciseTagChoice>(&v);
    assert!(err.contains("bytes"), "got: {err}");
}

#[test]
fn concise_tag_choice_cotl_inner_must_be_bytes() {
    let v = Value::Tag(TAG_COTL, Box::new(Value::Text("x".into())));
    let err = decode_err::<ConciseTagChoice>(&v);
    assert!(err.contains("bytes"), "got: {err}");
}

#[test]
fn profile_choice_int_rejected() {
    let v = Value::Integer(42);
    let err = decode_err::<ProfileChoice>(&v);
    assert!(err.contains("expected"), "got: {err}");
}

#[test]
fn corim_id_bool_rejected() {
    let v = Value::Bool(true);
    let err = decode_err::<CorimId>(&v);
    assert!(err.contains("expected"), "got: {err}");
}
