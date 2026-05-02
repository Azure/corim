// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Tests for `#[derive(CborTagChoiceSerialize)]` codegen.
//!
//! Uses small ad-hoc enums (not the production `ClassIdChoice` etc.) so
//! the macro behavior is verified in isolation. Production-enum byte-for-byte
//! parity tests against the existing hand-written serdes land alongside the
//! conversion commits (2.5–2.8), where they actually replace something.

use corim::cbor;
use corim_macros::CborTagChoiceSerialize;

// CBOR tags borrowed from the production catalog so the encoded bytes
// would be recognisable to any reader of the spec.
const TAG_UUID: u64 = 37;
const TAG_OID: u64 = 111;
const TAG_BYTES: u64 = 560;

// ---------------------------------------------------------------------------
// `#[cbor(tag = N)]` plain — non-bytes inner value
// ---------------------------------------------------------------------------

#[derive(CborTagChoiceSerialize)]
enum TaggedString {
    #[cbor(tag = 554)]
    PkixKey(String),
}

#[test]
fn tag_with_string_inner() {
    let v = TaggedString::PkixKey("hello".into());
    let bytes = cbor::encode(&v).unwrap();
    // d9 022a = tag 554; 65 = tstr(5); 68 65 6c 6c 6f = "hello"
    assert_eq!(
        bytes,
        [0xd9, 0x02, 0x2a, 0x65, b'h', b'e', b'l', b'l', b'o']
    );
}

// ---------------------------------------------------------------------------
// `#[cbor(tag = N, bytes)]` — Vec<u8> inner
// ---------------------------------------------------------------------------

#[derive(CborTagChoiceSerialize)]
enum TaggedBytesVec {
    #[cbor(tag = 111, bytes)]
    Oid(Vec<u8>),
}

#[test]
fn tag_bytes_vec_encodes_as_bstr() {
    let v = TaggedBytesVec::Oid(vec![0x55, 0x04, 0x03]);
    let bytes = cbor::encode(&v).unwrap();
    // d8 6f = tag 111; 43 = bstr(3); 55 04 03 = bytes
    assert_eq!(bytes, [0xd8, 0x6f, 0x43, 0x55, 0x04, 0x03]);
}

// ---------------------------------------------------------------------------
// `#[cbor(tag = N, bytes)]` — [u8; N] inner
// ---------------------------------------------------------------------------

#[derive(CborTagChoiceSerialize)]
enum TaggedBytesArray {
    #[cbor(tag = 37, bytes)]
    Uuid([u8; 16]),
}

#[test]
fn tag_bytes_array_encodes_as_bstr() {
    let v = TaggedBytesArray::Uuid([
        0x31, 0xfb, 0x5a, 0xbf, 0x02, 0x3e, 0x49, 0x92, 0xaa, 0x4e, 0x95, 0xf9, 0xc1, 0x50, 0x3b,
        0xfa,
    ]);
    let bytes = cbor::encode(&v).unwrap();
    // d8 25 = tag 37; 50 = bstr(16); ... 16 UUID bytes
    let expected = [
        0xd8, 0x25, 0x50, 0x31, 0xfb, 0x5a, 0xbf, 0x02, 0x3e, 0x49, 0x92, 0xaa, 0x4e, 0x95, 0xf9,
        0xc1, 0x50, 0x3b, 0xfa,
    ];
    assert_eq!(bytes, expected);
}

// ---------------------------------------------------------------------------
// `#[cbor(text)]` — inline tstr
// ---------------------------------------------------------------------------

#[derive(CborTagChoiceSerialize)]
enum InlineText {
    #[cbor(text)]
    Name(String),
}

#[test]
fn inline_text_encodes_as_bare_tstr() {
    let v = InlineText::Name("acme".into());
    let bytes = cbor::encode(&v).unwrap();
    // 64 = tstr(4); 61 63 6d 65 = "acme" — no leading tag byte.
    assert_eq!(bytes, [0x64, b'a', b'c', b'm', b'e']);
}

// ---------------------------------------------------------------------------
// `#[cbor(uint)]` — inline unsigned integer
// ---------------------------------------------------------------------------

#[derive(CborTagChoiceSerialize)]
enum InlineUint {
    #[cbor(uint)]
    Code(u64),
}

#[test]
fn inline_uint_encodes_as_bare_uint() {
    let v = InlineUint::Code(42);
    let bytes = cbor::encode(&v).unwrap();
    // 18 2a = uint 42 (one-byte length prefix).
    assert_eq!(bytes, [0x18, 0x2a]);
}

#[test]
fn inline_uint_encodes_max_u64() {
    let v = InlineUint::Code(u64::MAX);
    let bytes = cbor::encode(&v).unwrap();
    // 1b ff ff ff ff ff ff ff ff = uint with 8-byte length prefix
    assert_eq!(
        bytes,
        [0x1b, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff]
    );
}

// ---------------------------------------------------------------------------
// Mixed: all variant kinds in one enum (the realistic shape)
// ---------------------------------------------------------------------------

#[derive(CborTagChoiceSerialize)]
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
fn mixed_enum_dispatches_correctly() {
    // Each variant should land in its own match arm.
    let cases: &[(MeasuredElementShape, &[u8])] = &[
        (
            MeasuredElementShape::Oid(vec![0x55, 0x04]),
            &[0xd8, 0x6f, 0x42, 0x55, 0x04],
        ),
        (
            MeasuredElementShape::Uuid([0u8; 16]),
            &[
                0xd8, 0x25, 0x50, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            ],
        ),
        (MeasuredElementShape::Uint(0), &[0x00]),
        (MeasuredElementShape::Text("x".into()), &[0x61, b'x']),
    ];
    for (val, expected) in cases {
        let actual = cbor::encode(val).unwrap();
        assert_eq!(&actual[..], *expected, "mismatch for variant: {:?}", actual);
    }
}

// ---------------------------------------------------------------------------
// `accept_bare = "uuid_16"` is a decode-time relaxation; serialize ignores it.
// ---------------------------------------------------------------------------

#[derive(CborTagChoiceSerialize)]
enum WithBareAccept {
    #[cbor(tag = 37, bytes, accept_bare = "uuid_16")]
    Uuid([u8; 16]),
    /// Present so the enum has the same shape as real-world tag-choice enums
    /// with a catch-all `Bytes` variant; serialization of this variant is
    /// already covered by other test enums.
    #[cbor(tag = 560, bytes)]
    #[allow(dead_code)]
    Bytes(Vec<u8>),
}

#[test]
fn accept_bare_does_not_change_serialize() {
    // Encoding is identical with or without `accept_bare` — the relaxation
    // only matters on decode.
    let v = WithBareAccept::Uuid([0xAB; 16]);
    let bytes = cbor::encode(&v).unwrap();
    let expected = {
        let mut out = vec![0xd8, 0x25, 0x50];
        out.extend_from_slice(&[0xAB; 16]);
        out
    };
    assert_eq!(bytes, expected);
}

// ---------------------------------------------------------------------------
// Sanity: byte-for-byte parity with `serialize_tagged_bytes` direct call.
// This locks in the wire format for the conversion commits later in PR 2.
// ---------------------------------------------------------------------------

#[test]
fn macro_matches_direct_serialize_tagged_bytes() {
    use corim::cbor::value::serialize_tagged_bytes;

    #[derive(CborTagChoiceSerialize)]
    enum Local {
        #[cbor(tag = 37, bytes)]
        Uuid([u8; 16]),
    }

    let uuid = [
        0x31, 0xfb, 0x5a, 0xbf, 0x02, 0x3e, 0x49, 0x92, 0xaa, 0x4e, 0x95, 0xf9, 0xc1, 0x50, 0x3b,
        0xfa,
    ];

    // Via the macro:
    let macro_bytes = cbor::encode(&Local::Uuid(uuid)).unwrap();

    // Via the helper that the macro is supposed to emit:
    struct DirectCall(pub [u8; 16]);
    impl serde::Serialize for DirectCall {
        fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
            serialize_tagged_bytes(37, &self.0, s)
        }
    }
    let direct_bytes = cbor::encode(&DirectCall(uuid)).unwrap();

    assert_eq!(
        macro_bytes, direct_bytes,
        "macro must produce identical bytes to direct serialize_tagged_bytes call"
    );
}

// ---------------------------------------------------------------------------
// `#[cbor(tag = N, text)]` — tagged-text variant (RFC types like #6.554)
// ---------------------------------------------------------------------------

#[derive(CborTagChoiceSerialize)]
enum TaggedText {
    #[cbor(tag = 554, text)]
    PkixKey(String),
}

#[test]
fn tag_text_encodes_as_tagged_tstr() {
    let v = TaggedText::PkixKey("acme".into());
    let bytes = cbor::encode(&v).unwrap();
    // d9 02 2a = tag 554; 64 = tstr(4); 61 63 6d 65 = "acme"
    assert_eq!(bytes, [0xd9, 0x02, 0x2a, 0x64, b'a', b'c', b'm', b'e']);
}

// ---------------------------------------------------------------------------
// Helper-imports kept around for readability of the spec-byte assertions.
// ---------------------------------------------------------------------------

#[allow(dead_code)]
const _UNUSED_TAGS_TOUCHED: (u64, u64, u64) = (TAG_UUID, TAG_OID, TAG_BYTES);
