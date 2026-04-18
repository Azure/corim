// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Additional coverage for signed CoRIM, COSE algorithm identifiers,
//! X.509 header fields, the value-level serde bridge, and measurement
//! type serialization paths.

use corim::cbor;
use corim::cbor::value::Value;
use corim::types::common::*;
use corim::types::corim::*;
use corim::types::measurement::*;
use corim::types::signed::*;
use std::collections::BTreeMap;

// ===================================================================
// signed.rs — CoseAlgorithm comprehensive coverage
// ===================================================================

#[test]
fn cose_algorithm_all_variants_from_to_i64() {
    let cases: Vec<(i64, &str)> = vec![
        (-7, "ES256 (deprecated)"),
        (-8, "EdDSA (deprecated)"),
        (-9, "ESP256"),
        (-19, "Ed25519"),
        (-35, "ES384 (deprecated)"),
        (-36, "ES512 (deprecated)"),
        (-37, "PS256"),
        (-38, "PS384"),
        (-39, "PS512"),
        (-51, "ESP384"),
        (-52, "ESP512"),
        (-53, "Ed448"),
        (-999, "Unknown"),
    ];

    for (id, expected_name) in &cases {
        let alg = CoseAlgorithm::from_i64(*id);
        assert_eq!(alg.to_i64(), *id, "round-trip failed for {}", id);
        assert_eq!(alg.name(), *expected_name, "name mismatch for {}", id);
    }
}

#[test]
fn cose_algorithm_deprecated_flag() {
    assert!(CoseAlgorithm::Es256.is_deprecated());
    assert!(CoseAlgorithm::EdDsa.is_deprecated());
    assert!(CoseAlgorithm::Es384.is_deprecated());
    assert!(CoseAlgorithm::Es512.is_deprecated());
    assert!(!CoseAlgorithm::Esp256.is_deprecated());
    assert!(!CoseAlgorithm::Ed25519.is_deprecated());
    assert!(!CoseAlgorithm::Ps256.is_deprecated());
    assert!(!CoseAlgorithm::Ps384.is_deprecated());
    assert!(!CoseAlgorithm::Ps512.is_deprecated());
    assert!(!CoseAlgorithm::Esp384.is_deprecated());
    assert!(!CoseAlgorithm::Esp512.is_deprecated());
    assert!(!CoseAlgorithm::Ed448.is_deprecated());
    assert!(!CoseAlgorithm::Unknown(42).is_deprecated());
}

#[test]
fn cose_algorithm_display_all_variants() {
    for alg in [
        CoseAlgorithm::Esp256,
        CoseAlgorithm::Ed25519,
        CoseAlgorithm::Ps256,
        CoseAlgorithm::Ps384,
        CoseAlgorithm::Ps512,
        CoseAlgorithm::Esp384,
        CoseAlgorithm::Esp512,
        CoseAlgorithm::Ed448,
        CoseAlgorithm::Es256,
        CoseAlgorithm::EdDsa,
        CoseAlgorithm::Es384,
        CoseAlgorithm::Es512,
    ] {
        let s = format!("{}", alg);
        assert!(!s.is_empty());
        assert!(s.contains('('));
    }
    let unknown = CoseAlgorithm::Unknown(-999);
    assert_eq!(format!("{}", unknown), "Unknown(-999)");
}

#[test]
fn cose_algorithm_from_into_i64() {
    let alg: CoseAlgorithm = (-7i64).into();
    assert_eq!(alg, CoseAlgorithm::Es256);
    let n: i64 = alg.into();
    assert_eq!(n, -7);
}

// ===================================================================
// signed.rs — CoseX509 methods
// ===================================================================

#[test]
fn cose_x509_single_certs() {
    let x = CoseX509::Single(vec![0x30, 0x82, 0x01]);
    assert_eq!(x.certs().len(), 1);
    assert_eq!(x.end_entity(), &[0x30, 0x82, 0x01]);
}

#[test]
fn cose_x509_chain_certs() {
    let x = CoseX509::Chain(vec![vec![0x30, 0x01], vec![0x30, 0x02], vec![0x30, 0x03]]);
    assert_eq!(x.certs().len(), 3);
    assert_eq!(x.end_entity(), &[0x30, 0x01]);
}

// ===================================================================
// signed.rs — ProtectedCorimHeaderMap with X.509 fields
// ===================================================================

fn make_meta() -> CorimMetaMap {
    CorimMetaMap {
        signer: CorimSignerMap {
            signer_name: "ACME Ltd.".into(),
            signer_uri: None,
        },
        signature_validity: None,
    }
}

fn make_header_with_meta() -> ProtectedCorimHeaderMap {
    ProtectedCorimHeaderMap {
        alg: CoseAlgorithm::Es256,
        content_type: Some("application/rim+cbor".into()),
        payload_hash_alg: None,
        payload_preimage_content_type: None,
        payload_location: None,
        corim_meta: Some(make_meta()),
        cwt_claims: None,
        kid: None,
        x5bag: None,
        x5chain: None,
        x5t: None,
        x5u: None,
        extra: BTreeMap::new(),
    }
}

#[test]
fn protected_header_with_x509_fields_round_trip() {
    let mut header = make_header_with_meta();
    header.kid = Some(vec![0x01, 0x02, 0x03]);
    header.x5bag = Some(CoseX509::Single(vec![0x30, 0x82]));
    header.x5chain = Some(CoseX509::Chain(vec![vec![0x30, 0x01], vec![0x30, 0x02]]));
    header.x5t = Some(CoseCertHash {
        hash_alg: 1,
        hash_value: vec![0xAA; 32],
    });
    header.x5u = Some("https://example.com/cert.pem".into());

    let bytes = cbor::encode(&header).unwrap();
    let decoded: ProtectedCorimHeaderMap = cbor::decode(&bytes).unwrap();

    assert_eq!(decoded.kid, header.kid);
    assert!(decoded.x5bag.is_some());
    assert!(decoded.x5chain.is_some());
    assert!(decoded.x5t.is_some());
    assert_eq!(decoded.x5u, header.x5u);
}

#[test]
fn protected_header_hash_envelope_round_trip() {
    let header = ProtectedCorimHeaderMap {
        alg: CoseAlgorithm::Es256,
        content_type: None,
        payload_hash_alg: Some(1),
        payload_preimage_content_type: Some("application/rim+cbor".into()),
        payload_location: Some("https://example.com/payload".into()),
        corim_meta: Some(make_meta()),
        cwt_claims: None,
        kid: None,
        x5bag: None,
        x5chain: None,
        x5t: None,
        x5u: None,
        extra: BTreeMap::new(),
    };

    let bytes = cbor::encode(&header).unwrap();
    let decoded: ProtectedCorimHeaderMap = cbor::decode(&bytes).unwrap();

    assert!(decoded.is_hash_envelope());
    assert_eq!(decoded.payload_hash_alg, Some(1));
    assert_eq!(
        decoded.payload_preimage_content_type.as_deref(),
        Some("application/rim+cbor")
    );
    assert_eq!(
        decoded.payload_location.as_deref(),
        Some("https://example.com/payload")
    );
}

// ===================================================================
// signed.rs — encode/decode_signed_corim
// ===================================================================

#[test]
fn encode_decode_signed_corim_attached() {
    let header = make_header_with_meta();
    let protected_bytes = cbor::encode(&header).unwrap();
    let signed = CoseSign1Corim {
        protected_header_bytes: protected_bytes,
        protected: header,
        unprotected: vec![],
        payload: Some(vec![0xD9, 0x01, 0xF5, 0xA0]),
        signature: vec![0xDE; 64],
    };
    let encoded = encode_signed_corim(&signed).unwrap();
    let decoded = decode_signed_corim(&encoded).unwrap();
    assert_eq!(decoded.protected.alg, CoseAlgorithm::Es256);
    assert!(!decoded.is_detached());
    assert_eq!(decoded.signature.len(), 64);
}

#[test]
fn encode_decode_signed_corim_detached() {
    let header = make_header_with_meta();
    let protected_bytes = cbor::encode(&header).unwrap();
    let signed = CoseSign1Corim {
        protected_header_bytes: protected_bytes,
        protected: header,
        unprotected: vec![],
        payload: None,
        signature: vec![0xAB; 64],
    };
    let encoded = encode_signed_corim(&signed).unwrap();
    let decoded = decode_signed_corim(&encoded).unwrap();
    assert!(decoded.is_detached());
}

#[test]
fn decode_signed_corim_not_tag18() {
    let val = Value::Tag(
        501,
        Box::new(Value::Array(vec![
            Value::Bytes(vec![0xA0]),
            Value::Map(vec![]),
            Value::Bytes(vec![]),
            Value::Bytes(vec![]),
        ])),
    );
    let bytes = cbor::encode(&val).unwrap();
    let err = decode_signed_corim(&bytes).unwrap_err();
    assert!(format!("{}", err).contains("tag"), "got: {}", err);
}

#[test]
fn decode_signed_corim_not_a_tag() {
    let val = Value::Array(vec![Value::Integer(1)]);
    let bytes = cbor::encode(&val).unwrap();
    let err = decode_signed_corim(&bytes).unwrap_err();
    assert!(format!("{}", err).contains("tag 18"), "got: {}", err);
}

#[test]
fn decode_signed_corim_wrong_array_len() {
    let val = Value::Tag(
        18,
        Box::new(Value::Array(vec![Value::Bytes(vec![]), Value::Map(vec![])])),
    );
    let bytes = cbor::encode(&val).unwrap();
    let err = decode_signed_corim(&bytes).unwrap_err();
    assert!(format!("{}", err).contains("4-element"), "got: {}", err);
}

#[test]
fn decode_signed_corim_not_array() {
    let val = Value::Tag(18, Box::new(Value::Text("not-array".into())));
    let bytes = cbor::encode(&val).unwrap();
    let err = decode_signed_corim(&bytes).unwrap_err();
    assert!(format!("{}", err).contains("array"), "got: {}", err);
}

#[test]
fn decode_signed_corim_protected_not_bstr() {
    let val = Value::Tag(
        18,
        Box::new(Value::Array(vec![
            Value::Text("not-bstr".into()),
            Value::Map(vec![]),
            Value::Null,
            Value::Bytes(vec![]),
        ])),
    );
    let bytes = cbor::encode(&val).unwrap();
    let err = decode_signed_corim(&bytes).unwrap_err();
    assert!(format!("{}", err).contains("bstr"), "got: {}", err);
}

// ===================================================================
// signed.rs — CoseSign1Corim TBS
// ===================================================================

#[test]
fn cose_sign1_to_be_signed_attached() {
    let header = make_header_with_meta();
    let prot_bytes = cbor::encode(&header).unwrap();
    let signed = CoseSign1Corim {
        protected_header_bytes: prot_bytes,
        protected: header,
        unprotected: vec![],
        payload: Some(vec![0x01, 0x02]),
        signature: vec![],
    };
    let tbs = signed.to_be_signed(&[]).unwrap();
    assert!(!tbs.is_empty());
    let tbs_d = signed.to_be_signed_detached(&[0x03, 0x04], &[]).unwrap();
    assert_ne!(tbs, tbs_d);
}

#[test]
fn cose_sign1_to_be_signed_detached_errors() {
    let header = make_header_with_meta();
    let prot_bytes = cbor::encode(&header).unwrap();
    let signed = CoseSign1Corim {
        protected_header_bytes: prot_bytes,
        protected: header,
        unprotected: vec![],
        payload: None,
        signature: vec![],
    };
    assert!(signed.to_be_signed(&[]).is_err());
}

// ===================================================================
// signed.rs — SignedCorimBuilder
// ===================================================================

fn make_corim_payload() -> Vec<u8> {
    let comid = corim::builder::ComidBuilder::new(TagIdChoice::Text("t".into()))
        .add_reference_triple(corim::types::triples::ReferenceTriple::new(
            corim::types::environment::EnvironmentMap::for_class("V", "M"),
            vec![MeasurementMap {
                mkey: None,
                mval: MeasurementValuesMap {
                    svn: Some(SvnChoice::ExactValue(1)),
                    ..Default::default()
                },
                authorized_by: None,
            }],
        ))
        .build()
        .unwrap();
    corim::builder::CorimBuilder::new(CorimId::Text("test".into()))
        .add_comid_tag(comid)
        .unwrap()
        .build_bytes()
        .unwrap()
}

#[test]
fn signed_corim_builder_with_meta() {
    let mut builder = SignedCorimBuilder::new(-7i64, make_corim_payload())
        .set_corim_meta(make_meta())
        .set_content_type("application/rim+cbor")
        .add_unprotected(Value::Integer(99), Value::Text("info".into()))
        .add_protected(100, Value::Bool(true));
    let tbs = builder.to_be_signed(&[]).unwrap();
    assert!(!tbs.is_empty());
    // Cached path
    let tbs2 = builder.to_be_signed(&[]).unwrap();
    assert_eq!(tbs, tbs2);
    let signed_bytes = builder.build_with_signature(vec![0xAB; 64]).unwrap();
    let decoded = decode_signed_corim(&signed_bytes).unwrap();
    assert!(!decoded.is_detached());
}

#[test]
fn signed_corim_builder_detached() {
    let mut builder = SignedCorimBuilder::new(CoseAlgorithm::Es256, make_corim_payload())
        .set_corim_meta(make_meta());
    let _tbs = builder.to_be_signed(&[]).unwrap();
    let signed_bytes = builder
        .build_detached_with_signature(vec![0xCD; 64])
        .unwrap();
    let decoded = decode_signed_corim(&signed_bytes).unwrap();
    assert!(decoded.is_detached());
}

#[test]
fn signed_corim_builder_cwt_claims() {
    let mut builder = SignedCorimBuilder::new(CoseAlgorithm::Esp256, make_corim_payload())
        .set_cwt_claims(CwtClaims::new("ACME Corp").with_exp(9999999999).with_nbf(0));
    let _tbs = builder.to_be_signed(&[]).unwrap();
    let signed_bytes = builder.build_with_signature(vec![0; 64]).unwrap();
    let decoded = decode_signed_corim(&signed_bytes).unwrap();
    let cwt = decoded.protected.cwt_claims.unwrap();
    assert_eq!(cwt.iss, "ACME Corp");
    assert_eq!(cwt.exp, Some(9999999999));
}

#[test]
fn signed_corim_builder_no_meta_no_cwt_fails() {
    let mut builder = SignedCorimBuilder::new(-7i64, vec![0xA0]);
    assert!(builder.to_be_signed(&[]).is_err());
}

// ===================================================================
// signed.rs — CwtClaims
// ===================================================================

#[test]
fn cwt_claims_builder_methods() {
    let c = CwtClaims::new("iss")
        .with_sub("sub")
        .with_exp(9999)
        .with_nbf(1000);
    assert_eq!(c.iss, "iss");
    assert_eq!(c.sub, Some("sub".into()));
    assert_eq!(c.exp, Some(9999));
    assert_eq!(c.nbf, Some(1000));
}

// ===================================================================
// signed.rs — validate_signed_corim_payload
// ===================================================================

#[test]
fn validate_signed_corim_detached_payload_error() {
    let header = make_header_with_meta();
    let prot_bytes = cbor::encode(&header).unwrap();
    let signed = CoseSign1Corim {
        protected_header_bytes: prot_bytes,
        protected: header,
        unprotected: vec![],
        payload: None,
        signature: vec![0; 64],
    };
    assert!(validate_signed_corim_payload(&signed, 0).is_err());
}

// ===================================================================
// value_ser.rs — serde Serializer variant methods
// ===================================================================

#[test]
fn value_ser_unit_variant() {
    #[derive(serde::Serialize)]
    enum E {
        A,
        B,
    }
    assert_eq!(cbor::value::to_value(&E::A).unwrap(), Value::Integer(0));
    assert_eq!(cbor::value::to_value(&E::B).unwrap(), Value::Integer(1));
}

#[test]
fn value_ser_newtype_variant() {
    #[derive(serde::Serialize)]
    enum E {
        Wrap(u32),
    }
    assert_eq!(
        cbor::value::to_value(&E::Wrap(42)).unwrap(),
        Value::Integer(42)
    );
}

#[test]
fn value_ser_tuple_variant() {
    #[derive(serde::Serialize)]
    enum E {
        Pair(u32, String),
    }
    let v = cbor::value::to_value(&E::Pair(1, "hi".into())).unwrap();
    assert!(matches!(v, Value::Array(ref a) if a.len() == 2));
}

#[test]
fn value_ser_struct_variant() {
    #[derive(serde::Serialize)]
    enum E {
        Named { x: u32, y: String },
    }
    let v = cbor::value::to_value(&E::Named {
        x: 1,
        y: "hi".into(),
    })
    .unwrap();
    assert!(matches!(v, Value::Map(ref e) if e.len() == 2));
}

#[test]
fn value_ser_newtype_struct() {
    #[derive(serde::Serialize)]
    struct W(u64);
    assert_eq!(cbor::value::to_value(&W(123)).unwrap(), Value::Integer(123));
}

#[test]
fn value_ser_unit_struct() {
    #[derive(serde::Serialize)]
    struct U;
    assert_eq!(cbor::value::to_value(&U).unwrap(), Value::Null);
}

#[test]
fn value_ser_tuple_struct() {
    #[derive(serde::Serialize)]
    struct P(u32, u32);
    let v = cbor::value::to_value(&P(1, 2)).unwrap();
    assert!(matches!(v, Value::Array(ref a) if a.len() == 2));
}

#[test]
fn value_ser_named_struct() {
    #[derive(serde::Serialize)]
    struct S {
        name: String,
        age: u32,
    }
    let v = cbor::value::to_value(&S {
        name: "A".into(),
        age: 1,
    })
    .unwrap();
    assert!(matches!(v, Value::Map(ref e) if e.len() == 2));
}

#[test]
fn value_ser_char() {
    assert_eq!(
        cbor::value::to_value(&'X').unwrap(),
        Value::Text("X".into())
    );
}

// ===================================================================
// measurement.rs — IntRangeChoice::Int, IntegrityRegisters
// ===================================================================

#[test]
fn int_range_int_round_trip() {
    let ir = IntRangeChoice::Int(42);
    let bytes = cbor::encode(&ir).unwrap();
    let decoded: IntRangeChoice = cbor::decode(&bytes).unwrap();
    assert_eq!(decoded, IntRangeChoice::Int(42));
}

#[test]
fn integrity_registers_text_key_round_trip() {
    let mut map = BTreeMap::new();
    map.insert(
        IntegrityRegisterId::Text("pcr-0".into()),
        vec![Digest::new(1, vec![0xAA; 32])],
    );
    let regs = IntegrityRegisters(map);
    let bytes = cbor::encode(&regs).unwrap();
    let decoded: IntegrityRegisters = cbor::decode(&bytes).unwrap();
    assert!(decoded
        .0
        .contains_key(&IntegrityRegisterId::Text("pcr-0".into())));
}

// ===================================================================
// common.rs — Display truncation for long byte vectors
// ===================================================================

#[test]
fn display_instance_long_bytes() {
    let inst = InstanceIdChoice::Bytes(vec![0xFF; 32]);
    let s = format!("{}", inst);
    assert!(s.contains("..") && s.contains("32 bytes"), "got: {s}");
}

#[test]
fn display_crypto_key_long_thumbprint() {
    let key = CryptoKey::KeyThumbprint(Digest::new(7, vec![0xCC; 48]));
    let s = format!("{}", key);
    assert!(s.contains(".."), "got: {s}");
}

// ===================================================================
// signed.rs — build_sig_structure1
// ===================================================================

#[test]
fn build_sig_structure1_basic() {
    let tbs = build_sig_structure1(&[0xA0], &[], &[0x01, 0x02]).unwrap();
    let val: Value = cbor::decode(&tbs).unwrap();
    match val {
        Value::Array(arr) => {
            assert_eq!(arr.len(), 4);
            assert_eq!(arr[0], Value::Text("Signature1".into()));
        }
        _ => panic!("expected array"),
    }
}

#[test]
fn build_sig_structure1_with_aad() {
    let tbs1 = build_sig_structure1(&[0xA0], &[], &[0x01]).unwrap();
    let tbs2 = build_sig_structure1(&[0xA0], &[0xFF], &[0x01]).unwrap();
    assert_ne!(tbs1, tbs2);
}

// ===================================================================
// corim.rs — CorimLocator multiple href
// ===================================================================

#[test]
fn corim_locator_multiple_href() {
    let loc = CorimLocator {
        href: CorimLocatorHref::Multiple(vec!["https://a.com".into(), "https://b.com".into()]),
        thumbprint: None,
    };
    let bytes = cbor::encode(&loc).unwrap();
    let decoded: CorimLocator = cbor::decode(&bytes).unwrap();
    match decoded.href {
        CorimLocatorHref::Multiple(uris) => assert_eq!(uris.len(), 2),
        _ => panic!("expected multiple"),
    }
}
