// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Tests for signed CoRIM (COSE_Sign1-corim) support per §4.2.

use corim::builder::{ComidBuilder, CorimBuilder};
use corim::cbor;
use corim::cbor::value::Value;
use corim::types::common::{MeasuredElement, TagIdChoice};
use corim::types::corim::{CorimId, CorimMetaMap, CorimSignerMap};
use corim::types::environment::{ClassMap, EnvironmentMap};
use corim::types::measurement::{Digest, MeasurementMap, MeasurementValuesMap};
use corim::types::signed::*;
use corim::types::tags::TAG_SIGNED_CORIM;
use corim::types::triples::ReferenceTriple;
use corim::Validate;

/// Build a sample unsigned CoRIM payload (tag-501 wrapped) for testing.
fn build_sample_corim_bytes() -> Vec<u8> {
    let env = EnvironmentMap {
        class: Some(ClassMap {
            class_id: None,
            vendor: Some("TestVendor".into()),
            model: Some("TestModel".into()),
            layer: None,
            index: None,
        }),
        instance: None,
        group: None,
    };
    let meas = MeasurementMap {
        mkey: Some(MeasuredElement::Text("firmware".into())),
        mval: MeasurementValuesMap {
            digests: Some(vec![Digest::new(7, vec![0xBB; 48])]),
            ..MeasurementValuesMap::default()
        },
        authorized_by: None,
    };
    let comid = ComidBuilder::new(TagIdChoice::Text("signed-test-comid".into()))
        .add_reference_triple(ReferenceTriple::new(env, vec![meas]))
        .build()
        .unwrap();

    CorimBuilder::new(CorimId::Text("signed-test-corim".into()))
        .add_comid_tag(comid)
        .unwrap()
        .build_bytes()
        .unwrap()
}

fn make_corim_meta() -> CorimMetaMap {
    CorimMetaMap {
        signer: CorimSignerMap {
            signer_name: "ACME Corp".into(),
            signer_uri: Some("https://acme.example.com".into()),
        },
        signature_validity: None,
    }
}

fn make_cwt_claims() -> CwtClaims {
    CwtClaims::new("ACME Corp")
        .with_nbf(1700000000)
        .with_exp(1800000000)
}

// ===================================================================
// CwtClaims tests
// ===================================================================

#[test]
fn cwt_claims_round_trip() {
    let claims = CwtClaims::new("Test Issuer")
        .with_sub("test-doc")
        .with_nbf(1700000000)
        .with_exp(1800000000);

    let bytes = cbor::encode(&claims).unwrap();
    let decoded: CwtClaims = cbor::decode(&bytes).unwrap();

    assert_eq!(decoded.iss, "Test Issuer");
    assert_eq!(decoded.sub.as_deref(), Some("test-doc"));
    assert_eq!(decoded.nbf, Some(1700000000));
    assert_eq!(decoded.exp, Some(1800000000));
}

#[test]
fn cwt_claims_minimal() {
    let claims = CwtClaims::new("Minimal");
    let bytes = cbor::encode(&claims).unwrap();
    let decoded: CwtClaims = cbor::decode(&bytes).unwrap();
    assert_eq!(decoded.iss, "Minimal");
    assert_eq!(decoded.sub, None);
    assert_eq!(decoded.exp, None);
    assert_eq!(decoded.nbf, None);
    assert!(decoded.extra.is_empty());
}

#[test]
fn cwt_claims_with_extra_fields() {
    let mut claims = CwtClaims::new("Test");
    claims.extra.insert(100, Value::Text("custom".into()));

    let bytes = cbor::encode(&claims).unwrap();
    let decoded: CwtClaims = cbor::decode(&bytes).unwrap();
    assert_eq!(decoded.extra.get(&100), Some(&Value::Text("custom".into())));
}

#[test]
fn cwt_claims_missing_iss_fails() {
    // Encode a map without key 1 (iss)
    let val = Value::Map(vec![(Value::Integer(2), Value::Text("sub".into()))]);
    let bytes = cbor::encode(&val).unwrap();
    let result = cbor::decode::<CwtClaims>(&bytes);
    assert!(result.is_err());
}

// ===================================================================
// ProtectedCorimHeaderMap tests
// ===================================================================

#[test]
fn protected_header_with_corim_meta_round_trip() {
    let meta = make_corim_meta();
    let header = ProtectedCorimHeaderMap {
        alg: CoseAlgorithm::Es256,
        content_type: Some("application/rim+cbor".into()),
        payload_hash_alg: None,
        payload_preimage_content_type: None,
        payload_location: None,
        corim_meta: Some(meta.clone()),
        cwt_claims: None,
        extra: std::collections::BTreeMap::new(),
        kid: None,
        x5bag: None,
        x5chain: None,
        x5t: None,
        x5u: None,
    };

    let bytes = cbor::encode(&header).unwrap();
    let decoded: ProtectedCorimHeaderMap = cbor::decode(&bytes).unwrap();

    assert_eq!(decoded.alg, CoseAlgorithm::Es256);
    assert_eq!(
        decoded.content_type.as_deref(),
        Some("application/rim+cbor")
    );
    assert!(decoded.corim_meta.is_some());
    let dm = decoded.corim_meta.unwrap();
    assert_eq!(dm.signer.signer_name, "ACME Corp");
    assert_eq!(
        dm.signer.signer_uri.as_deref(),
        Some("https://acme.example.com")
    );
}

#[test]
fn protected_header_with_cwt_claims_round_trip() {
    let claims = make_cwt_claims();
    let header = ProtectedCorimHeaderMap {
        alg: CoseAlgorithm::Es384,
        content_type: Some("application/rim+cbor".into()),
        payload_hash_alg: None,
        payload_preimage_content_type: None,
        payload_location: None,
        corim_meta: None,
        cwt_claims: Some(claims),
        extra: std::collections::BTreeMap::new(),
        kid: None,
        x5bag: None,
        x5chain: None,
        x5t: None,
        x5u: None,
    };

    let bytes = cbor::encode(&header).unwrap();
    let decoded: ProtectedCorimHeaderMap = cbor::decode(&bytes).unwrap();

    assert_eq!(decoded.alg, CoseAlgorithm::Es384);
    assert!(decoded.cwt_claims.is_some());
    let dc = decoded.cwt_claims.unwrap();
    assert_eq!(dc.iss, "ACME Corp");
    assert_eq!(dc.nbf, Some(1700000000));
    assert_eq!(dc.exp, Some(1800000000));
}

#[test]
fn protected_header_with_both_meta_and_cwt() {
    let header = ProtectedCorimHeaderMap {
        alg: CoseAlgorithm::Es256,
        content_type: Some("application/rim+cbor".into()),
        payload_hash_alg: None,
        payload_preimage_content_type: None,
        payload_location: None,
        corim_meta: Some(make_corim_meta()),
        cwt_claims: Some(make_cwt_claims()),
        extra: std::collections::BTreeMap::new(),
        kid: None,
        x5bag: None,
        x5chain: None,
        x5t: None,
        x5u: None,
    };

    assert!(header.valid().is_ok());
    let bytes = cbor::encode(&header).unwrap();
    let decoded: ProtectedCorimHeaderMap = cbor::decode(&bytes).unwrap();
    assert!(decoded.corim_meta.is_some());
    assert!(decoded.cwt_claims.is_some());
}

#[test]
fn protected_header_missing_both_meta_and_cwt_fails_decode() {
    // Build a map with just alg and content-type but no meta-group
    let val = Value::Map(vec![
        (Value::Integer(1), Value::Integer(-7)),
        (
            Value::Integer(3),
            Value::Text("application/rim+cbor".into()),
        ),
    ]);
    let bytes = cbor::encode(&val).unwrap();
    let result = cbor::decode::<ProtectedCorimHeaderMap>(&bytes);
    assert!(result.is_err());
}

#[test]
fn protected_header_missing_alg_fails_decode() {
    // Build a map with meta but no alg
    let meta_bytes = cbor::encode(&make_corim_meta()).unwrap();
    let val = Value::Map(vec![
        (
            Value::Integer(3),
            Value::Text("application/rim+cbor".into()),
        ),
        (Value::Integer(8), Value::Bytes(meta_bytes)),
    ]);
    let bytes = cbor::encode(&val).unwrap();
    let result = cbor::decode::<ProtectedCorimHeaderMap>(&bytes);
    assert!(result.is_err());
}

#[test]
fn protected_header_validate_inline_mode() {
    let header = ProtectedCorimHeaderMap {
        alg: CoseAlgorithm::Es256,
        content_type: Some("application/rim+cbor".into()),
        payload_hash_alg: None,
        payload_preimage_content_type: None,
        payload_location: None,
        corim_meta: Some(make_corim_meta()),
        cwt_claims: None,
        extra: std::collections::BTreeMap::new(),
        kid: None,
        x5bag: None,
        x5chain: None,
        x5t: None,
        x5u: None,
    };
    assert!(header.valid().is_ok());
}

#[test]
fn protected_header_validate_inline_missing_content_type() {
    let header = ProtectedCorimHeaderMap {
        alg: CoseAlgorithm::Es256,
        content_type: None,
        payload_hash_alg: None,
        payload_preimage_content_type: None,
        payload_location: None,
        corim_meta: Some(make_corim_meta()),
        cwt_claims: None,
        extra: std::collections::BTreeMap::new(),
        kid: None,
        x5bag: None,
        x5chain: None,
        x5t: None,
        x5u: None,
    };
    assert!(header.valid().is_err());
}

#[test]
fn protected_header_validate_hash_envelope_mode() {
    let header = ProtectedCorimHeaderMap {
        alg: CoseAlgorithm::Es256,
        content_type: None,
        payload_hash_alg: Some(1), // SHA-256
        payload_preimage_content_type: Some("application/rim+cbor".into()),
        payload_location: Some("https://example.com/corim.cbor".into()),
        corim_meta: Some(make_corim_meta()),
        cwt_claims: None,
        extra: std::collections::BTreeMap::new(),
        kid: None,
        x5bag: None,
        x5chain: None,
        x5t: None,
        x5u: None,
    };
    assert!(header.valid().is_ok());
    assert!(header.is_hash_envelope());
}

#[test]
fn protected_header_validate_meta_cwt_mismatch() {
    let mut meta = make_corim_meta();
    meta.signer.signer_name = "Different Corp".into();
    let header = ProtectedCorimHeaderMap {
        alg: CoseAlgorithm::Es256,
        content_type: Some("application/rim+cbor".into()),
        payload_hash_alg: None,
        payload_preimage_content_type: None,
        payload_location: None,
        corim_meta: Some(meta),
        cwt_claims: Some(make_cwt_claims()),
        extra: std::collections::BTreeMap::new(),
        kid: None,
        x5bag: None,
        x5chain: None,
        x5t: None,
        x5u: None,
    };
    let result = header.valid();
    assert!(result.is_err());
    assert!(result.unwrap_err().contains("signer-name"));
}

// ===================================================================
// SignedCorimBuilder + full round-trip tests
// ===================================================================

#[test]
fn signed_corim_builder_with_cwt_claims() {
    let corim_bytes = build_sample_corim_bytes();
    let mut builder =
        SignedCorimBuilder::new(-7, corim_bytes).set_cwt_claims(CwtClaims::new("Builder Test"));

    let tbs = builder.to_be_signed(&[]).unwrap();
    assert!(!tbs.is_empty());

    // Verify TBS is valid CBOR (array of 4 items)
    let tbs_val: Value = cbor::decode(&tbs).unwrap();
    if let Value::Array(arr) = tbs_val {
        assert_eq!(arr.len(), 4);
        assert_eq!(arr[0], Value::Text("Signature1".into()));
        // protected header bytes
        assert!(matches!(arr[1], Value::Bytes(_)));
        // external_aad (empty)
        assert_eq!(arr[2], Value::Bytes(vec![]));
        // payload
        assert!(matches!(arr[3], Value::Bytes(_)));
    } else {
        panic!("TBS must be a CBOR array");
    }
}

#[test]
fn signed_corim_builder_with_corim_meta() {
    let corim_bytes = build_sample_corim_bytes();
    let mut builder = SignedCorimBuilder::new(-35, corim_bytes).set_corim_meta(make_corim_meta());

    let tbs = builder.to_be_signed(&[]).unwrap();
    assert!(!tbs.is_empty());

    let fake_signature = vec![0xAA; 64];
    let signed_bytes = builder
        .build_with_signature(fake_signature.clone())
        .unwrap();

    // Decode it back
    let signed = decode_signed_corim(&signed_bytes).unwrap();
    assert_eq!(signed.protected.alg, CoseAlgorithm::Es384);
    assert!(signed.protected.corim_meta.is_some());
    assert_eq!(
        signed
            .protected
            .corim_meta
            .as_ref()
            .unwrap()
            .signer
            .signer_name,
        "ACME Corp"
    );
    assert_eq!(signed.signature, fake_signature);
    assert!(signed.payload.is_some());
}

#[test]
fn signed_corim_builder_with_both_meta_and_cwt() {
    let corim_bytes = build_sample_corim_bytes();
    let mut builder = SignedCorimBuilder::new(-7, corim_bytes)
        .set_corim_meta(make_corim_meta())
        .set_cwt_claims(make_cwt_claims());

    let tbs = builder.to_be_signed(&[]).unwrap();
    assert!(!tbs.is_empty());

    let fake_sig = vec![0xCC; 64];
    let signed_bytes = builder.build_with_signature(fake_sig).unwrap();

    let signed = decode_signed_corim(&signed_bytes).unwrap();
    assert!(signed.protected.corim_meta.is_some());
    assert!(signed.protected.cwt_claims.is_some());
}

#[test]
fn signed_corim_builder_with_x509_header_fields() {
    use corim::types::measurement::DigestAlg;

    let corim_bytes = build_sample_corim_bytes();
    let leaf = vec![0x30, 0x82, 0x01, 0x01]; // fake DER leaf
    let issuer = vec![0x30, 0x82, 0x02, 0x02]; // fake DER issuer
    let x5t = CoseCertHash {
        hash_alg: DigestAlg::Int(-16), // SHA-256 (COSE alg)
        hash_value: vec![0xAB; 32],
    };

    let mut builder = SignedCorimBuilder::new(-7, corim_bytes)
        .set_cwt_claims(CwtClaims::new("X509 Test"))
        .x5chain(CoseX509::Chain(vec![leaf.clone(), issuer.clone()]))
        .kid(vec![0x01, 0x02, 0x03])
        .x5t(x5t.clone());

    let _tbs = builder.to_be_signed(&[]).unwrap();
    let signed_bytes = builder.build_with_signature(vec![0xEE; 64]).unwrap();

    let signed = decode_signed_corim(&signed_bytes).unwrap();
    assert_eq!(
        signed.protected.x5chain,
        Some(CoseX509::Chain(vec![leaf, issuer]))
    );
    assert_eq!(signed.protected.kid, Some(vec![0x01, 0x02, 0x03]));
    assert_eq!(signed.protected.x5t, Some(x5t));
}

#[test]
fn signed_corim_builder_missing_meta_and_cwt_fails() {
    let corim_bytes = build_sample_corim_bytes();
    let mut builder = SignedCorimBuilder::new(-7, corim_bytes);
    let result = builder.to_be_signed(&[]);
    assert!(result.is_err());
}

#[test]
fn signed_corim_builder_with_external_aad() {
    let corim_bytes = build_sample_corim_bytes();
    let mut builder =
        SignedCorimBuilder::new(-7, corim_bytes).set_cwt_claims(CwtClaims::new("AAD Test"));

    let aad = b"some-external-aad";
    let tbs_with_aad = builder.to_be_signed(aad).unwrap();

    // Verify the AAD is embedded in TBS
    let tbs_val: Value = cbor::decode(&tbs_with_aad).unwrap();
    if let Value::Array(arr) = tbs_val {
        assert_eq!(arr[2], Value::Bytes(aad.to_vec()));
    } else {
        panic!("TBS must be a CBOR array");
    }
}

#[test]
fn signed_corim_builder_with_unprotected_header() {
    let corim_bytes = build_sample_corim_bytes();
    let mut builder = SignedCorimBuilder::new(-7, corim_bytes)
        .set_cwt_claims(CwtClaims::new("Unprotected Test"))
        .add_unprotected(Value::Integer(33), Value::Text("x5chain".into()));

    let tbs = builder.to_be_signed(&[]).unwrap();
    assert!(!tbs.is_empty());

    let signed_bytes = builder.build_with_signature(vec![0xDD; 64]).unwrap();
    let signed = decode_signed_corim(&signed_bytes).unwrap();
    assert!(!signed.unprotected.is_empty());
}

// ===================================================================
// decode_signed_corim tests
// ===================================================================

#[test]
fn decode_signed_corim_valid() {
    let corim_bytes = build_sample_corim_bytes();
    let mut builder =
        SignedCorimBuilder::new(-7, corim_bytes).set_cwt_claims(CwtClaims::new("Decode Test"));

    let _tbs = builder.to_be_signed(&[]).unwrap();
    let signed_bytes = builder.build_with_signature(vec![0x42; 64]).unwrap();

    let signed = decode_signed_corim(&signed_bytes).unwrap();
    assert_eq!(signed.protected.alg, CoseAlgorithm::Es256);
    assert!(signed.payload.is_some());
    assert_eq!(signed.signature, vec![0x42; 64]);
}

#[test]
fn decode_signed_corim_not_a_tag() {
    let val = Value::Array(vec![]);
    let bytes = cbor::encode(&val).unwrap();
    let result = decode_signed_corim(&bytes);
    assert!(result.is_err());
}

#[test]
fn decode_signed_corim_wrong_tag() {
    let val = Value::Tag(99, Box::new(Value::Array(vec![])));
    let bytes = cbor::encode(&val).unwrap();
    let result = decode_signed_corim(&bytes);
    assert!(result.is_err());
    let err = result.unwrap_err();
    assert!(format!("{}", err).contains("expected CBOR tag 18"));
}

#[test]
fn decode_signed_corim_wrong_array_length() {
    let val = Value::Tag(
        TAG_SIGNED_CORIM,
        Box::new(Value::Array(vec![Value::Bytes(vec![]), Value::Map(vec![])])),
    );
    let bytes = cbor::encode(&val).unwrap();
    let result = decode_signed_corim(&bytes);
    assert!(result.is_err());
}

#[test]
fn decode_signed_corim_not_an_array() {
    let val = Value::Tag(TAG_SIGNED_CORIM, Box::new(Value::Text("bad".into())));
    let bytes = cbor::encode(&val).unwrap();
    let result = decode_signed_corim(&bytes);
    assert!(result.is_err());
}

#[test]
fn decode_signed_corim_nil_payload() {
    // Build a signed CoRIM with nil payload (detached)
    let meta_bytes = cbor::encode(&make_corim_meta()).unwrap();
    let protected = Value::Map(vec![
        (Value::Integer(1), Value::Integer(-7)),
        (
            Value::Integer(3),
            Value::Text("application/rim+cbor".into()),
        ),
        (Value::Integer(8), Value::Bytes(meta_bytes)),
    ]);
    let protected_bytes = cbor::encode(&protected).unwrap();

    let cose_arr = Value::Array(vec![
        Value::Bytes(protected_bytes),
        Value::Map(vec![]),
        Value::Null,
        Value::Bytes(vec![0xFF; 32]),
    ]);
    let tagged = Value::Tag(TAG_SIGNED_CORIM, Box::new(cose_arr));
    let bytes = cbor::encode(&tagged).unwrap();

    let signed = decode_signed_corim(&bytes).unwrap();
    assert!(signed.payload.is_none());
    assert_eq!(signed.signature, vec![0xFF; 32]);
}

// ===================================================================
// TBS (to-be-signed) construction tests
// ===================================================================

#[test]
fn tbs_sig_structure1_format() {
    let protected_bytes = vec![0xA1, 0x01, 0x26]; // {1: -7} in CBOR
    let payload = vec![0xDE, 0xAD];
    let external_aad = vec![];

    let tbs = build_sig_structure1(&protected_bytes, &external_aad, &payload).unwrap();

    // Decode and verify
    let val: Value = cbor::decode(&tbs).unwrap();
    match val {
        Value::Array(arr) => {
            assert_eq!(arr.len(), 4);
            assert_eq!(arr[0], Value::Text("Signature1".into()));
            assert_eq!(arr[1], Value::Bytes(protected_bytes));
            assert_eq!(arr[2], Value::Bytes(vec![]));
            assert_eq!(arr[3], Value::Bytes(vec![0xDE, 0xAD]));
        }
        _ => panic!("expected array"),
    }
}

#[test]
fn tbs_with_external_aad() {
    let protected_bytes = vec![0xA0]; // empty map
    let payload = vec![0x01];
    let external_aad = b"extra-context".to_vec();

    let tbs = build_sig_structure1(&protected_bytes, &external_aad, &payload).unwrap();
    let val: Value = cbor::decode(&tbs).unwrap();
    match val {
        Value::Array(arr) => {
            assert_eq!(arr[2], Value::Bytes(external_aad));
        }
        _ => panic!("expected array"),
    }
}

#[test]
fn cose_sign1_corim_tbs_method() {
    let corim_bytes = build_sample_corim_bytes();
    let mut builder =
        SignedCorimBuilder::new(-7, corim_bytes.clone()).set_cwt_claims(CwtClaims::new("TBS Test"));

    let tbs_from_builder = builder.to_be_signed(&[]).unwrap();

    let signed_bytes = builder.build_with_signature(vec![0x11; 64]).unwrap();
    let signed = decode_signed_corim(&signed_bytes).unwrap();

    let tbs_from_struct = signed.to_be_signed(&[]).unwrap();

    // Both TBS should be identical
    assert_eq!(tbs_from_builder, tbs_from_struct);
}

// ===================================================================
// encode_signed_corim / decode_signed_corim round-trip
// ===================================================================

#[test]
fn encode_decode_round_trip() {
    let corim_bytes = build_sample_corim_bytes();

    let protected = ProtectedCorimHeaderMap {
        alg: CoseAlgorithm::Es256,
        content_type: Some("application/rim+cbor".into()),
        payload_hash_alg: None,
        payload_preimage_content_type: None,
        payload_location: None,
        corim_meta: Some(make_corim_meta()),
        cwt_claims: None,
        extra: std::collections::BTreeMap::new(),
        kid: None,
        x5bag: None,
        x5chain: None,
        x5t: None,
        x5u: None,
    };
    let protected_header_bytes = cbor::encode(&protected).unwrap();

    let signed = CoseSign1Corim {
        protected_header_bytes: protected_header_bytes.clone(),
        protected,
        unprotected: vec![],
        payload: Some(corim_bytes),
        signature: vec![0xEE; 64],
    };

    let encoded = encode_signed_corim(&signed).unwrap();
    let decoded = decode_signed_corim(&encoded).unwrap();

    assert_eq!(decoded.protected.alg, CoseAlgorithm::Es256);
    assert_eq!(decoded.protected_header_bytes, protected_header_bytes);
    assert_eq!(decoded.signature, vec![0xEE; 64]);
    assert!(decoded.payload.is_some());
}

// ===================================================================
// validate_signed_corim_payload tests
// ===================================================================

#[test]
fn validate_signed_corim_payload_valid() {
    let corim_bytes = build_sample_corim_bytes();
    let mut builder =
        SignedCorimBuilder::new(-7, corim_bytes).set_cwt_claims(CwtClaims::new("Validate Test"));

    let _tbs = builder.to_be_signed(&[]).unwrap();
    let signed_bytes = builder.build_with_signature(vec![0x55; 64]).unwrap();

    let signed = decode_signed_corim(&signed_bytes).unwrap();

    // Use a timestamp that skips expiry (far future)
    let result = validate_signed_corim_payload(&signed, 0);
    assert!(result.is_ok());

    let validated = result.unwrap();
    assert_eq!(validated.comids.len(), 1);
}

#[test]
fn validate_signed_corim_payload_detached_fails() {
    let meta_bytes = cbor::encode(&make_corim_meta()).unwrap();
    let protected = Value::Map(vec![
        (Value::Integer(1), Value::Integer(-7)),
        (
            Value::Integer(3),
            Value::Text("application/rim+cbor".into()),
        ),
        (Value::Integer(8), Value::Bytes(meta_bytes)),
    ]);
    let protected_bytes = cbor::encode(&protected).unwrap();

    let cose_arr = Value::Array(vec![
        Value::Bytes(protected_bytes),
        Value::Map(vec![]),
        Value::Null,
        Value::Bytes(vec![0x00; 32]),
    ]);
    let tagged = Value::Tag(TAG_SIGNED_CORIM, Box::new(cose_arr));
    let bytes = cbor::encode(&tagged).unwrap();

    let signed = decode_signed_corim(&bytes).unwrap();
    let result = validate_signed_corim_payload(&signed, 0);
    assert!(result.is_err());
    assert!(format!("{}", result.unwrap_err()).contains("detached"));
}

// ===================================================================
// COSE header constant tests
// ===================================================================

#[test]
fn cose_header_constants() {
    assert_eq!(COSE_HEADER_ALG, 1);
    assert_eq!(COSE_HEADER_CONTENT_TYPE, 3);
    assert_eq!(COSE_HEADER_CORIM_META, 8);
    assert_eq!(COSE_HEADER_CWT_CLAIMS, 15);
    assert_eq!(COSE_HEADER_PAYLOAD_HASH_ALG, 258);
    assert_eq!(COSE_HEADER_PAYLOAD_PREIMAGE_CT, 259);
    assert_eq!(COSE_HEADER_PAYLOAD_LOCATION, 260);
}

// ===================================================================
// Full workflow: build → sign → decode → validate
// ===================================================================

#[test]
fn full_signed_corim_workflow() {
    // Step 1: Build an unsigned CoRIM
    let corim_bytes = build_sample_corim_bytes();

    // Step 2: Create a signed CoRIM builder
    let mut builder = SignedCorimBuilder::new(-7, corim_bytes).set_cwt_claims(
        CwtClaims::new("Workflow Test")
            .with_nbf(0)
            .with_exp(2000000000),
    );

    // Step 3: Get TBS blob for external signing
    let tbs = builder.to_be_signed(&[]).unwrap();
    assert!(!tbs.is_empty());

    // Step 4: "Sign" externally (fake signature for testing)
    let fake_signature = vec![0xAB; 64];

    // Step 5: Build the final signed CoRIM
    let signed_bytes = builder
        .build_with_signature(fake_signature.clone())
        .unwrap();

    // Step 6: Decode the signed CoRIM
    let signed = decode_signed_corim(&signed_bytes).unwrap();
    assert_eq!(signed.protected.alg, CoseAlgorithm::Es256);
    assert!(signed.protected.cwt_claims.is_some());
    assert_eq!(signed.signature, fake_signature);

    // Step 7: Verify TBS matches (caller would verify signature here)
    let tbs2 = signed.to_be_signed(&[]).unwrap();
    assert_eq!(tbs, tbs2);

    // Step 8: Validate the inner payload
    let validated = validate_signed_corim_payload(&signed, 1000000000).unwrap();
    assert_eq!(validated.comids.len(), 1);
    assert_eq!(
        validated.corim.id,
        CorimId::Text("signed-test-corim".into())
    );
}

#[test]
fn full_workflow_with_corim_meta() {
    let corim_bytes = build_sample_corim_bytes();
    let mut builder = SignedCorimBuilder::new(-35, corim_bytes).set_corim_meta(CorimMetaMap {
        signer: CorimSignerMap {
            signer_name: "Meta Signer".into(),
            signer_uri: None,
        },
        signature_validity: None,
    });

    let _tbs = builder.to_be_signed(&[]).unwrap();
    let signed_bytes = builder.build_with_signature(vec![0x99; 48]).unwrap();

    let signed = decode_signed_corim(&signed_bytes).unwrap();
    assert_eq!(signed.protected.alg, CoseAlgorithm::Es384);
    let meta = signed.protected.corim_meta.as_ref().unwrap();
    assert_eq!(meta.signer.signer_name, "Meta Signer");

    let validated = validate_signed_corim_payload(&signed, 0).unwrap();
    assert_eq!(validated.comids.len(), 1);
}

// ===================================================================
// Edge cases
// ===================================================================

#[test]
fn protected_header_extra_fields_preserved() {
    let header = ProtectedCorimHeaderMap {
        alg: CoseAlgorithm::Es256,
        content_type: Some("application/rim+cbor".into()),
        payload_hash_alg: None,
        payload_preimage_content_type: None,
        payload_location: None,
        corim_meta: Some(make_corim_meta()),
        cwt_claims: None,
        extra: {
            let mut m = std::collections::BTreeMap::new();
            m.insert(99, Value::Text("custom-value".into()));
            m
        },
        kid: None,
        x5bag: None,
        x5chain: None,
        x5t: None,
        x5u: None,
    };

    let bytes = cbor::encode(&header).unwrap();
    let decoded: ProtectedCorimHeaderMap = cbor::decode(&bytes).unwrap();
    assert_eq!(
        decoded.extra.get(&99),
        Some(&Value::Text("custom-value".into()))
    );
}

#[test]
fn signed_corim_large_signature() {
    let corim_bytes = build_sample_corim_bytes();
    let mut builder =
        SignedCorimBuilder::new(-36, corim_bytes).set_cwt_claims(CwtClaims::new("Large Sig Test"));

    let _tbs = builder.to_be_signed(&[]).unwrap();
    let large_sig = vec![0xFE; 132]; // ES512 signatures are ~132 bytes
    let signed_bytes = builder.build_with_signature(large_sig.clone()).unwrap();

    let signed = decode_signed_corim(&signed_bytes).unwrap();
    assert_eq!(signed.signature, large_sig);
}

#[test]
fn signed_corim_empty_signature() {
    let corim_bytes = build_sample_corim_bytes();
    let mut builder =
        SignedCorimBuilder::new(-7, corim_bytes).set_cwt_claims(CwtClaims::new("Empty Sig Test"));

    let _tbs = builder.to_be_signed(&[]).unwrap();
    // Build with empty signature (placeholder — TBS was computed)
    let signed_bytes = builder.build_with_signature(vec![]).unwrap();

    let signed = decode_signed_corim(&signed_bytes).unwrap();
    assert!(signed.signature.is_empty());
}

#[test]
fn builder_caches_protected_bytes() {
    let corim_bytes = build_sample_corim_bytes();
    let mut builder =
        SignedCorimBuilder::new(-7, corim_bytes).set_cwt_claims(CwtClaims::new("Cache Test"));

    let tbs1 = builder.to_be_signed(&[]).unwrap();
    let tbs2 = builder.to_be_signed(&[]).unwrap();
    // Same TBS both times (cached)
    assert_eq!(tbs1, tbs2);
}

#[test]
fn tag_18_magic_number() {
    // The first bytes of a signed CoRIM should be d2 84 (tag 18 + array(4))
    let corim_bytes = build_sample_corim_bytes();
    let mut builder =
        SignedCorimBuilder::new(-7, corim_bytes).set_cwt_claims(CwtClaims::new("Magic Test"));

    let _tbs = builder.to_be_signed(&[]).unwrap();
    let signed_bytes = builder.build_with_signature(vec![0x11; 64]).unwrap();

    // Tag 18 = 0xD2, followed by 0x84 for 4-element array
    assert_eq!(signed_bytes[0], 0xD2);
    assert_eq!(signed_bytes[1], 0x84);
}

// ===================================================================
// Detached payload signing tests
// ===================================================================

#[test]
fn detached_builder_produces_nil_payload() {
    let corim_bytes = build_sample_corim_bytes();
    let mut builder =
        SignedCorimBuilder::new(-7, corim_bytes).set_cwt_claims(CwtClaims::new("Detached Test"));

    let _tbs = builder.to_be_signed(&[]).unwrap();
    let signed_bytes = builder
        .build_detached_with_signature(vec![0xDD; 64])
        .unwrap();

    let signed = decode_signed_corim(&signed_bytes).unwrap();
    assert!(signed.is_detached());
    assert!(signed.payload.is_none());
    assert_eq!(signed.signature, vec![0xDD; 64]);
}

#[test]
fn detached_tbs_uses_actual_payload() {
    let corim_bytes = build_sample_corim_bytes();

    // Builder computes TBS over the real payload even in detached mode
    let mut builder_a =
        SignedCorimBuilder::new(-7, corim_bytes.clone()).set_cwt_claims(CwtClaims::new("TBS Test"));
    let tbs_from_builder = builder_a.to_be_signed(&[]).unwrap();

    // Build attached, decode, then compute TBS from the struct
    let signed_bytes = builder_a.build_with_signature(vec![0x00; 64]).unwrap();
    let attached = decode_signed_corim(&signed_bytes).unwrap();
    let tbs_from_attached = attached.to_be_signed(&[]).unwrap();
    assert_eq!(tbs_from_builder, tbs_from_attached);

    // Now build a detached envelope from the same protected header
    let mut builder_b =
        SignedCorimBuilder::new(-7, corim_bytes.clone()).set_cwt_claims(CwtClaims::new("TBS Test"));
    let tbs_before_detach = builder_b.to_be_signed(&[]).unwrap();
    let detached_bytes = builder_b
        .build_detached_with_signature(vec![0x00; 64])
        .unwrap();
    let detached = decode_signed_corim(&detached_bytes).unwrap();

    // to_be_signed on a detached envelope should fail
    assert!(detached.to_be_signed(&[]).is_err());

    // to_be_signed_detached with the original payload should match
    let tbs_from_detached = detached.to_be_signed_detached(&corim_bytes, &[]).unwrap();
    assert_eq!(tbs_before_detach, tbs_from_detached);
}

#[test]
fn detached_to_be_signed_errors_without_payload() {
    let corim_bytes = build_sample_corim_bytes();
    let mut builder =
        SignedCorimBuilder::new(-7, corim_bytes).set_cwt_claims(CwtClaims::new("Error Test"));

    let _tbs = builder.to_be_signed(&[]).unwrap();
    let detached_bytes = builder
        .build_detached_with_signature(vec![0xAA; 64])
        .unwrap();

    let signed = decode_signed_corim(&detached_bytes).unwrap();
    let err = signed.to_be_signed(&[]).unwrap_err();
    assert!(
        err.to_string().contains("detached"),
        "error should mention detached: {}",
        err
    );
}

#[test]
fn detached_to_be_signed_detached_with_external_aad() {
    let corim_bytes = build_sample_corim_bytes();
    let mut builder = SignedCorimBuilder::new(-7, corim_bytes.clone())
        .set_cwt_claims(CwtClaims::new("AAD Detach Test"));

    let _tbs = builder.to_be_signed(&[]).unwrap();
    let detached_bytes = builder
        .build_detached_with_signature(vec![0xBB; 64])
        .unwrap();

    let signed = decode_signed_corim(&detached_bytes).unwrap();
    let aad = b"my-external-aad";
    let tbs = signed.to_be_signed_detached(&corim_bytes, aad).unwrap();

    // Verify the AAD is in the TBS
    let tbs_val: Value = cbor::decode(&tbs).unwrap();
    if let Value::Array(arr) = tbs_val {
        assert_eq!(arr[2], Value::Bytes(aad.to_vec()));
        // payload should be the corim_bytes, not empty
        assert_eq!(arr[3], Value::Bytes(corim_bytes.clone()));
    } else {
        panic!("TBS must be a CBOR array");
    }
}

#[test]
fn detached_validate_fails_for_attached_api() {
    let corim_bytes = build_sample_corim_bytes();
    let mut builder =
        SignedCorimBuilder::new(-7, corim_bytes).set_cwt_claims(CwtClaims::new("Validate Detach"));

    let _tbs = builder.to_be_signed(&[]).unwrap();
    let detached_bytes = builder
        .build_detached_with_signature(vec![0xCC; 64])
        .unwrap();

    let signed = decode_signed_corim(&detached_bytes).unwrap();
    let result = validate_signed_corim_payload(&signed, 0);
    assert!(result.is_err());
    assert!(result.unwrap_err().to_string().contains("detached"));
}

#[test]
fn detached_validate_with_supplied_payload() {
    let corim_bytes = build_sample_corim_bytes();
    let mut builder = SignedCorimBuilder::new(-7, corim_bytes.clone())
        .set_cwt_claims(CwtClaims::new("Validate Detach OK"));

    let _tbs = builder.to_be_signed(&[]).unwrap();
    let detached_bytes = builder
        .build_detached_with_signature(vec![0xEE; 64])
        .unwrap();

    let signed = decode_signed_corim(&detached_bytes).unwrap();
    let validated = validate_signed_corim_payload_detached(&signed, &corim_bytes, 0).unwrap();
    assert_eq!(validated.comids.len(), 1);
}

#[test]
fn is_detached_flag() {
    let corim_bytes = build_sample_corim_bytes();

    // Attached
    let mut builder_a = SignedCorimBuilder::new(-7, corim_bytes.clone())
        .set_cwt_claims(CwtClaims::new("Flag Test"));
    let _tbs = builder_a.to_be_signed(&[]).unwrap();
    let attached_bytes = builder_a.build_with_signature(vec![0x11; 64]).unwrap();
    let attached = decode_signed_corim(&attached_bytes).unwrap();
    assert!(!attached.is_detached());

    // Detached
    let mut builder_b =
        SignedCorimBuilder::new(-7, corim_bytes).set_cwt_claims(CwtClaims::new("Flag Test"));
    let _tbs = builder_b.to_be_signed(&[]).unwrap();
    let detached_bytes = builder_b
        .build_detached_with_signature(vec![0x22; 64])
        .unwrap();
    let detached = decode_signed_corim(&detached_bytes).unwrap();
    assert!(detached.is_detached());
}

#[test]
fn full_detached_workflow() {
    // Step 1: Build an unsigned CoRIM payload
    let corim_bytes = build_sample_corim_bytes();

    // Step 2: Create builder, compute TBS, "sign"
    let mut builder = SignedCorimBuilder::new(-35, corim_bytes.clone())
        .set_cwt_claims(CwtClaims::new("Detached Workflow"));

    let tbs = builder.to_be_signed(&[]).unwrap();
    assert!(!tbs.is_empty());

    let fake_signature = vec![0xFE; 48];

    // Step 3: Build DETACHED envelope
    let envelope_bytes = builder
        .build_detached_with_signature(fake_signature.clone())
        .unwrap();

    // Step 4: Decode the envelope
    let envelope = decode_signed_corim(&envelope_bytes).unwrap();
    assert!(envelope.is_detached());
    assert_eq!(envelope.protected.alg, CoseAlgorithm::Es384);

    // Step 5: Reconstruct TBS from envelope + detached payload
    let tbs2 = envelope.to_be_signed_detached(&corim_bytes, &[]).unwrap();
    assert_eq!(tbs, tbs2);

    // Step 6: Validate the detached payload
    let validated = validate_signed_corim_payload_detached(&envelope, &corim_bytes, 0).unwrap();
    assert_eq!(validated.comids.len(), 1);
}

#[test]
fn to_be_signed_detached_works_on_attached_too() {
    // to_be_signed_detached should work even on an attached envelope,
    // using the supplied payload (overriding the embedded one)
    let corim_bytes = build_sample_corim_bytes();
    let mut builder = SignedCorimBuilder::new(-7, corim_bytes.clone())
        .set_cwt_claims(CwtClaims::new("Override Test"));

    let _tbs = builder.to_be_signed(&[]).unwrap();
    let signed_bytes = builder.build_with_signature(vec![0x11; 64]).unwrap();
    let signed = decode_signed_corim(&signed_bytes).unwrap();
    assert!(!signed.is_detached());

    // Both methods should produce the same TBS
    let tbs_attached = signed.to_be_signed(&[]).unwrap();
    let tbs_detached = signed.to_be_signed_detached(&corim_bytes, &[]).unwrap();
    assert_eq!(tbs_attached, tbs_detached);
}

// ===========================================================================
// CoseAlgorithm — full enum coverage
// ===========================================================================

#[test]
fn cose_algorithm_all_variants_round_trip_i64() {
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
fn cose_algorithm_deprecated_flag_marks_legacy_es_eddsa() {
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
fn cose_algorithm_display_includes_id_in_parens() {
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
    assert_eq!(format!("{}", CoseAlgorithm::Unknown(-999)), "Unknown(-999)");
}

#[test]
fn cose_algorithm_into_i64_and_back() {
    let alg: CoseAlgorithm = (-7i64).into();
    assert_eq!(alg, CoseAlgorithm::Es256);
    let n: i64 = alg.into();
    assert_eq!(n, -7);
}

// ===========================================================================
// CoseX509 — Single vs Chain
// ===========================================================================

#[test]
fn cose_x509_single_exposes_one_cert() {
    let x = CoseX509::Single(vec![0x30, 0x82, 0x01]);
    assert_eq!(x.certs().len(), 1);
    assert_eq!(x.end_entity(), &[0x30, 0x82, 0x01]);
}

#[test]
fn cose_x509_chain_exposes_all_with_first_as_end_entity() {
    let x = CoseX509::Chain(vec![vec![0x30, 0x01], vec![0x30, 0x02], vec![0x30, 0x03]]);
    assert_eq!(x.certs().len(), 3);
    assert_eq!(x.end_entity(), &[0x30, 0x01]);
}

// ===========================================================================
// ProtectedCorimHeaderMap — X.509 fields and hash-envelope mode
// ===========================================================================

fn coverage_meta() -> CorimMetaMap {
    CorimMetaMap {
        signer: CorimSignerMap {
            signer_name: "ACME Ltd.".into(),
            signer_uri: None,
        },
        signature_validity: None,
    }
}

fn coverage_header_with_meta() -> ProtectedCorimHeaderMap {
    ProtectedCorimHeaderMap {
        alg: CoseAlgorithm::Es256,
        content_type: Some("application/rim+cbor".into()),
        payload_hash_alg: None,
        payload_preimage_content_type: None,
        payload_location: None,
        corim_meta: Some(coverage_meta()),
        cwt_claims: None,
        kid: None,
        x5bag: None,
        x5chain: None,
        x5t: None,
        x5u: None,
        extra: std::collections::BTreeMap::new(),
    }
}

#[test]
fn protected_header_with_x509_fields_round_trip() {
    let mut header = coverage_header_with_meta();
    header.kid = Some(vec![0x01, 0x02, 0x03]);
    header.x5bag = Some(CoseX509::Single(vec![0x30, 0x82]));
    header.x5chain = Some(CoseX509::Chain(vec![vec![0x30, 0x01], vec![0x30, 0x02]]));
    header.x5t = Some(CoseCertHash {
        hash_alg: corim::types::DigestAlg::Int(1),
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
        corim_meta: Some(coverage_meta()),
        cwt_claims: None,
        kid: None,
        x5bag: None,
        x5chain: None,
        x5t: None,
        x5u: None,
        extra: std::collections::BTreeMap::new(),
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

// ===========================================================================
// encode_signed_corim / decode_signed_corim — round-trip + decode errors
// ===========================================================================

#[test]
fn encode_decode_signed_corim_attached_round_trip() {
    let header = coverage_header_with_meta();
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
fn encode_decode_signed_corim_detached_round_trip() {
    let header = coverage_header_with_meta();
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
fn decode_signed_corim_rejects_wrong_outer_tag() {
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
fn decode_signed_corim_rejects_non_tag_input() {
    let val = Value::Array(vec![Value::Integer(1)]);
    let bytes = cbor::encode(&val).unwrap();
    let err = decode_signed_corim(&bytes).unwrap_err();
    assert!(format!("{}", err).contains("tag 18"), "got: {}", err);
}

#[test]
fn decode_signed_corim_rejects_wrong_array_length() {
    let val = Value::Tag(
        18,
        Box::new(Value::Array(vec![Value::Bytes(vec![]), Value::Map(vec![])])),
    );
    let bytes = cbor::encode(&val).unwrap();
    let err = decode_signed_corim(&bytes).unwrap_err();
    assert!(format!("{}", err).contains("4-element"), "got: {}", err);
}

#[test]
fn decode_signed_corim_rejects_non_array_payload() {
    let val = Value::Tag(18, Box::new(Value::Text("not-array".into())));
    let bytes = cbor::encode(&val).unwrap();
    let err = decode_signed_corim(&bytes).unwrap_err();
    assert!(format!("{}", err).contains("array"), "got: {}", err);
}

#[test]
fn decode_signed_corim_rejects_non_bstr_protected() {
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

// ===========================================================================
// CoseSign1Corim::to_be_signed{,_detached}
// ===========================================================================

#[test]
fn cose_sign1_to_be_signed_attached_differs_from_detached() {
    let header = coverage_header_with_meta();
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
fn cose_sign1_to_be_signed_errors_on_detached_envelope() {
    let header = coverage_header_with_meta();
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

// ===========================================================================
// SignedCorimBuilder — meta / detached / CWT / no-meta-no-cwt error
// ===========================================================================

fn coverage_corim_payload() -> Vec<u8> {
    let comid = ComidBuilder::new(TagIdChoice::Text("t".into()))
        .add_reference_triple(ReferenceTriple::new(
            EnvironmentMap::for_class("V", "M"),
            vec![MeasurementMap {
                mkey: None,
                mval: MeasurementValuesMap {
                    svn: Some(corim::types::measurement::SvnChoice::ExactValue(1)),
                    ..Default::default()
                },
                authorized_by: None,
            }],
        ))
        .build()
        .unwrap();
    CorimBuilder::new(CorimId::Text("test".into()))
        .add_comid_tag(comid)
        .unwrap()
        .build_bytes()
        .unwrap()
}

#[test]
fn signed_corim_builder_with_meta_caches_tbs() {
    let mut builder = SignedCorimBuilder::new(-7i64, coverage_corim_payload())
        .set_corim_meta(coverage_meta())
        .set_content_type("application/rim+cbor")
        .add_unprotected(Value::Integer(99), Value::Text("info".into()))
        .add_protected(100, Value::Bool(true));
    let tbs = builder.to_be_signed(&[]).unwrap();
    assert!(!tbs.is_empty());
    // Second call must hit the cached protected-bytes path.
    let tbs2 = builder.to_be_signed(&[]).unwrap();
    assert_eq!(tbs, tbs2);
    let signed_bytes = builder.build_with_signature(vec![0xAB; 64]).unwrap();
    let decoded = decode_signed_corim(&signed_bytes).unwrap();
    assert!(!decoded.is_detached());
}

#[test]
fn signed_corim_builder_detached_round_trip() {
    let mut builder = SignedCorimBuilder::new(CoseAlgorithm::Es256, coverage_corim_payload())
        .set_corim_meta(coverage_meta());
    let _tbs = builder.to_be_signed(&[]).unwrap();
    let signed_bytes = builder
        .build_detached_with_signature(vec![0xCD; 64])
        .unwrap();
    let decoded = decode_signed_corim(&signed_bytes).unwrap();
    assert!(decoded.is_detached());
}

#[test]
fn signed_corim_builder_with_cwt_claims_round_trip() {
    let mut builder = SignedCorimBuilder::new(CoseAlgorithm::Esp256, coverage_corim_payload())
        .set_cwt_claims(CwtClaims::new("ACME Corp").with_exp(9999999999).with_nbf(0));
    let _tbs = builder.to_be_signed(&[]).unwrap();
    let signed_bytes = builder.build_with_signature(vec![0; 64]).unwrap();
    let decoded = decode_signed_corim(&signed_bytes).unwrap();
    let cwt = decoded.protected.cwt_claims.unwrap();
    assert_eq!(cwt.iss, "ACME Corp");
    assert_eq!(cwt.exp, Some(9999999999));
}

#[test]
fn signed_corim_builder_without_meta_or_cwt_fails() {
    let mut builder = SignedCorimBuilder::new(-7i64, vec![0xA0]);
    assert!(builder.to_be_signed(&[]).is_err());
}

// ===========================================================================
// CwtClaims fluent builder
// ===========================================================================

#[test]
fn cwt_claims_builder_methods_set_each_field() {
    let c = CwtClaims::new("iss")
        .with_sub("sub")
        .with_exp(9999)
        .with_nbf(1000);
    assert_eq!(c.iss, "iss");
    assert_eq!(c.sub, Some("sub".into()));
    assert_eq!(c.exp, Some(9999));
    assert_eq!(c.nbf, Some(1000));
}

// ===========================================================================
// validate_signed_corim_payload — detached error path
// ===========================================================================

#[test]
fn validate_signed_corim_payload_errors_when_detached() {
    let header = coverage_header_with_meta();
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

// ===========================================================================
// build_sig_structure1 — RFC 9052 §4.4 TBS construction
// ===========================================================================

#[test]
fn build_sig_structure1_emits_4_element_array_with_context() {
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
fn build_sig_structure1_with_aad_differs_from_without() {
    let tbs1 = build_sig_structure1(&[0xA0], &[], &[0x01]).unwrap();
    let tbs2 = build_sig_structure1(&[0xA0], &[0xFF], &[0x01]).unwrap();
    assert_ne!(tbs1, tbs2);
}
