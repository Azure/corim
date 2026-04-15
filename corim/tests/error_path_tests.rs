// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Negative / error-path tests: malformed CBOR, wrong tags, size limits,
//! empty-list validation, and other failure modes.

use corim::cbor;
use corim::types::common::*;
use corim::types::corim::*;
use corim::types::environment::*;
use corim::types::measurement::*;
use corim::types::triples::*;

fn make_env() -> EnvironmentMap {
    EnvironmentMap {
        class: Some(ClassMap {
            class_id: None,
            vendor: Some("V".into()),
            model: Some("M".into()),
            layer: None,
            index: None,
        }),
        instance: None,
        group: None,
    }
}

fn make_meas() -> MeasurementMap {
    MeasurementMap {
        mkey: Some(MeasuredElement::Text("fw".into())),
        mval: MeasurementValuesMap {
            digests: Some(vec![Digest::new(7, vec![0xAA; 48])]),
            ..MeasurementValuesMap::default()
        },
        authorized_by: None,
    }
}

fn make_valid_corim_bytes() -> Vec<u8> {
    use corim::builder::{ComidBuilder, CorimBuilder};
    let comid = ComidBuilder::new(TagIdChoice::Text("t".into()))
        .add_reference_triple(ReferenceTriple::new(make_env(), vec![make_meas()]))
        .build()
        .unwrap();
    CorimBuilder::new(CorimId::Text("c".into()))
        .set_validity(None, i64::MAX)
        .unwrap()
        .add_comid_tag(comid)
        .unwrap()
        .build_bytes()
        .unwrap()
}

// ═══════════════════════════════════════════════════════════════════════════
// Malformed CBOR input
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn decode_empty_bytes() {
    let result = corim::validate::decode_and_validate(&[]);
    assert!(result.is_err());
}

#[test]
fn decode_truncated_cbor() {
    let valid = make_valid_corim_bytes();
    // Truncate to half
    let truncated = &valid[..valid.len() / 2];
    let result = corim::validate::decode_and_validate(truncated);
    assert!(result.is_err());
}

#[test]
fn decode_random_garbage() {
    let garbage = vec![0xFF, 0xFE, 0xFD, 0xFC, 0xFB, 0xFA];
    let result = corim::validate::decode_and_validate(&garbage);
    assert!(result.is_err());
}

#[test]
fn decode_valid_cbor_but_not_tagged() {
    // Encode a plain map (not tag-501 wrapped)
    let map = corim::cbor::value::Value::Map(vec![(
        corim::cbor::value::Value::Integer(0),
        corim::cbor::value::Value::Text("id".into()),
    )]);
    let bytes = cbor::encode(&map).unwrap();
    let result = corim::validate::decode_and_validate(&bytes);
    assert!(result.is_err());
}

#[test]
fn decode_wrong_outer_tag() {
    // Wrap in tag 500 instead of 501
    let comid = corim::builder::ComidBuilder::new(TagIdChoice::Text("t".into()))
        .add_reference_triple(ReferenceTriple::new(make_env(), vec![make_meas()]))
        .build()
        .unwrap();
    let corim_map = corim::builder::CorimBuilder::new(CorimId::Text("c".into()))
        .add_comid_tag(comid)
        .unwrap()
        .build()
        .unwrap();
    let tagged = corim::cbor::value::Tagged::new(500, corim_map); // wrong tag!
    let bytes = cbor::encode(&tagged).unwrap();

    let result = corim::validate::decode_and_validate(&bytes);
    assert!(result.is_err());
    let err = format!("{}", result.unwrap_err());
    assert!(
        err.contains("501") || err.contains("500"),
        "error should mention tags: {}",
        err
    );
}

// ═══════════════════════════════════════════════════════════════════════════
// Payload size limit
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn decode_payload_too_large() {
    // Create a buffer slightly over MAX_PAYLOAD_SIZE
    let huge = vec![0u8; corim::validate::MAX_PAYLOAD_SIZE + 1];
    let result = corim::validate::decode_and_validate(&huge);
    assert!(result.is_err());
    let err = format!("{}", result.unwrap_err());
    assert!(err.contains("too large"), "error: {}", err);
}

#[test]
fn decode_payload_at_limit_is_accepted() {
    // Payload exactly at the limit should not be rejected for size
    // (it may fail for other reasons like invalid CBOR, but not size)
    let bytes = vec![0u8; corim::validate::MAX_PAYLOAD_SIZE];
    let result = corim::validate::decode_and_validate(&bytes);
    // Should fail with a CBOR decode error, NOT PayloadTooLarge
    assert!(result.is_err());
    let err = format!("{}", result.unwrap_err());
    assert!(
        !err.contains("too large"),
        "should not be a size error: {}",
        err
    );
}

// ═══════════════════════════════════════════════════════════════════════════
// Expiration / validity
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn decode_expired_corim() {
    use corim::builder::{ComidBuilder, CorimBuilder};
    let comid = ComidBuilder::new(TagIdChoice::Text("t".into()))
        .add_reference_triple(ReferenceTriple::new(make_env(), vec![make_meas()]))
        .build()
        .unwrap();
    let bytes = CorimBuilder::new(CorimId::Text("expired".into()))
        .set_validity(None, 0)
        .unwrap() // epoch 0 = always expired
        .add_comid_tag(comid)
        .unwrap()
        .build_bytes()
        .unwrap();

    let result = corim::validate::decode_and_validate(&bytes);
    assert!(result.is_err());
    assert!(format!("{}", result.unwrap_err()).contains("expired"));
}

// ═══════════════════════════════════════════════════════════════════════════
// Builder: empty list validation ([+ T])
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn builder_reference_triple_empty_measurements() {
    use corim::builder::ComidBuilder;
    let result = ComidBuilder::new(TagIdChoice::Text("t".into()))
        .add_reference_triple(ReferenceTriple::new(make_env(), vec![])) // empty!
        .build();
    assert!(result.is_err());
    assert!(format!("{}", result.unwrap_err()).contains("ref-claims"));
}

#[test]
fn builder_endorsed_triple_empty_endorsements() {
    use corim::builder::ComidBuilder;
    let result = ComidBuilder::new(TagIdChoice::Text("t".into()))
        .add_endorsed_triple(EndorsedTriple::new(make_env(), vec![])) // empty!
        .build();
    assert!(result.is_err());
    assert!(format!("{}", result.unwrap_err()).contains("endorsement"));
}

#[test]
fn builder_identity_triple_empty_keys() {
    use corim::builder::ComidBuilder;
    let result = ComidBuilder::new(TagIdChoice::Text("t".into()))
        .add_identity_triple(IdentityTriple::new(make_env(), vec![], None)) // empty!
        .build();
    assert!(result.is_err());
    assert!(format!("{}", result.unwrap_err()).contains("key-list"));
}

#[test]
fn builder_attest_key_triple_empty_keys() {
    use corim::builder::ComidBuilder;
    let result = ComidBuilder::new(TagIdChoice::Text("t".into()))
        .add_attest_key_triple(AttestKeyTriple::new(make_env(), vec![], None))
        .build();
    assert!(result.is_err());
    assert!(format!("{}", result.unwrap_err()).contains("key-list"));
}

#[test]
fn builder_dependency_triple_empty_trustees() {
    use corim::builder::ComidBuilder;
    let result = ComidBuilder::new(TagIdChoice::Text("t".into()))
        .add_dependency_triple(DomainDependencyTriple::new(make_env(), vec![]))
        .build();
    assert!(result.is_err());
    assert!(format!("{}", result.unwrap_err()).contains("trustees"));
}

#[test]
fn builder_membership_triple_empty_members() {
    use corim::builder::ComidBuilder;
    let result = ComidBuilder::new(TagIdChoice::Text("t".into()))
        .add_membership_triple(DomainMembershipTriple::new(make_env(), vec![]))
        .build();
    assert!(result.is_err());
    assert!(format!("{}", result.unwrap_err()).contains("members"));
}

#[test]
fn builder_coswid_triple_empty_tag_ids() {
    use corim::builder::ComidBuilder;
    let result = ComidBuilder::new(TagIdChoice::Text("t".into()))
        .add_coswid_triple(CoswidTriple::new(make_env(), vec![]))
        .build();
    assert!(result.is_err());
    assert!(format!("{}", result.unwrap_err()).contains("tag-ids"));
}

#[test]
fn builder_corim_no_tags() {
    use corim::builder::CorimBuilder;
    let result = CorimBuilder::new(CorimId::Text("empty".into())).build();
    assert!(result.is_err());
}

#[test]
fn builder_comid_no_triples() {
    use corim::builder::ComidBuilder;
    let result = ComidBuilder::new(TagIdChoice::Text("empty".into())).build();
    assert!(result.is_err());
}

// ═══════════════════════════════════════════════════════════════════════════
// Type-choice deserialization with wrong CBOR types
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn class_id_wrong_tag_number() {
    // Encode tag 999 wrapping bytes — should fail to decode as ClassIdChoice
    let val = corim::cbor::value::Value::Tag(
        999,
        Box::new(corim::cbor::value::Value::Bytes(vec![1, 2, 3])),
    );
    let bytes = cbor::encode(&val).unwrap();
    let result = cbor::decode::<ClassIdChoice>(&bytes);
    assert!(result.is_err());
}

#[test]
fn instance_id_wrong_tag_number() {
    let val = corim::cbor::value::Value::Tag(
        999,
        Box::new(corim::cbor::value::Value::Bytes(vec![1, 2, 3])),
    );
    let bytes = cbor::encode(&val).unwrap();
    let result = cbor::decode::<InstanceIdChoice>(&bytes);
    assert!(result.is_err());
}

#[test]
fn tag_id_not_text_or_tagged() {
    // Encode an integer — should fail to decode as TagIdChoice
    let bytes = cbor::encode(&42i64).unwrap();
    let result = cbor::decode::<TagIdChoice>(&bytes);
    assert!(result.is_err());
}

#[test]
fn crypto_key_wrong_tag_number() {
    let val = corim::cbor::value::Value::Tag(
        123,
        Box::new(corim::cbor::value::Value::Text("data".into())),
    );
    let bytes = cbor::encode(&val).unwrap();
    let result = cbor::decode::<CryptoKey>(&bytes);
    assert!(result.is_err());
}

#[test]
fn uuid_wrong_size_in_tag_id() {
    // Tag 37 wrapping 15 bytes (should be 16)
    let val = corim::cbor::value::Value::Tag(
        37,
        Box::new(corim::cbor::value::Value::Bytes(vec![0u8; 15])),
    );
    let bytes = cbor::encode(&val).unwrap();
    let result = cbor::decode::<TagIdChoice>(&bytes);
    assert!(result.is_err());
}

#[test]
fn uuid_wrong_size_in_class_id() {
    // Tag 37 wrapping 17 bytes
    let val = corim::cbor::value::Value::Tag(
        37,
        Box::new(corim::cbor::value::Value::Bytes(vec![0u8; 17])),
    );
    let bytes = cbor::encode(&val).unwrap();
    let result = cbor::decode::<ClassIdChoice>(&bytes);
    assert!(result.is_err());
}

// ═══════════════════════════════════════════════════════════════════════════
// Unknown map keys are skipped (forward-compat)
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn unknown_map_keys_skipped() {
    // Encode a ClassMap with an extra key 99
    let val = corim::cbor::value::Value::Map(vec![
        (
            corim::cbor::value::Value::Integer(1),
            corim::cbor::value::Value::Text("Vendor".into()),
        ),
        (
            corim::cbor::value::Value::Integer(99),
            corim::cbor::value::Value::Text("unknown-extension".into()),
        ),
    ]);
    let bytes = cbor::encode(&val).unwrap();
    let decoded: ClassMap = cbor::decode(&bytes).unwrap();
    assert_eq!(decoded.vendor.as_deref(), Some("Vendor"));
}

// ═══════════════════════════════════════════════════════════════════════════
// Display impls smoke test
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn display_impls_dont_panic() {
    assert!(!format!("{}", TagIdChoice::Text("t".into())).is_empty());
    assert!(!format!("{}", TagIdChoice::Uuid([0xAA; 16])).is_empty());
    assert!(!format!("{}", CorimId::Text("c".into())).is_empty());
    assert!(!format!("{}", CorimId::Uuid([0xBB; 16])).is_empty());
    assert!(!format!("{}", ClassIdChoice::Oid(vec![0x2B])).is_empty());
    assert!(!format!("{}", ClassIdChoice::Uuid([0xCC; 16])).is_empty());
    assert!(!format!("{}", ClassIdChoice::Bytes(vec![1, 2, 3])).is_empty());
    assert!(!format!("{}", InstanceIdChoice::Ueid(vec![1; 17])).is_empty());
    assert!(!format!("{}", GroupIdChoice::Uuid([0xDD; 16])).is_empty());
    assert!(!format!("{}", MeasuredElement::Text("m".into())).is_empty());
    assert!(!format!("{}", MeasuredElement::Uint(42)).is_empty());
    assert!(!format!("{}", CryptoKey::PkixBase64Key("k".into())).is_empty());
    assert!(!format!("{}", CryptoKey::Bytes(vec![1])).is_empty());
    assert!(!format!("{}", ProfileChoice::Uri("u".into())).is_empty());
    assert!(!format!("{}", ProfileChoice::Oid(vec![0x2B])).is_empty());
}
