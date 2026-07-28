// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Tests for CoTL (Concise Tag List) — §6.1 of draft-ietf-rats-corim-11.

use corim::builder::{ComidBuilder, CorimBuilder, CotlBuilder};
use corim::cbor;
use corim::types::common::*;
use corim::types::corim::*;
use corim::types::environment::EnvironmentMap;
use corim::types::measurement::*;
use corim::types::triples::ReferenceTriple;

fn make_comid() -> corim::types::comid::ComidTag {
    ComidBuilder::new(TagIdChoice::Text("test-comid".into()))
        .add_reference_triple(ReferenceTriple::new(
            EnvironmentMap::for_class("V", "M"),
            vec![MeasurementMap {
                mkey: None,
                mval: MeasurementValuesMap {
                    digests: Some(vec![Digest::new(7, vec![0xAA; 48])]),
                    ..MeasurementValuesMap::default()
                },
                authorized_by: None,
            }],
        ))
        .build()
        .unwrap()
}

// ═══════════════════════════════════════════════════════════════════════════
// CotlBuilder
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn cotl_builder_basic() {
    let cotl = CotlBuilder::new(TagIdChoice::Text("cotl-1".into()), 2000000000)
        .set_tag_version(0)
        .add_tag_id(TagIdChoice::Text("comid-1".into()))
        .add_tag_id(TagIdChoice::Text("comid-2".into()))
        .build()
        .unwrap();

    assert_eq!(cotl.tag_identity.tag_id, TagIdChoice::Text("cotl-1".into()));
    assert_eq!(cotl.tags_list.len(), 2);
    assert_eq!(cotl.tl_validity.not_after.epoch_secs(), 2000000000);
}

#[test]
fn cotl_builder_with_uuid_tags() {
    let cotl = CotlBuilder::new(TagIdChoice::Uuid([0xAA; 16]), 2000000000)
        .add_tag(TagIdentity {
            tag_id: TagIdChoice::Uuid([0xBB; 16]),
            tag_version: Some(3),
        })
        .build()
        .unwrap();

    assert_eq!(cotl.tags_list.len(), 1);
    assert_eq!(cotl.tags_list[0].tag_version, Some(3));
}

#[test]
fn cotl_builder_with_validity_window() {
    let cotl = CotlBuilder::new(TagIdChoice::Text("cotl".into()), 2000000000)
        .set_not_before(1000000000)
        .add_tag_id(TagIdChoice::Text("t".into()))
        .build()
        .unwrap();

    assert_eq!(
        cotl.tl_validity.not_before.unwrap().epoch_secs(),
        1000000000
    );
}

#[test]
fn cotl_builder_empty_tags_fails() {
    let result = CotlBuilder::new(TagIdChoice::Text("cotl".into()), 2000000000).build();
    assert!(result.is_err());
    assert!(format!("{}", result.unwrap_err()).contains("tags-list"));
}

#[test]
fn cotl_builder_invalid_validity_fails() {
    let result = CotlBuilder::new(TagIdChoice::Text("cotl".into()), 1000)
        .set_not_before(2000) // not_before > not_after
        .add_tag_id(TagIdChoice::Text("t".into()))
        .build();
    assert!(result.is_err());
}

// ═══════════════════════════════════════════════════════════════════════════
// ConciseTlTag round-trip
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn cotl_round_trip() {
    let cotl = CotlBuilder::new(TagIdChoice::Text("cotl-rt".into()), i64::MAX)
        .set_tag_version(1)
        .set_not_before(1000000000)
        .add_tag_id(TagIdChoice::Text("comid-a".into()))
        .add_tag_id(TagIdChoice::Uuid([0xCC; 16]))
        .build()
        .unwrap();

    let bytes = cbor::encode(&cotl).unwrap();
    let decoded: ConciseTlTag = cbor::decode(&bytes).unwrap();
    assert_eq!(cotl, decoded);
}

// ═══════════════════════════════════════════════════════════════════════════
// CoRIM with CoTL
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn corim_with_cotl_and_comid() {
    let comid = make_comid();
    let cotl = CotlBuilder::new(TagIdChoice::Text("cotl-1".into()), i64::MAX)
        .add_tag_id(TagIdChoice::Text("test-comid".into()))
        .build()
        .unwrap();

    let bytes = CorimBuilder::new(CorimId::Text("mixed-tags".into()))
        .add_comid_tag(comid)
        .unwrap()
        .add_cotl(cotl)
        .unwrap()
        .build_bytes()
        .unwrap();

    // Validate — should decode both CoMID and CoTL
    let (corim, comids) = corim::validate::decode_and_validate(&bytes).unwrap();
    assert_eq!(corim.tags.len(), 2);
    assert_eq!(comids.len(), 1);

    // Full validation should also return CoTL
    let full = corim::validate::decode_and_validate_full(&bytes).unwrap();
    assert_eq!(full.comids.len(), 1);
    assert_eq!(full.cotls.len(), 1);
    assert_eq!(
        full.cotls[0].tag_identity.tag_id,
        TagIdChoice::Text("cotl-1".into())
    );
    assert_eq!(full.coswids.len(), 0);
    assert_eq!(full.coswid_opaque_count, 0);
}

#[test]
fn corim_with_only_cotl_fails_validation() {
    // CoRIM with only CoTL and no CoMID should fail (no CoMID tags)
    let cotl = CotlBuilder::new(TagIdChoice::Text("cotl-only".into()), i64::MAX)
        .add_tag_id(TagIdChoice::Text("nonexistent".into()))
        .build()
        .unwrap();

    let bytes = CorimBuilder::new(CorimId::Text("cotl-only".into()))
        .add_cotl(cotl)
        .unwrap()
        .build_bytes()
        .unwrap();

    let result = corim::validate::decode_and_validate(&bytes);
    assert!(result.is_err());
    assert!(format!("{}", result.unwrap_err()).contains("CoMID"));
}

// ═══════════════════════════════════════════════════════════════════════════
// CoTL validation
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn cotl_expired_in_corim() {
    let comid = make_comid();
    let cotl = CotlBuilder::new(TagIdChoice::Text("expired-cotl".into()), 0) // epoch 0 = expired
        .add_tag_id(TagIdChoice::Text("test-comid".into()))
        .build()
        .unwrap();

    let bytes = CorimBuilder::new(CorimId::Text("with-expired-cotl".into()))
        .add_comid_tag(comid)
        .unwrap()
        .add_cotl(cotl)
        .unwrap()
        .build_bytes()
        .unwrap();

    let result = corim::validate::decode_and_validate(&bytes);
    assert!(result.is_err());
    assert!(format!("{}", result.unwrap_err()).contains("expired"));
}

#[test]
fn cotl_not_yet_valid_in_corim() {
    let comid = make_comid();
    let cotl = CotlBuilder::new(TagIdChoice::Text("future-cotl".into()), i64::MAX)
        .set_not_before(i64::MAX - 1) // far future
        .add_tag_id(TagIdChoice::Text("test-comid".into()))
        .build()
        .unwrap();

    let bytes = CorimBuilder::new(CorimId::Text("with-future-cotl".into()))
        .add_comid_tag(comid)
        .unwrap()
        .add_cotl(cotl)
        .unwrap()
        .build_bytes()
        .unwrap();

    let result = corim::validate::decode_and_validate(&bytes);
    assert!(result.is_err());
    assert!(format!("{}", result.unwrap_err()).contains("not yet valid"));
}

// ═══════════════════════════════════════════════════════════════════════════
// CoSWID as opaque bytes
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn corim_with_coswid_opaque() {
    let comid = make_comid();
    // CoSWID is opaque bytes — just pass any CBOR map
    let coswid_bytes = cbor::encode(&corim::cbor::value::Value::Map(vec![(
        corim::cbor::value::Value::Integer(0),
        corim::cbor::value::Value::Text("fake-coswid".into()),
    )]))
    .unwrap();

    let bytes = CorimBuilder::new(CorimId::Text("with-coswid".into()))
        .add_comid_tag(comid)
        .unwrap()
        .add_coswid_tag(coswid_bytes)
        .build_bytes()
        .unwrap();

    let full = corim::validate::decode_and_validate_full(&bytes).unwrap();
    assert_eq!(full.comids.len(), 1);
    assert_eq!(full.coswid_opaque_count, 1);
    assert_eq!(full.coswids.len(), 0);
    assert_eq!(full.cotls.len(), 0);
}
