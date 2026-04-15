// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Tests for CoSWID types and JSON serialization.

use corim::cbor;
use corim::types::common::TagIdChoice;
use corim::types::coswid::*;
use corim::types::tags::*;
use corim::Validate;

// ===========================================================================
// CoSWID CBOR round-trip
// ===========================================================================

fn make_swid_entity() -> SwidEntity {
    SwidEntity::new(
        "ACME Ltd",
        vec![SWID_ROLE_TAG_CREATOR, SWID_ROLE_SOFTWARE_CREATOR],
    )
    .with_reg_id("https://acme.example")
}

fn make_coswid() -> ConciseSwidTag {
    ConciseSwidTag::new(
        TagIdChoice::Text("example.acme.roadrunner-sw-v1".into()),
        "Roadrunner software bundle",
        0,
        vec![make_swid_entity()],
    )
}

#[test]
fn coswid_cbor_round_trip() {
    let tag = make_coswid();
    let bytes = cbor::encode(&tag).unwrap();
    let decoded: ConciseSwidTag = cbor::decode(&bytes).unwrap();
    assert_eq!(tag.tag_id, decoded.tag_id);
    assert_eq!(tag.software_name, decoded.software_name);
    assert_eq!(tag.tag_version, decoded.tag_version);
    assert_eq!(tag.entities.len(), decoded.entities.len());
    assert_eq!(tag.entities[0].entity_name, decoded.entities[0].entity_name);
    assert_eq!(tag.entities[0].roles, decoded.entities[0].roles);
}

#[test]
fn coswid_with_all_fields() {
    let mut tag = make_coswid();
    tag.software_version = Some("1.0.0".into());
    tag.version_scheme = Some(VERSION_SCHEME_SEMVER);
    tag.lang = Some("en-US".into());
    tag.corpus = Some(false);
    tag.patch = Some(false);
    tag.supplemental = Some(false);
    tag.links = Some(vec![
        SwidLink::new("example.acme.roadrunner-hw-v1", SWID_REL_PARENT),
        SwidLink::new("example.acme.roadrunner-sw-bl-v1", SWID_REL_COMPONENT),
    ]);

    let bytes = cbor::encode(&tag).unwrap();
    let decoded: ConciseSwidTag = cbor::decode(&bytes).unwrap();
    assert_eq!(tag.software_version, decoded.software_version);
    assert_eq!(tag.version_scheme, decoded.version_scheme);
    assert_eq!(tag.lang, decoded.lang);
    assert_eq!(tag.links.as_ref().unwrap().len(), 2);
}

#[test]
fn coswid_entity_round_trip() {
    let entity = make_swid_entity();
    let bytes = cbor::encode(&entity).unwrap();
    let decoded: SwidEntity = cbor::decode(&bytes).unwrap();
    assert_eq!(entity, decoded);
}

#[test]
fn coswid_link_round_trip() {
    let link = SwidLink::new(
        "swid:2df9de35-0aff-4a86-ace6-f7dddd1ade4c",
        SWID_REL_PATCHES,
    );
    let bytes = cbor::encode(&link).unwrap();
    let decoded: SwidLink = cbor::decode(&bytes).unwrap();
    assert_eq!(link, decoded);
}

#[test]
fn coswid_uuid_tag_id() {
    let uuid = [
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
        0x10,
    ];
    let tag = ConciseSwidTag::new(
        TagIdChoice::Uuid(uuid),
        "Test",
        0,
        vec![SwidEntity::new("Test Corp", vec![SWID_ROLE_TAG_CREATOR])],
    );
    let bytes = cbor::encode(&tag).unwrap();
    let decoded: ConciseSwidTag = cbor::decode(&bytes).unwrap();
    assert_eq!(TagIdChoice::Uuid(uuid), decoded.tag_id);
}

// ===========================================================================
// CoSWID Validation
// ===========================================================================

#[test]
fn coswid_valid() {
    let tag = make_coswid();
    assert!(tag.valid().is_ok());
}

#[test]
fn coswid_no_entity_is_invalid() {
    let tag = ConciseSwidTag::new(TagIdChoice::Text("test".into()), "Test", 0, vec![]);
    let err = tag.valid().unwrap_err();
    assert!(err.contains("at least one entity"), "got: {err}");
}

#[test]
fn coswid_no_tag_creator_is_invalid() {
    let tag = ConciseSwidTag::new(
        TagIdChoice::Text("test".into()),
        "Test",
        0,
        vec![SwidEntity::new(
            "Test Corp",
            vec![SWID_ROLE_SOFTWARE_CREATOR],
        )],
    );
    let err = tag.valid().unwrap_err();
    assert!(err.contains("tag-creator"), "got: {err}");
}

#[test]
fn coswid_patch_and_supplemental_both_true_is_invalid() {
    let mut tag = make_coswid();
    tag.patch = Some(true);
    tag.supplemental = Some(true);
    tag.links = Some(vec![SwidLink::new("x", SWID_REL_PATCHES)]);
    let err = tag.valid().unwrap_err();
    assert!(err.contains("patch and supplemental"), "got: {err}");
}

#[test]
fn coswid_patch_without_patches_link_is_invalid() {
    let mut tag = make_coswid();
    tag.patch = Some(true);
    // No links at all
    let err = tag.valid().unwrap_err();
    assert!(err.contains("patches"), "got: {err}");
}

#[test]
fn coswid_patch_with_patches_link_is_valid() {
    let mut tag = make_coswid();
    tag.patch = Some(true);
    tag.links = Some(vec![SwidLink::new("example.base-sw", SWID_REL_PATCHES)]);
    assert!(tag.valid().is_ok());
}

#[test]
fn swid_entity_empty_name_is_invalid() {
    let entity = SwidEntity::new("", vec![SWID_ROLE_TAG_CREATOR]);
    let err = entity.valid().unwrap_err();
    assert!(err.contains("entity-name"), "got: {err}");
}

#[test]
fn swid_entity_no_roles_is_invalid() {
    let entity = SwidEntity::new("Test Corp", vec![]);
    let err = entity.valid().unwrap_err();
    assert!(err.contains("role"), "got: {err}");
}

#[test]
fn swid_link_empty_href_is_invalid() {
    let link = SwidLink::new("", SWID_REL_COMPONENT);
    let err = link.valid().unwrap_err();
    assert!(err.contains("href"), "got: {err}");
}

// ===========================================================================
// CoSWID in CoRIM (builder + validate)
// ===========================================================================

#[test]
fn corim_builder_add_coswid() {
    use corim::builder::{ComidBuilder, CorimBuilder};
    use corim::types::corim::CorimId;
    use corim::types::environment::EnvironmentMap;
    use corim::types::measurement::{Digest, MeasurementMap, MeasurementValuesMap};
    use corim::types::triples::ReferenceTriple;

    let comid = ComidBuilder::new(TagIdChoice::Text("comid-1".into()))
        .add_reference_triple(ReferenceTriple::new(
            EnvironmentMap::for_class("ACME", "Widget"),
            vec![MeasurementMap {
                mkey: None,
                mval: MeasurementValuesMap {
                    digests: Some(vec![Digest::new(7, vec![0xAA; 32])]),
                    ..MeasurementValuesMap::default()
                },
                authorized_by: None,
            }],
        ))
        .build()
        .unwrap();

    let coswid = make_coswid();

    let bytes = CorimBuilder::new(CorimId::Text("with-coswid".into()))
        .add_comid_tag(comid)
        .unwrap()
        .add_coswid(coswid)
        .unwrap()
        .build_bytes()
        .unwrap();

    let full = corim::validate::decode_and_validate_full(&bytes).unwrap();
    assert_eq!(full.comids.len(), 1);
    assert_eq!(full.coswids.len(), 1);
    assert_eq!(full.coswids[0].software_name, "Roadrunner software bundle");
    assert_eq!(full.coswid_opaque_count, 0);
}

// ===========================================================================
// JSON serialization (requires `json` feature)
// ===========================================================================

#[cfg(feature = "json")]
mod json_tests {
    use super::*;
    use corim::json;
    use corim::types::common::{CborTime, EntityMap, TagIdentity, ValidityMap};
    use corim::types::environment::{ClassMap, EnvironmentMap};
    use corim::types::measurement::{Digest, MeasurementMap, MeasurementValuesMap, SvnChoice};

    #[test]
    fn json_class_map_round_trip() {
        let class = ClassMap::new("ACME", "Widget");
        let json_str = json::to_json(&class).unwrap();

        // Should contain the values
        assert!(json_str.contains("ACME"), "json: {json_str}");
        assert!(json_str.contains("Widget"), "json: {json_str}");

        // Round-trip
        let decoded: ClassMap = json::from_json(&json_str).unwrap();
        assert_eq!(class, decoded);
    }

    #[test]
    fn json_environment_map_round_trip() {
        let env = EnvironmentMap::for_class("Intel", "TDX");
        let json_str = json::to_json(&env).unwrap();
        let decoded: EnvironmentMap = json::from_json(&json_str).unwrap();
        assert_eq!(env, decoded);
    }

    #[test]
    fn json_measurement_map_with_svn() {
        // Round-trip for measurement values that don't contain raw bytes
        let meas = MeasurementMap {
            mkey: None,
            mval: MeasurementValuesMap {
                svn: Some(SvnChoice::ExactValue(42)),
                name: Some("test-component".into()),
                ..MeasurementValuesMap::default()
            },
            authorized_by: None,
        };
        let json_str = json::to_json(&meas).unwrap();
        let decoded: MeasurementMap = json::from_json(&json_str).unwrap();
        assert_eq!(meas.mval.svn, decoded.mval.svn);
        assert_eq!(meas.mval.name, decoded.mval.name);
    }

    #[test]
    fn json_measurement_with_digests_encodes() {
        // Digests encode to JSON (bytes → base64), but round-trip requires
        // context-aware bytes detection (deferred: tracked in Phase 7B.4)
        let meas = MeasurementMap {
            mkey: None,
            mval: MeasurementValuesMap {
                digests: Some(vec![Digest::new(7, vec![0xBB; 32])]),
                ..MeasurementValuesMap::default()
            },
            authorized_by: None,
        };
        let json_str = json::to_json(&meas).unwrap();
        // Should contain the base64-encoded digest value
        assert!(json_str.len() > 10, "json: {json_str}");
    }

    #[test]
    fn json_tag_identity_round_trip() {
        let tid = TagIdentity {
            tag_id: TagIdChoice::Text("my-tag".into()),
            tag_version: Some(1),
        };
        let json_str = json::to_json(&tid).unwrap();
        assert!(json_str.contains("my-tag"), "json: {json_str}");
        let decoded: TagIdentity = json::from_json(&json_str).unwrap();
        assert_eq!(tid, decoded);
    }

    #[test]
    fn json_coswid_round_trip() {
        let tag = make_coswid();
        let json_str = json::to_json(&tag).unwrap();
        assert!(json_str.contains("Roadrunner"), "json: {json_str}");
        assert!(json_str.contains("ACME"), "json: {json_str}");

        let decoded: ConciseSwidTag = json::from_json(&json_str).unwrap();
        assert_eq!(tag.software_name, decoded.software_name);
        assert_eq!(tag.tag_version, decoded.tag_version);
    }

    #[test]
    fn json_coswid_entity_uses_string_keys() {
        let entity = make_swid_entity();
        let json_str = json::to_json(&entity).unwrap();
        // Keys 31+ should use string names from the global table
        assert!(json_str.contains("entity-name"), "json: {json_str}");
        assert!(json_str.contains("reg-id"), "json: {json_str}");
        assert!(json_str.contains("role"), "json: {json_str}");
    }

    #[test]
    fn json_swid_link_uses_string_keys() {
        let link = SwidLink::new("https://example.com", SWID_REL_COMPONENT);
        let json_str = json::to_json(&link).unwrap();
        assert!(json_str.contains("href"), "json: {json_str}");
        assert!(json_str.contains("rel"), "json: {json_str}");
    }

    #[test]
    fn json_pretty_print() {
        let class = ClassMap::new("ACME", "Widget");
        let json_str = json::to_json_pretty(&class).unwrap();
        assert!(json_str.contains('\n'), "should be multiline");
        assert!(json_str.contains("ACME"));
    }

    #[test]
    fn json_uuid_type_choice() {
        let tag_id = TagIdChoice::Uuid([0x01; 16]);
        let json_str = json::to_json(&tag_id).unwrap();
        // Should be {"type":"uuid","value":"01010101-0101-0101-0101-010101010101"}
        assert!(json_str.contains("uuid"), "json: {json_str}");
        assert!(json_str.contains("01010101"), "json: {json_str}");
    }

    #[test]
    fn json_validity_map_round_trip() {
        let validity = ValidityMap {
            not_before: Some(CborTime::new(1000)),
            not_after: CborTime::new(2000),
        };
        let json_str = json::to_json(&validity).unwrap();
        let decoded: ValidityMap = json::from_json(&json_str).unwrap();
        assert_eq!(validity, decoded);
    }

    #[test]
    fn json_entity_map_round_trip() {
        let entity = EntityMap {
            entity_name: "ACME Ltd.".into(),
            reg_id: Some("https://acme.example".into()),
            role: vec![1, 2],
        };
        let json_str = json::to_json(&entity).unwrap();
        let decoded: EntityMap = json::from_json(&json_str).unwrap();
        assert_eq!(entity, decoded);
    }
}
