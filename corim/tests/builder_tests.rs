// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Tests for the public builder APIs (`ComidBuilder`, `CotlBuilder`,
//! `CorimBuilder`) covering the fluent setter methods and the failure
//! modes of `add_coswid` / `build`.

use corim::builder::{ComidBuilder, CorimBuilder, CotlBuilder};
use corim::types::common::*;
use corim::types::corim::*;
use corim::types::coswid::*;
use corim::types::environment::*;
use corim::types::measurement::*;
use corim::types::triples::*;

fn one_reference_triple() -> ReferenceTriple {
    ReferenceTriple::new(
        EnvironmentMap::for_class("V", "M"),
        vec![MeasurementMap {
            mkey: None,
            mval: MeasurementValuesMap {
                svn: Some(SvnChoice::ExactValue(1)),
                ..Default::default()
            },
            authorized_by: None,
        }],
    )
}

#[test]
fn cotl_builder_set_tag_version() {
    let cotl = CotlBuilder::new(TagIdChoice::Text("v".into()), i64::MAX)
        .set_tag_version(3)
        .add_tag_id(TagIdChoice::Text("x".into()))
        .build()
        .unwrap();
    assert_eq!(cotl.tag_identity.tag_version, Some(3));
}

#[test]
fn corim_builder_add_entity() {
    let entity = EntityMap {
        entity_name: "ACME".into(),
        reg_id: Some("https://acme.example".into()),
        role: vec![1],
    };
    let comid = ComidBuilder::new(TagIdChoice::Text("t".into()))
        .add_reference_triple(one_reference_triple())
        .build()
        .unwrap();
    let corim = CorimBuilder::new(CorimId::Text("c".into()))
        .add_entity(entity)
        .add_comid_tag(comid)
        .unwrap()
        .build()
        .unwrap();
    assert!(corim.entities.is_some());
    assert_eq!(corim.entities.unwrap().len(), 1);
}

#[test]
fn corim_builder_add_dependent_rim() {
    let locator = CorimLocator {
        href: CorimLocatorHref::Single("https://example.com/dep.corim".into()),
        thumbprint: None,
    };
    let comid = ComidBuilder::new(TagIdChoice::Text("t".into()))
        .add_reference_triple(one_reference_triple())
        .build()
        .unwrap();
    let corim = CorimBuilder::new(CorimId::Text("c".into()))
        .add_dependent_rim(locator)
        .add_comid_tag(comid)
        .unwrap()
        .build()
        .unwrap();
    assert!(corim.dependent_rims.is_some());
}

#[test]
fn corim_builder_add_tag_directly() {
    let corim = CorimBuilder::new(CorimId::Text("c".into()))
        .add_tag(ConciseTagChoice::Comid(vec![0xA0]))
        .build()
        .unwrap();
    assert_eq!(corim.tags.len(), 1);
}

#[test]
fn corim_builder_set_profile() {
    let comid = ComidBuilder::new(TagIdChoice::Text("t".into()))
        .add_reference_triple(one_reference_triple())
        .build()
        .unwrap();
    let corim = CorimBuilder::new(CorimId::Text("c".into()))
        .set_profile(ProfileChoice::Uri("https://example.com/profile".into()))
        .add_comid_tag(comid)
        .unwrap()
        .build()
        .unwrap();
    assert!(corim.profile.is_some());
}

#[test]
fn comid_builder_conditional_endorsement_accepts_empty_endorsements() {
    // The builder doesn't validate inner structure — it just collects triples.
    // Inner-validity (e.g. non-empty endorsements) is enforced by `Validate`,
    // not by `build()`.
    let result = ComidBuilder::new(TagIdChoice::Text("t".into()))
        .add_conditional_endorsement(ConditionalEndorsementTriple(
            vec![StatefulEnvironmentRecord(
                EnvironmentMap::for_class("V", "M"),
                vec![MeasurementMap {
                    mkey: None,
                    mval: MeasurementValuesMap {
                        svn: Some(SvnChoice::ExactValue(1)),
                        ..Default::default()
                    },
                    authorized_by: None,
                }],
            )],
            vec![],
        ))
        .build();
    assert!(result.is_ok());
}

#[test]
fn comid_builder_conditional_endorsement_series() {
    let env = EnvironmentMap::for_class("V", "M");
    let meas = vec![MeasurementMap {
        mkey: Some(MeasuredElement::Uint(1)),
        mval: MeasurementValuesMap {
            svn: Some(SvnChoice::ExactValue(1)),
            ..Default::default()
        },
        authorized_by: None,
    }];
    let ces = ConditionalEndorsementSeriesTriple::new(
        CesCondition {
            environment: env,
            claims_list: vec![],
            authorized_by: None,
        },
        vec![ConditionalSeriesRecord::new(meas.clone(), meas)],
    );
    let comid = ComidBuilder::new(TagIdChoice::Text("t".into()))
        .add_conditional_endorsement_series(ces)
        .build()
        .unwrap();
    assert!(comid.triples.conditional_endorsement_series.is_some());
}

#[test]
fn comid_builder_set_language_and_entities() {
    let comid = ComidBuilder::new(TagIdChoice::Text("t".into()))
        .set_language("en-US")
        .set_tag_version(2)
        .add_entity(EntityMap {
            entity_name: "Test".into(),
            reg_id: None,
            role: vec![0],
        })
        .add_linked_tag(LinkedTagMap {
            linked_tag_id: TagIdChoice::Text("other".into()),
            tag_rel: 0,
        })
        .add_reference_triple(one_reference_triple())
        .build()
        .unwrap();
    assert_eq!(comid.language.as_deref(), Some("en-US"));
    assert_eq!(comid.tag_identity.tag_version, Some(2));
    assert!(comid.entities.is_some());
    assert!(comid.linked_tags.is_some());
}

#[test]
fn corim_builder_add_coswid_invalid_fails() {
    // CoSWID with no entities — `add_coswid` validates and rejects.
    let bad_coswid = ConciseSwidTag::new(TagIdChoice::Text("x".into()), "Test", 0, vec![]);
    let result = CorimBuilder::new(CorimId::Text("c".into())).add_coswid(bad_coswid);
    assert!(result.is_err());
}
