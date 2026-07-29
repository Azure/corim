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
        CesCommonCondition {
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

// ---------------------------------------------------------------------------
// strict_links lint — cross-triple environment anchoring
// ---------------------------------------------------------------------------

fn one_measurement(svn: u64) -> MeasurementMap {
    MeasurementMap {
        mkey: None,
        mval: MeasurementValuesMap {
            svn: Some(SvnChoice::ExactValue(svn)),
            ..Default::default()
        },
        authorized_by: None,
    }
}

fn one_ces(env: EnvironmentMap) -> ConditionalEndorsementSeriesTriple {
    ConditionalEndorsementSeriesTriple::new(
        CesCommonCondition {
            environment: env,
            claims_list: vec![],
            authorized_by: None,
        },
        vec![ConditionalSeriesRecord::new(
            vec![one_measurement(1)],
            vec![one_measurement(2)],
        )],
    )
}

#[test]
fn comid_builder_strict_links_rejects_unanchored_ces_env() {
    use corim::error::BuilderError;

    let env_a = EnvironmentMap::for_class("VendorA", "ModelA");
    let env_b = EnvironmentMap::for_class("VendorB", "ModelB");

    let result = ComidBuilder::new(TagIdChoice::Text("t".into()))
        .add_reference_triple(ReferenceTriple::new(env_a, vec![one_measurement(1)]))
        .add_conditional_endorsement_series(one_ces(env_b))
        .strict_links(true)
        .build();

    match result {
        Err(BuilderError::UnanchoredConditionEnv { triple_kind, index }) => {
            assert_eq!(triple_kind, "conditional-endorsement-series");
            assert_eq!(index, 0);
        }
        other => panic!("expected UnanchoredConditionEnv, got {other:?}"),
    }
}

#[test]
fn comid_builder_strict_links_accepts_matching_ces_env() {
    let env = EnvironmentMap::for_class("VendorA", "ModelA");

    ComidBuilder::new(TagIdChoice::Text("t".into()))
        .add_reference_triple(ReferenceTriple::new(env.clone(), vec![one_measurement(1)]))
        .add_conditional_endorsement_series(one_ces(env))
        .strict_links(true)
        .build()
        .expect("strict_links should accept a CES env that matches a reference triple");
}

#[test]
fn comid_builder_default_accepts_unanchored_ces_env() {
    let env_a = EnvironmentMap::for_class("VendorA", "ModelA");
    let env_b = EnvironmentMap::for_class("VendorB", "ModelB");

    ComidBuilder::new(TagIdChoice::Text("t".into()))
        .add_reference_triple(ReferenceTriple::new(env_a, vec![one_measurement(1)]))
        .add_conditional_endorsement_series(one_ces(env_b))
        .build()
        .expect("default builder must not enforce link checking");
}

#[test]
fn comid_builder_strict_links_rejects_unanchored_endorsed_env() {
    use corim::error::BuilderError;

    let env_a = EnvironmentMap::for_class("VendorA", "ModelA");
    let env_b = EnvironmentMap::for_class("VendorB", "ModelB");

    let result = ComidBuilder::new(TagIdChoice::Text("t".into()))
        .add_reference_triple(ReferenceTriple::new(env_a, vec![one_measurement(1)]))
        .add_endorsed_triple(EndorsedTriple::new(env_b, vec![one_measurement(2)]))
        .strict_links(true)
        .build();

    match result {
        Err(BuilderError::UnanchoredConditionEnv { triple_kind, index }) => {
            assert_eq!(triple_kind, "endorsed");
            assert_eq!(index, 0);
        }
        other => panic!("expected UnanchoredConditionEnv(endorsed), got {other:?}"),
    }
}

#[test]
fn comid_builder_strict_links_rejects_unanchored_conditional_endorsement_env() {
    use corim::error::BuilderError;

    let env_a = EnvironmentMap::for_class("VendorA", "ModelA");
    let env_b = EnvironmentMap::for_class("VendorB", "ModelB");

    // Two stateful records: the first is anchored, the second is not.
    let cet = ConditionalEndorsementTriple(
        vec![
            StatefulEnvironmentRecord(env_a.clone(), vec![one_measurement(1)]),
            StatefulEnvironmentRecord(env_b, vec![one_measurement(2)]),
        ],
        vec![EndorsedTriple::new(env_a.clone(), vec![one_measurement(3)])],
    );

    let result = ComidBuilder::new(TagIdChoice::Text("t".into()))
        .add_reference_triple(ReferenceTriple::new(env_a, vec![one_measurement(1)]))
        .add_conditional_endorsement(cet)
        .strict_links(true)
        .build();

    match result {
        Err(BuilderError::UnanchoredConditionEnv { triple_kind, index }) => {
            assert_eq!(triple_kind, "conditional-endorsement");
            assert_eq!(index, 0);
        }
        other => panic!("expected UnanchoredConditionEnv(conditional-endorsement), got {other:?}"),
    }
}

#[test]
fn comid_builder_strict_links_accepts_anchored_endorsed_and_cet() {
    let env = EnvironmentMap::for_class("VendorA", "ModelA");

    let cet = ConditionalEndorsementTriple(
        vec![StatefulEnvironmentRecord(
            env.clone(),
            vec![one_measurement(1)],
        )],
        vec![EndorsedTriple::new(env.clone(), vec![one_measurement(3)])],
    );

    ComidBuilder::new(TagIdChoice::Text("t".into()))
        .add_reference_triple(ReferenceTriple::new(env.clone(), vec![one_measurement(1)]))
        .add_endorsed_triple(EndorsedTriple::new(env, vec![one_measurement(2)]))
        .add_conditional_endorsement(cet)
        .strict_links(true)
        .build()
        .expect("strict_links should accept anchored endorsed + CET envs");
}

// ---------------------------------------------------------------------------
// strict_links lint — cross-triple measurement anchoring (S2 + M1)
//
// Promise: every selection-side measurement on a CES condition, CES series
// record, or CE stateful-environment-record must structurally equal some
// measurement in a reference triple **for the same env**. Endorsement /
// addition lists are not anchored.
// ---------------------------------------------------------------------------

fn meas_with_mkey(mkey: &str, svn: u64) -> MeasurementMap {
    MeasurementMap {
        mkey: Some(MeasuredElement::Text(mkey.into())),
        mval: MeasurementValuesMap {
            svn: Some(SvnChoice::ExactValue(svn)),
            ..Default::default()
        },
        authorized_by: None,
    }
}

#[test]
fn comid_builder_strict_links_rejects_unanchored_ces_claims_list_measurement() {
    use corim::error::BuilderError;

    let env = EnvironmentMap::for_class("V", "M");
    // Reference triple anchors `firmware` on this env, but the CES
    // condition selects on `bootloader` — typo / forgotten reference.
    let ces = ConditionalEndorsementSeriesTriple::new(
        CesCommonCondition {
            environment: env.clone(),
            claims_list: vec![meas_with_mkey("bootloader", 1)],
            authorized_by: None,
        },
        vec![ConditionalSeriesRecord::new(
            vec![meas_with_mkey("bootloader", 1)],
            vec![one_measurement(2)],
        )],
    );

    let result = ComidBuilder::new(TagIdChoice::Text("t".into()))
        .add_reference_triple(ReferenceTriple::new(
            env,
            vec![meas_with_mkey("firmware", 1)],
        ))
        .add_conditional_endorsement_series(ces)
        .strict_links(true)
        .build();

    match result {
        Err(BuilderError::UnanchoredConditionMeasurement {
            triple_kind,
            triple_index,
            measurement_index,
        }) => {
            assert_eq!(triple_kind, "conditional-endorsement-series");
            assert_eq!(triple_index, 0);
            assert_eq!(measurement_index, 0);
        }
        other => panic!("expected UnanchoredConditionMeasurement, got {other:?}"),
    }
}

#[test]
fn comid_builder_strict_links_rejects_unanchored_ces_condition_measurement() {
    use corim::error::BuilderError;

    let env = EnvironmentMap::for_class("V", "M");
    // claims_list is anchored (empty is fine, or matches), but the series
    // record's *condition* references an mkey not present in any reference
    // triple for this env.
    let ces = ConditionalEndorsementSeriesTriple::new(
        CesCommonCondition {
            environment: env.clone(),
            claims_list: vec![],
            authorized_by: None,
        },
        vec![ConditionalSeriesRecord::new(
            vec![meas_with_mkey("missing", 1)],
            vec![one_measurement(2)],
        )],
    );

    let result = ComidBuilder::new(TagIdChoice::Text("t".into()))
        .add_reference_triple(ReferenceTriple::new(
            env,
            vec![meas_with_mkey("firmware", 1)],
        ))
        .add_conditional_endorsement_series(ces)
        .strict_links(true)
        .build();

    match result {
        Err(BuilderError::UnanchoredConditionMeasurement {
            triple_kind,
            triple_index,
            measurement_index,
        }) => {
            assert_eq!(triple_kind, "conditional-endorsement-series-condition");
            assert_eq!(triple_index, 0);
            assert_eq!(measurement_index, 0);
        }
        other => panic!("expected UnanchoredConditionMeasurement, got {other:?}"),
    }
}

#[test]
fn comid_builder_strict_links_accepts_matching_ces_measurements() {
    let env = EnvironmentMap::for_class("V", "M");
    let m = meas_with_mkey("firmware", 1);

    let ces = ConditionalEndorsementSeriesTriple::new(
        CesCommonCondition {
            environment: env.clone(),
            claims_list: vec![m.clone()],
            authorized_by: None,
        },
        vec![ConditionalSeriesRecord::new(
            vec![m.clone()],
            // Addition is intentionally *not* in the reference triple —
            // addition lists are not anchored.
            vec![one_measurement(99)],
        )],
    );

    ComidBuilder::new(TagIdChoice::Text("t".into()))
        .add_reference_triple(ReferenceTriple::new(env, vec![m]))
        .add_conditional_endorsement_series(ces)
        .strict_links(true)
        .build()
        .expect("strict_links should accept measurements that match a reference triple for the same env");
}

#[test]
fn comid_builder_strict_links_accepts_empty_ces_claims_list() {
    // Empty claims_list means "no condition" — must always pass anchoring.
    // This is the shape the launch-endorsement caller uses.
    let env = EnvironmentMap::for_class("V", "M");
    let m = meas_with_mkey("firmware", 1);

    let ces = ConditionalEndorsementSeriesTriple::new(
        CesCommonCondition {
            environment: env.clone(),
            claims_list: vec![],
            authorized_by: None,
        },
        vec![ConditionalSeriesRecord::new(
            vec![m.clone()],
            vec![one_measurement(2)],
        )],
    );

    ComidBuilder::new(TagIdChoice::Text("t".into()))
        .add_reference_triple(ReferenceTriple::new(env, vec![m]))
        .add_conditional_endorsement_series(ces)
        .strict_links(true)
        .build()
        .expect("empty claims_list must pass measurement anchoring");
}

#[test]
fn comid_builder_strict_links_rejects_unanchored_ce_stateful_measurement() {
    use corim::error::BuilderError;

    let env = EnvironmentMap::for_class("V", "M");
    let cet = ConditionalEndorsementTriple(
        vec![StatefulEnvironmentRecord(
            env.clone(),
            vec![meas_with_mkey("missing", 1)],
        )],
        vec![EndorsedTriple::new(env.clone(), vec![one_measurement(3)])],
    );

    let result = ComidBuilder::new(TagIdChoice::Text("t".into()))
        .add_reference_triple(ReferenceTriple::new(
            env,
            vec![meas_with_mkey("firmware", 1)],
        ))
        .add_conditional_endorsement(cet)
        .strict_links(true)
        .build();

    match result {
        Err(BuilderError::UnanchoredConditionMeasurement {
            triple_kind,
            triple_index,
            measurement_index,
        }) => {
            assert_eq!(triple_kind, "conditional-endorsement");
            assert_eq!(triple_index, 0);
            assert_eq!(measurement_index, 0);
        }
        other => panic!("expected UnanchoredConditionMeasurement, got {other:?}"),
    }
}

#[test]
fn comid_builder_strict_links_anchor_pool_is_same_env_only() {
    use corim::error::BuilderError;

    // Two reference triples on two different envs. `env_a` has `fw_a`,
    // `env_b` has `fw_b`. The CES condition env is `env_b` but selects
    // on `fw_a` — under S2 (same-env pool) this must fail even though
    // `fw_a` exists somewhere in the CoMID.
    let env_a = EnvironmentMap::for_class("V", "A");
    let env_b = EnvironmentMap::for_class("V", "B");
    let fw_a = meas_with_mkey("fw_a", 1);
    let fw_b = meas_with_mkey("fw_b", 1);

    let ces = ConditionalEndorsementSeriesTriple::new(
        CesCommonCondition {
            environment: env_b.clone(),
            claims_list: vec![fw_a.clone()],
            authorized_by: None,
        },
        vec![ConditionalSeriesRecord::new(
            vec![fw_b.clone()],
            vec![one_measurement(2)],
        )],
    );

    let result = ComidBuilder::new(TagIdChoice::Text("t".into()))
        .add_reference_triple(ReferenceTriple::new(env_a, vec![fw_a]))
        .add_reference_triple(ReferenceTriple::new(env_b, vec![fw_b]))
        .add_conditional_endorsement_series(ces)
        .strict_links(true)
        .build();

    match result {
        Err(BuilderError::UnanchoredConditionMeasurement {
            triple_kind,
            measurement_index,
            ..
        }) => {
            assert_eq!(triple_kind, "conditional-endorsement-series");
            assert_eq!(measurement_index, 0);
        }
        other => panic!("expected UnanchoredConditionMeasurement (same-env pool), got {other:?}"),
    }
}

#[test]
fn comid_builder_default_accepts_unanchored_measurement() {
    // Without strict_links, the lint must not fire even on obvious mismatches.
    let env = EnvironmentMap::for_class("V", "M");
    let ces = ConditionalEndorsementSeriesTriple::new(
        CesCommonCondition {
            environment: env.clone(),
            claims_list: vec![meas_with_mkey("missing", 1)],
            authorized_by: None,
        },
        vec![ConditionalSeriesRecord::new(
            vec![meas_with_mkey("missing", 1)],
            vec![one_measurement(2)],
        )],
    );

    ComidBuilder::new(TagIdChoice::Text("t".into()))
        .add_reference_triple(ReferenceTriple::new(
            env,
            vec![meas_with_mkey("firmware", 1)],
        ))
        .add_conditional_endorsement_series(ces)
        .build()
        .expect("default builder must not enforce measurement anchoring");
}

// ---------------------------------------------------------------------------
// env catalog — declare_env + add_*_for resolution (CURRENTLY FAILING)
// ---------------------------------------------------------------------------

#[test]
fn comid_builder_declare_env_resolves_at_build() {
    let mut b = ComidBuilder::new(TagIdChoice::Text("t".into()));
    let env_cpu = EnvironmentMap::for_class("CPU-CO", "CPU-MD");
    let cpu = b.declare_env("cpu", env_cpu.clone()).expect("declare ok");

    let comid = b
        .add_reference_triple_for(&cpu, vec![one_measurement(7)])
        .build()
        .expect("build should resolve the EnvRef to the inline env");

    let refs = comid
        .triples
        .reference_triples
        .expect("reference_triples should be populated by add_reference_triple_for");
    assert_eq!(refs.len(), 1);
    assert_eq!(&refs[0].0, &env_cpu);
}

#[test]
fn comid_builder_declare_env_rejects_duplicate_label() {
    use corim::error::BuilderError;

    let mut b = ComidBuilder::new(TagIdChoice::Text("t".into()));
    let env_a = EnvironmentMap::for_class("V", "A");
    let env_b = EnvironmentMap::for_class("V", "B");
    b.declare_env("cpu", env_a).expect("first declare ok");
    let err = b
        .declare_env("cpu", env_b)
        .expect_err("second declare with same label must error");
    match err {
        BuilderError::DuplicateEnvLabel { label } => assert_eq!(label, "cpu"),
        other => panic!("expected DuplicateEnvLabel, got {other:?}"),
    }
}

#[test]
fn comid_builder_cross_builder_ref_rejected_at_build() {
    use corim::error::BuilderError;

    let env_cpu = EnvironmentMap::for_class("CPU-CO", "CPU-MD");
    let mut b1 = ComidBuilder::new(TagIdChoice::Text("t1".into()));
    let cpu_from_b1 = b1.declare_env("cpu", env_cpu.clone()).expect("declare ok");

    let b2 = ComidBuilder::new(TagIdChoice::Text("t2".into()))
        .add_reference_triple_for(cpu_from_b1, vec![one_measurement(1)]);

    let err = b2.build().expect_err("cross-builder ref must error");
    match err {
        BuilderError::RefFromOtherBuilder { label } => assert_eq!(label, "cpu"),
        other => panic!("expected RefFromOtherBuilder, got {other:?}"),
    }
}

#[test]
fn comid_builder_strict_links_with_catalog_anchored_passes() {
    let mut b = ComidBuilder::new(TagIdChoice::Text("t".into()));
    let env_cpu = EnvironmentMap::for_class("CPU-CO", "CPU-MD");
    let cpu = b.declare_env("cpu", env_cpu).expect("declare ok");

    b.add_reference_triple_for(&cpu, vec![one_measurement(1)])
        .add_endorsed_triple_for(&cpu, vec![one_measurement(2)])
        .strict_links(true)
        .build()
        .expect("strict_links should accept a ref anchored by a reference triple");
}

#[test]
fn comid_builder_strict_links_with_catalog_unanchored_fails() {
    use corim::error::BuilderError;

    let mut b = ComidBuilder::new(TagIdChoice::Text("t".into()));
    let env_a = EnvironmentMap::for_class("VendorA", "ModelA");
    let env_b = EnvironmentMap::for_class("VendorB", "ModelB");
    let a = b.declare_env("a", env_a).expect("declare ok");
    let bref = b.declare_env("b", env_b).expect("declare ok");

    // Only `a` is in a reference triple; endorsed_for(b) must still fail
    // strict_links because the lint promise is structural anchoring,
    // not catalog presence.
    let err = b
        .add_reference_triple_for(&a, vec![one_measurement(1)])
        .add_endorsed_triple_for(&bref, vec![one_measurement(2)])
        .strict_links(true)
        .build()
        .expect_err("strict_links should fail for an unanchored ref");
    match err {
        BuilderError::UnanchoredConditionEnv { triple_kind, index } => {
            assert_eq!(triple_kind, "endorsed");
            assert_eq!(index, 0);
        }
        other => panic!("expected UnanchoredConditionEnv, got {other:?}"),
    }
}

#[test]
fn comid_builder_dependency_triple_for_resolves_mixed_env_specs() {
    use corim::builder::EnvSpec;

    let mut b = ComidBuilder::new(TagIdChoice::Text("t".into()));
    let env_a = EnvironmentMap::for_class("V", "A");
    let env_b = EnvironmentMap::for_class("V", "B");
    let env_c = EnvironmentMap::for_class("V", "C");
    let a = b.declare_env("a", env_a.clone()).expect("declare ok");
    let c = b.declare_env("c", env_c.clone()).expect("declare ok");

    // Mix one inline env with two refs in the trustees list.
    let comid = b
        .add_reference_triple_for(&a, vec![one_measurement(1)])
        .add_dependency_triple_for(&a, vec![EnvSpec::from(env_b.clone()), EnvSpec::from(&c)])
        .build()
        .expect("build ok");

    let deps = comid
        .triples
        .dependency_triples
        .expect("dependency present");
    assert_eq!(deps.len(), 1);
    assert_eq!(&deps[0].0, &env_a);
    assert_eq!(deps[0].1, vec![env_b, env_c]);
}

#[test]
fn comid_builder_conditional_endorsement_series_for_resolves_ref() {
    let mut b = ComidBuilder::new(TagIdChoice::Text("t".into()));
    let env = EnvironmentMap::for_class("V", "M");
    let env_ref = b.declare_env("platform", env.clone()).expect("declare ok");

    let series = vec![ConditionalSeriesRecord::new(
        vec![one_measurement(1)],
        vec![one_measurement(2)],
    )];

    // Same ref drives both the reference and the CES condition env — this is
    // the by-construction equivalence that the catalog API exists to provide.
    let comid = b
        .add_reference_triple_for(&env_ref, vec![one_measurement(1)])
        .add_conditional_endorsement_series_for(&env_ref, vec![], None, series)
        .strict_links(true)
        .build()
        .expect("build ok");

    let refs = comid.triples.reference_triples.expect("ref present");
    let cess = comid
        .triples
        .conditional_endorsement_series
        .expect("ces present");
    assert_eq!(refs.len(), 1);
    assert_eq!(cess.len(), 1);
    assert_eq!(&refs[0].0, &env);
    assert_eq!(&cess[0].0.environment, &env);
    // Wire-format equivalence: the two envs are structurally identical.
    assert_eq!(&refs[0].0, &cess[0].0.environment);
}

#[test]
fn comid_builder_conditional_endorsement_series_for_inline_env_also_works() {
    let env = EnvironmentMap::for_class("V", "M");
    let comid = ComidBuilder::new(TagIdChoice::Text("t".into()))
        .add_reference_triple_for(env.clone(), vec![one_measurement(1)])
        .add_conditional_endorsement_series_for(
            env,
            vec![one_measurement(7)],
            None,
            vec![ConditionalSeriesRecord::new(
                vec![one_measurement(1)],
                vec![one_measurement(2)],
            )],
        )
        .build()
        .expect("build ok");
    let cess = comid
        .triples
        .conditional_endorsement_series
        .expect("ces present");
    assert_eq!(cess.len(), 1);
    assert_eq!(cess[0].0.claims_list.len(), 1);
}

#[test]
fn comid_builder_conditional_endorsement_for_resolves_refs() {
    use corim::builder::EnvSpec;

    let mut b = ComidBuilder::new(TagIdChoice::Text("t".into()));
    let env_a = EnvironmentMap::for_class("V", "A");
    let env_b = EnvironmentMap::for_class("V", "B");
    let a = b.declare_env("a", env_a.clone()).expect("declare ok");
    // Two stateful-environment-records, one by ref, one inline.
    let comid = b
        .add_reference_triple_for(&a, vec![one_measurement(1)])
        .add_reference_triple_for(env_b.clone(), vec![one_measurement(2)])
        .add_conditional_endorsement_for(
            vec![
                (EnvSpec::from(&a), vec![one_measurement(1)]),
                (EnvSpec::from(env_b.clone()), vec![one_measurement(2)]),
            ],
            vec![EndorsedTriple::new(env_a.clone(), vec![one_measurement(9)])],
        )
        .strict_links(true)
        .build()
        .expect("build ok");

    let ces = comid.triples.conditional_endorsement.expect("ce present");
    assert_eq!(ces.len(), 1);
    assert_eq!(ces[0].0.len(), 2);
    assert_eq!(&ces[0].0[0].0, &env_a);
    assert_eq!(&ces[0].0[1].0, &env_b);
    // Endorsement env preserved as-passed.
    assert_eq!(&ces[0].1[0].0, &env_a);
}

#[test]
fn comid_builder_conditional_endorsement_series_for_rejects_foreign_ref() {
    use corim::error::BuilderError;

    let mut b1 = ComidBuilder::new(TagIdChoice::Text("t1".into()));
    let env = EnvironmentMap::for_class("V", "M");
    let foreign_ref = b1.declare_env("e", env.clone()).expect("declare ok");

    let mut b2 = ComidBuilder::new(TagIdChoice::Text("t2".into()));
    let local = b2.declare_env("e", env.clone()).expect("declare ok");
    let err = b2
        .add_reference_triple_for(&local, vec![one_measurement(1)])
        .add_conditional_endorsement_series_for(
            &foreign_ref,
            vec![],
            None,
            vec![ConditionalSeriesRecord::new(
                vec![one_measurement(1)],
                vec![one_measurement(2)],
            )],
        )
        .build()
        .expect_err("foreign ref must be rejected");
    match err {
        BuilderError::RefFromOtherBuilder { label } => assert_eq!(label, "e"),
        other => panic!("expected RefFromOtherBuilder, got {other:?}"),
    }
}

#[test]
fn comid_builder_conditional_endorsement_for_rejects_foreign_ref() {
    use corim::builder::EnvSpec;
    use corim::error::BuilderError;

    let mut b1 = ComidBuilder::new(TagIdChoice::Text("t1".into()));
    let env = EnvironmentMap::for_class("V", "M");
    let foreign_ref = b1.declare_env("e", env.clone()).expect("declare ok");

    let mut b2 = ComidBuilder::new(TagIdChoice::Text("t2".into()));
    let local = b2.declare_env("e", env.clone()).expect("declare ok");
    let err = b2
        .add_reference_triple_for(&local, vec![one_measurement(1)])
        .add_conditional_endorsement_for(
            vec![(EnvSpec::from(&foreign_ref), vec![one_measurement(1)])],
            vec![EndorsedTriple::new(env, vec![one_measurement(9)])],
        )
        .build()
        .expect_err("foreign ref must be rejected");
    match err {
        BuilderError::RefFromOtherBuilder { label } => assert_eq!(label, "e"),
        other => panic!("expected RefFromOtherBuilder, got {other:?}"),
    }
}
