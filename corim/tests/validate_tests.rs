// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Tests for the `Validate` trait implementations.
//!
//! These tests mirror the validation patterns from the CoRIM specification
//! (e.g., `TestEnvironment_Valid_empty`,
//! `TestTriples_Valid`, etc.).

use corim::types::comid::ComidTag;
use corim::types::common::*;
use corim::types::corim::*;
use corim::types::environment::*;
use corim::types::measurement::*;
use corim::types::triples::*;
use corim::Validate;

// ===========================================================================
// ClassMap validation
// ===========================================================================

#[test]
fn class_map_valid_vendor_model() {
    let c = ClassMap::new("ACME", "Widget");
    assert!(c.valid().is_ok());
}

#[test]
fn class_map_valid_class_id_only() {
    let c = ClassMap {
        class_id: Some(ClassIdChoice::Uuid([0xAA; 16])),
        ..ClassMap::default()
    };
    assert!(c.valid().is_ok());
}

#[test]
fn class_map_empty_is_invalid() {
    let c = ClassMap::default();
    let err = c.valid().unwrap_err();
    assert!(err.contains("class must not be empty"), "got: {err}");
}

// ===========================================================================
// EnvironmentMap validation
// ===========================================================================

#[test]
fn env_valid_with_class() {
    let env = EnvironmentMap::for_class("ACME", "Widget");
    assert!(env.valid().is_ok());
}

#[test]
fn env_valid_with_instance() {
    let env = EnvironmentMap {
        class: None,
        instance: Some(InstanceIdChoice::Uuid([0xBB; 16])),
        group: None,
    };
    assert!(env.valid().is_ok());
}

#[test]
fn env_valid_with_group() {
    let env = EnvironmentMap {
        class: None,
        instance: None,
        group: Some(GroupIdChoice::Uuid([0xCC; 16])),
    };
    assert!(env.valid().is_ok());
}

#[test]
fn env_empty_is_invalid() {
    let env = EnvironmentMap {
        class: None,
        instance: None,
        group: None,
    };
    let err = env.valid().unwrap_err();
    assert!(err.contains("environment must not be empty"), "got: {err}");
}

#[test]
fn env_with_empty_class_is_invalid() {
    let env = EnvironmentMap {
        class: Some(ClassMap::default()),
        instance: None,
        group: None,
    };
    let err = env.valid().unwrap_err();
    assert!(err.contains("class validation failed"), "got: {err}");
}

// ===========================================================================
// MeasurementValuesMap validation
// ===========================================================================

#[test]
fn mval_empty_is_invalid() {
    let mval = MeasurementValuesMap::default();
    let err = mval.valid().unwrap_err();
    assert!(err.contains("no measurement value set"), "got: {err}");
}

#[test]
fn mval_with_digests_is_valid() {
    let mval = MeasurementValuesMap {
        digests: Some(vec![Digest::new(7, vec![0xAA; 32])]),
        ..MeasurementValuesMap::default()
    };
    assert!(mval.valid().is_ok());
}

#[test]
fn mval_with_empty_digests_is_invalid() {
    let mval = MeasurementValuesMap {
        digests: Some(vec![]),
        ..MeasurementValuesMap::default()
    };
    let err = mval.valid().unwrap_err();
    assert!(err.contains("digests list must not be empty"), "got: {err}");
}

#[test]
fn mval_with_svn_is_valid() {
    let mval = MeasurementValuesMap {
        svn: Some(SvnChoice::ExactValue(42)),
        ..MeasurementValuesMap::default()
    };
    assert!(mval.valid().is_ok());
}

#[test]
fn mval_with_version_is_valid() {
    let mval = MeasurementValuesMap {
        version: Some(VersionMap {
            version: "1.0".into(),
            version_scheme: None,
        }),
        ..MeasurementValuesMap::default()
    };
    assert!(mval.valid().is_ok());
}

#[test]
fn mval_with_name_is_valid() {
    let mval = MeasurementValuesMap {
        name: Some("test-component".into()),
        ..MeasurementValuesMap::default()
    };
    assert!(mval.valid().is_ok());
}

// ===========================================================================
// MeasurementMap validation
// ===========================================================================

#[test]
fn measurement_map_valid() {
    let m = MeasurementMap {
        mkey: Some(MeasuredElement::Text("firmware".into())),
        mval: MeasurementValuesMap {
            digests: Some(vec![Digest::new(7, vec![0xAA; 48])]),
            ..MeasurementValuesMap::default()
        },
        authorized_by: None,
    };
    assert!(m.valid().is_ok());
}

#[test]
fn measurement_map_empty_mval_is_invalid() {
    let m = MeasurementMap {
        mkey: None,
        mval: MeasurementValuesMap::default(),
        authorized_by: None,
    };
    let err = m.valid().unwrap_err();
    assert!(err.contains("measurement values"), "got: {err}");
}

// ===========================================================================
// ReferenceTriple validation
// ===========================================================================

#[test]
fn reference_triple_valid() {
    let t = ReferenceTriple::new(
        EnvironmentMap::for_class("ACME", "Widget"),
        vec![MeasurementMap {
            mkey: None,
            mval: MeasurementValuesMap {
                digests: Some(vec![Digest::new(7, vec![0xAA; 32])]),
                ..MeasurementValuesMap::default()
            },
            authorized_by: None,
        }],
    );
    assert!(t.valid().is_ok());
}

#[test]
fn reference_triple_empty_env_is_invalid() {
    let t = ReferenceTriple::new(
        EnvironmentMap {
            class: None,
            instance: None,
            group: None,
        },
        vec![MeasurementMap {
            mkey: None,
            mval: MeasurementValuesMap {
                svn: Some(SvnChoice::ExactValue(1)),
                ..MeasurementValuesMap::default()
            },
            authorized_by: None,
        }],
    );
    let err = t.valid().unwrap_err();
    assert!(err.contains("environment validation failed"), "got: {err}");
}

#[test]
fn reference_triple_empty_measurements_is_invalid() {
    let t = ReferenceTriple::new(EnvironmentMap::for_class("ACME", "Widget"), vec![]);
    let err = t.valid().unwrap_err();
    assert!(err.contains("no measurement entries"), "got: {err}");
}

#[test]
fn reference_triple_invalid_measurement_value() {
    let t = ReferenceTriple::new(
        EnvironmentMap::for_class("ACME", "Widget"),
        vec![MeasurementMap {
            mkey: None,
            mval: MeasurementValuesMap::default(), // empty
            authorized_by: None,
        }],
    );
    let err = t.valid().unwrap_err();
    assert!(err.contains("measurement at index 0"), "got: {err}");
}

// ===========================================================================
// IdentityTriple validation
// ===========================================================================

#[test]
fn identity_triple_valid() {
    let t = IdentityTriple::new(
        EnvironmentMap::for_class("ACME", "Widget"),
        vec![CryptoKey::PkixBase64Key("MIIBIjANBg...".into())],
        None,
    );
    assert!(t.valid().is_ok());
}

#[test]
fn identity_triple_empty_env_is_invalid() {
    let t = IdentityTriple::new(
        EnvironmentMap {
            class: None,
            instance: None,
            group: None,
        },
        vec![CryptoKey::PkixBase64Key("key".into())],
        None,
    );
    let err = t.valid().unwrap_err();
    assert!(err.contains("environment"), "got: {err}");
}

#[test]
fn identity_triple_no_keys_is_invalid() {
    let t = IdentityTriple::new(EnvironmentMap::for_class("X", "Y"), vec![], None);
    let err = t.valid().unwrap_err();
    assert!(err.contains("no keys"), "got: {err}");
}

// ===========================================================================
// DomainDependencyTriple validation
// ===========================================================================

#[test]
fn domain_dependency_valid() {
    let t = DomainDependencyTriple::new(
        EnvironmentMap {
            class: None,
            instance: Some(InstanceIdChoice::Uuid([0xAA; 16])),
            group: None,
        },
        vec![EnvironmentMap {
            class: None,
            instance: Some(InstanceIdChoice::Uuid([0xBB; 16])),
            group: None,
        }],
    );
    assert!(t.valid().is_ok());
}

#[test]
fn domain_dependency_empty_domain_id_is_invalid() {
    let t = DomainDependencyTriple::new(
        EnvironmentMap {
            class: None,
            instance: None,
            group: None,
        },
        vec![EnvironmentMap::for_class("X", "Y")],
    );
    let err = t.valid().unwrap_err();
    assert!(err.contains("domain-id"), "got: {err}");
}

#[test]
fn domain_dependency_no_trustees_is_invalid() {
    let t = DomainDependencyTriple::new(EnvironmentMap::for_class("X", "Y"), vec![]);
    let err = t.valid().unwrap_err();
    assert!(err.contains("at least one trustee"), "got: {err}");
}

#[test]
fn domain_dependency_self_reference_is_invalid() {
    let env = EnvironmentMap::for_class("ACME", "Widget");
    let t = DomainDependencyTriple::new(env.clone(), vec![env]);
    let err = t.valid().unwrap_err();
    assert!(
        err.contains("domain-id must not appear in trustees"),
        "got: {err}"
    );
}

// ===========================================================================
// DomainMembershipTriple validation
// ===========================================================================

#[test]
fn domain_membership_valid() {
    let t = DomainMembershipTriple::new(
        EnvironmentMap::for_class("ACME", "Widget"),
        vec![EnvironmentMap::for_class("ACME", "SubWidget")],
    );
    assert!(t.valid().is_ok());
}

#[test]
fn domain_membership_no_members_is_invalid() {
    let t = DomainMembershipTriple::new(EnvironmentMap::for_class("X", "Y"), vec![]);
    let err = t.valid().unwrap_err();
    assert!(err.contains("at least one member"), "got: {err}");
}

// ===========================================================================
// CoswidTriple validation
// ===========================================================================

#[test]
fn coswid_triple_valid() {
    let t = CoswidTriple::new(
        EnvironmentMap::for_class("ACME", "Widget"),
        vec![TagIdChoice::Text("tag1".into())],
    );
    assert!(t.valid().is_ok());
}

#[test]
fn coswid_triple_empty_tag_ids_is_invalid() {
    let t = CoswidTriple::new(EnvironmentMap::for_class("ACME", "Widget"), vec![]);
    let err = t.valid().unwrap_err();
    assert!(err.contains("at least one CoSWID tag-id"), "got: {err}");
}

// ===========================================================================
// TriplesMap validation
// ===========================================================================

#[test]
fn triples_map_empty_is_invalid() {
    let t = TriplesMap {
        reference_triples: None,
        endorsed_triples: None,
        identity_triples: None,
        attest_key_triples: None,
        dependency_triples: None,
        membership_triples: None,
        coswid_triples: None,
        conditional_endorsement_series: None,
        conditional_endorsement: None,
    };
    let err = t.valid().unwrap_err();
    assert!(
        err.contains("triples struct must not be empty"),
        "got: {err}"
    );
}

#[test]
fn triples_map_with_empty_vecs_is_invalid() {
    let t = TriplesMap {
        reference_triples: Some(vec![]),
        endorsed_triples: Some(vec![]),
        identity_triples: None,
        attest_key_triples: None,
        dependency_triples: None,
        membership_triples: None,
        coswid_triples: None,
        conditional_endorsement_series: None,
        conditional_endorsement: None,
    };
    let err = t.valid().unwrap_err();
    assert!(
        err.contains("triples struct must not be empty"),
        "got: {err}"
    );
}

#[test]
fn triples_map_validates_inner_triples() {
    let bad_ref = ReferenceTriple::new(
        EnvironmentMap {
            class: None,
            instance: None,
            group: None,
        },
        vec![],
    );
    let t = TriplesMap {
        reference_triples: Some(vec![bad_ref]),
        endorsed_triples: None,
        identity_triples: None,
        attest_key_triples: None,
        dependency_triples: None,
        membership_triples: None,
        coswid_triples: None,
        conditional_endorsement_series: None,
        conditional_endorsement: None,
    };
    let err = t.valid().unwrap_err();
    assert!(err.contains("reference value at index 0"), "got: {err}");
}

// ===========================================================================
// ComidTag validation
// ===========================================================================

#[test]
fn comid_tag_valid() {
    let comid = ComidTag {
        language: None,
        tag_identity: TagIdentity {
            tag_id: TagIdChoice::Text("test-tag".into()),
            tag_version: None,
        },
        entities: None,
        linked_tags: None,
        triples: TriplesMap {
            reference_triples: Some(vec![ReferenceTriple::new(
                EnvironmentMap::for_class("ACME", "Widget"),
                vec![MeasurementMap {
                    mkey: None,
                    mval: MeasurementValuesMap {
                        svn: Some(SvnChoice::ExactValue(1)),
                        ..MeasurementValuesMap::default()
                    },
                    authorized_by: None,
                }],
            )]),
            endorsed_triples: None,
            identity_triples: None,
            attest_key_triples: None,
            dependency_triples: None,
            membership_triples: None,
            coswid_triples: None,
            conditional_endorsement_series: None,
            conditional_endorsement: None,
        },
    };
    assert!(comid.valid().is_ok());
}

#[test]
fn comid_tag_empty_triples_is_invalid() {
    let comid = ComidTag {
        language: None,
        tag_identity: TagIdentity {
            tag_id: TagIdChoice::Text("test-tag".into()),
            tag_version: None,
        },
        entities: None,
        linked_tags: None,
        triples: TriplesMap {
            reference_triples: None,
            endorsed_triples: None,
            identity_triples: None,
            attest_key_triples: None,
            dependency_triples: None,
            membership_triples: None,
            coswid_triples: None,
            conditional_endorsement_series: None,
            conditional_endorsement: None,
        },
    };
    let err = comid.valid().unwrap_err();
    assert!(err.contains("triples validation failed"), "got: {err}");
}

// ===========================================================================
// ConciseTlTag validation
// ===========================================================================

#[test]
fn cotl_valid() {
    let cotl = ConciseTlTag {
        tag_identity: TagIdentity {
            tag_id: TagIdChoice::Text("tl-1".into()),
            tag_version: None,
        },
        tags_list: vec![TagIdentity {
            tag_id: TagIdChoice::Text("comid-1".into()),
            tag_version: None,
        }],
        tl_validity: ValidityMap {
            not_before: Some(CborTime::new(1000)),
            not_after: CborTime::new(2000),
        },
    };
    assert!(cotl.valid().is_ok());
}

#[test]
fn cotl_empty_tags_list_is_invalid() {
    let cotl = ConciseTlTag {
        tag_identity: TagIdentity {
            tag_id: TagIdChoice::Text("tl-1".into()),
            tag_version: None,
        },
        tags_list: vec![],
        tl_validity: ValidityMap {
            not_before: None,
            not_after: CborTime::new(2000),
        },
    };
    let err = cotl.valid().unwrap_err();
    assert!(err.contains("tags-list must not be empty"), "got: {err}");
}

#[test]
fn cotl_not_before_after_not_after_is_invalid() {
    let cotl = ConciseTlTag {
        tag_identity: TagIdentity {
            tag_id: TagIdChoice::Text("tl-1".into()),
            tag_version: None,
        },
        tags_list: vec![TagIdentity {
            tag_id: TagIdChoice::Text("comid-1".into()),
            tag_version: None,
        }],
        tl_validity: ValidityMap {
            not_before: Some(CborTime::new(3000)),
            not_after: CborTime::new(2000),
        },
    };
    let err = cotl.valid().unwrap_err();
    assert!(
        err.contains("not-before must be <= not-after"),
        "got: {err}"
    );
}

// ===========================================================================
// CorimMap validation
// ===========================================================================

#[test]
fn corim_map_valid() {
    let corim = CorimMap {
        id: CorimId::Text("test-corim".into()),
        tags: vec![ConciseTagChoice::Comid(vec![0xA0])],
        dependent_rims: None,
        profile: None,
        rim_validity: None,
        entities: None,
    };
    assert!(corim.valid().is_ok());
}

#[test]
fn corim_map_empty_tags_is_invalid() {
    let corim = CorimMap {
        id: CorimId::Text("test-corim".into()),
        tags: vec![],
        dependent_rims: None,
        profile: None,
        rim_validity: None,
        entities: None,
    };
    let err = corim.valid().unwrap_err();
    assert!(err.contains("tags list must not be empty"), "got: {err}");
}

#[test]
fn corim_map_invalid_validity() {
    let corim = CorimMap {
        id: CorimId::Text("test-corim".into()),
        tags: vec![ConciseTagChoice::Comid(vec![0xA0])],
        dependent_rims: None,
        profile: None,
        rim_validity: Some(ValidityMap {
            not_before: Some(CborTime::new(3000)),
            not_after: CborTime::new(2000),
        }),
        entities: None,
    };
    let err = corim.valid().unwrap_err();
    assert!(
        err.contains("not-before must be <= not-after"),
        "got: {err}"
    );
}

// ===========================================================================
// ConditionalEndorsementTriple validation
// ===========================================================================

#[test]
fn conditional_endorsement_triple_valid() {
    let env = EnvironmentMap::for_class("ACME", "Widget");
    let meas = vec![MeasurementMap {
        mkey: None,
        mval: MeasurementValuesMap {
            svn: Some(SvnChoice::ExactValue(1)),
            ..MeasurementValuesMap::default()
        },
        authorized_by: None,
    }];
    let t = ConditionalEndorsementTriple(
        vec![StatefulEnvironmentRecord(env.clone(), meas.clone())],
        vec![EndorsedTriple::new(env, meas)],
    );
    assert!(t.valid().is_ok());
}

#[test]
fn conditional_endorsement_triple_empty_conditions_is_invalid() {
    let env = EnvironmentMap::for_class("ACME", "Widget");
    let meas = vec![MeasurementMap {
        mkey: None,
        mval: MeasurementValuesMap {
            svn: Some(SvnChoice::ExactValue(1)),
            ..MeasurementValuesMap::default()
        },
        authorized_by: None,
    }];
    let t = ConditionalEndorsementTriple(vec![], vec![EndorsedTriple::new(env, meas)]);
    let err = t.valid().unwrap_err();
    assert!(err.contains("conditions must not be empty"), "got: {err}");
}

// ===========================================================================
// StatefulEnvironmentRecord validation
// ===========================================================================

#[test]
fn stateful_env_record_valid() {
    let r = StatefulEnvironmentRecord(
        EnvironmentMap::for_class("ACME", "Widget"),
        vec![MeasurementMap {
            mkey: None,
            mval: MeasurementValuesMap {
                svn: Some(SvnChoice::ExactValue(1)),
                ..MeasurementValuesMap::default()
            },
            authorized_by: None,
        }],
    );
    assert!(r.valid().is_ok());
}

#[test]
fn stateful_env_record_empty_env_is_invalid() {
    let r = StatefulEnvironmentRecord(
        EnvironmentMap {
            class: None,
            instance: None,
            group: None,
        },
        vec![MeasurementMap {
            mkey: None,
            mval: MeasurementValuesMap {
                svn: Some(SvnChoice::ExactValue(1)),
                ..MeasurementValuesMap::default()
            },
            authorized_by: None,
        }],
    );
    let err = r.valid().unwrap_err();
    assert!(err.contains("environment"), "got: {err}");
}

#[test]
fn stateful_env_record_empty_measurements_is_invalid() {
    let r = StatefulEnvironmentRecord(EnvironmentMap::for_class("ACME", "Widget"), vec![]);
    let err = r.valid().unwrap_err();
    assert!(err.contains("measurements must not be empty"), "got: {err}");
}

// ===========================================================================
// Triple-level Validate impls
// ===========================================================================

#[test]
fn endorsed_triple_empty_env_invalid() {
    let t = EndorsedTriple::new(
        EnvironmentMap {
            class: None,
            instance: None,
            group: None,
        },
        vec![MeasurementMap {
            mkey: None,
            mval: MeasurementValuesMap {
                svn: Some(SvnChoice::ExactValue(1)),
                ..MeasurementValuesMap::default()
            },
            authorized_by: None,
        }],
    );
    let err = t.valid().unwrap_err();
    assert!(err.contains("environment"), "got: {err}");
}

#[test]
fn endorsed_triple_empty_measurements_invalid() {
    let t = EndorsedTriple::new(EnvironmentMap::for_class("A", "B"), vec![]);
    let err = t.valid().unwrap_err();
    assert!(err.contains("no measurement entries"), "got: {err}");
}

#[test]
fn endorsed_triple_invalid_measurement_invalid() {
    let t = EndorsedTriple::new(
        EnvironmentMap::for_class("A", "B"),
        vec![MeasurementMap {
            mkey: None,
            mval: MeasurementValuesMap::default(),
            authorized_by: None,
        }],
    );
    let err = t.valid().unwrap_err();
    assert!(err.contains("measurement at index 0"), "got: {err}");
}

#[test]
fn attest_key_triple_valid_minimal() {
    let t = AttestKeyTriple::new(
        EnvironmentMap::for_class("V", "M"),
        vec![CryptoKey::PkixBase64Key("key".into())],
        None,
    );
    assert!(t.valid().is_ok());
}

#[test]
fn domain_membership_invalid_member_env() {
    let t = DomainMembershipTriple::new(
        EnvironmentMap::for_class("X", "Y"),
        vec![EnvironmentMap {
            class: None,
            instance: None,
            group: None,
        }],
    );
    let err = t.valid().unwrap_err();
    assert!(err.contains("member at index 0"), "got: {err}");
}

#[test]
fn domain_dependency_invalid_trustee_env() {
    let t = DomainDependencyTriple::new(
        EnvironmentMap::for_class("X", "Y"),
        vec![EnvironmentMap {
            class: None,
            instance: None,
            group: None,
        }],
    );
    let err = t.valid().unwrap_err();
    assert!(err.contains("trustee at index 0"), "got: {err}");
}

#[test]
fn conditional_endorsement_triple_invalid_condition() {
    let env = EnvironmentMap::for_class("A", "B");
    let meas = vec![MeasurementMap {
        mkey: None,
        mval: MeasurementValuesMap {
            svn: Some(SvnChoice::ExactValue(1)),
            ..MeasurementValuesMap::default()
        },
        authorized_by: None,
    }];
    let t = ConditionalEndorsementTriple(
        vec![StatefulEnvironmentRecord(
            EnvironmentMap {
                class: None,
                instance: None,
                group: None,
            },
            meas.clone(),
        )],
        vec![EndorsedTriple::new(env, meas)],
    );
    let err = t.valid().unwrap_err();
    assert!(err.contains("condition at index 0"), "got: {err}");
}

#[test]
fn conditional_endorsement_triple_empty_endorsements() {
    let env = EnvironmentMap::for_class("A", "B");
    let meas = vec![MeasurementMap {
        mkey: None,
        mval: MeasurementValuesMap {
            svn: Some(SvnChoice::ExactValue(1)),
            ..MeasurementValuesMap::default()
        },
        authorized_by: None,
    }];
    let t = ConditionalEndorsementTriple(vec![StatefulEnvironmentRecord(env, meas)], vec![]);
    let err = t.valid().unwrap_err();
    assert!(err.contains("endorsements must not be empty"), "got: {err}");
}

#[test]
fn conditional_endorsement_triple_invalid_endorsement() {
    let env = EnvironmentMap::for_class("A", "B");
    let meas = vec![MeasurementMap {
        mkey: None,
        mval: MeasurementValuesMap {
            svn: Some(SvnChoice::ExactValue(1)),
            ..MeasurementValuesMap::default()
        },
        authorized_by: None,
    }];
    let bad = EndorsedTriple::new(
        EnvironmentMap {
            class: None,
            instance: None,
            group: None,
        },
        meas.clone(),
    );
    let t = ConditionalEndorsementTriple(vec![StatefulEnvironmentRecord(env, meas)], vec![bad]);
    let err = t.valid().unwrap_err();
    assert!(err.contains("endorsement at index 0"), "got: {err}");
}

// ===========================================================================
// TriplesMap delegates per-triple Validate
// ===========================================================================

fn empty_env() -> EnvironmentMap {
    EnvironmentMap {
        class: None,
        instance: None,
        group: None,
    }
}

#[test]
fn triples_map_validates_endorsed_triples() {
    let t = TriplesMap {
        reference_triples: None,
        endorsed_triples: Some(vec![EndorsedTriple::new(empty_env(), vec![])]),
        identity_triples: None,
        attest_key_triples: None,
        dependency_triples: None,
        membership_triples: None,
        coswid_triples: None,
        conditional_endorsement_series: None,
        conditional_endorsement: None,
    };
    let err = t.valid().unwrap_err();
    assert!(err.contains("endorsed value at index 0"), "got: {err}");
}

#[test]
fn triples_map_validates_identity_triples() {
    let t = TriplesMap {
        reference_triples: None,
        endorsed_triples: None,
        identity_triples: Some(vec![IdentityTriple::new(
            empty_env(),
            vec![CryptoKey::PkixBase64Key("k".into())],
            None,
        )]),
        attest_key_triples: None,
        dependency_triples: None,
        membership_triples: None,
        coswid_triples: None,
        conditional_endorsement_series: None,
        conditional_endorsement: None,
    };
    let err = t.valid().unwrap_err();
    assert!(err.contains("identity triple at index 0"), "got: {err}");
}

#[test]
fn triples_map_validates_attest_key_triples() {
    let t = TriplesMap {
        reference_triples: None,
        endorsed_triples: None,
        identity_triples: None,
        attest_key_triples: Some(vec![AttestKeyTriple::new(
            empty_env(),
            vec![CryptoKey::PkixBase64Key("k".into())],
            None,
        )]),
        dependency_triples: None,
        membership_triples: None,
        coswid_triples: None,
        conditional_endorsement_series: None,
        conditional_endorsement: None,
    };
    let err = t.valid().unwrap_err();
    assert!(err.contains("attest-key triple at index 0"), "got: {err}");
}

#[test]
fn triples_map_validates_dependency_triples() {
    let t = TriplesMap {
        reference_triples: None,
        endorsed_triples: None,
        identity_triples: None,
        attest_key_triples: None,
        dependency_triples: Some(vec![DomainDependencyTriple::new(
            empty_env(),
            vec![EnvironmentMap::for_class("X", "Y")],
        )]),
        membership_triples: None,
        coswid_triples: None,
        conditional_endorsement_series: None,
        conditional_endorsement: None,
    };
    let err = t.valid().unwrap_err();
    assert!(err.contains("dependency triple at index 0"), "got: {err}");
}

#[test]
fn triples_map_validates_membership_triples() {
    let t = TriplesMap {
        reference_triples: None,
        endorsed_triples: None,
        identity_triples: None,
        attest_key_triples: None,
        dependency_triples: None,
        membership_triples: Some(vec![DomainMembershipTriple::new(
            empty_env(),
            vec![EnvironmentMap::for_class("X", "Y")],
        )]),
        coswid_triples: None,
        conditional_endorsement_series: None,
        conditional_endorsement: None,
    };
    let err = t.valid().unwrap_err();
    assert!(err.contains("membership triple at index 0"), "got: {err}");
}

// ===========================================================================
// ComidTag — reject empty optional vec fields
// ===========================================================================

fn one_ref_triple_for_comid() -> TriplesMap {
    TriplesMap {
        reference_triples: Some(vec![ReferenceTriple::new(
            EnvironmentMap::for_class("V", "M"),
            vec![MeasurementMap {
                mkey: None,
                mval: MeasurementValuesMap {
                    svn: Some(SvnChoice::ExactValue(1)),
                    ..MeasurementValuesMap::default()
                },
                authorized_by: None,
            }],
        )]),
        endorsed_triples: None,
        identity_triples: None,
        attest_key_triples: None,
        dependency_triples: None,
        membership_triples: None,
        coswid_triples: None,
        conditional_endorsement_series: None,
        conditional_endorsement: None,
    }
}

#[test]
fn comid_tag_empty_entities_invalid() {
    let comid = ComidTag {
        language: None,
        tag_identity: TagIdentity {
            tag_id: TagIdChoice::Text("t".into()),
            tag_version: None,
        },
        entities: Some(vec![]),
        linked_tags: None,
        triples: one_ref_triple_for_comid(),
    };
    let err = comid.valid().unwrap_err();
    assert!(err.contains("entities"), "got: {err}");
}

#[test]
fn comid_tag_empty_linked_tags_invalid() {
    let comid = ComidTag {
        language: None,
        tag_identity: TagIdentity {
            tag_id: TagIdChoice::Text("t".into()),
            tag_version: None,
        },
        entities: None,
        linked_tags: Some(vec![]),
        triples: one_ref_triple_for_comid(),
    };
    let err = comid.valid().unwrap_err();
    assert!(err.contains("linked-tags"), "got: {err}");
}

// ===========================================================================
// TagIdentity helper
// ===========================================================================

#[test]
fn tag_identity_version_or_default() {
    let tid = TagIdentity {
        tag_id: TagIdChoice::Text("x".into()),
        tag_version: None,
    };
    assert_eq!(tid.tag_version_or_default(), 0);

    let tid2 = TagIdentity {
        tag_id: TagIdChoice::Text("x".into()),
        tag_version: Some(5),
    };
    assert_eq!(tid2.tag_version_or_default(), 5);
}

// ===========================================================================
// validate.rs — match_reference_values: no-match paths
// ===========================================================================

fn one_meas_with_svn(svn: u64) -> Vec<MeasurementMap> {
    vec![MeasurementMap {
        mkey: None,
        mval: MeasurementValuesMap {
            svn: Some(SvnChoice::ExactValue(svn)),
            ..Default::default()
        },
        authorized_by: None,
    }]
}

#[test]
fn match_reference_values_no_env_match() {
    let ref_triple = ReferenceTriple::new(
        EnvironmentMap::for_class("ACME", "Widget"),
        one_meas_with_svn(1),
    );
    let evidence = vec![corim::validate::EvidenceClaim {
        environment: EnvironmentMap::for_class("OTHER", "Thing"),
        measurements: one_meas_with_svn(1),
    }];
    assert!(corim::validate::match_reference_values(&[ref_triple], &evidence).is_empty());
}

#[test]
fn match_reference_values_no_measurement_match() {
    let env = EnvironmentMap::for_class("ACME", "Widget");
    let ref_triple = ReferenceTriple::new(
        env.clone(),
        vec![MeasurementMap {
            mkey: Some(MeasuredElement::Uint(99)),
            mval: MeasurementValuesMap {
                svn: Some(SvnChoice::ExactValue(1)),
                ..Default::default()
            },
            authorized_by: None,
        }],
    );
    let evidence = vec![corim::validate::EvidenceClaim {
        environment: env,
        measurements: vec![MeasurementMap {
            mkey: Some(MeasuredElement::Uint(1)),
            mval: MeasurementValuesMap {
                svn: Some(SvnChoice::ExactValue(1)),
                ..Default::default()
            },
            authorized_by: None,
        }],
    }];
    assert!(corim::validate::match_reference_values(&[ref_triple], &evidence).is_empty());
}

#[test]
fn match_reference_values_digest_mismatch_same_alg() {
    let env = EnvironmentMap::for_class("V", "M");
    let ref_triple = ReferenceTriple::new(
        env.clone(),
        vec![MeasurementMap {
            mkey: None,
            mval: MeasurementValuesMap {
                digests: Some(vec![Digest::new(7, vec![0xAA; 32])]),
                ..Default::default()
            },
            authorized_by: None,
        }],
    );
    let evidence = vec![corim::validate::EvidenceClaim {
        environment: env,
        measurements: vec![MeasurementMap {
            mkey: None,
            mval: MeasurementValuesMap {
                digests: Some(vec![Digest::new(7, vec![0xBB; 32])]),
                ..Default::default()
            },
            authorized_by: None,
        }],
    }];
    assert!(corim::validate::match_reference_values(&[ref_triple], &evidence).is_empty());
}

#[test]
fn match_reference_evidence_lacks_digests() {
    let env = EnvironmentMap::for_class("V", "M");
    let ref_triple = ReferenceTriple::new(
        env.clone(),
        vec![MeasurementMap {
            mkey: None,
            mval: MeasurementValuesMap {
                digests: Some(vec![Digest::new(7, vec![0xAA; 32])]),
                ..Default::default()
            },
            authorized_by: None,
        }],
    );
    let evidence = vec![corim::validate::EvidenceClaim {
        environment: env,
        measurements: one_meas_with_svn(1),
    }];
    assert!(corim::validate::match_reference_values(&[ref_triple], &evidence).is_empty());
}

#[test]
fn match_reference_evidence_lacks_svn() {
    let env = EnvironmentMap::for_class("V", "M");
    let ref_triple = ReferenceTriple::new(env.clone(), one_meas_with_svn(5));
    let evidence = vec![corim::validate::EvidenceClaim {
        environment: env,
        measurements: vec![MeasurementMap {
            mkey: None,
            mval: MeasurementValuesMap {
                digests: Some(vec![Digest::new(7, vec![0xAA; 32])]),
                ..Default::default()
            },
            authorized_by: None,
        }],
    }];
    assert!(corim::validate::match_reference_values(&[ref_triple], &evidence).is_empty());
}

// ===========================================================================
// validate.rs — apply_endorsement_series: no-match paths
// ===========================================================================

#[test]
fn apply_endorsement_series_no_env_match() {
    let ces = ConditionalEndorsementSeriesTriple::new(
        CesCondition {
            environment: EnvironmentMap::for_class("ACME", "Widget"),
            claims_list: vec![],
            authorized_by: None,
        },
        vec![ConditionalSeriesRecord::new(
            one_meas_with_svn(1),
            vec![MeasurementMap {
                mkey: None,
                mval: MeasurementValuesMap {
                    name: Some("endorsed".into()),
                    ..Default::default()
                },
                authorized_by: None,
            }],
        )],
    );
    let evidence = vec![corim::validate::EvidenceClaim {
        environment: EnvironmentMap::for_class("OTHER", "Thing"),
        measurements: vec![],
    }];
    assert!(corim::validate::apply_endorsement_series(&[ces], &evidence)
        .unwrap()
        .is_empty());
}

#[test]
fn apply_endorsement_series_no_selection_match() {
    let env = EnvironmentMap::for_class("V", "M");
    let ces = ConditionalEndorsementSeriesTriple::new(
        CesCondition {
            environment: env.clone(),
            claims_list: vec![],
            authorized_by: None,
        },
        vec![ConditionalSeriesRecord::new(
            vec![MeasurementMap {
                mkey: Some(MeasuredElement::Uint(99)),
                mval: MeasurementValuesMap {
                    svn: Some(SvnChoice::ExactValue(100)),
                    ..Default::default()
                },
                authorized_by: None,
            }],
            vec![MeasurementMap {
                mkey: None,
                mval: MeasurementValuesMap {
                    name: Some("e".into()),
                    ..Default::default()
                },
                authorized_by: None,
            }],
        )],
    );
    let evidence = vec![corim::validate::EvidenceClaim {
        environment: env,
        measurements: vec![MeasurementMap {
            mkey: Some(MeasuredElement::Uint(1)),
            mval: MeasurementValuesMap {
                svn: Some(SvnChoice::ExactValue(1)),
                ..Default::default()
            },
            authorized_by: None,
        }],
    }];
    assert!(corim::validate::apply_endorsement_series(&[ces], &evidence)
        .unwrap()
        .is_empty());
}

#[test]
fn appraisal_context_records_endorsement_phase_entries() {
    let env = EnvironmentMap::for_class("V", "M");
    let meas_sel = vec![MeasurementMap {
        mkey: Some(MeasuredElement::Uint(1)),
        mval: MeasurementValuesMap {
            svn: Some(SvnChoice::ExactValue(1)),
            ..Default::default()
        },
        authorized_by: None,
    }];
    let meas_add = vec![MeasurementMap {
        mkey: None,
        mval: MeasurementValuesMap {
            name: Some("endorsed-value".into()),
            ..Default::default()
        },
        authorized_by: None,
    }];
    let ces = ConditionalEndorsementSeriesTriple::new(
        CesCondition {
            environment: env.clone(),
            claims_list: vec![],
            authorized_by: None,
        },
        vec![ConditionalSeriesRecord::new(meas_sel.clone(), meas_add)],
    );
    let mut ctx = corim::validate::AppraisalContext::new();
    ctx.add_evidence(vec![corim::validate::EvidenceClaim {
        environment: env,
        measurements: meas_sel,
    }]);
    let endorsed = ctx.apply_conditional_endorsements(&[ces]).unwrap();
    assert_eq!(endorsed.len(), 1);
    assert!(ctx
        .entries
        .iter()
        .any(|e| e.claim_type == corim::validate::ClaimType::Endorsement));
}

// ===========================================================================
// CesCondition + triple accessors (round-trip & getters)
// ===========================================================================

#[test]
fn ces_condition_round_trip_with_authorized_by() {
    let cond = CesCondition {
        environment: EnvironmentMap::for_class("V", "M"),
        claims_list: vec![MeasurementMap {
            mkey: None,
            mval: MeasurementValuesMap {
                svn: Some(SvnChoice::ExactValue(1)),
                ..Default::default()
            },
            authorized_by: None,
        }],
        authorized_by: Some(vec![CryptoKey::PkixBase64Key("key".into())]),
    };
    let bytes = corim::cbor::encode(&cond).unwrap();
    let decoded: CesCondition = corim::cbor::decode(&bytes).unwrap();
    assert!(decoded.authorized_by.is_some());
    assert_eq!(decoded.claims_list.len(), 1);
}

#[test]
fn ces_condition_round_trip_without_authorized_by() {
    let cond = CesCondition {
        environment: EnvironmentMap::for_class("V", "M"),
        claims_list: vec![],
        authorized_by: None,
    };
    let bytes = corim::cbor::encode(&cond).unwrap();
    let decoded: CesCondition = corim::cbor::decode(&bytes).unwrap();
    assert!(decoded.authorized_by.is_none());
}

#[test]
fn ces_triple_accessor_methods() {
    let env = EnvironmentMap::for_class("V", "M");
    let meas = vec![MeasurementMap {
        mkey: Some(MeasuredElement::Uint(1)),
        mval: MeasurementValuesMap {
            svn: Some(SvnChoice::ExactValue(1)),
            ..Default::default()
        },
        authorized_by: None,
    }];
    let record = ConditionalSeriesRecord::new(meas.clone(), meas.clone());
    assert_eq!(record.selection().len(), 1);
    assert_eq!(record.addition().len(), 1);

    let cond = CesCondition {
        environment: env.clone(),
        claims_list: vec![],
        authorized_by: None,
    };
    let ces = ConditionalEndorsementSeriesTriple::new(cond, vec![record]);
    assert_eq!(ces.condition().environment, env);
    assert_eq!(ces.series().len(), 1);
}

#[test]
fn endorsed_triple_accessor_methods() {
    let env = EnvironmentMap::for_class("V", "M");
    let meas = one_meas_with_svn(1);
    let t = EndorsedTriple::new(env.clone(), meas);
    assert_eq!(*t.condition(), env);
    assert_eq!(t.endorsement().len(), 1);
}

#[test]
fn reference_triple_accessor_methods() {
    let env = EnvironmentMap::for_class("V", "M");
    let meas = one_meas_with_svn(1);
    let t = ReferenceTriple::new(env.clone(), meas);
    assert_eq!(*t.environment(), env);
    assert_eq!(t.measurements().len(), 1);
}

#[test]
fn coswid_triple_accessor_methods() {
    let t = CoswidTriple::new(
        EnvironmentMap::for_class("V", "M"),
        vec![TagIdChoice::Text("t".into())],
    );
    assert_eq!(
        t.environment().class.as_ref().unwrap().vendor.as_deref(),
        Some("V")
    );
    assert_eq!(t.tag_ids().len(), 1);
}

#[test]
fn identity_triple_accessor_methods() {
    let t = IdentityTriple::new(
        EnvironmentMap::for_class("V", "M"),
        vec![CryptoKey::PkixBase64Key("k".into())],
        Some(KeyTripleConditions {
            mkey: Some(MeasuredElement::Uint(1)),
            authorized_by: None,
        }),
    );
    assert!(t.conditions().is_some());
    assert_eq!(t.keys().len(), 1);
    assert_eq!(*t.environment(), EnvironmentMap::for_class("V", "M"));
}

#[test]
fn attest_key_triple_accessor_methods() {
    let t = AttestKeyTriple::new(
        EnvironmentMap::for_class("V", "M"),
        vec![CryptoKey::PkixBase64Key("k".into())],
        None,
    );
    assert!(t.conditions().is_none());
    assert_eq!(t.keys().len(), 1);
}

#[test]
fn domain_dependency_accessor_methods() {
    let t = DomainDependencyTriple::new(
        EnvironmentMap::for_class("V", "M"),
        vec![EnvironmentMap::for_class("A", "B")],
    );
    assert_eq!(*t.domain_id(), EnvironmentMap::for_class("V", "M"));
    assert_eq!(t.trustees().len(), 1);
}

#[test]
fn domain_membership_accessor_methods() {
    let t = DomainMembershipTriple::new(
        EnvironmentMap::for_class("V", "M"),
        vec![EnvironmentMap::for_class("A", "B")],
    );
    assert_eq!(*t.domain_id(), EnvironmentMap::for_class("V", "M"));
    assert_eq!(t.members().len(), 1);
}
