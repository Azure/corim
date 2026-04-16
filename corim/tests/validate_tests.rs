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
