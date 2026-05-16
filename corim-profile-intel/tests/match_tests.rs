// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Integration tests for `IntelProfile::match_measurement`, exercised
//! through `corim::validate::match_reference_values_with_profile` so
//! the dispatch contract is also covered.

use std::collections::BTreeMap;

use corim::cbor::value::Value;
use corim::profile::Profile;
use corim::types::common::MeasuredElement;
use corim::types::environment::{ClassMap, EnvironmentMap};
use corim::types::measurement::{Digest, MeasurementMap, MeasurementValuesMap};
use corim::types::triples::ReferenceTriple;
use corim::validate::{match_reference_values, match_reference_values_with_profile, EvidenceClaim};

use corim_profile_intel::{
    IntelProfile, MVAL_TEE_ADVISORY_IDS, MVAL_TEE_ATTRIBUTES, MVAL_TEE_EPOCH, MVAL_TEE_ISVSVN,
    MVAL_TEE_MRTEE, MVAL_TEE_TCBSTATUS, MVAL_TEE_VENDOR, TAG_INTEL_EXPRESSION,
};

// --- helpers ---------------------------------------------------------------

fn env() -> EnvironmentMap {
    EnvironmentMap {
        class: Some(ClassMap::new("Intel", "TDX")),
        instance: None,
        group: None,
    }
}

fn ref_triple_with_extras(extras: BTreeMap<i64, Value>) -> ReferenceTriple {
    ReferenceTriple::new(
        env(),
        vec![MeasurementMap {
            mkey: None,
            mval: MeasurementValuesMap {
                extra_entries: extras,
                ..Default::default()
            },
            authorized_by: None,
        }],
    )
}

fn evidence_with_extras(extras: BTreeMap<i64, Value>) -> Vec<EvidenceClaim> {
    vec![EvidenceClaim {
        environment: env(),
        measurements: vec![MeasurementMap {
            mkey: None,
            mval: MeasurementValuesMap {
                extra_entries: extras,
                ..Default::default()
            },
            authorized_by: None,
        }],
    }]
}

fn expr_tag(body: Value) -> Value {
    Value::Tag(TAG_INTEL_EXPRESSION, Box::new(body))
}

// --- Profile::match_measurement direct -------------------------------------

#[test]
fn match_measurement_returns_none_when_reference_has_no_intel_keys() {
    let p = IntelProfile::new();
    // Reference has only a standard key (11: name) in mval.
    let r = MeasurementMap {
        mkey: None,
        mval: MeasurementValuesMap {
            name: Some("x".into()),
            ..Default::default()
        },
        authorized_by: None,
    };
    let e = r.clone();
    assert_eq!(p.match_measurement(&r, &e), None);
}

#[test]
fn match_measurement_returns_some_false_when_evidence_missing_intel_key() {
    let p = IntelProfile::new();
    let mut r_extras = BTreeMap::new();
    r_extras.insert(MVAL_TEE_VENDOR, Value::Text("Intel".into()));
    let r_triple = ref_triple_with_extras(r_extras);
    let r = r_triple.measurements()[0].clone();

    // Evidence has the same structural shape but no Intel extras.
    let e = MeasurementMap {
        mkey: None,
        mval: MeasurementValuesMap::default(),
        authorized_by: None,
    };
    assert_eq!(p.match_measurement(&r, &e), Some(false));
}

#[test]
fn match_measurement_some_true_when_bare_intel_equal_and_core_matches() {
    let p = IntelProfile::new();
    let mut extras = BTreeMap::new();
    extras.insert(MVAL_TEE_VENDOR, Value::Text("Intel".into()));
    let r_triple = ref_triple_with_extras(extras.clone());
    let r = r_triple.measurements()[0].clone();

    let e = MeasurementMap {
        mkey: None,
        mval: MeasurementValuesMap {
            extra_entries: extras,
            ..Default::default()
        },
        authorized_by: None,
    };
    assert_eq!(p.match_measurement(&r, &e), Some(true));
}

#[test]
fn match_measurement_some_false_when_bare_intel_unequal() {
    let p = IntelProfile::new();
    let mut r_extras = BTreeMap::new();
    r_extras.insert(MVAL_TEE_VENDOR, Value::Text("Intel".into()));
    let r_triple = ref_triple_with_extras(r_extras);
    let r = r_triple.measurements()[0].clone();

    let mut e_extras = BTreeMap::new();
    e_extras.insert(MVAL_TEE_VENDOR, Value::Text("AMD".into()));
    let e = MeasurementMap {
        mkey: None,
        mval: MeasurementValuesMap {
            extra_entries: e_extras,
            ..Default::default()
        },
        authorized_by: None,
    };
    assert_eq!(p.match_measurement(&r, &e), Some(false));
}

#[test]
fn match_measurement_some_true_when_numeric_ge_satisfied() {
    let p = IntelProfile::new();
    // Reference: tee.isvsvn >= 5
    let mut r_extras = BTreeMap::new();
    r_extras.insert(
        MVAL_TEE_ISVSVN,
        expr_tag(Value::Array(vec![Value::Integer(2), Value::Integer(5)])),
    );
    let r_triple = ref_triple_with_extras(r_extras);
    let r = r_triple.measurements()[0].clone();

    // Evidence: tee.isvsvn = 7  → passes ge 5.
    let mut e_extras = BTreeMap::new();
    e_extras.insert(MVAL_TEE_ISVSVN, Value::Integer(7));
    let e = MeasurementMap {
        mkey: None,
        mval: MeasurementValuesMap {
            extra_entries: e_extras,
            ..Default::default()
        },
        authorized_by: None,
    };
    assert_eq!(p.match_measurement(&r, &e), Some(true));
}

#[test]
fn match_measurement_some_false_when_numeric_ge_violated() {
    let p = IntelProfile::new();
    let mut r_extras = BTreeMap::new();
    r_extras.insert(
        MVAL_TEE_ISVSVN,
        expr_tag(Value::Array(vec![Value::Integer(2), Value::Integer(5)])),
    );
    let r_triple = ref_triple_with_extras(r_extras);
    let r = r_triple.measurements()[0].clone();

    let mut e_extras = BTreeMap::new();
    e_extras.insert(MVAL_TEE_ISVSVN, Value::Integer(3));
    let e = MeasurementMap {
        mkey: None,
        mval: MeasurementValuesMap {
            extra_entries: e_extras,
            ..Default::default()
        },
        authorized_by: None,
    };
    assert_eq!(p.match_measurement(&r, &e), Some(false));
}

#[test]
fn match_measurement_some_true_when_mask_eq_passes() {
    let p = IntelProfile::new();
    // tee.attributes = mask-eq, value=0xF0, mask=0xF0  → upper nibble must be 0xF.
    let mut r_extras = BTreeMap::new();
    r_extras.insert(
        MVAL_TEE_ATTRIBUTES,
        expr_tag(Value::Array(vec![
            Value::Integer(1),
            Value::Bytes(vec![0xF0]),
            Value::Bytes(vec![0xF0]),
        ])),
    );
    let r_triple = ref_triple_with_extras(r_extras);
    let r = r_triple.measurements()[0].clone();

    let mut e_extras = BTreeMap::new();
    e_extras.insert(MVAL_TEE_ATTRIBUTES, Value::Bytes(vec![0xFA]));
    let e = MeasurementMap {
        mkey: None,
        mval: MeasurementValuesMap {
            extra_entries: e_extras,
            ..Default::default()
        },
        authorized_by: None,
    };
    assert_eq!(p.match_measurement(&r, &e), Some(true));
}

#[test]
fn match_measurement_some_false_when_mask_eq_fails() {
    let p = IntelProfile::new();
    let mut r_extras = BTreeMap::new();
    r_extras.insert(
        MVAL_TEE_ATTRIBUTES,
        expr_tag(Value::Array(vec![
            Value::Integer(1),
            Value::Bytes(vec![0xF0]),
            Value::Bytes(vec![0xF0]),
        ])),
    );
    let r_triple = ref_triple_with_extras(r_extras);
    let r = r_triple.measurements()[0].clone();

    let mut e_extras = BTreeMap::new();
    e_extras.insert(MVAL_TEE_ATTRIBUTES, Value::Bytes(vec![0x1A]));
    let e = MeasurementMap {
        mkey: None,
        mval: MeasurementValuesMap {
            extra_entries: e_extras,
            ..Default::default()
        },
        authorized_by: None,
    };
    assert_eq!(p.match_measurement(&r, &e), Some(false));
}

#[test]
fn match_measurement_some_true_when_set_member_matches() {
    let p = IntelProfile::new();
    // tee.tcbstatus member of {"UpToDate","Hardening"}
    let mut r_extras = BTreeMap::new();
    r_extras.insert(
        MVAL_TEE_TCBSTATUS,
        expr_tag(Value::Array(vec![
            Value::Integer(6), // member
            Value::Array(vec![
                Value::Text("UpToDate".into()),
                Value::Text("Hardening".into()),
            ]),
        ])),
    );
    let r_triple = ref_triple_with_extras(r_extras);
    let r = r_triple.measurements()[0].clone();

    let mut e_extras = BTreeMap::new();
    e_extras.insert(MVAL_TEE_TCBSTATUS, Value::Text("Hardening".into()));
    let e = MeasurementMap {
        mkey: None,
        mval: MeasurementValuesMap {
            extra_entries: e_extras,
            ..Default::default()
        },
        authorized_by: None,
    };
    assert_eq!(p.match_measurement(&r, &e), Some(true));
}

#[test]
fn match_measurement_some_false_when_set_not_member_violated() {
    let p = IntelProfile::new();
    // tee.advisory-ids not-member of {"CVE-2024-1234"}
    let mut r_extras = BTreeMap::new();
    r_extras.insert(
        MVAL_TEE_ADVISORY_IDS,
        expr_tag(Value::Array(vec![
            Value::Integer(7), // not-member
            Value::Array(vec![Value::Text("CVE-2024-1234".into())]),
        ])),
    );
    let r_triple = ref_triple_with_extras(r_extras);
    let r = r_triple.measurements()[0].clone();

    // Evidence reports the forbidden CVE → must fail.
    let mut e_extras = BTreeMap::new();
    e_extras.insert(MVAL_TEE_ADVISORY_IDS, Value::Text("CVE-2024-1234".into()));
    let e = MeasurementMap {
        mkey: None,
        mval: MeasurementValuesMap {
            extra_entries: e_extras,
            ..Default::default()
        },
        authorized_by: None,
    };
    assert_eq!(p.match_measurement(&r, &e), Some(false));
}

#[test]
fn match_measurement_returns_none_when_only_intel_key_is_epoch() {
    let p = IntelProfile::new();
    // Reference only contains tee.epoch (Skip class).
    let mut r_extras = BTreeMap::new();
    r_extras.insert(
        MVAL_TEE_EPOCH,
        expr_tag(Value::Array(vec![
            Value::Integer(2),  // ge
            Value::Integer(60), // grace period
            Value::Null,        // epoch_id
        ])),
    );
    let r_triple = ref_triple_with_extras(r_extras);
    let r = r_triple.measurements()[0].clone();

    // Evidence DOES provide a value for the epoch key (else the
    // missing-evidence policy would fire first and produce Some(false)).
    let mut e_extras = BTreeMap::new();
    e_extras.insert(MVAL_TEE_EPOCH, Value::Integer(0));
    let e = MeasurementMap {
        mkey: None,
        mval: MeasurementValuesMap {
            extra_entries: e_extras,
            ..Default::default()
        },
        authorized_by: None,
    };
    // All-Skip → defer to core.
    assert_eq!(p.match_measurement(&r, &e), None);
}

#[test]
fn match_measurement_some_true_intel_pass_skip_mix() {
    // Reference has a passing isvsvn AND a skip-class epoch. Mix
    // should produce Some(true) (and structural match) because at
    // least one key passed.
    let p = IntelProfile::new();
    let mut r_extras = BTreeMap::new();
    r_extras.insert(
        MVAL_TEE_ISVSVN,
        expr_tag(Value::Array(vec![Value::Integer(2), Value::Integer(1)])),
    );
    r_extras.insert(
        MVAL_TEE_EPOCH,
        expr_tag(Value::Array(vec![
            Value::Integer(2),
            Value::Integer(60),
            Value::Null,
        ])),
    );
    let r_triple = ref_triple_with_extras(r_extras);
    let r = r_triple.measurements()[0].clone();

    let mut e_extras = BTreeMap::new();
    e_extras.insert(MVAL_TEE_ISVSVN, Value::Integer(7));
    e_extras.insert(MVAL_TEE_EPOCH, Value::Integer(0)); // anything; epoch skipped
    let e = MeasurementMap {
        mkey: None,
        mval: MeasurementValuesMap {
            extra_entries: e_extras,
            ..Default::default()
        },
        authorized_by: None,
    };
    assert_eq!(p.match_measurement(&r, &e), Some(true));
}

#[test]
fn match_measurement_returns_some_false_when_core_fields_disagree() {
    // Intel key passes, but reference and evidence disagree on mkey
    // (a core field) — overall verdict must be false.
    let p = IntelProfile::new();
    let mut extras = BTreeMap::new();
    extras.insert(MVAL_TEE_VENDOR, Value::Text("Intel".into()));

    let r = MeasurementMap {
        mkey: Some(MeasuredElement::Uint(1)),
        mval: MeasurementValuesMap {
            extra_entries: extras.clone(),
            ..Default::default()
        },
        authorized_by: None,
    };
    let e = MeasurementMap {
        mkey: Some(MeasuredElement::Uint(2)),
        mval: MeasurementValuesMap {
            extra_entries: extras,
            ..Default::default()
        },
        authorized_by: None,
    };
    // Intel verdict combines true with core_fields_match()==false.
    assert_eq!(p.match_measurement(&r, &e), Some(false));
}

// --- through match_reference_values_with_profile ---------------------------

#[test]
fn dispatch_through_validate_passes_with_intel_profile() {
    // Without the profile, core sees only structural fields and the
    // Intel constraint is silently ignored. With the profile, the
    // numeric-ge check runs and the pair matches.
    let p = IntelProfile::new();
    let mut r_extras = BTreeMap::new();
    r_extras.insert(
        MVAL_TEE_ISVSVN,
        expr_tag(Value::Array(vec![Value::Integer(2), Value::Integer(5)])),
    );
    let triple = ref_triple_with_extras(r_extras);

    let mut e_extras = BTreeMap::new();
    e_extras.insert(MVAL_TEE_ISVSVN, Value::Integer(7));
    let evidence = evidence_with_extras(e_extras);

    let with_profile =
        match_reference_values_with_profile(std::slice::from_ref(&triple), &evidence, Some(&p));
    assert_eq!(with_profile.len(), 1, "profile-aware match should succeed");
    assert_eq!(with_profile[0].measurements.len(), 1);

    // Sanity: without profile, core also says it matches (it ignores
    // extras), so we can't differentiate solely on this case. Use a
    // FAILING-with-profile case below to prove profile is consulted.
    let no_profile = match_reference_values(&[triple], &evidence);
    assert_eq!(no_profile.len(), 1);
}

#[test]
fn dispatch_through_validate_rejects_with_intel_profile() {
    // Same shape but evidence violates the ge-5 constraint.
    // Without profile, core ignores extras and reports match.
    // With profile, the violation is detected and the pair is rejected.
    let p = IntelProfile::new();
    let mut r_extras = BTreeMap::new();
    r_extras.insert(
        MVAL_TEE_ISVSVN,
        expr_tag(Value::Array(vec![Value::Integer(2), Value::Integer(5)])),
    );
    let triple = ref_triple_with_extras(r_extras);

    let mut e_extras = BTreeMap::new();
    e_extras.insert(MVAL_TEE_ISVSVN, Value::Integer(3));
    let evidence = evidence_with_extras(e_extras);

    // No profile: core ignores extras → false positive.
    let no_profile = match_reference_values(std::slice::from_ref(&triple), &evidence);
    assert_eq!(
        no_profile.len(),
        1,
        "core ignores extras so it reports a false-positive match"
    );

    // With profile: Intel evaluator catches the violation.
    let with_profile = match_reference_values_with_profile(&[triple], &evidence, Some(&p));
    assert!(
        with_profile.is_empty(),
        "Intel profile should reject the pair"
    );
}

#[test]
fn dispatch_through_validate_passes_combining_intel_and_core_digest() {
    // Reference has BOTH a structural digest field AND an Intel mrtee
    // bare value. With profile, mrtee equality is checked AND core
    // digest equality is checked; both pass.
    let p = IntelProfile::new();

    let digest = Digest::new(1, vec![0xAAu8; 32]);
    let mut r_extras = BTreeMap::new();
    r_extras.insert(MVAL_TEE_MRTEE, Value::Bytes(vec![0xCCu8; 32]));

    let triple = ReferenceTriple::new(
        env(),
        vec![MeasurementMap {
            mkey: None,
            mval: MeasurementValuesMap {
                digests: Some(vec![digest.clone()]),
                extra_entries: r_extras.clone(),
                ..Default::default()
            },
            authorized_by: None,
        }],
    );
    let evidence = vec![EvidenceClaim {
        environment: env(),
        measurements: vec![MeasurementMap {
            mkey: None,
            mval: MeasurementValuesMap {
                digests: Some(vec![digest]),
                extra_entries: r_extras,
                ..Default::default()
            },
            authorized_by: None,
        }],
    }];
    let claims = match_reference_values_with_profile(&[triple], &evidence, Some(&p));
    assert_eq!(claims.len(), 1);
}

#[test]
fn dispatch_through_validate_rejects_when_core_disagrees() {
    // Intel mrtee equal, but core digest field differs → reject.
    let p = IntelProfile::new();
    let mut extras = BTreeMap::new();
    extras.insert(MVAL_TEE_MRTEE, Value::Bytes(vec![0xCCu8; 32]));

    let triple = ReferenceTriple::new(
        env(),
        vec![MeasurementMap {
            mkey: None,
            mval: MeasurementValuesMap {
                digests: Some(vec![Digest::new(1, vec![0xAAu8; 32])]),
                extra_entries: extras.clone(),
                ..Default::default()
            },
            authorized_by: None,
        }],
    );
    let evidence = vec![EvidenceClaim {
        environment: env(),
        measurements: vec![MeasurementMap {
            mkey: None,
            mval: MeasurementValuesMap {
                digests: Some(vec![Digest::new(1, vec![0xBBu8; 32])]), // differs
                extra_entries: extras,
                ..Default::default()
            },
            authorized_by: None,
        }],
    }];
    let claims = match_reference_values_with_profile(&[triple], &evidence, Some(&p));
    assert!(claims.is_empty(), "core digest mismatch should reject");
}

// (no trailing helpers)
