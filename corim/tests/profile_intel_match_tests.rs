// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#![cfg(feature = "profile-intel")]

//! Integration tests for `IntelProfile::match_measurement`, exercised
//! through `corim::validate::match_reference_values_with_profile` so
//! the dispatch contract is also covered.

use std::collections::BTreeMap;

use corim::cbor::value::Value;
use corim::profile::intel::{
    IntelProfile, MVAL_TEE_ADVISORY_IDS, MVAL_TEE_ATTRIBUTES, MVAL_TEE_ISVSVN, MVAL_TEE_MRTEE,
    MVAL_TEE_TCBSTATUS, MVAL_TEE_VENDOR, TAG_INTEL_EXPRESSION, TAG_INTEL_SET_TSTR_EXPRESSION,
};
use corim::profile::{MatchContext, Profile};
use corim::types::common::MeasuredElement;
use corim::types::environment::{ClassMap, EnvironmentMap};
use corim::types::measurement::{Digest, MeasurementMap, MeasurementValuesMap};
use corim::types::triples::ReferenceTriple;
use corim::validate::{match_reference_values, match_reference_values_with_profile, EvidenceClaim};

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

fn set_tstr_tag(body: Value) -> Value {
    Value::Tag(TAG_INTEL_SET_TSTR_EXPRESSION, Box::new(body))
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
    assert_eq!(p.match_measurement(&r, &e, &MatchContext::new()), None);
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
    assert_eq!(
        p.match_measurement(&r, &e, &MatchContext::new()),
        Some(false)
    );
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
    assert_eq!(
        p.match_measurement(&r, &e, &MatchContext::new()),
        Some(true)
    );
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
    assert_eq!(
        p.match_measurement(&r, &e, &MatchContext::new()),
        Some(false)
    );
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
    assert_eq!(
        p.match_measurement(&r, &e, &MatchContext::new()),
        Some(true)
    );
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
    assert_eq!(
        p.match_measurement(&r, &e, &MatchContext::new()),
        Some(false)
    );
}

#[test]
fn match_measurement_some_true_when_attributes_bare_equal() {
    // v07 §8.3.2 drops the mask-eq expression. tee.attributes is now
    // `$masked-value-type = ~tagged-bytes / $raw-value-type-choice`,
    // so the matching contract degenerates to CBOR equality on the
    // bare bstr unless a tagged-masked-raw-value (#6.563) is used.
    let p = IntelProfile::new();
    let mut r_extras = BTreeMap::new();
    r_extras.insert(MVAL_TEE_ATTRIBUTES, Value::Bytes(vec![0xFA, 0xCE]));
    let r_triple = ref_triple_with_extras(r_extras);
    let r = r_triple.measurements()[0].clone();

    let mut e_extras = BTreeMap::new();
    e_extras.insert(MVAL_TEE_ATTRIBUTES, Value::Bytes(vec![0xFA, 0xCE]));
    let e = MeasurementMap {
        mkey: None,
        mval: MeasurementValuesMap {
            extra_entries: e_extras,
            ..Default::default()
        },
        authorized_by: None,
    };
    assert_eq!(
        p.match_measurement(&r, &e, &MatchContext::new()),
        Some(true)
    );
}

#[test]
fn match_measurement_some_false_when_attributes_bare_unequal() {
    let p = IntelProfile::new();
    let mut r_extras = BTreeMap::new();
    r_extras.insert(MVAL_TEE_ATTRIBUTES, Value::Bytes(vec![0xFA, 0xCE]));
    let r_triple = ref_triple_with_extras(r_extras);
    let r = r_triple.measurements()[0].clone();

    let mut e_extras = BTreeMap::new();
    e_extras.insert(MVAL_TEE_ATTRIBUTES, Value::Bytes(vec![0x00, 0xCE]));
    let e = MeasurementMap {
        mkey: None,
        mval: MeasurementValuesMap {
            extra_entries: e_extras,
            ..Default::default()
        },
        authorized_by: None,
    };
    assert_eq!(
        p.match_measurement(&r, &e, &MatchContext::new()),
        Some(false)
    );
}

#[test]
fn match_measurement_some_true_when_set_member_matches() {
    let p = IntelProfile::new();
    // tee.tcbstatus member of {"UpToDate","Hardening"}
    // Per v07 §8.2.3: tagged-exp-tstr-member uses tag #6.60021.
    let mut r_extras = BTreeMap::new();
    r_extras.insert(
        MVAL_TEE_TCBSTATUS,
        set_tstr_tag(Value::Array(vec![
            Value::Integer(6), // op.mem
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
    assert_eq!(
        p.match_measurement(&r, &e, &MatchContext::new()),
        Some(true)
    );
}

#[test]
fn match_measurement_some_false_when_set_not_member_violated() {
    let p = IntelProfile::new();
    // tee.advisory-ids not-member of {"CVE-2024-1234"}
    // Per v07 §8.2.3: tagged-exp-tstr-not-member uses tag #6.60021.
    let mut r_extras = BTreeMap::new();
    r_extras.insert(
        MVAL_TEE_ADVISORY_IDS,
        set_tstr_tag(Value::Array(vec![
            Value::Integer(7), // op.nmem
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
    assert_eq!(
        p.match_measurement(&r, &e, &MatchContext::new()),
        Some(false)
    );
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
    assert_eq!(
        p.match_measurement(&r, &e, &MatchContext::new()),
        Some(false)
    );
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

    let with_profile = match_reference_values_with_profile(
        std::slice::from_ref(&triple),
        &evidence,
        Some(&p),
        &MatchContext::new(),
    );
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
    let with_profile =
        match_reference_values_with_profile(&[triple], &evidence, Some(&p), &MatchContext::new());
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
    let claims =
        match_reference_values_with_profile(&[triple], &evidence, Some(&p), &MatchContext::new());
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
    let claims =
        match_reference_values_with_profile(&[triple], &evidence, Some(&p), &MatchContext::new());
    assert!(claims.is_empty(), "core digest mismatch should reject");
}

// --- v07 new tag shapes ----------------------------------------------------

#[test]
fn match_measurement_int_range_accepts_value_in_window() {
    // v07 §8.3.11 lists tagged-int-range (#6.564) as an SVN reference shape.
    use corim::types::tags::TAG_INT_RANGE;
    let p = IntelProfile::new();
    let mut r_extras = BTreeMap::new();
    r_extras.insert(
        MVAL_TEE_ISVSVN,
        Value::Tag(
            TAG_INT_RANGE,
            Box::new(Value::Array(vec![Value::Integer(5), Value::Integer(10)])),
        ),
    );
    let r_triple = ref_triple_with_extras(r_extras);
    let r = r_triple.measurements()[0].clone();

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
    assert_eq!(
        p.match_measurement(&r, &e, &MatchContext::new()),
        Some(true)
    );

    // Out of window.
    let mut e_extras = BTreeMap::new();
    e_extras.insert(MVAL_TEE_ISVSVN, Value::Integer(11));
    let e = MeasurementMap {
        mkey: None,
        mval: MeasurementValuesMap {
            extra_entries: e_extras,
            ..Default::default()
        },
        authorized_by: None,
    };
    assert_eq!(
        p.match_measurement(&r, &e, &MatchContext::new()),
        Some(false)
    );
}

#[test]
fn match_measurement_min_svn_pass_and_fail() {
    // v07 §8.3.11 also lists tagged-min-svn (#6.553) as an SVN
    // reference shape.
    use corim::types::tags::TAG_MIN_SVN;
    let p = IntelProfile::new();
    let mut r_extras = BTreeMap::new();
    r_extras.insert(
        MVAL_TEE_ISVSVN,
        Value::Tag(TAG_MIN_SVN, Box::new(Value::Integer(5))),
    );
    let r_triple = ref_triple_with_extras(r_extras);
    let r = r_triple.measurements()[0].clone();

    let mut e_extras = BTreeMap::new();
    e_extras.insert(MVAL_TEE_ISVSVN, Value::Integer(5));
    let e = MeasurementMap {
        mkey: None,
        mval: MeasurementValuesMap {
            extra_entries: e_extras,
            ..Default::default()
        },
        authorized_by: None,
    };
    assert_eq!(
        p.match_measurement(&r, &e, &MatchContext::new()),
        Some(true)
    );

    let mut e_extras = BTreeMap::new();
    e_extras.insert(MVAL_TEE_ISVSVN, Value::Integer(4));
    let e = MeasurementMap {
        mkey: None,
        mval: MeasurementValuesMap {
            extra_entries: e_extras,
            ..Default::default()
        },
        authorized_by: None,
    };
    assert_eq!(
        p.match_measurement(&r, &e, &MatchContext::new()),
        Some(false)
    );
}

#[test]
fn match_measurement_set_of_digests_member() {
    // v07 §8.2.3: tagged-exp-digest-member uses tag #6.60020. Two
    // reference digests; evidence picks one.
    use corim::profile::intel::TAG_INTEL_SET_DIGEST_EXPRESSION;
    let p = IntelProfile::new();
    let good = Value::Array(vec![Value::Integer(1), Value::Bytes(vec![0xAAu8; 32])]);
    let alt = Value::Array(vec![Value::Integer(1), Value::Bytes(vec![0xBBu8; 32])]);
    let mut r_extras = BTreeMap::new();
    r_extras.insert(
        MVAL_TEE_MRTEE,
        Value::Tag(
            TAG_INTEL_SET_DIGEST_EXPRESSION,
            Box::new(Value::Array(vec![
                Value::Integer(6),
                Value::Array(vec![good.clone(), alt.clone()]),
            ])),
        ),
    );
    let r_triple = ref_triple_with_extras(r_extras);
    let r = r_triple.measurements()[0].clone();

    let mut e_extras = BTreeMap::new();
    e_extras.insert(MVAL_TEE_MRTEE, good);
    let e = MeasurementMap {
        mkey: None,
        mval: MeasurementValuesMap {
            extra_entries: e_extras,
            ..Default::default()
        },
        authorized_by: None,
    };
    assert_eq!(
        p.match_measurement(&r, &e, &MatchContext::new()),
        Some(true)
    );
}

#[test]
fn match_measurement_masked_raw_value_passes_under_mask() {
    // v07 §8.3.2 / §8.3.8: tee.attributes / tee.miscselect can carry a
    // `tagged-masked-raw-value` (#6.563) reference; evidence is a bare
    // `bstr`. Matching uses `(ev & mask) == (value & mask)`.
    use corim::types::tags::TAG_MASKED_RAW_VALUE;
    let p = IntelProfile::new();
    let mut r_extras = BTreeMap::new();
    r_extras.insert(
        MVAL_TEE_ATTRIBUTES,
        Value::Tag(
            TAG_MASKED_RAW_VALUE,
            Box::new(Value::Array(vec![
                Value::Bytes(vec![0xF0, 0x00]),
                Value::Bytes(vec![0xF0, 0xFF]),
            ])),
        ),
    );
    let r_triple = ref_triple_with_extras(r_extras);
    let r = r_triple.measurements()[0].clone();

    // Lower nibble of byte 0 is masked off; byte 1 must equal 0x00.
    let mut e_extras = BTreeMap::new();
    e_extras.insert(MVAL_TEE_ATTRIBUTES, Value::Bytes(vec![0xFA, 0x00]));
    let e = MeasurementMap {
        mkey: None,
        mval: MeasurementValuesMap {
            extra_entries: e_extras,
            ..Default::default()
        },
        authorized_by: None,
    };
    assert_eq!(
        p.match_measurement(&r, &e, &MatchContext::new()),
        Some(true)
    );

    // Evidence outside the mask must fail.
    let mut e_extras = BTreeMap::new();
    e_extras.insert(MVAL_TEE_ATTRIBUTES, Value::Bytes(vec![0x1A, 0x00]));
    let e = MeasurementMap {
        mkey: None,
        mval: MeasurementValuesMap {
            extra_entries: e_extras,
            ..Default::default()
        },
        authorized_by: None,
    };
    assert_eq!(
        p.match_measurement(&r, &e, &MatchContext::new()),
        Some(false)
    );
}
