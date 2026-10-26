// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#![cfg(feature = "profile-intel")]

//! End-to-end: a CoRIM whose `tee.isvsvn` (mval -73) and
//! `tee.advisory-ids` (mval -89) reference values carry tagged
//! expressions should be rendered by `--diagnose` with the operator
//! mnemonic instead of `#6.60010(…)`.

use corim::cbor::encode;
use corim::cbor::value::{Tagged, Value};
use corim::diagnose::inspect;
use corim::profile::intel::{
    IntelProfile, INTEL_PROFILE_OID_DER, MVAL_TEE_ADVISORY_IDS, MVAL_TEE_ISVSVN, MVAL_TEE_MRTEE,
    TAG_INTEL_EXPRESSION, TAG_INTEL_SET_DIGEST_EXPRESSION, TAG_INTEL_SET_TSTR_EXPRESSION,
};
use corim::profile::{Profile, ProfileRegistry};
use corim::types::measurement::{MeasurementMap, MeasurementValuesMap};
use corim::types::tags::{TAG_COMID, TAG_CORIM, TAG_OID};

fn build_corim_with_expressions() -> Vec<u8> {
    // tagged-numeric-ge: #6.60010([ 2 (ge), 5 ])
    let isvsvn_ref = Value::Tag(
        TAG_INTEL_EXPRESSION,
        Box::new(Value::Array(vec![
            Value::Integer(2i128),
            Value::Integer(5i128),
        ])),
    );

    // tagged-exp-tstr-not-member: #6.60021([ 7 (not-member), [advisory1, advisory2] ])
    let advisory_ref = Value::Tag(
        TAG_INTEL_SET_TSTR_EXPRESSION,
        Box::new(Value::Array(vec![
            Value::Integer(7i128),
            Value::Array(vec![
                Value::Text("INTEL-SA-00001".into()),
                Value::Text("INTEL-SA-00002".into()),
            ]),
        ])),
    );

    let mval = Value::Map(vec![
        (Value::Integer(11i128), Value::Text("intel-tee".into())),
        (Value::Integer(MVAL_TEE_ISVSVN as i128), isvsvn_ref),
        (Value::Integer(MVAL_TEE_ADVISORY_IDS as i128), advisory_ref),
    ]);
    let measurement = Value::Map(vec![(Value::Integer(1i128), mval)]);
    let env = Value::Map(vec![(
        Value::Integer(0i128),
        Value::Map(vec![(Value::Integer(1i128), Value::Text("Intel".into()))]),
    )]);
    let ref_triples = Value::Array(vec![Value::Array(vec![
        env,
        Value::Array(vec![measurement]),
    ])]);
    let triples_map = Value::Map(vec![(Value::Integer(0i128), ref_triples)]);
    let tag_identity = Value::Map(vec![(
        Value::Integer(0i128),
        Value::Text("intel-corim".into()),
    )]);
    let comid_map = Value::Map(vec![
        (Value::Integer(1i128), tag_identity),
        (Value::Integer(4i128), triples_map),
    ]);
    let comid_bytes = encode(&comid_map).unwrap();

    let profile_value = Value::Tag(
        TAG_OID,
        Box::new(Value::Bytes(INTEL_PROFILE_OID_DER.to_vec())),
    );
    let corim_inner = Value::Map(vec![
        (Value::Integer(0i128), Value::Text("intel-id".into())),
        (
            Value::Integer(1i128),
            Value::Array(vec![Value::Tag(
                TAG_COMID,
                Box::new(Value::Bytes(comid_bytes)),
            )]),
        ),
        (Value::Integer(3i128), profile_value),
    ]);
    encode(&Tagged::new(TAG_CORIM, corim_inner)).unwrap()
}

#[test]
fn diagnose_renders_numeric_ge_expression() {
    let bytes = build_corim_with_expressions();
    let mut registry = ProfileRegistry::new();
    registry.register(Box::new(IntelProfile::new()));
    let report = inspect(&bytes, &registry);

    assert_eq!(report.error_count(), 0, "issues: {:#?}", report.issues());

    let isvsvn = report
        .issues()
        .iter()
        .find(|i| i.path().ends_with("{-73}"))
        .expect("issue for -73");
    assert_eq!(
        isvsvn.message(),
        "tee.isvsvn = ge 5",
        "got: {:?}",
        isvsvn.message()
    );
}

#[test]
fn diagnose_renders_not_member_expression() {
    let bytes = build_corim_with_expressions();
    let mut registry = ProfileRegistry::new();
    registry.register(Box::new(IntelProfile::new()));
    let report = inspect(&bytes, &registry);

    let advisory = report
        .issues()
        .iter()
        .find(|i| i.path().ends_with("{-89}"))
        .expect("issue for -89");
    assert_eq!(
        advisory.message(),
        "tee.advisory-ids = not-member (2 strings)",
        "got: {:?}",
        advisory.message()
    );
}

#[test]
fn diagnose_falls_back_for_malformed_expression() {
    // #6.60010 with no body (empty array) — decoder rejects, summary
    // falls back to `#6.60010(…)`.
    let bad_expr = Value::Tag(TAG_INTEL_EXPRESSION, Box::new(Value::Array(vec![])));
    let mval = Value::Map(vec![
        (Value::Integer(11i128), Value::Text("intel".into())),
        (Value::Integer(MVAL_TEE_ISVSVN as i128), bad_expr),
    ]);
    let measurement = Value::Map(vec![(Value::Integer(1i128), mval)]);
    let env = Value::Map(vec![(
        Value::Integer(0i128),
        Value::Map(vec![(Value::Integer(1i128), Value::Text("Intel".into()))]),
    )]);
    let ref_triples = Value::Array(vec![Value::Array(vec![
        env,
        Value::Array(vec![measurement]),
    ])]);
    let triples_map = Value::Map(vec![(Value::Integer(0i128), ref_triples)]);
    let tag_identity = Value::Map(vec![(
        Value::Integer(0i128),
        Value::Text("intel-corim".into()),
    )]);
    let comid_map = Value::Map(vec![
        (Value::Integer(1i128), tag_identity),
        (Value::Integer(4i128), triples_map),
    ]);
    let comid_bytes = encode(&comid_map).unwrap();
    let profile_value = Value::Tag(
        TAG_OID,
        Box::new(Value::Bytes(INTEL_PROFILE_OID_DER.to_vec())),
    );
    let corim_inner = Value::Map(vec![
        (Value::Integer(0i128), Value::Text("intel-id".into())),
        (
            Value::Integer(1i128),
            Value::Array(vec![Value::Tag(
                TAG_COMID,
                Box::new(Value::Bytes(comid_bytes)),
            )]),
        ),
        (Value::Integer(3i128), profile_value),
    ]);
    let bytes = encode(&Tagged::new(TAG_CORIM, corim_inner)).unwrap();

    let mut registry = ProfileRegistry::new();
    registry.register(Box::new(IntelProfile::new()));
    let report = inspect(&bytes, &registry);

    let label = report
        .issues()
        .iter()
        .find(|i| i.path().ends_with("{-73}"))
        .expect("issue for -73");
    assert_eq!(label.message(), "tee.isvsvn = #6.60010(…)");
    assert!(
        report
            .issues()
            .iter()
            .any(|issue| issue.message().contains("wrong arity")),
        "expected semantic validation error, got: {:#?}",
        report.issues()
    );
}

#[test]
fn static_validation_rejects_malformed_expression() {
    let profile = IntelProfile::new();
    let mut mval = MeasurementValuesMap::default();
    mval.extra_entries.insert(
        MVAL_TEE_ISVSVN,
        Value::Tag(TAG_INTEL_EXPRESSION, Box::new(Value::Array(vec![]))),
    );
    let measurement = MeasurementMap {
        mkey: None,
        mval,
        authorized_by: None,
    };

    let error = profile
        .validate_reference_measurement(&measurement)
        .unwrap_err();
    assert!(error.contains("tee.isvsvn"));
    assert!(error.contains("wrong arity"));
}

#[test]
fn static_validation_rejects_malformed_digest_set_member() {
    let profile = IntelProfile::new();
    let mut mval = MeasurementValuesMap::default();
    mval.extra_entries.insert(
        MVAL_TEE_MRTEE,
        Value::Tag(
            TAG_INTEL_SET_DIGEST_EXPRESSION,
            Box::new(Value::Array(vec![
                Value::Integer(6),
                Value::Array(vec![Value::Array(vec![Value::Integer(1)])]),
            ])),
        ),
    );
    let measurement = MeasurementMap {
        mkey: None,
        mval,
        authorized_by: None,
    };

    let error = profile
        .validate_reference_measurement(&measurement)
        .unwrap_err();
    assert!(error.contains("tee.mrtee"));
    assert!(error.contains("set-digest member"));
}
