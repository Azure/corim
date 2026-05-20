// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#![cfg(feature = "profile-intel")]

//! End-to-end tests: build a CoRIM whose `profile` field is the Intel
//! OID and verify that `IntelProfile`, when registered, labels Intel
//! `measurement-values-map` extension keys with their spec names.

use corim::cbor::encode;
use corim::cbor::value::{Tagged, Value};
use corim::diagnose::{inspect, Severity};
use corim::profile::intel::{
    IntelProfile, INTEL_PROFILE_OID_DER, MVAL_TEE_MRSIGNER, MVAL_TEE_MRTEE, MVAL_TEE_VENDOR,
};
use corim::profile::ProfileRegistry;
use corim::types::tags::{TAG_COMID, TAG_CORIM, TAG_OID};

/// Build a minimal valid CoRIM whose `profile` field is `#6.111(oid)`
/// with the Intel OID DER bytes, and whose only CoMID has one
/// reference triple with mval containing `tee.mrtee`, `tee.mrsigner`,
/// and `tee.vendor`.
fn build_intel_corim() -> Vec<u8> {
    // digest = [ 1 (sha-256), 32 bytes ]
    let mrtee = Value::Array(vec![Value::Integer(1i128), Value::Bytes(vec![0xAAu8; 32])]);
    let mrsigner = Value::Array(vec![Value::Integer(1i128), Value::Bytes(vec![0xBBu8; 32])]);

    // measurement.mval = {
    //   11: "intel-tee",        // standard `name`
    //   -83: mrtee,              // tee.mrtee
    //   -84: mrsigner,           // tee.mrsigner
    //   -70: "Intel",            // tee.vendor
    // }
    let mval = Value::Map(vec![
        (Value::Integer(11i128), Value::Text("intel-tee".into())),
        (Value::Integer(MVAL_TEE_MRTEE as i128), mrtee),
        (Value::Integer(MVAL_TEE_MRSIGNER as i128), mrsigner),
        (
            Value::Integer(MVAL_TEE_VENDOR as i128),
            Value::Text("Intel".into()),
        ),
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
fn unregistered_intel_profile_falls_back_to_generic_labels() {
    let bytes = build_intel_corim();
    let registry = ProfileRegistry::new();
    let report = inspect(&bytes, &registry);

    assert_eq!(report.error_count(), 0, "issues: {:#?}", report.issues());

    let mrtee_issue = report
        .issues()
        .iter()
        .find(|i| i.path().ends_with("{-83}"))
        .expect("expected an info issue for -83");
    assert!(
        mrtee_issue.message().contains("extension key -83"),
        "expected generic label without registered profile, got: {:?}",
        mrtee_issue.message()
    );
}

#[test]
fn registered_intel_profile_labels_known_keys_by_name() {
    let bytes = build_intel_corim();
    let mut registry = ProfileRegistry::new();
    registry.register(Box::new(IntelProfile::new()));
    let report = inspect(&bytes, &registry);

    assert_eq!(report.error_count(), 0, "issues: {:#?}", report.issues());

    let mrtee = report
        .issues()
        .iter()
        .find(|i| i.path().ends_with("{-83}"))
        .expect("issue for -83");
    assert_eq!(mrtee.severity(), Severity::Info);
    assert!(
        mrtee.message().starts_with("tee.mrtee = "),
        "got: {:?}",
        mrtee.message()
    );

    let mrsigner = report
        .issues()
        .iter()
        .find(|i| i.path().ends_with("{-84}"))
        .expect("issue for -84");
    assert!(
        mrsigner.message().starts_with("tee.mrsigner = "),
        "got: {:?}",
        mrsigner.message()
    );

    let vendor = report
        .issues()
        .iter()
        .find(|i| i.path().ends_with("{-70}"))
        .expect("issue for -70");
    assert_eq!(vendor.message(), "tee.vendor = \"Intel\"");
}

#[test]
fn profile_recognition_emits_info_at_profile_key() {
    let bytes = build_intel_corim();
    let mut registry = ProfileRegistry::new();
    registry.register(Box::new(IntelProfile::new()));
    let report = inspect(&bytes, &registry);

    let recognized = report
        .issues()
        .iter()
        .find(|i| i.message().contains("matched registered profile"));
    assert!(
        recognized.is_some(),
        "expected an info issue noting the registered profile matched, got: {:#?}",
        report.issues()
    );
}
