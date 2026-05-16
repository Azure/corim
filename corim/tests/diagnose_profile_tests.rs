// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Tests for profile-aware diagnose: the walker should call
//! [`Profile::diagnose_mval_entry`] for unknown integer keys inside a
//! `measurement-values-map`, but only when the manifest's
//! `corim-map.profile` matches a profile registered in the registry.

use corim::cbor::encode;
use corim::cbor::value::{Tagged, Value};
use corim::diagnose::{inspect, Severity};
use corim::profile::{MatchContext, Profile, ProfileRegistry};
use corim::types::corim::ProfileChoice;
use corim::types::measurement::MeasurementMap;
use corim::types::tags::{TAG_COMID, TAG_CORIM};

const PROFILE_URI: &str = "urn:example:diagnose-test";

/// Profile that labels mval key -85 as "demo.thing = <value>".
struct DemoProfile {
    id: ProfileChoice,
}
impl Profile for DemoProfile {
    fn identifier(&self) -> &ProfileChoice {
        &self.id
    }
    fn diagnose_mval_entry(&self, key: i64, value: &Value) -> Option<String> {
        if key == -85 {
            Some(format!("demo.thing = {:?}", value))
        } else {
            None
        }
    }
    fn match_measurement(
        &self,
        _r: &MeasurementMap,
        _e: &MeasurementMap,
        _ctx: &MatchContext,
    ) -> Option<bool> {
        None
    }
}

/// Build a minimal valid CoRIM containing one CoMID whose first measurement
/// has an mval with a profile-defined extension key (-85).
fn build_corim_with_profile_and_extension(profile_uri: &str) -> Vec<u8> {
    // measurement.mval = { 11: "name", -85: 42 }
    let mval = Value::Map(vec![
        (Value::Integer(11i128), Value::Text("widget".into())),
        (Value::Integer(-85i128), Value::Integer(42i128)),
    ]);
    // measurement = { 1: mval }
    let measurement = Value::Map(vec![(Value::Integer(1i128), mval)]);
    // env = { 0: { 1: "ACME" } }
    let env = Value::Map(vec![(
        Value::Integer(0i128),
        Value::Map(vec![(Value::Integer(1i128), Value::Text("ACME".into()))]),
    )]);
    // reference-triples = [[env, [measurement]]]
    let ref_triples = Value::Array(vec![Value::Array(vec![
        env,
        Value::Array(vec![measurement]),
    ])]);
    // triples = { 0: reference-triples }
    let triples_map = Value::Map(vec![(Value::Integer(0i128), ref_triples)]);
    // tag-identity = { 0: "test-tag" }
    let tag_identity = Value::Map(vec![(
        Value::Integer(0i128),
        Value::Text("test-tag".into()),
    )]);
    // concise-mid-tag = { 1: tag-identity, 4: triples }
    let comid_map = Value::Map(vec![
        (Value::Integer(1i128), tag_identity),
        (Value::Integer(4i128), triples_map),
    ]);
    let comid_bytes = encode(&comid_map).unwrap();

    // corim-map = { 0: "my-id", 1: [#6.506(comid_bytes)], 3: profile_uri }
    let corim_inner = Value::Map(vec![
        (Value::Integer(0i128), Value::Text("my-id".into())),
        (
            Value::Integer(1i128),
            Value::Array(vec![Value::Tag(
                TAG_COMID,
                Box::new(Value::Bytes(comid_bytes)),
            )]),
        ),
        (Value::Integer(3i128), Value::Text(profile_uri.into())),
    ]);
    encode(&Tagged::new(TAG_CORIM, corim_inner)).unwrap()
}

#[test]
fn extension_key_without_registered_profile_gets_generic_label() {
    let bytes = build_corim_with_profile_and_extension(PROFILE_URI);
    let registry = ProfileRegistry::new();
    let report = inspect(&bytes, &registry);

    assert_eq!(report.error_count(), 0, "issues: {:#?}", report.issues());

    let ext_issue = report
        .issues()
        .iter()
        .find(|i| i.path().ends_with("{-85}"))
        .expect("expected an info issue for the -85 extension key");
    assert_eq!(ext_issue.severity(), Severity::Info);
    assert!(
        ext_issue.message().contains("extension key -85"),
        "expected generic label, got: {:?}",
        ext_issue.message()
    );
}

#[test]
fn extension_key_with_registered_profile_gets_profile_label() {
    let bytes = build_corim_with_profile_and_extension(PROFILE_URI);
    let mut registry = ProfileRegistry::new();
    registry.register(Box::new(DemoProfile {
        id: ProfileChoice::Uri(PROFILE_URI.into()),
    }));
    let report = inspect(&bytes, &registry);

    assert_eq!(report.error_count(), 0, "issues: {:#?}", report.issues());

    let ext_issue = report
        .issues()
        .iter()
        .find(|i| i.path().ends_with("{-85}"))
        .expect("expected an info issue for the -85 extension key");
    assert_eq!(ext_issue.severity(), Severity::Info);
    assert!(
        ext_issue.message().contains("demo.thing"),
        "expected profile-supplied label, got: {:?}",
        ext_issue.message()
    );
}

#[test]
fn extension_key_with_non_matching_profile_falls_through_to_generic() {
    // Manifest declares one profile URI; registry has a different one.
    let bytes = build_corim_with_profile_and_extension(PROFILE_URI);
    let mut registry = ProfileRegistry::new();
    registry.register(Box::new(DemoProfile {
        id: ProfileChoice::Uri("urn:example:other-profile".into()),
    }));
    let report = inspect(&bytes, &registry);

    assert_eq!(report.error_count(), 0, "issues: {:#?}", report.issues());

    let ext_issue = report
        .issues()
        .iter()
        .find(|i| i.path().ends_with("{-85}"))
        .expect("expected an info issue for the -85 extension key");
    assert!(
        ext_issue.message().contains("extension key -85"),
        "expected generic label when profile doesn't match, got: {:?}",
        ext_issue.message()
    );
}

#[test]
fn matching_profile_emits_recognition_info_issue() {
    let bytes = build_corim_with_profile_and_extension(PROFILE_URI);
    let mut registry = ProfileRegistry::new();
    registry.register(Box::new(DemoProfile {
        id: ProfileChoice::Uri(PROFILE_URI.into()),
    }));
    let report = inspect(&bytes, &registry);

    // The walker should emit an info issue when the profile field matches a
    // registered profile. It is anchored at the corim-map profile key path
    // and mentions the URI.
    let recognized = report
        .issues()
        .iter()
        .find(|i| {
            i.severity() == Severity::Info && i.message().contains("matched registered profile")
        })
        .expect("expected a profile-recognition info issue");
    assert!(recognized.message().contains(PROFILE_URI));
}

#[test]
fn walker_descends_into_comid_and_reports_structural_errors() {
    // Build a CoRIM whose CoMID is missing the required tag-identity key.
    // The pre-commit-4 walker would have missed this; the new walker should
    // surface it as an error inside the CoMID.
    let comid_map = Value::Map(vec![(
        Value::Integer(4i128),
        Value::Map(vec![(
            Value::Integer(0i128),
            Value::Array(vec![Value::Array(vec![
                Value::Map(vec![(
                    Value::Integer(0i128),
                    Value::Map(vec![(Value::Integer(1i128), Value::Text("ACME".into()))]),
                )]),
                Value::Array(vec![Value::Map(vec![(
                    Value::Integer(1i128),
                    Value::Map(vec![(Value::Integer(11i128), Value::Text("widget".into()))]),
                )])]),
            ])]),
        )]),
    )]);
    let comid_bytes = encode(&comid_map).unwrap();
    let corim_inner = Value::Map(vec![
        (Value::Integer(0i128), Value::Text("my-id".into())),
        (
            Value::Integer(1i128),
            Value::Array(vec![Value::Tag(
                TAG_COMID,
                Box::new(Value::Bytes(comid_bytes)),
            )]),
        ),
    ]);
    let bytes = encode(&Tagged::new(TAG_CORIM, corim_inner)).unwrap();
    let report = inspect(&bytes, &ProfileRegistry::new());

    let missing_id_err = report
        .issues()
        .iter()
        .find(|i| i.severity() == Severity::Error && i.message().contains("tag-identity"))
        .expect("expected an error about missing tag-identity inside the CoMID");
    // Path should be anchored inside the CoMID at the inner-bytes path
    // — verify it points into the tags[0] entry, not the outer corim-map.
    assert!(
        missing_id_err.path().contains("[0]"),
        "expected CoMID-scoped path, got: {}",
        missing_id_err.path()
    );
}
