// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#![cfg(feature = "profile-azure")]

use corim::builder::{ComidBuilder, CorimBuilder};
use corim::cbor::encode;
use corim::cbor::value::{Tagged, Value};
use corim::profile::azure::{AzureProfile, AZURE_PROFILE_URI, MVAL_TCBSTATUS};
use corim::profile::{MatchContext, Profile, ProfileRegistry};
use corim::types::common::TagIdChoice;
use corim::types::corim::{CorimId, ProfileChoice};
use corim::types::environment::{ClassMap, EnvironmentMap};
use corim::types::measurement::{MeasurementMap, MeasurementValuesMap, SvnChoice};
use corim::types::tags::{TAG_COMID, TAG_CORIM, TAG_URI};
use corim::types::triples::ReferenceTriple;
use corim::validate::{match_reference_values_with_profile, EvidenceClaim};
use std::sync::{Arc, Mutex};

struct RecordingProfile {
    id: ProfileChoice,
    calls: Arc<Mutex<Vec<&'static str>>>,
}

impl Profile for RecordingProfile {
    fn identifier(&self) -> &ProfileChoice {
        &self.id
    }

    fn validate_reference_triple(&self, _triple: &ReferenceTriple) -> Result<(), String> {
        self.calls.lock().unwrap().push("triple");
        Ok(())
    }

    fn validate_reference_measurement(&self, _measurement: &MeasurementMap) -> Result<(), String> {
        self.calls.lock().unwrap().push("measurement");
        Ok(())
    }
}

fn measurement_with(status: Option<&str>, svn: Option<u64>) -> MeasurementMap {
    let mut mval = MeasurementValuesMap::default();

    if let Some(status) = status {
        mval.extra_entries
            .insert(MVAL_TCBSTATUS, Value::Text(status.into()));
    }

    if let Some(svn) = svn {
        mval.svn = Some(SvnChoice::ExactValue(svn));
    }

    MeasurementMap {
        mkey: None,
        mval,
        authorized_by: None,
    }
}

fn environment() -> EnvironmentMap {
    EnvironmentMap {
        class: Some(ClassMap::new("Microsoft", "Azure")),
        instance: None,
        group: None,
    }
}

fn build_corim(profile: ProfileChoice, measurement: MeasurementMap) -> Vec<u8> {
    let comid = ComidBuilder::new(TagIdChoice::Text("azure-comid".into()))
        .add_reference_triple(ReferenceTriple::new(environment(), vec![measurement]))
        .build()
        .unwrap();
    CorimBuilder::new(CorimId::Text("azure-corim".into()))
        .set_profile(profile)
        .add_comid_tag(comid)
        .unwrap()
        .build_bytes()
        .unwrap()
}

fn build_corim_with_malformed_measurement_sibling() -> Vec<u8> {
    let environment = Value::Map(vec![(
        Value::Integer(0),
        Value::Map(vec![(Value::Integer(1), Value::Text("Microsoft".into()))]),
    )]);
    let invalid_profile_measurement = Value::Map(vec![(
        Value::Integer(1),
        Value::Map(vec![(
            Value::Integer(i128::from(MVAL_TCBSTATUS)),
            Value::Text("UnknownState".into()),
        )]),
    )]);
    let reference_triples = Value::Array(vec![Value::Array(vec![
        environment,
        Value::Array(vec![Value::Integer(0), invalid_profile_measurement]),
    ])]);
    let comid = Value::Map(vec![
        (
            Value::Integer(1),
            Value::Map(vec![(Value::Integer(0), Value::Text("azure-comid".into()))]),
        ),
        (
            Value::Integer(4),
            Value::Map(vec![(Value::Integer(0), reference_triples)]),
        ),
    ]);
    let comid_bytes = encode(&comid).unwrap();
    let corim = Value::Map(vec![
        (Value::Integer(0), Value::Text("azure-corim".into())),
        (
            Value::Integer(1),
            Value::Array(vec![Value::Tag(
                TAG_COMID,
                Box::new(Value::Bytes(comid_bytes)),
            )]),
        ),
        (
            Value::Integer(3),
            Value::Tag(TAG_URI, Box::new(Value::Text(AZURE_PROFILE_URI.into()))),
        ),
    ]);
    encode(&Tagged::new(TAG_CORIM, corim)).unwrap()
}

#[test]
fn identifier_uses_azure_profile_uri() {
    let profile = AzureProfile::new();
    assert_eq!(
        profile.identifier(),
        &ProfileChoice::Uri(AZURE_PROFILE_URI.into())
    );
}

#[test]
fn match_returns_none_when_reference_has_no_tcbstatus() {
    let profile = AzureProfile::new();
    let reference = measurement_with(None, Some(1));
    let evidence = measurement_with(Some("UpToDate"), Some(1));

    assert_eq!(
        profile.match_measurement(&reference, &evidence, &MatchContext::new()),
        None
    );
}

#[test]
fn match_returns_false_when_evidence_missing_tcbstatus() {
    let profile = AzureProfile::new();
    let reference = measurement_with(Some("UpToDate"), Some(1));
    let evidence = measurement_with(None, Some(1));

    assert_eq!(
        profile.match_measurement(&reference, &evidence, &MatchContext::new()),
        Some(false)
    );
}

#[test]
fn match_returns_true_for_equal_tcbstatus_and_core_fields() {
    let profile = AzureProfile::new();
    let reference = measurement_with(Some("UpToDate"), Some(7));
    let evidence = measurement_with(Some("UpToDate"), Some(7));

    assert_eq!(
        profile.match_measurement(&reference, &evidence, &MatchContext::new()),
        Some(true)
    );
}

#[test]
fn match_returns_false_when_core_fields_do_not_match() {
    let profile = AzureProfile::new();
    let reference = measurement_with(Some("UpToDate"), Some(7));
    let evidence = measurement_with(Some("UpToDate"), Some(8));

    assert_eq!(
        profile.match_measurement(&reference, &evidence, &MatchContext::new()),
        Some(false)
    );
}

#[test]
fn match_returns_false_when_tcbstatus_values_differ() {
    let profile = AzureProfile::new();
    let reference = measurement_with(Some("UpToDate"), Some(1));
    let evidence = measurement_with(Some("OutOfDate"), Some(1));

    assert_eq!(
        profile.match_measurement(&reference, &evidence, &MatchContext::new()),
        Some(false)
    );
}

#[test]
fn match_returns_false_when_tcbstatus_value_is_invalid() {
    let profile = AzureProfile::new();
    let reference = measurement_with(Some("UnknownState"), Some(1));
    let evidence = measurement_with(Some("UnknownState"), Some(1));

    assert_eq!(
        profile.match_measurement(&reference, &evidence, &MatchContext::new()),
        Some(false)
    );
}

#[test]
fn static_validation_rejects_invalid_tcbstatus() {
    let profile = AzureProfile::new();
    let measurement = measurement_with(Some("UnknownState"), Some(1));

    let error = profile
        .validate_reference_measurement(&measurement)
        .unwrap_err();
    assert!(error.contains("tcbstatus"));
    assert!(error.contains("UnknownState"));
}

#[test]
fn profile_aware_decode_and_diagnose_reject_invalid_tcbstatus() {
    let bytes = build_corim(
        ProfileChoice::Uri(AZURE_PROFILE_URI.into()),
        measurement_with(Some("UnknownState"), Some(1)),
    );
    let mut registry = ProfileRegistry::new();
    registry.register(Box::new(AzureProfile::new()));

    let error =
        corim::validate::decode_and_validate_at_with_registry(&bytes, 0, &registry).unwrap_err();
    assert!(error.to_string().contains("measurements[0]"));
    assert!(error.to_string().contains("UnknownState"));

    let report = corim::diagnose::inspect(&bytes, &registry);
    let issue = report
        .issues()
        .iter()
        .find(|issue| issue.message().contains("UnknownState"))
        .expect("profile semantic issue");
    assert!(issue.path().ends_with(".measurements[0]"));
}

#[test]
fn diagnose_validates_measurements_independently() {
    let bytes = build_corim_with_malformed_measurement_sibling();
    let mut registry = ProfileRegistry::new();
    registry.register(Box::new(AzureProfile::new()));

    let report = corim::diagnose::inspect(&bytes, &registry);
    assert!(
        report
            .issues()
            .iter()
            .any(|issue| issue.path().ends_with(".measurements[0]")),
        "expected structural error for malformed sibling: {:#?}",
        report.issues()
    );
    assert!(
        report
            .issues()
            .iter()
            .any(|issue| issue.path().ends_with(".measurements[1]")
                && issue.message().contains("UnknownState")),
        "expected independent profile error: {:#?}",
        report.issues()
    );
}

#[test]
fn diagnose_runs_triple_validation_before_measurement_validation() {
    let bytes = build_corim(
        ProfileChoice::Uri(AZURE_PROFILE_URI.into()),
        measurement_with(Some("UpToDate"), Some(1)),
    );
    let calls = Arc::new(Mutex::new(Vec::new()));
    let mut registry = ProfileRegistry::new();
    registry.register(Box::new(RecordingProfile {
        id: ProfileChoice::Uri(AZURE_PROFILE_URI.into()),
        calls: Arc::clone(&calls),
    }));

    let report = corim::diagnose::inspect(&bytes, &registry);

    assert_eq!(report.error_count(), 0, "issues: {:#?}", report.issues());
    assert_eq!(*calls.lock().unwrap(), vec!["triple", "measurement"]);
}

#[test]
fn unregistered_profile_skips_profile_semantic_validation() {
    let bytes = build_corim(
        ProfileChoice::Uri("https://example.com/unregistered-profile".into()),
        measurement_with(Some("UnknownState"), Some(1)),
    );
    let mut registry = ProfileRegistry::new();
    registry.register(Box::new(AzureProfile::new()));

    corim::validate::decode_and_validate_at_with_registry(&bytes, 0, &registry)
        .expect("an unregistered profile remains forward-compatible");
}

#[test]
fn appraisal_rejects_malformed_reference_as_invalid_document() {
    let profile = AzureProfile::new();
    let reference = ReferenceTriple::new(
        environment(),
        vec![measurement_with(Some("UnknownState"), Some(1))],
    );
    let evidence = EvidenceClaim {
        environment: environment(),
        measurements: vec![measurement_with(Some("UnknownState"), Some(1))],
    };

    let error = match_reference_values_with_profile(
        &[reference],
        &[evidence],
        Some(&profile),
        &MatchContext::new(),
    )
    .unwrap_err();
    assert!(error.to_string().contains("UnknownState"));
}

#[test]
fn diagnose_renders_expected_labels() {
    let profile = AzureProfile::new();

    assert_eq!(
        profile.diagnose_mval_entry(MVAL_TCBSTATUS, &Value::Text("UpToDate".into())),
        Some("tcbstatus = UpToDate".into())
    );
    assert_eq!(
        profile.diagnose_mval_entry(MVAL_TCBSTATUS, &Value::Text("OutOfDate".into())),
        Some("tcbstatus = OutOfDate".into())
    );
    assert_eq!(
        profile.diagnose_mval_entry(MVAL_TCBSTATUS, &Value::Integer(42)),
        Some("tcbstatus = <invalid>".into())
    );
}

#[test]
fn diagnose_ignores_non_profile_keys() {
    let profile = AzureProfile::new();
    assert_eq!(
        profile.diagnose_mval_entry(-701, &Value::Text("UpToDate".into())),
        None
    );
}
