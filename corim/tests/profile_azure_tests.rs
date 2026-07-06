// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#![cfg(feature = "profile-azure")]

use corim::cbor::value::Value;
use corim::profile::azure::{AzureProfile, AZURE_PROFILE_URI, MVAL_TCBSTATUS};
use corim::profile::{MatchContext, Profile};
use corim::types::corim::ProfileChoice;
use corim::types::measurement::{MeasurementMap, MeasurementValuesMap, SvnChoice};

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
