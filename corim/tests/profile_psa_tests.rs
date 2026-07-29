// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#![cfg(feature = "profile-psa")]

use corim::cbor::value::Value;
use corim::profile::psa::{is_valid_cert_num, PsaProfile, MVAL_PSA_CERT_NUM, PSA_PROFILE_URI};
use corim::profile::{MatchContext, Profile};
use corim::types::corim::ProfileChoice;
use corim::types::measurement::{MeasurementMap, MeasurementValuesMap, SvnChoice};

const VALID: &str = "1234567890123 - 12345";
const OTHER: &str = "9999999999999 - 00000";

fn measurement_with(cert_num: Option<&str>, svn: Option<u64>) -> MeasurementMap {
    let mut mval = MeasurementValuesMap::default();

    if let Some(cert_num) = cert_num {
        mval.extra_entries
            .insert(MVAL_PSA_CERT_NUM, Value::Text(cert_num.into()));
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
fn is_valid_cert_num_accepts_canonical_form() {
    assert!(is_valid_cert_num(VALID));
    assert!(is_valid_cert_num("0000000000000 - 00000"));
}

#[test]
fn is_valid_cert_num_rejects_malformed() {
    // No separator spaces.
    assert!(!is_valid_cert_num("1234567890123-12345"));
    // Too few / too many digits in each group.
    assert!(!is_valid_cert_num("123456789012 - 12345"));
    assert!(!is_valid_cert_num("12345678901234 - 12345"));
    assert!(!is_valid_cert_num("1234567890123 - 1234"));
    assert!(!is_valid_cert_num("1234567890123 - 123456"));
    // Non-digit characters.
    assert!(!is_valid_cert_num("1234567890123 - 1234a"));
    assert!(!is_valid_cert_num("a234567890123 - 12345"));
    // Wrong separator width.
    assert!(!is_valid_cert_num("1234567890123  - 12345"));
    assert!(!is_valid_cert_num("1234567890123 -  12345"));
    // Empty.
    assert!(!is_valid_cert_num(""));
}

#[test]
fn identifier_uses_psa_profile_uri() {
    let profile = PsaProfile::new();
    assert_eq!(
        profile.identifier(),
        &ProfileChoice::Uri(PSA_PROFILE_URI.into())
    );
}

#[test]
fn match_returns_none_when_reference_has_no_cert_num() {
    let profile = PsaProfile::new();
    let reference = measurement_with(None, Some(1));
    let evidence = measurement_with(Some(VALID), Some(1));

    assert_eq!(
        profile.match_measurement(&reference, &evidence, &MatchContext::new()),
        None
    );
}

#[test]
fn match_returns_false_when_evidence_missing_cert_num() {
    let profile = PsaProfile::new();
    let reference = measurement_with(Some(VALID), Some(1));
    let evidence = measurement_with(None, Some(1));

    assert_eq!(
        profile.match_measurement(&reference, &evidence, &MatchContext::new()),
        Some(false)
    );
}

#[test]
fn match_returns_true_for_equal_cert_num_and_core_fields() {
    let profile = PsaProfile::new();
    let reference = measurement_with(Some(VALID), Some(7));
    let evidence = measurement_with(Some(VALID), Some(7));

    assert_eq!(
        profile.match_measurement(&reference, &evidence, &MatchContext::new()),
        Some(true)
    );
}

#[test]
fn match_returns_false_when_core_fields_do_not_match() {
    let profile = PsaProfile::new();
    let reference = measurement_with(Some(VALID), Some(7));
    let evidence = measurement_with(Some(VALID), Some(8));

    assert_eq!(
        profile.match_measurement(&reference, &evidence, &MatchContext::new()),
        Some(false)
    );
}

#[test]
fn match_returns_false_when_cert_num_values_differ() {
    let profile = PsaProfile::new();
    let reference = measurement_with(Some(VALID), Some(1));
    let evidence = measurement_with(Some(OTHER), Some(1));

    assert_eq!(
        profile.match_measurement(&reference, &evidence, &MatchContext::new()),
        Some(false)
    );
}

#[test]
fn match_returns_false_when_cert_num_value_is_invalid() {
    let profile = PsaProfile::new();
    let reference = measurement_with(Some("not-a-cert-num"), Some(1));
    let evidence = measurement_with(Some("not-a-cert-num"), Some(1));

    assert_eq!(
        profile.match_measurement(&reference, &evidence, &MatchContext::new()),
        Some(false)
    );
}

#[test]
fn diagnose_renders_expected_labels() {
    let profile = PsaProfile::new();

    assert_eq!(
        profile.diagnose_mval_entry(MVAL_PSA_CERT_NUM, &Value::Text(VALID.into())),
        Some(format!("psa-cert-num = {VALID}"))
    );
    assert_eq!(
        profile.diagnose_mval_entry(MVAL_PSA_CERT_NUM, &Value::Text("bogus".into())),
        Some("psa-cert-num = <invalid>".into())
    );
    assert_eq!(
        profile.diagnose_mval_entry(MVAL_PSA_CERT_NUM, &Value::Integer(42)),
        Some("psa-cert-num = <invalid>".into())
    );
}

#[test]
fn diagnose_ignores_non_profile_keys() {
    let profile = PsaProfile::new();
    assert_eq!(
        profile.diagnose_mval_entry(99, &Value::Text(VALID.into())),
        None
    );
}

#[test]
fn json_alias_round_trips() {
    let profile = PsaProfile::new();
    assert_eq!(
        profile.mval_json_alias("psa-cert-num"),
        Some(MVAL_PSA_CERT_NUM)
    );
    assert_eq!(profile.mval_json_alias("tcbstatus"), None);
    assert_eq!(
        profile.mval_json_name(MVAL_PSA_CERT_NUM),
        Some("psa-cert-num")
    );
    assert_eq!(profile.mval_json_name(99), None);
}

#[test]
fn cert_num_round_trips_through_extra_entries() {
    // The core crate preserves the key-100 entry verbatim on encode/decode.
    let mval = measurement_with(Some(VALID), Some(3)).mval;
    let bytes = corim::cbor::encode(&mval).expect("encode");
    let decoded: MeasurementValuesMap = corim::cbor::decode(&bytes).expect("decode");
    assert_eq!(
        decoded.extra_entries.get(&MVAL_PSA_CERT_NUM),
        Some(&Value::Text(VALID.into()))
    );
    assert_eq!(decoded, mval);
}
