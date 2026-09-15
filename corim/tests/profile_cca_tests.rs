// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#![cfg(feature = "profile-cca")]

use corim::cbor::value::Value;
use corim::profile::cca::{
    is_cca_platform_mkey, is_cca_realm_mkey, CcaPlatformProfile, CcaRealmProfile,
    CCA_PLATFORM_PROFILE_URI, CCA_REALM_PROFILE_URI,
};
use corim::profile::{MatchContext, Profile};
use corim::types::common::{CryptoKey, MeasuredElement};
use corim::types::corim::ProfileChoice;
use corim::types::measurement::{Digest, MeasurementMap, MeasurementValuesMap, RawValueChoice};

fn measurement_with_mkey(mkey: &str, digest_val: &[u8]) -> MeasurementMap {
    MeasurementMap {
        mkey: Some(MeasuredElement::Text(mkey.into())),
        mval: MeasurementValuesMap {
            digests: Some(vec![Digest::new(7, digest_val.to_vec())]),
            ..MeasurementValuesMap::default()
        },
        authorized_by: None,
    }
}

fn software_component_measurement(name: &str, digest_val: &[u8], signer: &[u8]) -> MeasurementMap {
    MeasurementMap {
        mkey: Some(MeasuredElement::Text(name.into())),
        mval: MeasurementValuesMap {
            digests: Some(vec![Digest::new(7, digest_val.to_vec())]),
            cryptokeys: Some(vec![CryptoKey::Bytes(signer.to_vec())]),
            ..MeasurementValuesMap::default()
        },
        authorized_by: None,
    }
}

fn rotpk_measurement(mkey: &str, key_bytes: &[u8]) -> MeasurementMap {
    MeasurementMap {
        mkey: Some(MeasuredElement::Text(mkey.into())),
        mval: MeasurementValuesMap {
            cryptokeys: Some(vec![CryptoKey::Bytes(key_bytes.to_vec())]),
            ..MeasurementValuesMap::default()
        },
        authorized_by: None,
    }
}

fn raw_value_measurement(mkey: &str, value: &[u8]) -> MeasurementMap {
    MeasurementMap {
        mkey: Some(MeasuredElement::Text(mkey.into())),
        mval: MeasurementValuesMap {
            raw_value: Some(RawValueChoice::Bytes(value.to_vec())),
            ..MeasurementValuesMap::default()
        },
        authorized_by: None,
    }
}

#[test]
fn platform_profile_uses_cca_platform_uri() {
    let profile = CcaPlatformProfile::new();
    assert_eq!(
        profile.identifier(),
        &ProfileChoice::Uri(CCA_PLATFORM_PROFILE_URI.into())
    );
}

#[test]
fn realm_profile_uses_cca_realm_uri() {
    let profile = CcaRealmProfile::new();
    assert_eq!(
        profile.identifier(),
        &ProfileChoice::Uri(CCA_REALM_PROFILE_URI.into())
    );
}

#[test]
fn recognized_platform_mkeys_include_software_component_and_config() {
    assert!(is_cca_platform_mkey("cca.software-component"));
    assert!(is_cca_platform_mkey("cca.platform-config"));
    assert!(is_cca_platform_mkey("cca.rotpk.CM.2.3"));
    assert!(is_cca_platform_mkey("cca.rotpk.DM.7.5"));
    assert!(is_cca_platform_mkey("cca.platform-manufacturing-config"));
    assert!(!is_cca_platform_mkey("cca.unknown"));
    assert!(!is_cca_platform_mkey("cca.rotpk.CM.8.0"));
    assert!(!is_cca_platform_mkey("cca.rotpk.CM.2.6"));
}

#[test]
fn recognized_realm_mkeys_include_rim_rem_and_rpv() {
    assert!(is_cca_realm_mkey("cca.rim"));
    assert!(is_cca_realm_mkey("cca.rem0"));
    assert!(is_cca_realm_mkey("cca.rem3"));
    assert!(is_cca_realm_mkey("cca.rpv"));
    assert!(!is_cca_realm_mkey("cca.rem10"));
}

#[test]
fn platform_match_accepts_same_cca_mkey_and_same_core_values() {
    let profile = CcaPlatformProfile::new();
    let reference =
        software_component_measurement("cca.software-component", &[0x11, 0x22, 0x33], &[0xAA; 32]);
    let evidence =
        software_component_measurement("cca.software-component", &[0x11, 0x22, 0x33], &[0xAA; 32]);

    assert_eq!(
        profile.match_measurement(&reference, &evidence, &MatchContext::new()),
        Some(true)
    );
}

#[test]
fn platform_match_rejects_mkey_mismatch() {
    let profile = CcaPlatformProfile::new();
    let reference = measurement_with_mkey("cca.software-component", &[0x11, 0x22, 0x33]);
    let evidence = measurement_with_mkey("cca.platform-config", &[0x11, 0x22, 0x33]);

    assert_eq!(
        profile.match_measurement(&reference, &evidence, &MatchContext::new()),
        Some(false)
    );
}

#[test]
fn platform_match_rejects_invalid_cca_structures() {
    let profile = CcaPlatformProfile::new();
    let reference = measurement_with_mkey("cca.software-component", &[0x11, 0x22, 0x33]);
    let evidence = rotpk_measurement("cca.rotpk.CM.2.3", &[0xAA; 32]);

    assert_eq!(
        profile.match_measurement(&reference, &evidence, &MatchContext::new()),
        Some(false)
    );
}

#[test]
fn realm_match_rejects_raw_value_violation() {
    let profile = CcaRealmProfile::new();
    let reference = raw_value_measurement("cca.rpv", b"abc");
    let evidence = measurement_with_mkey("cca.rpv", b"def");

    assert_eq!(
        profile.match_measurement(&reference, &evidence, &MatchContext::new()),
        Some(false)
    );
}

#[test]
fn diagnosis_uses_cca_names_for_known_platform_mkeys() {
    let profile = CcaPlatformProfile::new();
    let key = Value::Text("cca.software-component".into());
    assert_eq!(
        profile.diagnose_mval_entry(0, &key),
        Some("cca.software-component = cca.software-component".into())
    );
    assert_eq!(profile.diagnose_mval_entry(99, &Value::Integer(42)), None);
}
