// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#![cfg(feature = "profile-cca")]

use corim::profile::cca::{
    is_cca_platform_mkey, is_cca_realm_mkey, CcaPlatformProfile, CcaRealmProfile,
    CCA_PLATFORM_PROFILE_URI, CCA_REALM_PROFILE_URI,
};
use corim::profile::{MatchContext, Profile};
use corim::types::common::{ClassIdChoice, CryptoKey, InstanceIdChoice, MeasuredElement};
use corim::types::corim::ProfileChoice;
use corim::types::environment::{ClassMap, EnvironmentMap};
use corim::types::measurement::{Digest, MeasurementMap, MeasurementValuesMap, RawValueChoice};
use corim::types::triples::ReferenceTriple;
use corim::validate::{match_reference_values_with_profile, EvidenceClaim};

fn measurement_with_mkey(mkey: &str, digest_val: &[u8]) -> MeasurementMap {
    MeasurementMap {
        mkey: Some(MeasuredElement::Text(mkey.into())),
        mval: MeasurementValuesMap {
            digests: Some(vec![Digest::new_text("sha-256", digest_val.to_vec())]),
            ..MeasurementValuesMap::default()
        },
        authorized_by: None,
    }
}

fn software_component_measurement(name: &str, digest_val: &[u8], signer: &[u8]) -> MeasurementMap {
    MeasurementMap {
        mkey: Some(MeasuredElement::Text(name.into())),
        mval: MeasurementValuesMap {
            digests: Some(vec![Digest::new_text("sha-256", digest_val.to_vec())]),
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

fn masked_raw_value_measurement(mkey: &str, value: &[u8], mask: &[u8]) -> MeasurementMap {
    MeasurementMap {
        mkey: Some(MeasuredElement::Text(mkey.into())),
        mval: MeasurementValuesMap {
            raw_value: Some(RawValueChoice::Masked {
                value: value.to_vec(),
                mask: mask.to_vec(),
            }),
            ..MeasurementValuesMap::default()
        },
        authorized_by: None,
    }
}

fn environment_with_class_id(class_id: &[u8]) -> EnvironmentMap {
    EnvironmentMap {
        class: Some(ClassMap {
            class_id: Some(ClassIdChoice::Bytes(class_id.to_vec())),
            ..ClassMap::default()
        }),
        instance: None,
        group: None,
    }
}

/// Platform triples are keyed by a 32-byte Implementation ID
/// (draft-ydb-rats-cca-endorsements-04 §3.1.2).
fn platform_environment() -> EnvironmentMap {
    environment_with_class_id(&[0x5A; 32])
}

/// Realm triples carry the RIM itself as `class-id`
/// (draft-ydb-rats-cca-endorsements-04 §3.2.2).
fn realm_environment(rim: &[u8]) -> EnvironmentMap {
    environment_with_class_id(rim)
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
    assert!(!is_cca_platform_mkey("cca.rotpk.CM.02.3"));
    assert!(!is_cca_platform_mkey("cca.rotpk.CM.2.03"));
}

#[test]
fn recognized_realm_mkeys_include_rim_rem_and_rpv() {
    assert!(is_cca_realm_mkey("cca.rim"));
    assert!(is_cca_realm_mkey("cca.rem0"));
    assert!(is_cca_realm_mkey("cca.rem3"));
    assert!(is_cca_realm_mkey("cca.rpv"));
    assert!(!is_cca_realm_mkey("cca.rem10"));
    assert!(!is_cca_realm_mkey("cca.rem00"));
}

#[test]
fn platform_match_accepts_same_cca_mkey_and_same_core_values() {
    let profile = CcaPlatformProfile::new();
    let reference =
        software_component_measurement("cca.software-component", &[0x11; 32], &[0xAA; 32]);
    let evidence =
        software_component_measurement("cca.software-component", &[0x11; 32], &[0xAA; 32]);

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
fn platform_match_defers_for_non_cca_mkey() {
    let profile = CcaPlatformProfile::new();
    let reference = measurement_with_mkey("tee.something", &[0x11, 0x22, 0x33]);
    let evidence = measurement_with_mkey("tee.something", &[0x11, 0x22, 0x33]);

    assert_eq!(
        profile.match_measurement(&reference, &evidence, &MatchContext::new()),
        None
    );
}

#[test]
fn platform_match_rejects_invalid_cca_structures() {
    let profile = CcaPlatformProfile::new();
    let reference = measurement_with_mkey("cca.rotpk.CM.2.3", &[0x11, 0x22, 0x33]);
    let evidence = raw_value_measurement("cca.rotpk.CM.2.3", &[0xAA; 32]);

    assert_eq!(
        profile.match_measurement(&reference, &evidence, &MatchContext::new()),
        Some(false)
    );
}

#[test]
fn platform_match_accepts_rotpk_reference_against_raw_value_evidence() {
    let profile = CcaPlatformProfile::new();
    let reference = rotpk_measurement("cca.rotpk.CM.2.3", &[0xAA; 32]);
    let evidence = raw_value_measurement("cca.rotpk.CM.2.3", &[0xAA; 32]);

    assert_eq!(
        profile.match_measurement(&reference, &evidence, &MatchContext::new()),
        Some(true)
    );
}

#[test]
fn platform_match_rejects_different_software_component_signer_id() {
    let profile = CcaPlatformProfile::new();
    let reference =
        software_component_measurement("cca.software-component", &[0x11; 32], &[0xAA; 32]);
    let evidence =
        software_component_measurement("cca.software-component", &[0x11; 32], &[0xBB; 32]);

    assert_eq!(
        profile.match_measurement(&reference, &evidence, &MatchContext::new()),
        Some(false)
    );
}

#[test]
fn platform_match_rejects_different_rotpk_key() {
    let profile = CcaPlatformProfile::new();
    let reference = rotpk_measurement("cca.rotpk.CM.2.3", &[0xAA; 32]);
    let evidence = raw_value_measurement("cca.rotpk.CM.2.3", &[0xBB; 32]);

    assert_eq!(
        profile.match_measurement(&reference, &evidence, &MatchContext::new()),
        Some(false)
    );
}

#[test]
fn platform_match_accepts_masked_config_reference_against_unmasked_evidence() {
    let profile = CcaPlatformProfile::new();
    let reference =
        masked_raw_value_measurement("cca.platform-config", &[0xA0, 0x05], &[0xF0, 0x00]);
    let evidence = raw_value_measurement("cca.platform-config", &[0xAF, 0xFF]);

    assert_eq!(
        profile.match_measurement(&reference, &evidence, &MatchContext::new()),
        Some(true)
    );
}

#[test]
fn platform_match_rejects_masked_config_evidence() {
    let profile = CcaPlatformProfile::new();
    let reference =
        masked_raw_value_measurement("cca.platform-config", &[0xA0, 0x05], &[0xF0, 0x00]);
    let evidence =
        masked_raw_value_measurement("cca.platform-config", &[0xAF, 0xFF], &[0xFF, 0xFF]);

    assert_eq!(
        profile.match_measurement(&reference, &evidence, &MatchContext::new()),
        Some(false)
    );
}

fn platform_evidence() -> Vec<EvidenceClaim> {
    vec![EvidenceClaim {
        environment: platform_environment(),
        measurements: vec![
            software_component_measurement("cca.software-component", &[0x11; 32], &[0xAA; 32]),
            raw_value_measurement("cca.platform-config", &[0xAF, 0xFF]),
        ],
    }]
}

fn platform_claims(profile: &CcaPlatformProfile, measurements: Vec<MeasurementMap>) -> usize {
    let triples = vec![ReferenceTriple::new(platform_environment(), measurements)];

    match_reference_values_with_profile(
        &triples,
        &platform_evidence(),
        Some(profile),
        &MatchContext::new(),
    )
    .len()
}

#[test]
fn platform_profile_accepts_complete_reference_triple() {
    let profile = CcaPlatformProfile::new();

    assert_eq!(
        platform_claims(
            &profile,
            vec![
                software_component_measurement("cca.software-component", &[0x11; 32], &[0xAA; 32]),
                masked_raw_value_measurement("cca.platform-config", &[0xA0, 0x05], &[0xF0, 0x00]),
            ],
        ),
        1
    );
}

#[test]
fn platform_profile_rejects_duplicate_config_measurements() {
    let profile = CcaPlatformProfile::new();
    let config = masked_raw_value_measurement("cca.platform-config", &[0xA0, 0x05], &[0xF0, 0x00]);

    assert_eq!(
        platform_claims(
            &profile,
            vec![
                software_component_measurement("cca.software-component", &[0x11; 32], &[0xAA; 32]),
                config.clone(),
                config,
            ],
        ),
        0
    );
}

#[test]
fn platform_profile_rejects_triple_without_platform_config() {
    let profile = CcaPlatformProfile::new();

    assert_eq!(
        platform_claims(
            &profile,
            vec![software_component_measurement(
                "cca.software-component",
                &[0x11; 32],
                &[0xAA; 32]
            )],
        ),
        0
    );
}

#[test]
fn platform_profile_rejects_triple_without_software_component() {
    let profile = CcaPlatformProfile::new();

    assert_eq!(
        platform_claims(
            &profile,
            vec![masked_raw_value_measurement(
                "cca.platform-config",
                &[0xA0, 0x05],
                &[0xF0, 0x00]
            )],
        ),
        0
    );
}

#[test]
fn platform_profile_rejects_triple_without_cca_measurements() {
    let profile = CcaPlatformProfile::new();

    assert_eq!(
        platform_claims(
            &profile,
            vec![measurement_with_mkey("tee.something", &[0x11; 32])],
        ),
        0
    );
}

#[test]
fn platform_profile_accepts_standalone_rotpk_triple() {
    let profile = CcaPlatformProfile::new();
    let rotpk = rotpk_measurement("cca.rotpk.CM.2.3", &[0xAA; 32]);
    let triples = vec![ReferenceTriple::new(
        platform_environment(),
        vec![rotpk.clone()],
    )];
    let evidence = vec![EvidenceClaim {
        environment: platform_environment(),
        measurements: vec![raw_value_measurement("cca.rotpk.CM.2.3", &[0xAA; 32])],
    }];

    let claims = match_reference_values_with_profile(
        &triples,
        &evidence,
        Some(&profile),
        &MatchContext::new(),
    );

    assert_eq!(claims.len(), 1);
}

#[test]
fn platform_profile_accepts_rotpk_triple_for_one_array_entry() {
    let profile = CcaPlatformProfile::new();
    let first = rotpk_measurement("cca.rotpk.CM.2.0", &[0xAA; 32]);
    let second = rotpk_measurement("cca.rotpk.CM.2.1", &[0xBB; 32]);
    let triples = vec![ReferenceTriple::new(
        platform_environment(),
        vec![first.clone(), second.clone()],
    )];
    let evidence = vec![EvidenceClaim {
        environment: platform_environment(),
        measurements: vec![
            raw_value_measurement("cca.rotpk.CM.2.0", &[0xAA; 32]),
            raw_value_measurement("cca.rotpk.CM.2.1", &[0xBB; 32]),
        ],
    }];

    let claims = match_reference_values_with_profile(
        &triples,
        &evidence,
        Some(&profile),
        &MatchContext::new(),
    );

    assert_eq!(claims.len(), 1);
    assert_eq!(claims[0].measurements.len(), 2);
}

#[test]
fn platform_profile_rejects_rotpk_mixed_array_entries() {
    let profile = CcaPlatformProfile::new();
    let first = rotpk_measurement("cca.rotpk.CM.2.0", &[0xAA; 32]);
    let second = rotpk_measurement("cca.rotpk.CM.3.0", &[0xBB; 32]);
    let third = rotpk_measurement("cca.rotpk.DM.2.1", &[0xCC; 32]);

    for measurements in [vec![first.clone(), second], vec![first.clone(), third]] {
        let triples = vec![ReferenceTriple::new(
            platform_environment(),
            measurements.clone(),
        )];
        let evidence = vec![EvidenceClaim {
            environment: platform_environment(),
            measurements,
        }];

        let claims = match_reference_values_with_profile(
            &triples,
            &evidence,
            Some(&profile),
            &MatchContext::new(),
        );

        assert!(claims.is_empty());
    }
}

#[test]
fn platform_profile_rejects_rotpk_mixed_with_unknown_measurement() {
    let profile = CcaPlatformProfile::new();
    let rotpk = rotpk_measurement("cca.rotpk.CM.2.0", &[0xAA; 32]);
    let triples = vec![ReferenceTriple::new(
        platform_environment(),
        vec![rotpk, measurement_with_mkey("tee.something", &[0x11; 32])],
    )];
    let evidence = vec![EvidenceClaim {
        environment: platform_environment(),
        measurements: vec![raw_value_measurement("cca.rotpk.CM.2.0", &[0xAA; 32])],
    }];

    let claims = match_reference_values_with_profile(
        &triples,
        &evidence,
        Some(&profile),
        &MatchContext::new(),
    );

    assert!(claims.is_empty());
}

#[test]
fn platform_profile_rejects_rotpk_mixed_with_platform_measurements() {
    let profile = CcaPlatformProfile::new();

    assert_eq!(
        platform_claims(
            &profile,
            vec![
                software_component_measurement("cca.software-component", &[0x11; 32], &[0xAA; 32]),
                masked_raw_value_measurement("cca.platform-config", &[0xA0, 0x05], &[0xF0, 0x00]),
                rotpk_measurement("cca.rotpk.CM.2.3", &[0xAA; 32]),
            ],
        ),
        0
    );
}

#[test]
fn platform_profile_rejects_triple_without_implementation_id() {
    let profile = CcaPlatformProfile::new();
    let triples = vec![ReferenceTriple::new(
        EnvironmentMap::for_class("ACME", "Platform"),
        vec![
            software_component_measurement("cca.software-component", &[0x11; 32], &[0xAA; 32]),
            masked_raw_value_measurement("cca.platform-config", &[0xA0, 0x05], &[0xF0, 0x00]),
        ],
    )];
    let evidence = vec![EvidenceClaim {
        environment: EnvironmentMap::for_class("ACME", "Platform"),
        measurements: platform_evidence().remove(0).measurements,
    }];

    let claims = match_reference_values_with_profile(
        &triples,
        &evidence,
        Some(&profile),
        &MatchContext::new(),
    );

    assert!(claims.is_empty());
}

#[test]
fn platform_profile_rejects_triple_with_non_ueid_instance() {
    let profile = CcaPlatformProfile::new();
    let mut environment = platform_environment();
    environment.instance = Some(InstanceIdChoice::Bytes(vec![0x01; 32]));
    let triples = vec![ReferenceTriple::new(
        environment.clone(),
        vec![
            software_component_measurement("cca.software-component", &[0x11; 32], &[0xAA; 32]),
            masked_raw_value_measurement("cca.platform-config", &[0xA0, 0x05], &[0xF0, 0x00]),
        ],
    )];
    let evidence = vec![EvidenceClaim {
        environment,
        measurements: platform_evidence().remove(0).measurements,
    }];

    let claims = match_reference_values_with_profile(
        &triples,
        &evidence,
        Some(&profile),
        &MatchContext::new(),
    );

    assert!(claims.is_empty());
}

#[test]
fn platform_profile_rejects_malformed_reference_measurement_in_triple() {
    let profile = CcaPlatformProfile::new();
    let mut malformed_software_component =
        software_component_measurement("cca.software-component", &[0x11; 32], &[0xAA; 32]);
    malformed_software_component.mval.cryptokeys = None;

    assert_eq!(
        platform_claims(
            &profile,
            vec![
                malformed_software_component,
                masked_raw_value_measurement("cca.platform-config", &[0xA0, 0x05], &[0xF0, 0x00]),
            ],
        ),
        0
    );
}

#[test]
fn platform_match_rejects_unmasked_config_reference() {
    let profile = CcaPlatformProfile::new();
    let reference = raw_value_measurement("cca.platform-config", &[0xAA, 0xBB]);
    let evidence = raw_value_measurement("cca.platform-config", &[0xAA, 0xBB]);

    assert_eq!(
        profile.match_measurement(&reference, &evidence, &MatchContext::new()),
        Some(false)
    );
}

#[test]
fn platform_match_rejects_software_component_digest_with_integer_alg() {
    let profile = CcaPlatformProfile::new();
    let reference = MeasurementMap {
        mkey: Some(MeasuredElement::Text("cca.software-component".into())),
        mval: MeasurementValuesMap {
            digests: Some(vec![Digest::new(7, vec![0x11; 32])]),
            cryptokeys: Some(vec![CryptoKey::Bytes(vec![0xAA; 32])]),
            ..MeasurementValuesMap::default()
        },
        authorized_by: None,
    };
    let evidence =
        software_component_measurement("cca.software-component", &[0x11; 32], &[0xAA; 32]);

    assert_eq!(
        profile.match_measurement(&reference, &evidence, &MatchContext::new()),
        Some(false)
    );
}

#[test]
fn platform_match_rejects_software_component_extra_mval_field() {
    let profile = CcaPlatformProfile::new();
    let mut reference =
        software_component_measurement("cca.software-component", &[0x11; 32], &[0xAA; 32]);
    reference.mval.raw_value = Some(RawValueChoice::Bytes(vec![0xCC; 32]));
    let evidence =
        software_component_measurement("cca.software-component", &[0x11; 32], &[0xAA; 32]);

    assert_eq!(
        profile.match_measurement(&reference, &evidence, &MatchContext::new()),
        Some(false)
    );
}

#[test]
fn platform_match_rejects_rotpk_extra_mval_field() {
    let profile = CcaPlatformProfile::new();
    let mut reference = rotpk_measurement("cca.rotpk.CM.2.3", &[0xAA; 32]);
    reference.mval.raw_value = Some(RawValueChoice::Bytes(vec![0xCC; 32]));
    let evidence = raw_value_measurement("cca.rotpk.CM.2.3", &[0xAA; 32]);

    assert_eq!(
        profile.match_measurement(&reference, &evidence, &MatchContext::new()),
        Some(false)
    );
}

#[test]
fn platform_match_rejects_multiple_software_component_signer_ids() {
    let profile = CcaPlatformProfile::new();
    let mut reference =
        software_component_measurement("cca.software-component", &[0x11; 32], &[0xAA; 32]);
    reference
        .mval
        .cryptokeys
        .as_mut()
        .unwrap()
        .push(CryptoKey::Bytes(vec![0xBB; 32]));
    let evidence =
        software_component_measurement("cca.software-component", &[0x11; 32], &[0xAA; 32]);

    assert_eq!(
        profile.match_measurement(&reference, &evidence, &MatchContext::new()),
        Some(false)
    );
}

#[test]
fn platform_match_rejects_authorized_by() {
    let profile = CcaPlatformProfile::new();
    let mut reference = rotpk_measurement("cca.rotpk.CM.2.3", &[0xAA; 32]);
    reference.authorized_by = Some(vec![CryptoKey::Bytes(vec![0xCC; 32])]);
    let evidence = raw_value_measurement("cca.rotpk.CM.2.3", &[0xAA; 32]);

    assert_eq!(
        profile.match_measurement(&reference, &evidence, &MatchContext::new()),
        Some(false)
    );
}

#[test]
fn realm_match_rejects_raw_value_violation() {
    let profile = CcaRealmProfile::new();
    let reference = raw_value_measurement("cca.rpv", &[0xAA; 64]);
    let evidence = measurement_with_mkey("cca.rpv", b"def");

    assert_eq!(
        profile.match_measurement(&reference, &evidence, &MatchContext::new()),
        Some(false)
    );
}

#[test]
fn realm_match_rejects_short_rpv() {
    let profile = CcaRealmProfile::new();
    let reference = raw_value_measurement("cca.rpv", b"abc");
    let evidence = raw_value_measurement("cca.rpv", b"abc");

    assert_eq!(
        profile.match_measurement(&reference, &evidence, &MatchContext::new()),
        Some(false)
    );
}

fn realm_claims(
    profile: &CcaRealmProfile,
    environment: EnvironmentMap,
    measurements: Vec<MeasurementMap>,
) -> usize {
    let triples = vec![ReferenceTriple::new(
        environment.clone(),
        measurements.clone(),
    )];
    let evidence = vec![EvidenceClaim {
        environment,
        measurements,
    }];

    match_reference_values_with_profile(&triples, &evidence, Some(profile), &MatchContext::new())
        .len()
}

#[test]
fn realm_profile_rejects_reference_triple_without_mandatory_rim() {
    let profile = CcaRealmProfile::new();

    assert_eq!(
        realm_claims(
            &profile,
            realm_environment(&[0xAA; 32]),
            vec![measurement_with_mkey("cca.rem0", &[0x11; 32])],
        ),
        0
    );
}

#[test]
fn realm_profile_rejects_reference_triple_without_cca_measurements() {
    let profile = CcaRealmProfile::new();

    assert_eq!(
        realm_claims(
            &profile,
            realm_environment(&[0xAA; 32]),
            vec![measurement_with_mkey("tee.something", &[0x11; 32])],
        ),
        0
    );
}

#[test]
fn realm_profile_accepts_reference_triple_with_mandatory_rim() {
    let profile = CcaRealmProfile::new();
    let rim_value = [0xAA; 32];

    assert_eq!(
        realm_claims(
            &profile,
            realm_environment(&rim_value),
            vec![
                measurement_with_mkey("cca.rim", &rim_value),
                measurement_with_mkey("cca.rem0", &[0x11; 32]),
            ],
        ),
        1
    );
}

#[test]
fn realm_profile_rejects_rim_that_disagrees_with_environment_class_id() {
    let profile = CcaRealmProfile::new();

    assert_eq!(
        realm_claims(
            &profile,
            realm_environment(&[0xAA; 32]),
            vec![measurement_with_mkey("cca.rim", &[0xBB; 32])],
        ),
        0
    );
}

#[test]
fn realm_profile_rejects_reference_triple_without_rim_class_id() {
    let profile = CcaRealmProfile::new();

    assert_eq!(
        realm_claims(
            &profile,
            EnvironmentMap::for_class("ACME", "Realm"),
            vec![measurement_with_mkey("cca.rim", &[0xAA; 32])],
        ),
        0
    );
}

#[test]
fn realm_profile_rejects_duplicate_realm_measurements() {
    let profile = CcaRealmProfile::new();
    let rim_value = [0xAA; 32];
    let rem = measurement_with_mkey("cca.rem0", &[0x11; 32]);

    assert_eq!(
        realm_claims(
            &profile,
            realm_environment(&rim_value),
            vec![
                measurement_with_mkey("cca.rim", &rim_value),
                rem.clone(),
                rem,
            ],
        ),
        0
    );
}

#[test]
fn realm_profile_rejects_malformed_rim_in_reference_triple() {
    let profile = CcaRealmProfile::new();
    let rim_value = [0xAA; 32];
    let mut rim = measurement_with_mkey("cca.rim", &rim_value);
    rim.authorized_by = Some(vec![CryptoKey::Bytes(vec![0xCC; 32])]);

    assert_eq!(
        realm_claims(
            &profile,
            realm_environment(&rim_value),
            vec![rim, measurement_with_mkey("cca.rem0", &[0x11; 32])],
        ),
        0
    );
}

#[test]
fn realm_match_rejects_masked_rpv() {
    let profile = CcaRealmProfile::new();
    let reference = masked_raw_value_measurement("cca.rpv", &[0xAA; 32], &[0xFF; 32]);
    let evidence = raw_value_measurement("cca.rpv", &[0xAA; 32]);

    assert_eq!(
        profile.match_measurement(&reference, &evidence, &MatchContext::new()),
        Some(false)
    );
}

#[test]
fn realm_match_rejects_rim_extra_mval_field() {
    let profile = CcaRealmProfile::new();
    let mut reference = measurement_with_mkey("cca.rim", &[0xAA; 32]);
    reference.mval.raw_value = Some(RawValueChoice::Bytes(vec![0xCC; 32]));
    let evidence = measurement_with_mkey("cca.rim", &[0xAA; 32]);

    assert_eq!(
        profile.match_measurement(&reference, &evidence, &MatchContext::new()),
        Some(false)
    );
}

#[test]
fn realm_match_defers_for_non_cca_mkey() {
    let profile = CcaRealmProfile::new();
    let reference = measurement_with_mkey("tee.something", &[0x11, 0x22, 0x33]);
    let evidence = measurement_with_mkey("tee.something", &[0x11, 0x22, 0x33]);

    assert_eq!(
        profile.match_measurement(&reference, &evidence, &MatchContext::new()),
        None
    );
}

#[test]
fn realm_match_rejects_authorized_by() {
    let profile = CcaRealmProfile::new();
    let reference = measurement_with_mkey("cca.rim", &[0x11, 0x22, 0x33]);
    let mut evidence = measurement_with_mkey("cca.rim", &[0x11, 0x22, 0x33]);
    evidence.authorized_by = Some(vec![CryptoKey::Bytes(vec![0xCC; 32])]);

    assert_eq!(
        profile.match_measurement(&reference, &evidence, &MatchContext::new()),
        Some(false)
    );
}

#[test]
fn diagnosis_does_not_treat_mkeys_as_mval_extensions() {
    let profile = CcaPlatformProfile::new();
    assert_eq!(
        profile.diagnose_mval_entry(
            -999,
            &corim::cbor::value::Value::Text("cca.software-component".into())
        ),
        None
    );
}
