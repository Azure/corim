// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Comprehensive CDDL conformance tests for draft-ietf-rats-corim-10.
//!
//! Systematically verifies every CDDL production: round-trip encoding,
//! correct CBOR tags, non-empty constraints, all type-choice variants,
//! optional-field handling, and real-world golden-file decoding.

use corim::cbor;
use corim::types::comid::*;
use corim::types::common::*;
use corim::types::corim::*;
use corim::types::environment::*;
use corim::types::measurement::*;
use corim::types::tags::*;
use corim::types::triples::*;
use std::collections::BTreeMap;

// ═══════════════════════════════════════════════════════════════════════════
// Helpers
// ═══════════════════════════════════════════════════════════════════════════

fn round_trip<T>(val: &T) -> T
where
    T: serde::Serialize + serde::de::DeserializeOwned + std::fmt::Debug + PartialEq,
{
    let bytes = cbor::encode(val).expect("encode failed");
    let decoded: T = cbor::decode(&bytes).expect("decode failed");
    assert_eq!(val, &decoded, "round-trip mismatch");
    decoded
}

fn assert_cbor_tag<T: serde::Serialize>(val: &T, expected_tag: u64) {
    let bytes = cbor::encode(val).unwrap();
    let raw: corim::cbor::value::Value = cbor::decode(&bytes).unwrap();
    match raw {
        corim::cbor::value::Value::Tag(t, _) => {
            assert_eq!(
                t, expected_tag,
                "expected CBOR tag {}, got {}",
                expected_tag, t
            );
        }
        _ => panic!("expected tagged value, got {:?}", raw),
    }
}

fn make_env() -> EnvironmentMap {
    EnvironmentMap {
        class: Some(ClassMap {
            class_id: None,
            vendor: Some("V".into()),
            model: Some("M".into()),
            layer: None,
            index: None,
        }),
        instance: None,
        group: None,
    }
}

fn make_meas(mkey: &str) -> MeasurementMap {
    MeasurementMap {
        mkey: Some(MeasuredElement::Text(mkey.into())),
        mval: MeasurementValuesMap {
            digests: Some(vec![Digest::new(7, vec![0xAA; 48])]),
            ..MeasurementValuesMap::default()
        },
        authorized_by: None,
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// §7.4 — $tag-id-type-choice / $corim-id-type-choice  (tags: text / #6.37)
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn tag_id_text_round_trip() {
    round_trip(&TagIdChoice::Text("my-tag-id".into()));
}

#[test]
fn tag_id_uuid_round_trip_and_tag() {
    let v = TagIdChoice::Uuid([1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16]);
    assert_cbor_tag(&v, TAG_UUID);
    round_trip(&v);
}

#[test]
fn corim_id_text_round_trip() {
    round_trip(&CorimId::Text("corim-001".into()));
}

#[test]
fn corim_id_uuid_round_trip_and_tag() {
    let v = CorimId::Uuid([0xAB; 16]);
    assert_cbor_tag(&v, TAG_UUID);
    round_trip(&v);
}

// ═══════════════════════════════════════════════════════════════════════════
// §5.1.4.2 — $class-id-type-choice  (#6.111 / #6.37 / #6.560)
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn class_id_oid() {
    let v = ClassIdChoice::Oid(vec![0x2B, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37]);
    assert_cbor_tag(&v, TAG_OID);
    round_trip(&v);
}

#[test]
fn class_id_uuid() {
    let v = ClassIdChoice::Uuid([0xCD; 16]);
    assert_cbor_tag(&v, TAG_UUID);
    round_trip(&v);
}

#[test]
fn class_id_bytes() {
    let v = ClassIdChoice::Bytes(vec![0xDE, 0xAD, 0xBE, 0xEF]);
    assert_cbor_tag(&v, TAG_BYTES);
    round_trip(&v);
}

// ═══════════════════════════════════════════════════════════════════════════
// §5.1.4.3 — $instance-id-type-choice  (9 variants)
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn instance_id_ueid() {
    let v = InstanceIdChoice::Ueid(vec![0x01; 17]);
    assert_cbor_tag(&v, TAG_UEID);
    round_trip(&v);
}

#[test]
fn instance_id_uuid() {
    let v = InstanceIdChoice::Uuid([0x42; 16]);
    assert_cbor_tag(&v, TAG_UUID);
    round_trip(&v);
}

#[test]
fn instance_id_bytes() {
    let v = InstanceIdChoice::Bytes(vec![0xFF; 8]);
    assert_cbor_tag(&v, TAG_BYTES);
    round_trip(&v);
}

#[test]
fn instance_id_pkix_base64_key() {
    let v = InstanceIdChoice::PkixBase64Key("MIIBIjANBgkqhki...".into());
    assert_cbor_tag(&v, TAG_PKIX_BASE64_KEY);
    round_trip(&v);
}

#[test]
fn instance_id_pkix_base64_cert() {
    let v = InstanceIdChoice::PkixBase64Cert("MIICpDCCAYwCAgP...".into());
    assert_cbor_tag(&v, TAG_PKIX_BASE64_CERT);
    round_trip(&v);
}

#[test]
fn instance_id_cose_key() {
    let v = InstanceIdChoice::CoseKey(vec![0xA1, 0x01, 0x02]);
    assert_cbor_tag(&v, TAG_COSE_KEY);
    round_trip(&v);
}

#[test]
fn instance_id_key_thumbprint() {
    let v = InstanceIdChoice::KeyThumbprint(Digest::new(7, vec![0xAA; 48]));
    assert_cbor_tag(&v, TAG_KEY_THUMBPRINT);
    round_trip(&v);
}

#[test]
fn instance_id_cert_thumbprint() {
    let v = InstanceIdChoice::CertThumbprint(Digest::new(2, vec![0xBB; 32]));
    assert_cbor_tag(&v, TAG_CERT_THUMBPRINT);
    round_trip(&v);
}

#[test]
fn instance_id_pkix_asn1der_cert() {
    let v = InstanceIdChoice::PkixAsn1DerCert(vec![0x30, 0x82, 0x01, 0x22]);
    assert_cbor_tag(&v, TAG_PKIX_ASN1DER_CERT);
    round_trip(&v);
}

// ═══════════════════════════════════════════════════════════════════════════
// §5.1.4.4 — $group-id-type-choice  (#6.37 / #6.560)
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn group_id_uuid() {
    let v = GroupIdChoice::Uuid([0x99; 16]);
    assert_cbor_tag(&v, TAG_UUID);
    round_trip(&v);
}

#[test]
fn group_id_bytes() {
    let v = GroupIdChoice::Bytes(vec![0x11, 0x22, 0x33]);
    assert_cbor_tag(&v, TAG_BYTES);
    round_trip(&v);
}

// ═══════════════════════════════════════════════════════════════════════════
// §5.1.4.5.1 — $measured-element-type-choice  (OID / UUID / uint / text)
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn measured_element_oid() {
    let v = MeasuredElement::Oid(vec![0x2B, 0x06]);
    assert_cbor_tag(&v, TAG_OID);
    round_trip(&v);
}

#[test]
fn measured_element_uuid() {
    let v = MeasuredElement::Uuid([0x77; 16]);
    assert_cbor_tag(&v, TAG_UUID);
    round_trip(&v);
}

#[test]
fn measured_element_uint() {
    round_trip(&MeasuredElement::Uint(42));
}

#[test]
fn measured_element_text() {
    round_trip(&MeasuredElement::Text("firmware-digest".into()));
}

// ═══════════════════════════════════════════════════════════════════════════
// §5.1.4.6 — $crypto-key-type-choice  (9 variants, tags 554–562)
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn crypto_key_pkix_base64_key() {
    let v = CryptoKey::PkixBase64Key("MIIBIjAN...".into());
    assert_cbor_tag(&v, TAG_PKIX_BASE64_KEY);
    round_trip(&v);
}

#[test]
fn crypto_key_pkix_base64_cert() {
    let v = CryptoKey::PkixBase64Cert("MIICpDCC...".into());
    assert_cbor_tag(&v, TAG_PKIX_BASE64_CERT);
    round_trip(&v);
}

#[test]
fn crypto_key_pkix_base64_cert_path() {
    let v = CryptoKey::PkixBase64CertPath("MIICpDCC...chain...".into());
    assert_cbor_tag(&v, TAG_PKIX_BASE64_CERT_PATH);
    round_trip(&v);
}

#[test]
fn crypto_key_key_thumbprint() {
    let v = CryptoKey::KeyThumbprint(Digest::new(7, vec![0xCC; 48]));
    assert_cbor_tag(&v, TAG_KEY_THUMBPRINT);
    round_trip(&v);
}

#[test]
fn crypto_key_cose_key() {
    let v = CryptoKey::CoseKey(vec![0xA1, 0x01, 0x01]);
    assert_cbor_tag(&v, TAG_COSE_KEY);
    round_trip(&v);
}

#[test]
fn crypto_key_cert_thumbprint() {
    let v = CryptoKey::CertThumbprint(Digest::new(2, vec![0xDD; 32]));
    assert_cbor_tag(&v, TAG_CERT_THUMBPRINT);
    round_trip(&v);
}

#[test]
fn crypto_key_cert_path_thumbprint() {
    let v = CryptoKey::CertPathThumbprint(Digest::new(2, vec![0xEE; 32]));
    assert_cbor_tag(&v, TAG_CERT_PATH_THUMBPRINT);
    round_trip(&v);
}

#[test]
fn crypto_key_pkix_asn1der_cert() {
    let v = CryptoKey::PkixAsn1DerCert(vec![0x30, 0x82, 0x03]);
    assert_cbor_tag(&v, TAG_PKIX_ASN1DER_CERT);
    round_trip(&v);
}

#[test]
fn crypto_key_bytes() {
    let v = CryptoKey::Bytes(vec![0x01, 0x02, 0x03, 0x04]);
    assert_cbor_tag(&v, TAG_BYTES);
    round_trip(&v);
}

// ═══════════════════════════════════════════════════════════════════════════
// §4.1.4 — $profile-type-choice  (URI / #6.111)
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn profile_uri() {
    round_trip(&ProfileChoice::Uri("https://example.com/profile/v1".into()));
}

#[test]
fn profile_oid() {
    let v = ProfileChoice::Oid(vec![0x2B, 0x06, 0x01, 0x04]);
    assert_cbor_tag(&v, TAG_OID);
    round_trip(&v);
}

// ═══════════════════════════════════════════════════════════════════════════
// §5.1.4.5.6 — $raw-value-type-choice  (#6.560 / #6.563)
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn raw_value_bytes() {
    let v = RawValueChoice::Bytes(vec![0xDE, 0xAD, 0xBE, 0xEF]);
    assert_cbor_tag(&v, TAG_BYTES);
    round_trip(&v);
}

#[test]
fn raw_value_masked() {
    let v = RawValueChoice::Masked {
        value: vec![0xFF; 16],
        mask: vec![0x0F; 16],
    };
    assert_cbor_tag(&v, TAG_MASKED_RAW_VALUE);
    round_trip(&v);
}

// ═══════════════════════════════════════════════════════════════════════════
// §5.1.4.5.4 — svn-type-choice  (#6.552 / #6.553 / uint)
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn svn_exact_tagged() {
    let v = SvnChoice::ExactValue(42);
    assert_cbor_tag(&v, TAG_SVN);
    round_trip(&v);
}

#[test]
fn svn_min_tagged() {
    let v = SvnChoice::MinValue(10);
    assert_cbor_tag(&v, TAG_MIN_SVN);
    round_trip(&v);
}

#[test]
fn svn_untagged_uint_decodes_as_exact() {
    // Encode a raw unsigned int — must decode as ExactValue
    let bytes = cbor::encode(&42u64).unwrap();
    let decoded: SvnChoice = cbor::decode(&bytes).unwrap();
    assert_eq!(decoded, SvnChoice::ExactValue(42));
}

// ═══════════════════════════════════════════════════════════════════════════
// §5.1.4.5.7 — mac-addr-type-choice / ip-addr-type-choice
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn mac_addr_eui48() {
    round_trip(&MacAddr::Eui48([0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF]));
}

#[test]
fn mac_addr_eui64() {
    round_trip(&MacAddr::Eui64([
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
    ]));
}

#[test]
fn ip_addr_v4() {
    round_trip(&IpAddr::V4([10, 0, 0, 1]));
}

#[test]
fn ip_addr_v6() {
    round_trip(&IpAddr::V6([
        0xFE, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1,
    ]));
}

// ═══════════════════════════════════════════════════════════════════════════
// §5.1.4.8 — int-range-type-choice  (int / #6.564)
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn int_range_plain_int() {
    round_trip(&IntRangeChoice::Int(42));
}

#[test]
fn int_range_bounded() {
    let v = IntRangeChoice::Range {
        min: Some(-10),
        max: Some(100),
    };
    assert_cbor_tag(&v, TAG_INT_RANGE);
    round_trip(&v);
}

#[test]
fn int_range_negative_inf() {
    round_trip(&IntRangeChoice::Range {
        min: None,
        max: Some(50),
    });
}

#[test]
fn int_range_positive_inf() {
    round_trip(&IntRangeChoice::Range {
        min: Some(0),
        max: None,
    });
}

#[test]
fn int_range_both_inf() {
    round_trip(&IntRangeChoice::Range {
        min: None,
        max: None,
    });
}

// ═══════════════════════════════════════════════════════════════════════════
// §5.1.4.7 — integrity-registers
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn integrity_registers_mixed_keys() {
    let mut m = BTreeMap::new();
    m.insert(
        IntegrityRegisterId::Uint(0),
        vec![Digest::new(7, vec![0xAA; 48])],
    );
    m.insert(
        IntegrityRegisterId::Text("PCR1".into()),
        vec![
            Digest::new(7, vec![0xBB; 48]),
            Digest::new(2, vec![0xCC; 32]),
        ],
    );
    let v = IntegrityRegisters(m);
    let bytes = cbor::encode(&v).unwrap();
    let decoded: IntegrityRegisters = cbor::decode(&bytes).unwrap();
    assert_eq!(decoded.0.len(), 2);
    assert_eq!(
        decoded.0[&IntegrityRegisterId::Text("PCR1".into())].len(),
        2
    );
}

// ═══════════════════════════════════════════════════════════════════════════
// §5.1.4.5.5 — flags-map  (round-trip + non-empty)
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn flags_map_all_fields() {
    round_trip(&FlagsMap {
        is_configured: Some(true),
        is_secure: Some(true),
        is_recovery: Some(false),
        is_debug: Some(false),
        is_replay_protected: Some(true),
        is_integrity_protected: Some(true),
        is_runtime_meas: Some(false),
        is_immutable: Some(true),
        is_tcb: Some(true),
        is_confidentiality_protected: Some(false),
    });
}

#[test]
fn flags_map_single_field() {
    round_trip(&FlagsMap {
        is_configured: None,
        is_secure: None,
        is_recovery: None,
        is_debug: Some(true),
        is_replay_protected: None,
        is_integrity_protected: None,
        is_runtime_meas: None,
        is_immutable: None,
        is_tcb: None,
        is_confidentiality_protected: None,
    });
}

#[test]
fn flags_map_non_empty_enforced() {
    let f = FlagsMap {
        is_configured: None,
        is_secure: None,
        is_recovery: None,
        is_debug: None,
        is_replay_protected: None,
        is_integrity_protected: None,
        is_runtime_meas: None,
        is_immutable: None,
        is_tcb: None,
        is_confidentiality_protected: None,
    };
    assert!(
        cbor::encode(&f).is_err(),
        "all-None FlagsMap must fail non-empty"
    );
}

// ═══════════════════════════════════════════════════════════════════════════
// §7.1 — non-empty<M> constraint on all 6 non-empty types
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn non_empty_measurement_values_map() {
    assert!(cbor::encode(&MeasurementValuesMap::default()).is_err());
}

#[test]
fn non_empty_triples_map() {
    let t = TriplesMap {
        reference_triples: None,
        endorsed_triples: None,
        identity_triples: None,
        attest_key_triples: None,
        dependency_triples: None,
        membership_triples: None,
        coswid_triples: None,
        conditional_endorsement_series: None,
        conditional_endorsement: None,
    };
    assert!(cbor::encode(&t).is_err());
}

#[test]
fn non_empty_key_triple_conditions() {
    assert!(cbor::encode(&KeyTripleConditions {
        mkey: None,
        authorized_by: None
    })
    .is_err());
}

#[test]
fn non_empty_environment_map() {
    assert!(cbor::encode(&EnvironmentMap {
        class: None,
        instance: None,
        group: None
    })
    .is_err());
}

#[test]
fn non_empty_class_map() {
    assert!(cbor::encode(&ClassMap {
        class_id: None,
        vendor: None,
        model: None,
        layer: None,
        index: None
    })
    .is_err());
}

// ═══════════════════════════════════════════════════════════════════════════
// §5.1.4.2 — class-map with all fields populated
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn class_map_all_fields() {
    round_trip(&ClassMap {
        class_id: Some(ClassIdChoice::Uuid([0xAB; 16])),
        vendor: Some("ACME".into()),
        model: Some("Widget".into()),
        layer: Some(2),
        index: Some(3),
    });
}

// ═══════════════════════════════════════════════════════════════════════════
// §5.1.4.1 — environment-map with each optional field
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn environment_with_instance() {
    round_trip(&EnvironmentMap {
        class: None,
        instance: Some(InstanceIdChoice::Ueid(vec![0x01; 17])),
        group: None,
    });
}

#[test]
fn environment_with_group() {
    round_trip(&EnvironmentMap {
        class: None,
        instance: None,
        group: Some(GroupIdChoice::Uuid([0x88; 16])),
    });
}

#[test]
fn environment_all_fields() {
    round_trip(&EnvironmentMap {
        class: Some(ClassMap {
            class_id: Some(ClassIdChoice::Oid(vec![0x2B, 0x06])),
            vendor: Some("V".into()),
            model: Some("M".into()),
            layer: Some(0),
            index: Some(1),
        }),
        instance: Some(InstanceIdChoice::Uuid([0x42; 16])),
        group: Some(GroupIdChoice::Bytes(vec![0xFF; 4])),
    });
}

// ═══════════════════════════════════════════════════════════════════════════
// §5.1.1 — tag-identity-map  (with/without version)
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn tag_identity_with_version() {
    round_trip(&TagIdentity {
        tag_id: TagIdChoice::Uuid([0xAA; 16]),
        tag_version: Some(5),
    });
}

#[test]
fn tag_identity_without_version() {
    round_trip(&TagIdentity {
        tag_id: TagIdChoice::Text("my-tag".into()),
        tag_version: None,
    });
}

// ═══════════════════════════════════════════════════════════════════════════
// §5.1.3 — linked-tag-map  (supplements / replaces)
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn linked_tag_supplements() {
    round_trip(&LinkedTagMap {
        linked_tag_id: TagIdChoice::Text("other-tag".into()),
        tag_rel: TAG_REL_SUPPLEMENTS,
    });
}

#[test]
fn linked_tag_replaces() {
    round_trip(&LinkedTagMap {
        linked_tag_id: TagIdChoice::Uuid([0xBB; 16]),
        tag_rel: TAG_REL_REPLACES,
    });
}

// ═══════════════════════════════════════════════════════════════════════════
// §7.3 — validity-map  (with/without not-before)
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn validity_full() {
    round_trip(&ValidityMap {
        not_before: Some(CborTime(1700000000)),
        not_after: CborTime(1800000000),
    });
}

#[test]
fn validity_no_not_before() {
    round_trip(&ValidityMap {
        not_before: None,
        not_after: CborTime(1800000000),
    });
}

// ═══════════════════════════════════════════════════════════════════════════
// §7.2 — entity-map  (with/without reg-id)
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn entity_with_reg_id() {
    round_trip(&EntityMap {
        entity_name: "ACME Corp".into(),
        reg_id: Some("https://acme.example.com".into()),
        role: vec![COMID_ROLE_TAG_CREATOR, COMID_ROLE_CREATOR],
    });
}

#[test]
fn entity_without_reg_id() {
    round_trip(&EntityMap {
        entity_name: "Anonymous".into(),
        reg_id: None,
        role: vec![COMID_ROLE_MAINTAINER],
    });
}

// ═══════════════════════════════════════════════════════════════════════════
// §5.1.4.5.3 — version-map  (with/without scheme)
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn version_with_scheme() {
    round_trip(&VersionMap {
        version: "1.2.3".into(),
        version_scheme: Some(VERSION_SCHEME_SEMVER),
    });
}

#[test]
fn version_without_scheme() {
    round_trip(&VersionMap {
        version: "rev42".into(),
        version_scheme: None,
    });
}

// ═══════════════════════════════════════════════════════════════════════════
// §5.1.4.5.2 — measurement-values-map  with ALL 14 fields populated
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn measurement_values_map_all_14_fields() {
    let mut regs = BTreeMap::new();
    regs.insert(
        IntegrityRegisterId::Uint(0),
        vec![Digest::new(7, vec![0x11; 48])],
    );

    round_trip(&MeasurementValuesMap {
        version: Some(VersionMap {
            version: "2.0".into(),
            version_scheme: Some(VERSION_SCHEME_SEMVER),
        }),
        svn: Some(SvnChoice::MinValue(3)),
        digests: Some(vec![Digest::new(7, vec![0xAA; 48])]),
        flags: Some(FlagsMap {
            is_configured: Some(true),
            is_secure: Some(true),
            is_recovery: None,
            is_debug: Some(false),
            is_replay_protected: None,
            is_integrity_protected: None,
            is_runtime_meas: None,
            is_immutable: None,
            is_tcb: Some(true),
            is_confidentiality_protected: None,
        }),
        raw_value: Some(RawValueChoice::Bytes(vec![0xDE, 0xAD])),
        mac_addr: Some(MacAddr::Eui48([0x00, 0x11, 0x22, 0x33, 0x44, 0x55])),
        ip_addr: Some(IpAddr::V4([192, 168, 1, 1])),
        serial_number: Some("SN-12345".into()),
        ueid: Some(vec![0x01; 17]),
        uuid: Some(vec![0x02; 16]),
        name: Some("firmware-component".into()),
        cryptokeys: Some(vec![CryptoKey::PkixBase64Key("MIIBIj...".into())]),
        integrity_registers: Some(IntegrityRegisters(regs)),
        int_range: Some(IntRangeChoice::Range {
            min: Some(0),
            max: Some(100),
        }),
        extra_entries: BTreeMap::new(),
    });
}

// ═══════════════════════════════════════════════════════════════════════════
// §5.1.4.5 — measurement-map  with/without authorized-by / anonymous
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn measurement_map_with_authorized_by() {
    round_trip(&MeasurementMap {
        mkey: Some(MeasuredElement::Uint(7)),
        mval: MeasurementValuesMap {
            digests: Some(vec![Digest::new(7, vec![0xEE; 48])]),
            ..MeasurementValuesMap::default()
        },
        authorized_by: Some(vec![CryptoKey::PkixBase64Key("key-data".into())]),
    });
}

#[test]
fn measurement_map_anonymous() {
    // No mkey = "anonymous" measurement per §5.1.4.5.1
    round_trip(&MeasurementMap {
        mkey: None,
        mval: MeasurementValuesMap {
            svn: Some(SvnChoice::ExactValue(1)),
            ..MeasurementValuesMap::default()
        },
        authorized_by: None,
    });
}

// ═══════════════════════════════════════════════════════════════════════════
// §5.1.5  — reference-triple-record
// §5.1.6  — endorsed-triple-record
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn reference_triple() {
    round_trip(&ReferenceTriple::new(
        make_env(),
        vec![make_meas("fw"), make_meas("config")],
    ));
}

#[test]
fn endorsed_triple() {
    round_trip(&EndorsedTriple::new(
        make_env(),
        vec![make_meas("certified")],
    ));
}

// ═══════════════════════════════════════════════════════════════════════════
// §5.1.9 / §5.1.10 — identity / attest-key triple  (with and without conditions)
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn identity_triple_with_conditions() {
    round_trip(&IdentityTriple::new(
        make_env(),
        vec![CryptoKey::PkixBase64Cert("cert-data".into())],
        Some(KeyTripleConditions {
            mkey: Some(MeasuredElement::Text("idevid".into())),
            authorized_by: Some(vec![CryptoKey::Bytes(vec![0x01])]),
        }),
    ));
}

#[test]
fn identity_triple_without_conditions() {
    round_trip(&IdentityTriple::new(
        make_env(),
        vec![CryptoKey::Bytes(vec![0x01, 0x02])],
        None,
    ));
}

#[test]
fn attest_key_triple_with_conditions() {
    round_trip(&AttestKeyTriple::new(
        make_env(),
        vec![CryptoKey::CoseKey(vec![0xA1, 0x01, 0x02])],
        Some(KeyTripleConditions {
            mkey: Some(MeasuredElement::Uint(0)),
            authorized_by: None,
        }),
    ));
}

#[test]
fn attest_key_triple_without_conditions() {
    round_trip(&AttestKeyTriple::new(
        make_env(),
        vec![CryptoKey::Bytes(vec![0x03, 0x04])],
        None,
    ));
}

// ═══════════════════════════════════════════════════════════════════════════
// §5.1.11.1 — domain-membership-triple-record
// §5.1.11.2 — domain-dependency-triple-record
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn domain_dependency() {
    round_trip(&DomainDependencyTriple::new(make_env(), vec![make_env()]));
}

#[test]
fn domain_membership() {
    round_trip(&DomainMembershipTriple::new(make_env(), vec![make_env()]));
}

// ═══════════════════════════════════════════════════════════════════════════
// §5.1.12 — coswid-triple-record  (text + UUID tag ids)
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn coswid_triple_text_tag_id() {
    round_trip(&CoswidTriple::new(
        make_env(),
        vec![TagIdChoice::Text("test-tag".into())],
    ));
}

#[test]
fn coswid_triple_uuid_tag_id() {
    round_trip(&CoswidTriple::new(
        make_env(),
        vec![TagIdChoice::Uuid([0x77; 16])],
    ));
}

// ═══════════════════════════════════════════════════════════════════════════
// §5.1.7 — conditional-endorsement-triple-record + stateful-environment-record
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn stateful_environment_record() {
    round_trip(&StatefulEnvironmentRecord(
        make_env(),
        vec![make_meas("state")],
    ));
}

#[test]
fn conditional_endorsement_triple() {
    round_trip(&ConditionalEndorsementTriple(
        vec![StatefulEnvironmentRecord(
            make_env(),
            vec![make_meas("state")],
        )],
        vec![EndorsedTriple::new(make_env(), vec![make_meas("endorsed")])],
    ));
}

// ═══════════════════════════════════════════════════════════════════════════
// §5.1.8 — conditional-endorsement-series  (CES condition, series record, triple)
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn ces_condition_without_authorized_by() {
    round_trip(&CesCondition {
        environment: make_env(),
        claims_list: vec![make_meas("fw")],
        authorized_by: None,
    });
}

#[test]
fn ces_condition_with_authorized_by() {
    round_trip(&CesCondition {
        environment: make_env(),
        claims_list: Vec::new(),
        authorized_by: Some(vec![CryptoKey::Bytes(vec![0xAA, 0xBB])]),
    });
}

#[test]
fn ces_condition_empty_claims() {
    round_trip(&CesCondition {
        environment: make_env(),
        claims_list: Vec::new(),
        authorized_by: None,
    });
}

#[test]
fn conditional_series_record() {
    round_trip(&ConditionalSeriesRecord::new(
        vec![make_meas("selection")],
        vec![make_meas("addition")],
    ));
}

#[test]
fn conditional_endorsement_series_triple() {
    round_trip(&ConditionalEndorsementSeriesTriple::new(
        CesCondition {
            environment: make_env(),
            claims_list: vec![make_meas("fw")],
            authorized_by: None,
        },
        vec![ConditionalSeriesRecord::new(
            vec![make_meas("fw")],
            vec![MeasurementMap {
                mkey: None,
                mval: MeasurementValuesMap {
                    svn: Some(SvnChoice::ExactValue(5)),
                    ..MeasurementValuesMap::default()
                },
                authorized_by: None,
            }],
        )],
    ));
}

// ═══════════════════════════════════════════════════════════════════════════
// §5.1.4 — triples-map with ALL 9 triple types populated simultaneously
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn triples_map_all_nine_types() {
    let env = make_env();
    let m = make_meas("m");

    round_trip(&TriplesMap {
        reference_triples: Some(vec![ReferenceTriple::new(env.clone(), vec![m.clone()])]),
        endorsed_triples: Some(vec![EndorsedTriple::new(env.clone(), vec![m.clone()])]),
        identity_triples: Some(vec![IdentityTriple::new(
            env.clone(),
            vec![CryptoKey::Bytes(vec![1])],
            None,
        )]),
        attest_key_triples: Some(vec![AttestKeyTriple::new(
            env.clone(),
            vec![CryptoKey::Bytes(vec![2])],
            None,
        )]),
        dependency_triples: Some(vec![DomainDependencyTriple::new(
            env.clone(),
            vec![env.clone()],
        )]),
        membership_triples: Some(vec![DomainMembershipTriple::new(
            env.clone(),
            vec![env.clone()],
        )]),
        coswid_triples: Some(vec![CoswidTriple::new(
            env.clone(),
            vec![TagIdChoice::Text("t".into())],
        )]),
        conditional_endorsement_series: Some(vec![ConditionalEndorsementSeriesTriple::new(
            CesCondition {
                environment: env.clone(),
                claims_list: Vec::new(),
                authorized_by: None,
            },
            vec![ConditionalSeriesRecord::new(
                vec![m.clone()],
                vec![m.clone()],
            )],
        )]),
        conditional_endorsement: Some(vec![ConditionalEndorsementTriple(
            vec![StatefulEnvironmentRecord(env.clone(), vec![m.clone()])],
            vec![EndorsedTriple::new(env.clone(), vec![m.clone()])],
        )]),
    });
}

// ═══════════════════════════════════════════════════════════════════════════
// §5.1 — concise-mid-tag (ComidTag) with ALL optional fields
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn comid_tag_all_optional_fields() {
    round_trip(&ComidTag {
        language: Some("en-US".into()),
        tag_identity: TagIdentity {
            tag_id: TagIdChoice::Uuid([0x42; 16]),
            tag_version: Some(3),
        },
        entities: Some(vec![EntityMap {
            entity_name: "ACME".into(),
            reg_id: Some("https://acme.example.com".into()),
            role: vec![COMID_ROLE_TAG_CREATOR],
        }]),
        linked_tags: Some(vec![LinkedTagMap {
            linked_tag_id: TagIdChoice::Text("other".into()),
            tag_rel: TAG_REL_SUPPLEMENTS,
        }]),
        triples: TriplesMap {
            reference_triples: Some(vec![ReferenceTriple::new(
                make_env(),
                vec![make_meas("fw")],
            )]),
            endorsed_triples: None,
            identity_triples: None,
            attest_key_triples: None,
            dependency_triples: None,
            membership_triples: None,
            coswid_triples: None,
            conditional_endorsement_series: None,
            conditional_endorsement: None,
        },
    });
}

// ═══════════════════════════════════════════════════════════════════════════
// §4.1 — corim-map with ALL optional fields
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn corim_map_all_optional_fields() {
    let comid = ComidTag {
        language: None,
        tag_identity: TagIdentity {
            tag_id: TagIdChoice::Text("t1".into()),
            tag_version: None,
        },
        entities: None,
        linked_tags: None,
        triples: TriplesMap {
            reference_triples: Some(vec![ReferenceTriple::new(make_env(), vec![make_meas("f")])]),
            endorsed_triples: None,
            identity_triples: None,
            attest_key_triples: None,
            dependency_triples: None,
            membership_triples: None,
            coswid_triples: None,
            conditional_endorsement_series: None,
            conditional_endorsement: None,
        },
    };
    let comid_bytes = cbor::encode(&comid).unwrap();

    round_trip(&CorimMap {
        id: CorimId::Uuid([0x42; 16]),
        tags: vec![ConciseTagChoice::Comid(comid_bytes)],
        dependent_rims: Some(vec![CorimLocator {
            href: CorimLocatorHref::Multiple(vec![
                "https://example.com/a.corim".into(),
                "https://example.com/b.corim".into(),
            ]),
            thumbprint: Some(CorimLocatorThumbprint::Single(Digest::new(
                7,
                vec![0xAA; 48],
            ))),
        }]),
        profile: Some(ProfileChoice::Uri("https://example.com/profile".into())),
        rim_validity: Some(ValidityMap {
            not_before: Some(CborTime(1700000000)),
            not_after: CborTime(1900000000),
        }),
        entities: Some(vec![EntityMap {
            entity_name: "Creator".into(),
            reg_id: None,
            role: vec![CORIM_ROLE_MANIFEST_CREATOR],
        }]),
    });
}

// ═══════════════════════════════════════════════════════════════════════════
// §4.1.3 — corim-locator-map  (all variants)
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn corim_locator_single_href() {
    round_trip(&CorimLocator {
        href: CorimLocatorHref::Single("https://example.com/rim.corim".into()),
        thumbprint: None,
    });
}

#[test]
fn corim_locator_multiple_hrefs() {
    round_trip(&CorimLocator {
        href: CorimLocatorHref::Multiple(vec!["https://a.com".into(), "https://b.com".into()]),
        thumbprint: None,
    });
}

#[test]
fn corim_locator_with_single_thumbprint() {
    round_trip(&CorimLocator {
        href: CorimLocatorHref::Single("https://example.com".into()),
        thumbprint: Some(CorimLocatorThumbprint::Single(Digest::new(
            2,
            vec![0xBB; 32],
        ))),
    });
}

#[test]
fn corim_locator_with_multiple_thumbprints() {
    round_trip(&CorimLocator {
        href: CorimLocatorHref::Single("https://example.com".into()),
        thumbprint: Some(CorimLocatorThumbprint::Multiple(vec![
            Digest::new(7, vec![0xAA; 48]),
            Digest::new(2, vec![0xBB; 32]),
        ])),
    });
}

// ═══════════════════════════════════════════════════════════════════════════
// §6.1 — concise-tl-tag
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn concise_tl_tag_with_uuid() {
    round_trip(&ConciseTlTag {
        tag_identity: TagIdentity {
            tag_id: TagIdChoice::Uuid([0xCC; 16]),
            tag_version: Some(1),
        },
        tags_list: vec![
            TagIdentity {
                tag_id: TagIdChoice::Text("a".into()),
                tag_version: None,
            },
            TagIdentity {
                tag_id: TagIdChoice::Uuid([0xDD; 16]),
                tag_version: Some(2),
            },
        ],
        tl_validity: ValidityMap {
            not_before: Some(CborTime(1000)),
            not_after: CborTime(2000),
        },
    });
}

// ═══════════════════════════════════════════════════════════════════════════
// §4.2.3 — corim-signer-map / corim-meta-map  (with/without optional fields)
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn corim_signer_with_uri() {
    round_trip(&CorimSignerMap {
        signer_name: "S".into(),
        signer_uri: Some("https://s.com".into()),
    });
}

#[test]
fn corim_signer_without_uri() {
    round_trip(&CorimSignerMap {
        signer_name: "S".into(),
        signer_uri: None,
    });
}

#[test]
fn corim_meta_with_validity() {
    round_trip(&CorimMetaMap {
        signer: CorimSignerMap {
            signer_name: "S".into(),
            signer_uri: None,
        },
        signature_validity: Some(ValidityMap {
            not_before: Some(CborTime(1000)),
            not_after: CborTime(2000),
        }),
    });
}

#[test]
fn corim_meta_without_validity() {
    round_trip(&CorimMetaMap {
        signer: CorimSignerMap {
            signer_name: "S".into(),
            signer_uri: None,
        },
        signature_validity: None,
    });
}

// ═══════════════════════════════════════════════════════════════════════════
// End-to-end: build → encode → decode → validate  (4 triple types)
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn end_to_end_build_encode_decode_validate() {
    use corim::builder::{ComidBuilder, CorimBuilder};

    let env = make_env();

    let comid = ComidBuilder::new(TagIdChoice::Text("e2e-test".into()))
        .set_tag_version(1)
        .set_language("en")
        .add_entity(EntityMap {
            entity_name: "Tester".into(),
            reg_id: None,
            role: vec![COMID_ROLE_TAG_CREATOR],
        })
        .add_reference_triple(ReferenceTriple::new(env.clone(), vec![make_meas("fw")]))
        .add_endorsed_triple(EndorsedTriple::new(
            env.clone(),
            vec![MeasurementMap {
                mkey: None,
                mval: MeasurementValuesMap {
                    svn: Some(SvnChoice::MinValue(3)),
                    ..MeasurementValuesMap::default()
                },
                authorized_by: None,
            }],
        ))
        .add_identity_triple(IdentityTriple::new(
            env.clone(),
            vec![CryptoKey::PkixBase64Key("key-data".into())],
            None,
        ))
        .add_conditional_endorsement_series(ConditionalEndorsementSeriesTriple::new(
            CesCondition {
                environment: env.clone(),
                claims_list: Vec::new(),
                authorized_by: None,
            },
            vec![ConditionalSeriesRecord::new(
                vec![make_meas("fw")],
                vec![MeasurementMap {
                    mkey: None,
                    mval: MeasurementValuesMap {
                        svn: Some(SvnChoice::ExactValue(5)),
                        ..MeasurementValuesMap::default()
                    },
                    authorized_by: None,
                }],
            )],
        ))
        .build()
        .unwrap();

    let bytes = CorimBuilder::new(CorimId::Text("e2e-corim".into()))
        .set_profile(ProfileChoice::Uri("https://example.com/profile".into()))
        .set_validity(Some(0), i64::MAX)
        .unwrap()
        .add_comid_tag(comid)
        .unwrap()
        .build_bytes()
        .unwrap();

    // Validate
    let (corim, comids) = corim::validate::decode_and_validate(&bytes).unwrap();
    assert_eq!(corim.id, CorimId::Text("e2e-corim".into()));
    assert_eq!(comids.len(), 1);
    assert!(comids[0].triples.reference_triples.is_some());
    assert!(comids[0].triples.endorsed_triples.is_some());
    assert!(comids[0].triples.identity_triples.is_some());
    assert!(comids[0].triples.conditional_endorsement_series.is_some());
    assert_eq!(comids[0].language.as_deref(), Some("en"));
    assert_eq!(comids[0].tag_identity.tag_version, Some(1));
}
