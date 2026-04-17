// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Tests to boost code coverage toward the 80% target.
//!
//! This file targets the lowest-coverage modules identified by cargo-llvm-cov:
//! - cbor/minimal_backend/value_ser.rs (41%)
//! - json/value_conv.rs (47%)
//! - types/common.rs (69%)
//! - types/triples.rs (69%)
//! - types/measurement.rs (72%)
//! - types/corim.rs (72%)
//! - cbor/value/mod.rs (59%)
//! - cbor/minimal_backend/value_de.rs (68%)

use corim::cbor;
use corim::cbor::value::Value;
use corim::types::common::*;
use corim::types::corim::*;
use corim::types::environment::*;
use corim::types::measurement::*;
use corim::types::triples::*;
use corim::Validate;

// ===========================================================================
// cbor::value::Value — into_* failure paths + to_value/from_value
// ===========================================================================

#[test]
fn value_into_integer_failure() {
    assert!(Value::Text("hello".into()).into_integer().is_none());
    assert!(Value::Bool(true).into_integer().is_none());
    assert!(Value::Null.into_integer().is_none());
}

#[test]
fn value_into_bytes_failure() {
    assert!(Value::Integer(42).into_bytes().is_none());
    assert!(Value::Text("hello".into()).into_bytes().is_none());
}

#[test]
fn value_into_text_failure() {
    assert!(Value::Integer(42).into_text().is_none());
    assert!(Value::Bytes(vec![1, 2]).into_text().is_none());
}

#[test]
fn value_into_array_failure() {
    assert!(Value::Integer(42).into_array().is_none());
    assert!(Value::Text("x".into()).into_array().is_none());
}

#[test]
fn value_into_tag_failure() {
    assert!(Value::Integer(42).into_tag().is_none());
    assert!(Value::Array(vec![]).into_tag().is_none());
}

#[test]
fn value_into_tag_success() {
    let v = Value::Tag(37, Box::new(Value::Bytes(vec![0; 16])));
    let (tag, inner) = v.into_tag().unwrap();
    assert_eq!(tag, 37);
    assert!(matches!(inner, Value::Bytes(_)));
}

#[test]
fn value_to_from_value_round_trip() {
    use corim::cbor::value::{from_value, to_value};
    let class = ClassMap::new("ACME", "Widget");
    let v = to_value(&class).unwrap();
    assert!(matches!(v, Value::Map(_)));
    let decoded: ClassMap = from_value(&v).unwrap();
    assert_eq!(class, decoded);
}

// ===========================================================================
// value_ser.rs — exercise serde Serializer methods
// ===========================================================================

#[test]
fn value_ser_bool_round_trip() {
    let bytes = cbor::encode(&true).unwrap();
    let v: bool = cbor::decode(&bytes).unwrap();
    assert!(v);
}

#[test]
fn value_ser_floats() {
    let bytes = cbor::encode(&core::f64::consts::PI).unwrap();
    let v: f64 = cbor::decode(&bytes).unwrap();
    assert!((v - core::f64::consts::PI).abs() < 0.001);

    let bytes32 = cbor::encode(&2.5f32).unwrap();
    let v32: f64 = cbor::decode(&bytes32).unwrap();
    assert!((v32 - 2.5).abs() < 0.001);
}

#[test]
fn value_ser_various_integers() {
    // i8, i16, i32
    let b = cbor::encode(&(-1i8)).unwrap();
    assert_eq!(cbor::decode::<i64>(&b).unwrap(), -1);

    let b = cbor::encode(&(300i16)).unwrap();
    assert_eq!(cbor::decode::<i64>(&b).unwrap(), 300);

    let b = cbor::encode(&(100000i32)).unwrap();
    assert_eq!(cbor::decode::<i64>(&b).unwrap(), 100000);

    // u8, u16, u32
    let b = cbor::encode(&(255u8)).unwrap();
    assert_eq!(cbor::decode::<u64>(&b).unwrap(), 255);

    let b = cbor::encode(&(65535u16)).unwrap();
    assert_eq!(cbor::decode::<u64>(&b).unwrap(), 65535);

    let b = cbor::encode(&(4000000000u32)).unwrap();
    assert_eq!(cbor::decode::<u64>(&b).unwrap(), 4000000000);
}

#[test]
fn value_ser_option_some_none() {
    let some_val: Option<u32> = Some(42);
    let none_val: Option<u32> = None;

    let bytes_some = cbor::encode(&some_val).unwrap();
    let bytes_none = cbor::encode(&none_val).unwrap();

    let decoded_some: Option<u32> = cbor::decode(&bytes_some).unwrap();
    let decoded_none: Option<u32> = cbor::decode(&bytes_none).unwrap();

    assert_eq!(decoded_some, Some(42));
    assert_eq!(decoded_none, None);
}

#[test]
fn value_ser_string_and_bytes() {
    let s = "hello world";
    let bytes = cbor::encode(&s).unwrap();
    let decoded: String = cbor::decode(&bytes).unwrap();
    assert_eq!(decoded, s);
}

#[test]
fn value_ser_nested_structures() {
    // Vec<Vec<u32>> — exercises serialize_seq nesting
    let nested: Vec<Vec<u32>> = vec![vec![1, 2], vec![3, 4, 5]];
    let bytes = cbor::encode(&nested).unwrap();
    let decoded: Vec<Vec<u32>> = cbor::decode(&bytes).unwrap();
    assert_eq!(nested, decoded);
}

// ===========================================================================
// value_de.rs — exercise deserializer paths
// ===========================================================================

#[test]
fn value_de_negative_i64() {
    // Negative number that requires i64
    let v = Value::Integer(i64::MIN as i128);
    let bytes = cbor::encode(&v).unwrap();
    let decoded: Value = cbor::decode(&bytes).unwrap();
    assert_eq!(decoded, Value::Integer(i64::MIN as i128));
}

#[test]
fn value_de_float_round_trip_via_value() {
    let v = Value::Float(core::f64::consts::E);
    let bytes = cbor::encode(&v).unwrap();
    let decoded: Value = cbor::decode(&bytes).unwrap();
    if let Value::Float(f) = decoded {
        assert!((f - core::f64::consts::E).abs() < 0.001);
    } else {
        panic!("expected float");
    }
}

#[test]
fn value_de_null_round_trip() {
    let v = Value::Null;
    let bytes = cbor::encode(&v).unwrap();
    let decoded: Value = cbor::decode(&bytes).unwrap();
    assert_eq!(decoded, Value::Null);
}

#[test]
fn value_de_bool_round_trip() {
    for b in [true, false] {
        let v = Value::Bool(b);
        let bytes = cbor::encode(&v).unwrap();
        let decoded: Value = cbor::decode(&bytes).unwrap();
        assert_eq!(decoded, Value::Bool(b));
    }
}

#[test]
fn value_de_bytes_via_deserialize_bytes() {
    // Bytes round-trip through Value
    let v = Value::Bytes(vec![0xDE, 0xAD, 0xBE, 0xEF]);
    let bytes = cbor::encode(&v).unwrap();
    let decoded: Value = cbor::decode(&bytes).unwrap();
    assert_eq!(decoded, Value::Bytes(vec![0xDE, 0xAD, 0xBE, 0xEF]));
}

#[test]
fn value_de_tag_round_trip_via_value() {
    let v = Value::Tag(42, Box::new(Value::Text("hello".into())));
    let bytes = cbor::encode(&v).unwrap();
    let decoded: Value = cbor::decode(&bytes).unwrap();
    assert_eq!(
        decoded,
        Value::Tag(42, Box::new(Value::Text("hello".into())))
    );
}

#[test]
fn value_de_map_with_text_keys() {
    let entries = vec![
        (Value::Text("a".into()), Value::Integer(1)),
        (Value::Text("b".into()), Value::Integer(2)),
    ];
    let v = Value::Map(entries.clone());
    let bytes = cbor::encode(&v).unwrap();
    let decoded: Value = cbor::decode(&bytes).unwrap();
    assert_eq!(decoded, Value::Map(entries));
}

// ===========================================================================
// Display impls — types/common.rs
// ===========================================================================

#[test]
fn display_tag_id_choice() {
    let text = TagIdChoice::Text("my-tag".into());
    assert_eq!(format!("{}", text), "my-tag");

    let uuid = TagIdChoice::Uuid([
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
        0x10,
    ]);
    let s = format!("{}", uuid);
    assert!(s.contains("01020304"));
    assert!(s.contains("-"));
}

#[test]
fn display_class_id_choice() {
    let oid = ClassIdChoice::Oid(vec![0x06, 0x03, 0x55, 0x04, 0x03]);
    assert!(format!("{}", oid).starts_with("oid:"));

    let uuid = ClassIdChoice::Uuid([0xAA; 16]);
    assert!(format!("{}", uuid).contains("aaaaaaaa"));

    let bytes = ClassIdChoice::Bytes(vec![1, 2, 3]);
    assert!(format!("{}", bytes).starts_with("bytes:"));
}

#[test]
fn display_instance_id_choice() {
    let ueid = InstanceIdChoice::Ueid(vec![0x02; 10]);
    assert!(format!("{}", ueid).starts_with("ueid:"));

    let uuid = InstanceIdChoice::Uuid([0xBB; 16]);
    assert!(format!("{}", uuid).contains("bbbbbbbb"));

    let bytes_id = InstanceIdChoice::Bytes(vec![0xFF; 4]);
    assert!(format!("{}", bytes_id).starts_with("bytes:"));

    let pkix_key = InstanceIdChoice::PkixBase64Key("MIIBIjANBg...".into());
    assert!(format!("{}", pkix_key).starts_with("pkix-key:"));

    let pkix_cert = InstanceIdChoice::PkixBase64Cert("MIIC...".into());
    assert!(format!("{}", pkix_cert).starts_with("pkix-cert:"));

    let cose_key = InstanceIdChoice::CoseKey(vec![0xA0, 0x01]);
    assert!(format!("{}", cose_key).contains("cose-key:"));

    let kt = InstanceIdChoice::KeyThumbprint(Digest::new(7, vec![0xCC; 32]));
    assert!(format!("{}", kt).starts_with("key-tp:"));

    let ct = InstanceIdChoice::CertThumbprint(Digest::new(7, vec![0xDD; 32]));
    assert!(format!("{}", ct).starts_with("cert-tp:"));

    let asn1 = InstanceIdChoice::PkixAsn1DerCert(vec![0x30; 100]);
    assert!(format!("{}", asn1).starts_with("asn1-cert:"));
}

#[test]
fn display_group_id_choice() {
    let uuid = GroupIdChoice::Uuid([0xCC; 16]);
    assert!(format!("{}", uuid).contains("cccccccc"));

    let bytes = GroupIdChoice::Bytes(vec![1, 2, 3, 4]);
    assert!(format!("{}", bytes).starts_with("bytes:"));
}

#[test]
fn display_measured_element() {
    let oid = MeasuredElement::Oid(vec![0x06, 0x01]);
    assert!(format!("{}", oid).starts_with("oid:"));

    let uuid = MeasuredElement::Uuid([0xDD; 16]);
    assert!(format!("{}", uuid).contains("dddddddd"));

    let uint = MeasuredElement::Uint(42);
    assert_eq!(format!("{}", uint), "42");

    let text = MeasuredElement::Text("firmware".into());
    assert_eq!(format!("{}", text), "firmware");
}

#[test]
fn display_crypto_key_all_variants() {
    assert!(format!("{}", CryptoKey::PkixBase64Key("key...".into())).starts_with("pkix-key:"));
    assert!(format!("{}", CryptoKey::PkixBase64Cert("cert...".into())).starts_with("pkix-cert:"));
    assert!(
        format!("{}", CryptoKey::PkixBase64CertPath("path...".into()))
            .starts_with("pkix-cert-path:")
    );
    assert!(
        format!("{}", CryptoKey::KeyThumbprint(Digest::new(1, vec![0; 32]))).starts_with("key-tp:")
    );
    assert!(format!("{}", CryptoKey::CoseKey(vec![0xA1])).starts_with("cose-key:"));
    assert!(
        format!("{}", CryptoKey::CertThumbprint(Digest::new(1, vec![0; 32])))
            .starts_with("cert-tp:")
    );
    assert!(format!(
        "{}",
        CryptoKey::CertPathThumbprint(Digest::new(1, vec![0; 32]))
    )
    .starts_with("cert-path-tp:"));
    assert!(format!("{}", CryptoKey::PkixAsn1DerCert(vec![0x30; 50])).starts_with("asn1-cert:"));
    assert!(format!("{}", CryptoKey::Bytes(vec![1, 2, 3])).starts_with("bytes:"));
}

#[test]
fn display_corim_id() {
    let text = CorimId::Text("my-corim".into());
    assert_eq!(format!("{}", text), "my-corim");

    let uuid = CorimId::Uuid([0xAA; 16]);
    assert!(format!("{}", uuid).contains("aaaaaaaa"));
}

#[test]
fn display_profile_choice() {
    let uri = ProfileChoice::Uri("https://example.com".into());
    assert_eq!(format!("{}", uri), "https://example.com");

    let oid = ProfileChoice::Oid(vec![0x06, 0x03]);
    assert!(format!("{}", oid).starts_with("oid:"));
}

#[test]
fn display_cbor_time() {
    let t = CborTime::new(1234567890);
    assert_eq!(format!("{}", t), "1234567890");
}

// ===========================================================================
// From conversions — types/common.rs
// ===========================================================================

#[test]
fn from_conversions() {
    let _: TagIdChoice = "hello".into();
    let _: TagIdChoice = String::from("hello").into();
    let _: TagIdChoice = [0u8; 16].into();

    let _: CorimId = "test".into();
    let _: CorimId = String::from("test").into();
    let _: CorimId = [0u8; 16].into();

    let _: MeasuredElement = "firmware".into();
    let _: MeasuredElement = String::from("firmware").into();
    let _: MeasuredElement = 42u64.into();
}

// ===========================================================================
// types/triples.rs — more Validate coverage
// ===========================================================================

#[test]
fn endorsed_triple_empty_env_invalid() {
    let t = EndorsedTriple::new(
        EnvironmentMap {
            class: None,
            instance: None,
            group: None,
        },
        vec![MeasurementMap {
            mkey: None,
            mval: MeasurementValuesMap {
                svn: Some(SvnChoice::ExactValue(1)),
                ..MeasurementValuesMap::default()
            },
            authorized_by: None,
        }],
    );
    let err = t.valid().unwrap_err();
    assert!(err.contains("environment"), "got: {err}");
}

#[test]
fn endorsed_triple_empty_measurements_invalid() {
    let t = EndorsedTriple::new(EnvironmentMap::for_class("A", "B"), vec![]);
    let err = t.valid().unwrap_err();
    assert!(err.contains("no measurement entries"), "got: {err}");
}

#[test]
fn endorsed_triple_invalid_measurement_invalid() {
    let t = EndorsedTriple::new(
        EnvironmentMap::for_class("A", "B"),
        vec![MeasurementMap {
            mkey: None,
            mval: MeasurementValuesMap::default(),
            authorized_by: None,
        }],
    );
    let err = t.valid().unwrap_err();
    assert!(err.contains("measurement at index 0"), "got: {err}");
}

#[test]
fn attest_key_triple_valid() {
    let t = AttestKeyTriple::new(
        EnvironmentMap::for_class("V", "M"),
        vec![CryptoKey::PkixBase64Key("key".into())],
        None,
    );
    assert!(t.valid().is_ok());
}

#[test]
fn domain_membership_invalid_member_env() {
    let t = DomainMembershipTriple::new(
        EnvironmentMap::for_class("X", "Y"),
        vec![EnvironmentMap {
            class: None,
            instance: None,
            group: None,
        }],
    );
    let err = t.valid().unwrap_err();
    assert!(err.contains("member at index 0"), "got: {err}");
}

#[test]
fn domain_dependency_invalid_trustee_env() {
    let t = DomainDependencyTriple::new(
        EnvironmentMap::for_class("X", "Y"),
        vec![EnvironmentMap {
            class: None,
            instance: None,
            group: None,
        }],
    );
    let err = t.valid().unwrap_err();
    assert!(err.contains("trustee at index 0"), "got: {err}");
}

#[test]
fn conditional_endorsement_triple_invalid_condition() {
    let env = EnvironmentMap::for_class("A", "B");
    let meas = vec![MeasurementMap {
        mkey: None,
        mval: MeasurementValuesMap {
            svn: Some(SvnChoice::ExactValue(1)),
            ..MeasurementValuesMap::default()
        },
        authorized_by: None,
    }];
    // Bad condition: empty environment
    let t = ConditionalEndorsementTriple(
        vec![StatefulEnvironmentRecord(
            EnvironmentMap {
                class: None,
                instance: None,
                group: None,
            },
            meas.clone(),
        )],
        vec![EndorsedTriple::new(env, meas)],
    );
    let err = t.valid().unwrap_err();
    assert!(err.contains("condition at index 0"), "got: {err}");
}

#[test]
fn conditional_endorsement_triple_empty_endorsements() {
    let env = EnvironmentMap::for_class("A", "B");
    let meas = vec![MeasurementMap {
        mkey: None,
        mval: MeasurementValuesMap {
            svn: Some(SvnChoice::ExactValue(1)),
            ..MeasurementValuesMap::default()
        },
        authorized_by: None,
    }];
    let t = ConditionalEndorsementTriple(vec![StatefulEnvironmentRecord(env, meas)], vec![]);
    let err = t.valid().unwrap_err();
    assert!(err.contains("endorsements must not be empty"), "got: {err}");
}

#[test]
fn conditional_endorsement_triple_invalid_endorsement() {
    let env = EnvironmentMap::for_class("A", "B");
    let meas = vec![MeasurementMap {
        mkey: None,
        mval: MeasurementValuesMap {
            svn: Some(SvnChoice::ExactValue(1)),
            ..MeasurementValuesMap::default()
        },
        authorized_by: None,
    }];
    let bad_endorsed = EndorsedTriple::new(
        EnvironmentMap {
            class: None,
            instance: None,
            group: None,
        },
        meas.clone(),
    );
    let t = ConditionalEndorsementTriple(
        vec![StatefulEnvironmentRecord(env, meas)],
        vec![bad_endorsed],
    );
    let err = t.valid().unwrap_err();
    assert!(err.contains("endorsement at index 0"), "got: {err}");
}

#[test]
fn triples_map_validates_endorsed_triples() {
    let t = TriplesMap {
        reference_triples: None,
        endorsed_triples: Some(vec![EndorsedTriple::new(
            EnvironmentMap {
                class: None,
                instance: None,
                group: None,
            },
            vec![],
        )]),
        identity_triples: None,
        attest_key_triples: None,
        dependency_triples: None,
        membership_triples: None,
        coswid_triples: None,
        conditional_endorsement_series: None,
        conditional_endorsement: None,
    };
    let err = t.valid().unwrap_err();
    assert!(err.contains("endorsed value at index 0"), "got: {err}");
}

#[test]
fn triples_map_validates_identity_triples() {
    let t = TriplesMap {
        reference_triples: None,
        endorsed_triples: None,
        identity_triples: Some(vec![IdentityTriple::new(
            EnvironmentMap {
                class: None,
                instance: None,
                group: None,
            },
            vec![CryptoKey::PkixBase64Key("k".into())],
            None,
        )]),
        attest_key_triples: None,
        dependency_triples: None,
        membership_triples: None,
        coswid_triples: None,
        conditional_endorsement_series: None,
        conditional_endorsement: None,
    };
    let err = t.valid().unwrap_err();
    assert!(err.contains("identity triple at index 0"), "got: {err}");
}

#[test]
fn triples_map_validates_attest_key_triples() {
    let t = TriplesMap {
        reference_triples: None,
        endorsed_triples: None,
        identity_triples: None,
        attest_key_triples: Some(vec![AttestKeyTriple::new(
            EnvironmentMap {
                class: None,
                instance: None,
                group: None,
            },
            vec![CryptoKey::PkixBase64Key("k".into())],
            None,
        )]),
        dependency_triples: None,
        membership_triples: None,
        coswid_triples: None,
        conditional_endorsement_series: None,
        conditional_endorsement: None,
    };
    let err = t.valid().unwrap_err();
    assert!(err.contains("attest-key triple at index 0"), "got: {err}");
}

#[test]
fn triples_map_validates_dependency_triples() {
    let t = TriplesMap {
        reference_triples: None,
        endorsed_triples: None,
        identity_triples: None,
        attest_key_triples: None,
        dependency_triples: Some(vec![DomainDependencyTriple::new(
            EnvironmentMap {
                class: None,
                instance: None,
                group: None,
            },
            vec![EnvironmentMap::for_class("X", "Y")],
        )]),
        membership_triples: None,
        coswid_triples: None,
        conditional_endorsement_series: None,
        conditional_endorsement: None,
    };
    let err = t.valid().unwrap_err();
    assert!(err.contains("dependency triple at index 0"), "got: {err}");
}

#[test]
fn triples_map_validates_membership_triples() {
    let t = TriplesMap {
        reference_triples: None,
        endorsed_triples: None,
        identity_triples: None,
        attest_key_triples: None,
        dependency_triples: None,
        membership_triples: Some(vec![DomainMembershipTriple::new(
            EnvironmentMap {
                class: None,
                instance: None,
                group: None,
            },
            vec![EnvironmentMap::for_class("X", "Y")],
        )]),
        coswid_triples: None,
        conditional_endorsement_series: None,
        conditional_endorsement: None,
    };
    let err = t.valid().unwrap_err();
    assert!(err.contains("membership triple at index 0"), "got: {err}");
}

// ===========================================================================
// types/corim.rs — Display, CorimLocator thumbprint, ConciseTagChoice
// ===========================================================================

#[test]
fn corim_locator_single_thumbprint_round_trip() {
    let loc = CorimLocator {
        href: CorimLocatorHref::Single("https://example.com".into()),
        thumbprint: Some(CorimLocatorThumbprint::Single(Digest::new(
            7,
            vec![0xAA; 32],
        ))),
    };
    let bytes = cbor::encode(&loc).unwrap();
    let decoded: CorimLocator = cbor::decode(&bytes).unwrap();
    assert_eq!(loc, decoded);
}

#[test]
fn corim_locator_multiple_thumbprints_round_trip() {
    let loc = CorimLocator {
        href: CorimLocatorHref::Multiple(vec!["https://a.com".into(), "https://b.com".into()]),
        thumbprint: Some(CorimLocatorThumbprint::Multiple(vec![
            Digest::new(7, vec![0xAA; 32]),
            Digest::new(1, vec![0xBB; 20]),
        ])),
    };
    let bytes = cbor::encode(&loc).unwrap();
    let decoded: CorimLocator = cbor::decode(&bytes).unwrap();
    assert_eq!(loc, decoded);
}

#[test]
fn concise_tag_choice_unknown_tag() {
    // Create a tagged value with an unknown tag number
    let tagged = Value::Tag(999, Box::new(Value::Bytes(vec![1, 2, 3])));
    let bytes = cbor::encode(&tagged).unwrap();
    let decoded: ConciseTagChoice = cbor::decode(&bytes).unwrap();
    assert!(matches!(decoded, ConciseTagChoice::Unknown(999, _)));
}

// ===========================================================================
// types/measurement.rs — IntegrityRegisters, IpAddr, more
// ===========================================================================

#[test]
fn integrity_registers_round_trip() {
    use std::collections::BTreeMap;
    let mut map = BTreeMap::new();
    map.insert(
        IntegrityRegisterId::Uint(0),
        vec![Digest::new(7, vec![0xAA; 32])],
    );
    map.insert(
        IntegrityRegisterId::Text("pcr-1".into()),
        vec![Digest::new(1, vec![0xBB; 20])],
    );
    let regs = IntegrityRegisters(map);
    let mval = MeasurementValuesMap {
        integrity_registers: Some(regs),
        ..MeasurementValuesMap::default()
    };
    let bytes = cbor::encode(&mval).unwrap();
    let decoded: MeasurementValuesMap = cbor::decode(&bytes).unwrap();
    assert!(decoded.integrity_registers.is_some());
    let regs = decoded.integrity_registers.unwrap();
    assert_eq!(regs.0.len(), 2);
}

#[test]
fn ip_addr_v6_round_trip() {
    let mval = MeasurementValuesMap {
        ip_addr: Some(IpAddr::V6([
            0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1,
        ])),
        ..MeasurementValuesMap::default()
    };
    let bytes = cbor::encode(&mval).unwrap();
    let decoded: MeasurementValuesMap = cbor::decode(&bytes).unwrap();
    assert!(matches!(decoded.ip_addr, Some(IpAddr::V6(_))));
}

#[test]
fn mac_addr_eui64_round_trip() {
    let mval = MeasurementValuesMap {
        mac_addr: Some(MacAddr::Eui64([
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
        ])),
        ..MeasurementValuesMap::default()
    };
    let bytes = cbor::encode(&mval).unwrap();
    let decoded: MeasurementValuesMap = cbor::decode(&bytes).unwrap();
    assert!(matches!(decoded.mac_addr, Some(MacAddr::Eui64(_))));
}

#[test]
fn raw_value_masked_round_trip() {
    let mval = MeasurementValuesMap {
        raw_value: Some(RawValueChoice::Masked {
            value: vec![0x01, 0x02, 0x03, 0x04],
            mask: vec![0xFF, 0xFF, 0xFF, 0xFF],
        }),
        ..MeasurementValuesMap::default()
    };
    let bytes = cbor::encode(&mval).unwrap();
    let decoded: MeasurementValuesMap = cbor::decode(&bytes).unwrap();
    assert!(matches!(
        decoded.raw_value,
        Some(RawValueChoice::Masked { .. })
    ));
}

#[test]
fn measurement_values_map_many_fields() {
    let mval = MeasurementValuesMap {
        version: Some(VersionMap {
            version: "1.0".into(),
            version_scheme: Some(16384),
        }),
        serial_number: Some("SN12345".into()),
        ueid: Some(vec![0x02; 10]),
        uuid: Some(vec![0xAA; 16]),
        name: Some("test-comp".into()),
        cryptokeys: Some(vec![CryptoKey::PkixBase64Key("key...".into())]),
        ..MeasurementValuesMap::default()
    };
    let bytes = cbor::encode(&mval).unwrap();
    let decoded: MeasurementValuesMap = cbor::decode(&bytes).unwrap();
    assert_eq!(decoded.serial_number, Some("SN12345".into()));
    assert_eq!(decoded.name, Some("test-comp".into()));
    assert!(decoded.cryptokeys.is_some());
    assert!(decoded.ueid.is_some());
    assert!(decoded.uuid.is_some());
}

// ===========================================================================
// types/common.rs — CryptoKey CBOR round-trips (cover more serde paths)
// ===========================================================================

#[test]
fn crypto_key_all_variants_round_trip() {
    let keys: Vec<CryptoKey> = vec![
        CryptoKey::PkixBase64Key("MIIBIjANBg...".into()),
        CryptoKey::PkixBase64Cert("MIIC...".into()),
        CryptoKey::PkixBase64CertPath("MIIE...".into()),
        CryptoKey::KeyThumbprint(Digest::new(7, vec![0xCC; 32])),
        CryptoKey::CoseKey(vec![0xA1, 0x01]),
        CryptoKey::CertThumbprint(Digest::new(7, vec![0xDD; 32])),
        CryptoKey::CertPathThumbprint(Digest::new(7, vec![0xEE; 32])),
        CryptoKey::PkixAsn1DerCert(vec![0x30, 0x82]),
        CryptoKey::Bytes(vec![0x01, 0x02, 0x03]),
    ];
    for key in &keys {
        let bytes = cbor::encode(key).unwrap();
        let decoded: CryptoKey = cbor::decode(&bytes).unwrap();
        assert_eq!(key, &decoded, "failed for {:?}", key);
    }
}

#[test]
fn instance_id_all_variants_round_trip() {
    let ids: Vec<InstanceIdChoice> = vec![
        InstanceIdChoice::Uuid([0xBB; 16]),
        InstanceIdChoice::Bytes(vec![0x01, 0x02]),
        InstanceIdChoice::PkixBase64Key("key-str".into()),
        InstanceIdChoice::PkixBase64Cert("cert-str".into()),
        InstanceIdChoice::CoseKey(vec![0xA1, 0x01]),
        InstanceIdChoice::KeyThumbprint(Digest::new(7, vec![0xCC; 32])),
        InstanceIdChoice::CertThumbprint(Digest::new(7, vec![0xDD; 32])),
        InstanceIdChoice::PkixAsn1DerCert(vec![0x30, 0x82]),
    ];
    for id in &ids {
        let bytes = cbor::encode(id).unwrap();
        let decoded: InstanceIdChoice = cbor::decode(&bytes).unwrap();
        assert_eq!(id, &decoded, "failed for {:?}", id);
    }
}

// ===========================================================================
// ComidTag validation — more paths
// ===========================================================================

#[test]
fn comid_tag_empty_entities_invalid() {
    let comid = corim::types::comid::ComidTag {
        language: None,
        tag_identity: TagIdentity {
            tag_id: TagIdChoice::Text("t".into()),
            tag_version: None,
        },
        entities: Some(vec![]), // empty entities
        linked_tags: None,
        triples: TriplesMap {
            reference_triples: Some(vec![ReferenceTriple::new(
                EnvironmentMap::for_class("V", "M"),
                vec![MeasurementMap {
                    mkey: None,
                    mval: MeasurementValuesMap {
                        svn: Some(SvnChoice::ExactValue(1)),
                        ..MeasurementValuesMap::default()
                    },
                    authorized_by: None,
                }],
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
    };
    let err = comid.valid().unwrap_err();
    assert!(err.contains("entities"), "got: {err}");
}

#[test]
fn comid_tag_empty_linked_tags_invalid() {
    let comid = corim::types::comid::ComidTag {
        language: None,
        tag_identity: TagIdentity {
            tag_id: TagIdChoice::Text("t".into()),
            tag_version: None,
        },
        entities: None,
        linked_tags: Some(vec![]), // empty linked_tags
        triples: TriplesMap {
            reference_triples: Some(vec![ReferenceTriple::new(
                EnvironmentMap::for_class("V", "M"),
                vec![MeasurementMap {
                    mkey: None,
                    mval: MeasurementValuesMap {
                        svn: Some(SvnChoice::ExactValue(1)),
                        ..MeasurementValuesMap::default()
                    },
                    authorized_by: None,
                }],
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
    };
    let err = comid.valid().unwrap_err();
    assert!(err.contains("linked-tags"), "got: {err}");
}

// ===========================================================================
// TagIdentity helper
// ===========================================================================

#[test]
fn tag_identity_version_default() {
    let tid = TagIdentity {
        tag_id: TagIdChoice::Text("x".into()),
        tag_version: None,
    };
    assert_eq!(tid.tag_version_or_default(), 0);

    let tid2 = TagIdentity {
        tag_id: TagIdChoice::Text("x".into()),
        tag_version: Some(5),
    };
    assert_eq!(tid2.tag_version_or_default(), 5);
}

// ===========================================================================
// JSON value_conv.rs — exercise more tag→JSON + type_choice→value paths
// ===========================================================================

#[cfg(feature = "json")]
mod json_coverage_tests {
    use corim::cbor::value::Value;
    use corim::json::json_to_value;
    use corim::json::value_to_json;

    #[test]
    fn json_float_nan_becomes_null() {
        let v = Value::Float(f64::NAN);
        let j = value_to_json(&v);
        assert!(j.is_null());
    }

    #[test]
    fn json_large_integer_becomes_string() {
        let v = Value::Integer(i128::MAX);
        let j = value_to_json(&v);
        assert!(j.is_string());
    }

    #[test]
    fn json_map_with_text_key() {
        let v = Value::Map(vec![(
            Value::Text("name".into()),
            Value::Text("test".into()),
        )]);
        let j = value_to_json(&v);
        assert_eq!(j["name"], "test");
    }

    #[test]
    fn json_map_with_non_standard_key() {
        let v = Value::Map(vec![(Value::Bool(true), Value::Integer(1))]);
        let j = value_to_json(&v);
        // Bool key gets Debug-formatted
        assert!(j.is_object());
    }

    #[test]
    fn json_tag_oid() {
        let v = Value::Tag(111, Box::new(Value::Bytes(vec![0x06, 0x03, 0x55, 0x04])));
        let j = value_to_json(&v);
        assert_eq!(j["type"], "oid");
    }

    #[test]
    fn json_tag_ueid_non_bytes() {
        // UEID tag wrapping non-bytes
        let v = Value::Tag(550, Box::new(Value::Text("not-bytes".into())));
        let j = value_to_json(&v);
        assert_eq!(j["type"], "ueid");
    }

    #[test]
    fn json_tag_uuid_non_bytes() {
        // UUID tag wrapping non-bytes
        let v = Value::Tag(37, Box::new(Value::Text("not-bytes".into())));
        let j = value_to_json(&v);
        assert_eq!(j["type"], "uuid");
    }

    #[test]
    fn json_tag_svn() {
        let v = Value::Tag(552, Box::new(Value::Integer(42)));
        let j = value_to_json(&v);
        assert_eq!(j["type"], "svn");
        assert_eq!(j["value"], 42);
    }

    #[test]
    fn json_tag_min_svn() {
        let v = Value::Tag(553, Box::new(Value::Integer(10)));
        let j = value_to_json(&v);
        assert_eq!(j["type"], "min-svn");
    }

    #[test]
    fn json_tag_crypto_keys() {
        for (tag, expected_type) in [
            (554, "pkix-base64-key"),
            (555, "pkix-base64-cert"),
            (556, "pkix-base64-cert-path"),
            (557, "key-thumbprint"),
            (558, "cose-key"),
            (559, "cert-thumbprint"),
            (560, "bytes"),
            (561, "cert-path-thumbprint"),
            (562, "pkix-asn1der-cert"),
            (563, "masked-raw-value"),
            (564, "int-range"),
        ] {
            let v = Value::Tag(tag, Box::new(Value::Integer(0)));
            let j = value_to_json(&v);
            assert_eq!(j["type"], expected_type, "tag {tag}");
        }
    }

    #[test]
    fn json_tag_coswid_comid_cotl() {
        for tag in [505, 506, 508] {
            let v = Value::Tag(tag, Box::new(Value::Bytes(vec![0xA0])));
            let j = value_to_json(&v);
            assert_eq!(j["__cbor_tag"], tag);
        }
    }

    #[test]
    fn json_tag_unknown() {
        let v = Value::Tag(99999, Box::new(Value::Text("hello".into())));
        let j = value_to_json(&v);
        assert_eq!(j["__cbor_tag"], 99999);
        assert_eq!(j["__cbor_value"], "hello");
    }

    #[test]
    fn json_epoch_time_tag() {
        let v = Value::Tag(1, Box::new(Value::Integer(1234567890)));
        let j = value_to_json(&v);
        assert_eq!(j, 1234567890);
    }

    // --- json_to_value type-choice paths ---

    #[test]
    fn json_type_choice_svn_to_value() {
        let j = serde_json::json!({"type": "svn", "value": 42});
        let v = json_to_value(&j);
        assert!(matches!(v, Value::Tag(552, _)));
    }

    #[test]
    fn json_type_choice_min_svn_to_value() {
        let j = serde_json::json!({"type": "min-svn", "value": 10});
        let v = json_to_value(&j);
        assert!(matches!(v, Value::Tag(553, _)));
    }

    #[test]
    fn json_type_choice_all_crypto_to_value() {
        let cases = vec![
            ("pkix-base64-key", 554),
            ("pkix-base64-cert", 555),
            ("pkix-base64-cert-path", 556),
            ("key-thumbprint", 557),
            ("cose-key", 558),
            ("cert-thumbprint", 559),
            ("cert-path-thumbprint", 561),
            ("pkix-asn1der-cert", 562),
            ("masked-raw-value", 563),
            ("int-range", 564),
        ];
        for (type_name, expected_tag) in cases {
            let j = serde_json::json!({"type": type_name, "value": 0});
            let v = json_to_value(&j);
            match v {
                Value::Tag(t, _) => assert_eq!(t, expected_tag, "type: {type_name}"),
                _ => panic!("expected tag for {type_name}, got {v:?}"),
            }
        }
    }

    #[test]
    fn json_type_choice_ueid_base64_to_value() {
        let j = serde_json::json!({"type": "ueid", "value": "AQID"});
        let v = json_to_value(&j);
        match v {
            Value::Tag(550, inner) => assert!(matches!(*inner, Value::Bytes(_))),
            _ => panic!("expected tag 550"),
        }
    }

    #[test]
    fn json_type_choice_bytes_base64_to_value() {
        let j = serde_json::json!({"type": "bytes", "value": "AQID"});
        let v = json_to_value(&j);
        match v {
            Value::Tag(560, inner) => assert!(matches!(*inner, Value::Bytes(_))),
            _ => panic!("expected tag 560"),
        }
    }

    #[test]
    fn json_type_choice_uuid_invalid_format() {
        // UUID with non-hex string
        let j = serde_json::json!({"type": "uuid", "value": "not-a-uuid"});
        let v = json_to_value(&j);
        // Falls back to Tag(37, json_to_value)
        assert!(matches!(v, Value::Tag(37, _)));
    }

    #[test]
    fn json_type_choice_unknown() {
        let j = serde_json::json!({"type": "custom-type", "value": "data"});
        let v = json_to_value(&j);
        // Should be a map with "type" and "value" text keys
        assert!(matches!(v, Value::Map(_)));
    }

    #[test]
    fn json_cbor_tag_object_to_value() {
        let j = serde_json::json!({"__cbor_tag": 501, "__cbor_value": {"0": "test"}});
        let v = json_to_value(&j);
        assert!(matches!(v, Value::Tag(501, _)));
    }

    #[test]
    fn json_number_u64_to_value() {
        let j = serde_json::json!(u64::MAX);
        let v = json_to_value(&j);
        assert!(matches!(v, Value::Integer(_)));
    }

    #[test]
    fn json_number_float_to_value() {
        let j = serde_json::json!(core::f64::consts::PI);
        let v = json_to_value(&j);
        assert!(matches!(v, Value::Float(_)));
    }

    #[test]
    fn json_string_key_to_int_key() {
        // "entity-name" is in the global key table at index 31
        let j = serde_json::json!({"entity-name": "ACME"});
        let v = json_to_value(&j);
        if let Value::Map(entries) = v {
            assert_eq!(entries[0].0, Value::Integer(31));
        } else {
            panic!("expected map");
        }
    }

    #[test]
    fn json_string_key_numeric() {
        // A numeric string key that's not in the table
        let j = serde_json::json!({"99": "value"});
        let v = json_to_value(&j);
        if let Value::Map(entries) = v {
            assert_eq!(entries[0].0, Value::Integer(99));
        } else {
            panic!("expected map");
        }
    }

    #[test]
    fn json_string_key_non_numeric() {
        // A non-numeric, non-registered string key
        let j = serde_json::json!({"custom-key": "value"});
        let v = json_to_value(&j);
        if let Value::Map(entries) = v {
            assert_eq!(entries[0].0, Value::Text("custom-key".into()));
        } else {
            panic!("expected map");
        }
    }

    #[test]
    fn json_to_json_pretty_round_trip() {
        use corim::json;
        use corim::types::environment::ClassMap;
        let class = ClassMap::new("Test", "Widget");
        let pretty = json::to_json_pretty(&class).unwrap();
        assert!(pretty.contains('\n'));
        let decoded: ClassMap = json::from_json(&pretty).unwrap();
        assert_eq!(class, decoded);
    }

    #[test]
    fn json_from_json_parse_error() {
        use corim::json;
        use corim::types::environment::ClassMap;
        let result = json::from_json::<ClassMap>("not valid json{{{");
        assert!(result.is_err());
    }
}
