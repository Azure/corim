// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Tests for the CBOR `Value` enum and the serde bridge in
//! `cbor/value/`, `cbor/minimal_backend/value_ser.rs`, and
//! `cbor/minimal_backend/value_de.rs`.
//!
//! Covers: `Value::into_*` accessors, primitive ser/de round-trips,
//! the serde `Serializer` variant methods (unit/newtype/tuple/struct
//! variants), `Tagged<T>` decode behavior, i128 boundary handling,
//! and round-trips for select container types whose serde paths are
//! not exercised by the higher-level integration tests.

use corim::cbor;
use corim::cbor::value::Value;
use corim::types::common::*;
use corim::types::corim::*;
use corim::types::environment::*;
use corim::types::measurement::*;
use std::collections::BTreeMap;

// ===========================================================================
// Value::into_* accessors
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

// ===========================================================================
// to_value / from_value bridge
// ===========================================================================

#[test]
fn to_value_from_value_round_trip_via_class_map() {
    use corim::cbor::value::{from_value, to_value};
    let class = ClassMap::new("ACME", "Widget");
    let v = to_value(&class).unwrap();
    assert!(matches!(v, Value::Map(_)));
    let decoded: ClassMap = from_value(&v).unwrap();
    assert_eq!(class, decoded);
}

// ===========================================================================
// value_ser.rs — primitive Serializer methods
// ===========================================================================

#[test]
fn ser_bool_round_trip() {
    let bytes = cbor::encode(&true).unwrap();
    let v: bool = cbor::decode(&bytes).unwrap();
    assert!(v);
}

#[test]
fn ser_floats_round_trip() {
    let bytes = cbor::encode(&core::f64::consts::PI).unwrap();
    let v: f64 = cbor::decode(&bytes).unwrap();
    assert!((v - core::f64::consts::PI).abs() < 0.001);

    let bytes32 = cbor::encode(&2.5f32).unwrap();
    let v32: f64 = cbor::decode(&bytes32).unwrap();
    assert!((v32 - 2.5).abs() < 0.001);
}

#[test]
fn ser_various_integer_widths_round_trip() {
    for (b, expected) in [
        (cbor::encode(&(-1i8)).unwrap(), -1i64),
        (cbor::encode(&(300i16)).unwrap(), 300),
        (cbor::encode(&(100000i32)).unwrap(), 100000),
    ] {
        assert_eq!(cbor::decode::<i64>(&b).unwrap(), expected);
    }

    for (b, expected) in [
        (cbor::encode(&(255u8)).unwrap(), 255u64),
        (cbor::encode(&(65535u16)).unwrap(), 65535),
        (cbor::encode(&(4000000000u32)).unwrap(), 4000000000),
    ] {
        assert_eq!(cbor::decode::<u64>(&b).unwrap(), expected);
    }
}

#[test]
fn ser_option_some_and_none() {
    let some_val: Option<u32> = Some(42);
    let none_val: Option<u32> = None;
    let decoded_some: Option<u32> = cbor::decode(&cbor::encode(&some_val).unwrap()).unwrap();
    let decoded_none: Option<u32> = cbor::decode(&cbor::encode(&none_val).unwrap()).unwrap();
    assert_eq!(decoded_some, Some(42));
    assert_eq!(decoded_none, None);
}

#[test]
fn ser_string_round_trip() {
    let s = "hello world";
    let bytes = cbor::encode(&s).unwrap();
    let decoded: String = cbor::decode(&bytes).unwrap();
    assert_eq!(decoded, s);
}

#[test]
fn ser_nested_vec_round_trip() {
    let nested: Vec<Vec<u32>> = vec![vec![1, 2], vec![3, 4, 5]];
    let bytes = cbor::encode(&nested).unwrap();
    let decoded: Vec<Vec<u32>> = cbor::decode(&bytes).unwrap();
    assert_eq!(nested, decoded);
}

// ===========================================================================
// value_ser.rs — Serializer variant methods (enum / struct shapes)
// ===========================================================================

#[test]
fn ser_unit_variant_serializes_as_index() {
    #[derive(serde::Serialize)]
    enum E {
        A,
        B,
    }
    assert_eq!(cbor::value::to_value(&E::A).unwrap(), Value::Integer(0));
    assert_eq!(cbor::value::to_value(&E::B).unwrap(), Value::Integer(1));
}

#[test]
fn ser_newtype_variant_serializes_as_inner() {
    #[derive(serde::Serialize)]
    enum E {
        Wrap(u32),
    }
    assert_eq!(
        cbor::value::to_value(&E::Wrap(42)).unwrap(),
        Value::Integer(42)
    );
}

#[test]
fn ser_tuple_variant_serializes_as_array() {
    #[derive(serde::Serialize)]
    enum E {
        Pair(u32, String),
    }
    let v = cbor::value::to_value(&E::Pair(1, "hi".into())).unwrap();
    assert!(matches!(v, Value::Array(ref a) if a.len() == 2));
}

#[test]
fn ser_struct_variant_serializes_as_map() {
    #[derive(serde::Serialize)]
    enum E {
        Named { x: u32, y: String },
    }
    let v = cbor::value::to_value(&E::Named {
        x: 1,
        y: "hi".into(),
    })
    .unwrap();
    assert!(matches!(v, Value::Map(ref e) if e.len() == 2));
}

#[test]
fn ser_newtype_struct_serializes_as_inner() {
    #[derive(serde::Serialize)]
    struct W(u64);
    assert_eq!(cbor::value::to_value(&W(123)).unwrap(), Value::Integer(123));
}

#[test]
fn ser_unit_struct_serializes_as_null() {
    #[derive(serde::Serialize)]
    struct U;
    assert_eq!(cbor::value::to_value(&U).unwrap(), Value::Null);
}

#[test]
fn ser_tuple_struct_serializes_as_array() {
    #[derive(serde::Serialize)]
    struct P(u32, u32);
    let v = cbor::value::to_value(&P(1, 2)).unwrap();
    assert!(matches!(v, Value::Array(ref a) if a.len() == 2));
}

#[test]
fn ser_named_struct_serializes_as_map() {
    #[derive(serde::Serialize)]
    struct S {
        name: String,
        age: u32,
    }
    let v = cbor::value::to_value(&S {
        name: "A".into(),
        age: 1,
    })
    .unwrap();
    assert!(matches!(v, Value::Map(ref e) if e.len() == 2));
}

#[test]
fn ser_char_serializes_as_text() {
    assert_eq!(
        cbor::value::to_value(&'X').unwrap(),
        Value::Text("X".into())
    );
}

// ===========================================================================
// value_de.rs — Deserializer round-trips through Value
// ===========================================================================

#[test]
fn de_negative_i64_min_round_trip() {
    let v = Value::Integer(i64::MIN as i128);
    let bytes = cbor::encode(&v).unwrap();
    let decoded: Value = cbor::decode(&bytes).unwrap();
    assert_eq!(decoded, Value::Integer(i64::MIN as i128));
}

#[test]
fn de_float_round_trip() {
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
fn de_null_round_trip() {
    let bytes = cbor::encode(&Value::Null).unwrap();
    let decoded: Value = cbor::decode(&bytes).unwrap();
    assert_eq!(decoded, Value::Null);
}

#[test]
fn de_bool_round_trip() {
    for b in [true, false] {
        let bytes = cbor::encode(&Value::Bool(b)).unwrap();
        let decoded: Value = cbor::decode(&bytes).unwrap();
        assert_eq!(decoded, Value::Bool(b));
    }
}

#[test]
fn de_bytes_round_trip() {
    let v = Value::Bytes(vec![0xDE, 0xAD, 0xBE, 0xEF]);
    let bytes = cbor::encode(&v).unwrap();
    let decoded: Value = cbor::decode(&bytes).unwrap();
    assert_eq!(decoded, Value::Bytes(vec![0xDE, 0xAD, 0xBE, 0xEF]));
}

#[test]
fn de_tag_round_trip() {
    let v = Value::Tag(42, Box::new(Value::Text("hello".into())));
    let bytes = cbor::encode(&v).unwrap();
    let decoded: Value = cbor::decode(&bytes).unwrap();
    assert_eq!(
        decoded,
        Value::Tag(42, Box::new(Value::Text("hello".into())))
    );
}

#[test]
fn de_map_with_text_keys_round_trip() {
    let entries = vec![
        (Value::Text("a".into()), Value::Integer(1)),
        (Value::Text("b".into()), Value::Integer(2)),
    ];
    let v = Value::Map(entries.clone());
    let bytes = cbor::encode(&v).unwrap();
    let decoded: Value = cbor::decode(&bytes).unwrap();
    assert_eq!(decoded, Value::Map(entries));
}

#[test]
fn de_seq_rejects_non_array() {
    let bytes = cbor::encode(&Value::Integer(42)).unwrap();
    assert!(cbor::decode::<Vec<u32>>(&bytes).is_err());
}

#[test]
fn de_map_rejects_non_map() {
    let bytes = cbor::encode(&Value::Integer(42)).unwrap();
    assert!(cbor::decode::<std::collections::HashMap<String, u32>>(&bytes).is_err());
}

// ===========================================================================
// Tagged<T> bridge
// ===========================================================================

#[test]
fn tagged_captures_arbitrary_tag_number() {
    // Tagged<T> is a transparent wrapper — it captures whatever tag is on
    // the wire without enforcing a specific value.
    let v = Value::Tag(999, Box::new(Value::Text("hello".into())));
    let bytes = cbor::encode(&v).unwrap();
    let decoded: corim::cbor::value::Tagged<String> = cbor::decode(&bytes).unwrap();
    assert_eq!(decoded.tag, 999);
}

#[test]
fn tagged_rejects_non_tag_value() {
    let bytes = cbor::encode(&Value::Integer(42)).unwrap();
    let result = cbor::decode::<corim::cbor::value::Tagged<String>>(&bytes);
    assert!(result.is_err());
}

// ===========================================================================
// i128 boundary handling
// ===========================================================================

#[test]
fn i128_above_u64_max_errors_on_encode() {
    // CBOR cannot represent values above u64::MAX — must error, not panic.
    let v = Value::Integer((u64::MAX as i128) + 1);
    assert!(cbor::encode(&v).is_err());
}

#[test]
fn i128_below_neg_2_pow_64_errors_on_encode() {
    let v = Value::Integer(-(u64::MAX as i128) - 2);
    assert!(cbor::encode(&v).is_err());
}

#[test]
fn i128_at_i64_min_round_trips() {
    let v = Value::Integer(i64::MIN as i128);
    let bytes = cbor::encode(&v).unwrap();
    let decoded: Value = cbor::decode(&bytes).unwrap();
    assert_eq!(decoded, Value::Integer(i64::MIN as i128));
}

// ===========================================================================
// Round-trips for container/measurement types whose serde paths are not
// otherwise exercised by the higher-level integration tests.
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
fn corim_locator_multiple_href_round_trip() {
    let loc = CorimLocator {
        href: CorimLocatorHref::Multiple(vec!["https://a.com".into(), "https://b.com".into()]),
        thumbprint: None,
    };
    let bytes = cbor::encode(&loc).unwrap();
    let decoded: CorimLocator = cbor::decode(&bytes).unwrap();
    match decoded.href {
        CorimLocatorHref::Multiple(uris) => assert_eq!(uris.len(), 2),
        _ => panic!("expected multiple"),
    }
}

#[test]
fn concise_tag_choice_unknown_tag_preserved() {
    let tagged = Value::Tag(999, Box::new(Value::Bytes(vec![1, 2, 3])));
    let bytes = cbor::encode(&tagged).unwrap();
    let decoded: ConciseTagChoice = cbor::decode(&bytes).unwrap();
    assert!(matches!(decoded, ConciseTagChoice::Unknown(999, _)));
}

#[test]
fn integrity_registers_uint_and_text_keys_round_trip() {
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
    assert_eq!(decoded.integrity_registers.unwrap().0.len(), 2);
}

#[test]
fn integrity_registers_text_key_only_round_trip() {
    let mut map = BTreeMap::new();
    map.insert(
        IntegrityRegisterId::Text("pcr-0".into()),
        vec![Digest::new(1, vec![0xAA; 32])],
    );
    let regs = IntegrityRegisters(map);
    let bytes = cbor::encode(&regs).unwrap();
    let decoded: IntegrityRegisters = cbor::decode(&bytes).unwrap();
    assert!(decoded
        .0
        .contains_key(&IntegrityRegisterId::Text("pcr-0".into())));
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
fn measurement_values_map_many_fields_round_trip() {
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

#[test]
fn int_range_int_round_trip() {
    let ir = IntRangeChoice::Int(42);
    let bytes = cbor::encode(&ir).unwrap();
    let decoded: IntRangeChoice = cbor::decode(&bytes).unwrap();
    assert_eq!(decoded, IntRangeChoice::Int(42));
}
