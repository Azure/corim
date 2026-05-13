// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Tests for the CBOR ↔ JSON conversion in `json/value_conv.rs`,
//! covering tagged-value translation in both directions and the
//! string-key-to-int-key mapping driven by the global key table.

#![cfg(feature = "json")]

use corim::cbor::value::Value;
use corim::json::{json_to_value, value_to_json};

// ===========================================================================
// value_to_json — primitive edges
// ===========================================================================

#[test]
fn float_nan_becomes_null() {
    let v = Value::Float(f64::NAN);
    assert!(value_to_json(&v).is_null());
}

#[test]
fn large_integer_above_i64_becomes_string() {
    let v = Value::Integer(i128::MAX);
    assert!(value_to_json(&v).is_string());
}

#[test]
fn map_with_text_key_becomes_object() {
    let v = Value::Map(vec![(
        Value::Text("name".into()),
        Value::Text("test".into()),
    )]);
    let j = value_to_json(&v);
    assert_eq!(j["name"], "test");
}

#[test]
fn map_with_non_standard_key_still_emits_object() {
    let v = Value::Map(vec![(Value::Bool(true), Value::Integer(1))]);
    let j = value_to_json(&v);
    assert!(j.is_object());
}

// ===========================================================================
// value_to_json — tagged-value translation
// ===========================================================================

#[test]
fn tag_oid_becomes_typed_object() {
    let v = Value::Tag(111, Box::new(Value::Bytes(vec![0x06, 0x03, 0x55, 0x04])));
    assert_eq!(value_to_json(&v)["type"], "oid");
}

#[test]
fn tag_ueid_with_non_bytes_payload_still_typed() {
    let v = Value::Tag(550, Box::new(Value::Text("not-bytes".into())));
    assert_eq!(value_to_json(&v)["type"], "ueid");
}

#[test]
fn tag_uuid_with_non_bytes_payload_still_typed() {
    let v = Value::Tag(37, Box::new(Value::Text("not-bytes".into())));
    assert_eq!(value_to_json(&v)["type"], "uuid");
}

#[test]
fn tag_svn_carries_value() {
    let v = Value::Tag(552, Box::new(Value::Integer(42)));
    let j = value_to_json(&v);
    assert_eq!(j["type"], "svn");
    assert_eq!(j["value"], 42);
}

#[test]
fn tag_min_svn_typed() {
    let v = Value::Tag(553, Box::new(Value::Integer(10)));
    assert_eq!(value_to_json(&v)["type"], "min-svn");
}

#[test]
fn crypto_key_tag_table_roundtrips_to_named_type() {
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
        assert_eq!(value_to_json(&v)["type"], expected_type, "tag {tag}");
    }
}

#[test]
fn coswid_comid_cotl_tags_use_cbor_tag_envelope() {
    for tag in [505, 506, 508] {
        let v = Value::Tag(tag, Box::new(Value::Bytes(vec![0xA0])));
        assert_eq!(value_to_json(&v)["__cbor_tag"], tag);
    }
}

#[test]
fn unknown_tag_uses_cbor_tag_envelope() {
    let v = Value::Tag(99999, Box::new(Value::Text("hello".into())));
    let j = value_to_json(&v);
    assert_eq!(j["__cbor_tag"], 99999);
    assert_eq!(j["__cbor_value"], "hello");
}

#[test]
fn epoch_time_tag_unwraps_to_inner_integer() {
    let v = Value::Tag(1, Box::new(Value::Integer(1234567890)));
    assert_eq!(value_to_json(&v), 1234567890);
}

// ===========================================================================
// json_to_value — typed-object dispatch
// ===========================================================================

#[test]
fn typed_svn_object_to_tag() {
    let j = serde_json::json!({"type": "svn", "value": 42});
    assert!(matches!(json_to_value(&j), Value::Tag(552, _)));
}

#[test]
fn typed_min_svn_object_to_tag() {
    let j = serde_json::json!({"type": "min-svn", "value": 10});
    assert!(matches!(json_to_value(&j), Value::Tag(553, _)));
}

#[test]
fn typed_crypto_key_objects_dispatch_to_tags() {
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
        match json_to_value(&j) {
            Value::Tag(t, _) => assert_eq!(t, expected_tag, "type: {type_name}"),
            other => panic!("expected tag for {type_name}, got {other:?}"),
        }
    }
}

#[test]
fn typed_ueid_with_base64_string_decodes_to_bytes() {
    let j = serde_json::json!({"type": "ueid", "value": "AQID"});
    match json_to_value(&j) {
        Value::Tag(550, inner) => assert!(matches!(*inner, Value::Bytes(_))),
        _ => panic!("expected tag 550"),
    }
}

#[test]
fn typed_bytes_with_base64_string_decodes_to_bytes() {
    let j = serde_json::json!({"type": "bytes", "value": "AQID"});
    match json_to_value(&j) {
        Value::Tag(560, inner) => assert!(matches!(*inner, Value::Bytes(_))),
        _ => panic!("expected tag 560"),
    }
}

#[test]
fn typed_uuid_with_invalid_format_falls_back_to_recursive_value() {
    let j = serde_json::json!({"type": "uuid", "value": "not-a-uuid"});
    assert!(matches!(json_to_value(&j), Value::Tag(37, _)));
}

#[test]
fn unknown_typed_object_preserved_as_map() {
    let j = serde_json::json!({"type": "custom-type", "value": "data"});
    assert!(matches!(json_to_value(&j), Value::Map(_)));
}

#[test]
fn cbor_tag_envelope_object_round_trips_to_tag() {
    let j = serde_json::json!({"__cbor_tag": 501, "__cbor_value": {"0": "test"}});
    assert!(matches!(json_to_value(&j), Value::Tag(501, _)));
}

// ===========================================================================
// json_to_value — number kinds
// ===========================================================================

#[test]
fn u64_max_becomes_integer_value() {
    let j = serde_json::json!(u64::MAX);
    assert!(matches!(json_to_value(&j), Value::Integer(_)));
}

#[test]
fn float_becomes_float_value() {
    let j = serde_json::json!(core::f64::consts::PI);
    assert!(matches!(json_to_value(&j), Value::Float(_)));
}

// ===========================================================================
// json_to_value — string-key-to-int-key mapping
// ===========================================================================

#[test]
fn registered_string_key_maps_to_int() {
    // "entity-name" is in the global key table at index 31.
    let j = serde_json::json!({"entity-name": "ACME"});
    if let Value::Map(entries) = json_to_value(&j) {
        assert_eq!(entries[0].0, Value::Integer(31));
    } else {
        panic!("expected map");
    }
}

#[test]
fn numeric_string_key_parses_to_int() {
    let j = serde_json::json!({"99": "value"});
    if let Value::Map(entries) = json_to_value(&j) {
        assert_eq!(entries[0].0, Value::Integer(99));
    } else {
        panic!("expected map");
    }
}

#[test]
fn unregistered_non_numeric_key_stays_text() {
    let j = serde_json::json!({"custom-key": "value"});
    if let Value::Map(entries) = json_to_value(&j) {
        assert_eq!(entries[0].0, Value::Text("custom-key".into()));
    } else {
        panic!("expected map");
    }
}

// ===========================================================================
// to_json_pretty / from_json
// ===========================================================================

#[test]
fn pretty_round_trip_preserves_structure() {
    use corim::json;
    use corim::types::environment::ClassMap;
    let class = ClassMap::new("Test", "Widget");
    let pretty = json::to_json_pretty(&class).unwrap();
    assert!(pretty.contains('\n'));
    let decoded: ClassMap = json::from_json(&pretty).unwrap();
    assert_eq!(class, decoded);
}

#[test]
fn from_json_invalid_input_errors() {
    use corim::json;
    use corim::types::environment::ClassMap;
    assert!(json::from_json::<ClassMap>("not valid json{{{").is_err());
}
