// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Behavioral tests for the strict, lossless CBOR JSON contract.
#![cfg(feature = "json")]

use corim::cbor::value::Value;
use corim::json::{from_json, json_to_value, parse_json, to_json, value_to_json};
use serde_json::json;

#[test]
fn lossless_float_bits_and_typed_duplicate_map_keys() {
    let bits = 0xfff8_0000_0000_0123;
    let value = Value::Map(vec![
        (Value::Integer(1), Value::Float(f64::from_bits(bits))),
        (Value::Text("1".into()), Value::Bytes(vec![0, 255])),
        (Value::Integer(1), Value::Bool(true)),
    ]);
    let encoded = to_json(&value).unwrap();
    let decoded: Value = from_json(&encoded).unwrap();
    match decoded {
        Value::Map(entries) => {
            assert_eq!(entries.len(), 3);
            assert_eq!(entries[0].0, Value::Integer(1));
            match entries[0].1 {
                Value::Float(float) => assert_eq!(float.to_bits(), bits),
                ref other => panic!("lost float: {other:?}"),
            }
            assert_eq!(
                entries[1],
                (Value::Text("1".into()), Value::Bytes(vec![0, 255]))
            );
            assert_eq!(entries[2], (Value::Integer(1), Value::Bool(true)));
        }
        other => panic!("lost map: {other:?}"),
    }
}

#[test]
fn exact_schema_for_all_value_types() {
    let cases = vec![
        (Value::Null, json!(null)),
        (Value::Bool(false), json!(false)),
        (Value::Text("text".into()), json!("text")),
        (Value::Integer(-42), json!({"type":"integer","value":"-42"})),
        (
            Value::Bytes(vec![0, 255]),
            json!({"type":"byte-string","value":"00ff"}),
        ),
        (
            Value::Float(1.5),
            json!({"type":"float-bits","value":"3ff8000000000000"}),
        ),
        (Value::Array(vec![Value::Null]), json!([null])),
        (Value::Map(vec![]), json!({"type":"map","value":[]})),
        (
            Value::Tag(u64::MAX, Box::new(Value::Null)),
            json!({"type":"tag","tag":"18446744073709551615","value":null}),
        ),
    ];
    for (value, expected) in cases {
        assert_eq!(value_to_json(&value).unwrap(), expected);
        assert_eq!(json_to_value(&expected).unwrap(), value);
    }
}

#[test]
fn floats_preserve_finite_nonfinite_signed_zero_and_nan_payloads() {
    for bits in [
        0,
        1,
        0x8000_0000_0000_0000,
        0x3ff0_0000_0000_0000,
        0x7fef_ffff_ffff_ffff,
        0x7ff0_0000_0000_0000,
        0xfff0_0000_0000_0000,
        0x7ff8_0000_0000_0123,
        0xfff0_0000_0000_0001,
    ] {
        let value = Value::Float(f64::from_bits(bits));
        let encoded = to_json(&value).unwrap();
        match from_json::<Value>(&encoded).unwrap() {
            Value::Float(n) => assert_eq!(n.to_bits(), bits),
            other => panic!("lost float: {other:?}"),
        }
    }
}

#[test]
fn integer_extremes_roundtrip_and_overflow_is_rejected() {
    for n in [
        -(1_i128 << 64),
        i128::from(i64::MIN),
        0,
        i128::from(u64::MAX),
    ] {
        let value = Value::Integer(n);
        assert_eq!(
            from_json::<Value>(&to_json(&value).unwrap()).unwrap(),
            value
        );
    }
    for n in [
        i128::MIN,
        -(1_i128 << 64) - 1,
        i128::from(u64::MAX) + 1,
        i128::MAX,
    ] {
        assert!(value_to_json(&Value::Integer(n)).is_err());
        assert!(json_to_value(&json!({"type":"integer","value":n.to_string()})).is_err());
    }
}

#[test]
fn complex_keys_duplicate_entries_and_wrapper_shaped_maps_roundtrip() {
    let value = Value::Map(vec![
        (Value::Text("type".into()), Value::Text("integer".into())),
        (Value::Text("value".into()), Value::Text("42".into())),
        (Value::Bool(true), Value::Null),
        (Value::Bytes(vec![1]), Value::Array(vec![])),
        (Value::Array(vec![Value::Integer(1)]), Value::Null),
        (
            Value::Map(vec![]),
            Value::Tag(32, Box::new(Value::Text("uri".into()))),
        ),
        (Value::Integer(1), Value::Text("first".into())),
        (Value::Text("1".into()), Value::Text("text".into())),
        (Value::Integer(1), Value::Text("second".into())),
    ]);
    assert_eq!(
        from_json::<Value>(&to_json(&value).unwrap()).unwrap(),
        value
    );
}

#[test]
fn malformed_wrappers_and_legacy_schema_are_rejected() {
    for value in [
        json!(1),
        json!(1.5),
        json!({}),
        json!({"corim-id":"old"}),
        json!({"type":"uuid","value":"01010101"}),
        json!({"__cbor_tag":32,"__cbor_value":"uri"}),
        json!({"type":"integer"}),
        json!({"type":"integer","value":"1","extra":false}),
        json!({"type":"integer","value":1}),
        json!({"type":"integer","value":"+1"}),
        json!({"type":"integer","value":"01"}),
        json!({"type":"integer","value":"-0"}),
        json!({"type":"integer","value":" 1"}),
        json!({"type":"integer","value":"1.0"}),
        json!({"type":"integer","value":"9999999999999999999999999999999999999999"}),
        json!({"type":"byte-string","value":"0"}),
        json!({"type":"byte-string","value":"AA"}),
        json!({"type":"byte-string","value":"gg"}),
        json!({"type":"byte-string","value":null}),
        json!({"type":"float-bits","value":"0000"}),
        json!({"type":"float-bits","value":"FFF0000000000000"}),
        json!({"type":"float-bits","value":"xxx0000000000000"}),
        json!({"type":"tag","value":null}),
        json!({"type":"tag","tag":32,"value":null}),
        json!({"type":"tag","tag":"-1","value":null}),
        json!({"type":"tag","tag":"18446744073709551616","value":null}),
        json!({"type":"tag","tag":"01","value":null}),
        json!({"type":"tag","tag":"32","value":null,"extra":0}),
        json!({"type":"map","value":{}}),
        json!({"type":"map","value":[[]]}),
        json!({"type":"map","value":[[null]]}),
        json!({"type":"map","value":[[null,null,null]]}),
        json!({"type":"map","value":[[null,3]]}),
    ] {
        assert!(json_to_value(&value).is_err(), "accepted {value}");
    }
}

#[test]
fn parse_rejects_duplicate_members_trailing_data_and_excessive_nesting() {
    for text in [
        r#"{"type":"integer","type":"integer","value":"1"}"#,
        r#"{"type":"integer","value":"1","value":"2"}"#,
        "null null",
        "[",
        "NaN",
    ] {
        assert!(parse_json(text).is_err(), "accepted {text}");
    }
    let text = format!("{}null{}", "[".repeat(300), "]".repeat(300));
    assert!(parse_json(&text).is_err());
}

#[test]
fn sixty_four_deep_maps_survive_expanded_json_nesting() {
    let mut value = Value::Null;
    for _ in 0..64 {
        value = Value::Map(vec![(Value::Null, value)]);
    }
    let text = to_json(&value).unwrap();
    assert!(
        serde_json::from_str::<serde_json::Value>(&text).is_err(),
        "fixture must exceed serde_json's default recursion limit"
    );
    assert_eq!(from_json::<Value>(&text).unwrap(), value);
    let excessive = Value::Array(vec![value]);
    assert!(value_to_json(&excessive).is_err());
}

#[test]
fn bytes_and_tags_are_never_semantically_coerced() {
    for tag in [18, 32, 37, 111, 501, 506, 550, u64::MAX] {
        for inner in [
            Value::Bytes(vec![0, 255]),
            Value::Text("not bytes".into()),
            Value::Null,
        ] {
            let value = Value::Tag(tag, Box::new(inner));
            assert_eq!(
                from_json::<Value>(&to_json(&value).unwrap()).unwrap(),
                value
            );
        }
    }
    let bytes = Value::Bytes(vec![]);
    assert_eq!(
        from_json::<Value>(&to_json(&bytes).unwrap()).unwrap(),
        bytes
    );
}

#[test]
fn direct_tree_decoding_enforces_depth_node_and_scalar_budgets() {
    let mut array = json!(null);
    for _ in 0..65 {
        array = json!([array]);
    }
    assert!(json_to_value(&array).is_err());
    assert!(json_to_value(&json!(vec![serde_json::Value::Null; 1_000_001])).is_err());
    let text = serde_json::Value::String("x".repeat(16 * 1024 * 1024 + 1));
    assert!(json_to_value(&text).is_err());
}

#[test]
fn document_json_strings_enforce_default_byte_limit_after_expansion() {
    let limit = corim::cbor::DEFAULT_MAX_INPUT_BYTES;
    let mut value = Value::Array(vec![Value::Bytes(vec![]), Value::Text(String::new())]);
    let overhead = to_json(&value).unwrap().len();
    assert_eq!((limit - overhead) % 2, 0);
    let Value::Array(nodes) = &mut value else {
        panic!()
    };
    nodes[0] = Value::Bytes(vec![0; (limit - overhead) / 2]);

    let mut exact = to_json(&value).unwrap();
    assert_eq!(exact.len(), limit);
    assert_eq!(from_json::<Value>(&exact).unwrap(), value);
    assert!(
        corim::json::to_json_pretty(&value).is_err(),
        "pretty expansion must obey the same byte limit"
    );

    exact.push(' ');
    assert!(
        from_json::<Value>(&exact).is_err(),
        "one excess input byte must be rejected"
    );
    drop(exact);
    let Value::Array(nodes) = &mut value else {
        panic!()
    };
    nodes[1] = Value::Text("x".into());
    assert!(
        to_json(&value).is_err(),
        "one excess output byte must be rejected"
    );
}
