// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! The direct serde bridge must retain CBOR wire and resource boundaries.
use corim::cbor::value::{from_value, to_value, Value};
use corim::cbor::{DEFAULT_MAX_INPUT_BYTES, DEFAULT_MAX_VALUES, MAX_DECODE_DEPTH};
use corim::types::signed::{CoseLabel, NumericDate};

#[test]
fn bridge_rejects_out_of_range_integers_before_typed_replay() {
    for n in [
        i128::MIN,
        -(1_i128 << 64) - 1,
        i128::from(u64::MAX) + 1,
        i128::MAX,
    ] {
        let value = Value::Integer(n);
        assert!(to_value(&value).is_err(), "to_value accepted {n}");
        assert!(to_value(&n).is_err(), "raw integer accepted {n}");
        assert!(
            from_value::<Value>(&value).is_err(),
            "Value replay accepted {n}"
        );
        assert!(
            from_value::<CoseLabel>(&value).is_err(),
            "label replay accepted {n}"
        );
        assert!(
            from_value::<NumericDate>(&value).is_err(),
            "date replay accepted {n}"
        );
        assert!(
            from_value::<serde::de::IgnoredAny>(&value).is_err(),
            "ignored replay accepted {n}"
        );
    }
}

#[test]
fn bridge_rejects_nested_unencodable_keys_and_values_even_when_ignored() {
    for n in [i128::MIN, i128::MAX] {
        let invalid = Value::Integer(n);
        for value in [
            Value::Array(vec![invalid.clone()]),
            Value::Map(vec![(invalid.clone(), Value::Null)]),
            Value::Map(vec![(Value::Text("ignored".into()), invalid.clone())]),
            Value::Tag(10001, Box::new(invalid.clone())),
            Value::Map(vec![(Value::Array(vec![invalid.clone()]), Value::Null)]),
            Value::Array(vec![Value::Map(vec![(Value::Null, invalid)])]),
        ] {
            assert!(to_value(&value).is_err(), "serialized {value:?}");
            assert!(from_value::<Value>(&value).is_err(), "replayed {value:?}");
            assert!(
                from_value::<serde::de::IgnoredAny>(&value).is_err(),
                "ignored {value:?}"
            );
        }
    }
}

#[test]
fn bridge_preserves_cbor_integer_extremes_map_order_and_duplicates() {
    let value = Value::Map(vec![
        (Value::Text("1".into()), Value::Integer(-(1_i128 << 64))),
        (Value::Integer(1), Value::Integer(i128::from(u64::MAX))),
        (
            Value::Text("1".into()),
            Value::Integer(i128::from(i64::MIN)),
        ),
    ]);
    assert_eq!(to_value(&value).unwrap(), value);
    assert_eq!(from_value::<Value>(&value).unwrap(), value);
}

#[test]
fn bridge_bounds_tree_before_replaying_ignored_content() {
    let mut value = Value::Null;
    for _ in 0..MAX_DECODE_DEPTH {
        value = Value::Array(vec![value]);
    }
    assert_eq!(to_value(&value).unwrap(), value);
    assert_eq!(from_value::<Value>(&value).unwrap(), value);
    let too_deep = Value::Array(vec![value]);
    let too_many = Value::Array(vec![Value::Null; DEFAULT_MAX_VALUES]);
    let too_large = Value::Bytes(vec![0; DEFAULT_MAX_INPUT_BYTES]);
    for value in [too_deep, too_many, too_large] {
        assert!(to_value(&value).is_err());
        assert!(from_value::<serde::de::IgnoredAny>(&value).is_err());
    }
}
