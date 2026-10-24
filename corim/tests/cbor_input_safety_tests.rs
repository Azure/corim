// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Regressions for input-triggered CBOR panics (RFC 8949 §10).

use corim::cbor::{self, constants as c, value::Value};

fn oversized_strings_are_errors(major: u8, prefix: &[u8]) {
    // Include lengths that overflow at different reader offsets, plus one
    // that is representable but exceeds the remaining input.
    for len in [u64::MAX, u64::MAX - 1, u64::MAX - 8, u64::MAX - 9, 1024] {
        let mut input = prefix.to_vec();
        input.push((major << 5) | c::AI_EIGHT_BYTES);
        input.extend_from_slice(&len.to_be_bytes());
        assert!(
            cbor::decode::<Value>(&input).is_err(),
            "declared length {len} must return an error"
        );
    }
}

#[test]
fn oversized_byte_string_lengths_return_errors() {
    oversized_strings_are_errors(c::MAJOR_BYTES, &[]);
}

#[test]
fn oversized_text_string_lengths_return_errors() {
    oversized_strings_are_errors(c::MAJOR_TEXT, &[]);
}

#[test]
fn oversized_nested_string_lengths_return_errors() {
    // One-element array shifts the reader offset before the string header.
    let prefix = [(c::MAJOR_ARRAY << 5) | 1];
    oversized_strings_are_errors(c::MAJOR_BYTES, &prefix);
    oversized_strings_are_errors(c::MAJOR_TEXT, &prefix);
}

#[test]
fn truncated_and_exact_length_strings() {
    for major in [c::MAJOR_BYTES, c::MAJOR_TEXT] {
        let input = [(major << 5) | 2, b'a', b'b'];
        assert!(cbor::decode::<Value>(&input[..2]).is_err());
        let expected = if major == c::MAJOR_BYTES {
            Value::Bytes(b"ab".to_vec())
        } else {
            Value::Text("ab".into())
        };
        assert_eq!(cbor::decode::<Value>(&input).unwrap(), expected);
        assert!(cbor::decode::<Value>(&[major << 5]).is_ok());
    }
}

#[test]
fn out_of_range_integer_map_keys_return_encode_errors() {
    for n in [i128::MAX, i128::MIN] {
        let map = Value::Map(vec![(Value::Integer(n), Value::Null)]);
        assert!(cbor::encode(&map).is_err());
    }
}

#[test]
fn out_of_range_integer_inside_compound_map_key_returns_encode_error() {
    let key = Value::Array(vec![Value::Integer(i128::MAX)]);
    let map = Value::Map(vec![(key, Value::Null)]);
    assert!(cbor::encode(&map).is_err());
}

#[test]
fn representable_integer_map_key_boundaries_round_trip() {
    // RFC 8949 §3.1: major types 0/1 cover -2^64 through 2^64-1.
    let map = Value::Map(vec![
        (Value::Integer(i128::from(u64::MAX)), Value::Bool(true)),
        (
            Value::Integer(-1 - i128::from(u64::MAX)),
            Value::Bool(false),
        ),
    ]);
    let encoded = cbor::encode(&map).unwrap();
    assert_eq!(cbor::decode::<Value>(&encoded).unwrap(), map);
}
