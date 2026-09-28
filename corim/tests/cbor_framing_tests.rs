// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use corim::cbor::{
    self, constants as c, decode_exact_with_limits as exact, decode_prefix_with_limits as prefix,
    value::Tagged, value::Value, CborCodec, DecodeLimits, DecodeSession, DefaultCodec,
};
use corim::{types::tags::TAG_CORIM, DecodeError};
use serde::{de::DeserializeOwned, Deserialize, Deserializer, Serialize};
use std::{
    fmt::Debug,
    sync::atomic::{AtomicUsize, Ordering},
};

/// Reserved additional information 28, invalid for unsigned integers (RFC 8949 §3).
const INVALID_HEAD: u8 = 0x1c;

fn trailing<T: Debug>(result: Result<T, DecodeError>, expected: usize) {
    assert!(
        matches!(result, Err(DecodeError::TrailingData { remaining }) if remaining == expected),
        "{result:?}"
    );
}

fn limit<T: Debug>(result: Result<T, DecodeError>, expected: &str, cap: usize) {
    assert!(
        matches!(result, Err(DecodeError::LimitExceeded { resource, limit }) if resource == expected && limit == cap),
        "{result:?}"
    );
}

fn syntax<T: Debug>(result: Result<T, DecodeError>) {
    assert!(
        matches!(result, Err(DecodeError::Deserialization(_))),
        "{result:?}"
    );
}

fn round_trip<T: Serialize + DeserializeOwned + PartialEq + Debug>(value: T) {
    let mut bytes = cbor::encode(&value).unwrap();
    let end = bytes.len();
    assert_eq!(cbor::decode_exact::<T>(&bytes).unwrap(), value);
    let (decoded, rest) = cbor::decode_prefix::<T>(&bytes).unwrap();
    assert_eq!(decoded, value);
    assert!(rest.is_empty());
    assert_eq!(rest.as_ptr(), bytes[end..].as_ptr());
    bytes.extend_from_slice(&[INVALID_HEAD, c::BYTE_NULL]);
    let (decoded, rest) = cbor::decode_prefix::<T>(&bytes).unwrap();
    assert_eq!(decoded, value);
    assert_eq!(rest, &bytes[end..]);
    assert_eq!(rest.as_ptr(), bytes[end..].as_ptr());
    trailing(cbor::decode_exact::<T>(&bytes), 2);
}

#[test]
fn typed_and_value_framing_borrows_unparsed_suffix() {
    round_trip(42u64);
    round_trip(String::from("framing"));
    round_trip(Tagged::new(TAG_CORIM, String::from("tagged")));
    round_trip(Value::Tag(TAG_CORIM, Box::new(Value::Integer(42))));
    round_trip(Value::Array(vec![
        Value::Null,
        Value::Text("nested".into()),
    ]));
}

#[test]
fn session_prefix_sequence_charges_only_each_parsed_item() {
    let first = cbor::encode(&Value::Array(vec![Value::Null])).unwrap();
    let second = cbor::encode(&String::from("next")).unwrap();
    let bytes = [first.as_slice(), second.as_slice()].concat();
    let mut limits = DecodeLimits::default();
    limits.max_values = 3; // Array + null + text, not the suffix on the first call.
    let mut session = DecodeSession::new(&limits).unwrap();
    let (value, rest) = session.decode_prefix::<Value>(&bytes).unwrap();
    assert_eq!(value, Value::Array(vec![Value::Null]));
    assert_eq!(rest.as_ptr(), bytes[first.len()..].as_ptr());
    let (text, rest) = session.decode_prefix::<String>(rest).unwrap();
    assert_eq!(text, "next");
    assert!(rest.is_empty());
    assert_eq!(rest.as_ptr(), bytes[bytes.len()..].as_ptr());
    limit(session.decode_exact::<Value>(&[c::BYTE_NULL]), "values", 3);
}

#[test]
fn empty_truncated_and_invalid_heads_are_syntax_errors() {
    let integer = cbor::encode(&256u64).unwrap();
    let text = cbor::encode(&String::from("abc")).unwrap();
    let array = cbor::encode(&vec![true]).unwrap();
    let limits = DecodeLimits::default();
    let inputs = [
        &[][..],
        &integer[..1],
        &text[..2],
        &array[..1],
        &[INVALID_HEAD],
    ];
    for bytes in inputs {
        syntax(cbor::decode_exact::<Value>(bytes));
        syntax(cbor::decode_prefix::<Value>(bytes));
        syntax(exact::<u64>(bytes, &limits));
        syntax(prefix::<String>(bytes, &limits));
        let mut session = DecodeSession::new(&limits).unwrap();
        syntax(session.decode_exact::<Value>(bytes));
        syntax(session.decode_prefix::<Value>(bytes));
    }
}

#[test]
fn exact_checks_framing_before_invoking_typed_deserializer() {
    static CALLS: AtomicUsize = AtomicUsize::new(0);
    #[derive(Debug)]
    struct Counted;
    impl<'de> Deserialize<'de> for Counted {
        fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
            CALLS.fetch_add(1, Ordering::SeqCst);
            bool::deserialize(d)?;
            Ok(Self)
        }
    }
    let bytes = [c::BYTE_TRUE, INVALID_HEAD];
    let limits = DecodeLimits::default();
    let mut session = DecodeSession::new(&limits).unwrap();
    trailing(cbor::decode_exact::<Counted>(&bytes), 1);
    trailing(exact::<Counted>(&bytes, &limits), 1);
    trailing(session.decode_exact::<Counted>(&bytes), 1);
    trailing(session.decode_nested_exact::<Counted>(&bytes, 1), 1);
    assert_eq!(CALLS.load(Ordering::SeqCst), 0);
    session.decode_exact::<Counted>(&bytes[..1]).unwrap();
    cbor::decode_prefix::<Counted>(&bytes).unwrap();
    assert_eq!(CALLS.load(Ordering::SeqCst), 2);
}

#[test]
fn explicit_depth_value_and_collection_caps_precede_trailing_detection() {
    // Map + key + tag + array + bool: five nodes, three enclosing containers.
    let value = Value::Map(vec![(
        Value::Integer(0),
        Value::Tag(TAG_CORIM, Box::new(Value::Array(vec![Value::Bool(true)]))),
    )]);
    let mut bytes = cbor::encode(&value).unwrap();
    let end = bytes.len();
    bytes.push(INVALID_HEAD);
    for (resource, cap) in [("depth", 3), ("values", 5), ("collection entries", 1)] {
        let mut limits = DecodeLimits::default();
        let set = |limits: &mut DecodeLimits, cap| match resource {
            "depth" => limits.max_depth = cap,
            "values" => limits.max_values = cap,
            _ => limits.max_collection_items = cap,
        };
        set(&mut limits, cap);
        assert_eq!(exact::<Value>(&bytes[..end], &limits).unwrap(), value);
        let (decoded, rest) = prefix::<Value>(&bytes, &limits).unwrap();
        assert_eq!(decoded, value);
        assert_eq!(rest.as_ptr(), bytes[end..].as_ptr());
        trailing(exact::<Value>(&bytes, &limits), 1);
        set(&mut limits, cap - 1);
        limit(exact::<Value>(&bytes, &limits), resource, cap - 1);
        limit(prefix::<Value>(&bytes, &limits), resource, cap - 1);
    }
}

#[test]
fn whole_slice_input_cap_applies_even_to_unparsed_suffix() {
    let bytes = [c::BYTE_TRUE, INVALID_HEAD];
    let mut limits = DecodeLimits::default();
    limits.max_input_bytes = bytes.len();
    assert!(prefix::<bool>(&bytes, &limits).unwrap().0);
    trailing(exact::<bool>(&bytes, &limits), 1);
    // The documented cap is on the supplied slice, not the consumed prefix.
    limits.max_input_bytes = 1;
    assert!(exact::<bool>(&bytes[..1], &limits).unwrap());
    limit(exact::<bool>(&bytes, &limits), "input bytes", 1);
    limit(prefix::<bool>(&bytes, &limits), "input bytes", 1);
    let mut session = DecodeSession::new(&limits).unwrap();
    limit(session.decode_prefix::<bool>(&bytes), "input bytes", 1);
    limit(session.decode_exact::<bool>(&bytes[..1]), "input bytes", 1);
}

#[test]
fn failed_prefix_syntax_and_type_conversion_consume_parsed_nodes() {
    let mut malformed = cbor::encode(&vec![true, false]).unwrap();
    *malformed.last_mut().unwrap() = INVALID_HEAD;
    let text = cbor::encode(&String::from("not a bool")).unwrap();
    for (bytes, spent) in [(malformed, 3), (text, 1)] {
        let mut limits = DecodeLimits::default();
        limits.max_values = spent + 1;
        let mut session = DecodeSession::new(&limits).unwrap();
        syntax(session.decode_prefix::<bool>(&bytes));
        assert!(session.decode_prefix::<bool>(&[c::BYTE_TRUE]).unwrap().0);
        let exhausted = session.decode_prefix::<Value>(&[c::BYTE_NULL]);
        limit(exhausted, "values", spent + 1);
        let sticky = session.decode_nested_exact::<Value>(&[c::BYTE_NULL], 0);
        limit(sticky, "values", spent + 1);
    }
}

#[test]
fn trailing_failure_charges_first_item_but_is_not_sticky() {
    let mut limits = DecodeLimits::default();
    limits.max_values = 2;
    let mut session = DecodeSession::new(&limits).unwrap();
    let bytes = [c::BYTE_TRUE, INVALID_HEAD];
    trailing(session.decode_exact::<bool>(&bytes), 1);
    assert!(session.decode_exact::<bool>(&[c::BYTE_TRUE]).unwrap());
    limit(session.decode_prefix::<Value>(&[c::BYTE_NULL]), "values", 2);
    limit(session.decode_exact::<Value>(&[]), "values", 2);
}

#[test]
fn nested_exact_retains_enclosing_depth_and_shared_budget() {
    let array = cbor::encode(&vec![true]).unwrap();
    let mut limits = DecodeLimits::default();
    limits.max_depth = 2;
    limits.max_values = 4;
    let mut session = DecodeSession::new(&limits).unwrap();
    let decoded = session.decode_nested_exact::<Vec<bool>>(&array, 1).unwrap();
    assert_eq!(decoded, vec![true]);
    let bytes = [c::BYTE_TRUE, INVALID_HEAD];
    trailing(session.decode_nested_exact::<bool>(&bytes, 2), 1);
    assert!(session.decode_nested_exact::<bool>(&bytes[..1], 2).unwrap());
    limit(session.decode_exact::<bool>(&[c::BYTE_TRUE]), "values", 4);
    for (bytes, depth) in [(array.as_slice(), 2), (&[c::BYTE_TRUE][..], 3)] {
        let mut session = DecodeSession::new(&limits).unwrap();
        let exceeded = session.decode_nested_exact::<Value>(bytes, depth);
        limit(exceeded, "depth", 2);
        limit(session.decode_prefix::<bool>(&[c::BYTE_TRUE]), "depth", 2);
    }
}

#[test]
fn legacy_decoders_including_default_codec_keep_prefix_semantics() {
    let limits = DecodeLimits::default();
    for suffix in [c::BYTE_FALSE, INVALID_HEAD] {
        let bytes = [c::BYTE_TRUE, suffix];
        assert!(cbor::decode::<bool>(&bytes).unwrap());
        assert!(cbor::decode_with_limits::<bool>(&bytes, &limits).unwrap());
        assert!(<DefaultCodec as CborCodec>::decode::<bool>(&bytes).unwrap());
        let mut session = DecodeSession::new(&limits).unwrap();
        assert!(session.decode::<bool>(&bytes).unwrap());
        assert!(session.decode_nested::<bool>(&bytes, 0).unwrap());
        trailing(cbor::decode_exact::<bool>(&bytes), 1);
    }
}
