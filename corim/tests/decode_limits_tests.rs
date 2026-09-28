// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Resource-limit regressions for untrusted CBOR (RFC 8949 §10).

use corim::cbor::{self, constants as c, minimal, value::Value, DecodeLimits};

#[test]
fn session_counts_failed_attempts_and_stays_failed_after_limit() {
    let mut limits = DecodeLimits::default();
    limits.max_values = 4;
    let mut session = cbor::DecodeSession::new(&limits).unwrap();
    // The failed attempt consumes an array, null, and invalid item: three nodes.
    let malformed = [(c::MAJOR_ARRAY << 5) | 2, c::BYTE_NULL, 0xff];
    assert!(session.decode::<Value>(&malformed).is_err());
    assert_eq!(
        session.decode::<Value>(&[c::BYTE_NULL]).unwrap(),
        Value::Null
    );
    assert_limit(session.decode::<Value>(&[c::BYTE_NULL]), "values", 4);
    assert_limit(session.decode::<Value>(&[]), "values", 4);
}

#[test]
fn session_nested_depth_is_checked_for_scalars_and_containers() {
    let mut limits = DecodeLimits::default();
    limits.max_depth = 2;
    let mut session = cbor::DecodeSession::new(&limits).unwrap();
    assert!(session.decode_nested::<Value>(&[c::BYTE_NULL], 2).is_ok());
    assert_limit(
        session.decode_nested::<Value>(&[(c::MAJOR_ARRAY << 5)], 2),
        "depth",
        2,
    );
    let mut session = cbor::DecodeSession::new(&limits).unwrap();
    assert_limit(
        session.decode_nested::<Value>(&[c::BYTE_NULL], 3),
        "depth",
        2,
    );
}
use corim::types::tags::TAG_LEGACY_TOP;
use corim::DecodeError;

fn nested_arrays(depth: usize) -> Vec<u8> {
    let mut bytes = vec![(c::MAJOR_ARRAY << 5) | 1; depth];
    bytes.push(c::BYTE_NULL);
    bytes
}

fn declared_collection(major: u8, count: usize) -> Vec<u8> {
    let mut bytes = vec![(major << 5) | c::AI_FOUR_BYTES];
    bytes.extend_from_slice(&u32::try_from(count).unwrap().to_be_bytes());
    bytes
}

fn assert_limit<T: std::fmt::Debug>(result: Result<T, DecodeError>, resource: &str, limit: usize) {
    match result {
        Err(DecodeError::LimitExceeded {
            resource: actual,
            limit: actual_limit,
        }) => {
            assert_eq!(actual, resource);
            assert_eq!(actual_limit, limit);
        }
        other => panic!("expected {resource} limit {limit}, got {other:?}"),
    }
}

fn nodes(value: &Value) -> usize {
    1 + match value {
        Value::Array(items) => items.iter().map(nodes).sum(),
        Value::Map(entries) => entries.iter().map(|(k, v)| nodes(k) + nodes(v)).sum(),
        Value::Tag(_, inner) => nodes(inner),
        _ => 0,
    }
}

#[test]
fn default_limits_match_the_public_contract() {
    let limits = DecodeLimits::default();
    assert_eq!(limits.max_input_bytes, 16 * 1024 * 1024);
    assert_eq!(limits.max_depth, 64);
    assert_eq!(limits.max_values, 1_000_000);
    assert_eq!(limits.max_collection_items, 2_000_000);
}

#[test]
fn scalar_depth_zero_and_empty_containers_depth_one() {
    let mut limits = DecodeLimits::default();
    limits.max_depth = 0;
    limits.max_values = 1;
    limits.max_collection_items = 0;
    for value in [
        Value::Null,
        Value::Integer(0),
        Value::Bytes(vec![]),
        Value::Text(String::new()),
    ] {
        let bytes = cbor::encode(&value).unwrap();
        assert_eq!(
            cbor::decode_with_limits::<Value>(&bytes, &limits).unwrap(),
            value
        );
    }
    for value in [Value::Array(vec![]), Value::Map(vec![])] {
        let bytes = cbor::encode(&value).unwrap();
        assert_limit(
            cbor::decode_with_limits::<Value>(&bytes, &limits),
            "depth",
            0,
        );
        limits.max_depth = 1;
        assert_eq!(
            cbor::decode_with_limits::<Value>(&bytes, &limits).unwrap(),
            value
        );
        limits.max_depth = 0;
    }
}

#[test]
fn zero_value_budget_rejects_even_scalar_and_empty_containers() {
    let mut limits = DecodeLimits::default();
    limits.max_values = 0;
    for value in [Value::Null, Value::Array(vec![]), Value::Map(vec![])] {
        assert_limit(
            cbor::decode_with_limits::<Value>(&cbor::encode(&value).unwrap(), &limits),
            "values",
            0,
        );
    }
}

#[test]
fn input_byte_budget_is_inclusive_and_can_be_zero() {
    let bytes = cbor::encode(&Value::Bytes(vec![0; 32])).unwrap();
    let mut limits = DecodeLimits::default();
    limits.max_input_bytes = bytes.len();
    assert!(cbor::decode_with_limits::<Value>(&bytes, &limits).is_ok());
    limits.max_input_bytes -= 1;
    assert_limit(
        cbor::decode_with_limits::<Value>(&bytes, &limits),
        "input bytes",
        limits.max_input_bytes,
    );
    limits.max_input_bytes = 0;
    assert_limit(
        cbor::decode_with_limits::<Value>(&[c::BYTE_NULL], &limits),
        "input bytes",
        0,
    );
    assert!(matches!(
        cbor::decode_with_limits::<Value>(&[], &limits),
        Err(DecodeError::Deserialization(_))
    ));
}

#[test]
fn trusted_callers_can_raise_the_default_input_budget() {
    let mut limits = DecodeLimits::default();
    // PR03 preserves prefix decoding: avoid duplicating a 16 MiB bstr while
    // proving that the byte limit checks the entire supplied slice.
    let bytes = vec![c::BYTE_NULL; limits.max_input_bytes + 1];
    let exact = &bytes[..limits.max_input_bytes];
    assert_eq!(cbor::decode::<Value>(exact).unwrap(), Value::Null);
    assert_eq!(
        minimal::decode_value(&mut minimal::SliceReader::new(exact)).unwrap(),
        Value::Null
    );
    assert_limit(
        cbor::decode::<Value>(&bytes),
        "input bytes",
        limits.max_input_bytes,
    );
    assert!(
        minimal::decode_value(&mut minimal::SliceReader::new(&bytes))
            .unwrap_err()
            .to_string()
            .contains("input bytes")
    );
    limits.max_input_bytes = bytes.len();
    assert_eq!(
        cbor::decode_with_limits::<Value>(&bytes, &limits).unwrap(),
        Value::Null
    );
}

#[test]
fn containers_map_keys_and_tags_each_consume_values() {
    let value = Value::Map(vec![
        (Value::Integer(0), Value::Bool(true)),
        (
            Value::Text("nested".into()),
            Value::Tag(
                TAG_LEGACY_TOP,
                Box::new(Value::Array(vec![Value::Null, Value::Map(vec![])])),
            ),
        ),
    ]);
    let bytes = cbor::encode(&value).unwrap();
    let mut limits = DecodeLimits::default();
    limits.max_values = nodes(&value);
    assert_eq!(
        cbor::decode_with_limits::<Value>(&bytes, &limits).unwrap(),
        value
    );
    limits.max_values -= 1;
    assert_limit(
        cbor::decode_with_limits::<Value>(&bytes, &limits),
        "values",
        limits.max_values,
    );
}

#[test]
fn array_map_and_tag_depth_is_additive() {
    let value = Value::Map(vec![(
        Value::Integer(0),
        Value::Tag(
            TAG_LEGACY_TOP,
            Box::new(Value::Array(vec![Value::Map(vec![])])),
        ),
    )]);
    let bytes = cbor::encode(&value).unwrap();
    let mut limits = DecodeLimits::default();
    limits.max_depth = 4;
    assert!(cbor::decode_with_limits::<Value>(&bytes, &limits).is_ok());
    limits.max_depth = 3;
    assert_limit(
        cbor::decode_with_limits::<Value>(&bytes, &limits),
        "depth",
        3,
    );
}

#[test]
fn collection_budget_counts_map_entries_not_keys_plus_values() {
    let mut limits = DecodeLimits::default();
    for value in [
        Value::Array(vec![Value::Null, Value::Null]),
        Value::Map(vec![
            (Value::Integer(0), Value::Null),
            (Value::Integer(1), Value::Null),
        ]),
    ] {
        let bytes = cbor::encode(&value).unwrap();
        limits.max_collection_items = 2;
        assert!(cbor::decode_with_limits::<Value>(&bytes, &limits).is_ok());
        limits.max_collection_items = 1;
        assert_limit(
            cbor::decode_with_limits::<Value>(&bytes, &limits),
            "collection entries",
            1,
        );
    }
    limits.max_collection_items = 0;
    assert_limit(
        cbor::decode_with_limits::<Value>(&nested_arrays(1), &limits),
        "collection entries",
        0,
    );
}

#[test]
fn collection_budget_is_per_container_not_aggregate() {
    let value = Value::Array(vec![Value::Array(vec![Value::Null; 2]); 2]);
    let mut limits = DecodeLimits::default();
    limits.max_collection_items = 2;
    assert_eq!(
        cbor::decode_with_limits::<Value>(&cbor::encode(&value).unwrap(), &limits).unwrap(),
        value
    );
}

#[test]
fn hard_ceilings_are_rejected_instead_of_clamped() {
    let mut limits = DecodeLimits::default();
    limits.max_depth = 65;
    assert!(matches!(
        cbor::decode_with_limits::<()>(&[c::BYTE_NULL], &limits),
        Err(DecodeError::InvalidStructure(_))
    ));
    limits = DecodeLimits::default();
    limits.max_collection_items = 2_000_001;
    assert!(matches!(
        cbor::decode_with_limits::<()>(&[c::BYTE_NULL], &limits),
        Err(DecodeError::InvalidStructure(_))
    ));
}

#[test]
fn truncated_wide_collections_reject_declared_work_before_reading_children() {
    for major in [c::MAJOR_ARRAY, c::MAJOR_MAP] {
        let mut limits = DecodeLimits::default();
        limits.max_values = usize::MAX;
        let at_ceiling = declared_collection(major, limits.max_collection_items);
        assert!(matches!(
            cbor::decode_with_limits::<Value>(&at_ceiling, &limits),
            Err(DecodeError::Deserialization(_))
        ));
        let above_ceiling = declared_collection(major, limits.max_collection_items + 1);
        assert_limit(
            cbor::decode_with_limits::<Value>(&above_ceiling, &limits),
            "collection entries",
            limits.max_collection_items,
        );
        limits.max_values = 4;
        assert_limit(
            cbor::decode_with_limits::<Value>(&declared_collection(major, 4), &limits),
            "values",
            4,
        );
    }
}

#[test]
fn map_keys_are_included_in_declared_minimum_work() {
    let bytes = declared_collection(c::MAJOR_MAP, 2);
    let mut limits = DecodeLimits::default();
    limits.max_values = 4; // map + two keys + two values needs five.
    assert_limit(
        cbor::decode_with_limits::<Value>(&bytes, &limits),
        "values",
        4,
    );
    limits.max_values = 5;
    assert!(matches!(
        cbor::decode_with_limits::<Value>(&bytes, &limits),
        Err(DecodeError::Deserialization(_))
    ));
}

#[test]
fn default_value_boundary_and_trusted_override() {
    let defaults = DecodeLimits::default();
    let bytes = declared_collection(c::MAJOR_ARRAY, defaults.max_values);
    assert_limit(cbor::decode::<Value>(&bytes), "values", defaults.max_values);
    let mut limits = defaults;
    limits.max_values += 1;
    // The declared minimum work is accepted with a raised budget, then the
    // missing children produce a syntax error. Do not materialize a million
    // Value nodes: that would exceed this regression suite's memory budget.
    assert!(matches!(
        cbor::decode_with_limits::<Value>(&bytes, &limits),
        Err(DecodeError::Deserialization(_))
    ));
    assert_eq!(
        cbor::decode_with_limits::<Value>(&[c::BYTE_NULL], &limits).unwrap(),
        Value::Null
    );
    let exact = declared_collection(c::MAJOR_ARRAY, defaults.max_values - 1);
    assert!(matches!(
        cbor::decode::<Value>(&exact),
        Err(DecodeError::Deserialization(_))
    ));
}

#[test]
fn generic_byte_strings_are_opaque_not_implicitly_decoded() {
    let value = Value::Bytes(nested_arrays(40_000));
    let mut limits = DecodeLimits::default();
    limits.max_depth = 0;
    limits.max_values = 1;
    assert_eq!(
        cbor::decode_with_limits::<Value>(&cbor::encode(&value).unwrap(), &limits).unwrap(),
        value
    );
}

#[test]
fn direct_minimal_decode_uses_default_resource_limits() {
    let mut reader = minimal::SliceReader::new(&[c::BYTE_NULL]);
    assert_eq!(minimal::decode_value(&mut reader).unwrap(), Value::Null);
    for bytes in [
        nested_arrays(65),
        declared_collection(c::MAJOR_ARRAY, 1_000_000),
        declared_collection(c::MAJOR_MAP, 2_000_001),
    ] {
        let error = minimal::decode_value(&mut minimal::SliceReader::new(&bytes)).unwrap_err();
        assert!(error.to_string().contains("limit"), "{error}");
    }
}

#[test]
fn constrained_stack_depth_boundary_in_subprocess() {
    const CHILD: &str = "CORIM_PR03_STACK_VALUE_CHILD";
    if std::env::var_os(CHILD).is_some() {
        std::thread::Builder::new()
            .stack_size(512 * 1024)
            .spawn(|| {
                // Hostile input is constructed directly, never by a recursive encoder.
                let bytes = nested_arrays(64);
                assert!(cbor::decode::<Value>(&bytes).is_ok());
                assert!(minimal::decode_value(&mut minimal::SliceReader::new(&bytes)).is_ok());
                assert_limit(cbor::decode::<Value>(&nested_arrays(65)), "depth", 64);
                assert_limit(cbor::decode::<Value>(&nested_arrays(40_000)), "depth", 64);
                assert!(
                    minimal::decode_value(&mut minimal::SliceReader::new(&nested_arrays(40_000)))
                        .is_err()
                );
            })
            .unwrap()
            .join()
            .unwrap();
        return;
    }
    let output = std::process::Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "constrained_stack_depth_boundary_in_subprocess",
            "--nocapture",
        ])
        .env(CHILD, "1")
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "512 KiB stack child failed: {}\n{}",
        output.status,
        String::from_utf8_lossy(&output.stderr)
    );
}
