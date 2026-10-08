// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Operation-local budgets across CoRIM CBOR-in-bstr boundaries (RFC 8949 §10).
//! These tests cover crate-owned types, not arbitrary user Deserialize code.

use corim::builder::{ComidBuilder, CorimBuilder};
use corim::cbor::{self, constants as c, value::Value, DecodeLimits};
use corim::types::common::TagIdChoice;
use corim::types::corim::{CorimId, CorimMetaMap, CorimSignerMap};
use corim::types::environment::{ClassMap, EnvironmentMap};
use corim::types::measurement::{MeasurementMap, MeasurementValuesMap, SvnChoice};
use corim::types::signed::*;
use corim::types::tags::*;
use corim::types::triples::ReferenceTriple;
use corim::validate::{
    check_decode_limits, decode_and_validate_full_at, decode_and_validate_full_at_with_limits,
};
use corim::{DecodeError, ValidationError};

const NOW: i64 = 1_777_000_000;
const NVIDIA: &[u8] = include_bytes!("fixtures/nvidia_cx7_tcg_wrapped.cbor");
/// Break stop code, RFC 8949 §3.2.1 (invalid as a standalone item).
const BYTE_BREAK: u8 = (c::MAJOR_SIMPLE << 5) | c::AI_INDEFINITE;
/// SHA-256, IANA COSE Algorithms registry / RFC 9054 §2.
const COSE_SHA_256: i64 = -16;
/// Test-only extension label, not a standardized header parameter.
const TEST_EXTENSION_LABEL: i64 = 10_001;

fn key(label: i64) -> Value {
    Value::Integer(i128::from(label))
}

fn nodes(value: &Value) -> usize {
    1 + match value {
        Value::Array(items) => items.iter().map(nodes).sum(),
        Value::Map(entries) => entries.iter().map(|(k, v)| nodes(k) + nodes(v)).sum(),
        Value::Tag(_, inner) => nodes(inner),
        _ => 0,
    }
}

fn decoded(bytes: &[u8]) -> Value {
    cbor::decode(bytes).unwrap()
}

fn field(value: &Value, label: i64) -> &Value {
    match value {
        Value::Tag(_, inner) => field(inner, label),
        Value::Map(entries) => &entries.iter().find(|(k, _)| *k == key(label)).unwrap().1,
        _ => panic!("expected a map"),
    }
}

fn set_field(value: &mut Value, label: i64, replacement: Value) {
    match value {
        Value::Tag(_, inner) => set_field(inner, label, replacement),
        Value::Map(entries) => {
            if let Some((_, v)) = entries.iter_mut().find(|(k, _)| *k == key(label)) {
                *v = replacement;
            } else {
                entries.push((key(label), replacement));
            }
        }
        _ => panic!("expected a map"),
    }
}

fn byte_string(value: &Value) -> &[u8] {
    match value {
        Value::Bytes(bytes) => bytes,
        Value::Tag(_, inner) => byte_string(inner),
        _ => panic!("expected a byte string"),
    }
}

fn unsigned_nodes(bytes: &[u8]) -> usize {
    let outer = decoded(bytes);
    let Value::Array(tags) = field(&outer, CORIM_KEY_TAGS) else {
        panic!("tags array")
    };
    nodes(&outer)
        + tags
            .iter()
            .map(|tag| nodes(&decoded(byte_string(tag))))
            .sum::<usize>()
}

fn header_nodes(bytes: &[u8]) -> usize {
    let header = decoded(bytes);
    nodes(&header)
        + nodes(&decoded(byte_string(field(
            &header,
            COSE_HEADER_CORIM_META,
        ))))
}

fn limits_with_values(max_values: usize) -> DecodeLimits {
    let mut limits = DecodeLimits::default();
    limits.max_values = max_values;
    limits
}

fn above_default_extension(byte_limit: bool) -> Value {
    if byte_limit {
        Value::Bytes(vec![0; cbor::DEFAULT_MAX_INPUT_BYTES + 1])
    } else {
        Value::Array(vec![Value::Null; cbor::DEFAULT_MAX_VALUES])
    }
}

fn exact_document_limits(bytes: &[u8], values: usize) -> DecodeLimits {
    let mut limits = DecodeLimits::default();
    limits.max_input_bytes = bytes.len();
    limits.max_values = values;
    limits
}

#[test]
fn raised_limits_survive_unsigned_map_deserialization() {
    for byte_limit in [true, false] {
        let original = unsigned(1);
        let mut outer = decoded(&original);
        let embedded_values = unsigned_nodes(&original) - nodes(&outer);
        set_field(
            &mut outer,
            TEST_EXTENSION_LABEL,
            above_default_extension(byte_limit),
        );
        let total = nodes(&outer) + embedded_values;
        let bytes = cbor::encode(&outer).unwrap();
        drop(outer);
        let mut limits = exact_document_limits(&bytes, total);
        let result = decode_and_validate_full_at_with_limits(&bytes, NOW, &limits).unwrap();
        assert_eq!(result.comids.len(), 1);
        limits.max_values -= 1;
        assert_validation_limit(
            decode_and_validate_full_at_with_limits(&bytes, NOW, &limits),
            "values",
            total - 1,
        );
    }
}

#[test]
fn raised_limits_survive_tcg_comid_deserialization() {
    for byte_limit in [true, false] {
        for tagged_inner in [false, true] {
            let mut outer = decoded(&unsigned(1));
            let Value::Array(tags) = field(&outer, CORIM_KEY_TAGS) else {
                panic!("tags")
            };
            let mut comid = decoded(byte_string(&tags[0]));
            set_field(
                &mut comid,
                TEST_EXTENSION_LABEL,
                above_default_extension(byte_limit),
            );
            let inner = if tagged_inner {
                Value::Tag(TAG_COMID, Box::new(comid))
            } else {
                comid
            };
            let inner_values = nodes(&inner);
            let inner_bytes = cbor::encode(&inner).unwrap();
            drop(inner);
            set_field(
                &mut outer,
                CORIM_KEY_TAGS,
                Value::Array(vec![Value::Bytes(inner_bytes)]),
            );
            let total = nodes(&outer) + inner_values;
            let bytes = cbor::encode(&outer).unwrap();
            drop(outer);
            let mut limits = exact_document_limits(&bytes, total);
            let result = decode_and_validate_full_at_with_limits(&bytes, NOW, &limits).unwrap();
            assert_eq!(result.comids.len(), 1);
            limits.max_values -= 1;
            assert_validation_limit(
                decode_and_validate_full_at_with_limits(&bytes, NOW, &limits),
                "values",
                total - 1,
            );
        }
    }
}

#[test]
fn raised_limits_survive_direct_cwt_claims_deserialization() {
    for byte_limit in [true, false] {
        let mut protected = decoded(&header());
        let metadata_values = header_nodes(&header()) - nodes(&protected);
        set_field(
            &mut protected,
            COSE_HEADER_CWT_CLAIMS,
            Value::Map(vec![
                (key(CWT_CLAIM_ISS), Value::Text("Budget signer".into())),
                (
                    key(TEST_EXTENSION_LABEL),
                    above_default_extension(byte_limit),
                ),
            ]),
        );
        let total = nodes(&protected) + metadata_values;
        let bytes = cbor::encode(&protected).unwrap();
        drop(protected);
        let mut limits = exact_document_limits(&bytes, total);
        let result = ProtectedCorimHeaderMap::decode_with_limits(&bytes, &limits).unwrap();
        assert_eq!(result.cwt_claims.unwrap().extra.len(), 1);
        limits.max_values -= 1;
        assert_limit(
            ProtectedCorimHeaderMap::decode_with_limits(&bytes, &limits),
            "values",
            total - 1,
        );
    }
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

fn assert_validation_limit<T: std::fmt::Debug>(
    result: Result<T, ValidationError>,
    resource: &str,
    limit: usize,
) {
    match result {
        Err(ValidationError::Decode(error)) => assert_limit::<()>(Err(error), resource, limit),
        other => panic!("expected a decode limit, got {other:?}"),
    }
}

fn unsigned(tag_count: usize) -> Vec<u8> {
    let comid = ComidBuilder::new(TagIdChoice::Text("budget-comid".into()))
        .add_reference_triple(ReferenceTriple::new(
            EnvironmentMap {
                class: Some(ClassMap {
                    class_id: None,
                    vendor: Some("TestVendor".into()),
                    model: None,
                    layer: None,
                    index: None,
                }),
                instance: None,
                group: None,
            },
            vec![MeasurementMap {
                mkey: None,
                mval: MeasurementValuesMap {
                    svn: Some(SvnChoice::ExactValue(1)),
                    ..Default::default()
                },
                authorized_by: None,
            }],
        ))
        .build()
        .unwrap();
    let mut builder = CorimBuilder::new(CorimId::Text("budget-corim".into()));
    for _ in 0..tag_count {
        builder = builder.add_comid_tag(comid.clone()).unwrap();
    }
    builder.build_bytes().unwrap()
}

fn header() -> Vec<u8> {
    cbor::encode(
        &ProtectedCorimHeaderMapBuilder::new(CoseAlgorithm::Es256)
            .content_type(CORIM_CONTENT_TYPE)
            .corim_meta(CorimMetaMap {
                signer: CorimSignerMap {
                    signer_name: "Budget signer".into(),
                    signer_uri: None,
                },
                signature_validity: None,
            })
            .build(),
    )
    .unwrap()
}

#[test]
fn header_entry_point_shares_limits_with_corim_meta() {
    let bytes = header();
    let total = header_nodes(&bytes);
    assert!(
        ProtectedCorimHeaderMap::decode_with_limits(&bytes, &limits_with_values(total)).is_ok()
    );
    assert_limit(
        ProtectedCorimHeaderMap::decode_with_limits(&bytes, &limits_with_values(total - 1)),
        "values",
        total - 1,
    );
    let mut limits = DecodeLimits::default();
    limits.max_depth = 1;
    assert_limit(
        ProtectedCorimHeaderMap::decode_with_limits(&bytes, &limits),
        "depth",
        1,
    );
}

#[test]
fn signed_envelope_input_limit_uses_shared_resource_error() {
    let bytes = envelope(&header(), None);
    let mut limits = DecodeLimits::default();
    limits.max_input_bytes = bytes.len();
    assert!(decode_signed_corim_with_limits(&bytes, &limits).is_ok());
    limits.max_input_bytes -= 1;
    assert_limit(
        decode_signed_corim_with_limits(&bytes, &limits),
        "input bytes",
        limits.max_input_bytes,
    );
    limits.max_input_bytes = 0;
    assert_limit(
        decode_signed_corim_with_limits(&bytes, &limits),
        "input bytes",
        0,
    );
}

#[test]
fn signed_envelope_default_input_limit_uses_shared_resource_error() {
    let limit = DecodeLimits::default().max_input_bytes;
    let bytes = vec![c::BYTE_NULL; limit + 1];
    assert_limit(decode_signed_corim(&bytes), "input bytes", limit);
}

fn envelope(protected: &[u8], payload: Option<&[u8]>) -> Vec<u8> {
    cbor::encode(&Value::Tag(
        TAG_SIGNED_CORIM,
        Box::new(Value::Array(vec![
            Value::Bytes(protected.to_vec()),
            Value::Map(vec![]),
            payload.map_or(Value::Null, |bytes| Value::Bytes(bytes.to_vec())),
            Value::Bytes(vec![0xAB; 64]),
        ])),
    ))
    .unwrap()
}

fn nested_arrays(depth: usize) -> Vec<u8> {
    let mut bytes = vec![(c::MAJOR_ARRAY << 5) | 1; depth];
    bytes.push(c::BYTE_NULL);
    bytes
}

fn legacy_wrapped(bytes: &[u8], tag: u64, count: usize) -> Vec<u8> {
    // Encode just one shallow tag header, then prepend copies iteratively.
    let mut prefix = cbor::encode(&Value::Tag(tag, Box::new(Value::Null))).unwrap();
    assert_eq!(prefix.pop(), Some(c::BYTE_NULL));
    let mut wrapped = prefix.repeat(count);
    wrapped.extend_from_slice(bytes);
    wrapped
}

fn with_coswid(payload: &[u8], coswid: Vec<u8>) -> Vec<u8> {
    let mut outer = decoded(payload);
    let mut tags = match field(&outer, CORIM_KEY_TAGS) {
        Value::Array(tags) => tags.clone(),
        _ => panic!("tags array"),
    };
    tags.push(Value::Tag(TAG_COSWID, Box::new(Value::Bytes(coswid))));
    set_field(&mut outer, CORIM_KEY_TAGS, Value::Array(tags));
    cbor::encode(&outer).unwrap()
}

#[test]
fn unsigned_outer_and_multiple_tags_share_exact_value_budget() {
    let bytes = unsigned(3);
    let required = unsigned_nodes(&bytes);
    let limits = limits_with_values(required);
    assert_eq!(
        decode_and_validate_full_at_with_limits(&bytes, NOW, &limits)
            .unwrap()
            .comids
            .len(),
        3
    );
    check_decode_limits(&bytes, &limits).unwrap();
    let limits = limits_with_values(required - 1);
    assert_validation_limit(
        decode_and_validate_full_at_with_limits(&bytes, NOW, &limits),
        "values",
        required - 1,
    );
    assert_limit(check_decode_limits(&bytes, &limits), "values", required - 1);
    // Each inner CBOR item fits on its own: the failure must be aggregate.
    let value = decoded(&bytes);
    let Value::Array(tags) = field(&value, CORIM_KEY_TAGS) else {
        panic!("tags")
    };
    for tag in tags {
        assert!(cbor::decode_with_limits::<Value>(byte_string(tag), &limits).is_ok());
    }
    assert_eq!(
        decode_and_validate_full_at(&bytes, NOW)
            .unwrap()
            .comids
            .len(),
        3
    );
}

#[test]
fn signed_outer_header_meta_payload_and_tags_share_exact_value_budget() {
    let payload = unsigned(2);
    let protected = header();
    let bytes = envelope(&protected, Some(&payload));
    let required = nodes(&decoded(&bytes)) + header_nodes(&protected) + unsigned_nodes(&payload);
    let limits = limits_with_values(required);
    assert_eq!(
        decode_signed_corim_with_limits(&bytes, &limits)
            .unwrap()
            .protected_header_bytes,
        protected
    );
    check_decode_limits(&bytes, &limits).unwrap();
    let limits = limits_with_values(required - 1);
    assert_limit(
        decode_signed_corim_with_limits(&bytes, &limits),
        "values",
        required - 1,
    );
    assert_limit(check_decode_limits(&bytes, &limits), "values", required - 1);
}

#[test]
fn attached_validation_shares_header_meta_and_payload_budget() {
    let payload = unsigned(2);
    let protected = header();
    let signed = decode_signed_corim(&envelope(&protected, Some(&payload))).unwrap();
    // The in-memory envelope is not decoded again; only header and payload count.
    let required = header_nodes(&protected) + unsigned_nodes(&payload);
    assert_eq!(
        validate_signed_corim_payload_with_limits(&signed, NOW, &limits_with_values(required))
            .unwrap()
            .comids
            .len(),
        2
    );
    assert_validation_limit(
        validate_signed_corim_payload_with_limits(&signed, NOW, &limits_with_values(required - 1)),
        "values",
        required - 1,
    );
    assert_eq!(
        validate_signed_corim_payload(&signed, NOW)
            .unwrap()
            .comids
            .len(),
        2
    );
}

#[test]
fn detached_validation_shares_header_meta_and_supplied_payload_budget() {
    let payload = unsigned(2);
    let protected = header();
    let bytes = envelope(&protected, None);
    let outer_required = nodes(&decoded(&bytes)) + header_nodes(&protected);
    let signed =
        decode_signed_corim_with_limits(&bytes, &limits_with_values(outer_required)).unwrap();
    assert!(signed.is_detached());
    assert_limit(
        decode_signed_corim_with_limits(&bytes, &limits_with_values(outer_required - 1)),
        "values",
        outer_required - 1,
    );
    assert!(
        validate_signed_corim_payload_with_limits(&signed, NOW, &DecodeLimits::default()).is_err()
    );
    let required = header_nodes(&protected) + unsigned_nodes(&payload);
    assert_eq!(
        validate_signed_corim_payload_detached_with_limits(
            &signed,
            &payload,
            NOW,
            &limits_with_values(required)
        )
        .unwrap()
        .comids
        .len(),
        2
    );
    assert_validation_limit(
        validate_signed_corim_payload_detached_with_limits(
            &signed,
            &payload,
            NOW,
            &limits_with_values(required - 1),
        ),
        "values",
        required - 1,
    );
    assert_eq!(
        validate_signed_corim_payload_detached(&signed, &payload, NOW)
            .unwrap()
            .comids
            .len(),
        2
    );
}

#[test]
fn supplied_detached_payload_overrides_attached_payload_for_budgeting() {
    let protected = header();
    let signed = decode_signed_corim(&envelope(&protected, Some(&unsigned(1)))).unwrap();
    let supplied = unsigned(3);
    let required = header_nodes(&protected) + unsigned_nodes(&supplied);
    assert_eq!(
        validate_signed_corim_payload_detached_with_limits(
            &signed,
            &supplied,
            NOW,
            &limits_with_values(required)
        )
        .unwrap()
        .comids
        .len(),
        3
    );
    assert_validation_limit(
        validate_signed_corim_payload_detached_with_limits(
            &signed,
            &supplied,
            NOW,
            &limits_with_values(required - 1),
        ),
        "values",
        required - 1,
    );
}

#[test]
fn hash_payload_is_opaque_even_when_it_looks_like_hostile_cbor() {
    let mut protected = decoded(&header());
    set_field(
        &mut protected,
        COSE_HEADER_PAYLOAD_HASH_ALG,
        key(COSE_SHA_256),
    );
    set_field(
        &mut protected,
        COSE_HEADER_PAYLOAD_PREIMAGE_CT,
        Value::Text(CORIM_CONTENT_TYPE.into()),
    );
    let protected = cbor::encode(&protected).unwrap();
    let hash = nested_arrays(40_000);
    let bytes = envelope(&protected, Some(&hash));
    let required = nodes(&decoded(&bytes)) + header_nodes(&protected);
    let limits = limits_with_values(required);
    let signed = decode_signed_corim_with_limits(&bytes, &limits).unwrap();
    assert!(signed.protected.is_hash_envelope());
    assert_eq!(signed.payload.as_deref(), Some(hash.as_slice()));
    check_decode_limits(&bytes, &limits).unwrap();
    assert_limit(
        decode_signed_corim_with_limits(&bytes, &limits_with_values(required - 1)),
        "values",
        required - 1,
    );
}

#[test]
fn hash_payload_validation_requires_preimage_instead_of_decoding_digest() {
    let mut protected = decoded(&header());
    set_field(
        &mut protected,
        COSE_HEADER_PAYLOAD_HASH_ALG,
        key(COSE_SHA_256),
    );
    set_field(
        &mut protected,
        COSE_HEADER_PAYLOAD_PREIMAGE_CT,
        Value::Text(CORIM_CONTENT_TYPE.into()),
    );
    let protected = cbor::encode(&protected).unwrap();
    for digest in [vec![0xAB; 32], unsigned(1), nested_arrays(65)] {
        let signed = decode_signed_corim(&envelope(&protected, Some(&digest))).unwrap();
        for result in [
            validate_signed_corim_payload(&signed, NOW),
            validate_signed_corim_payload_with_limits(&signed, NOW, &DecodeLimits::default()),
            validate_signed_corim_payload_detached(&signed, &digest, NOW),
            validate_signed_corim_payload_detached_with_limits(
                &signed,
                &digest,
                NOW,
                &DecodeLimits::default(),
            ),
        ] {
            assert!(
                matches!(result, Err(ValidationError::Invalid(ref message))
                if message.contains("hash-envelope") && message.contains("preimage")),
                "must not decode a digest as inline CBOR: {result:?}"
            );
        }
    }
}

#[test]
fn unsigned_explicit_input_limit_uses_shared_resource_error() {
    let bytes = unsigned(1);
    let mut limits = DecodeLimits::default();
    limits.max_input_bytes = bytes.len();
    assert!(decode_and_validate_full_at_with_limits(&bytes, NOW, &limits).is_ok());
    for max in [bytes.len() - 1, 0] {
        limits.max_input_bytes = max;
        assert_validation_limit(
            decode_and_validate_full_at_with_limits(&bytes, NOW, &limits),
            "input bytes",
            max,
        );
    }
}

#[test]
fn legacy_unsigned_input_size_error_is_preserved() {
    let max = corim::validate::MAX_PAYLOAD_SIZE;
    let bytes = vec![c::BYTE_NULL; max + 1];
    for result in [
        decode_and_validate_full_at(&bytes, NOW).map(|_| ()),
        corim::validate::decode_and_validate_at(&bytes, NOW).map(|_| ()),
        corim::validate::decode_and_validate_full_at_with_registry(
            &bytes,
            NOW,
            &corim::profile::ProfileRegistry::new(),
        )
        .map(|_| ()),
    ] {
        assert!(
            matches!(result, Err(ValidationError::PayloadTooLarge { size, max: found })
            if size == bytes.len() && found == max)
        );
    }
    assert_validation_limit(
        decode_and_validate_full_at_with_limits(&bytes, NOW, &DecodeLimits::default()),
        "input bytes",
        max,
    );
}

#[test]
fn signed_payload_explicit_input_limit_uses_shared_resource_error() {
    let protected = header();
    let bytes = unsigned(8);
    assert!(bytes.len() > protected.len());
    let signed = decode_signed_corim(&envelope(&protected, Some(&bytes))).unwrap();
    let mut limits = DecodeLimits::default();
    limits.max_input_bytes = bytes.len() - 1;
    assert_validation_limit(
        validate_signed_corim_payload_with_limits(&signed, NOW, &limits),
        "input bytes",
        limits.max_input_bytes,
    );
    assert_validation_limit(
        validate_signed_corim_payload_detached_with_limits(&signed, &bytes, NOW, &limits),
        "input bytes",
        limits.max_input_bytes,
    );
}

#[test]
fn corim_meta_depth_limit_is_not_swallowed_by_header_compatibility() {
    let mut protected = decoded(&header());
    set_field(
        &mut protected,
        COSE_HEADER_CORIM_META,
        Value::Bytes(nested_arrays(65)),
    );
    let bytes = envelope(&cbor::encode(&protected).unwrap(), None);
    assert_limit(decode_signed_corim(&bytes), "depth", 64);
    assert_limit(
        check_decode_limits(&bytes, &DecodeLimits::default()),
        "depth",
        64,
    );
}

#[test]
fn corim_meta_values_share_the_outer_budget_even_on_malformed_metadata() {
    let mut protected = decoded(&header());
    let meta = Value::Array(vec![Value::Null; 16]);
    set_field(
        &mut protected,
        COSE_HEADER_CORIM_META,
        Value::Bytes(cbor::encode(&meta).unwrap()),
    );
    let protected = cbor::encode(&protected).unwrap();
    let bytes = envelope(&protected, None);
    let limit = nodes(&decoded(&bytes)) + nodes(&decoded(&protected)) + nodes(&meta) - 1;
    assert_limit(
        decode_signed_corim_with_limits(&bytes, &limits_with_values(limit)),
        "values",
        limit,
    );
}

#[test]
fn opaque_coswid_fallback_preserves_syntax_tolerance_but_not_limit_failures() {
    let bytes = with_coswid(&unsigned(1), cbor::encode(&Value::Null).unwrap());
    let required = unsigned_nodes(&bytes);
    let validated =
        decode_and_validate_full_at_with_limits(&bytes, NOW, &limits_with_values(required))
            .unwrap();
    assert_eq!(validated.coswid_opaque_count, 1);
    assert_validation_limit(
        decode_and_validate_full_at_with_limits(&bytes, NOW, &limits_with_values(required - 1)),
        "values",
        required - 1,
    );
    let hostile = with_coswid(&unsigned(1), nested_arrays(65));
    assert_validation_limit(decode_and_validate_full_at(&hostile, NOW), "depth", 64);
    assert_limit(
        decode_signed_corim(&envelope(&header(), Some(&hostile))),
        "depth",
        64,
    );
}

#[test]
fn resource_only_check_ignores_syntax_but_reports_resource_failures() {
    let defaults = DecodeLimits::default();
    for malformed in [vec![], vec![BYTE_BREAK], vec![(c::MAJOR_ARRAY << 5) | 1]] {
        assert!(cbor::decode::<Value>(&malformed).is_err());
        check_decode_limits(&malformed, &defaults).unwrap();
    }
    assert_limit(
        check_decode_limits(&nested_arrays(65), &defaults),
        "depth",
        64,
    );
    let mut limits = defaults;
    limits.max_input_bytes = 0;
    assert_limit(
        check_decode_limits(&[BYTE_BREAK], &limits),
        "input bytes",
        0,
    );
    limits = defaults;
    limits.max_collection_items = 0;
    assert_limit(
        check_decode_limits(&[(c::MAJOR_ARRAY << 5) | 1], &limits),
        "collection entries",
        0,
    );
}

#[test]
fn resource_only_check_inspects_malformed_embedded_documents() {
    let payload = with_coswid(&unsigned(1), vec![BYTE_BREAK]);
    check_decode_limits(&payload, &DecodeLimits::default()).unwrap();
    let signed = envelope(&header(), Some(&[BYTE_BREAK]));
    check_decode_limits(&signed, &DecodeLimits::default()).unwrap();
    let mut limits = DecodeLimits::default();
    limits.max_values = nodes(&decoded(&signed)) + header_nodes(&header());
    assert_limit(
        check_decode_limits(&signed, &limits),
        "values",
        limits.max_values,
    );
}

#[test]
fn original_nonpreferred_protected_bytes_are_preserved_for_signatures() {
    let canonical = header();
    assert_eq!(canonical[0] >> 5, c::MAJOR_MAP);
    let entries = canonical[0] & 0x1f;
    assert!(entries < c::AI_ONE_BYTE);
    // RFC 8949 §3 permits a nonpreferred one-byte count for a small map.
    let mut original = vec![(c::MAJOR_MAP << 5) | c::AI_ONE_BYTE, entries];
    original.extend_from_slice(&canonical[1..]);
    let payload = unsigned(1);
    let bytes = envelope(&original, Some(&payload));
    let signed = decode_signed_corim_with_limits(&bytes, &DecodeLimits::default()).unwrap();
    assert_eq!(signed.protected_header_bytes, original);
    assert_ne!(cbor::encode(&signed.protected).unwrap(), original);
    let tbs = decoded(&signed.to_be_signed(&[]).unwrap());
    let Value::Array(parts) = tbs else {
        panic!("Sig_structure1 array")
    };
    assert_eq!(parts[1], Value::Bytes(original.clone()));
    validate_signed_corim_payload_with_limits(&signed, NOW, &DecodeLimits::default()).unwrap();
    assert_eq!(signed.protected_header_bytes, original);
}

#[test]
fn tcg_wrappers_consume_depth_instead_of_being_peeled_before_budgeting() {
    let bytes = unsigned(1);
    // Canonical outer depth is four: tag, map, tags array, embedded tag.
    let at_limit = legacy_wrapped(&bytes, TAG_LEGACY_TOP, 60);
    assert_eq!(
        decode_and_validate_full_at(&at_limit, NOW)
            .unwrap()
            .comids
            .len(),
        1
    );
    let required = unsigned_nodes(&at_limit);
    assert_eq!(
        decode_and_validate_full_at_with_limits(&at_limit, NOW, &limits_with_values(required))
            .unwrap()
            .comids
            .len(),
        1
    );
    assert_validation_limit(
        decode_and_validate_full_at_with_limits(&at_limit, NOW, &limits_with_values(required - 1)),
        "values",
        required - 1,
    );
    let over_limit = legacy_wrapped(&at_limit, TAG_LEGACY_TOP, 1);
    assert_validation_limit(decode_and_validate_full_at(&over_limit, NOW), "depth", 64);
    let signed = envelope(&header(), None);
    // Signed outer depth is three: tag, array, unprotected map.
    let wrapped = legacy_wrapped(&signed, TAG_LEGACY_SIGNED, 61);
    assert!(decode_signed_corim(&wrapped).is_ok());
    assert_limit(
        decode_signed_corim(&legacy_wrapped(&wrapped, TAG_LEGACY_TOP, 1)),
        "depth",
        64,
    );
}

#[test]
fn invalid_limits_are_rejected_by_document_entry_points() {
    let bytes = unsigned(1);
    let protected = header();
    let envelope_bytes = envelope(&protected, Some(&bytes));
    let signed = decode_signed_corim(&envelope_bytes).unwrap();
    for invalid_depth in [true, false] {
        let mut limits = DecodeLimits::default();
        if invalid_depth {
            limits.max_depth = 65;
        } else {
            limits.max_collection_items = 2_000_001;
        }
        assert!(matches!(
            check_decode_limits(&bytes, &limits),
            Err(DecodeError::InvalidStructure(_))
        ));
        assert!(matches!(
            decode_signed_corim_with_limits(&envelope_bytes, &limits),
            Err(DecodeError::InvalidStructure(_))
        ));
        assert!(matches!(
            decode_and_validate_full_at_with_limits(&bytes, NOW, &limits),
            Err(ValidationError::Decode(DecodeError::InvalidStructure(_)))
        ));
        assert!(matches!(
            validate_signed_corim_payload_with_limits(&signed, NOW, &limits),
            Err(ValidationError::Decode(DecodeError::InvalidStructure(_)))
        ));
        assert!(matches!(
            validate_signed_corim_payload_detached_with_limits(&signed, &bytes, NOW, &limits),
            Err(ValidationError::Decode(DecodeError::InvalidStructure(_)))
        ));
    }
}

#[test]
fn typed_header_and_real_fixture_fit_a_512_kib_stack_in_subprocess() {
    const CHILD: &str = "CORIM_PR03_STACK_DOCUMENT_CHILD";
    if std::env::var_os(CHILD).is_some() {
        std::thread::Builder::new()
            .stack_size(512 * 1024)
            .spawn(|| {
                // Known crate-owned typed paths, including real nested CBOR-in-bstr.
                let signed = decode_signed_corim(NVIDIA).unwrap();
                let validated = validate_signed_corim_payload(&signed, NOW).unwrap();
                assert_eq!(validated.comids.len(), 1);
                assert_eq!(
                    signed
                        .protected
                        .corim_meta
                        .as_ref()
                        .unwrap()
                        .signer
                        .signer_name,
                    "NVIDIA"
                );
                // Header root map plus 63 array containers exercises depth 64
                // through ProtectedCorimHeaderMap and its preserved extension Value.
                let mut protected = header();
                assert_eq!(protected[0] >> 5, c::MAJOR_MAP);
                assert!((protected[0] & 0x1f) < c::AI_MAX_INLINE);
                protected[0] += 1; // One more entry in the short map header.
                protected.extend_from_slice(&cbor::encode(&key(TEST_EXTENSION_LABEL)).unwrap());
                protected.extend_from_slice(&nested_arrays(63));
                let bytes = envelope(&protected, None);
                assert!(decode_signed_corim(&bytes).is_ok());
                assert_limit(decode_signed_corim(&nested_arrays(40_000)), "depth", 64);
                assert_validation_limit(
                    decode_and_validate_full_at(&nested_arrays(40_000), NOW),
                    "depth",
                    64,
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
            "typed_header_and_real_fixture_fit_a_512_kib_stack_in_subprocess",
            "--nocapture",
        ])
        .env(CHILD, "1")
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "512 KiB typed child failed: {}\n{}",
        output.status,
        String::from_utf8_lossy(&output.stderr)
    );
}
