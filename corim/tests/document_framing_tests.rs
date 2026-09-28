// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Document framing is exact; the legacy generic CBOR decoder remains prefix-based.

use corim::builder::{ComidBuilder, CotlBuilder};
use corim::cbor::{self, constants as c, value::Value, DecodeLimits};
use corim::types::common::TagIdChoice;
use corim::types::corim::{CorimMetaMap, CorimSignerMap};
use corim::types::coswid::{ConciseSwidTag, SwidEntity};
use corim::types::environment::EnvironmentMap;
use corim::types::measurement::{MeasurementMap, MeasurementValuesMap, SvnChoice};
use corim::types::signed::*;
use corim::types::tags::*;
use corim::types::triples::ReferenceTriple;
use corim::validate::{check_decode_limits, decode_and_validate_full_at};

const NOW: i64 = 1_777_000_000;
/// Break stop code (RFC 8949 §3.2.1), invalid as a standalone item.
const BREAK: u8 = (c::MAJOR_SIMPLE << 5) | c::AI_INDEFINITE;
/// SHA-256, COSE Algorithms registry (RFC 9054 §2).
const SHA_256: i64 = -16;

fn enc(value: &impl serde::Serialize) -> Vec<u8> {
    cbor::encode(value).unwrap()
}
fn key(label: i64) -> Value { Value::Integer(i128::from(label)) }
fn tagged(tag: u64, value: Value) -> Value { Value::Tag(tag, Box::new(value)) }
fn trailing(mut bytes: Vec<u8>, suffix: u8) -> Vec<u8> { bytes.push(suffix); bytes }
fn comid() -> Vec<u8> {
    enc(&ComidBuilder::new(TagIdChoice::Text("framing".into()))
        .add_reference_triple(ReferenceTriple::new(EnvironmentMap::for_class("V", "M"), vec![MeasurementMap {
            mkey: None, authorized_by: None,
            mval: MeasurementValuesMap { svn: Some(SvnChoice::ExactValue(1)), ..Default::default() },
        }])).build().unwrap())
}
fn unsigned(extra: Option<Value>) -> Vec<u8> {
    let mut tags = vec![tagged(TAG_COMID, Value::Bytes(comid()))];
    tags.extend(extra);
    enc(&tagged(TAG_CORIM, Value::Map(vec![
        (key(CORIM_KEY_ID), Value::Text("framing".into())),
        (key(CORIM_KEY_TAGS), Value::Array(tags)),
    ])))
}
fn header() -> Vec<u8> {
    enc(&ProtectedCorimHeaderMapBuilder::new(CoseAlgorithm::Es256)
        .content_type(CORIM_CONTENT_TYPE).cwt_claims(CwtClaims::new("Signer"))
        .corim_meta(CorimMetaMap {
            signer: CorimSignerMap { signer_name: "Signer".into(), signer_uri: None },
            signature_validity: None,
        }).build())
}
fn envelope(protected: Vec<u8>, payload: Option<Vec<u8>>) -> Vec<u8> {
    enc(&tagged(TAG_SIGNED_CORIM, Value::Array(vec![
        Value::Bytes(protected), Value::Map(vec![]),
        payload.map_or(Value::Null, Value::Bytes), Value::Bytes(vec![0xab; 64]),
    ])))
}

#[test]
fn clean_documents_and_legacy_prefix_decode_remain_valid() {
    assert_eq!(cbor::decode::<Value>(&[0, c::BYTE_NULL]).unwrap(), Value::Integer(0));
    let payload = unsigned(None);
    assert_eq!(decode_and_validate_full_at(&payload, NOW).unwrap().comids.len(), 1);
    let signed = decode_signed_corim(&envelope(header(), Some(payload))).unwrap();
    assert_eq!(validate_signed_corim_payload(&signed, NOW).unwrap().comids.len(), 1);
}

#[test]
fn unsigned_and_legacy_wrapped_documents_reject_trailing_items() {
    let clean = unsigned(None);
    let value: Value = cbor::decode(&clean).unwrap();
    let wrapped = enc(&tagged(TAG_LEGACY_TOP, value));
    assert!(decode_and_validate_full_at(&wrapped, NOW).is_ok());
    for bytes in [clean, wrapped] {
        for suffix in [BREAK, c::BYTE_NULL] {
            assert!(decode_and_validate_full_at(&trailing(bytes.clone(), suffix), NOW).is_err());
        }
    }
}

#[test]
fn every_embedded_tag_body_rejects_trailing_items() {
    let cotl = enc(&CotlBuilder::new(TagIdChoice::Text("list".into()), NOW + 100)
        .add_tag_id(TagIdChoice::Text("framing".into())).build().unwrap());
    let swid = enc(&ConciseSwidTag::new(TagIdChoice::Text("swid".into()), "software", 0,
        vec![SwidEntity::new("Signer", vec![SWID_ROLE_TAG_CREATOR])]));
    let mut accepted = Vec::new();
    for (name, tag, body) in [
        ("comid", Some(TAG_COMID), comid()), ("cotl", Some(TAG_COTL), cotl),
        ("coswid", Some(TAG_COSWID), swid), ("bare-bstr", None, comid()),
        ("opaque-coswid", Some(TAG_COSWID), enc(&Value::Null)),
    ] {
        // Keep the raw bstr form for the legacy CoMID compatibility path.
        let entry = |bytes: Vec<u8>| match tag {
            Some(tag) => tagged(tag, Value::Bytes(bytes)), None => Value::Bytes(bytes),
        };
        assert!(decode_and_validate_full_at(&unsigned(Some(entry(body.clone()))), NOW).is_ok(), "{name}");
        for suffix in [BREAK, c::BYTE_NULL] {
            let bytes = unsigned(Some(entry(trailing(body.clone(), suffix))));
            if decode_and_validate_full_at(&bytes, NOW).is_ok() { accepted.push((name, suffix)); }
            if decode_signed_corim(&envelope(header(), Some(bytes))).is_ok() { accepted.push(("signed nested body", suffix)); }
        }
    }
    assert!(accepted.is_empty(), "accepted trailing data: {accepted:?}");
}

#[test]
fn signed_outer_and_inline_payload_reject_trailing_items() {
    let clean = envelope(header(), Some(unsigned(None)));
    let value: Value = cbor::decode(&clean).unwrap();
    let wrapped = enc(&tagged(TAG_LEGACY_TOP, tagged(TAG_LEGACY_SIGNED, value)));
    assert!(decode_signed_corim(&wrapped).is_ok());
    let mut accepted = Vec::new();
    for suffix in [BREAK, c::BYTE_NULL] {
        for (name, bytes) in [
            ("outer", trailing(clean.clone(), suffix)),
            ("wrapped", trailing(wrapped.clone(), suffix)),
            ("payload", envelope(header(), Some(trailing(unsigned(None), suffix)))),
        ] {
            if decode_signed_corim(&bytes).is_ok() { accepted.push((name, suffix)); }
        }
    }
    assert!(accepted.is_empty(), "accepted trailing data: {accepted:?}");
}

#[test]
fn protected_header_and_meta_cannot_ignore_trailing_data_or_fall_back_to_cwt() {
    let mut accepted = Vec::new();
    for suffix in [BREAK, c::BYTE_NULL] {
        let Value::Map(mut fields) = cbor::decode::<Value>(&header()).unwrap() else { panic!("header map") };
        let (_, Value::Bytes(meta)) = fields.iter_mut().find(|(k, _)| *k == key(COSE_HEADER_CORIM_META)).unwrap() else { panic!("meta bstr") };
        meta.push(suffix); // Valid matching CWT claims are still present.
        for (name, protected) in [("header", trailing(header(), suffix)), ("meta", enc(&Value::Map(fields)))] {
            if ProtectedCorimHeaderMap::decode_with_limits(&protected, &DecodeLimits::default()).is_ok() { accepted.push(name); }
            if decode_signed_corim(&envelope(protected, None)).is_ok() { accepted.push(name); }
        }
    }
    assert!(accepted.is_empty(), "accepted trailing data: {accepted:?}");
}

#[test]
fn in_memory_and_supplied_detached_payloads_require_exact_framing() {
    let mut signed = decode_signed_corim(&envelope(header(), Some(unsigned(None)))).unwrap();
    let bad = trailing(unsigned(None), BREAK);
    signed.payload = Some(bad.clone());
    let attached_rejected = validate_signed_corim_payload(&signed, NOW).is_err();
    let detached = decode_signed_corim(&envelope(header(), None)).unwrap();
    assert!(validate_signed_corim_payload_detached(&detached, &unsigned(None), NOW).is_ok());
    let detached_rejected = validate_signed_corim_payload_detached(&detached, &bad, NOW).is_err();
    assert!(attached_rejected && detached_rejected,
        "trailing payload rejected: attached={attached_rejected}, detached={detached_rejected}");
}

#[test]
fn opaque_syntax_and_hash_digest_are_not_reinterpreted_as_documents() {
    let bytes = unsigned(Some(tagged(TAG_COSWID, Value::Bytes(vec![BREAK]))));
    assert_eq!(decode_and_validate_full_at(&bytes, NOW).unwrap().coswid_opaque_count, 1);
    let protected = ProtectedCorimHeaderMapBuilder::new(CoseAlgorithm::Es256)
        .cwt_claims(CwtClaims::new("Signer")).payload_hash_alg(SHA_256)
        .payload_preimage_content_type(CORIM_CONTENT_TYPE).build();
    let bytes = envelope(enc(&protected), Some(vec![0, BREAK]));
    let signed = decode_signed_corim(&bytes).unwrap();
    assert_eq!(signed.payload, Some(vec![0, BREAK]));
    check_decode_limits(&bytes, &DecodeLimits::default()).unwrap();
    assert!(decode_signed_corim(&envelope(header(), None)).unwrap().is_detached());
}

#[test]
fn protected_bytes_are_preserved_without_normalization() {
    let Value::Map(mut fields) = cbor::decode::<Value>(&header()).unwrap() else { panic!("header map") };
    fields.reverse();
    // RFC 8949 §3.1: a valid nonpreferred length and reversed map order.
    let mut protected = vec![(c::MAJOR_MAP << 5) | c::AI_ONE_BYTE, u8::try_from(fields.len()).unwrap()];
    for (k, v) in fields { protected.extend(enc(&k)); protected.extend(enc(&v)); }
    let signed = decode_signed_corim(&envelope(protected.clone(), Some(unsigned(None)))).unwrap();
    assert_ne!(enc(&signed.protected), protected);
    assert_eq!(signed.protected_header_bytes, protected);
    let Value::Array(tbs) = cbor::decode::<Value>(&signed.to_be_signed(&[]).unwrap()).unwrap() else { panic!("Sig_structure") };
    assert_eq!(tbs[1], Value::Bytes(protected));
}