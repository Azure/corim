// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Schema-level duplicate rejection; generic CBOR Value remains lossless.

use corim::builder::{ComidBuilder, CorimBuilder};
use corim::cbor::{self, constants as c, value::Value};
use corim::types::common::TagIdChoice;
use corim::types::corim::{ConciseTagChoice, CorimId, CorimMap};
use corim::types::coswid::{ConciseSwidTag, SwidEntity};
use corim::types::environment::EnvironmentMap;
use corim::types::measurement::{
    Digest, IntegrityRegisterId, IntegrityRegisters, MeasurementMap, MeasurementValuesMap,
    SvnChoice,
};
use corim::types::signed::ProtectedCorimHeaderMap as Header;
use corim::types::signed::*;
use corim::types::tags::*;
use corim::validate::decode_and_validate_full_at;
use serde::{de::DeserializeOwned, Serialize};

const EXTENSION: i64 = 10001; // Test-only, unregistered extension label.
const COSE_CRIT: i64 = 2; // RFC 9052 §3.1; no public constant.
const COSE_IV: i64 = 5; // RFC 9052 §3.1; no public constant.
type Entries = Vec<(Value, Value)>;
fn int(n: i64) -> Value {
    Value::Integer(n.into())
}
fn text(s: &str) -> Value {
    Value::Text(s.into())
}
fn value(v: &impl Serialize) -> Value {
    cbor::decode(&cbor::encode(v).unwrap()).unwrap()
}
fn entries(v: &impl Serialize) -> Entries {
    let Value::Map(m) = value(v) else {
        panic!("expected map")
    };
    m
}
fn decode<T: DeserializeOwned>(v: &Value) -> Result<T, corim::DecodeError> {
    cbor::decode(&cbor::encode(v).unwrap())
}
// Evaluate every row before asserting, so the pre-fix report lists all gaps.
fn reject<T: DeserializeOwned>(cases: Vec<Value>) {
    let accepted: Vec<_> = cases
        .into_iter()
        .filter(|v| decode::<T>(v).is_ok())
        .collect();
    assert!(accepted.is_empty(), "accepted duplicate maps: {accepted:?}");
}
fn duplicate_cases<T: DeserializeOwned>(base: Entries, fields: Entries) -> Vec<Value> {
    let mut cases = Vec::new();
    for entry in fields {
        let mut m = base.clone();
        m.retain(|(k, _)| *k != entry.0);
        m.push(entry.clone());
        assert!(decode::<T>(&Value::Map(m.clone())).is_ok());
        m.push(entry);
        cases.push(Value::Map(m));
    }
    cases
}
fn header() -> ProtectedCorimHeaderMap {
    ProtectedCorimHeaderMapBuilder::new(CoseAlgorithm::Es256)
        .content_type(CORIM_CONTENT_TYPE)
        .cwt_claims(CwtClaims::new("issuer"))
        .build()
}
fn flat_header() -> Entries {
    let mut m = entries(&header());
    m.retain(|(k, _)| *k != int(COSE_HEADER_CWT_CLAIMS));
    m.push((int(CWT_CLAIM_ISS), text("issuer")));
    m
}
fn disjoint_header() -> Entries {
    let mut m = flat_header();
    m.extend([
        (int(CWT_CLAIM_SUB), text("subject")),
        (int(COSE_CRIT), Value::Array(vec![int(COSE_HEADER_ALG)])),
        (int(CWT_CLAIM_EXP), int(123)),
        (int(COSE_HEADER_KID), Value::Bytes(vec![4])),
        (int(CWT_CLAIM_NBF), Value::Float(12.0)),
        (int(COSE_IV), Value::Bytes(vec![5])),
    ]);
    m
}
fn signed(protected: &[u8]) -> Vec<u8> {
    let envelope = Value::Array(vec![
        Value::Bytes(protected.to_vec()),
        Value::Map(vec![]),
        Value::Null,
        Value::Bytes(vec![0; 64]),
    ]);
    cbor::encode(&Value::Tag(TAG_SIGNED_CORIM, Box::new(envelope))).unwrap()
}
// Same typed fixture recipe used by signed_corim_tests, with an SVN measurement.
fn sample_corim() -> CorimMap {
    let env = EnvironmentMap::for_class("V", "M");
    let mval = MeasurementValuesMap {
        svn: Some(SvnChoice::ExactValue(1)),
        ..Default::default()
    };
    let meas = MeasurementMap {
        mkey: None,
        mval,
        authorized_by: None,
    };
    let comid = ComidBuilder::new(TagIdChoice::Text("comid".into()))
        .add_reference_triple_for(env, vec![meas])
        .build()
        .unwrap();
    CorimBuilder::new(CorimId::Text("corim".into()))
        .add_comid_tag(comid)
        .unwrap()
        .build()
        .unwrap()
}

#[test]
fn generic_value_preserves_repeated_keys_for_inspection() {
    let v = Value::Map(vec![
        (int(EXTENSION), text("first")),
        (int(EXTENSION), text("second")),
    ]);
    assert_eq!(decode::<Value>(&v).unwrap(), v);
}

#[test]
fn corim_rejects_duplicate_required_and_optional_null_fields() {
    let base = entries(&sample_corim());
    let mut fields = base.clone();
    for key in [
        CORIM_KEY_DEPENDENT_RIMS,
        CORIM_KEY_PROFILE,
        CORIM_KEY_RIM_VALIDITY,
        CORIM_KEY_ENTITIES,
    ] {
        fields.push((int(key), Value::Null));
    }
    let mut cases = duplicate_cases::<CorimMap>(base.clone(), fields);
    let mut changed = base;
    changed.push((int(CORIM_KEY_ID), text("different")));
    cases.push(Value::Map(changed));
    reject::<CorimMap>(cases);
}

#[test]
fn extension_and_modeled_duplicates_reject_even_identical_values() {
    let fields = vec![
        (int(EXTENSION), int(1)),
        (int(MVAL_KEY_SVN), value(&SvnChoice::ExactValue(1))),
    ];
    reject::<MeasurementValuesMap>(duplicate_cases::<MeasurementValuesMap>(vec![], fields));
}

#[test]
fn skipped_environment_extension_duplicates_reject() {
    let fields = vec![(int(EXTENSION), int(1))];
    reject::<EnvironmentMap>(duplicate_cases::<EnvironmentMap>(vec![], fields));
}

#[test]
fn serializers_reject_extras_colliding_with_populated_modeled_fields() {
    let mut mval = MeasurementValuesMap {
        svn: Some(SvnChoice::ExactValue(1)),
        ..Default::default()
    };
    mval.extra_entries
        .insert(MVAL_KEY_SVN, value(&SvnChoice::ExactValue(1)));
    let mut claims = CwtClaims::new("issuer");
    claims
        .extra
        .insert(ClaimKey::Int(CWT_CLAIM_ISS), text("issuer"));
    let mut h = header();
    h.extra.insert(COSE_HEADER_ALG, int(h.alg.to_i64()));
    let errors = [
        cbor::encode(&mval).is_err(),
        cbor::encode(&claims).is_err(),
        cbor::encode(&h).is_err(),
    ];
    assert_eq!(errors, [true; 3], "SVN / iss / alg collisions");
}

#[test]
fn header_rejects_duplicates_including_skipped_text_labels() {
    let mut fields = entries(&header());
    fields.extend([
        (int(COSE_HEADER_X5CHAIN), Value::Bytes(vec![1])),
        (int(EXTENSION), int(1)),
        (text("unmodeled"), int(1)),
    ]);
    reject::<Header>(duplicate_cases::<Header>(entries(&header()), fields));
}

#[test]
fn flat_claims_reject_same_role_and_non_exception_duplicates() {
    let mut cases = Vec::new();
    for (key, a, b) in [
        (CWT_CLAIM_ISS, text("issuer"), text("different")),
        (CWT_CLAIM_SUB, text("subject"), text("different")),
        (CWT_CLAIM_EXP, int(123), Value::Float(123.0)),
        (CWT_CLAIM_NBF, int(123), Value::Float(123.0)),
        (COSE_CRIT, text("subject"), int(1)),
        (COSE_HEADER_KID, int(123), text("not-kid")),
        (COSE_IV, int(12), text("not-iv")),
    ] {
        for (first, second) in [(a.clone(), a.clone()), (a.clone(), b.clone()), (b, a)] {
            let mut m = flat_header();
            m.retain(|(k, v)| !(*k == int(key) && matches!(v, Value::Text(_))));
            m.push((int(key), first));
            assert!(decode::<Header>(&Value::Map(m.clone())).is_ok());
            m.push((int(key), second));
            cases.push(Value::Map(m));
        }
    }
    reject::<Header>(cases);
}

#[test]
fn type_disjoint_flat_claims_accept_both_orders_preserving_protected_bytes() {
    let mut encodings = Vec::new();
    for reverse in [false, true] {
        let mut m = disjoint_header();
        if reverse {
            m.reverse();
        }
        let bytes = cbor::encode(&Value::Map(m)).unwrap();
        encodings.push(bytes.clone());
        let parsed = decode_signed_corim(&signed(&bytes)).unwrap();
        assert_eq!(parsed.protected_header_bytes, bytes);
        let mut expected = header();
        expected.kid = Some(vec![4]);
        expected.cwt_claims = Some(
            CwtClaims::new("issuer")
                .with_sub("subject")
                .with_exp(123)
                .with_nbf(12),
        );
        expected
            .extra
            .insert(COSE_CRIT, Value::Array(vec![int(COSE_HEADER_ALG)]));
        expected.extra.insert(COSE_IV, Value::Bytes(vec![5]));
        assert_eq!(parsed.protected, expected);
        let tbs = parsed.to_be_signed_detached(b"payload", &[]).unwrap();
        let tbs = cbor::decode::<Value>(&tbs).unwrap().into_array().unwrap();
        assert_eq!(tbs[1], Value::Bytes(bytes));
    }
    assert_ne!(encodings[0], encodings[1], "distinct wire orders");
}

#[test]
fn third_occurrence_after_type_disjoint_pair_rejects() {
    let base = disjoint_header();
    assert!(decode::<Header>(&Value::Map(base.clone())).is_ok());
    let mut cases = Vec::new();
    let repeated = base.iter().filter(|e| e.0 != int(COSE_HEADER_CONTENT_TYPE));
    for entry in repeated {
        let mut m = base.clone();
        m.push(entry.clone());
        cases.push(Value::Map(m));
    }
    reject::<Header>(cases);
}

#[test]
fn unique_unknown_fields_remain_forward_compatible() {
    let raw = Value::Map(vec![(int(EXTENSION), text("kept"))]);
    let mval: MeasurementValuesMap = decode(&raw).unwrap();
    assert_eq!(value(&mval), raw);
    assert!(decode::<EnvironmentMap>(&raw).is_ok()); // Skipped, not retained.
    let mut claims = CwtClaims::new("issuer");
    claims.extra.insert(ClaimKey::Int(EXTENSION), text("int"));
    claims
        .extra
        .insert(ClaimKey::Text("custom".into()), text("text"));
    assert_eq!(decode::<CwtClaims>(&value(&claims)).unwrap(), claims);
    let mut h = header();
    h.extra.insert(EXTENSION, raw);
    assert_eq!(decode::<Header>(&value(&h)).unwrap(), h);
}

#[test]
fn integrity_register_duplicate_uint_and_text_ids_reject() {
    let digests = value(&vec![Digest::new(7, vec![0xAA; 48])]);
    reject::<IntegrityRegisters>(
        [int(1), text("1")]
            .into_iter()
            .map(|key| Value::Map(vec![(key.clone(), digests.clone()), (key, digests.clone())]))
            .collect(),
    );
}

#[test]
fn integrity_register_uint_and_text_ids_are_distinct() {
    let digests = vec![Digest::new(7, vec![0xAA; 48])];
    let raw = Value::Map(vec![
        (int(1), value(&digests)),
        (text("1"), value(&digests)),
    ]);
    let parsed: IntegrityRegisters = decode(&raw).unwrap();
    assert_eq!(parsed.0.len(), 2);
    for key in [
        IntegrityRegisterId::Uint(1),
        IntegrityRegisterId::Text("1".into()),
    ] {
        assert_eq!(parsed.0.get(&key), Some(&digests));
    }
}

#[test]
fn duplicate_metadata_signer_cannot_fall_back_to_opaque_with_valid_cwt() {
    let signer = Value::Map(vec![(int(SIGNER_KEY_NAME), text("issuer"))]);
    let field = (int(META_KEY_SIGNER), signer);
    let mut m = vec![field.clone()];
    let mut h = entries(&header());
    h.push((
        int(COSE_HEADER_CORIM_META),
        Value::Bytes(cbor::encode(&Value::Map(m.clone())).unwrap()),
    ));
    let control = signed(&cbor::encode(&Value::Map(h.clone())).unwrap());
    let control = decode_signed_corim(&control).unwrap();
    assert!(control.protected.corim_meta.is_some());
    m.push(field);
    h.last_mut().unwrap().1 = Value::Bytes(cbor::encode(&Value::Map(m)).unwrap());
    let bytes = cbor::encode(&Value::Map(h)).unwrap();
    for error in [
        Header::decode_with_limits(&bytes, &cbor::DecodeLimits::default()).unwrap_err(),
        decode_signed_corim(&signed(&bytes)).unwrap_err(),
    ] {
        assert!(matches!(error, corim::DecodeError::DuplicateKey { .. }));
    }
}

#[test]
fn duplicate_coswid_key_cannot_fall_back_to_opaque_in_unsigned_validator() {
    let swid = ConciseSwidTag::new(
        TagIdChoice::Text("swid".into()),
        "software",
        0,
        vec![SwidEntity::new("issuer", vec![SWID_ROLE_TAG_CREATOR])],
    );
    let mut corim = sample_corim();
    corim
        .tags
        .push(ConciseTagChoice::Coswid(cbor::encode(&swid).unwrap()));
    let wrap = |c: &CorimMap| cbor::encode(&Value::Tag(TAG_CORIM, Box::new(value(c)))).unwrap();
    let valid = decode_and_validate_full_at(&wrap(&corim), 0).unwrap();
    assert_eq!(valid.coswids.len(), 1);
    assert_eq!(valid.coswid_opaque_count, 0);
    let mut m = entries(&swid);
    m.push((int(SWID_KEY_TAG_ID), value(&swid.tag_id)));
    *corim.tags.last_mut().unwrap() =
        ConciseTagChoice::Coswid(cbor::encode(&Value::Map(m)).unwrap());
    assert!(matches!(
        decode_and_validate_full_at(&wrap(&corim), 0),
        Err(corim::ValidationError::Decode(
            corim::DecodeError::DuplicateKey { .. }
        ))
    ));
}

// Handcraft aliases rather than letting the encoder canonicalize integer keys.
fn wire_alias(base: Entries, key: i64, ai: u8, width: usize, reverse: bool) -> Vec<u8> {
    let repeated = base.iter().find(|(k, _)| *k == int(key)).unwrap().clone();
    let mut bytes = vec![(c::MAJOR_MAP << 5) | u8::try_from(base.len() + 1).unwrap()];
    let last = base.len();
    for (index, (k, v)) in base.into_iter().chain([repeated]).enumerate() {
        if k == int(key) && ((index == last) != reverse) {
            bytes.push((c::MAJOR_UNSIGNED << 5) | ai);
            bytes.extend_from_slice(&u64::try_from(key).unwrap().to_be_bytes()[8 - width..]);
        } else {
            bytes.extend(cbor::encode(&k).unwrap());
        }
        bytes.extend(cbor::encode(&v).unwrap());
    }
    bytes
}

#[test]
fn numeric_key_aliases_reject_at_schema_boundaries_but_value_preserves_pairs() {
    for (ai, width) in [
        (c::AI_ONE_BYTE, 1),
        (c::AI_TWO_BYTES, 2),
        (c::AI_FOUR_BYTES, 4),
        (c::AI_EIGHT_BYTES, 8),
    ] {
        for reverse in [false, true] {
            for (kind, base, key) in [
                ("macro", entries(&sample_corim()), CORIM_KEY_ID),
                ("header", entries(&header()), COSE_HEADER_ALG),
                ("cwt", entries(&CwtClaims::new("issuer")), CWT_CLAIM_ISS),
            ] {
                let mut expected = base.clone();
                expected.push(base.iter().find(|(k, _)| *k == int(key)).unwrap().clone());
                let bytes = wire_alias(base, key, ai, width, reverse);
                assert_eq!(cbor::decode::<Value>(&bytes).unwrap(), Value::Map(expected));
                let error = match kind {
                    "macro" => cbor::decode::<CorimMap>(&bytes).unwrap_err(),
                    "header" => {
                        Header::decode_with_limits(&bytes, &Default::default()).unwrap_err()
                    }
                    _ => cbor::decode::<CwtClaims>(&bytes).unwrap_err(),
                };
                assert!(error.to_string().contains("duplicate"), "{kind}: {error}");
            }
        }
    }
}

#[test]
fn absent_macro_field_is_reserved_for_the_typed_field_not_extras() {
    let mut mval = MeasurementValuesMap::default();
    mval.extra_entries
        .insert(MVAL_KEY_SVN, value(&SvnChoice::ExactValue(1)));
    assert!(cbor::encode(&mval).is_err());
    mval.extra_entries.clear();
    mval.svn = Some(SvnChoice::ExactValue(1));
    assert_eq!(decode::<MeasurementValuesMap>(&value(&mval)).unwrap(), mval);
}

#[test]
fn cwt_reserved_extras_reject_even_when_optional_fields_are_absent() {
    for key in [CWT_CLAIM_ISS, CWT_CLAIM_SUB, CWT_CLAIM_EXP, CWT_CLAIM_NBF] {
        let mut claims = CwtClaims::new("issuer");
        assert_eq!((&claims.sub, claims.exp, claims.nbf), (&None, None, None));
        claims.extra.insert(ClaimKey::Int(key), Value::Null);
        assert!(cbor::encode(&claims).is_err(), "reserved key {key}");
    }
    let mut claims = CwtClaims::new("issuer");
    claims
        .extra
        .insert(ClaimKey::Text("1".into()), text("distinct"));
    assert_eq!(decode::<CwtClaims>(&value(&claims)).unwrap(), claims);
}

#[test]
fn optional_header_fields_reject_populated_extra_collisions() {
    let mut h = header();
    h.kid = Some(vec![4]);
    h.x5u = Some("https://example.com/cert".into());
    h.payload_hash_alg = Some(7);
    h.payload_preimage_content_type = Some(CORIM_CONTENT_TYPE.into());
    h.payload_location = Some("https://example.com/rim".into());
    h.corim_meta = Some(
        decode(&Value::Map(vec![(
            int(META_KEY_SIGNER),
            Value::Map(vec![(int(SIGNER_KEY_NAME), text("issuer"))]),
        )]))
        .unwrap(),
    );
    for (key, v) in entries(&h) {
        let Value::Integer(key) = key else {
            panic!("integer label")
        };
        let mut collision = h.clone();
        collision.extra.insert(i64::try_from(key).unwrap(), v);
        assert!(cbor::encode(&collision).is_err(), "populated key {key}");
    }
}

#[test]
fn malformed_metadata_remains_a_raw_extra_when_typed_metadata_is_absent() {
    let mut h = header();
    h.extra.insert(
        COSE_HEADER_CORIM_META,
        Value::Bytes(cbor::encode(&Value::Null).unwrap()),
    );
    let bytes = cbor::encode(&h).unwrap();
    let parsed = Header::decode_with_limits(&bytes, &Default::default()).unwrap();
    assert_eq!(parsed, h);
    assert!(parsed.corim_meta.is_none());
    let envelope = decode_signed_corim(&signed(&bytes)).unwrap();
    assert_eq!(envelope.protected, h);
    assert_eq!(envelope.protected_header_bytes, bytes);
}

#[test]
fn unprotected_duplicate_integer_and_text_labels_reject_on_encode_and_decode() {
    let clean = decode_signed_corim(&signed(&cbor::encode(&header()).unwrap())).unwrap();
    // The protected-header alg/iss exception must not apply to unprotected maps.
    for key in [int(COSE_HEADER_ALG), text("1")] {
        for (a, b) in [(int(-7), text("issuer")), (text("issuer"), int(-7))] {
            let mut envelope = clean.clone();
            envelope.unprotected = vec![(key.clone(), a), (key.clone(), b)];
            assert!(encode_signed_corim(&envelope).is_err());
            let bytes = cbor::encode(&Value::Tag(
                TAG_SIGNED_CORIM,
                Box::new(Value::Array(vec![
                    Value::Bytes(envelope.protected_header_bytes),
                    Value::Map(envelope.unprotected),
                    Value::Null,
                    Value::Bytes(envelope.signature),
                ])),
            ))
            .unwrap();
            assert!(matches!(
                decode_signed_corim(&bytes),
                Err(corim::DecodeError::DuplicateKey { .. })
            ));
        }
    }
}

#[test]
fn unprotected_integer_and_text_labels_with_same_spelling_are_distinct() {
    let mut envelope = decode_signed_corim(&signed(&cbor::encode(&header()).unwrap())).unwrap();
    envelope.unprotected = vec![(int(COSE_HEADER_ALG), int(-7)), (text("1"), text("issuer"))];
    let bytes = encode_signed_corim(&envelope).unwrap();
    assert_eq!(decode_signed_corim(&bytes).unwrap(), envelope);
}
