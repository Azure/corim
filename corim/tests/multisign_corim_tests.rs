use corim::builder::{ComidBuilder, CorimBuilder};
use corim::cbor::{self, value::Value, DecodeLimits};
use corim::document::{self, TimeCheck, ValidationContext};
use corim::profile::ProfileRegistry;
use corim::types::common::TagIdChoice;
use corim::types::corim::CorimId;
use corim::types::environment::EnvironmentMap;
use corim::types::measurement::{MeasurementMap, MeasurementValuesMap, SvnChoice};
use corim::types::signed::*;
use corim::types::tags::{TAG_CORIM, TAG_MULTI_SIGNED_CORIM};
use corim::types::triples::ReferenceTriple;

const NOW: i64 = 1_800_000_000;

fn header(issuer: &str, alg: CoseAlgorithm) -> Vec<u8> {
    let header = ProtectedCorimHeaderMapBuilder::new(alg)
        .content_type(CORIM_CONTENT_TYPE)
        .cwt_claims(CwtClaims::new(issuer).with_exp(NOW + 100))
        .build();
    cbor::encode(&header).unwrap()
}

fn payload() -> Vec<u8> {
    let mut values = MeasurementValuesMap::default();
    values.svn = Some(SvnChoice::ExactValue(1));
    let comid = ComidBuilder::new(TagIdChoice::Text("multi".into()))
        .add_reference_triple(ReferenceTriple::new(
            EnvironmentMap::for_class("vendor", "model"),
            vec![MeasurementMap {
                mkey: None,
                mval: values,
                authorized_by: None,
            }],
        ))
        .build()
        .unwrap();
    CorimBuilder::new(CorimId::Text("multi".into()))
        .add_comid_tag(comid)
        .unwrap()
        .build_bytes()
        .unwrap()
}

fn envelope(payload: Option<Vec<u8>>) -> CoseSignCorim {
    let creator = header("creator", CoseAlgorithm::Esp256);
    CoseSignCorim::from_parts(
        creator.clone(),
        vec![],
        payload,
        vec![
            CoseSignature::from_parts(creator, vec![], vec![1]).unwrap(),
            CoseSignature::from_parts(header("second", CoseAlgorithm::Esp384), vec![], vec![2])
                .unwrap(),
        ],
    )
    .unwrap()
}

#[test]
fn multi_signature_round_trip_and_exact_signature_structure() {
    let envelope = envelope(Some(payload()));
    let bytes = encode_multi_signed_corim(&envelope).unwrap();
    assert_eq!(decode_multi_signed_corim(&bytes).unwrap(), envelope);
    for (index, signature) in envelope.signatures().iter().enumerate() {
        let tbs = envelope.to_be_signed(index, b"aad").unwrap();
        assert_eq!(
            cbor::decode_exact::<Value>(&tbs).unwrap(),
            Value::Array(vec![
                Value::Text("Signature".into()),
                Value::Bytes(envelope.protected_header_bytes().to_vec()),
                Value::Bytes(signature.protected_header_bytes().to_vec()),
                Value::Bytes(b"aad".to_vec()),
                Value::Bytes(envelope.payload.as_ref().unwrap().clone()),
            ])
        );
    }
    assert!(envelope.to_be_signed(2, &[]).is_err());
}

#[test]
fn common_document_dispatch_checks_every_signer_and_detached_payload() {
    let registry = ProfileRegistry::new();
    let bytes = encode_multi_signed_corim(&envelope(Some(payload()))).unwrap();
    let outcome = document::validate(
        &bytes,
        &ValidationContext::new(TimeCheck::At(NOW), &registry),
    )
    .unwrap();
    assert!(outcome.coverage().is_complete());
    assert!(matches!(outcome.envelope(), Some(SignedEnvelope::Sign(_))));
    let detached = envelope(None);
    assert!(detached.to_be_signed(0, &[]).is_err());
    let bytes = encode_multi_signed_corim(&detached).unwrap();
    let context = ValidationContext::new(TimeCheck::At(NOW), &registry);
    assert!(document::validate(&bytes, &context).is_err());
    let payload = payload();
    assert!(document::validate(&bytes, &context.with_detached_payload(&payload)).is_ok());
}

#[test]
fn reject_empty_signatures_wrong_slots_first_signer_mismatch_and_trailing_data() {
    let bytes = encode_multi_signed_corim(&envelope(Some(payload()))).unwrap();
    let Value::Tag(_, inner) = cbor::decode_exact::<Value>(&bytes).unwrap() else {
        panic!("tag");
    };
    let Value::Array(parts) = *inner else {
        panic!("array")
    };
    for signatures in [
        Value::Array(vec![]),
        Value::Bytes(vec![]),
        Value::Array(vec![Value::Null]),
    ] {
        let mut malformed = parts.clone();
        malformed[3] = signatures;
        let bytes = cbor::encode(&Value::Tag(
            TAG_MULTI_SIGNED_CORIM,
            Box::new(Value::Array(malformed)),
        ))
        .unwrap();
        assert!(decode_multi_signed_corim(&bytes).is_err());
    }
    assert!(CoseSignCorim::from_parts(
        header("other", CoseAlgorithm::Esp256),
        vec![],
        Some(payload()),
        envelope(Some(payload())).signatures().to_vec(),
    )
    .is_err());
    let mut trailing = bytes;
    trailing.push(0);
    assert!(decode_multi_signed_corim(&trailing).is_err());
}

#[test]
fn body_and_signer_bytes_are_authoritative_and_budget_is_shared() {
    let mut envelope = envelope(Some(payload()));
    let bytes = encode_multi_signed_corim(&envelope).unwrap();
    let tbs = envelope.to_be_signed(1, &[]).unwrap();
    envelope
        .unprotected
        .push((Value::Integer(1000), Value::Null));
    assert_eq!(envelope.to_be_signed(1, &[]).unwrap(), tbs);
    let mut limits = DecodeLimits::default();
    limits.max_values = 10;
    assert!(decode_multi_signed_corim_with_limits(&bytes, &limits).is_err());
    assert!(document::inspect(&bytes, &limits).is_err());
    assert!(matches!(
        cbor::decode_exact::<Value>(&payload()).unwrap(),
        Value::Tag(TAG_CORIM, _)
    ));
}

#[test]
fn original_nonpreferred_header_bytes_are_not_reencoded() {
    let mut creator = header("creator", CoseAlgorithm::Esp256);
    // Encode key 1 with a non-preferred one-byte argument (RFC 8949 §3).
    assert_eq!(creator[1], 1);
    creator.insert(1, 0x18);
    let envelope = CoseSignCorim::from_parts(
        creator.clone(),
        vec![],
        Some(payload()),
        vec![CoseSignature::from_parts(creator.clone(), vec![], vec![1]).unwrap()],
    )
    .unwrap();
    assert_eq!(envelope.protected_header_bytes(), creator);
    assert_eq!(envelope.signatures()[0].protected_header_bytes(), creator);
    let Value::Array(tbs) =
        cbor::decode_exact::<Value>(&envelope.to_be_signed(0, &[]).unwrap()).unwrap()
    else {
        panic!("array")
    };
    assert_eq!(tbs[1], Value::Bytes(creator.clone()));
    assert_eq!(tbs[2], Value::Bytes(creator));
}

#[test]
fn every_signer_window_is_checked_and_preparation_errors_win() {
    let mut value: Value =
        cbor::decode_exact(&encode_multi_signed_corim(&envelope(Some(payload()))).unwrap())
            .unwrap();
    let Value::Tag(_, inner) = &mut value else {
        panic!("tag")
    };
    let Value::Array(parts) = inner.as_mut() else {
        panic!("array")
    };
    let Value::Array(signers) = &mut parts[3] else {
        panic!("signers")
    };
    let Value::Array(second) = &mut signers[1] else {
        panic!("signature")
    };
    let expired = ProtectedCorimHeaderMapBuilder::new(CoseAlgorithm::Esp384)
        .content_type(CORIM_CONTENT_TYPE)
        .cwt_claims(CwtClaims::new("second").with_exp(NOW - 1))
        .build();
    second[0] = Value::Bytes(cbor::encode(&expired).unwrap());
    let registry = ProfileRegistry::new();
    let context = ValidationContext::new(TimeCheck::At(NOW), &registry);
    let bytes = cbor::encode(&value).unwrap();
    assert!(matches!(
        document::validate(&bytes, &context),
        Err(corim::ValidationError::Expired)
    ));
    let Value::Tag(_, inner) = &mut value else {
        panic!("tag")
    };
    let Value::Array(parts) = inner.as_mut() else {
        panic!("array")
    };
    let Value::Array(signers) = &mut parts[3] else {
        panic!("signers")
    };
    let Value::Array(second) = &mut signers[1] else {
        panic!("signature")
    };
    let Value::Bytes(bytes) = &mut second[0] else {
        panic!("bytes")
    };
    bytes.push(0);
    assert!(matches!(
        document::validate(&cbor::encode(&value).unwrap(), &context),
        Err(corim::ValidationError::Decode(
            corim::DecodeError::TrailingData { .. }
        ))
    ));
}

#[test]
fn multi_signature_builder_checks_signature_count_and_detached_tbs() {
    let creator = ProtectedCorimHeaderMapBuilder::new(CoseAlgorithm::Esp256)
        .content_type(CORIM_CONTENT_TYPE)
        .cwt_claims(CwtClaims::new("creator"))
        .build();
    let builder = MultiSignedCorimBuilder::new(creator, payload()).unwrap();
    assert!(builder.clone().build_with_signatures(vec![]).is_err());
    assert!(builder.to_be_signed(1, &[]).is_err());
    let tbs = builder.to_be_signed(0, b"aad").unwrap();
    let bytes = builder
        .build_detached_with_signatures(vec![vec![1]])
        .unwrap();
    let envelope = decode_multi_signed_corim(&bytes).unwrap();
    assert!(envelope.is_detached());
    assert_eq!(
        envelope
            .to_be_signed_detached(0, &payload(), b"aad")
            .unwrap(),
        tbs
    );
}

#[test]
fn each_known_tree_is_charged_once_against_the_aggregate_budget() {
    fn count(value: &Value) -> usize {
        1 + match value {
            Value::Array(values) => values.iter().map(count).sum(),
            Value::Map(entries) => entries
                .iter()
                .map(|(key, value)| count(key) + count(value))
                .sum(),
            Value::Tag(_, inner) => count(inner),
            _ => 0,
        }
    }
    let envelope = envelope(Some(payload()));
    let bytes = encode_multi_signed_corim(&envelope).unwrap();
    let mut needed = count(&cbor::decode_exact::<Value>(&bytes).unwrap());
    needed += count(&cbor::decode_exact::<Value>(envelope.protected_header_bytes()).unwrap());
    for signature in envelope.signatures() {
        needed += count(&cbor::decode_exact::<Value>(signature.protected_header_bytes()).unwrap());
    }
    let payload = payload();
    needed += count(&cbor::decode_exact::<Value>(&payload).unwrap());
    let payload: cbor::value::Tagged<corim::types::corim::CorimMap> =
        cbor::decode_exact(&payload).unwrap();
    for tag in payload.value.tags {
        if let corim::types::corim::ConciseTagChoice::Comid(bytes) = tag {
            needed += count(&cbor::decode_exact::<Value>(&bytes).unwrap());
        }
    }
    let registry = ProfileRegistry::new();
    for (limit, success) in [(needed, true), (needed - 1, false)] {
        let mut limits = DecodeLimits::default();
        limits.max_values = limit;
        let context = ValidationContext::new(TimeCheck::At(NOW), &registry).with_limits(limits);
        assert_eq!(
            document::validate(&bytes, &context).is_ok(),
            success,
            "budget {limit}"
        );
        assert_eq!(
            document::inspect(&bytes, &limits).is_ok(),
            success,
            "inspection budget {limit}"
        );
    }
}
