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
            CoseSignature::from_parts(
                header("second", CoseAlgorithm::Esp384),
                vec![],
                vec![2],
            )
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
    let Value::Array(parts) = *inner else { panic!("array") };
    for signatures in [Value::Array(vec![]), Value::Bytes(vec![]), Value::Array(vec![Value::Null])] {
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
    envelope.unprotected.push((Value::Integer(1000), Value::Null));
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
