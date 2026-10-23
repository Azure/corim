// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use corim::builder::{ComidBuilder, CorimBuilder};
use corim::cbor::{self, value::Value, DecodeLimits};
use corim::document::{self, CompatibilityNote, TimeCheck, ValidationContext};
use corim::profile::ProfileRegistry;
use corim::types::common::{TagIdChoice, ValidityMap};
use corim::types::corim::{CorimId, CorimMetaMap, CorimSignerMap};
use corim::types::environment::EnvironmentMap;
use corim::types::measurement::{MeasurementMap, MeasurementValuesMap};
use corim::types::signed::{
    CwtClaims, SignedCorimBuilder, COSE_HEADER_ALG, COSE_HEADER_CORIM_META, CWT_CLAIM_EXP,
    CWT_CLAIM_NBF, CWT_CLAIM_SUB,
};
use corim::types::tags::CORIM_KEY_TAGS;
use corim::{DecodeError, ValidationError};

fn payload() -> Vec<u8> {
    let mut values = MeasurementValuesMap::default();
    values.name = Some("firmware".into());
    let comid = ComidBuilder::new(TagIdChoice::Text("preparation".into()))
        .add_reference_triple(corim::types::triples::ReferenceTriple::new(
            EnvironmentMap::for_class("Vendor", "Model"),
            vec![MeasurementMap {
                mkey: None,
                mval: values,
                authorized_by: None,
            }],
        ))
        .build()
        .unwrap();
    CorimBuilder::new(CorimId::Text("preparation".into()))
        .add_comid_tag(comid)
        .unwrap()
        .build_bytes()
        .unwrap()
}

fn signed(metadata: bool) -> Value {
    let mut builder =
        SignedCorimBuilder::new(-7, payload()).set_cwt_claims(CwtClaims::new("issuer").with_exp(1));
    if metadata {
        builder = builder.set_corim_meta(CorimMetaMap {
            signer: CorimSignerMap {
                signer_name: "issuer".into(),
                signer_uri: None,
            },
            signature_validity: Some(ValidityMap {
                not_before: None,
                not_after: 1.into(),
            }),
        });
    }
    cbor::decode_exact(&builder.build_with_signature(vec![0; 64]).unwrap()).unwrap()
}

fn parts(root: &mut Value) -> &mut Vec<Value> {
    let Value::Tag(_, inner) = root else {
        panic!("signed tag");
    };
    let Value::Array(parts) = inner.as_mut() else {
        panic!("COSE array");
    };
    parts
}

fn map(value: &mut Value) -> &mut Vec<(Value, Value)> {
    match value {
        Value::Tag(_, inner) => map(inner),
        Value::Map(fields) => fields,
        _ => panic!("map"),
    }
}

fn bytes(value: &mut Value) -> &mut Vec<u8> {
    let Value::Bytes(bytes) = value else {
        panic!("byte string");
    };
    bytes
}

fn edit_header(root: &mut Value, edit: impl FnOnce(&mut Vec<(Value, Value)>)) {
    let raw = bytes(&mut parts(root)[0]);
    let mut header: Value = cbor::decode_exact(raw).unwrap();
    edit(map(&mut header));
    *raw = cbor::encode(&header).unwrap();
}

fn nodes(value: &Value) -> usize {
    1 + match value {
        Value::Array(items) => items.iter().map(nodes).sum(),
        Value::Map(entries) => entries
            .iter()
            .map(|(key, value)| nodes(key) + nodes(value))
            .sum(),
        Value::Tag(_, inner) => nodes(inner),
        _ => 0,
    }
}

#[derive(Clone, Copy, Debug)]
enum Boundary {
    Metadata,
    Payload,
    Tag,
}

#[derive(Clone, Copy, Debug)]
enum Failure {
    Trailing,
    Duplicate,
    Values,
}

fn corrupt(raw: &mut Vec<u8>, failure: Failure) {
    match failure {
        Failure::Trailing => raw.extend(cbor::encode(&Value::Null).unwrap()),
        Failure::Duplicate => {
            let mut value: Value = cbor::decode_exact(raw).unwrap();
            let fields = map(&mut value);
            fields.push(fields[0].clone());
            *raw = cbor::encode(&value).unwrap();
        }
        Failure::Values => {}
    }
}

fn check_expired_header_failure(failure: Failure) {
    for boundary in [Boundary::Metadata, Boundary::Payload, Boundary::Tag] {
        let mut root = signed(matches!(boundary, Boundary::Metadata));
        let registry = ProfileRegistry::new();
        let clean = cbor::encode(&root).unwrap();
        assert!(
            document::validate(&clean, &ValidationContext::new(TimeCheck::At(0), &registry))
                .is_ok()
        );
        assert!(matches!(
            document::validate(
                &clean,
                &ValidationContext::new(TimeCheck::At(100), &registry)
            ),
            Err(ValidationError::Expired)
        ));
        let mut limits = DecodeLimits::default();
        if matches!(failure, Failure::Values) {
            let outer_nodes = nodes(&root);
            let slots = parts(&mut root);
            let header: Value = cbor::decode_exact(bytes(&mut slots[0])).unwrap();
            limits.max_values = outer_nodes + nodes(&header);
            if matches!(boundary, Boundary::Tag) {
                limits.max_values += nodes(&cbor::decode_exact(bytes(&mut slots[2])).unwrap());
            }
        } else {
            match boundary {
                Boundary::Metadata => edit_header(&mut root, |fields| {
                    let (_, value) = fields
                        .iter_mut()
                        .find(|(key, _)| *key == Value::Integer(COSE_HEADER_CORIM_META.into()))
                        .unwrap();
                    corrupt(bytes(value), failure);
                }),
                Boundary::Payload => corrupt(bytes(&mut parts(&mut root)[2]), failure),
                Boundary::Tag => {
                    let raw = bytes(&mut parts(&mut root)[2]);
                    let mut payload: Value = cbor::decode_exact(raw).unwrap();
                    let (_, Value::Array(tags)) = map(&mut payload)
                        .iter_mut()
                        .find(|(key, _)| *key == Value::Integer(CORIM_KEY_TAGS.into()))
                        .unwrap()
                    else {
                        panic!("tags");
                    };
                    let Value::Tag(_, body) = &mut tags[0] else {
                        panic!("CoMID");
                    };
                    corrupt(bytes(body), failure);
                    *raw = cbor::encode(&payload).unwrap();
                }
            }
        }
        let error = document::validate(
            &cbor::encode(&root).unwrap(),
            &ValidationContext::new(TimeCheck::At(100), &registry).with_limits(limits),
        )
        .unwrap_err();
        let expected = match (&failure, &error) {
            (Failure::Trailing, ValidationError::Decode(DecodeError::TrailingData { .. }))
            | (Failure::Duplicate, ValidationError::Decode(DecodeError::DuplicateKey { .. }))
            | (
                Failure::Values,
                ValidationError::Decode(DecodeError::LimitExceeded {
                    resource: "values", ..
                }),
            ) => true,
            _ => false,
        };
        assert!(expected, "{boundary:?} {failure:?}: {error:?}");
    }
}

#[test]
fn expired_headers_do_not_hide_embedded_framing_errors() {
    check_expired_header_failure(Failure::Trailing);
}

#[test]
fn expired_headers_do_not_hide_embedded_duplicate_keys() {
    check_expired_header_failure(Failure::Duplicate);
}

#[test]
fn expired_headers_do_not_hide_embedded_resource_failures() {
    check_expired_header_failure(Failure::Values);
}

#[test]
fn matching_flat_subject_and_times_are_reported_without_flat_issuer() {
    let builder = SignedCorimBuilder::new(-7, payload()).set_cwt_claims(
        CwtClaims::new("issuer")
            .with_sub("subject")
            .with_exp(100)
            .with_nbf(0),
    );
    let clean: Value =
        cbor::decode_exact(&builder.build_with_signature(vec![0; 64]).unwrap()).unwrap();
    let registry = ProfileRegistry::new();
    let context = ValidationContext::new(TimeCheck::At(0), &registry);
    for (key, value) in [
        (CWT_CLAIM_SUB, Value::Text("subject".into())),
        (CWT_CLAIM_EXP, Value::Integer(100)),
        (CWT_CLAIM_EXP, Value::Float(100.0)),
        (CWT_CLAIM_NBF, Value::Integer(0)),
        (CWT_CLAIM_NBF, Value::Float(0.0)),
    ] {
        let mut root = clean.clone();
        edit_header(&mut root, |fields| {
            fields.push((Value::Integer(key.into()), value))
        });
        let outcome = document::validate(&cbor::encode(&root).unwrap(), &context).unwrap();
        assert!(
            outcome
                .coverage()
                .compatibility()
                .contains(&CompatibilityNote::FlatCwtClaims),
            "flat claim {key}"
        );
    }
    // These are the ordinary COSE roles of the same labels, not flat claims.
    for (key, value) in [
        (
            CWT_CLAIM_SUB,
            Value::Array(vec![Value::Integer(COSE_HEADER_ALG.into())]),
        ),
        (CWT_CLAIM_EXP, Value::Bytes(vec![1])),
        (CWT_CLAIM_NBF, Value::Bytes(vec![2])),
    ] {
        let mut root = clean.clone();
        edit_header(&mut root, |fields| {
            fields.push((Value::Integer(key.into()), value))
        });
        let outcome = document::validate(&cbor::encode(&root).unwrap(), &context).unwrap();
        assert!(!outcome
            .coverage()
            .compatibility()
            .contains(&CompatibilityNote::FlatCwtClaims));
    }
}
