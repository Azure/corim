// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use corim::builder::{ComidBuilder, CorimBuilder};
use corim::cbor::{
    self,
    value::{Tagged, Value},
    DecodeLimits,
};
use corim::document::{self, CompatibilityNote, ProfileCoverage, TimeCheck, ValidationContext};
use corim::profile::{Profile, ProfileRegistry};
use corim::types::common::TagIdChoice;
use corim::types::corim::{ConciseTagChoice, CorimId, CorimMap, ProfileChoice};
use corim::types::environment::EnvironmentMap;
use corim::types::measurement::{MeasurementMap, MeasurementValuesMap, SvnChoice};
use corim::types::signed::{CoseAlgorithm, CwtClaims, SignedCorimBuilder};
use corim::types::tags::{TAG_CORIM, TAG_LEGACY_TOP, TAG_SIGNED_CORIM};
use corim::{DecodeError, ValidationError};

fn unsigned() -> Vec<u8> {
    let mut values = MeasurementValuesMap::default();
    values.svn = Some(SvnChoice::MinValue(1));
    let comid = ComidBuilder::new(TagIdChoice::Text("document".into()))
        .add_reference_triple(corim::types::triples::ReferenceTriple::new(
            EnvironmentMap::for_class("vendor", "model"),
            vec![MeasurementMap {
                mkey: None,
                mval: values,
                authorized_by: None,
            }],
        ))
        .build()
        .unwrap();
    CorimBuilder::new(CorimId::Text("document".into()))
        .add_comid_tag(comid)
        .unwrap()
        .build_bytes()
        .unwrap()
}

fn nodes(value: &Value) -> usize {
    1 + match value {
        Value::Map(entries) => entries
            .iter()
            .map(|(key, value)| nodes(key) + nodes(value))
            .sum(),
        Value::Array(entries) => entries.iter().map(nodes).sum(),
        Value::Tag(_, value) => nodes(value),
        _ => 0,
    }
}

fn unsigned_nodes(bytes: &[u8]) -> usize {
    let root: Value = cbor::decode_exact(bytes).unwrap();
    let corim = cbor::decode_exact::<Tagged<CorimMap>>(bytes).unwrap().value;
    let ConciseTagChoice::Comid(body) = &corim.tags[0] else {
        panic!("CoMID");
    };
    nodes(&root) + nodes(&cbor::decode_exact(body).unwrap())
}

#[test]
fn unsigned_and_signed_outcomes_state_their_actual_coverage() {
    let registry = ProfileRegistry::new();
    let context = ValidationContext::new(TimeCheck::At(0), &registry);
    let bytes = unsigned();
    let plain = document::validate(&bytes, &context).unwrap();
    assert!(plain.coverage().is_complete());
    assert_eq!(plain.coverage().profile(), &ProfileCoverage::NotDeclared);
    assert!(plain.envelope().is_none());
    let signed = SignedCorimBuilder::new(CoseAlgorithm::Es256, bytes)
        .set_cwt_claims(CwtClaims::new("issuer"))
        .add_protected("private:extension", Value::Text("opaque".into()))
        .build_with_signature(vec![0; 64])
        .unwrap();
    let outcome = document::validate(&signed, &context).unwrap();
    assert!(outcome.coverage().is_complete());
    let envelope = outcome.envelope().unwrap();
    let original = envelope.protected_header_bytes().to_vec();
    let mut edited_copy = envelope.protected().clone();
    edited_copy.alg = CoseAlgorithm::Es384;
    assert_ne!(edited_copy, *envelope.protected());
    assert_eq!(envelope.protected_header_bytes(), original);
}

#[test]
fn skipped_time_and_unknown_profile_are_explicitly_partial() {
    let registry = ProfileRegistry::new();
    let partial = document::validate(
        &unsigned(),
        &ValidationContext::new(TimeCheck::Skip, &registry),
    )
    .unwrap();
    assert!(!partial.coverage().is_complete());
    assert_eq!(partial.coverage().time(), TimeCheck::Skip);
    let mut corim = cbor::decode_exact::<Tagged<CorimMap>>(&unsigned())
        .unwrap()
        .value;
    let id = ProfileChoice::Uri("tag:example.com,2026:unregistered".into());
    corim.profile = Some(id.clone());
    let bytes = cbor::encode(&corim).unwrap();
    let outcome =
        document::validate(&bytes, &ValidationContext::new(TimeCheck::At(0), &registry)).unwrap();
    assert_eq!(
        outcome.coverage().profile(),
        &ProfileCoverage::Unregistered(id)
    );
    assert!(!outcome.coverage().is_complete());
}

#[test]
fn supplied_detached_payload_uses_the_same_document_contract() {
    let payload = unsigned();
    let bytes = SignedCorimBuilder::new(CoseAlgorithm::Es256, payload.clone())
        .set_cwt_claims(CwtClaims::new("issuer"))
        .build_detached_with_signature(vec![0; 64])
        .unwrap();
    let registry = ProfileRegistry::new();
    let context = ValidationContext::new(TimeCheck::At(0), &registry);
    assert!(document::validate(&bytes, &context).is_err());
    let supplied = context.clone().with_detached_payload(&payload);
    let outcome = document::validate(&bytes, &supplied).unwrap();
    assert!(outcome.coverage().is_complete());
    assert!(outcome.envelope().unwrap().is_detached());
    assert_eq!(outcome.payload().comids.len(), 1);
    assert!(document::validate(&payload, &supplied).is_err());
    let attached = SignedCorimBuilder::new(CoseAlgorithm::Es256, payload.clone())
        .set_cwt_claims(CwtClaims::new("issuer"))
        .build_with_signature(vec![0; 64])
        .unwrap();
    assert!(document::validate(&attached, &supplied).is_ok());
    let mismatched = context.with_detached_payload(&bytes);
    assert!(document::validate(&attached, &mismatched).is_err());
}

#[test]
fn numeric_dates_compare_precisely_without_measurement_matcher_policy() {
    use core::cmp::Ordering;
    use corim::types::signed::NumericDate;
    for (left, right, expected) in [
        (
            NumericDate::Int(9_007_199_254_740_993),
            NumericDate::Float(9_007_199_254_740_992.0),
            Ordering::Greater,
        ),
        (
            NumericDate::Int(0),
            NumericDate::Float(-0.0),
            Ordering::Equal,
        ),
        (
            NumericDate::Float(1000.25),
            NumericDate::Int(1000),
            Ordering::Greater,
        ),
        (
            NumericDate::Float(-0.75),
            NumericDate::Int(0),
            Ordering::Less,
        ),
    ] {
        assert_eq!(left.numeric_cmp(&right).unwrap(), expected);
        assert_eq!(right.numeric_cmp(&left).unwrap(), expected.reverse());
    }
    assert!(NumericDate::Float(f64::NAN)
        .numeric_cmp(&NumericDate::Int(0))
        .is_err());
    assert!(NumericDate::Int(0)
        .numeric_cmp(&NumericDate::Float(f64::INFINITY))
        .is_err());
}

#[derive(Clone, Debug)]
struct ExampleProfile(ProfileChoice);

impl Profile for ExampleProfile {
    fn identifier(&self) -> &ProfileChoice {
        &self.0
    }
}

#[test]
fn registered_profiles_are_checked_but_unknown_tags_remain_partial() {
    let id = ProfileChoice::Uri("tag:example.com,2026:registered".into());
    let mut registry = ProfileRegistry::new();
    registry.register(Box::new(ExampleProfile(id.clone())));
    let context = ValidationContext::new(TimeCheck::At(0), &registry);
    let mut corim = cbor::decode_exact::<Tagged<CorimMap>>(&unsigned())
        .unwrap()
        .value;
    corim.profile = Some(id.clone());
    let outcome = document::validate(&cbor::encode(&corim).unwrap(), &context).unwrap();
    assert!(outcome.coverage().is_complete());
    assert_eq!(outcome.coverage().profile(), &ProfileCoverage::Checked(id));
    corim
        .tags
        .push(ConciseTagChoice::Unknown(TAG_SIGNED_CORIM, vec![0]));
    let outcome = document::validate(&cbor::encode(&corim).unwrap(), &context).unwrap();
    assert_eq!(outcome.coverage().unexamined_tags(), &[1]);
    assert!(!outcome.coverage().is_complete());
}

#[test]
fn one_aggregate_budget_counts_each_document_tree_once() {
    let bytes = unsigned();
    let registry = ProfileRegistry::new();
    let count = unsigned_nodes(&bytes);
    let mut limits = DecodeLimits::default();
    limits.max_values = count;
    let context = ValidationContext::new(TimeCheck::At(0), &registry).with_limits(limits);
    assert!(document::validate(&bytes, &context).is_ok());
    limits.max_values -= 1;
    let context = ValidationContext::new(TimeCheck::At(0), &registry).with_limits(limits);
    assert!(matches!(
        document::validate(&bytes, &context),
        Err(ValidationError::Decode(DecodeError::LimitExceeded {
            resource: "values",
            ..
        }))
    ));
    let signed = SignedCorimBuilder::new(CoseAlgorithm::Es256, bytes)
        .set_cwt_claims(CwtClaims::new("issuer"))
        .build_with_signature(vec![0; 64])
        .unwrap();
    let envelope = corim::types::signed::decode_signed_corim(&signed).unwrap();
    limits.max_values = count
        + nodes(&cbor::decode_exact(&signed).unwrap())
        + nodes(&cbor::decode_exact(envelope.protected_header_bytes()).unwrap());
    let context = ValidationContext::new(TimeCheck::At(0), &registry).with_limits(limits);
    assert!(document::validate(&signed, &context).is_ok());
    limits.max_values -= 1;
    let context = ValidationContext::new(TimeCheck::At(0), &registry).with_limits(limits);
    assert!(matches!(
        document::validate(&signed, &context),
        Err(ValidationError::Decode(DecodeError::LimitExceeded {
            resource: "values",
            ..
        }))
    ));
}

#[test]
fn compatibility_notes_do_not_make_checked_documents_partial() {
    let registry = ProfileRegistry::new();
    let context = ValidationContext::new(TimeCheck::At(0), &registry);
    let value: Value = cbor::decode_exact(&unsigned()).unwrap();
    let wrapped = Value::Tag(TAG_LEGACY_TOP, Box::new(value.clone()));
    let outcome = document::validate(&cbor::encode(&wrapped).unwrap(), &context).unwrap();
    assert!(outcome.coverage().is_complete());
    assert_eq!(
        outcome.coverage().compatibility(),
        &[CompatibilityNote::LegacyOuterTag(TAG_LEGACY_TOP)]
    );
    let Value::Tag(TAG_CORIM, inner) = value else {
        panic!("CoRIM");
    };
    let outcome = document::validate(&cbor::encode(&inner).unwrap(), &context).unwrap();
    assert!(outcome
        .coverage()
        .compatibility()
        .contains(&CompatibilityNote::BareCorimMap));
    assert!(outcome
        .payload()
        .corim
        .tags
        .iter()
        .all(|tag| matches!(tag, ConciseTagChoice::Comid(_))));
}
