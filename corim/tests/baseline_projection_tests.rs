// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Behavioral invariants for baseline comparison's private interpretation.

// These fixtures also compile when the public models are non-exhaustive.
#![allow(clippy::field_reassign_with_default)]

use corim::baseline::{compare, render_path};
use corim::builder::{ComidBuilder, CorimBuilder};
use corim::types::common::{MeasuredElement, TagIdChoice};
use corim::types::corim::{CorimId, CorimMap};
use corim::types::environment::EnvironmentMap;
use corim::types::matcher::{Number, NumberMatcher, TextMatcher};
use corim::types::measurement::{
    Digest, IntegrityRegisterId, IntegrityRegisters, MeasurementMap, MeasurementValuesMap,
};
use corim::types::triples::ReferenceTriple;

fn measurement(marker: u8, reverse: bool) -> MeasurementMap {
    let mut values = MeasurementValuesMap::default();
    let mut digests = vec![
        Digest::new(7, vec![marker]),
        Digest::new(7, vec![marker + 1]),
    ];
    let mut texts = vec!["first".into(), "second".into(), "first".into()];
    if reverse {
        digests.reverse();
        texts.reverse();
    }
    values.digests = Some(digests.clone());
    values.integrity_registers = Some(IntegrityRegisters(
        [
            (IntegrityRegisterId::Uint(1), digests.clone()),
            (IntegrityRegisterId::Text("1".into()), digests),
        ]
        .into(),
    ));
    values.text = Some(TextMatcher::Set(texts));
    MeasurementMap {
        mkey: Some(MeasuredElement::Text("same".into())),
        mval: values,
        authorized_by: None,
    }
}

fn document(measurements: Vec<MeasurementMap>) -> CorimMap {
    let comid = ComidBuilder::new(TagIdChoice::Text("same".into()))
        .add_reference_triple(ReferenceTriple::new(
            EnvironmentMap::for_class("vendor", "model"),
            measurements,
        ))
        .build()
        .unwrap();
    CorimBuilder::new(CorimId::Text("projection".into()))
        .add_comid_tag(comid)
        .unwrap()
        .build()
        .unwrap()
}

#[test]
fn duplicate_typed_identities_reserve_nested_multiset_matches() {
    let baseline = document(vec![measurement(1, false), measurement(8, false)]);
    let mut changed = measurement(1, true);
    changed.mval.digests.as_mut().unwrap()[0].1 = vec![40];
    let input = document(vec![measurement(8, true), changed]);
    let report = compare(&input, &baseline).unwrap();
    assert!(report.structural_mismatches.is_empty());
    assert_eq!(report.value_differences.len(), 1);
    assert_eq!(report.value_differences[0].field, "digest-value");
    assert_eq!(
        render_path(&report.value_differences[0].path),
        "$.comid[same].reference[0].measurement[same].digests[1]"
    );
}

#[test]
fn floating_matcher_identity_uses_bits_including_nan_and_signed_zero() {
    let with_number = |bits| {
        let mut entry = measurement(1, false);
        entry.mval.number = Some(NumberMatcher::Set(vec![
            Number::Float(f64::from_bits(bits)),
            Number::Int(1),
        ]));
        entry
    };
    let nan = f64::NAN.to_bits();
    for (first, second) in [(0.0f64.to_bits(), (-0.0f64).to_bits()), (nan, nan ^ 1)] {
        // checked_comids normalizes NaNs through the CBOR engine. Compare
        // identical decoded bit patterns, not their pre-encoding payloads.
        let baseline = document(vec![with_number(first), with_number(second)]);
        let input = document(vec![with_number(second), with_number(first)]);
        let report = compare(&input, &baseline).unwrap();
        assert!(report.structural_mismatches.is_empty());
        assert!(report.value_differences.is_empty());
    }
}

#[test]
fn optional_measurement_presence_is_not_an_empty_collection() {
    let absent = measurement(1, false);
    let mut present = absent.clone();
    present.mval.integrity_registers = Some(IntegrityRegisters(Default::default()));
    let mut missing = present.clone();
    missing.mval.integrity_registers = None;
    let report = compare(&document(vec![missing]), &document(vec![present])).unwrap();
    assert_eq!(report.structural_mismatches.len(), 1);
    assert!(report.value_differences.is_empty());
    assert_eq!(
        render_path(&report.structural_mismatches[0].path),
        "$.comid[same].reference[0].measurement[same].integrity-registers"
    );
    // The fixture itself still has both typed register identities.
    assert_eq!(absent.mval.integrity_registers.unwrap().0.len(), 2);
}

#[test]
fn extension_map_order_is_unordered_but_nested_arrays_remain_positional() {
    use corim::cbor::value::Value;
    let mut baseline = measurement(1, false);
    baseline.mval.extra_entries.insert(
        10001,
        Value::Map(vec![
            (
                Value::Integer(1),
                Value::Array(vec![Value::Bool(true), Value::Bool(false)]),
            ),
            (Value::Text("1".into()), Value::Integer(1)),
        ]),
    );
    let mut reordered = baseline.clone();
    let Value::Map(entries) = reordered.mval.extra_entries.get_mut(&10001).unwrap() else {
        panic!("map fixture");
    };
    entries.reverse();
    let report = compare(
        &document(vec![reordered.clone()]),
        &document(vec![baseline.clone()]),
    )
    .unwrap();
    assert!(report.structural_mismatches.is_empty());
    assert!(report.value_differences.is_empty());
    let Value::Map(entries) = reordered.mval.extra_entries.get_mut(&10001).unwrap() else {
        panic!("map fixture");
    };
    let Value::Array(values) = &mut entries[1].1 else {
        panic!("array fixture")
    };
    values.reverse();
    let report = compare(&document(vec![reordered]), &document(vec![baseline])).unwrap();
    assert!(report.structural_mismatches.is_empty());
    assert_eq!(report.value_differences.len(), 2);
}

#[test]
fn decoded_flags_serialization_failures_remain_errors_on_either_side() {
    use corim::cbor::{self, value::Value};
    use corim::types::corim::ConciseTagChoice;
    use corim::types::tags::*;

    fn field(value: &mut Value, label: i64) -> &mut Value {
        let Value::Map(entries) = value else {
            panic!("map fixture")
        };
        &mut entries
            .iter_mut()
            .find(|(key, _)| *key == Value::Integer(i128::from(label)))
            .unwrap()
            .1
    }
    fn item(value: &mut Value, index: usize) -> &mut Value {
        let Value::Array(values) = value else {
            panic!("array fixture")
        };
        &mut values[index]
    }

    let valid = document(vec![measurement(1, false)]);
    let mut extension_only = valid.clone();
    let mut comid: Value =
        cbor::decode(&cbor::encode(&valid.tags[0].as_comid().unwrap()).unwrap()).unwrap();
    let references = field(field(&mut comid, COMID_KEY_TRIPLES), TRIPLES_KEY_REFERENCE);
    let measurements = item(item(references, 0), 1);
    let Value::Map(mval) = field(item(measurements, 0), MEAS_KEY_MVAL) else {
        panic!("mval fixture");
    };
    mval.push((
        Value::Integer(i128::from(MVAL_KEY_FLAGS)),
        Value::Map(vec![(Value::Integer(10001), Value::Bool(true))]),
    ));
    extension_only.tags[0] = ConciseTagChoice::Comid(cbor::encode(&comid).unwrap());
    for (input, baseline) in [(&extension_only, &valid), (&valid, &extension_only)] {
        let error = compare(input, baseline).unwrap_err();
        assert!(
            matches!(error, corim::ValidationError::Invalid(ref detail) if detail.contains("non-empty constraint") && detail.contains("FlagsMap"))
        );
    }
}
