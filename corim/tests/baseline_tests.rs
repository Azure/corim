// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Tests for `corim::baseline` structural conformance comparison.

// These fixtures also compile when the public models are non-exhaustive.
#![allow(clippy::field_reassign_with_default)]

use corim::baseline::{compare as try_compare, MismatchKind};
use corim::builder::{ComidBuilder, CorimBuilder};
use corim::cbor::{self, value::Tagged, value::Value};
use corim::types::common::{MeasuredElement, TagIdChoice};
use corim::types::corim::{ConciseTagChoice, CorimId, CorimMap};
use corim::types::environment::{ClassMap, EnvironmentMap};
use corim::types::measurement::{Digest, MeasurementMap, MeasurementValuesMap, SvnChoice};
use corim::types::tags::{TAG_COMID, TAG_CORIM};
use corim::types::triples::ReferenceTriple;

fn compare(input: &CorimMap, baseline: &CorimMap) -> corim::baseline::ConformanceReport {
    try_compare(input, baseline).unwrap()
}

/// Build a one-CoMID, one-reference-triple CoRIM with a single MRTD
/// measurement carrying the given digest bytes and svn.
fn corim_with(digest: Vec<u8>, svn: SvnChoice, mkey: &str) -> CorimMap {
    let env = EnvironmentMap {
        class: Some(ClassMap {
            class_id: None,
            vendor: Some("Intel".into()),
            model: Some("TDX".into()),
            layer: None,
            index: None,
        }),
        instance: None,
        group: None,
    };
    let meas = MeasurementMap {
        mkey: Some(MeasuredElement::Text(mkey.into())),
        mval: {
            let __corim_field_0 = Some(vec![Digest::new(7, digest)]);

            let __corim_field_1 = Some(svn);
            let mut __corim_value: MeasurementValuesMap = MeasurementValuesMap::default();
            __corim_value.digests = __corim_field_0;
            __corim_value.svn = __corim_field_1;
            __corim_value
        },
        authorized_by: None,
    };
    let comid = ComidBuilder::new(TagIdChoice::Text("c1".into()))
        .add_reference_triple(ReferenceTriple::new(env, vec![meas]))
        .build()
        .unwrap();
    let bytes = CorimBuilder::new(CorimId::Text("corim-1".into()))
        .add_comid_tag(comid)
        .unwrap()
        .build_bytes()
        .unwrap();
    corim::validate::decode_and_validate(&bytes).unwrap().0
}

/// Decode a TCG wire form: bare bstr containing either a map or #6.506(map).
fn tcg_corim(corim: &CorimMap, tagged_inner: bool) -> CorimMap {
    let mut corim = corim.clone();
    for tag in &mut corim.tags {
        if let ConciseTagChoice::Comid(bytes) = tag {
            let inner = if tagged_inner {
                let map: Value = cbor::decode(bytes).unwrap();
                cbor::encode(&Value::Tag(TAG_COMID, Box::new(map))).unwrap()
            } else {
                bytes.clone()
            };
            *tag = cbor::decode(&cbor::encode(&Value::Bytes(inner)).unwrap()).unwrap();
        }
    }
    let bytes = cbor::encode(&Tagged {
        tag: TAG_CORIM,
        value: corim,
    })
    .unwrap();
    let validated = corim::validate::decode_and_validate_full_at(&bytes, 0).unwrap();
    assert_eq!(validated.comids.len(), 1);
    validated.corim
}

fn check_large_typed_list(scope: &str) {
    let mut baseline = corim_with(vec![1], SvnChoice::MinValue(1), "MRTD");
    let mut comid = baseline.tags[0].as_comid().unwrap();
    let measurements = &mut comid.triples.reference_triples.as_mut().unwrap()[0].1;
    if scope == "digests" {
        measurements[0].mval.digests = Some(vec![Digest::new(7, vec![1]); 100_000]);
    } else {
        let measurement = MeasurementMap {
            mkey: if scope == "unkeyed" {
                None
            } else {
                Some(MeasuredElement::Text("same".into()))
            },
            mval: {
                let __corim_field_0 = Some(false);
                let mut __corim_value: MeasurementValuesMap = Default::default();
                __corim_value.r#bool = __corim_field_0;
                __corim_value
            },
            authorized_by: None,
        };
        *measurements = vec![measurement; if scope == "unkeyed" { 100_000 } else { 10_000 }];
    }
    baseline.tags[0] = ConciseTagChoice::Comid(cbor::encode(&comid).unwrap());
    if scope == "changed-keyed" {
        for measurement in &mut comid.triples.reference_triples.as_mut().unwrap()[0].1 {
            measurement.mval.r#bool = Some(true);
        }
    }
    let mut input = baseline.clone();
    input.tags[0] = ConciseTagChoice::Comid(cbor::encode(&comid).unwrap());
    let report = try_compare(&input, &baseline).unwrap();
    assert!(report.is_conformant(), "{scope}");
    assert_eq!(
        report.value_differences.len(),
        if scope == "changed-keyed" { 10_000 } else { 0 },
        "{scope}"
    );
}

#[test]
fn nested_map_keys_in_measurement_extensions_compare_without_reencoding_explosion() {
    use corim::cbor::constants;
    let mut document = corim_with(vec![1], SvnChoice::MinValue(1), "MRTD");
    let mut comid = document.tags[0].as_comid().unwrap();
    comid.triples.reference_triples.as_mut().unwrap()[0].1[0].mval = {
        let __corim_field_0 = [(10001, Value::Null)].into();
        let mut __corim_value: MeasurementValuesMap = Default::default();
        __corim_value.extra_entries = __corim_field_0;
        __corim_value
    };
    let mut bytes = cbor::encode(&comid).unwrap();
    assert_eq!(bytes.pop(), Some(constants::BYTE_NULL));
    bytes.extend(vec![(constants::MAJOR_MAP << 5) | 1; 40]);
    bytes.extend(vec![constants::BYTE_NULL; 41]);
    document.tags[0] = ConciseTagChoice::Comid(bytes.clone());
    let report = compare(&document, &document);
    assert!(report.is_conformant());
    assert!(report.value_differences.is_empty());
    assert_eq!(bytes.pop(), Some(constants::BYTE_NULL));
    bytes.push(constants::BYTE_TRUE);
    let mut changed = document.clone();
    changed.tags[0] = ConciseTagChoice::Comid(bytes);
    assert!(!compare(&changed, &document).is_conformant());
}

#[test]
fn large_changed_keyed_measurements_complete() {
    check_large_typed_list("changed-keyed");
}

#[test]
fn large_unkeyed_measurements_complete() {
    check_large_typed_list("unkeyed");
}

#[test]
fn large_repeated_digests_complete() {
    check_large_typed_list("digests");
}

#[test]
fn indexed_parent_keys_preserve_nested_unordered_semantics() {
    use corim::types::common::CryptoKey;
    use corim::types::matcher::TextMatcher;
    use corim::types::measurement::{IntegrityRegisterId, IntegrityRegisters};
    use corim::types::triples::{
        CesCommonCondition, ConditionalEndorsementSeriesTriple, ConditionalEndorsementTriple,
        ConditionalSeriesRecord, EndorsedTriple, StatefulEnvironmentRecord,
    };
    let template = corim_with(vec![1], SvnChoice::MinValue(1), "same");
    let original = template.tags[0].as_comid().unwrap();
    let group = |marker, reverse| {
        let mut triple = original.triples.reference_triples.as_ref().unwrap()[0].clone();
        let mut digests = vec![Digest::new(7, vec![marker]), Digest::new(8, vec![marker])];
        let mut keys = vec![
            CryptoKey::Bytes(vec![marker]),
            CryptoKey::KeyThumbprint(Digest::new(7, vec![marker])),
        ];
        let mut set = vec![format!("a{marker}"), format!("b{marker}")];
        if reverse {
            digests.reverse();
            keys.reverse();
            set.reverse();
        }
        let values = &mut triple.1[0].mval;
        values.digests = Some(digests.clone());
        values.cryptokeys = Some(keys);
        values.integrity_registers = Some(IntegrityRegisters(
            [(IntegrityRegisterId::Uint(0), digests)].into(),
        ));
        values.text = Some(TextMatcher::Set(set));
        triple
    };
    for scope in [
        "comids",
        "reference",
        "endorsed",
        "series",
        "series-order",
        "conditional",
    ] {
        let make = |reverse| {
            let mut groups = vec![group(1, reverse), group(2, reverse)];
            if reverse {
                groups.reverse();
            }
            let mut document = template.clone();
            let mut comid = original.clone();
            comid.triples.reference_triples = None;
            match scope {
                "comids" => {
                    document.tags = groups
                        .into_iter()
                        .map(|group| {
                            let mut comid = comid.clone();
                            comid.triples.reference_triples = Some(vec![group]);
                            ConciseTagChoice::Comid(cbor::encode(&comid).unwrap())
                        })
                        .collect();
                    return document;
                }
                "reference" => comid.triples.reference_triples = Some(groups),
                "endorsed" => {
                    comid.triples.endorsed_triples = Some(
                        groups
                            .into_iter()
                            .map(|group| EndorsedTriple(group.0, group.1))
                            .collect(),
                    )
                }
                "series" => {
                    comid.triples.conditional_endorsement_series = Some(
                        groups
                            .into_iter()
                            .map(|group| {
                                ConditionalEndorsementSeriesTriple::new(
                                    CesCommonCondition {
                                        environment: group.0,
                                        claims_list: group.1.clone(),
                                        authorized_by: None,
                                    },
                                    vec![ConditionalSeriesRecord::new(group.1.clone(), group.1)],
                                )
                            })
                            .collect(),
                    )
                }
                "series-order" => {
                    comid.triples.conditional_endorsement_series = Some(
                        groups
                            .iter()
                            .enumerate()
                            .map(|(index, group)| {
                                ConditionalEndorsementSeriesTriple::new(
                                    CesCommonCondition {
                                        environment: group.0.clone(),
                                        claims_list: vec![],
                                        authorized_by: None,
                                    },
                                    groups
                                        .iter()
                                        .cycle()
                                        .skip(index)
                                        .take(groups.len())
                                        .map(|record| {
                                            ConditionalSeriesRecord::new(
                                                record.1.clone(),
                                                record.1.clone(),
                                            )
                                        })
                                        .collect(),
                                )
                            })
                            .collect(),
                    )
                }
                "conditional" => {
                    comid.triples.conditional_endorsement =
                        Some(vec![ConditionalEndorsementTriple(
                            groups
                                .iter()
                                .map(|group| {
                                    StatefulEnvironmentRecord(group.0.clone(), group.1.clone())
                                })
                                .collect(),
                            groups
                                .into_iter()
                                .map(|group| EndorsedTriple(group.0, group.1))
                                .collect(),
                        )])
                }
                _ => panic!("scope"),
            }
            document.tags[0] = ConciseTagChoice::Comid(cbor::encode(&comid).unwrap());
            document
        };
        let report = compare(&make(true), &make(false));
        assert!(report.is_conformant(), "{scope}: {report:?}");
        assert!(report.value_differences.is_empty(), "{scope}: {report:?}");
    }
}

#[test]
fn indexed_keyed_measurements_do_not_move_unkeyed_positions() {
    let mut baseline = corim_with(vec![1], SvnChoice::MinValue(1), "first");
    let mut comid = baseline.tags[0].as_comid().unwrap();
    let measurements = &mut comid.triples.reference_triples.as_mut().unwrap()[0].1;
    let mut unkeyed = measurements[0].clone();
    unkeyed.mkey = None;
    let mut last = measurements[0].clone();
    last.mkey = Some(MeasuredElement::Text("last".into()));
    measurements.extend([unkeyed, last]);
    baseline.tags[0] = ConciseTagChoice::Comid(cbor::encode(&comid).unwrap());
    comid.triples.reference_triples.as_mut().unwrap()[0]
        .1
        .swap(0, 2);
    let mut input = baseline.clone();
    input.tags[0] = ConciseTagChoice::Comid(cbor::encode(&comid).unwrap());
    assert_eq!(compare(&input, &baseline), compare(&baseline, &baseline));
    comid.triples.reference_triples.as_mut().unwrap()[0]
        .1
        .swap(0, 1);
    input.tags[0] = ConciseTagChoice::Comid(cbor::encode(&comid).unwrap());
    assert!(!compare(&input, &baseline).is_conformant());
}

#[test]
fn uuid_tag_identity_is_not_a_position_or_display_string() {
    let mut baseline = corim_with(vec![0xAA; 48], SvnChoice::MinValue(1), "MRTD");
    let mut first = baseline.tags[0].as_comid().unwrap();
    first.tag_identity.tag_id = TagIdChoice::Uuid([1; 16]);
    let mut second = first.clone();
    second.tag_identity.tag_id = TagIdChoice::Uuid([2; 16]);
    second.tag_identity.tag_version = Some(2);
    baseline.tags = vec![
        ConciseTagChoice::Comid(cbor::encode(&first).unwrap()),
        ConciseTagChoice::Comid(cbor::encode(&second).unwrap()),
    ];
    let mut reordered = baseline.clone();
    reordered.tags.reverse();
    assert_eq!(
        try_compare(&reordered, &baseline).unwrap(),
        try_compare(&baseline, &baseline).unwrap()
    );
    for id in [TagIdChoice::Uuid([3; 16]), TagIdChoice::Text("#0".into())] {
        let mut changed = baseline.clone();
        first.tag_identity.tag_id = id;
        changed.tags[0] = ConciseTagChoice::Comid(cbor::encode(&first).unwrap());
        assert!(!try_compare(&changed, &baseline).unwrap().is_conformant());
    }
}

#[test]
fn duplicate_tag_ids_pair_exact_values_before_residual_changes() {
    let mut baseline = corim_with(vec![0xAA; 48], SvnChoice::MinValue(1), "MRTD");
    let mut second = baseline.tags[0].as_comid().unwrap();
    second.tag_identity.tag_version = Some(2);
    baseline
        .tags
        .push(ConciseTagChoice::Comid(cbor::encode(&second).unwrap()));
    let mut reordered = baseline.clone();
    reordered.tags.reverse();
    assert_eq!(
        compare(&reordered, &baseline),
        compare(&baseline, &baseline)
    );
    second.tag_identity.tag_version = Some(3);
    reordered.tags[0] = ConciseTagChoice::Comid(cbor::encode(&second).unwrap());
    let report = compare(&reordered, &baseline);
    assert!(report.is_conformant());
    assert_eq!(report.value_differences.len(), 1);
}

#[test]
fn nested_unordered_content_reserves_the_correct_duplicate_identity() {
    let mut baseline = corim_with(vec![0xAA; 48], SvnChoice::MinValue(1), "MRTD");
    let mut comid = baseline.tags[0].as_comid().unwrap();
    let measurements = &mut comid.triples.reference_triples.as_mut().unwrap()[0].1;
    let mut second = measurements[0].clone();
    measurements[0].mval.digests = Some(vec![Digest::new(7, vec![1]), Digest::new(8, vec![2])]);
    second.mval.digests = Some(vec![Digest::new(9, vec![3]), Digest::new(10, vec![4])]);
    measurements.push(second);
    baseline.tags[0] = ConciseTagChoice::Comid(cbor::encode(&comid).unwrap());
    let measurements = &mut comid.triples.reference_triples.as_mut().unwrap()[0].1;
    measurements.reverse();
    for measurement in measurements {
        measurement.mval.digests.as_mut().unwrap().reverse();
    }
    let mut reordered = baseline.clone();
    reordered.tags[0] = ConciseTagChoice::Comid(cbor::encode(&comid).unwrap());
    let report = compare(&reordered, &baseline);
    assert!(report.is_conformant(), "{report:?}");
    assert!(report.value_differences.is_empty(), "{report:?}");
}

#[test]
fn repeated_identities_preserve_cardinality() {
    let baseline = corim_with(vec![0xAA; 48], SvnChoice::MinValue(1), "MRTD");
    for scope in ["tags", "triples", "measurements", "digests"] {
        let mut input = baseline.clone();
        if scope == "tags" {
            input.tags.push(input.tags[0].clone());
        } else {
            let mut comid = input.tags[0].as_comid().unwrap();
            let triples = comid.triples.reference_triples.as_mut().unwrap();
            match scope {
                "triples" => triples.push(triples[0].clone()),
                "measurements" => {
                    let duplicate = triples[0].1[0].clone();
                    triples[0].1.push(duplicate);
                }
                "digests" => {
                    let digests = triples[0].1[0].mval.digests.as_mut().unwrap();
                    digests.push(digests[0].clone());
                }
                _ => panic!("scope"),
            }
            input.tags[0] = ConciseTagChoice::Comid(cbor::encode(&comid).unwrap());
        }
        assert!(
            !try_compare(&input, &baseline).unwrap().is_conformant(),
            "{scope}"
        );
        assert!(
            !try_compare(&baseline, &input).unwrap().is_conformant(),
            "{scope}"
        );
    }
}

#[test]
fn extension_comparison_is_recursive_shape_not_whole_value() {
    let make = |value: Value| {
        let mut document = corim_with(vec![0xAA; 48], SvnChoice::MinValue(1), "MRTD");
        let mut comid = document.tags[0].as_comid().unwrap();
        comid.triples.reference_triples.as_mut().unwrap()[0].1[0]
            .mval
            .extra_entries
            .insert(-9999, value);
        document.tags[0] = ConciseTagChoice::Comid(cbor::encode(&comid).unwrap());
        document
    };
    let nested = |value| {
        Value::Map(vec![(
            Value::Text("nested".into()),
            Value::Array(vec![value]),
        )])
    };
    for (baseline, input, conforms) in [
        (nested(Value::Integer(1)), nested(Value::Integer(2)), true),
        (
            nested(Value::Integer(1)),
            nested(Value::Text("1".into())),
            false,
        ),
        (Value::Array(vec![Value::Null]), Value::Array(vec![]), false),
        (
            Value::Map(vec![]),
            Value::Map(vec![(Value::Text("new".into()), Value::Null)]),
            false,
        ),
        (
            Value::Tag(TAG_CORIM, Box::new(Value::Integer(1))),
            Value::Tag(TAG_COMID, Box::new(Value::Integer(1))),
            false,
        ),
    ] {
        assert_eq!(
            try_compare(&make(input), &make(baseline))
                .unwrap()
                .is_conformant(),
            conforms
        );
    }
    let entries = vec![
        (Value::Text("a".into()), Value::Integer(1)),
        (Value::Text("b".into()), Value::Integer(2)),
    ];
    let mut reversed = entries.clone();
    reversed.reverse();
    let report = try_compare(&make(Value::Map(entries)), &make(Value::Map(reversed))).unwrap();
    assert!(report.is_conformant());
    assert!(report.value_differences.is_empty());
}

#[test]
fn typed_field_shapes_are_structural_but_contents_are_values() {
    use corim::types::common::CryptoKey;
    use corim::types::measurement::{IntRangeChoice, IntegrityRegisterId, IntegrityRegisters};
    let make = |mval| {
        let mut document = corim_with(vec![0xAA; 48], SvnChoice::MinValue(1), "MRTD");
        let mut comid = document.tags[0].as_comid().unwrap();
        comid.triples.reference_triples.as_mut().unwrap()[0].1[0].mval = mval;
        document.tags[0] = ConciseTagChoice::Comid(cbor::encode(&comid).unwrap());
        document
    };
    let registers = |id, algorithm, byte| {
        let __corim_field_0 = Some(IntegrityRegisters(
            [(
                IntegrityRegisterId::Uint(id),
                vec![Digest::new(algorithm, vec![byte; 48])],
            )]
            .into(),
        ));
        let mut __corim_value: MeasurementValuesMap = Default::default();
        __corim_value.integrity_registers = __corim_field_0;
        __corim_value
    };
    let keys = |key| {
        let __corim_field_0 = Some(vec![key]);
        let mut __corim_value: MeasurementValuesMap = Default::default();
        __corim_value.cryptokeys = __corim_field_0;
        __corim_value
    };
    let range = |value| {
        let __corim_field_0 = Some(value);
        let mut __corim_value: MeasurementValuesMap = Default::default();
        __corim_value.int_range = __corim_field_0;
        __corim_value
    };
    for (baseline, input, conforms) in [
        (registers(0, 7, 1), registers(1, 7, 1), false),
        (registers(0, 7, 1), registers(0, 8, 1), false),
        (registers(0, 7, 1), registers(0, 7, 2), true),
        (
            keys(CryptoKey::Bytes(vec![1])),
            keys(CryptoKey::CoseKey(vec![1])),
            false,
        ),
        (
            keys(CryptoKey::KeyThumbprint(Digest::new(7, vec![1]))),
            keys(CryptoKey::KeyThumbprint(Digest::new(8, vec![1]))),
            false,
        ),
        (
            keys(CryptoKey::Bytes(vec![1])),
            keys(CryptoKey::Bytes(vec![2])),
            true,
        ),
        (
            range(IntRangeChoice::Int(1)),
            range(IntRangeChoice::Int(2)),
            true,
        ),
        (
            range(IntRangeChoice::Int(1)),
            range(IntRangeChoice::Range {
                min: Some(0),
                max: Some(2),
            }),
            false,
        ),
        (
            range(IntRangeChoice::Range {
                min: None,
                max: Some(2),
            }),
            range(IntRangeChoice::Range {
                min: Some(0),
                max: Some(2),
            }),
            false,
        ),
    ] {
        let report = try_compare(&make(input), &make(baseline)).unwrap();
        assert_eq!(report.is_conformant(), conforms, "{report:?}");
        if conforms {
            assert!(!report.value_differences.is_empty());
        }
    }
}

#[test]
fn checked_comparison_rejects_skipped_tags_on_either_side() {
    let valid = corim_with(vec![0xAA; 48], SvnChoice::MinValue(1), "MRTD");
    for tag in [
        ConciseTagChoice::Comid(vec![0xff]),
        ConciseTagChoice::BareBstr(vec![0xff]),
        ConciseTagChoice::Coswid(vec![]),
        ConciseTagChoice::Cotl(vec![]),
        ConciseTagChoice::Unknown(TAG_CORIM, vec![]),
    ] {
        for mixed in [false, true] {
            let mut invalid = valid.clone();
            if !mixed {
                invalid.tags.clear();
            }
            invalid.tags.push(tag.clone());
            assert!(try_compare(&invalid, &valid).is_err(), "input: {tag:?}");
            assert!(try_compare(&valid, &invalid).is_err(), "baseline: {tag:?}");
            assert!(try_compare(&invalid, &invalid).is_err(), "both: {tag:?}");
        }
    }
}

#[test]
fn checked_comparison_validates_structure_without_reading_clock() {
    let valid = corim_with(vec![0xAA; 48], SvnChoice::MinValue(1), "MRTD");
    let mut empty = valid.clone();
    empty.tags.clear();
    assert!(try_compare(&empty, &valid).is_err());
    assert!(try_compare(&valid, &empty).is_err());
    let mut invalid = valid.clone();
    invalid.entities = Some(vec![]);
    assert!(try_compare(&invalid, &valid).is_err());
    assert!(try_compare(&valid, &invalid).is_err());
    let mut expired = valid.clone();
    expired.rim_validity = Some(corim::types::ValidityMap {
        not_before: None,
        not_after: 1.into(),
    });
    assert!(try_compare(&expired, &expired).unwrap().is_conformant());
    expired.rim_validity.as_mut().unwrap().not_before = Some(2.into());
    assert!(try_compare(&expired, &valid).is_err());
    assert!(try_compare(&valid, &expired).is_err());
}

#[test]
fn checked_comparison_preserves_decode_errors_and_limits() {
    use corim::{DecodeError, ValidationError};
    let valid = corim_with(vec![0xAA; 48], SvnChoice::MinValue(1), "MRTD");
    let ConciseTagChoice::Comid(bytes) = &valid.tags[0] else {
        panic!("CoMID fixture");
    };
    let mut trailing_bytes = bytes.clone();
    trailing_bytes.push(0xff);
    let Value::Map(mut entries) = cbor::decode_exact(bytes).unwrap() else {
        panic!("CoMID map");
    };
    entries.push(entries[0].clone());
    let duplicate_bytes = cbor::encode(&Value::Map(entries)).unwrap();
    for (bytes, duplicate) in [(trailing_bytes, false), (duplicate_bytes, true)] {
        let mut invalid = valid.clone();
        invalid.tags[0] = ConciseTagChoice::Comid(bytes);
        for (input, baseline) in [(&invalid, &valid), (&valid, &invalid)] {
            let error = try_compare(input, baseline).unwrap_err();
            if duplicate {
                assert!(matches!(
                    error,
                    ValidationError::Decode(DecodeError::DuplicateKey { .. })
                ));
            } else {
                assert!(matches!(
                    error,
                    ValidationError::Decode(DecodeError::TrailingData { .. })
                ));
            }
        }
    }
    let mut oversized = valid.clone();
    oversized.tags[0] =
        ConciseTagChoice::Comid(vec![0; cbor::DecodeLimits::default().max_input_bytes]);
    for (input, baseline) in [(&oversized, &valid), (&valid, &oversized)] {
        assert!(matches!(
            try_compare(input, baseline),
            Err(ValidationError::Decode(DecodeError::LimitExceeded { .. }))
        ));
    }
}

#[test]
fn tcg_comparison_matches_canonical_difference_reports() {
    let baseline = corim_with(vec![0xAA; 48], SvnChoice::MinValue(1), "MRTD");
    for input in [
        baseline.clone(),
        corim_with(vec![0xBB; 48], SvnChoice::MinValue(2), "MRTD"),
        corim_with(vec![0xAA; 48], SvnChoice::ExactValue(1), "MRTD"),
    ] {
        let expected = compare(&input, &baseline);
        assert_eq!(try_compare(&input, &baseline).unwrap(), expected);
        for tagged_inner in [false, true] {
            assert_eq!(
                try_compare(&tcg_corim(&input, tagged_inner), &baseline).unwrap(),
                expected
            );
            assert_eq!(
                try_compare(&input, &tcg_corim(&baseline, tagged_inner)).unwrap(),
                expected
            );
        }
    }
}

#[test]
fn tcg_and_canonical_comids_compare_identically() {
    let canonical = corim_with(vec![0xAA; 48], SvnChoice::MinValue(1), "MRTD");
    let expected = compare(&canonical, &canonical);
    for tagged_inner in [false, true] {
        let tcg = tcg_corim(&canonical, tagged_inner);
        assert_eq!(compare(&tcg, &canonical), expected);
        assert_eq!(compare(&canonical, &tcg), expected);
    }
}

#[test]
fn tcg_comid_digest_changes_are_reported() {
    let base = corim_with(vec![0xAA; 48], SvnChoice::MinValue(1), "MRTD");
    let input = corim_with(vec![0xBB; 48], SvnChoice::MinValue(1), "MRTD");
    let expected = compare(&input, &base);
    assert_eq!(expected.value_differences.len(), 1);
    for baseline_tagged in [false, true] {
        for input_tagged in [false, true] {
            assert_eq!(
                compare(
                    &tcg_corim(&input, input_tagged),
                    &tcg_corim(&base, baseline_tagged)
                ),
                expected
            );
        }
    }
}

#[test]
fn tcg_comid_svn_type_changes_are_structural() {
    let base = corim_with(vec![0xAA; 48], SvnChoice::MinValue(1), "MRTD");
    let input = corim_with(vec![0xAA; 48], SvnChoice::ExactValue(1), "MRTD");
    let expected = compare(&input, &base);
    assert!(!expected.is_conformant());
    for tagged_inner in [false, true] {
        assert_eq!(
            compare(
                &tcg_corim(&input, tagged_inner),
                &tcg_corim(&base, tagged_inner)
            ),
            expected
        );
    }
}

#[test]
fn identical_corims_conform_with_no_differences() {
    let base = corim_with(vec![0xAA; 48], SvnChoice::MinValue(1), "MRTD");
    let input = corim_with(vec![0xAA; 48], SvnChoice::MinValue(1), "MRTD");
    let report = compare(&input, &base);
    assert!(report.is_conformant());
    assert!(report.structural_mismatches.is_empty());
    assert!(report.value_differences.is_empty());
}

#[test]
fn different_digest_bytes_is_a_value_difference_not_a_mismatch() {
    let base = corim_with(vec![0xAA; 48], SvnChoice::MinValue(1), "MRTD");
    let input = corim_with(vec![0xBB; 48], SvnChoice::MinValue(1), "MRTD");
    let report = compare(&input, &base);
    assert!(report.is_conformant(), "digest bytes may differ");
    assert!(report.structural_mismatches.is_empty());
    assert_eq!(report.value_differences.len(), 1);
    assert_eq!(report.value_differences[0].field, "digest-value");
}

#[test]
fn different_svn_value_is_a_value_difference() {
    let base = corim_with(vec![0xAA; 48], SvnChoice::MinValue(1), "MRTD");
    let input = corim_with(vec![0xAA; 48], SvnChoice::MinValue(5), "MRTD");
    let report = compare(&input, &base);
    assert!(report.is_conformant());
    assert_eq!(report.value_differences.len(), 1);
    assert_eq!(report.value_differences[0].field, "svn");
}

#[test]
fn svn_type_change_is_a_structural_mismatch() {
    let base = corim_with(vec![0xAA; 48], SvnChoice::MinValue(1), "MRTD");
    let input = corim_with(vec![0xAA; 48], SvnChoice::ExactValue(1), "MRTD");
    let report = compare(&input, &base);
    assert!(!report.is_conformant(), "exact vs min svn is structural");
    assert_eq!(report.structural_mismatches.len(), 1);
    assert!(matches!(
        report.structural_mismatches[0].kind,
        MismatchKind::TypeMismatch { .. }
    ));
}

#[test]
fn missing_measurement_in_input_is_a_structural_mismatch() {
    // Baseline has a measurement keyed "MRTD"; input keys it "OTHER" →
    // baseline's MRTD is missing, input's OTHER is unexpected.
    let base = corim_with(vec![0xAA; 48], SvnChoice::MinValue(1), "MRTD");
    let input = corim_with(vec![0xAA; 48], SvnChoice::MinValue(1), "OTHER");
    let report = compare(&input, &base);
    assert!(!report.is_conformant());
    let kinds: Vec<_> = report
        .structural_mismatches
        .iter()
        .map(|m| &m.kind)
        .collect();
    assert!(kinds.contains(&&MismatchKind::MissingInInput));
    assert!(kinds.contains(&&MismatchKind::UnexpectedInInput));
}

#[test]
fn missing_svn_field_in_input_is_a_structural_mismatch() {
    let base = corim_with(vec![0xAA; 48], SvnChoice::MinValue(1), "MRTD");
    // Build an input without an svn field.
    let env = EnvironmentMap {
        class: Some(ClassMap {
            class_id: None,
            vendor: Some("Intel".into()),
            model: Some("TDX".into()),
            layer: None,
            index: None,
        }),
        instance: None,
        group: None,
    };
    let meas = MeasurementMap {
        mkey: Some(MeasuredElement::Text("MRTD".into())),
        mval: {
            let __corim_field_0 = Some(vec![Digest::new(7, vec![0xAA; 48])]);

            let mut __corim_value: MeasurementValuesMap = MeasurementValuesMap::default();
            __corim_value.digests = __corim_field_0;
            __corim_value
        },
        authorized_by: None,
    };
    let comid = ComidBuilder::new(TagIdChoice::Text("c1".into()))
        .add_reference_triple(ReferenceTriple::new(env, vec![meas]))
        .build()
        .unwrap();
    let bytes = CorimBuilder::new(CorimId::Text("corim-1".into()))
        .add_comid_tag(comid)
        .unwrap()
        .build_bytes()
        .unwrap();
    let input = corim::validate::decode_and_validate(&bytes).unwrap().0;

    let report = compare(&input, &base);
    assert!(
        !report.is_conformant(),
        "svn present in baseline, absent in input"
    );
    assert!(report
        .structural_mismatches
        .iter()
        .any(|m| m.kind == MismatchKind::MissingInInput));
}

/// A conditional-endorsement-series triple's series `addition` digest is
/// compared: differing bytes are a value difference (still conformant).
#[test]
fn ces_series_addition_digest_is_compared() {
    use corim::types::triples::{
        CesCommonCondition, ConditionalEndorsementSeriesTriple, ConditionalSeriesRecord,
    };

    fn ces_corim(addition_digest: Vec<u8>) -> CorimMap {
        let env = EnvironmentMap {
            class: Some(ClassMap {
                class_id: None,
                vendor: Some("Intel".into()),
                model: Some("TDX".into()),
                layer: None,
                index: None,
            }),
            instance: None,
            group: None,
        };
        let cond_meas = MeasurementMap {
            mkey: Some(MeasuredElement::Text("cond".into())),
            mval: {
                let __corim_field_0 = Some(SvnChoice::MinValue(1));
                let mut __corim_value: MeasurementValuesMap = MeasurementValuesMap::default();
                __corim_value.svn = __corim_field_0;
                __corim_value
            },
            authorized_by: None,
        };
        let add_meas = MeasurementMap {
            mkey: Some(MeasuredElement::Text("add".into())),
            mval: {
                let __corim_field_0 = Some(vec![Digest::new(7, addition_digest)]);
                let mut __corim_value: MeasurementValuesMap = MeasurementValuesMap::default();
                __corim_value.digests = __corim_field_0;
                __corim_value
            },
            authorized_by: None,
        };
        let ces = ConditionalEndorsementSeriesTriple::new(
            CesCommonCondition {
                environment: env,
                claims_list: vec![],
                authorized_by: None,
            },
            vec![ConditionalSeriesRecord::new(
                vec![cond_meas],
                vec![add_meas],
            )],
        );
        let comid = ComidBuilder::new(TagIdChoice::Text("c1".into()))
            .add_conditional_endorsement_series(ces)
            .build()
            .unwrap();
        let bytes = CorimBuilder::new(CorimId::Text("corim-1".into()))
            .add_comid_tag(comid)
            .unwrap()
            .build_bytes()
            .unwrap();
        corim::validate::decode_and_validate(&bytes).unwrap().0
    }

    let base = ces_corim(vec![0xAA; 48]);
    let same = ces_corim(vec![0xAA; 48]);
    let diff = ces_corim(vec![0xBB; 48]);

    assert!(compare(&same, &base).value_differences.is_empty());
    let report = compare(&diff, &base);
    assert!(report.is_conformant(), "CES digest bytes may differ");
    assert_eq!(
        report.value_differences.len(),
        1,
        "CES addition digest compared"
    );
    assert_eq!(report.value_differences[0].field, "digest-value");
}

/// `profile` is structural: a differing profile means the documents follow
/// different structures and must fail conformance, not pass as a value diff.
#[test]
fn profile_difference_is_a_structural_mismatch() {
    use corim::types::corim::ProfileChoice;

    fn corim_with_profile(profile: &str) -> CorimMap {
        let comid = ComidBuilder::new(TagIdChoice::Text("c1".into()))
            .add_reference_triple(ReferenceTriple::new(
                EnvironmentMap {
                    class: Some(ClassMap {
                        class_id: None,
                        vendor: Some("Intel".into()),
                        model: Some("TDX".into()),
                        layer: None,
                        index: None,
                    }),
                    instance: None,
                    group: None,
                },
                vec![MeasurementMap {
                    mkey: Some(MeasuredElement::Text("MRTD".into())),
                    mval: {
                        let __corim_field_0 = Some(SvnChoice::MinValue(1));
                        let mut __corim_value: MeasurementValuesMap =
                            MeasurementValuesMap::default();
                        __corim_value.svn = __corim_field_0;
                        __corim_value
                    },
                    authorized_by: None,
                }],
            ))
            .build()
            .unwrap();
        let bytes = CorimBuilder::new(CorimId::Text("corim-1".into()))
            .set_profile(ProfileChoice::Uri(profile.into()))
            .add_comid_tag(comid)
            .unwrap()
            .build_bytes()
            .unwrap();
        corim::validate::decode_and_validate(&bytes).unwrap().0
    }

    let base = corim_with_profile("https://example.com/profile/a");
    let input = corim_with_profile("https://example.com/profile/b");
    let report = compare(&input, &base);
    assert!(!report.is_conformant(), "differing profile is structural");
    assert!(report
        .structural_mismatches
        .iter()
        .any(|m| matches!(m.kind, MismatchKind::TypeMismatch { .. })));
    assert!(report.value_differences.is_empty());
}

/// Distinct `mval-extension` keys (incl. negative ones) must not collapse
/// onto the same rendered path.
#[test]
fn mval_extension_keys_render_distinctly() {
    use corim::baseline::render_path;
    use corim::cbor::value::Value;

    fn corim_with_ext(entries: &[(i64, Value)]) -> CorimMap {
        let mut extra = std::collections::BTreeMap::new();
        for (k, v) in entries {
            extra.insert(*k, v.clone());
        }
        let comid = ComidBuilder::new(TagIdChoice::Text("c1".into()))
            .add_reference_triple(ReferenceTriple::new(
                EnvironmentMap {
                    class: Some(ClassMap {
                        class_id: None,
                        vendor: Some("Intel".into()),
                        model: Some("TDX".into()),
                        layer: None,
                        index: None,
                    }),
                    instance: None,
                    group: None,
                },
                vec![MeasurementMap {
                    mkey: Some(MeasuredElement::Text("MRTD".into())),
                    mval: {
                        let __corim_field_0 = Some(SvnChoice::MinValue(1));

                        let __corim_field_1 = extra;
                        let mut __corim_value: MeasurementValuesMap =
                            MeasurementValuesMap::default();
                        __corim_value.svn = __corim_field_0;
                        __corim_value.extra_entries = __corim_field_1;
                        __corim_value
                    },
                    authorized_by: None,
                }],
            ))
            .build()
            .unwrap();
        let bytes = CorimBuilder::new(CorimId::Text("corim-1".into()))
            .add_comid_tag(comid)
            .unwrap()
            .build_bytes()
            .unwrap();
        corim::validate::decode_and_validate(&bytes).unwrap().0
    }

    // Baseline carries two distinct extension keys; input has neither.
    let base = corim_with_ext(&[(-1, Value::Integer(10)), (-2, Value::Integer(20))]);
    let input = corim_with_ext(&[]);
    let report = compare(&input, &base);

    let ext_paths: Vec<String> = report
        .structural_mismatches
        .iter()
        .filter(|m| m.kind == MismatchKind::MissingInInput)
        .map(|m| render_path(&m.path))
        .filter(|p| p.contains("mval-extension"))
        .collect();
    assert!(
        ext_paths.iter().any(|p| p.ends_with("[-1]")),
        "{ext_paths:?}"
    );
    assert!(
        ext_paths.iter().any(|p| p.ends_with("[-2]")),
        "{ext_paths:?}"
    );
    // The two keys must not collapse onto one path.
    assert_eq!(
        ext_paths.len(),
        2,
        "distinct keys, distinct paths: {ext_paths:?}"
    );
}

/// A measurement's `authorized-by` (authority keys) is structural: dropping,
/// adding, or changing it must fail conformance.
#[test]
fn measurement_authorized_by_difference_is_structural() {
    use corim::types::common::CryptoKey;

    fn corim_with_authority(authority: Option<CryptoKey>) -> CorimMap {
        let comid = ComidBuilder::new(TagIdChoice::Text("c1".into()))
            .add_reference_triple(ReferenceTriple::new(
                EnvironmentMap {
                    class: Some(ClassMap {
                        class_id: None,
                        vendor: Some("Intel".into()),
                        model: Some("TDX".into()),
                        layer: None,
                        index: None,
                    }),
                    instance: None,
                    group: None,
                },
                vec![MeasurementMap {
                    mkey: Some(MeasuredElement::Text("MRTD".into())),
                    mval: {
                        let __corim_field_0 = Some(SvnChoice::MinValue(1));
                        let mut __corim_value: MeasurementValuesMap =
                            MeasurementValuesMap::default();
                        __corim_value.svn = __corim_field_0;
                        __corim_value
                    },
                    authorized_by: authority.map(|k| vec![k]),
                }],
            ))
            .build()
            .unwrap();
        let bytes = CorimBuilder::new(CorimId::Text("corim-1".into()))
            .add_comid_tag(comid)
            .unwrap()
            .build_bytes()
            .unwrap();
        corim::validate::decode_and_validate(&bytes).unwrap().0
    }

    let base = corim_with_authority(Some(CryptoKey::PkixBase64Key("KEY-A".into())));

    // Same authority → conformant.
    let same = corim_with_authority(Some(CryptoKey::PkixBase64Key("KEY-A".into())));
    assert!(compare(&same, &base).is_conformant());

    // Changed authority → structural mismatch.
    let changed = corim_with_authority(Some(CryptoKey::PkixBase64Key("KEY-B".into())));
    let report = compare(&changed, &base);
    assert!(!report.is_conformant(), "changed authority is structural");
    assert!(report.structural_mismatches.iter().any(|m| m
        .path
        .contains(&corim::baseline::PathSegment::Field("authorized-by"))));

    // Dropped authority → structural mismatch.
    let dropped = corim_with_authority(None);
    assert!(
        !compare(&dropped, &base).is_conformant(),
        "dropped authority is structural"
    );
}

// ---------------------------------------------------------------------------
// CoRIM-level and CoMID-level metadata (value differences, not structural)
// ---------------------------------------------------------------------------

/// Build a CoRIM whose CoMID/CoRIM metadata can be varied independently of
/// the triples, so metadata-only deltas can be asserted.
fn corim_with_meta(
    tag_version: u64,
    not_after: i64,
    entity: Option<&str>,
    language: Option<&str>,
) -> CorimMap {
    use corim::types::common::EntityMap;

    let mut comid = ComidBuilder::new(TagIdChoice::Text("c1".into()))
        .set_tag_version(tag_version)
        .add_reference_triple(ReferenceTriple::new(
            EnvironmentMap {
                class: Some(ClassMap {
                    class_id: None,
                    vendor: Some("Intel".into()),
                    model: Some("TDX".into()),
                    layer: None,
                    index: None,
                }),
                instance: None,
                group: None,
            },
            vec![MeasurementMap {
                mkey: Some(MeasuredElement::Text("MRTD".into())),
                mval: {
                    let __corim_field_0 = Some(SvnChoice::MinValue(1));
                    let mut __corim_value: MeasurementValuesMap = MeasurementValuesMap::default();
                    __corim_value.svn = __corim_field_0;
                    __corim_value
                },
                authorized_by: None,
            }],
        ));
    if let Some(lang) = language {
        comid = comid.set_language(lang);
    }
    let comid = comid.build().unwrap();

    let mut builder = CorimBuilder::new(CorimId::Text("corim-1".into()))
        .add_comid_tag(comid)
        .unwrap()
        .set_validity(None, not_after)
        .unwrap();
    if let Some(name) = entity {
        builder = builder.add_entity(EntityMap {
            entity_name: name.into(),
            reg_id: None,
            role: vec![1],
        });
    }
    let bytes = builder.build_bytes().unwrap();
    corim::validate::decode_and_validate(&bytes).unwrap().0
}

#[test]
fn rim_validity_difference_is_a_value_difference() {
    let base = corim_with_meta(1, 1_900_000_000, None, None);
    let input = corim_with_meta(1, 1_950_000_000, None, None);
    let report = compare(&input, &base);
    assert!(report.is_conformant(), "validity may change on re-issue");
    assert!(
        report
            .value_differences
            .iter()
            .any(|v| v.field == "rim-validity"),
        "{:?}",
        report.value_differences
    );
}

#[test]
fn comid_tag_version_difference_is_a_value_difference() {
    let base = corim_with_meta(1, 1_900_000_000, None, None);
    let input = corim_with_meta(2, 1_900_000_000, None, None);
    let report = compare(&input, &base);
    assert!(
        report.is_conformant(),
        "tag-version bumps on every re-issue"
    );
    assert!(
        report
            .value_differences
            .iter()
            .any(|v| v.field == "tag-version"),
        "{:?}",
        report.value_differences
    );
}

#[test]
fn corim_entities_difference_is_a_value_difference() {
    let base = corim_with_meta(1, 1_900_000_000, Some("ACME"), None);
    let input = corim_with_meta(1, 1_900_000_000, Some("Globex"), None);
    let report = compare(&input, &base);
    assert!(report.is_conformant());
    assert!(
        report
            .value_differences
            .iter()
            .any(|v| v.field == "entities"),
        "{:?}",
        report.value_differences
    );
}

#[test]
fn comid_language_difference_is_a_value_difference() {
    let base = corim_with_meta(1, 1_900_000_000, None, Some("en-US"));
    let input = corim_with_meta(1, 1_900_000_000, None, Some("fr-FR"));
    let report = compare(&input, &base);
    assert!(report.is_conformant());
    assert!(
        report
            .value_differences
            .iter()
            .any(|v| v.field == "language"),
        "{:?}",
        report.value_differences
    );
}

#[test]
fn identical_metadata_reports_no_differences() {
    let base = corim_with_meta(3, 1_900_000_000, Some("ACME"), Some("en-US"));
    let input = corim_with_meta(3, 1_900_000_000, Some("ACME"), Some("en-US"));
    let report = compare(&input, &base);
    assert!(report.is_conformant());
    assert!(
        report.value_differences.is_empty(),
        "{:?}",
        report.value_differences
    );
}
