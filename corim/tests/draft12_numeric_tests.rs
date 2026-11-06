use corim::cbor::{self, value::Value};
use corim::types::tags::{MVAL_KEY_INTEGER, TAG_MATCHER_SET, TAG_NUMERIC_RANGE};
use corim::types::MeasurementValuesMap;
use corim::types::{
    BytesMatcher, CesCommonCondition, ConditionalEndorsementSeriesTriple,
    ConditionalEndorsementTriple, ConditionalSeriesRecord, EndorsedTriple, EnvironmentMap,
    FloatMatcher, IntegerMatcher, MeasurementMap, ReferenceTriple, StatefulEnvironmentRecord,
    TextMatcher,
};
use corim::Validate;

#[test]
fn key17_rejects_legacy_float_and_mixed_numeric_matchers() {
    for value in [
        Value::Float(1.0),
        Value::Tag(
            TAG_NUMERIC_RANGE,
            Box::new(Value::Array(vec![Value::Float(1.0), Value::Null])),
        ),
        Value::Tag(
            TAG_MATCHER_SET,
            Box::new(Value::Array(vec![Value::Integer(1), Value::Float(2.0)])),
        ),
    ] {
        let encoded = cbor::encode(&Value::Map(vec![(
            Value::Integer(i128::from(MVAL_KEY_INTEGER)),
            value,
        )]))
        .unwrap();
        assert!(cbor::decode_exact::<MeasurementValuesMap>(&encoded).is_err());
    }
}

#[test]
fn numeric_domains_are_strict_in_bare_set_and_range_forms() {
    let integer = Value::Integer(1);
    let float = Value::Float(1.0);
    for (key, wrong, valid) in [
        (MVAL_KEY_INTEGER, float.clone(), integer.clone()),
        (corim::types::tags::MVAL_KEY_FLOAT, integer, float),
    ] {
        for value in [
            wrong.clone(),
            Value::Tag(
                TAG_MATCHER_SET,
                Box::new(Value::Array(vec![valid, wrong.clone()])),
            ),
            Value::Tag(
                TAG_NUMERIC_RANGE,
                Box::new(Value::Array(vec![wrong, Value::Null])),
            ),
        ] {
            let bytes =
                cbor::encode(&Value::Map(vec![(Value::Integer(i128::from(key)), value)])).unwrap();
            assert!(cbor::decode_exact::<MeasurementValuesMap>(&bytes).is_err());
        }
    }
}

#[test]
fn invalid_numeric_values_fail_validation_encoding_and_decoding() {
    for matcher in [
        FloatMatcher::Exact(f64::NAN),
        FloatMatcher::Set(vec![1.0, f64::NAN]),
        FloatMatcher::Set(vec![1.0]),
        FloatMatcher::Range {
            min: None,
            max: None,
        },
        FloatMatcher::Range {
            min: Some(2.0),
            max: Some(1.0),
        },
        FloatMatcher::Range {
            min: Some(f64::NEG_INFINITY),
            max: None,
        },
        FloatMatcher::Range {
            min: None,
            max: Some(f64::INFINITY),
        },
        FloatMatcher::Range {
            min: Some(f64::NAN),
            max: None,
        },
    ] {
        assert!(matcher.valid().is_err());
        assert!(cbor::encode(&matcher).is_err());
    }
    for matcher in [
        IntegerMatcher::Exact(i128::MAX),
        IntegerMatcher::Exact(i128::MIN),
        IntegerMatcher::Set(vec![0, i128::from(u64::MAX) + 1]),
        IntegerMatcher::Range {
            min: Some(-2 - i128::from(u64::MAX)),
            max: None,
        },
        IntegerMatcher::Range {
            min: None,
            max: None,
        },
    ] {
        assert!(matcher.valid().is_err());
        assert!(cbor::encode(&matcher).is_err());
    }
    for value in [
        Value::Float(f64::NAN),
        Value::Tag(
            TAG_MATCHER_SET,
            Box::new(Value::Array(vec![
                Value::Float(1.0),
                Value::Float(f64::NAN),
            ])),
        ),
        Value::Tag(
            TAG_NUMERIC_RANGE,
            Box::new(Value::Array(vec![
                Value::Float(f64::NEG_INFINITY),
                Value::Null,
            ])),
        ),
        Value::Tag(
            TAG_NUMERIC_RANGE,
            Box::new(Value::Array(vec![Value::Null, Value::Float(f64::INFINITY)])),
        ),
        Value::Tag(
            TAG_NUMERIC_RANGE,
            Box::new(Value::Array(vec![Value::Null, Value::Null])),
        ),
        Value::Tag(
            TAG_NUMERIC_RANGE,
            Box::new(Value::Array(vec![Value::Float(2.0), Value::Float(1.0)])),
        ),
    ] {
        assert!(cbor::decode_exact::<FloatMatcher>(&cbor::encode(&value).unwrap()).is_err());
    }
    assert!(IntegerMatcher::Set(vec![1, 1]).valid().is_ok());
    assert!(FloatMatcher::Set(vec![f64::INFINITY, f64::INFINITY])
        .valid()
        .is_ok());
    assert!(FloatMatcher::Range {
        min: Some(-0.0),
        max: Some(0.0)
    }
    .valid()
    .is_ok());
}

fn measurement(values: MeasurementValuesMap) -> MeasurementMap {
    MeasurementMap {
        mkey: None,
        mval: values,
        authorized_by: None,
    }
}

fn assertion() -> MeasurementMap {
    let mut values = MeasurementValuesMap::default();
    values.integer = Some(IntegerMatcher::Exact(2));
    values.float = Some(FloatMatcher::Exact(2.0));
    measurement(values)
}

fn conditions() -> Vec<MeasurementMap> {
    let mut values = Vec::new();
    for integer in [
        IntegerMatcher::Set(vec![1, 2]),
        IntegerMatcher::Range {
            min: Some(1),
            max: Some(3),
        },
    ] {
        let mut map = MeasurementValuesMap::default();
        map.integer = Some(integer);
        values.push(measurement(map));
    }
    for float in [
        FloatMatcher::Set(vec![1.0, 2.0]),
        FloatMatcher::Range {
            min: Some(1.0),
            max: Some(3.0),
        },
    ] {
        let mut map = MeasurementValuesMap::default();
        map.float = Some(float);
        values.push(measurement(map));
    }
    let mut text = MeasurementValuesMap::default();
    text.text = Some(TextMatcher::Set(vec!["a".into(), "b".into()]));
    values.push(measurement(text));
    let mut bytes = MeasurementValuesMap::default();
    bytes.bytes = Some(BytesMatcher::Set(vec![vec![1], vec![2]]));
    values.push(measurement(bytes));
    values
}

#[test]
fn matchers_are_valid_only_in_condition_contexts() {
    let environment = EnvironmentMap::for_class("vendor", "model");
    for condition in conditions() {
        assert!(condition.valid().is_ok());
        assert!(
            ReferenceTriple(environment.clone(), vec![condition.clone()])
                .valid()
                .is_err()
        );
        assert!(EndorsedTriple(environment.clone(), vec![condition.clone()])
            .valid()
            .is_err());
        let ces = ConditionalEndorsementSeriesTriple(
            CesCommonCondition {
                environment: environment.clone(),
                claims_list: vec![condition.clone()],
                authorized_by: None,
            },
            vec![ConditionalSeriesRecord(
                vec![condition.clone()],
                vec![assertion()],
            )],
        );
        assert!(ces.valid().is_ok());
        let mut invalid = ces.clone();
        invalid.1[0].1 = vec![condition.clone()];
        assert!(invalid.valid().is_err());
        assert!(ConditionalEndorsementTriple(
            vec![StatefulEnvironmentRecord(
                environment.clone(),
                vec![condition.clone()]
            )],
            vec![EndorsedTriple(environment.clone(), vec![assertion()])],
        )
        .valid()
        .is_ok());

        let evidence = corim::validate::EvidenceClaim {
            environment: environment.clone(),
            measurements: vec![condition.clone()],
        };
        let reference = ReferenceTriple(environment.clone(), vec![assertion()]);
        assert!(corim::validate::match_reference_values(
            std::slice::from_ref(&reference),
            std::slice::from_ref(&evidence)
        )
        .is_empty());
        assert!(
            corim::validate::match_reference_values_with_profile::<dyn corim::profile::Profile>(
                &[reference],
                std::slice::from_ref(&evidence),
                None,
                &corim::profile::MatchContext::new(),
            )
            .is_err()
        );
        assert!(
            corim::validate::apply_endorsement_series(std::slice::from_ref(&ces), &[evidence])
                .is_err()
        );
        let evidence = corim::validate::EvidenceClaim {
            environment: environment.clone(),
            measurements: vec![assertion()],
        };
        let reference = ReferenceTriple(environment.clone(), vec![condition]);
        assert!(corim::validate::match_reference_values(
            &[reference],
            std::slice::from_ref(&evidence)
        )
        .is_empty());
        assert!(corim::validate::apply_endorsement_series(&[invalid], &[evidence]).is_err());
    }
}

#[test]
fn conditions_match_only_their_own_numeric_codepoint() {
    let mut integer = MeasurementValuesMap::default();
    integer.integer = Some(IntegerMatcher::Exact(2));
    let mut float = MeasurementValuesMap::default();
    float.float = Some(FloatMatcher::Exact(2.0));
    assert!(!corim::validate::core_fields_match(
        &measurement(integer.clone()),
        &measurement(float.clone())
    ));
    assert!(!corim::validate::core_fields_match(
        &measurement(float),
        &measurement(integer)
    ));
    let evidence = corim::validate::EvidenceClaim {
        environment: EnvironmentMap::for_class("vendor", "model"),
        measurements: vec![assertion()],
    };
    for condition in conditions().into_iter().take(4) {
        let ces = ConditionalEndorsementSeriesTriple(
            CesCommonCondition {
                environment: evidence.environment.clone(),
                claims_list: vec![],
                authorized_by: None,
            },
            vec![ConditionalSeriesRecord(vec![condition], vec![assertion()])],
        );
        let result =
            corim::validate::apply_endorsement_series(&[ces], std::slice::from_ref(&evidence))
                .unwrap();
        assert_eq!(result.len(), 1);
    }
}

#[test]
fn common_conditions_constrain_numeric_endorsement_matching() {
    let evidence = corim::validate::EvidenceClaim {
        environment: EnvironmentMap::for_class("vendor", "model"),
        measurements: vec![assertion()],
    };
    for matches in [false, true] {
        let mut common = MeasurementValuesMap::default();
        common.integer = Some(IntegerMatcher::Range {
            min: Some(if matches { 1 } else { 3 }),
            max: None,
        });
        let ces = ConditionalEndorsementSeriesTriple(
            CesCommonCondition {
                environment: evidence.environment.clone(),
                claims_list: vec![measurement(common)],
                authorized_by: None,
            },
            vec![ConditionalSeriesRecord(
                vec![assertion()],
                vec![assertion()],
            )],
        );
        assert_eq!(
            corim::validate::apply_endorsement_series(&[ces], std::slice::from_ref(&evidence))
                .unwrap()
                .len(),
            usize::from(matches),
        );
    }
}

#[cfg(feature = "json")]
#[test]
fn lossless_json_keeps_raw_values_but_checks_typed_numeric_domains() {
    use corim::types::tags::MVAL_KEY_FLOAT;
    for (key, value) in [
        (MVAL_KEY_INTEGER, Value::Float(1.0)),
        (MVAL_KEY_FLOAT, Value::Integer(1)),
        (MVAL_KEY_FLOAT, Value::Float(f64::NAN)),
    ] {
        let raw = Value::Map(vec![(Value::Integer(i128::from(key)), value)]);
        let json = corim::json::to_json(&raw).unwrap();
        assert!(corim::json::from_json::<MeasurementValuesMap>(&json).is_err());
        let decoded: Value = corim::json::from_json(&json).unwrap();
        assert_eq!(cbor::encode(&decoded).unwrap(), cbor::encode(&raw).unwrap());
    }
}

fn document_with_triples(triples: corim::types::TriplesMap) -> Vec<u8> {
    use corim::builder::{ComidBuilder, CorimBuilder};
    use corim::types::{CorimId, TagIdChoice};
    let mut comid = ComidBuilder::new(TagIdChoice::Text("numeric".into()))
        .add_reference_triple(ReferenceTriple(
            EnvironmentMap::for_class("vendor", "model"),
            vec![assertion()],
        ))
        .build()
        .unwrap();
    comid.triples = triples;
    CorimBuilder::new(CorimId::Text("numeric".into()))
        .add_comid_tag(comid)
        .unwrap()
        .build_bytes()
        .unwrap()
}

fn empty_triples() -> corim::types::TriplesMap {
    corim::types::TriplesMap {
        reference_triples: None,
        endorsed_triples: None,
        identity_triples: None,
        attest_key_triples: None,
        dependency_triples: None,
        membership_triples: None,
        coswid_triples: None,
        conditional_endorsement_series: None,
        conditional_endorsement: None,
    }
}

#[test]
fn embedded_validation_and_diagnostics_distinguish_numeric_assertions() {
    let environment = EnvironmentMap::for_class("vendor", "model");
    for condition in conditions().into_iter().take(4) {
        let mut triples = empty_triples();
        triples.reference_triples = Some(vec![ReferenceTriple(
            environment.clone(),
            vec![condition.clone()],
        )]);
        let bytes = document_with_triples(triples);
        assert!(corim::validate::decode_and_validate_full_at(&bytes, 0).is_err());
        let report = corim::diagnose::inspect(&bytes, &corim::profile::ProfileRegistry::new());
        assert!(report
            .issues()
            .iter()
            .any(|issue| issue.message().contains("only permitted in conditions")));

        let mut triples = empty_triples();
        triples.conditional_endorsement_series = Some(vec![ConditionalEndorsementSeriesTriple(
            CesCommonCondition {
                environment: environment.clone(),
                claims_list: vec![condition.clone()],
                authorized_by: None,
            },
            vec![ConditionalSeriesRecord(
                vec![condition.clone()],
                vec![assertion()],
            )],
        )]);
        let bytes = document_with_triples(triples.clone());
        assert!(corim::validate::decode_and_validate_full_at(&bytes, 0).is_ok());
        assert_eq!(
            corim::diagnose::inspect(&bytes, &corim::profile::ProfileRegistry::new()).error_count(),
            0
        );
        triples.conditional_endorsement_series.as_mut().unwrap()[0].1[0].1 = vec![condition];
        let bytes = document_with_triples(triples);
        assert!(corim::validate::decode_and_validate_full_at(&bytes, 0).is_err());
        assert!(
            corim::diagnose::inspect(&bytes, &corim::profile::ProfileRegistry::new()).error_count()
                > 0
        );
    }
}
