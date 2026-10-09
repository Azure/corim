use corim::cbor::{self, value::Value};
use corim::types::tags::{
    MVAL_KEY_BYTES, MVAL_KEY_NUMBER, MVAL_KEY_TEXT, TAG_MATCHER_SET, TAG_NUMBER_RANGE,
};
use corim::types::{BytesMatcher, MeasurementValuesMap, Number, NumberMatcher, TextMatcher};
use corim::Validate;

fn round_trip<T: serde::Serialize + serde::de::DeserializeOwned + PartialEq + core::fmt::Debug>(
    value: T,
) {
    assert_eq!(
        cbor::decode_exact::<T>(&cbor::encode(&value).unwrap()).unwrap(),
        value
    );
}

#[test]
fn matcher_wire_shapes_and_round_trips() {
    for number in [
        Number::Int(-1 - i128::from(u64::MAX)),
        Number::Int(i128::from(u64::MAX)),
        Number::Float(1.5),
        Number::Float(f64::INFINITY),
    ] {
        round_trip(NumberMatcher::Exact(number));
    }
    round_trip(NumberMatcher::Range {
        min: None,
        max: Some(Number::Int(5)),
    });
    round_trip(NumberMatcher::Set(vec![Number::Int(1), Number::Float(2.5)]));
    round_trip(TextMatcher::Exact("".into()));
    round_trip(TextMatcher::Set(vec!["a".into(), "b".into()]));
    round_trip(BytesMatcher::Exact(vec![]));
    round_trip(BytesMatcher::Set(vec![vec![0], vec![255]]));
    for map in [
        MeasurementValuesMap {
            number: Some(NumberMatcher::Exact(Number::Int(3))),
            ..Default::default()
        },
        MeasurementValuesMap {
            text: Some(TextMatcher::Exact("hi".into())),
            ..Default::default()
        },
        MeasurementValuesMap {
            bytes: Some(BytesMatcher::Exact(vec![1, 2])),
            ..Default::default()
        },
    ] {
        assert!(map.valid().is_ok());
        round_trip(map);
    }
    let range = NumberMatcher::Range {
        min: Some(Number::Int(1)),
        max: None,
    };
    assert_eq!(
        cbor::decode_exact::<Value>(&cbor::encode(&range).unwrap()).unwrap(),
        Value::Tag(
            TAG_NUMBER_RANGE,
            Box::new(Value::Array(vec![Value::Integer(1), Value::Null]))
        )
    );
    let bytes = BytesMatcher::Set(vec![vec![1], vec![2]]);
    assert_eq!(
        cbor::decode_exact::<Value>(&cbor::encode(&bytes).unwrap()).unwrap(),
        Value::Tag(
            TAG_MATCHER_SET,
            Box::new(Value::Array(vec![
                Value::Bytes(vec![1]),
                Value::Bytes(vec![2])
            ]))
        )
    );
}

#[test]
fn malformed_matchers_reject_decode_and_encode() {
    let malformed = [
        Value::Bool(true),
        Value::Null,
        Value::Array(vec![]),
        Value::Tag(TAG_NUMBER_RANGE + 10, Box::new(Value::Integer(1))),
        Value::Tag(TAG_MATCHER_SET, Box::new(Value::Null)),
        Value::Tag(TAG_MATCHER_SET, Box::new(Value::Array(vec![]))),
        Value::Tag(
            TAG_MATCHER_SET,
            Box::new(Value::Array(vec![Value::Integer(1)])),
        ),
        Value::Tag(
            TAG_MATCHER_SET,
            Box::new(Value::Array(vec![Value::Bool(false), Value::Bool(true)])),
        ),
    ];
    for value in malformed {
        let bytes = cbor::encode(&value).unwrap();
        assert!(cbor::decode_exact::<NumberMatcher>(&bytes).is_err());
        assert!(cbor::decode_exact::<TextMatcher>(&bytes).is_err());
        assert!(cbor::decode_exact::<BytesMatcher>(&bytes).is_err());
    }
    for inner in [
        Value::Null,
        Value::Array(vec![]),
        Value::Array(vec![Value::Null]),
        Value::Array(vec![Value::Integer(3), Value::Integer(2)]),
        Value::Array(vec![Value::Float(f64::NAN), Value::Null]),
        Value::Array(vec![Value::Text("bad".into()), Value::Null]),
    ] {
        assert!(cbor::decode_exact::<NumberMatcher>(
            &cbor::encode(&Value::Tag(TAG_NUMBER_RANGE, Box::new(inner))).unwrap()
        )
        .is_err());
    }
    for value in [
        NumberMatcher::Set(vec![]),
        NumberMatcher::Range {
            min: Some(Number::Int(2)),
            max: Some(Number::Int(1)),
        },
        NumberMatcher::Exact(Number::Int(i128::MAX)),
    ] {
        assert!(value.valid().is_err());
        assert!(cbor::encode(&value).is_err());
    }
    assert!(cbor::encode(&TextMatcher::Set(vec!["only".into()])).is_err());
    assert!(cbor::encode(&BytesMatcher::Set(vec![vec![]])).is_err());
    for key in [MVAL_KEY_NUMBER, MVAL_KEY_TEXT, MVAL_KEY_BYTES] {
        let mut map = MeasurementValuesMap::default();
        map.extra_entries.insert(key, Value::Integer(1));
        assert!(cbor::encode(&map).is_err());
    }
}

#[test]
fn numeric_matching_is_exact_across_integer_float_boundaries() {
    let exact = NumberMatcher::Exact;
    for (integer, float, equal) in [
        (1, 1.0, true),
        (0, -0.0, true),
        (-1, -1.0, true),
        (1, 1.5, false),
        (-1, -1.5, false),
        (9_007_199_254_740_993, 9_007_199_254_740_992.0, false),
        (i128::from(u64::MAX), 18_446_744_073_709_551_616.0, false),
        (
            -1 - i128::from(u64::MAX),
            -18_446_744_073_709_551_616.0,
            true,
        ),
    ] {
        assert_eq!(
            exact(Number::Int(integer)).matches(&exact(Number::Float(float))),
            equal
        );
        assert_eq!(
            exact(Number::Float(float)).matches(&exact(Number::Int(integer))),
            equal
        );
    }
    let range = NumberMatcher::Range {
        min: Some(Number::Int(9_007_199_254_740_993)),
        max: None,
    };
    assert!(!range.matches(&exact(Number::Float(9_007_199_254_740_992.0))));
    assert!(range.matches(&exact(Number::Int(9_007_199_254_740_993))));
    let unbounded = NumberMatcher::Range {
        min: None,
        max: None,
    };
    for value in [f64::NEG_INFINITY, f64::INFINITY] {
        assert!(unbounded.matches(&exact(Number::Float(value))));
    }
    assert!(!unbounded.matches(&exact(Number::Float(f64::NAN))));
    assert!(!exact(Number::Float(f64::NAN)).matches(&exact(Number::Float(f64::NAN))));
    let decoded: NumberMatcher =
        cbor::decode_exact(&cbor::encode(&exact(Number::Float(f64::NAN))).unwrap()).unwrap();
    assert!(matches!(decoded, NumberMatcher::Exact(Number::Float(value)) if value.is_nan()));
    assert!(!unbounded.matches(&unbounded));
    assert!(!unbounded.matches(&NumberMatcher::Set(vec![Number::Int(1), Number::Int(2)])));
}

#[test]
fn text_and_bytes_sets_match_only_exact_observations() {
    let text = TextMatcher::Set(vec!["a".into(), "b".into()]);
    assert!(text.matches(&TextMatcher::Exact("a".into())));
    assert!(!text.matches(&TextMatcher::Exact("A".into())));
    assert!(!text.matches(&text));
    let bytes = BytesMatcher::Set(vec![vec![0], vec![255]]);
    assert!(bytes.matches(&BytesMatcher::Exact(vec![255])));
    assert!(!bytes.matches(&BytesMatcher::Exact(vec![1])));
    assert!(!bytes.matches(&bytes));
}

#[test]
fn core_appraisal_enforces_matcher_fields() {
    use corim::types::MeasurementMap;
    let condition = MeasurementMap {
        mkey: None,
        authorized_by: None,
        mval: MeasurementValuesMap {
            number: Some(NumberMatcher::Range {
                min: Some(Number::Int(1)),
                max: Some(Number::Int(3)),
            }),
            text: Some(TextMatcher::Set(vec!["a".into(), "b".into()])),
            bytes: Some(BytesMatcher::Exact(vec![0, 255])),
            ..Default::default()
        },
    };
    let observed = MeasurementMap {
        mval: MeasurementValuesMap {
            number: Some(NumberMatcher::Exact(Number::Float(2.5))),
            text: Some(TextMatcher::Exact("b".into())),
            bytes: condition.mval.bytes.clone(),
            ..Default::default()
        },
        ..condition.clone()
    };
    assert!(corim::validate::core_fields_match(&condition, &observed));
    for missing in [MVAL_KEY_NUMBER, MVAL_KEY_TEXT, MVAL_KEY_BYTES] {
        let mut absent = observed.clone();
        match missing {
            MVAL_KEY_NUMBER => absent.mval.number = None,
            MVAL_KEY_TEXT => absent.mval.text = None,
            _ => absent.mval.bytes = None,
        }
        assert!(!corim::validate::core_fields_match(&condition, &absent));
    }
}

#[test]
fn boolean_measurement_is_exact_and_false_is_present() {
    use corim::types::{tags::MVAL_KEY_BOOL, MeasurementMap};
    for expected in [false, true] {
        let map = MeasurementValuesMap {
            r#bool: Some(expected),
            ..Default::default()
        };
        assert!(map.valid().is_ok());
        round_trip(map.clone());
        assert_eq!(
            cbor::decode_exact::<Value>(&cbor::encode(&map).unwrap()).unwrap(),
            Value::Map(vec![(
                Value::Integer(i128::from(MVAL_KEY_BOOL)),
                Value::Bool(expected)
            )])
        );
        let condition = MeasurementMap {
            mkey: None,
            authorized_by: None,
            mval: map,
        };
        for observed in [None, Some(false), Some(true)] {
            let observation = MeasurementMap {
                mval: MeasurementValuesMap {
                    r#bool: observed,
                    ..Default::default()
                },
                ..condition.clone()
            };
            assert_eq!(
                corim::validate::core_fields_match(&condition, &observation),
                observed == Some(expected)
            );
        }
    }
    for value in [
        Value::Integer(0),
        Value::Text("true".into()),
        Value::Tag(
            TAG_MATCHER_SET,
            Box::new(Value::Array(vec![Value::Bool(false), Value::Bool(true)])),
        ),
    ] {
        let bytes = cbor::encode(&Value::Map(vec![(
            Value::Integer(i128::from(MVAL_KEY_BOOL)),
            value,
        )]))
        .unwrap();
        assert!(cbor::decode_exact::<MeasurementValuesMap>(&bytes).is_err());
    }
}

#[cfg(feature = "json")]
#[test]
fn matcher_json_round_trip_preserves_types_and_nonfinite_numbers() {
    for number in [
        NumberMatcher::Exact(Number::Int(i128::from(u64::MAX))),
        NumberMatcher::Exact(Number::Int(-1 - i128::from(u64::MAX))),
        NumberMatcher::Exact(Number::Float(f64::INFINITY)),
        NumberMatcher::Exact(Number::Float(f64::from_bits(0x7ff8_0000_0000_1234))),
        NumberMatcher::Set(vec![Number::Int(1), Number::Float(f64::NEG_INFINITY)]),
        NumberMatcher::Range {
            min: None,
            max: Some(Number::Float(f64::INFINITY)),
        },
    ] {
        let original = MeasurementValuesMap {
            r#bool: Some(false),
            number: Some(number),
            text: Some(TextMatcher::Set(vec!["a".into(), "b".into()])),
            bytes: Some(BytesMatcher::Set(vec![vec![], vec![0, 255]])),
            ..Default::default()
        };
        let json = corim::json::to_json(&original).unwrap();
        let decoded: MeasurementValuesMap = corim::json::from_json(&json).unwrap();
        assert_eq!(
            cbor::encode(&decoded).unwrap(),
            cbor::encode(&original).unwrap(),
            "{json}"
        );
    }
    let bytes = BytesMatcher::Exact(vec![0, 255]);
    let json = corim::json::to_json(&bytes).unwrap();
    assert_eq!(
        corim::json::from_json::<BytesMatcher>(&json).unwrap(),
        bytes
    );
}

#[cfg(feature = "json")]
#[test]
fn invalid_matcher_json_does_not_disappear_as_null() {
    for json in [
        r#"{"16":true,"17":{"type":"integer","value":"invalid"}}"#,
        r#"{"16":true,"17":{"type":"float-bits","value":"invalid"}}"#,
        r#"{"16":true,"19":{"type":"byte-string","value":"zz"}}"#,
        r#"{"17":{"type":"number-range","value":[{"type":"integer","value":"invalid"},null]}}"#,
    ] {
        assert!(
            corim::json::from_json::<MeasurementValuesMap>(json).is_err(),
            "{json}"
        );
    }
}

fn corim_with_matchers(mval: MeasurementValuesMap) -> corim::types::CorimMap {
    let comid =
        corim::builder::ComidBuilder::new(corim::types::TagIdChoice::Text("matcher".into()))
            .add_reference_triple_for(
                corim::types::EnvironmentMap::for_class("V", "M"),
                vec![corim::types::MeasurementMap {
                    mkey: None,
                    authorized_by: None,
                    mval,
                }],
            )
            .build()
            .unwrap();
    corim::builder::CorimBuilder::new(corim::types::CorimId::Text("matcher".into()))
        .add_comid_tag(comid)
        .unwrap()
        .build()
        .unwrap()
}

#[test]
fn baseline_reports_matcher_presence_and_value_differences() {
    let base = MeasurementValuesMap {
        r#bool: Some(false),
        number: Some(NumberMatcher::Exact(Number::Float(f64::NAN))),
        text: Some(TextMatcher::Exact("a".into())),
        bytes: Some(BytesMatcher::Exact(vec![1])),
        ..Default::default()
    };
    let baseline = corim_with_matchers(base.clone());
    let identical = corim::baseline::compare(&baseline, &baseline);
    assert!(identical.structural_mismatches.is_empty());
    assert!(identical.value_differences.is_empty());
    let changed = corim_with_matchers(MeasurementValuesMap {
        r#bool: Some(true),
        number: Some(NumberMatcher::Exact(Number::Int(2))),
        text: Some(TextMatcher::Exact("b".into())),
        bytes: Some(BytesMatcher::Exact(vec![2])),
        ..Default::default()
    });
    let report = corim::baseline::compare(&changed, &baseline);
    assert!(report.structural_mismatches.is_empty());
    for field in ["bool", "number", "text", "bytes"] {
        assert!(report
            .value_differences
            .iter()
            .any(|difference| difference.field == field));
    }
    for key in [
        corim::types::tags::MVAL_KEY_BOOL,
        MVAL_KEY_NUMBER,
        MVAL_KEY_TEXT,
        MVAL_KEY_BYTES,
    ] {
        let mut missing = base.clone();
        match key {
            corim::types::tags::MVAL_KEY_BOOL => missing.r#bool = None,
            MVAL_KEY_NUMBER => missing.number = None,
            MVAL_KEY_TEXT => missing.text = None,
            _ => missing.bytes = None,
        }
        assert_eq!(
            corim::baseline::compare(&corim_with_matchers(missing), &baseline)
                .structural_mismatches
                .len(),
            1
        );
    }
}

#[cfg(feature = "profile-cca")]
#[test]
fn cca_profile_does_not_silently_accept_new_matcher_fields() {
    use corim::profile::Profile;
    let profile = corim::profile::cca::CcaRealmProfile::new();
    let original = corim::types::MeasurementMap {
        mkey: Some(corim::types::MeasuredElement::Text("cca.rim".into())),
        authorized_by: None,
        mval: MeasurementValuesMap {
            digests: Some(vec![corim::types::Digest::new_text("sha-256", vec![0; 32])]),
            ..Default::default()
        },
    };
    let context = corim::profile::MatchContext::new();
    assert_eq!(
        profile.match_measurement(&original, &original, &context),
        Some(true)
    );
    for key in [
        corim::types::tags::MVAL_KEY_BOOL,
        MVAL_KEY_NUMBER,
        MVAL_KEY_TEXT,
        MVAL_KEY_BYTES,
    ] {
        let mut measurement = original.clone();
        match key {
            corim::types::tags::MVAL_KEY_BOOL => measurement.mval.r#bool = Some(true),
            MVAL_KEY_NUMBER => measurement.mval.number = Some(NumberMatcher::Exact(Number::Int(1))),
            MVAL_KEY_TEXT => measurement.mval.text = Some(TextMatcher::Exact("a".into())),
            _ => measurement.mval.bytes = Some(BytesMatcher::Exact(vec![1])),
        }
        assert_eq!(
            profile.match_measurement(&measurement, &measurement, &context),
            Some(false)
        );
    }
}

#[test]
fn numeric_matchers_accept_all_cbor_float_widths() {
    for bytes in [
        vec![0xf9, 0x3e, 0x00],
        vec![0xfa, 0x3f, 0xc0, 0, 0],
        vec![0xfb, 0x3f, 0xf8, 0, 0, 0, 0, 0, 0],
    ] {
        assert_eq!(
            cbor::decode_exact::<NumberMatcher>(&bytes).unwrap(),
            NumberMatcher::Exact(Number::Float(1.5))
        );
    }
}

#[test]
fn duplicate_matcher_fields_are_rejected() {
    for (key, value) in [
        (corim::types::tags::MVAL_KEY_BOOL, Value::Bool(false)),
        (MVAL_KEY_NUMBER, Value::Integer(1)),
        (MVAL_KEY_TEXT, Value::Text("a".into())),
        (MVAL_KEY_BYTES, Value::Bytes(vec![1])),
    ] {
        let entry = (Value::Integer(i128::from(key)), value);
        let bytes = cbor::encode(&Value::Map(vec![entry.clone(), entry])).unwrap();
        assert!(cbor::decode_exact::<MeasurementValuesMap>(&bytes).is_err());
    }
}

#[cfg(feature = "profile-intel")]
#[test]
fn profile_appraisal_applies_standard_matcher_rules() {
    let condition = MeasurementValuesMap {
        r#bool: Some(false),
        number: Some(NumberMatcher::Set(vec![Number::Int(1), Number::Float(2.5)])),
        text: Some(TextMatcher::Set(vec!["a".into(), "b".into()])),
        bytes: Some(BytesMatcher::Exact(vec![255])),
        ..Default::default()
    };
    let references = corim_with_matchers(condition).tags[0]
        .as_comid()
        .unwrap()
        .triples
        .reference_triples
        .unwrap();
    let profile = corim::profile::intel::IntelProfile::new();
    for matches in [false, true] {
        let evidence = corim::validate::EvidenceClaim {
            environment: references[0].environment().clone(),
            measurements: vec![corim::types::MeasurementMap {
                mkey: None,
                authorized_by: None,
                mval: MeasurementValuesMap {
                    r#bool: Some(false),
                    number: Some(NumberMatcher::Exact(Number::Float(if matches {
                        2.5
                    } else {
                        3.0
                    }))),
                    text: Some(TextMatcher::Exact("a".into())),
                    bytes: Some(BytesMatcher::Exact(vec![255])),
                    ..Default::default()
                },
            }],
        };
        let result = corim::validate::match_reference_values_with_profile(
            &references,
            std::slice::from_ref(&evidence),
            Some(&profile),
            &corim::profile::MatchContext::new(),
        )
        .unwrap();
        assert_eq!(result.len(), usize::from(matches));
        if matches {
            assert_eq!(result[0].measurements, evidence.measurements);
        }
    }
}
