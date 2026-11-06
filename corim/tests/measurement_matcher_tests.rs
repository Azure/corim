use corim::cbor::{self, value::Value};
use corim::types::tags::{
    MVAL_KEY_BYTES, MVAL_KEY_FLOAT, MVAL_KEY_INTEGER, MVAL_KEY_TEXT, TAG_MATCHER_SET,
    TAG_NUMERIC_RANGE,
};
use corim::types::{BytesMatcher, FloatMatcher, IntegerMatcher, MeasurementValuesMap, TextMatcher};
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
    for integer in [-1 - i128::from(u64::MAX), i128::from(u64::MAX)] {
        round_trip(IntegerMatcher::Exact(integer));
    }
    for float in [1.5, f64::INFINITY, f64::NEG_INFINITY, -0.0] {
        round_trip(FloatMatcher::Exact(float));
    }
    round_trip(IntegerMatcher::Range {
        min: None,
        max: Some(5),
    });
    round_trip(IntegerMatcher::Set(vec![1, 2]));
    round_trip(FloatMatcher::Set(vec![1.0, 2.5]));
    round_trip(TextMatcher::Exact("".into()));
    round_trip(TextMatcher::Set(vec!["a".into(), "b".into()]));
    round_trip(BytesMatcher::Exact(vec![]));
    round_trip(BytesMatcher::Set(vec![vec![0], vec![255]]));
    for map in [
        {
            let mut values = MeasurementValuesMap::default();
            values.integer = Some(IntegerMatcher::Exact(3));
            values.float = Some(FloatMatcher::Exact(3.0));
            values
        },
        {
            let mut values = MeasurementValuesMap::default();
            values.text = Some(TextMatcher::Exact("hi".into()));
            values
        },
        {
            let mut values = MeasurementValuesMap::default();
            values.bytes = Some(BytesMatcher::Exact(vec![1, 2]));
            values
        },
    ] {
        assert!(map.valid().is_ok());
        round_trip(map);
    }
    let range = IntegerMatcher::Range {
        min: Some(1),
        max: None,
    };
    assert_eq!(
        cbor::decode_exact::<Value>(&cbor::encode(&range).unwrap()).unwrap(),
        Value::Tag(
            TAG_NUMERIC_RANGE,
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
        Value::Tag(TAG_NUMERIC_RANGE + 10, Box::new(Value::Integer(1))),
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
        assert!(cbor::decode_exact::<IntegerMatcher>(&bytes).is_err());
        assert!(cbor::decode_exact::<FloatMatcher>(&bytes).is_err());
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
        assert!(cbor::decode_exact::<IntegerMatcher>(
            &cbor::encode(&Value::Tag(TAG_NUMERIC_RANGE, Box::new(inner))).unwrap()
        )
        .is_err());
    }
    for value in [
        IntegerMatcher::Set(vec![]),
        IntegerMatcher::Range {
            min: Some(2),
            max: Some(1),
        },
        IntegerMatcher::Exact(i128::MAX),
    ] {
        assert!(value.valid().is_err());
        assert!(cbor::encode(&value).is_err());
    }
    assert!(cbor::encode(&TextMatcher::Set(vec!["only".into()])).is_err());
    assert!(cbor::encode(&BytesMatcher::Set(vec![vec![]])).is_err());
    for key in [
        MVAL_KEY_INTEGER,
        MVAL_KEY_FLOAT,
        MVAL_KEY_TEXT,
        MVAL_KEY_BYTES,
    ] {
        let mut map = MeasurementValuesMap::default();
        map.extra_entries.insert(key, Value::Integer(1));
        assert!(cbor::encode(&map).is_err());
    }
}

#[test]
fn numeric_matching_preserves_integer_precision_and_float_equality() {
    let range = IntegerMatcher::Range {
        min: Some(9_007_199_254_740_993),
        max: None,
    };
    assert!(!range.matches(&IntegerMatcher::Exact(9_007_199_254_740_992)));
    assert!(range.matches(&IntegerMatcher::Exact(9_007_199_254_740_993)));
    let positive = FloatMatcher::Range {
        min: Some(0.0),
        max: None,
    };
    assert!(positive.matches(&FloatMatcher::Exact(f64::INFINITY)));
    assert!(!positive.matches(&FloatMatcher::Exact(f64::NEG_INFINITY)));
    assert!(!positive.matches(&FloatMatcher::Exact(f64::NAN)));
    assert!(FloatMatcher::Exact(0.0).matches(&FloatMatcher::Exact(-0.0)));
    assert!(FloatMatcher::Set(vec![1.0, 0.0]).matches(&FloatMatcher::Exact(-0.0)));
    assert!(!positive.matches(&positive));
    assert!(!positive.matches(&FloatMatcher::Set(vec![1.0, 2.0])));
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
        mval: {
            let mut values = MeasurementValuesMap::default();
            values.float = Some(FloatMatcher::Range {
                min: Some(1.0),
                max: Some(3.0),
            });
            values.text = Some(TextMatcher::Set(vec!["a".into(), "b".into()]));
            values.bytes = Some(BytesMatcher::Exact(vec![0, 255]));
            values
        },
    };
    let observed = MeasurementMap {
        mval: {
            let mut values = MeasurementValuesMap::default();
            values.float = Some(FloatMatcher::Exact(2.5));
            values.text = Some(TextMatcher::Exact("b".into()));
            values.bytes = condition.mval.bytes.clone();
            values
        },
        ..condition.clone()
    };
    assert!(corim::validate::core_fields_match(&condition, &observed));
    for missing in [MVAL_KEY_FLOAT, MVAL_KEY_TEXT, MVAL_KEY_BYTES] {
        let mut absent = observed.clone();
        match missing {
            MVAL_KEY_FLOAT => absent.mval.float = None,
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
        let map = {
            let mut values = MeasurementValuesMap::default();
            values.r#bool = Some(expected);
            values
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
                mval: {
                    let mut values = MeasurementValuesMap::default();
                    values.r#bool = observed;
                    values
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
    for (integer, float) in [
        (Some(IntegerMatcher::Exact(i128::from(u64::MAX))), None),
        (Some(IntegerMatcher::Exact(-1 - i128::from(u64::MAX))), None),
        (None, Some(FloatMatcher::Exact(f64::INFINITY))),
        (None, Some(FloatMatcher::Set(vec![1.0, f64::NEG_INFINITY]))),
        (
            None,
            Some(FloatMatcher::Range {
                min: None,
                max: Some(1.0),
            }),
        ),
    ] {
        let original = {
            let mut values = MeasurementValuesMap::default();
            values.r#bool = Some(false);
            values.integer = integer;
            values.float = float;
            values.text = Some(TextMatcher::Set(vec!["a".into(), "b".into()]));
            values.bytes = Some(BytesMatcher::Set(vec![vec![], vec![0, 255]]));
            values
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
        r#"{"17":{"type":"integer-range","value":[{"type":"integer","value":"invalid"},null]}}"#,
    ] {
        assert!(
            corim::json::from_json::<MeasurementValuesMap>(json).is_err(),
            "{json}"
        );
    }
}

#[test]
fn present_null_matcher_fields_are_rejected_in_embedded_documents() {
    use corim::types::tags::{MEAS_KEY_MVAL, MVAL_KEY_BOOL, TAG_CORIM};
    fn insert_null(value: &mut Value, key: i64) {
        match value {
            Value::Map(fields) => {
                for (field, value) in fields {
                    if *field == Value::Integer(i128::from(MEAS_KEY_MVAL)) {
                        if let Value::Map(fields) = value {
                            if fields.iter().any(|(key, _)| {
                                *key == Value::Integer(i128::from(corim::types::tags::MVAL_KEY_SVN))
                            }) {
                                fields.push((Value::Integer(i128::from(key)), Value::Null));
                                return;
                            }
                        }
                    }
                    insert_null(value, key);
                }
            }
            Value::Array(values) => {
                for value in values {
                    insert_null(value, key);
                }
            }
            Value::Tag(_, inner) => insert_null(inner, key),
            _ => {}
        }
    }
    for key in [
        MVAL_KEY_BOOL,
        MVAL_KEY_INTEGER,
        MVAL_KEY_FLOAT,
        MVAL_KEY_TEXT,
        MVAL_KEY_BYTES,
    ] {
        let control = {
            let mut values = MeasurementValuesMap::default();
            values.svn = Some(corim::types::SvnChoice::ExactValue(1));
            values
        };
        let mut corim = corim_with_matchers(control.clone());
        let direct = Value::Map(vec![
            (
                Value::Integer(i128::from(corim::types::tags::MVAL_KEY_SVN)),
                Value::Integer(1),
            ),
            (Value::Integer(i128::from(key)), Value::Null),
        ]);
        assert!(
            cbor::decode_exact::<MeasurementValuesMap>(&cbor::encode(&direct).unwrap()).is_err(),
            "key {key}: explicit null accepted"
        );
        let corim::types::corim::ConciseTagChoice::Comid(body) = &mut corim.tags[0] else {
            panic!("CoMID fixture");
        };
        let mut comid: Value = cbor::decode_exact(body).unwrap();
        insert_null(&mut comid, key);
        *body = cbor::encode(&comid).unwrap();
        let bytes = cbor::encode(&corim::cbor::value::Tagged {
            tag: TAG_CORIM,
            value: corim,
        })
        .unwrap();
        assert!(
            corim::validate::decode_and_validate_full_at(&bytes, 0).is_err(),
            "embedded key {key}: explicit null accepted"
        );
        #[cfg(feature = "json")]
        {
            let json = format!(r#"{{"1":1,"{key}":null}}"#);
            assert!(
                corim::json::from_json::<MeasurementValuesMap>(&json).is_err(),
                "{json}"
            );
        }
        round_trip(control);
    }
    round_trip({
        let mut values = MeasurementValuesMap::default();
        values.integer = Some(IntegerMatcher::Range {
            min: None,
            max: Some(1),
        });
        values
    });
}

fn corim_with_matchers(mval: MeasurementValuesMap) -> corim::types::CorimMap {
    // Sets/ranges belong in a conditional claim, not a Reference Value assertion.
    let measurement = corim::types::MeasurementMap {
        mkey: None,
        authorized_by: None,
        mval,
    };
    let mut comid =
        corim::builder::ComidBuilder::new(corim::types::TagIdChoice::Text("matcher".into()))
            .add_reference_triple_for(
                corim::types::EnvironmentMap::for_class("V", "M"),
                vec![{
                    let mut assertion = measurement.clone();
                    assertion.mval = MeasurementValuesMap::default();
                    assertion.mval.svn = Some(corim::types::SvnChoice::ExactValue(1));
                    assertion
                }],
            )
            .build()
            .unwrap();
    comid.triples.reference_triples = None;
    comid.triples.conditional_endorsement_series =
        Some(vec![corim::types::ConditionalEndorsementSeriesTriple(
            corim::types::CesCommonCondition {
                environment: corim::types::EnvironmentMap::for_class("V", "M"),
                claims_list: vec![],
                authorized_by: None,
            },
            vec![corim::types::ConditionalSeriesRecord(
                vec![measurement],
                vec![],
            )],
        )]);
    corim::builder::CorimBuilder::new(corim::types::CorimId::Text("matcher".into()))
        .add_comid_tag(comid)
        .unwrap()
        .build()
        .unwrap()
}

#[test]
fn baseline_reports_matcher_presence_and_value_differences() {
    let base = {
        let mut values = MeasurementValuesMap::default();
        values.r#bool = Some(false);
        values.float = Some(FloatMatcher::Exact(f64::INFINITY));
        values.text = Some(TextMatcher::Exact("a".into()));
        values.bytes = Some(BytesMatcher::Exact(vec![1]));
        values
    };
    let baseline = corim_with_matchers(base.clone());
    let identical = corim::baseline::compare(&baseline, &baseline).unwrap();
    assert!(identical.structural_mismatches.is_empty());
    assert!(identical.value_differences.is_empty());
    let changed = corim_with_matchers({
        let mut values = MeasurementValuesMap::default();
        values.r#bool = Some(true);
        values.integer = Some(IntegerMatcher::Exact(2));
        values.text = Some(TextMatcher::Exact("b".into()));
        values.bytes = Some(BytesMatcher::Exact(vec![2]));
        values
    });
    let report = corim::baseline::compare(&changed, &baseline).unwrap();
    assert_eq!(report.structural_mismatches.len(), 2);
    assert!(report
        .structural_mismatches
        .iter()
        .any(|difference| difference
            .path
            .contains(&corim::baseline::PathSegment::Field("float"))));
    for field in ["bool", "text", "bytes"] {
        assert!(report
            .value_differences
            .iter()
            .any(|difference| difference.field == field));
    }
    for key in [
        corim::types::tags::MVAL_KEY_BOOL,
        MVAL_KEY_FLOAT,
        MVAL_KEY_TEXT,
        MVAL_KEY_BYTES,
    ] {
        let mut missing = base.clone();
        match key {
            corim::types::tags::MVAL_KEY_BOOL => missing.r#bool = None,
            MVAL_KEY_FLOAT => missing.float = None,
            MVAL_KEY_TEXT => missing.text = None,
            _ => missing.bytes = None,
        }
        assert_eq!(
            corim::baseline::compare(&corim_with_matchers(missing), &baseline)
                .unwrap()
                .structural_mismatches
                .len(),
            1
        );
    }
}

#[test]
fn baseline_numeric_set_reservation_uses_float_bits() {
    for values in [vec![f64::INFINITY, f64::NEG_INFINITY], vec![0.0, -0.0]] {
        let mut reversed = values.clone();
        reversed.reverse();
        let baseline = corim_with_matchers({
            let mut initial_values = MeasurementValuesMap::default();
            initial_values.float = Some(FloatMatcher::Set(values));
            initial_values
        });
        let input = corim_with_matchers({
            let mut values = MeasurementValuesMap::default();
            values.float = Some(FloatMatcher::Set(reversed));
            values
        });
        let report = corim::baseline::compare(&input, &baseline).unwrap();
        assert!(report.is_conformant());
        assert!(report.value_differences.is_empty(), "{report:?}");
    }
}

#[test]
fn baseline_matcher_sets_are_unordered_and_shape_sensitive() {
    let baseline = corim_with_matchers({
        let mut values = MeasurementValuesMap::default();
        values.text = Some(TextMatcher::Set(vec!["a".into(), "b".into()]));
        values
    });
    let reordered = corim_with_matchers({
        let mut values = MeasurementValuesMap::default();
        values.text = Some(TextMatcher::Set(vec!["b".into(), "a".into()]));
        values
    });
    let report = corim::baseline::compare(&reordered, &baseline).unwrap();
    assert!(report.is_conformant());
    assert!(report.value_differences.is_empty());
    for matcher in [
        TextMatcher::Exact("a".into()),
        TextMatcher::Set(vec!["a".into(), "b".into(), "c".into()]),
    ] {
        let changed = corim_with_matchers({
            let mut values = MeasurementValuesMap::default();
            values.text = Some(matcher);
            values
        });
        assert!(!corim::baseline::compare(&changed, &baseline)
            .unwrap()
            .is_conformant());
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
        mval: {
            let mut values = MeasurementValuesMap::default();
            values.digests = Some(vec![corim::types::Digest::new_text("sha-256", vec![0; 32])]);
            values
        },
    };
    let context = corim::profile::MatchContext::new();
    assert_eq!(
        profile.match_measurement(&original, &original, &context),
        Some(true)
    );
    for key in [
        corim::types::tags::MVAL_KEY_BOOL,
        MVAL_KEY_INTEGER,
        MVAL_KEY_FLOAT,
        MVAL_KEY_TEXT,
        MVAL_KEY_BYTES,
    ] {
        let mut measurement = original.clone();
        match key {
            corim::types::tags::MVAL_KEY_BOOL => measurement.mval.r#bool = Some(true),
            MVAL_KEY_INTEGER => measurement.mval.integer = Some(IntegerMatcher::Exact(1)),
            MVAL_KEY_FLOAT => measurement.mval.float = Some(FloatMatcher::Exact(1.0)),
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
            cbor::decode_exact::<FloatMatcher>(&bytes).unwrap(),
            FloatMatcher::Exact(1.5)
        );
    }
}

#[test]
fn duplicate_matcher_fields_are_rejected() {
    for (key, value) in [
        (corim::types::tags::MVAL_KEY_BOOL, Value::Bool(false)),
        (MVAL_KEY_INTEGER, Value::Integer(1)),
        (MVAL_KEY_FLOAT, Value::Float(1.0)),
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
    let condition = {
        let mut values = MeasurementValuesMap::default();
        values.r#bool = Some(false);
        values.float = Some(FloatMatcher::Exact(2.5));
        values.text = Some(TextMatcher::Exact("a".into()));
        values.bytes = Some(BytesMatcher::Exact(vec![255]));
        values
    };
    let references = vec![corim::types::ReferenceTriple(
        corim::types::EnvironmentMap::for_class("V", "M"),
        vec![corim::types::MeasurementMap {
            mkey: None,
            authorized_by: None,
            mval: condition,
        }],
    )];
    let profile = corim::profile::intel::IntelProfile::new();
    for matches in [false, true] {
        let evidence = corim::validate::EvidenceClaim {
            environment: references[0].environment().clone(),
            measurements: vec![corim::types::MeasurementMap {
                mkey: None,
                authorized_by: None,
                mval: {
                    let mut values = MeasurementValuesMap::default();
                    values.r#bool = Some(false);
                    values.float = Some(FloatMatcher::Exact(if matches { 2.5 } else { 3.0 }));
                    values.text = Some(TextMatcher::Exact("a".into()));
                    values.bytes = Some(BytesMatcher::Exact(vec![255]));
                    values
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
