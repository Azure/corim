use corim::cbor::{self, value::Value};
use corim::types::tags::TAG_INT_RANGE;
use corim::types::{IntRangeChoice, MeasurementValuesMap};
use corim::Validate;

#[test]
fn legacy_int_ranges_reject_missing_and_reversed_bounds() {
    for (min, max) in [(None, None), (Some(2), Some(1))] {
        let value = IntRangeChoice::Range { min, max };
        assert!(value.valid().is_err());
        let mut values = MeasurementValuesMap::default();
        values.int_range = Some(value.clone());
        assert!(values.valid().is_err());
        assert!(cbor::encode(&value).is_err());
        let raw = Value::Tag(
            TAG_INT_RANGE,
            Box::new(Value::Array(vec![
                min.map_or(Value::Null, |value| Value::Integer(i128::from(value))),
                max.map_or(Value::Null, |value| Value::Integer(i128::from(value))),
            ])),
        );
        assert!(cbor::decode_exact::<IntRangeChoice>(&cbor::encode(&raw).unwrap()).is_err());
    }
}

#[test]
fn legacy_int_ranges_preserve_valid_inclusive_and_one_sided_bounds() {
    for (min, max) in [
        (None, Some(i64::MAX)),
        (Some(i64::MIN), None),
        (Some(1), Some(1)),
        (Some(-1), Some(1)),
    ] {
        let value = IntRangeChoice::Range { min, max };
        assert!(value.valid().is_ok());
        assert_eq!(
            cbor::decode_exact::<IntRangeChoice>(&cbor::encode(&value).unwrap()).unwrap(),
            value,
        );
    }
}
