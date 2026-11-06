use corim::cbor::{self, value::Value};
use corim::types::tags::TAG_INT_RANGE;
use corim::types::IntRangeChoice;

#[test]
fn legacy_int_ranges_reject_missing_and_reversed_bounds() {
    for (min, max) in [(None, None), (Some(2), Some(1))] {
        let value = IntRangeChoice::Range { min, max };
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
