use corim::cbor::{self, value::Value};
use corim::types::MeasurementValuesMap;

#[test]
fn key17_rejects_legacy_float_and_mixed_numeric_matchers() {
    for value in [
        Value::Float(1.0),
        Value::Tag(565, Box::new(Value::Array(vec![Value::Float(1.0), Value::Null]))),
        Value::Tag(
            566,
            Box::new(Value::Array(vec![Value::Integer(1), Value::Float(2.0)])),
        ),
    ] {
        let encoded = cbor::encode(&Value::Map(vec![(Value::Integer(17), value)])).unwrap();
        assert!(cbor::decode_exact::<MeasurementValuesMap>(&encoded).is_err());
    }
}
