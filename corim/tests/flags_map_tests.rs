use corim::cbor::{self, value::Value};
use corim::types::tags::FLAG_KEY_IS_SECURE;
use corim::types::{Flag, FlagsMap};

const EXTENSION: i64 = 99;

#[test]
fn named_and_integer_aliases_share_one_entry_but_text_labels_remain_distinct() {
    let mut flags = FlagsMap::default();
    flags.insert(Flag::IsSecure, Value::Bool(true)).unwrap();
    assert_eq!(
        flags
            .insert(Flag::Extension(FLAG_KEY_IS_SECURE), Value::Bool(false))
            .unwrap(),
        Some(Value::Bool(true))
    );
    assert_eq!(flags.iter().count(), 1);
    assert_eq!(flags.get(&Flag::IsSecure), Some(&Value::Bool(false)));
    assert!(flags
        .insert(Flag::IsSecure, Value::Text("invalid".into()))
        .is_err());
    flags
        .insert(Flag::Text("1".into()), Value::Text("extension".into()))
        .unwrap();
    assert_eq!(flags.iter().count(), 2);
    let bytes = cbor::encode(&flags).unwrap();
    assert_eq!(cbor::decode_exact::<FlagsMap>(&bytes).unwrap(), flags);
    assert_eq!(
        flags.remove(&Flag::Extension(FLAG_KEY_IS_SECURE)),
        Some(Value::Bool(false))
    );
    assert!(flags.get(&Flag::IsSecure).is_none());
}

#[test]
fn nonboolean_extension_values_are_retained_without_becoming_known_flags() {
    let mut flags = FlagsMap::default();
    flags
        .insert(
            Flag::Extension(EXTENSION),
            Value::Array(vec![Value::Text("opaque".into())]),
        )
        .unwrap();
    assert!(flags.iter().all(|(flag, _)| flag.is_extension()));
    let bytes = cbor::encode(&flags).unwrap();
    assert_eq!(cbor::decode_exact::<FlagsMap>(&bytes).unwrap(), flags);
    assert!(Flag::IsSecure.name().is_some());
    assert!(Flag::Extension(EXTENSION).name().is_none());
}

#[test]
fn malformed_flag_maps_reject_explicitly() {
    let key = Value::Integer(i128::from(FLAG_KEY_IS_SECURE));
    for value in [
        Value::Null,
        Value::Array(vec![]),
        Value::Map(vec![]),
        Value::Map(vec![(key.clone(), Value::Null)]),
        Value::Map(vec![(key.clone(), Value::Integer(1))]),
        Value::Map(vec![(Value::Array(vec![]), Value::Bool(true))]),
        Value::Map(vec![(
            Value::Integer(i128::from(u64::MAX)),
            Value::Bool(true),
        )]),
        Value::Map(vec![
            (key.clone(), Value::Bool(true)),
            (key, Value::Bool(false)),
        ]),
    ] {
        let bytes = cbor::encode(&value).unwrap();
        assert!(cbor::decode_exact::<FlagsMap>(&bytes).is_err(), "{value:?}");
    }

    assert!(cbor::encode(&FlagsMap::default()).is_err());
}

#[test]
fn readable_serialization_cannot_normalize_text_labels_into_integer_flags() {
        let mut flags = FlagsMap::default();
        flags.insert(Flag::Text("1".into()), Value::Bool(true)).unwrap();
        let error = corim::cbor::value::to_human_readable_value(&flags).unwrap_err();
        assert!(error.contains("--lossless"), "{error}");
        let bytes = cbor::encode(&flags).unwrap();
        assert_eq!(cbor::decode_exact::<FlagsMap>(&bytes).unwrap(), flags);
        let mut known = FlagsMap::default();
        known.insert(Flag::IsSecure, Value::Bool(true)).unwrap();
        assert!(corim::cbor::value::to_human_readable_value(&known).is_ok());
}
