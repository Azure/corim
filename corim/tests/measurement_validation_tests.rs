use corim::cbor::{self, value::Value};
use corim::diagnose::{self, Severity};
use corim::profile::ProfileRegistry;
use corim::types::{
    ConditionalEndorsementTriple, EndorsedTriple, EnvironmentMap, IntegerMatcher,
    MeasurementMap, MeasurementValuesMap, StatefulEnvironmentRecord, SvnChoice,
};
use corim::types::tags::*;
use corim::Validate;

fn key(label: i64) -> Value { Value::Integer(i128::from(label)) }
fn measurement() -> MeasurementMap {
    let mut values = MeasurementValuesMap::default();
    values.svn = Some(SvnChoice::ExactValue(1));
    MeasurementMap { mkey: None, mval: values, authorized_by: None }
}
fn invalid_condition() -> StatefulEnvironmentRecord {
    let mut values = MeasurementValuesMap::default();
    values.digests = Some(vec![]);
    StatefulEnvironmentRecord(
        EnvironmentMap::for_class("vendor", "model"),
        vec![MeasurementMap { mkey: None, mval: values, authorized_by: None }],
    )
}
fn document(triples: Value) -> Vec<u8> {
    let comid = Value::Map(vec![
        (key(COMID_KEY_TAG_IDENTITY), Value::Map(vec![(key(TAG_IDENTITY_KEY_TAG_ID), Value::Text("validation".into()))])),
        (key(COMID_KEY_TRIPLES), triples),
    ]);
    cbor::encode(&Value::Tag(TAG_CORIM, Box::new(Value::Map(vec![
        (key(CORIM_KEY_ID), Value::Text("validation".into())),
        (key(CORIM_KEY_TAGS), Value::Array(vec![
            Value::Tag(TAG_COMID, Box::new(Value::Bytes(cbor::encode(&comid).unwrap()))),
        ])),
    ])))).unwrap()
}

#[test]
fn conditional_measurements_require_full_validation_without_forbidding_matchers() {
    assert!(invalid_condition().valid().is_err());
    let mut values = MeasurementValuesMap::default();
    values.integer = Some(IntegerMatcher::Range { min: Some(1), max: None });
    let valid = StatefulEnvironmentRecord(
        EnvironmentMap::for_class("vendor", "model"),
        vec![MeasurementMap { mkey: None, mval: values, authorized_by: None }],
    );
    assert!(valid.valid().is_ok());
}

#[test]
fn complete_document_validation_rejects_empty_conditional_digests() {
    let triple = ConditionalEndorsementTriple(
        vec![invalid_condition()],
        vec![EndorsedTriple(EnvironmentMap::for_class("vendor", "model"), vec![measurement()])],
    );
    let bytes = document(Value::Map(vec![
        (key(TRIPLES_KEY_COND_ENDORSEMENT), Value::Array(vec![
            cbor::value::to_value(&triple).unwrap(),
        ])),
    ]));
    assert!(corim::validate::decode_and_validate_full_at(&bytes, 0).is_err());
}

#[test]
fn diagnostics_report_typed_flag_errors_and_continue_to_later_measurements() {
    let malformed = Value::Map(vec![
        (key(MEAS_KEY_MVAL), Value::Map(vec![
            (key(MVAL_KEY_FLAGS), Value::Map(vec![
                (key(FLAG_KEY_IS_SECURE), Value::Null),
            ])),
        ])),
    ]);
    for later_error in [false, true] {
        let mut measurements = vec![malformed.clone(), cbor::value::to_value(&measurement()).unwrap()];
        if later_error { measurements.push(Value::Map(vec![])); }
        let bytes = document(Value::Map(vec![
            (key(TRIPLES_KEY_REFERENCE), Value::Array(vec![Value::Array(vec![
                cbor::value::to_value(&EnvironmentMap::for_class("vendor", "model")).unwrap(),
                Value::Array(measurements),
            ])])),
        ]));
        assert!(corim::validate::decode_and_validate_full_at(&bytes, 0).is_err());
        let report = diagnose::inspect(&bytes, &ProfileRegistry::new());
        assert!(report.issues().iter().any(|issue|
            issue.severity() == Severity::Error
                && issue.path().ends_with("measurements[0]")
                && issue.message().contains("flag")
        ), "{report}");
        if later_error {
            assert!(report.issues().iter().any(|issue|
                issue.severity() == Severity::Error
                    && issue.path().contains("measurements[2]")
            ), "{report}");
        }
    }
}
