use corim::cbor::value::Value;
use corim::types::measurement::IntegrityRegisterId;
use corim::types::{
    CryptoKey, Digest, EnvironmentMap, FlagsMap, IntRangeChoice, IntegrityRegisters,
    MeasuredElement, MeasurementMap, MeasurementValuesMap, RawValueChoice, ReferenceTriple,
};
use corim::validate::{core_fields_match, EvidenceClaim};

fn measurement(values: MeasurementValuesMap) -> MeasurementMap {
    MeasurementMap {
        mkey: None,
        authorized_by: None,
        mval: values,
    }
}

#[test]
fn flags_require_condition_paths_but_allow_additional_evidence_flags() {
    let mut condition = MeasurementValuesMap::default();
    condition.flags = Some(
        corim::cbor::value::from_value::<FlagsMap>(&Value::Map(vec![(
            Value::Integer(i128::from(corim::types::tags::FLAG_KEY_IS_SECURE)),
            Value::Bool(false),
        )]))
        .unwrap(),
    );
    let condition = measurement(condition);
    let mut entry = condition.clone();
    entry.mval.flags.as_mut().unwrap().is_debug = Some(true);
    assert!(core_fields_match(&condition, &entry));
    entry.mval.flags.as_mut().unwrap().is_secure = None;
    assert!(!core_fields_match(&condition, &entry));
    entry.mval.flags.as_mut().unwrap().is_secure = Some(true);
    assert!(!core_fields_match(&condition, &entry));
    entry.mval.flags = None;
    assert!(!core_fields_match(&condition, &entry));
}

#[test]
fn unknown_comparison_algorithms_never_fall_back_to_binary_equality() {
    let mut values = MeasurementValuesMap::default();
    values.name = Some("same".into());
    values
        .extra_entries
        .insert(10001, Value::Text("same".into()));
    let condition = measurement(values);
    let environment = EnvironmentMap::for_class("vendor", "model");
    let reference = ReferenceTriple(environment.clone(), vec![condition.clone()]);
    let evidence = EvidenceClaim {
        environment,
        measurements: vec![condition],
    };
    assert!(corim::validate::match_reference_values(
        std::slice::from_ref(&reference),
        std::slice::from_ref(&evidence),
    )
    .is_empty());
    assert!(
        corim::validate::match_reference_values_with_profile::<dyn corim::profile::Profile>(
            &[reference],
            &[evidence],
            None,
            &corim::profile::MatchContext::new(),
        )
        .unwrap()
        .is_empty()
    );
}

#[test]
fn element_identifiers_match_only_when_both_absent_or_equal() {
    let mut values = MeasurementValuesMap::default();
    values.name = Some("same".into());
    let absent = measurement(values);
    let mut present = absent.clone();
    present.mkey = Some(MeasuredElement::Text("id".into()));
    assert!(!core_fields_match(&absent, &present));
    assert!(!core_fields_match(&present, &absent));
    assert!(core_fields_match(&present, &present));
    assert!(core_fields_match(&absent, &absent));
}

#[test]
fn legacy_integer_ranges_use_inclusion_and_subsumption() {
    let map = |range| {
        let mut values = MeasurementValuesMap::default();
        values.int_range = Some(range);
        measurement(values)
    };
    let condition = map(IntRangeChoice::Range {
        min: Some(1),
        max: Some(3),
    });
    assert!(core_fields_match(&condition, &map(IntRangeChoice::Int(2))));
    assert!(core_fields_match(
        &condition,
        &map(IntRangeChoice::Range {
            min: Some(1),
            max: Some(2)
        })
    ));
    assert!(!core_fields_match(
        &condition,
        &map(IntRangeChoice::Range {
            min: None,
            max: Some(2)
        })
    ));
    assert!(!core_fields_match(&condition, &map(IntRangeChoice::Int(4))));
    assert!(core_fields_match(
        &map(IntRangeChoice::Int(2)),
        &map(IntRangeChoice::Range {
            min: Some(2),
            max: Some(2)
        })
    ));
}

#[test]
fn integrity_register_conditions_allow_additional_registers_and_algorithms() {
    let mut values = MeasurementValuesMap::default();
    values.integrity_registers = Some(IntegrityRegisters(
        [(IntegrityRegisterId::Uint(0), vec![Digest::new(1, vec![1])])].into(),
    ));
    let condition = measurement(values);
    let mut entry = condition.clone();
    let registers = &mut entry.mval.integrity_registers.as_mut().unwrap().0;
    registers
        .get_mut(&IntegrityRegisterId::Uint(0))
        .unwrap()
        .push(Digest::new(2, vec![2]));
    registers.insert(IntegrityRegisterId::Uint(1), vec![Digest::new(1, vec![3])]);
    assert!(core_fields_match(&condition, &entry));
    entry
        .mval
        .integrity_registers
        .as_mut()
        .unwrap()
        .0
        .remove(&IntegrityRegisterId::Uint(0));
    assert!(!core_fields_match(&condition, &entry));
}

#[test]
fn cryptokey_conditions_require_matching_ordered_prefixes() {
    let mut values = MeasurementValuesMap::default();
    values.cryptokeys = Some(vec![CryptoKey::Bytes(vec![1])]);
    let condition = measurement(values);
    let mut entry = condition.clone();
    entry
        .mval
        .cryptokeys
        .as_mut()
        .unwrap()
        .push(CryptoKey::Bytes(vec![2]));
    assert!(core_fields_match(&condition, &entry));
    entry.mval.cryptokeys.as_mut().unwrap().reverse();
    assert!(!core_fields_match(&condition, &entry));
    entry.mval.cryptokeys = None;
    assert!(!core_fields_match(&condition, &entry));
}

#[test]
fn raw_value_conditions_compare_only_masked_bits_against_bare_assertions() {
    let mut values = MeasurementValuesMap::default();
    values.raw_value = Some(RawValueChoice::Masked {
        value: vec![0xa0],
        mask: vec![0xf0],
    });
    let condition = measurement(values);
    let mut entry = condition.clone();
    entry.mval.raw_value = Some(RawValueChoice::Bytes(vec![0xaf]));
    assert!(core_fields_match(&condition, &entry));
    entry.mval.raw_value = Some(RawValueChoice::Bytes(vec![0xbf]));
    assert!(!core_fields_match(&condition, &entry));
    entry.mval.raw_value = Some(RawValueChoice::Bytes(vec![0xa0, 0x00]));
    assert!(!core_fields_match(&condition, &entry));
    assert!(!core_fields_match(&condition, &condition));
}
