use corim::cbor::{self, value::Value};
use corim::profile::{MatchContext, Profile};
use corim::types::environment::EnvironmentMap;
use corim::types::measurement::{FlagsMap, MeasurementMap, MeasurementValuesMap, SvnChoice};
use corim::types::triples::{
    CesCommonCondition, ConditionalEndorsementSeriesTriple, ConditionalSeriesRecord,
    ReferenceTriple,
};
use corim::validate::{match_reference_values, match_reference_values_with_profile, EvidenceClaim};
use corim::Validate;

const UNKNOWN_ATTRIBUTE: i64 = 10001;
const UNKNOWN_FLAG: i64 = 99;

fn measurement() -> MeasurementMap {
    let mut values = MeasurementValuesMap::default();
    values.svn = Some(SvnChoice::ExactValue(1));
    MeasurementMap {
        mkey: None,
        mval: values,
        authorized_by: None,
    }
}
fn series(
    condition: Vec<MeasurementMap>,
    addition: Vec<MeasurementMap>,
) -> ConditionalEndorsementSeriesTriple {
    ConditionalEndorsementSeriesTriple(
        CesCommonCondition {
            environment: EnvironmentMap::for_class("vendor", "model"),
            claims_list: vec![],
            authorized_by: None,
        },
        vec![ConditionalSeriesRecord(condition, addition)],
    )
}

#[test]
fn conditional_series_rejects_empty_conditions_and_additions() {
    assert!(series(vec![], vec![measurement()]).valid().is_err());
    assert!(series(vec![measurement()], vec![]).valid().is_err());
    assert!(series(vec![measurement()], vec![measurement()])
        .valid()
        .is_ok());
    let evidence = vec![EvidenceClaim {
        environment: EnvironmentMap::for_class("vendor", "model"),
        measurements: vec![measurement()],
    }];
    assert!(corim::validate::apply_endorsement_series(
        &[series(vec![], vec![measurement()])],
        &evidence
    )
    .is_err());
}

fn profile_requires_all_constraints(profile: &dyn Profile, key: i64, known: Value) {
    let mut reference = measurement();
    reference.mval.extra_entries.insert(key, known);
    let mut observed = reference.clone();
    reference
        .mval
        .extra_entries
        .insert(UNKNOWN_ATTRIBUTE, Value::Bool(true));
    let environment = EnvironmentMap::for_class("vendor", "model");
    let reference = ReferenceTriple::new(environment.clone(), vec![reference]);
    let ctx = MatchContext::new();
    for include_unknown in [false, true] {
        if include_unknown {
            observed
                .mval
                .extra_entries
                .insert(UNKNOWN_ATTRIBUTE, Value::Bool(true));
        }
        let evidence = [EvidenceClaim {
            environment: environment.clone(),
            measurements: vec![observed.clone()],
        }];
        assert!(match_reference_values_with_profile(
            std::slice::from_ref(&reference),
            &evidence,
            Some(profile),
            &ctx
        )
        .unwrap()
        .is_empty());
    }
}

#[test]
#[cfg(feature = "profile-intel")]
fn intel_known_and_unknown_conditions_fail_closed() {
    profile_requires_all_constraints(
        &corim::profile::intel::IntelProfile::new(),
        corim::profile::intel::MVAL_TEE_VENDOR,
        Value::Text("Intel".into()),
    );
}
#[test]
#[cfg(feature = "profile-azure")]
fn azure_known_and_unknown_conditions_fail_closed() {
    profile_requires_all_constraints(
        &corim::profile::azure::AzureProfile::new(),
        corim::profile::azure::MVAL_TCBSTATUS,
        Value::Text("UpToDate".into()),
    );
}
#[test]
#[cfg(feature = "profile-psa")]
fn psa_known_and_unknown_conditions_fail_closed() {
    profile_requires_all_constraints(
        &corim::profile::psa::PsaProfile::new(),
        corim::profile::psa::MVAL_PSA_CERT_NUM,
        Value::Text("1234567890123 - 12345".into()),
    );
}

fn profile_accepts_core_mask(profile: &dyn Profile, key: i64, known: Value) {
    use corim::types::measurement::RawValueChoice;
    use corim::types::tags::MVAL_KEY_RAW_VALUE_MASK_DEPRECATED;
    let mut reference = measurement();
    reference.mval.raw_value = Some(RawValueChoice::Bytes(vec![0xa0]));
    reference.mval.extra_entries.insert(key, known);
    reference.mval.extra_entries.insert(MVAL_KEY_RAW_VALUE_MASK_DEPRECATED, Value::Bytes(vec![0xf0]));
    let mut observed = reference.clone();
    observed.mval.extra_entries.remove(&MVAL_KEY_RAW_VALUE_MASK_DEPRECATED);
    observed.mval.raw_value = Some(RawValueChoice::Bytes(vec![0xaf]));
    assert_eq!(profile.match_measurement(&reference, &observed, &MatchContext::new()), Some(true));
    for mask in [Value::Text("bad".into()), Value::Bytes(vec![]), Value::Bytes(vec![0xf0, 0xf0])] {
        reference.mval.extra_entries.insert(MVAL_KEY_RAW_VALUE_MASK_DEPRECATED, mask);
        assert_eq!(profile.match_measurement(&reference, &observed, &MatchContext::new()), Some(false));
    }
    reference.mval.extra_entries.insert(MVAL_KEY_RAW_VALUE_MASK_DEPRECATED, Value::Bytes(vec![0xf0]));
    reference.mval.extra_entries.insert(UNKNOWN_ATTRIBUTE, Value::Bool(true));
    assert_eq!(profile.match_measurement(&reference, &observed, &MatchContext::new()), Some(false));
}

#[test]
#[cfg(feature = "profile-intel")]
fn intel_delegates_recognized_core_mask_modifiers() {
    profile_accepts_core_mask(&corim::profile::intel::IntelProfile::new(),
        corim::profile::intel::MVAL_TEE_VENDOR, Value::Text("Intel".into()));
}
#[test]
#[cfg(feature = "profile-azure")]
fn azure_delegates_recognized_core_mask_modifiers() {
    profile_accepts_core_mask(&corim::profile::azure::AzureProfile::new(),
        corim::profile::azure::MVAL_TCBSTATUS, Value::Text("UpToDate".into()));
}
#[test]
#[cfg(feature = "profile-psa")]
fn psa_delegates_recognized_core_mask_modifiers() {
    profile_accepts_core_mask(&corim::profile::psa::PsaProfile::new(),
        corim::profile::psa::MVAL_PSA_CERT_NUM, Value::Text("1234567890123 - 12345".into()));
}

#[test]
fn extension_flags_round_trip_but_unknown_condition_paths_never_match_core() {
    let value = Value::Map(vec![(
        Value::Integer(i128::from(UNKNOWN_FLAG)),
        Value::Bool(true),
    )]);
    let flags: FlagsMap = cbor::decode_exact(&cbor::encode(&value).unwrap()).unwrap();
    let round_trip = cbor::encode(&flags);
    let mut reference = measurement();
    reference.mval.flags = Some(flags);
    let mut observed = measurement();
    let flags: FlagsMap = cbor::decode_exact(
        &cbor::encode(&Value::Map(vec![(Value::Integer(1), Value::Bool(false))])).unwrap(),
    )
    .unwrap();
    observed.mval.flags = Some(flags);
    let environment = EnvironmentMap::for_class("vendor", "model");
    let evidence = [EvidenceClaim {
        environment: environment.clone(),
        measurements: vec![observed],
    }];
    assert!(match_reference_values(
        &[ReferenceTriple::new(environment, vec![reference])],
        &evidence
    )
    .is_empty());
    assert_eq!(
        cbor::decode_exact::<Value>(&round_trip.unwrap()).unwrap(),
        value
    );
}

#[test]
fn unrelated_environments_do_not_rescan_every_evidence_measurement() {
    const CHILD: &str = "CORIM_PR103_SCAN_CHILD";
    if std::env::var_os(CHILD).is_none() {
        let mut child = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "unrelated_environments_do_not_rescan_every_evidence_measurement",
                "--nocapture",
            ])
            .env(CHILD, "1")
            .stdout(std::process::Stdio::null())
            .spawn()
            .unwrap();
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
        loop {
            if let Some(status) = child.try_wait().unwrap() {
                assert!(status.success());
                return;
            }
            if std::time::Instant::now() >= deadline {
                child.kill().unwrap();
                child.wait().unwrap();
                panic!("unrelated-environment appraisal exceeded ten seconds");
            }
            std::thread::sleep(std::time::Duration::from_millis(20));
        }
    }
    let references = vec![
        ReferenceTriple::new(
            EnvironmentMap::for_class("vendor", "reference"),
            vec![measurement()]
        );
        2500
    ];
    let evidence = vec![
        EvidenceClaim {
            environment: EnvironmentMap::for_class("vendor", "unrelated"),
            measurements: vec![measurement(); 400],
        };
        1000
    ];
    assert!(match_reference_values(&references, &evidence).is_empty());
}
