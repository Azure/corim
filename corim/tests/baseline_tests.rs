// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Tests for `corim::baseline` structural conformance comparison.

use corim::baseline::{compare, MismatchKind};
use corim::builder::{ComidBuilder, CorimBuilder};
use corim::types::common::{MeasuredElement, TagIdChoice};
use corim::types::corim::{CorimId, CorimMap};
use corim::types::environment::{ClassMap, EnvironmentMap};
use corim::types::measurement::{Digest, MeasurementMap, MeasurementValuesMap, SvnChoice};
use corim::types::triples::ReferenceTriple;

/// Build a one-CoMID, one-reference-triple CoRIM with a single MRTD
/// measurement carrying the given digest bytes and svn.
fn corim_with(digest: Vec<u8>, svn: SvnChoice, mkey: &str) -> CorimMap {
    let env = EnvironmentMap {
        class: Some(ClassMap {
            class_id: None,
            vendor: Some("Intel".into()),
            model: Some("TDX".into()),
            layer: None,
            index: None,
        }),
        instance: None,
        group: None,
    };
    let meas = MeasurementMap {
        mkey: Some(MeasuredElement::Text(mkey.into())),
        mval: MeasurementValuesMap {
            digests: Some(vec![Digest::new(7, digest)]),
            svn: Some(svn),
            ..MeasurementValuesMap::default()
        },
        authorized_by: None,
    };
    let comid = ComidBuilder::new(TagIdChoice::Text("c1".into()))
        .add_reference_triple(ReferenceTriple::new(env, vec![meas]))
        .build()
        .unwrap();
    let bytes = CorimBuilder::new(CorimId::Text("corim-1".into()))
        .add_comid_tag(comid)
        .unwrap()
        .build_bytes()
        .unwrap();
    corim::validate::decode_and_validate(&bytes).unwrap().0
}

#[test]
fn identical_corims_conform_with_no_differences() {
    let base = corim_with(vec![0xAA; 48], SvnChoice::MinValue(1), "MRTD");
    let input = corim_with(vec![0xAA; 48], SvnChoice::MinValue(1), "MRTD");
    let report = compare(&input, &base);
    assert!(report.is_conformant());
    assert!(report.structural_mismatches.is_empty());
    assert!(report.value_differences.is_empty());
}

#[test]
fn different_digest_bytes_is_a_value_difference_not_a_mismatch() {
    let base = corim_with(vec![0xAA; 48], SvnChoice::MinValue(1), "MRTD");
    let input = corim_with(vec![0xBB; 48], SvnChoice::MinValue(1), "MRTD");
    let report = compare(&input, &base);
    assert!(report.is_conformant(), "digest bytes may differ");
    assert!(report.structural_mismatches.is_empty());
    assert_eq!(report.value_differences.len(), 1);
    assert_eq!(report.value_differences[0].field, "digest-value");
}

#[test]
fn different_svn_value_is_a_value_difference() {
    let base = corim_with(vec![0xAA; 48], SvnChoice::MinValue(1), "MRTD");
    let input = corim_with(vec![0xAA; 48], SvnChoice::MinValue(5), "MRTD");
    let report = compare(&input, &base);
    assert!(report.is_conformant());
    assert_eq!(report.value_differences.len(), 1);
    assert_eq!(report.value_differences[0].field, "svn");
}

#[test]
fn svn_type_change_is_a_structural_mismatch() {
    let base = corim_with(vec![0xAA; 48], SvnChoice::MinValue(1), "MRTD");
    let input = corim_with(vec![0xAA; 48], SvnChoice::ExactValue(1), "MRTD");
    let report = compare(&input, &base);
    assert!(!report.is_conformant(), "exact vs min svn is structural");
    assert_eq!(report.structural_mismatches.len(), 1);
    assert!(matches!(
        report.structural_mismatches[0].kind,
        MismatchKind::TypeMismatch { .. }
    ));
}

#[test]
fn missing_measurement_in_input_is_a_structural_mismatch() {
    // Baseline has a measurement keyed "MRTD"; input keys it "OTHER" →
    // baseline's MRTD is missing, input's OTHER is unexpected.
    let base = corim_with(vec![0xAA; 48], SvnChoice::MinValue(1), "MRTD");
    let input = corim_with(vec![0xAA; 48], SvnChoice::MinValue(1), "OTHER");
    let report = compare(&input, &base);
    assert!(!report.is_conformant());
    let kinds: Vec<_> = report
        .structural_mismatches
        .iter()
        .map(|m| &m.kind)
        .collect();
    assert!(kinds.contains(&&MismatchKind::MissingInInput));
    assert!(kinds.contains(&&MismatchKind::UnexpectedInInput));
}

#[test]
fn missing_svn_field_in_input_is_a_structural_mismatch() {
    let base = corim_with(vec![0xAA; 48], SvnChoice::MinValue(1), "MRTD");
    // Build an input without an svn field.
    let env = EnvironmentMap {
        class: Some(ClassMap {
            class_id: None,
            vendor: Some("Intel".into()),
            model: Some("TDX".into()),
            layer: None,
            index: None,
        }),
        instance: None,
        group: None,
    };
    let meas = MeasurementMap {
        mkey: Some(MeasuredElement::Text("MRTD".into())),
        mval: MeasurementValuesMap {
            digests: Some(vec![Digest::new(7, vec![0xAA; 48])]),
            svn: None,
            ..MeasurementValuesMap::default()
        },
        authorized_by: None,
    };
    let comid = ComidBuilder::new(TagIdChoice::Text("c1".into()))
        .add_reference_triple(ReferenceTriple::new(env, vec![meas]))
        .build()
        .unwrap();
    let bytes = CorimBuilder::new(CorimId::Text("corim-1".into()))
        .add_comid_tag(comid)
        .unwrap()
        .build_bytes()
        .unwrap();
    let input = corim::validate::decode_and_validate(&bytes).unwrap().0;

    let report = compare(&input, &base);
    assert!(
        !report.is_conformant(),
        "svn present in baseline, absent in input"
    );
    assert!(report
        .structural_mismatches
        .iter()
        .any(|m| m.kind == MismatchKind::MissingInInput));
}

/// A conditional-endorsement-series triple's series `addition` digest is
/// compared: differing bytes are a value difference (still conformant).
#[test]
fn ces_series_addition_digest_is_compared() {
    use corim::types::triples::{
        CesCommonCondition, ConditionalEndorsementSeriesTriple, ConditionalSeriesRecord,
    };

    fn ces_corim(addition_digest: Vec<u8>) -> CorimMap {
        let env = EnvironmentMap {
            class: Some(ClassMap {
                class_id: None,
                vendor: Some("Intel".into()),
                model: Some("TDX".into()),
                layer: None,
                index: None,
            }),
            instance: None,
            group: None,
        };
        let cond_meas = MeasurementMap {
            mkey: Some(MeasuredElement::Text("cond".into())),
            mval: MeasurementValuesMap {
                svn: Some(SvnChoice::MinValue(1)),
                ..MeasurementValuesMap::default()
            },
            authorized_by: None,
        };
        let add_meas = MeasurementMap {
            mkey: Some(MeasuredElement::Text("add".into())),
            mval: MeasurementValuesMap {
                digests: Some(vec![Digest::new(7, addition_digest)]),
                ..MeasurementValuesMap::default()
            },
            authorized_by: None,
        };
        let ces = ConditionalEndorsementSeriesTriple::new(
            CesCommonCondition {
                environment: env,
                claims_list: vec![],
                authorized_by: None,
            },
            vec![ConditionalSeriesRecord::new(
                vec![cond_meas],
                vec![add_meas],
            )],
        );
        let comid = ComidBuilder::new(TagIdChoice::Text("c1".into()))
            .add_conditional_endorsement_series(ces)
            .build()
            .unwrap();
        let bytes = CorimBuilder::new(CorimId::Text("corim-1".into()))
            .add_comid_tag(comid)
            .unwrap()
            .build_bytes()
            .unwrap();
        corim::validate::decode_and_validate(&bytes).unwrap().0
    }

    let base = ces_corim(vec![0xAA; 48]);
    let same = ces_corim(vec![0xAA; 48]);
    let diff = ces_corim(vec![0xBB; 48]);

    assert!(compare(&same, &base).value_differences.is_empty());
    let report = compare(&diff, &base);
    assert!(report.is_conformant(), "CES digest bytes may differ");
    assert_eq!(
        report.value_differences.len(),
        1,
        "CES addition digest compared"
    );
    assert_eq!(report.value_differences[0].field, "digest-value");
}
