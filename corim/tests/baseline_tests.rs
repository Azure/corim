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

/// `profile` is structural: a differing profile means the documents follow
/// different structures and must fail conformance, not pass as a value diff.
#[test]
fn profile_difference_is_a_structural_mismatch() {
    use corim::types::corim::ProfileChoice;

    fn corim_with_profile(profile: &str) -> CorimMap {
        let comid = ComidBuilder::new(TagIdChoice::Text("c1".into()))
            .add_reference_triple(ReferenceTriple::new(
                EnvironmentMap {
                    class: Some(ClassMap {
                        class_id: None,
                        vendor: Some("Intel".into()),
                        model: Some("TDX".into()),
                        layer: None,
                        index: None,
                    }),
                    instance: None,
                    group: None,
                },
                vec![MeasurementMap {
                    mkey: Some(MeasuredElement::Text("MRTD".into())),
                    mval: MeasurementValuesMap {
                        svn: Some(SvnChoice::MinValue(1)),
                        ..MeasurementValuesMap::default()
                    },
                    authorized_by: None,
                }],
            ))
            .build()
            .unwrap();
        let bytes = CorimBuilder::new(CorimId::Text("corim-1".into()))
            .set_profile(ProfileChoice::Uri(profile.into()))
            .add_comid_tag(comid)
            .unwrap()
            .build_bytes()
            .unwrap();
        corim::validate::decode_and_validate(&bytes).unwrap().0
    }

    let base = corim_with_profile("https://example.com/profile/a");
    let input = corim_with_profile("https://example.com/profile/b");
    let report = compare(&input, &base);
    assert!(!report.is_conformant(), "differing profile is structural");
    assert!(report
        .structural_mismatches
        .iter()
        .any(|m| matches!(m.kind, MismatchKind::TypeMismatch { .. })));
    assert!(report.value_differences.is_empty());
}

/// Distinct `mval-extension` keys (incl. negative ones) must not collapse
/// onto the same rendered path.
#[test]
fn mval_extension_keys_render_distinctly() {
    use corim::baseline::render_path;
    use corim::cbor::value::Value;

    fn corim_with_ext(entries: &[(i64, Value)]) -> CorimMap {
        let mut extra = std::collections::BTreeMap::new();
        for (k, v) in entries {
            extra.insert(*k, v.clone());
        }
        let comid = ComidBuilder::new(TagIdChoice::Text("c1".into()))
            .add_reference_triple(ReferenceTriple::new(
                EnvironmentMap {
                    class: Some(ClassMap {
                        class_id: None,
                        vendor: Some("Intel".into()),
                        model: Some("TDX".into()),
                        layer: None,
                        index: None,
                    }),
                    instance: None,
                    group: None,
                },
                vec![MeasurementMap {
                    mkey: Some(MeasuredElement::Text("MRTD".into())),
                    mval: MeasurementValuesMap {
                        svn: Some(SvnChoice::MinValue(1)),
                        extra_entries: extra,
                        ..MeasurementValuesMap::default()
                    },
                    authorized_by: None,
                }],
            ))
            .build()
            .unwrap();
        let bytes = CorimBuilder::new(CorimId::Text("corim-1".into()))
            .add_comid_tag(comid)
            .unwrap()
            .build_bytes()
            .unwrap();
        corim::validate::decode_and_validate(&bytes).unwrap().0
    }

    // Baseline carries two distinct extension keys; input has neither.
    let base = corim_with_ext(&[(-1, Value::Integer(10)), (-2, Value::Integer(20))]);
    let input = corim_with_ext(&[]);
    let report = compare(&input, &base);

    let ext_paths: Vec<String> = report
        .structural_mismatches
        .iter()
        .filter(|m| m.kind == MismatchKind::MissingInInput)
        .map(|m| render_path(&m.path))
        .filter(|p| p.contains("mval-extension"))
        .collect();
    assert!(
        ext_paths.iter().any(|p| p.ends_with("[-1]")),
        "{ext_paths:?}"
    );
    assert!(
        ext_paths.iter().any(|p| p.ends_with("[-2]")),
        "{ext_paths:?}"
    );
    // The two keys must not collapse onto one path.
    assert_eq!(
        ext_paths.len(),
        2,
        "distinct keys, distinct paths: {ext_paths:?}"
    );
}

/// A measurement's `authorized-by` (authority keys) is structural: dropping,
/// adding, or changing it must fail conformance.
#[test]
fn measurement_authorized_by_difference_is_structural() {
    use corim::types::common::CryptoKey;

    fn corim_with_authority(authority: Option<CryptoKey>) -> CorimMap {
        let comid = ComidBuilder::new(TagIdChoice::Text("c1".into()))
            .add_reference_triple(ReferenceTriple::new(
                EnvironmentMap {
                    class: Some(ClassMap {
                        class_id: None,
                        vendor: Some("Intel".into()),
                        model: Some("TDX".into()),
                        layer: None,
                        index: None,
                    }),
                    instance: None,
                    group: None,
                },
                vec![MeasurementMap {
                    mkey: Some(MeasuredElement::Text("MRTD".into())),
                    mval: MeasurementValuesMap {
                        svn: Some(SvnChoice::MinValue(1)),
                        ..MeasurementValuesMap::default()
                    },
                    authorized_by: authority.map(|k| vec![k]),
                }],
            ))
            .build()
            .unwrap();
        let bytes = CorimBuilder::new(CorimId::Text("corim-1".into()))
            .add_comid_tag(comid)
            .unwrap()
            .build_bytes()
            .unwrap();
        corim::validate::decode_and_validate(&bytes).unwrap().0
    }

    let base = corim_with_authority(Some(CryptoKey::PkixBase64Key("KEY-A".into())));

    // Same authority → conformant.
    let same = corim_with_authority(Some(CryptoKey::PkixBase64Key("KEY-A".into())));
    assert!(compare(&same, &base).is_conformant());

    // Changed authority → structural mismatch.
    let changed = corim_with_authority(Some(CryptoKey::PkixBase64Key("KEY-B".into())));
    let report = compare(&changed, &base);
    assert!(!report.is_conformant(), "changed authority is structural");
    assert!(report.structural_mismatches.iter().any(|m| m
        .path
        .contains(&corim::baseline::PathSegment::Field("authorized-by"))));

    // Dropped authority → structural mismatch.
    let dropped = corim_with_authority(None);
    assert!(
        !compare(&dropped, &base).is_conformant(),
        "dropped authority is structural"
    );
}

// ---------------------------------------------------------------------------
// CoRIM-level and CoMID-level metadata (value differences, not structural)
// ---------------------------------------------------------------------------

/// Build a CoRIM whose CoMID/CoRIM metadata can be varied independently of
/// the triples, so metadata-only deltas can be asserted.
fn corim_with_meta(
    tag_version: u64,
    not_after: i64,
    entity: Option<&str>,
    language: Option<&str>,
) -> CorimMap {
    use corim::types::common::EntityMap;

    let mut comid = ComidBuilder::new(TagIdChoice::Text("c1".into()))
        .set_tag_version(tag_version)
        .add_reference_triple(ReferenceTriple::new(
            EnvironmentMap {
                class: Some(ClassMap {
                    class_id: None,
                    vendor: Some("Intel".into()),
                    model: Some("TDX".into()),
                    layer: None,
                    index: None,
                }),
                instance: None,
                group: None,
            },
            vec![MeasurementMap {
                mkey: Some(MeasuredElement::Text("MRTD".into())),
                mval: MeasurementValuesMap {
                    svn: Some(SvnChoice::MinValue(1)),
                    ..MeasurementValuesMap::default()
                },
                authorized_by: None,
            }],
        ));
    if let Some(lang) = language {
        comid = comid.set_language(lang);
    }
    let comid = comid.build().unwrap();

    let mut builder = CorimBuilder::new(CorimId::Text("corim-1".into()))
        .add_comid_tag(comid)
        .unwrap()
        .set_validity(None, not_after)
        .unwrap();
    if let Some(name) = entity {
        builder = builder.add_entity(EntityMap {
            entity_name: name.into(),
            reg_id: None,
            role: vec![1],
        });
    }
    let bytes = builder.build_bytes().unwrap();
    corim::validate::decode_and_validate(&bytes).unwrap().0
}

#[test]
fn rim_validity_difference_is_a_value_difference() {
    let base = corim_with_meta(1, 1_900_000_000, None, None);
    let input = corim_with_meta(1, 1_950_000_000, None, None);
    let report = compare(&input, &base);
    assert!(report.is_conformant(), "validity may change on re-issue");
    assert!(
        report
            .value_differences
            .iter()
            .any(|v| v.field == "rim-validity"),
        "{:?}",
        report.value_differences
    );
}

#[test]
fn comid_tag_version_difference_is_a_value_difference() {
    let base = corim_with_meta(1, 1_900_000_000, None, None);
    let input = corim_with_meta(2, 1_900_000_000, None, None);
    let report = compare(&input, &base);
    assert!(
        report.is_conformant(),
        "tag-version bumps on every re-issue"
    );
    assert!(
        report
            .value_differences
            .iter()
            .any(|v| v.field == "tag-version"),
        "{:?}",
        report.value_differences
    );
}

#[test]
fn corim_entities_difference_is_a_value_difference() {
    let base = corim_with_meta(1, 1_900_000_000, Some("ACME"), None);
    let input = corim_with_meta(1, 1_900_000_000, Some("Globex"), None);
    let report = compare(&input, &base);
    assert!(report.is_conformant());
    assert!(
        report
            .value_differences
            .iter()
            .any(|v| v.field == "entities"),
        "{:?}",
        report.value_differences
    );
}

#[test]
fn comid_language_difference_is_a_value_difference() {
    let base = corim_with_meta(1, 1_900_000_000, None, Some("en-US"));
    let input = corim_with_meta(1, 1_900_000_000, None, Some("fr-FR"));
    let report = compare(&input, &base);
    assert!(report.is_conformant());
    assert!(
        report
            .value_differences
            .iter()
            .any(|v| v.field == "language"),
        "{:?}",
        report.value_differences
    );
}

#[test]
fn identical_metadata_reports_no_differences() {
    let base = corim_with_meta(3, 1_900_000_000, Some("ACME"), Some("en-US"));
    let input = corim_with_meta(3, 1_900_000_000, Some("ACME"), Some("en-US"));
    let report = compare(&input, &base);
    assert!(report.is_conformant());
    assert!(
        report.value_differences.is_empty(),
        "{:?}",
        report.value_differences
    );
}
