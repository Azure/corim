// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Integration tests for `validate --format json`, covering the `signed`
//! object that mirrors the fields the text renderer shows for a signed CoRIM.

use std::process::Command;

use corim::builder::{ComidBuilder, CorimBuilder};
use corim::types::common::{ClassIdChoice, CryptoKey, MeasuredElement, TagIdChoice};
use corim::types::corim::{CorimId, CorimMetaMap, CorimSignerMap};
use corim::types::environment::{ClassMap, EnvironmentMap};
use corim::types::measurement::{
    Digest, MeasurementMap, MeasurementValuesMap, RawValueChoice, SvnChoice,
};
use corim::types::signed::{CwtClaims, SignedCorimBuilder};
use corim::types::triples::ReferenceTriple;

fn bin() -> &'static str {
    env!("CARGO_BIN_EXE_corim-cli")
}

fn unique_temp(stem: &str, ext: &str) -> std::path::PathBuf {
    use std::sync::atomic::{AtomicU64, Ordering};
    static N: AtomicU64 = AtomicU64::new(0);
    let n = N.fetch_add(1, Ordering::Relaxed);
    std::env::temp_dir().join(format!("corim_cli_{stem}_{}_{n}.{ext}", std::process::id()))
}

fn sample_unsigned_corim() -> Vec<u8> {
    let env = EnvironmentMap {
        class: Some(ClassMap {
            class_id: None,
            vendor: Some("TestVendor".into()),
            model: Some("TestModel".into()),
            layer: None,
            index: None,
        }),
        instance: None,
        group: None,
    };
    let meas = MeasurementMap {
        mkey: Some(MeasuredElement::Text("firmware".into())),
        mval: {
            let __corim_field_0 = Some(SvnChoice::MinValue(1));
            let mut __corim_value: MeasurementValuesMap = MeasurementValuesMap::default();
            __corim_value.svn = __corim_field_0;
            __corim_value
        },
        authorized_by: None,
    };
    let comid = ComidBuilder::new(TagIdChoice::Text("json-comid".into()))
        .add_reference_triple(ReferenceTriple::new(env, vec![meas]))
        .build()
        .unwrap();
    CorimBuilder::new(CorimId::Text("json-corim".into()))
        .add_comid_tag(comid)
        .unwrap()
        .build_bytes()
        .unwrap()
}

fn make_signed(unsigned: &[u8], detached: bool) -> Vec<u8> {
    let builder = SignedCorimBuilder::new(-38, unsigned.to_vec())
        .set_cwt_claims(CwtClaims::new("test-issuer").with_sub("test-subject"))
        .set_corim_meta(CorimMetaMap {
            signer: CorimSignerMap {
                signer_name: "test-issuer".into(),
                signer_uri: None,
            },
            signature_validity: None,
        });
    if detached {
        builder
            .build_detached_with_signature(vec![0xAB; 64])
            .unwrap()
    } else {
        builder.build_with_signature(vec![0xAB; 64]).unwrap()
    }
}

/// Run `validate -f json` on `bytes` and parse the result.
fn validate_json(bytes: &[u8], ext: &str) -> serde_json::Value {
    let path = unique_temp("validate_json", ext);
    std::fs::write(&path, bytes).unwrap();
    let out = Command::new(bin())
        .args(["validate", "-f", "json", path.to_str().unwrap()])
        .output()
        .expect("run validate");
    let _ = std::fs::remove_file(&path);
    let stdout = String::from_utf8(out.stdout).expect("utf-8 stdout");
    let stderr = String::from_utf8_lossy(&out.stderr);
    // Assert the exit status first: otherwise a failing run surfaces as a
    // confusing JSON parse error instead of the real reason.
    assert!(
        out.status.success(),
        "validate exited with {}\nstderr:\n{stderr}\nstdout:\n{stdout}",
        out.status
    );
    serde_json::from_str(&stdout)
        .unwrap_or_else(|e| panic!("output is not valid JSON: {e}\n{stdout}"))
}

fn decoded_json(value: &serde_json::Value) -> corim::cbor::value::Value {
    corim::json::json_to_value(value).unwrap()
}

fn map_entry(
    value: &serde_json::Value,
    key: corim::cbor::value::Value,
) -> corim::cbor::value::Value {
    let corim::cbor::value::Value::Map(entries) = decoded_json(value) else {
        panic!("lossless map");
    };
    entries
        .into_iter()
        .find(|(candidate, _)| *candidate == key)
        .unwrap()
        .1
}

fn validate_json_status(bytes: &[u8], ext: &str) -> (std::process::ExitStatus, serde_json::Value) {
    let path = unique_temp("validate_json_status", ext);
    std::fs::write(&path, bytes).unwrap();
    let out = Command::new(bin())
        .args(["validate", "-f", "json", path.to_str().unwrap()])
        .output()
        .expect("run validate");
    let _ = std::fs::remove_file(&path);
    let stdout = String::from_utf8(out.stdout).expect("utf-8 stdout");
    let parsed = serde_json::from_str(&stdout)
        .unwrap_or_else(|e| panic!("output is not valid JSON: {e}\n{stdout}"));
    (out.status, parsed)
}

fn validate_with_flags(bytes: &[u8], flags: &[&str]) -> std::process::Output {
    let path = unique_temp("strict_validation", "cbor");
    std::fs::write(&path, bytes).unwrap();
    let result = Command::new(bin())
        .arg("validate")
        .arg(&path)
        .args(flags)
        .output()
        .unwrap();
    std::fs::remove_file(path).unwrap();
    result
}

#[test]
fn empty_validation_input_is_invalid_not_an_io_failure() {
    for format in ["text", "json"] {
        for skip in [false, true] {
            let mut flags = vec!["--format", format];
            if skip {
                flags.push("--skip-expiry");
            }
            let output = validate_with_flags(&[], &flags);
            assert_eq!(output.status.code(), Some(2));
            if format == "json" {
                let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
                assert_eq!(report["valid"], false);
                assert!(report["errors"][0].as_str().unwrap().contains("empty"));
            }
        }
    }
    for flag in ["--edn", "--diagnose"] {
        assert_eq!(validate_with_flags(&[], &[flag]).status.code(), Some(1));
    }
}

#[test]
fn baseline_io_failures_are_distinct_from_invalid_content() {
    let missing = unique_temp("missing_baseline", "cbor");
    let invalid = unique_temp("invalid_baseline", "cbor");
    std::fs::write(&invalid, []).unwrap();
    for format in ["text", "json"] {
        for (path, code) in [(&missing, 1), (&std::env::temp_dir(), 1), (&invalid, 2)] {
            let output = validate_with_flags(
                &sample_unsigned_corim(),
                &["--baseline", path.to_str().unwrap(), "--format", format],
            );
            assert_eq!(
                output.status.code(),
                Some(code),
                "{}",
                String::from_utf8_lossy(&output.stdout)
            );
            if format == "json" {
                let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
                assert_eq!(report["valid"], false);
                assert!(!report["errors"].as_array().unwrap().is_empty());
            }
        }
    }
    std::fs::remove_file(invalid).unwrap();
}

#[test]
fn tag_only_documents_validate_all_tags_in_both_time_modes() {
    use corim::cbor::{self, value::Tagged};
    use corim::types::tags::SWID_ROLE_TAG_CREATOR;
    use corim::types::{
        ConciseSwidTag, ConciseTagChoice, ConciseTlTag, SwidEntity, TagIdentity, ValidityMap,
    };
    let swid = ConciseSwidTag::new(
        TagIdChoice::Text("software".into()),
        "Software",
        0,
        vec![SwidEntity::new("issuer", vec![SWID_ROLE_TAG_CREATOR])],
    );
    let cotl = ConciseTlTag {
        tag_identity: TagIdentity {
            tag_id: TagIdChoice::Text("list".into()),
            tag_version: None,
        },
        tags_list: vec![TagIdentity {
            tag_id: TagIdChoice::Text("software".into()),
            tag_version: None,
        }],
        tl_validity: ValidityMap {
            not_before: None,
            not_after: i64::MAX.into(),
        },
    };
    let mut expired = cotl.clone();
    expired.tl_validity.not_after = 1.into();
    for (tag, valid_now, valid_without_clock) in [
        (
            ConciseTagChoice::Coswid(cbor::encode(&swid).unwrap()),
            true,
            true,
        ),
        (
            ConciseTagChoice::Cotl(cbor::encode(&cotl).unwrap()),
            true,
            true,
        ),
        (
            ConciseTagChoice::Cotl(cbor::encode(&expired).unwrap()),
            false,
            true,
        ),
        (ConciseTagChoice::Coswid(vec![0xff]), false, false),
        (ConciseTagChoice::Cotl(vec![0xff]), false, false),
    ] {
        let mut corim: Tagged<corim::types::CorimMap> =
            cbor::decode_exact(&sample_unsigned_corim()).unwrap();
        corim.value.tags = vec![tag];
        let payload = cbor::encode(&corim).unwrap();
        if valid_now {
            let limits = cbor::DecodeLimits::default();
            assert!(matches!(
                corim::validate::decode_and_validate_full_at_with_limits(&payload, 100, &limits),
                Err(corim::ValidationError::NoComidTags)
            ));
            assert!(
                corim::validate::decode_and_validate_document_at_with_limits(
                    &payload, 100, &limits
                )
                .is_ok()
            );
        }
        for signed in [false, true] {
            let bytes = if signed {
                make_signed(&payload, false)
            } else {
                payload.clone()
            };
            for skip in [false, true] {
                for format in ["text", "json"] {
                    let mut flags = vec!["--format", format];
                    if skip {
                        flags.push("--skip-expiry");
                    }
                    let output = validate_with_flags(&bytes, &flags);
                    let valid = if skip { valid_without_clock } else { valid_now };
                    assert_eq!(
                        output.status.code(),
                        Some(if !valid {
                            2
                        } else if skip {
                            4
                        } else {
                            0
                        }),
                        "signed={signed} skip={skip}: {}{}",
                        String::from_utf8_lossy(&output.stdout),
                        String::from_utf8_lossy(&output.stderr)
                    );
                    if format == "json" {
                        let report: serde_json::Value =
                            serde_json::from_slice(&output.stdout).unwrap();
                        if valid {
                            assert_eq!(report["comid_count"], 0);
                        } else {
                            assert_eq!(report["valid"], false);
                        }
                    }
                }
            }
        }
    }
}

#[test]
fn validity_nulls_are_rejected_without_changing_tolerant_inspection() {
    use corim::cbor::{
        self,
        value::{Tagged, Value},
    };
    use corim::types::tags::*;
    use corim::types::{ConciseTagChoice, ConciseTlTag, TagIdentity, ValidityMap};
    let limits = cbor::DecodeLimits::default();
    for location in ["rim-validity", "rim not-before", "cotl not-before"] {
        for null in [true, false] {
            let mut validity = vec![(
                Value::Integer(VALIDITY_KEY_NOT_AFTER.into()),
                Value::Tag(TAG_EPOCH_TIME, Box::new(Value::Integer(i64::MAX.into()))),
            )];
            if null {
                validity.push((Value::Integer(VALIDITY_KEY_NOT_BEFORE.into()), Value::Null));
            }
            let mut corim: Tagged<corim::types::CorimMap> =
                cbor::decode_exact(&sample_unsigned_corim()).unwrap();
            if location == "cotl not-before" {
                let identity = TagIdentity {
                    tag_id: TagIdChoice::Text("list".into()),
                    tag_version: None,
                };
                let cotl = ConciseTlTag {
                    tag_identity: identity.clone(),
                    tags_list: vec![identity],
                    tl_validity: ValidityMap {
                        not_before: None,
                        not_after: i64::MAX.into(),
                    },
                };
                let Value::Map(mut entries) =
                    cbor::decode_exact(&cbor::encode(&cotl).unwrap()).unwrap()
                else {
                    panic!("CoTL map");
                };
                entries.retain(|(key, _)| *key != Value::Integer(COTL_KEY_VALIDITY.into()));
                entries.push((
                    Value::Integer(COTL_KEY_VALIDITY.into()),
                    Value::Map(validity.clone()),
                ));
                let bytes = cbor::encode(&Value::Map(entries)).unwrap();
                assert!(cbor::decode_exact::<ConciseTlTag>(&bytes).is_ok());
                corim.value.tags.push(ConciseTagChoice::Cotl(bytes));
            }
            let Value::Tag(tag, map) = cbor::decode_exact(&cbor::encode(&corim).unwrap()).unwrap()
            else {
                panic!("tagged CoRIM");
            };
            let Value::Map(mut entries) = *map else {
                panic!("CoRIM map");
            };
            if location == "rim-validity" && null {
                entries.push((Value::Integer(CORIM_KEY_RIM_VALIDITY.into()), Value::Null));
            } else if location == "rim not-before" {
                entries.push((
                    Value::Integer(CORIM_KEY_RIM_VALIDITY.into()),
                    Value::Map(validity),
                ));
            }
            let payload = cbor::encode(&Value::Tag(tag, Box::new(Value::Map(entries)))).unwrap();
            assert!(cbor::decode_exact::<Tagged<corim::types::CorimMap>>(&payload).is_ok());
            assert_eq!(
                corim::validate::decode_and_validate_structure_with_limits(&payload, &limits)
                    .is_ok(),
                !null,
                "{location}"
            );
            assert_eq!(
                corim::validate::decode_and_validate_document_at_with_limits(
                    &payload, 100, &limits
                )
                .is_ok(),
                !null,
                "{location}"
            );
            assert_eq!(
                corim::validate::decode_and_validate_full_at_with_limits(&payload, 100, &limits)
                    .is_ok(),
                !null,
                "{location}"
            );
            for bytes in [payload.clone(), make_signed(&payload, false)] {
                assert!(validate_with_flags(&bytes, &["--edn"]).status.success());
                for skip in [false, true] {
                    let mut flags = vec!["--format", "json"];
                    if skip {
                        flags.push("--skip-expiry");
                    }
                    let output = validate_with_flags(&bytes, &flags);
                    assert_eq!(
                        output.status.code(),
                        Some(if null {
                            2
                        } else if skip {
                            4
                        } else {
                            0
                        }),
                        "{location}, skip={skip}: {}",
                        String::from_utf8_lossy(&output.stdout)
                    );
                    if null {
                        let report: serde_json::Value =
                            serde_json::from_slice(&output.stdout).unwrap();
                        assert_eq!(report["valid"], false);
                        assert!(report["errors"][0].as_str().unwrap().contains("validity"));
                    }
                }
            }
        }
    }
}

#[test]
fn validation_modes_reject_invalid_and_incomplete_documents() {
    use corim::cbor::{self, value::Tagged};
    use corim::types::tags::TAG_CORIM;
    let payload = sample_unsigned_corim();
    let build = |payload: Vec<u8>, claims: CwtClaims| {
        SignedCorimBuilder::new(-38, payload)
            .set_cwt_claims(claims)
            .build_with_signature(vec![1; 64])
            .unwrap()
    };
    let mut corim: Tagged<corim::types::CorimMap> = cbor::decode_exact(&payload).unwrap();
    corim
        .value
        .tags
        .push(corim::types::ConciseTagChoice::Cotl(vec![0xff]));
    let malformed_cotl = cbor::encode(&Tagged {
        tag: TAG_CORIM,
        value: corim.value,
    })
    .unwrap();
    let mut future: Tagged<corim::types::CorimMap> = cbor::decode_exact(&payload).unwrap();
    future.value.rim_validity = Some(corim::types::ValidityMap {
        not_before: Some(i64::MAX.into()),
        not_after: i64::MAX.into(),
    });
    for (name, bytes) in [
        (
            "malformed signed payload",
            build(vec![0xff], CwtClaims::new("issuer")),
        ),
        (
            "expired header",
            build(payload.clone(), CwtClaims::new("issuer").with_exp(1)),
        ),
        (
            "future header",
            build(payload.clone(), CwtClaims::new("issuer").with_nbf(i64::MAX)),
        ),
        (
            "conflicting issuer",
            SignedCorimBuilder::new(-38, payload.clone())
                .set_cwt_claims(CwtClaims::new("issuer"))
                .set_corim_meta(CorimMetaMap {
                    signer: CorimSignerMap {
                        signer_name: "other".into(),
                        signer_uri: None,
                    },
                    signature_validity: None,
                })
                .build_with_signature(vec![1; 64])
                .unwrap(),
        ),
        (
            "detached payload",
            SignedCorimBuilder::new(-38, payload.clone())
                .set_cwt_claims(CwtClaims::new("issuer"))
                .build_detached_with_signature(vec![1; 64])
                .unwrap(),
        ),
        ("malformed CoTL", malformed_cotl),
        ("future rim", cbor::encode(&future).unwrap()),
    ] {
        for format in ["text", "json"] {
            let output = validate_with_flags(&bytes, &["--format", format]);
            assert_eq!(
                output.status.code(),
                Some(2),
                "{name}: {}",
                String::from_utf8_lossy(&output.stdout)
            );
            if format == "json" {
                let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
                assert_eq!(report["valid"], false, "{name}");
                assert!(!report["errors"].as_array().unwrap().is_empty());
            }
        }
    }
}

#[test]
fn skip_expiry_reports_partial_validation_without_hiding_structure_errors() {
    let payload = sample_unsigned_corim();
    for malformed in [false, true] {
        let bytes = SignedCorimBuilder::new(
            -38,
            if malformed {
                vec![0xff]
            } else {
                payload.clone()
            },
        )
        .set_cwt_claims(CwtClaims::new("issuer").with_exp(1))
        .build_with_signature(vec![1; 64])
        .unwrap();
        let output = validate_with_flags(&bytes, &["--format", "json", "--skip-expiry"]);
        assert_eq!(output.status.code(), Some(if malformed { 2 } else { 4 }));
        let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
        assert_eq!(report["time_validated"], false);
        if malformed {
            assert_eq!(report["valid"], false);
        } else {
            assert!(report["valid"].is_null());
        }
    }
    let output = validate_with_flags(&sample_unsigned_corim(), &["--skip-expiry"]);
    assert_eq!(output.status.code(), Some(4));
    assert!(String::from_utf8(output.stdout)
        .unwrap()
        .contains("temporal checks skipped"));
}

#[test]
fn skip_expiry_skips_rim_and_cotl_clocks_but_not_profile_or_header_rules() {
    use corim::cbor::{self, value::Tagged};
    let mut corim: Tagged<corim::types::CorimMap> =
        cbor::decode_exact(&sample_unsigned_corim()).unwrap();
    corim.value.rim_validity = Some(corim::types::ValidityMap {
        not_before: None,
        not_after: 1.into(),
    });
    let cotl = corim::types::ConciseTlTag {
        tag_identity: corim::types::TagIdentity {
            tag_id: TagIdChoice::Text("list".into()),
            tag_version: None,
        },
        tags_list: vec![corim::types::TagIdentity {
            tag_id: TagIdChoice::Text("json-comid".into()),
            tag_version: None,
        }],
        tl_validity: corim::types::ValidityMap {
            not_before: None,
            not_after: 1.into(),
        },
    };
    corim.value.tags.push(corim::types::ConciseTagChoice::Cotl(
        cbor::encode(&cotl).unwrap(),
    ));
    let bytes = cbor::encode(&corim).unwrap();
    assert_eq!(validate_with_flags(&bytes, &[]).status.code(), Some(2));
    let output = validate_with_flags(&bytes, &["--skip-expiry", "-f", "json"]);
    assert_eq!(
        output.status.code(),
        Some(4),
        "{}",
        String::from_utf8_lossy(&output.stdout)
    );
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert!(report["valid"].is_null());
    assert_eq!(report["time_validated"], false);
    let invalid_profile = cca_platform_corim(vec![cca_software_component()]);
    assert_eq!(
        validate_with_flags(&invalid_profile, &["--skip-expiry"])
            .status
            .code(),
        Some(2)
    );
    let invalid_header = SignedCorimBuilder::new(-38, sample_unsigned_corim())
        .set_cwt_claims(CwtClaims::new("issuer").with_exp(1))
        .set_content_type("text/plain")
        .build_with_signature(vec![1; 64])
        .unwrap();
    assert_eq!(
        validate_with_flags(&invalid_header, &["--skip-expiry"])
            .status
            .code(),
        Some(2)
    );
}

#[test]
fn baseline_rejects_uncompared_tags_on_either_side() {
    use corim::cbor::{self, value::Tagged};
    use corim::types::tags::SWID_ROLE_TAG_CREATOR;
    use corim::types::{
        ConciseSwidTag, ConciseTagChoice, ConciseTlTag, SwidEntity, TagIdentity, ValidityMap,
    };
    let normal = sample_unsigned_corim();
    for coswid in [false, true] {
        for mixed in [false, true] {
            let documents: Vec<Vec<u8>> = ["first", "second"]
                .into_iter()
                .map(|name| {
                    let tag = if coswid {
                        ConciseTagChoice::Coswid(
                            cbor::encode(&ConciseSwidTag::new(
                                TagIdChoice::Text(name.into()),
                                name,
                                0,
                                vec![SwidEntity::new("issuer", vec![SWID_ROLE_TAG_CREATOR])],
                            ))
                            .unwrap(),
                        )
                    } else {
                        let identity = TagIdentity {
                            tag_id: TagIdChoice::Text(name.into()),
                            tag_version: None,
                        };
                        ConciseTagChoice::Cotl(
                            cbor::encode(&ConciseTlTag {
                                tag_identity: identity.clone(),
                                tags_list: vec![identity],
                                tl_validity: ValidityMap {
                                    not_before: None,
                                    not_after: i64::MAX.into(),
                                },
                            })
                            .unwrap(),
                        )
                    };
                    let mut document: Tagged<corim::types::CorimMap> =
                        cbor::decode_exact(&normal).unwrap();
                    if !mixed {
                        document.value.tags.clear();
                    }
                    document.value.tags.push(tag);
                    cbor::encode(&document).unwrap()
                })
                .collect();
            for (target, baseline) in [
                (&documents[0], &documents[1]),
                (&normal, &documents[0]),
                (&documents[0], &normal),
            ] {
                for signed in [false, true] {
                    let target = if signed {
                        make_signed(target, false)
                    } else {
                        target.clone()
                    };
                    let baseline = if signed {
                        make_signed(baseline, false)
                    } else {
                        baseline.clone()
                    };
                    assert!(validate_with_flags(&target, &[]).status.success());
                    assert!(validate_with_flags(&baseline, &[]).status.success());
                    let path = unique_temp("unsupported_baseline", "cbor");
                    std::fs::write(&path, baseline).unwrap();
                    for skip in [false, true] {
                        for format in ["text", "json"] {
                            let mut flags =
                                vec!["--baseline", path.to_str().unwrap(), "--format", format];
                            if skip {
                                flags.push("--skip-expiry");
                            }
                            let output = validate_with_flags(&target, &flags);
                            assert_eq!(
                                output.status.code(),
                                Some(2),
                                "coswid={coswid}, mixed={mixed}, signed={signed}: {}",
                                String::from_utf8_lossy(&output.stdout)
                            );
                            if format == "json" {
                                let report: serde_json::Value =
                                    serde_json::from_slice(&output.stdout).unwrap();
                                assert_eq!(report["valid"], false);
                                assert!(report["errors"][0]
                                    .as_str()
                                    .unwrap()
                                    .contains("unsupported"));
                            }
                        }
                    }
                    std::fs::remove_file(path).unwrap();
                }
            }
        }
    }
}

#[test]
fn lossless_json_baselines_reject_invalid_validity_fields() {
    use corim::cbor::{self, value::Value};
    use corim::types::tags::{
        CORIM_KEY_RIM_VALIDITY, CORIM_KEY_TAGS, COTL_KEY_VALIDITY, TAG_COTL, TAG_EPOCH_TIME,
        VALIDITY_KEY_NOT_AFTER, VALIDITY_KEY_NOT_BEFORE,
    };
    for cotl in [false, true] {
        for (value, valid) in [
            (None, true),
            (Some(Value::Integer(0)), true),
            (
                Some(Value::Tag(TAG_EPOCH_TIME, Box::new(Value::Integer(0)))),
                true,
            ),
            (Some(Value::Null), false),
            (Some(Value::Text("invalid".into())), false),
            (Some(Value::Integer(u64::MAX.into())), false),
            (Some(Value::Float(0.5)), false),
            (Some(Value::Bool(true)), false),
            (
                Some(Value::Tag(TAG_EPOCH_TIME, Box::new(Value::Null))),
                false,
            ),
        ] {
            let mut baseline: Value = cbor::decode_exact(&sample_unsigned_corim()).unwrap();
            let Value::Tag(_, root) = &mut baseline else {
                panic!("CoRIM tag");
            };
            let Value::Map(fields) = root.as_mut() else {
                panic!("CoRIM map");
            };
            let mut validity = vec![(
                Value::Integer(VALIDITY_KEY_NOT_AFTER.into()),
                Value::Integer(i64::MAX.into()),
            )];
            if let Some(value) = value {
                validity.push((Value::Integer(VALIDITY_KEY_NOT_BEFORE.into()), value));
            }
            let validity = Value::Map(validity);
            if cotl {
                let tl = corim::types::ConciseTlTag {
                    tag_identity: corim::types::TagIdentity {
                        tag_id: TagIdChoice::Text("list".into()),
                        tag_version: None,
                    },
                    tags_list: vec![corim::types::TagIdentity {
                        tag_id: TagIdChoice::Text("member".into()),
                        tag_version: None,
                    }],
                    tl_validity: corim::types::ValidityMap {
                        not_before: None,
                        not_after: i64::MAX.into(),
                    },
                };
                let Value::Map(mut tl) = cbor::value::to_value(&tl).unwrap() else {
                    panic!("CoTL");
                };
                tl.iter_mut()
                    .find(|(key, _)| *key == Value::Integer(COTL_KEY_VALIDITY.into()))
                    .unwrap()
                    .1 = validity;
                let (_, Value::Array(tags)) = fields
                    .iter_mut()
                    .find(|(key, _)| *key == Value::Integer(CORIM_KEY_TAGS.into()))
                    .unwrap()
                else {
                    panic!("tags");
                };
                tags.push(Value::Tag(
                    TAG_COTL,
                    Box::new(Value::Bytes(cbor::encode(&Value::Map(tl)).unwrap())),
                ));
            } else {
                fields.push((Value::Integer(CORIM_KEY_RIM_VALIDITY.into()), validity));
            }
            let baseline = corim::json::value_to_json(&baseline).unwrap();
            let path = unique_temp("json_validity_baseline", "json");
            let generated = unique_temp("json_validity_generated", "cbor");
            std::fs::write(&path, serde_json::to_vec(&baseline).unwrap()).unwrap();
            for skip in [false, true] {
                let mut flags = vec!["--baseline", path.to_str().unwrap(), "--format", "json"];
                if skip {
                    flags.push("--skip-expiry");
                }
                let output = validate_with_flags(&sample_unsigned_corim(), &flags);
                let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
                assert_eq!(
                    output.status.code(),
                    Some(if !valid || cotl {
                        2
                    } else if skip {
                        4
                    } else {
                        0
                    }),
                    "cotl={cotl}, skip={skip}, baseline={baseline}: {report}"
                );
                if !valid {
                    assert_eq!(report["valid"], false);
                    let message = report["errors"][0].as_str().unwrap();
                    assert!(
                        !message.contains("unsupported"),
                        "invalid timestamp escaped conversion: {message}"
                    );
                } else if cotl {
                    assert!(report["errors"][0]
                        .as_str()
                        .unwrap()
                        .contains("unsupported"));
                }
            }
            let output = Command::new(bin())
                .args([
                    "generate",
                    path.to_str().unwrap(),
                    "-o",
                    generated.to_str().unwrap(),
                ])
                .output()
                .unwrap();
            assert_eq!(
                output.status.success(),
                valid,
                "baseline={baseline}: {}",
                String::from_utf8_lossy(&output.stderr)
            );
            if valid {
                std::fs::remove_file(generated).unwrap();
            }
            std::fs::remove_file(path).unwrap();
        }
    }
}

#[test]
fn baseline_nonfinite_differences_preserve_float_bits() {
    use corim::cbor::{self, value::Tagged};
    use corim::types::matcher::{Number, NumberMatcher};
    let make = |number| {
        let mut document: Tagged<corim::types::CorimMap> =
            cbor::decode_exact(&sample_unsigned_corim()).unwrap();
        let mut comid = document.value.tags[0].as_comid().unwrap();
        comid.triples.reference_triples.as_mut().unwrap()[0].1[0]
            .mval
            .number = Some(NumberMatcher::Exact(Number::Float(number)));
        document.value.tags[0] =
            corim::types::ConciseTagChoice::Comid(cbor::encode(&comid).unwrap());
        cbor::encode(&document).unwrap()
    };
    let baseline_number = f64::from_bits(0x7ff8_0000_0000_0042);
    let path = unique_temp("baseline_float_bits", "cbor");
    std::fs::write(&path, make(baseline_number)).unwrap();
    let output = validate_with_flags(
        &make(f64::INFINITY),
        &["--baseline", path.to_str().unwrap(), "-f", "json"],
    );
    std::fs::remove_file(path).unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stdout)
    );
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    let difference = report["value_differences"]
        .as_array()
        .unwrap()
        .iter()
        .find(|value| value["field"] == "number")
        .unwrap();
    assert_eq!(difference["baseline"]["type"], "float-bits");
    assert_eq!(
        difference["baseline"]["value"],
        format!("{:016x}", baseline_number.to_bits())
    );
    assert_eq!(
        difference["input"]["value"],
        format!("{:016x}", f64::INFINITY.to_bits())
    );
}

#[test]
fn signed_header_json_and_baselines_preserve_labels_and_fractional_times() {
    use corim::cbor::value::Value;
    use corim::types::signed::NumericDate;
    let make = |expiration, extension| {
        SignedCorimBuilder::new(-7, sample_unsigned_corim())
            .set_cwt_claims(CwtClaims::new("issuer").with_exp(NumericDate::Float(expiration)))
            .add_protected(10001, Value::Integer(1))
            .add_protected("10001", extension)
            .build_with_signature(vec![0; 64])
            .unwrap()
    };
    let baseline = make(2_000_000_000.25, Value::Integer(1));
    let report = validate_json(&baseline, "cose");
    let protected = &report["signed"]["protected"];
    assert_eq!(
        decoded_json(&protected["exp"]),
        Value::Float(2_000_000_000.25)
    );
    assert_eq!(
        map_entry(&protected["header_extra"], Value::Integer(10001)),
        Value::Integer(1)
    );
    assert_eq!(
        map_entry(&protected["header_extra"], Value::Text("10001".into())),
        Value::Integer(1)
    );
    let path = unique_temp("lossless_header", "cose");
    std::fs::write(&path, &baseline).unwrap();
    for (candidate, expected_exit, expected_result) in [
        (
            make(2_000_000_000.75, Value::Integer(1)),
            0,
            "value-differences",
        ),
        (
            make(2_000_000_000.25, Value::Text("changed".into())),
            3,
            "structural-mismatch",
        ),
    ] {
        let output = validate_with_flags(
            &candidate,
            &["--baseline", path.to_str().unwrap(), "-f", "json"],
        );
        let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
        assert_eq!(output.status.code(), Some(expected_exit), "{report}");
        assert_eq!(report["result"], expected_result, "{report}");
    }
    std::fs::remove_file(path).unwrap();
}

#[test]
fn baselines_use_same_time_and_structural_policy_as_input() {
    use corim::cbor::{self, value::Tagged};
    let target = sample_unsigned_corim();
    let mut baseline: Tagged<corim::types::CorimMap> = cbor::decode_exact(&target).unwrap();
    baseline.value.rim_validity = Some(corim::types::ValidityMap {
        not_before: None,
        not_after: 1.into(),
    });
    let json = corim::json::to_json(&baseline).unwrap().into_bytes();
    for bytes in [cbor::encode(&baseline).unwrap(), json] {
        let path = unique_temp("expired_baseline", "data");
        std::fs::write(&path, bytes).unwrap();
        let output = validate_with_flags(
            &target,
            &["--baseline", path.to_str().unwrap(), "-f", "json"],
        );
        assert_eq!(output.status.code(), Some(2));
        let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
        assert_eq!(report["valid"], false);
        let output = validate_with_flags(
            &target,
            &[
                "--baseline",
                path.to_str().unwrap(),
                "--skip-expiry",
                "-f",
                "json",
            ],
        );
        assert_eq!(
            output.status.code(),
            Some(4),
            "{}",
            String::from_utf8_lossy(&output.stdout)
        );
        let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
        assert_eq!(report["time_validated"], false);
        std::fs::remove_file(path).unwrap();
    }
    let malformed = SignedCorimBuilder::new(-38, vec![0xff])
        .set_cwt_claims(CwtClaims::new("issuer"))
        .build_with_signature(vec![1; 64])
        .unwrap();
    let path = unique_temp("invalid_baseline", "cose");
    std::fs::write(&path, malformed).unwrap();
    assert_eq!(
        validate_with_flags(
            &target,
            &["--baseline", path.to_str().unwrap(), "--skip-expiry"]
        )
        .status
        .code(),
        Some(2)
    );
    std::fs::remove_file(path).unwrap();
}

#[test]
fn nonpreferred_signed_tag_is_validated_without_unsigned_fallback() {
    let mut bytes = make_signed(&sample_unsigned_corim(), false);
    assert_eq!(bytes.remove(0), 0xd2);
    bytes.splice(..0, [0xd8, 18]);
    let output = validate_with_flags(&bytes, &["-f", "json"]);
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stdout)
    );
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(report["valid"], true);
    assert_eq!(report["time_validated"], true);
    assert_eq!(report["signed"]["signature_verified"], false);
}

fn cca_platform_environment() -> EnvironmentMap {
    EnvironmentMap {
        class: Some(ClassMap {
            class_id: Some(ClassIdChoice::Bytes(vec![0x5A; 32])),
            ..ClassMap::default()
        }),
        instance: None,
        group: None,
    }
}

fn cca_software_component() -> MeasurementMap {
    MeasurementMap {
        mkey: Some(MeasuredElement::Text("cca.software-component".into())),
        mval: {
            let __corim_field_0 = Some(vec![Digest::new_text("sha-256", vec![0x11; 32])]);

            let __corim_field_1 = Some(vec![CryptoKey::Bytes(vec![0xAA; 32])]);
            let mut __corim_value: MeasurementValuesMap = MeasurementValuesMap::default();
            __corim_value.digests = __corim_field_0;
            __corim_value.cryptokeys = __corim_field_1;
            __corim_value
        },
        authorized_by: None,
    }
}

fn cca_platform_config() -> MeasurementMap {
    MeasurementMap {
        mkey: Some(MeasuredElement::Text("cca.platform-config".into())),
        mval: {
            let __corim_field_0 = Some(RawValueChoice::Masked {
                value: vec![0xA0, 0x05],
                mask: vec![0xF0, 0x00],
            });
            let mut __corim_value: MeasurementValuesMap = MeasurementValuesMap::default();
            __corim_value.raw_value = __corim_field_0;
            __corim_value
        },
        authorized_by: None,
    }
}

fn cca_platform_corim(measurements: Vec<MeasurementMap>) -> Vec<u8> {
    let comid = ComidBuilder::new(TagIdChoice::Text("cca-platform-comid".into()))
        .add_reference_triple(ReferenceTriple::new(
            cca_platform_environment(),
            measurements,
        ))
        .build()
        .unwrap();

    CorimBuilder::new(CorimId::Text("cca-platform-corim".into()))
        .set_profile(corim::types::corim::ProfileChoice::Uri(
            "tag:arm.com,2025:endorsements/cca_platform#1.0.0".into(),
        ))
        .add_comid_tag(comid)
        .unwrap()
        .build_bytes()
        .unwrap()
}

fn cca_platform_instance_environment() -> EnvironmentMap {
    EnvironmentMap {
        instance: Some(corim::types::common::InstanceIdChoice::Ueid(
            [&[0x01u8][..], &[0x5A; 32]].concat(),
        )),
        ..cca_platform_environment()
    }
}

fn cca_platform_corim_with_attest_key(
    environment: EnvironmentMap,
    keys: Vec<CryptoKey>,
) -> Vec<u8> {
    let comid = ComidBuilder::new(TagIdChoice::Text("cca-platform-comid".into()))
        .add_reference_triple(ReferenceTriple::new(
            cca_platform_environment(),
            vec![cca_software_component(), cca_platform_config()],
        ))
        .add_attest_key_triple(corim::types::triples::AttestKeyTriple::new(
            environment,
            keys,
            None,
        ))
        .build()
        .unwrap();

    CorimBuilder::new(CorimId::Text("cca-platform-corim".into()))
        .set_profile(corim::types::corim::ProfileChoice::Uri(
            "tag:arm.com,2025:endorsements/cca_platform#1.0.0".into(),
        ))
        .add_comid_tag(comid)
        .unwrap()
        .build_bytes()
        .unwrap()
}

#[test]
fn signed_corim_json_includes_protected_header_fields() {
    let signed = make_signed(&sample_unsigned_corim(), false);
    let v = validate_json(&signed, "cose");

    assert_eq!(v["valid"], true);
    let p = &v["signed"]["protected"];
    assert_eq!(v["signed"]["tag"], 18);
    assert_eq!(p["alg"], "PS384");
    assert_eq!(p["alg_id"], -38);
    assert_eq!(p["content_type"], "application/rim+cbor");
    assert_eq!(p["issuer"], "test-issuer");
    assert_eq!(p["subject"], "test-subject");
    assert_eq!(p["signer_name"], "test-issuer");
    assert_eq!(p["has_cwt_claims"], true);
    assert_eq!(p["has_corim_meta"], true);
    assert!(p["size"].as_u64().unwrap() > 0);
}

#[test]
fn signed_corim_json_reports_payload_and_signature() {
    let signed = make_signed(&sample_unsigned_corim(), false);
    let v = validate_json(&signed, "cose");

    assert_eq!(v["signed"]["payload"]["detached"], false);
    assert!(v["signed"]["payload"]["size"].as_u64().unwrap() > 0);
    assert_eq!(v["signed"]["signature"]["size"], 64);
    // Structure-only tool: never claim the signature was checked.
    assert_eq!(v["signed"]["signature_verified"], false);
    // The inner CoRIM is still summarized alongside the envelope.
    assert_eq!(v["id"], "json-corim");
}

/// Incomplete signed documents produce structured failure rather than success.
#[test]
fn detached_signed_corim_json_reports_incomplete_validation() {
    let signed = make_signed(&sample_unsigned_corim(), true);
    let (status, report) = validate_json_status(&signed, "cose");
    assert_eq!(status.code(), Some(2));
    assert_eq!(report["valid"], false);
    assert!(report["errors"]
        .as_array()
        .unwrap()
        .iter()
        .any(|error| error.as_str().unwrap().contains("detached payload")));
}

#[test]
fn unsigned_corim_json_has_no_signed_object() {
    let v = validate_json(&sample_unsigned_corim(), "cbor");
    assert_eq!(v["valid"], true);
    assert!(v.get("signed").is_none(), "unsigned CoRIM has no envelope");
    assert_eq!(v["id"], "json-corim");
}

#[test]
fn validate_accepts_cca_platform_profile_reference_triples() {
    let bytes = cca_platform_corim(vec![cca_software_component(), cca_platform_config()]);
    let v = validate_json(&bytes, "cbor");

    assert_eq!(v["valid"], true);
    assert_eq!(
        decoded_json(&v["profile"]),
        corim::cbor::value::Value::Tag(
            corim::types::tags::TAG_URI,
            Box::new(corim::cbor::value::Value::Text(
                "tag:arm.com,2025:endorsements/cca_platform#1.0.0".into()
            ),)
        )
    );
}

#[test]
fn validate_rejects_invalid_cca_platform_profile_reference_triples() {
    let bytes = cca_platform_corim(vec![cca_software_component()]);
    let (status, v) = validate_json_status(&bytes, "cbor");

    assert!(!status.success(), "validate unexpectedly succeeded: {v}");
    assert_eq!(v["valid"], false);
    assert!(
        v["errors"].as_array().unwrap().iter().any(|error| error
            .as_str()
            .is_some_and(|s| s.contains("exactly one platform configuration")
                && s.contains("tag:arm.com,2025:endorsements/cca_platform#1.0.0"))),
        "expected profile-specific validation error, got: {v}"
    );
}

#[test]
fn validate_accepts_cca_platform_profile_attest_key_triple() {
    let bytes = cca_platform_corim_with_attest_key(
        cca_platform_instance_environment(),
        vec![CryptoKey::PkixBase64Key(
            "-----BEGIN PUBLIC KEY-----\n\
             MIGbMBAGByqGSM49AgEGBSuBBAAjA4GGAAQAkHEvSZK7R4iZ7mXzk9H26ZPEpQIao\n\
             XeruzgQ1VdPt/4kS6KW3DdMkLSzy4UrxGyY5NhHIWT+nV6S27apqM/TOW0AqEnMc\n\
             VrN+aoQQgvGlBG3CT9Vvx6U2JeVtMiVuxv/3psg3L1esLr3MbJT8WEMAb6tZdpyR\n\
             Zot0I1FaRLRC4qt+A0=\n\
             -----END PUBLIC KEY-----"
                .into(),
        )],
    );
    let v = validate_json(&bytes, "cbor");

    assert_eq!(v["valid"], true);
}

#[test]
fn validate_rejects_invalid_cca_platform_profile_attest_key_triple() {
    // §3.1.4 requires exactly one `tagged-pkix-base64-key-type` key; an
    // opaque key-identifier bytes value must be rejected.
    let bytes = cca_platform_corim_with_attest_key(
        cca_platform_instance_environment(),
        vec![CryptoKey::Bytes(vec![0xAA; 32])],
    );
    let (status, v) = validate_json_status(&bytes, "cbor");

    assert!(!status.success(), "validate unexpectedly succeeded: {v}");
    assert_eq!(v["valid"], false);
    assert!(
        v["errors"].as_array().unwrap().iter().any(|error| error
            .as_str()
            .is_some_and(|s| s.contains("attest-key-triples")
                && s.contains("exactly one PKIX public key")
                && s.contains("tag:arm.com,2025:endorsements/cca_platform#1.0.0"))),
        "expected profile-specific validation error, got: {v}"
    );
}

#[test]
fn validate_rejects_malformed_cca_platform_cpak_spki() {
    let bytes = cca_platform_corim_with_attest_key(
        cca_platform_instance_environment(),
        vec![CryptoKey::PkixBase64Key(
            "-----BEGIN PUBLIC KEY-----\nMA==\n-----END PUBLIC KEY-----".into(),
        )],
    );
    let (status, v) = validate_json_status(&bytes, "cbor");

    assert!(!status.success(), "validate unexpectedly succeeded: {v}");
    assert_eq!(v["valid"], false);
    assert!(
        v["errors"].as_array().unwrap().iter().any(|error| error
            .as_str()
            .is_some_and(|s| s.contains("DER SubjectPublicKeyInfo"))),
        "expected malformed CPAK diagnostic, got: {v}"
    );
}

/// Producer-controlled strings reach the report verbatim, so control
/// characters must be escaped rather than emitted raw (which would make the
/// output unparseable).
#[test]
fn control_characters_in_producer_strings_stay_valid_json() {
    let nasty = "iss\twith\r\nctrl\u{01}and \"quotes\" \\ backslash";
    let signed = SignedCorimBuilder::new(-38, sample_unsigned_corim())
        .set_cwt_claims(CwtClaims::new(nasty))
        .build_with_signature(vec![0xAB; 64])
        .unwrap();

    // `validate_json` parses the output, so a bad escape fails here.
    let v = validate_json(&signed, "cose");
    assert_eq!(v["signed"]["protected"]["issuer"], nasty);
}

/// Text-keyed CWT claims (e.g. the `"svn"` claim Azure SOC-MANA CoRIMs
/// carry) and integer extras such as `iat` must both reach the report.
#[test]
fn extra_cwt_claims_are_reported() {
    use corim::cbor::value::Value;
    use corim::types::signed::ClaimKey;

    let mut claims = CwtClaims::new("test-issuer");
    claims
        .extra
        .insert(ClaimKey::Text("svn".into()), Value::Integer(7));
    claims.extra.insert(
        ClaimKey::Int(6),
        Value::Tag(1, Box::new(Value::Integer(1788524559))),
    );

    let signed = SignedCorimBuilder::new(-38, sample_unsigned_corim())
        .set_cwt_claims(claims)
        .build_with_signature(vec![0xAB; 64])
        .unwrap();

    let v = validate_json(&signed, "cose");
    let extra = &v["signed"]["protected"]["cwt_claims_extra"];
    assert_eq!(
        map_entry(extra, Value::Text("svn".into())),
        Value::Integer(7)
    );
    assert_eq!(
        map_entry(extra, Value::Integer(6)),
        Value::Tag(
            corim::types::tags::TAG_EPOCH_TIME,
            Box::new(Value::Integer(1788524559))
        )
    );
}

/// Integer and text claim labels retain distinct CBOR types.
#[test]
fn int_and_text_claim_keys_do_not_collide() {
    use corim::cbor::value::Value;
    use corim::types::signed::ClaimKey;

    let mut claims = CwtClaims::new("iss");
    claims
        .extra
        .insert(ClaimKey::Int(6), Value::Text("as-int".into()));
    claims
        .extra
        .insert(ClaimKey::Text("6".into()), Value::Text("as-text".into()));

    let signed = SignedCorimBuilder::new(-38, sample_unsigned_corim())
        .set_cwt_claims(claims)
        .build_with_signature(vec![0xAB; 64])
        .unwrap();

    let v = validate_json(&signed, "cose");
    let extra = &v["signed"]["protected"]["cwt_claims_extra"];
    assert_eq!(
        map_entry(extra, Value::Integer(6)),
        Value::Text("as-int".into())
    );
    assert_eq!(
        map_entry(extra, Value::Text("6".into())),
        Value::Text("as-text".into())
    );
}

#[test]
fn claim_byte_values_retain_their_byte_string_type() {
    use corim::cbor::value::Value;
    use corim::types::signed::ClaimKey;

    let mut claims = CwtClaims::new("iss");
    claims.extra.insert(
        ClaimKey::Text("blob".into()),
        Value::Bytes(vec![0xde, 0xad, 0xbe, 0xef]),
    );

    let signed = SignedCorimBuilder::new(-38, sample_unsigned_corim())
        .set_cwt_claims(claims)
        .build_with_signature(vec![0xAB; 64])
        .unwrap();

    let v = validate_json(&signed, "cose");
    assert_eq!(
        map_entry(
            &v["signed"]["protected"]["cwt_claims_extra"],
            Value::Text("blob".into())
        ),
        Value::Bytes(vec![0xde, 0xad, 0xbe, 0xef]),
    );
}

/// A hostile text claim value must not be able to inject a quote or newline
/// into the single-line text report.
#[test]
fn text_claim_values_are_escaped_in_the_text_report() {
    use corim::cbor::value::Value;
    use corim::types::signed::ClaimKey;

    let mut claims = CwtClaims::new("iss");
    claims.extra.insert(
        ClaimKey::Text("evil".into()),
        Value::Text("a\"b\nCWT claim spoofed: 1".into()),
    );
    let signed = SignedCorimBuilder::new(-38, sample_unsigned_corim())
        .set_cwt_claims(claims)
        .build_with_signature(vec![0xAB; 64])
        .unwrap();

    let path = unique_temp("escaped_claim", "cose");
    std::fs::write(&path, &signed).unwrap();
    let out = Command::new(bin())
        .args(["validate", path.to_str().unwrap()])
        .output()
        .unwrap();
    let _ = std::fs::remove_file(&path);
    let stdout = String::from_utf8(out.stdout).unwrap();

    let claim_lines: Vec<&str> = stdout.lines().filter(|l| l.contains("CWT claim")).collect();
    assert_eq!(
        claim_lines.len(),
        1,
        "value must not span lines: {claim_lines:?}"
    );
    assert!(claim_lines[0].contains(r#"\n"#), "{}", claim_lines[0]);
    assert!(claim_lines[0].contains(r#"\""#), "{}", claim_lines[0]);
}

#[test]
fn byte_map_keys_retain_their_cbor_type() {
    use corim::cbor::value::Value;
    use corim::types::signed::ClaimKey;

    let mut claims = CwtClaims::new("iss");
    claims.extra.insert(
        ClaimKey::Text("m".into()),
        Value::Map(vec![(Value::Bytes(vec![0xde, 0xad]), Value::Integer(1))]),
    );
    let signed = SignedCorimBuilder::new(-38, sample_unsigned_corim())
        .set_cwt_claims(claims)
        .build_with_signature(vec![0xAB; 64])
        .unwrap();

    let v = validate_json(&signed, "cose");
    let m = map_entry(
        &v["signed"]["protected"]["cwt_claims_extra"],
        Value::Text("m".into()),
    );
    assert_eq!(
        m,
        Value::Map(vec![(Value::Bytes(vec![0xde, 0xad]), Value::Integer(1))])
    );
}

/// Distinct CBOR map keys that stringify alike (integer `1` vs text `"1"`)
/// must not collapse into one JSON object key and lose an entry.
#[test]
fn integer_and_text_map_keys_preserve_distinct_entries() {
    use corim::cbor::value::Value;
    use corim::types::signed::ClaimKey;

    let mut claims = CwtClaims::new("iss");
    claims.extra.insert(
        ClaimKey::Text("m".into()),
        Value::Map(vec![
            (Value::Integer(1), Value::Text("as-int".into())),
            (Value::Text("1".into()), Value::Text("as-text".into())),
        ]),
    );
    let signed = SignedCorimBuilder::new(-38, sample_unsigned_corim())
        .set_cwt_claims(claims)
        .build_with_signature(vec![0xAB; 64])
        .unwrap();

    let v = validate_json(&signed, "cose");
    let m = map_entry(
        &v["signed"]["protected"]["cwt_claims_extra"],
        Value::Text("m".into()),
    );
    assert_eq!(
        m,
        Value::Map(vec![
            (Value::Integer(1), Value::Text("as-int".into())),
            (Value::Text("1".into()), Value::Text("as-text".into())),
        ])
    );
}

#[test]
fn ordinary_extension_maps_use_the_same_lossless_contract() {
    use corim::cbor::value::Value;
    use corim::types::signed::ClaimKey;

    let mut claims = CwtClaims::new("iss");
    claims.extra.insert(
        ClaimKey::Text("m".into()),
        Value::Map(vec![
            (Value::Text("a".into()), Value::Integer(1)),
            (Value::Text("b".into()), Value::Integer(2)),
        ]),
    );
    let signed = SignedCorimBuilder::new(-38, sample_unsigned_corim())
        .set_cwt_claims(claims)
        .build_with_signature(vec![0xAB; 64])
        .unwrap();

    let v = validate_json(&signed, "cose");
    let m = map_entry(
        &v["signed"]["protected"]["cwt_claims_extra"],
        Value::Text("m".into()),
    );
    assert_eq!(
        m,
        Value::Map(vec![
            (Value::Text("a".into()), Value::Integer(1)),
            (Value::Text("b".into()), Value::Integer(2)),
        ])
    );
}
