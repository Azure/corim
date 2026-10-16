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
        mval: MeasurementValuesMap {
            svn: Some(SvnChoice::MinValue(1)),
            ..MeasurementValuesMap::default()
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
                        Some(if valid { 0 } else { 2 }),
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
                        Some(if null { 2 } else { 0 }),
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
        assert_eq!(output.status.code(), Some(if malformed { 2 } else { 0 }));
        let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
        assert_eq!(report["time_validated"], false);
        if malformed {
            assert_eq!(report["valid"], false);
        } else {
            assert!(report["valid"].is_null());
        }
    }
    let output = validate_with_flags(&sample_unsigned_corim(), &["--skip-expiry"]);
    assert!(output.status.success());
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
    assert!(
        output.status.success(),
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
fn json_baselines_reject_invalid_present_timestamps_before_conversion() {
    use serde_json::{json, Value};
    let template = json!({"corim-id":"json-corim","comids":[{"tag-identity":{"id":"json-comid"},"triples":{"reference-triples":[[{"class":{"vendor":"TestVendor","model":"TestModel"}},[{"key":"firmware","value":{"svn":{"type":"min-svn","value":1}}}]]]}}]});
    for cotl in [false, true] {
        for (before, after) in [("not-before", "not-after"), ("0", "1")] {
            for (value, valid) in [
                (None, true),
                (Some(json!(0)), true),
                (Some(json!({"__cbor_tag":1,"__cbor_value":0})), true),
                (Some(Value::Null), false),
                (Some(json!("invalid")), false),
                (Some(json!(u64::MAX)), false),
                (Some(json!(0.5)), false),
                (Some(json!(true)), false),
                (Some(json!({"__cbor_tag":1,"__cbor_value":null})), false),
            ] {
                let mut baseline = template.clone();
                let mut validity = serde_json::Map::new();
                validity.insert(after.into(), json!(i64::MAX));
                if let Some(value) = value {
                    validity.insert(before.into(), value);
                }
                if cotl {
                    baseline["cotls"] = json!([{"tag-identity":{"id":"list"},"tags-list":[{"id":"member"}],"tl-validity":validity}]);
                } else {
                    baseline["rim-validity"] = validity.into();
                }
                let path = unique_temp("json_validity_baseline", "json");
                let generated = unique_temp("json_validity_generated", "cbor");
                std::fs::write(&path, serde_json::to_vec(&baseline).unwrap()).unwrap();
                for skip in [false, true] {
                    let mut flags = vec!["--baseline", path.to_str().unwrap(), "--format", "json"];
                    if skip {
                        flags.push("--skip-expiry");
                    }
                    let output = validate_with_flags(&sample_unsigned_corim(), &flags);
                    let report: Value = serde_json::from_slice(&output.stdout).unwrap();
                    assert_eq!(
                        output.status.code(),
                        Some(if valid && !cotl { 0 } else { 2 }),
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
    let json = br#"{"corim-id":"json-corim","rim-validity":{"not-after":1},"comids":[{"tag-identity":{"id":"json-comid"},"triples":{"reference-triples":[[{"class":{"vendor":"TestVendor","model":"TestModel"}},[{"key":"firmware","value":{"svn":{"type":"min-svn","value":1}}}]]]}}]}"#;
    for bytes in [cbor::encode(&baseline).unwrap(), json.to_vec()] {
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
        assert!(
            output.status.success(),
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
        mval: MeasurementValuesMap {
            digests: Some(vec![Digest::new_text("sha-256", vec![0x11; 32])]),
            cryptokeys: Some(vec![CryptoKey::Bytes(vec![0xAA; 32])]),
            ..MeasurementValuesMap::default()
        },
        authorized_by: None,
    }
}

fn cca_platform_config() -> MeasurementMap {
    MeasurementMap {
        mkey: Some(MeasuredElement::Text("cca.platform-config".into())),
        mval: MeasurementValuesMap {
            raw_value: Some(RawValueChoice::Masked {
                value: vec![0xA0, 0x05],
                mask: vec![0xF0, 0x00],
            }),
            ..MeasurementValuesMap::default()
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
        v["profile"],
        "tag:arm.com,2025:endorsements/cca_platform#1.0.0"
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
    assert_eq!(extra["text"]["svn"], 7, "text-keyed claim must survive");
    assert_eq!(extra["int"]["6"]["__cbor_tag"], 1);
    assert_eq!(extra["int"]["6"]["__cbor_value"], 1788524559i64);
}

/// JSON object keys are strings, so integer and text claim keys live in
/// separate namespaces and cannot collapse onto one entry.
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
    assert_eq!(extra["int"]["6"], "as-int");
    assert_eq!(extra["text"]["6"], "as-text");
}

/// Byte values use base64, matching `corim::json` and the convert/generate
/// templates rather than introducing a second encoding.
#[test]
fn claim_byte_values_use_base64() {
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
        v["signed"]["protected"]["cwt_claims_extra"]["text"]["blob"],
        "3q2+7w=="
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

/// A CBOR map keyed by a non-text, non-integer value must not bake JSON
/// quotes into the object key.
#[test]
fn byte_map_keys_do_not_keep_json_quotes() {
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
    let m = &v["signed"]["protected"]["cwt_claims_extra"]["text"]["m"];
    let keys: Vec<&String> = m.as_object().unwrap().keys().collect();
    assert_eq!(keys.len(), 1);
    assert_eq!(
        keys[0], "3q0=",
        "key must be the bare base64, got {:?}",
        keys[0]
    );
}

/// Distinct CBOR map keys that stringify alike (integer `1` vs text `"1"`)
/// must not collapse into one JSON object key and lose an entry.
#[test]
fn colliding_map_keys_fall_back_to_entry_array() {
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
    let m = &v["signed"]["protected"]["cwt_claims_extra"]["text"]["m"];
    let entries = m.as_array().expect("colliding keys render as an array");
    assert_eq!(entries.len(), 2, "no entry may be dropped: {m}");
    // The key's CBOR type survives: a number stays a number, text stays text.
    assert!(entries
        .iter()
        .any(|e| e["key"] == 1 && e["value"] == "as-int"));
    assert!(entries
        .iter()
        .any(|e| e["key"] == "1" && e["value"] == "as-text"));
}

/// Non-colliding maps keep the friendlier object form.
#[test]
fn distinct_map_keys_stay_an_object() {
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
    let m = &v["signed"]["protected"]["cwt_claims_extra"]["text"]["m"];
    assert_eq!(m["a"], 1);
    assert_eq!(m["b"], 2);
}
