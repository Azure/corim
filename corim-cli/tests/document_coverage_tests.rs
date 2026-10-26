// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use corim::builder::{ComidBuilder, CorimBuilder};
use corim::cbor::{self, value::Tagged};
use corim::types::common::TagIdChoice;
use corim::types::corim::{ConciseTagChoice, CorimId, CorimMap, ProfileChoice};
use corim::types::environment::EnvironmentMap;
use corim::types::measurement::{MeasurementMap, MeasurementValuesMap, SvnChoice};
use corim::types::tags::TAG_SIGNED_CORIM;
use std::process::{Command, Output};

fn path(label: &str) -> std::path::PathBuf {
    use std::sync::atomic::{AtomicUsize, Ordering};
    static NEXT: AtomicUsize = AtomicUsize::new(0);
    std::env::temp_dir().join(format!(
        "corim_coverage_{}_{}_{}",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed),
        label,
    ))
}

fn sample() -> Tagged<CorimMap> {
    let mut values = MeasurementValuesMap::default();
    values.svn = Some(SvnChoice::MinValue(1));
    let comid = ComidBuilder::new(TagIdChoice::Text("coverage".into()))
        .add_reference_triple(corim::types::triples::ReferenceTriple::new(
            EnvironmentMap::for_class("vendor", "model"),
            vec![MeasurementMap {
                mkey: None,
                mval: values,
                authorized_by: None,
            }],
        ))
        .build()
        .unwrap();
    let bytes = CorimBuilder::new(CorimId::Text("coverage".into()))
        .add_comid_tag(comid)
        .unwrap()
        .build_bytes()
        .unwrap();
    cbor::decode_exact(&bytes).unwrap()
}

fn validate(bytes: &[u8], extra: &[&str]) -> Output {
    let input = path("input.cbor");
    std::fs::write(&input, bytes).unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_corim-cli"))
        .args(["validate", "-f", "json"])
        .args(extra)
        .arg(&input)
        .output()
        .unwrap();
    std::fs::remove_file(input).unwrap();
    output
}

#[test]
fn unknown_profiles_and_content_are_partial_not_success() {
    for (profile, unknown_tag) in [(true, false), (false, true), (true, true)] {
        let mut document = sample();
        if profile {
            document.value.profile =
                Some(ProfileChoice::Uri("tag:example.com,2026:unknown".into()));
        }
        if unknown_tag {
            document
                .value
                .tags
                .push(ConciseTagChoice::Unknown(TAG_SIGNED_CORIM, vec![0]));
        }
        let output = validate(&cbor::encode(&document).unwrap(), &[]);
        let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
        assert_eq!(output.status.code(), Some(4), "{report}");
        assert_eq!(report["status"], "partial");
        assert_eq!(report["valid"], serde_json::Value::Null);
        assert_eq!(report["coverage"]["complete"], false);
        assert_eq!(report["coverage"]["signature_verified"], false);
        if profile {
            assert_eq!(report["coverage"]["profile"]["status"], "unregistered");
        }
        if unknown_tag {
            assert_eq!(
                report["coverage"]["unexamined_tags"],
                serde_json::json!([1])
            );
        }
    }
}

#[test]
fn generation_refuses_partial_documents_before_writing() {
    let mut document = sample();
    document.value.profile = Some(ProfileChoice::Uri("tag:example.com,2026:unknown".into()));
    let input = path("input.json");
    let output = path("refused.cbor");
    std::fs::write(&input, corim::json::to_json(&document).unwrap()).unwrap();
    let result = Command::new(env!("CARGO_BIN_EXE_corim-cli"))
        .arg("generate")
        .arg(&input)
        .arg("-o")
        .arg(&output)
        .output()
        .unwrap();
    let wrote_output = output.exists();
    std::fs::remove_file(input).unwrap();
    if wrote_output {
        std::fs::remove_file(output).unwrap();
    }
    assert_eq!(
        result.status.code(),
        Some(4),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    assert!(!wrote_output);
}

#[test]
fn validated_extraction_refuses_partial_payloads_before_writing() {
    use corim::types::signed::{CwtClaims, SignedCorimBuilder};
    let mut document = sample();
    document.value.profile = Some(ProfileChoice::Uri("tag:example.com,2026:unknown".into()));
    let signed = SignedCorimBuilder::new(-7, cbor::encode(&document).unwrap())
        .set_cwt_claims(CwtClaims::new("issuer"))
        .build_with_signature(vec![0; 64])
        .unwrap();
    let input = path("signed.cbor");
    let output = path("refused-payload.cbor");
    std::fs::write(&input, signed).unwrap();
    let result = Command::new(env!("CARGO_BIN_EXE_corim-cli"))
        .arg("extract")
        .arg(&input)
        .arg("--validate")
        .arg("-o")
        .arg(&output)
        .output()
        .unwrap();
    let wrote_output = output.exists();
    std::fs::remove_file(input).unwrap();
    if wrote_output {
        std::fs::remove_file(output).unwrap();
    }
    assert_eq!(
        result.status.code(),
        Some(4),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    assert!(!wrote_output);
}

#[test]
fn validated_extraction_rejects_nested_signed_payloads_without_writing() {
    use corim::document::{self, TimeCheck, ValidationContext};
    use corim::profile::ProfileRegistry;
    use corim::types::signed::{CoseAlgorithm, CwtClaims, SignedCorimBuilder};
    let wrap = |payload, issuer: &str| {
        SignedCorimBuilder::new(CoseAlgorithm::Es256, payload)
            .set_cwt_claims(CwtClaims::new(issuer))
            .build_with_signature(vec![1; 64])
            .unwrap()
    };
    for partial in [false, true] {
        let mut payload = sample();
        if partial {
            payload.value.profile = Some(ProfileChoice::Uri("tag:example.com,2026:unknown".into()));
        }
        let inner = wrap(cbor::encode(&payload).unwrap(), "inner");
        let registry = ProfileRegistry::new();
        let checked =
            document::validate(&inner, &ValidationContext::new(TimeCheck::At(0), &registry))
                .unwrap();
        assert!(checked.envelope().is_some());
        assert_eq!(checked.coverage().is_complete(), !partial);
        let outer = wrap(inner.clone(), "outer");
        for destination in ["stdout", "missing", "existing"] {
            let input = path("nested-signed.cbor");
            let output = path("nested-refused.cbor");
            let sentinel = b"existing output must survive";
            std::fs::write(&input, &outer).unwrap();
            if destination == "existing" {
                std::fs::write(&output, sentinel).unwrap();
            }
            let mut command = Command::new(env!("CARGO_BIN_EXE_corim-cli"));
            command
                .arg("extract")
                .arg(&input)
                .arg("--validate")
                .arg("-o");
            if destination == "stdout" {
                command.arg("-");
            } else {
                command.arg(&output);
            }
            let result = command.output().unwrap();
            std::fs::remove_file(input).unwrap();
            let contents = if output.exists() {
                let contents = std::fs::read(&output).unwrap();
                std::fs::remove_file(output).unwrap();
                Some(contents)
            } else {
                None
            };
            assert_eq!(
                result.status.code(),
                Some(1),
                "{destination}, partial={partial}: {}",
                String::from_utf8_lossy(&result.stderr)
            );
            assert!(
                result.stdout.is_empty(),
                "nested payload must not leak to stdout"
            );
            assert!(String::from_utf8_lossy(&result.stderr).contains("unsigned CoRIM"));
            assert_eq!(
                contents,
                (destination == "existing").then(|| sentinel.to_vec())
            );
        }
        // Extraction without the validation flag remains byte-preserving.
        let input = path("unvalidated-nested.cbor");
        std::fs::write(&input, outer).unwrap();
        let result = Command::new(env!("CARGO_BIN_EXE_corim-cli"))
            .arg("extract")
            .arg(&input)
            .output()
            .unwrap();
        std::fs::remove_file(input).unwrap();
        assert!(result.status.success());
        assert_eq!(result.stdout, inner);
    }
}

#[test]
fn baseline_mismatch_takes_precedence_over_partial_coverage() {
    let mut baseline = sample();
    baseline.value.profile = Some(ProfileChoice::Uri("tag:example.com,2026:unknown".into()));
    let path = path("baseline.cbor");
    std::fs::write(&path, cbor::encode(&baseline).unwrap()).unwrap();
    let output = validate(
        &cbor::encode(&baseline).unwrap(),
        &["--baseline", path.to_str().unwrap()],
    );
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(output.status.code(), Some(4), "{report}");
    assert_eq!(report["result"], "match");
    assert_eq!(report["status"], "partial");
    let mut candidate = baseline.clone();
    candidate.value.profile = None;
    let output = validate(
        &cbor::encode(&candidate).unwrap(),
        &["--baseline", path.to_str().unwrap()],
    );
    std::fs::remove_file(path).unwrap();
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(output.status.code(), Some(3), "{report}");
    assert_eq!(report["result"], "structural-mismatch");
    assert_eq!(report["status"], "partial");
}
