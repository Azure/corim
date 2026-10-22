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
