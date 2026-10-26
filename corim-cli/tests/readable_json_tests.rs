// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use corim::builder::{ComidBuilder, CorimBuilder};
use corim::cbor::{
    self,
    value::{Tagged, Value},
};
use corim::types::common::{MeasuredElement, TagIdChoice};
use corim::types::corim::{CorimId, CorimMap};
use corim::types::environment::EnvironmentMap;
use corim::types::measurement::{MeasurementMap, MeasurementValuesMap, SvnChoice};
use corim::types::triples::ReferenceTriple;
use std::process::{Command, Output};

const READABLE: &str = r#"{
  "$comment": ["Readable authoring", {"not-before": null}],
  "corim-id": "readable",
  "comids": [{
    "//": "CoMID annotation",
    "tag-identity": {"id": "readable-comid"},
    "triples": {
      "reference-triples": [[
        {"class": {"vendor": "Vendor", "model": "Model", "$comment": "class"}},
        [{"key": "firmware", "value": {
          "//": "measurement annotation",
          "svn": {"type": "min-svn", "value": 1, "$comment": "type choice"}
        }}]
      ]]
    }
  }]
}"#;

struct File(std::path::PathBuf);

impl File {
    fn new(label: &str, bytes: Option<&[u8]>) -> Self {
        use std::sync::atomic::{AtomicUsize, Ordering};
        static NEXT: AtomicUsize = AtomicUsize::new(0);
        let path = std::env::temp_dir().join(format!(
            "corim_readable_{}_{}_{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed),
            label,
        ));
        if let Some(bytes) = bytes {
            std::fs::write(&path, bytes).unwrap();
        }
        Self(path)
    }
}

impl Drop for File {
    fn drop(&mut self) {
        if self.0.exists() {
            std::fs::remove_file(&self.0).unwrap();
        }
    }
}

fn sample() -> Vec<u8> {
    let mut values = MeasurementValuesMap::default();
    values.svn = Some(SvnChoice::MinValue(1));
    let comid = ComidBuilder::new(TagIdChoice::Text("readable-comid".into()))
        .add_reference_triple(ReferenceTriple::new(
            EnvironmentMap::for_class("Vendor", "Model"),
            vec![MeasurementMap {
                mkey: Some(MeasuredElement::Text("firmware".into())),
                mval: values,
                authorized_by: None,
            }],
        ))
        .build()
        .unwrap();
    CorimBuilder::new(CorimId::Text("readable".into()))
        .add_comid_tag(comid)
        .unwrap()
        .build_bytes()
        .unwrap()
}

fn generate(input: &File, output: &File) -> Output {
    Command::new(env!("CARGO_BIN_EXE_corim-cli"))
        .arg("generate")
        .arg(&input.0)
        .arg("-o")
        .arg(&output.0)
        .output()
        .unwrap()
}

#[test]
fn readable_annotations_are_accepted_and_not_encoded() {
    let input = File::new("authoring.json", Some(READABLE.as_bytes()));
    let output = File::new("generated.cbor", None);
    let result = generate(&input, &output);
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    let bytes = std::fs::read(&output.0).unwrap();
    assert_eq!(bytes, sample());
    assert!(!bytes
        .windows(b"$comment".len())
        .any(|part| part == b"$comment"));
    let document: Tagged<CorimMap> = cbor::decode_exact(&bytes).unwrap();
    assert_eq!(document.value.id, CorimId::Text("readable".into()));
}

#[test]
fn convert_defaults_to_readable_decoded_comid_fields() {
    let input = File::new("source.cbor", Some(&sample()));
    let result = Command::new(env!("CARGO_BIN_EXE_corim-cli"))
        .arg("convert")
        .arg(&input.0)
        .output()
        .unwrap();
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    let document: serde_json::Value = serde_json::from_slice(&result.stdout).unwrap();
    assert_eq!(document["corim-id"], "readable");
    assert!(document["comids"][0]["triples"]["reference-triples"].is_array());
    let generated = File::new("generated.cbor", None);
    let converted = File::new("converted.json", Some(&result.stdout));
    assert!(generate(&converted, &generated).status.success());
    assert_eq!(std::fs::read(&generated.0).unwrap(), sample());
}

#[test]
fn explicit_lossless_conversion_keeps_the_raw_document_contract() {
    let bytes = sample();
    let input = File::new("source.cbor", Some(&bytes));
    let result = Command::new(env!("CARGO_BIN_EXE_corim-cli"))
        .args(["convert", "--lossless"])
        .arg(&input.0)
        .output()
        .unwrap();
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    let json = corim::json::parse_json(std::str::from_utf8(&result.stdout).unwrap()).unwrap();
    let decoded = corim::json::json_to_value(&json).unwrap();
    assert_eq!(cbor::encode(&decoded).unwrap(), bytes);
    let converted = File::new("lossless.json", Some(&result.stdout));
    let output = File::new("generated.cbor", None);
    assert!(generate(&converted, &output).status.success());
    assert_eq!(std::fs::read(&output.0).unwrap(), bytes);
}

#[test]
fn signed_readable_output_is_payload_authoring_while_lossless_keeps_the_envelope() {
    use corim::types::signed::{CwtClaims, SignedCorimBuilder};
    let signed = SignedCorimBuilder::new(-7, sample())
        .set_cwt_claims(CwtClaims::new("issuer"))
        .build_with_signature(vec![0xab; 64])
        .unwrap();
    let input = File::new("signed.cbor", Some(&signed));
    let readable = Command::new(env!("CARGO_BIN_EXE_corim-cli"))
        .arg("convert")
        .arg(&input.0)
        .output()
        .unwrap();
    assert!(
        readable.status.success(),
        "{}",
        String::from_utf8_lossy(&readable.stderr)
    );
    let document: serde_json::Value = serde_json::from_slice(&readable.stdout).unwrap();
    assert_eq!(document["corim-id"], "readable");
    assert!(document.get("protected-header").is_some());
    let authoring = File::new("signed-authoring.json", Some(&readable.stdout));
    let unsigned = File::new("unsigned.cbor", None);
    assert!(generate(&authoring, &unsigned).status.success());
    assert_eq!(std::fs::read(&unsigned.0).unwrap(), sample());
    let lossless = Command::new(env!("CARGO_BIN_EXE_corim-cli"))
        .args(["convert", "--lossless"])
        .arg(&input.0)
        .output()
        .unwrap();
    assert!(lossless.status.success());
    let raw: Value =
        corim::json::from_json(std::str::from_utf8(&lossless.stdout).unwrap()).unwrap();
    assert_eq!(cbor::encode(&raw).unwrap(), signed);
}

#[test]
fn detached_readable_conversion_requests_explicit_lossless_mode() {
    use corim::types::signed::{CwtClaims, SignedCorimBuilder};
    let signed = SignedCorimBuilder::new(-7, sample())
        .set_cwt_claims(CwtClaims::new("issuer"))
        .build_detached_with_signature(vec![0xab; 64])
        .unwrap();
    let input = File::new("detached.cbor", Some(&signed));
    let output = File::new("refused.json", None);
    let readable = Command::new(env!("CARGO_BIN_EXE_corim-cli"))
        .arg("convert")
        .arg(&input.0)
        .arg("-o")
        .arg(&output.0)
        .output()
        .unwrap();
    assert!(!readable.status.success());
    assert!(String::from_utf8_lossy(&readable.stderr).contains("--lossless"));
    assert!(!output.0.exists());
}

#[test]
fn readable_json_baselines_use_the_shared_validation_pipeline() {
    let baseline = File::new("baseline.json", Some(READABLE.as_bytes()));
    let target = File::new("target.cbor", Some(&sample()));
    let result = Command::new(env!("CARGO_BIN_EXE_corim-cli"))
        .arg("validate")
        .arg(&target.0)
        .arg("--baseline")
        .arg(&baseline.0)
        .args(["-f", "json"])
        .output()
        .unwrap();
    let report: serde_json::Value = serde_json::from_slice(&result.stdout).unwrap();
    assert_eq!(result.status.code(), Some(0), "{report}");
    assert_eq!(report["result"], "match");
    assert_eq!(report["coverage"]["baseline"]["complete"], true);
}

#[test]
fn readable_generation_does_not_bypass_partial_validation() {
    let mut template: serde_json::Value = serde_json::from_str(READABLE).unwrap();
    template["profile"] = serde_json::json!("tag:example.com,2026:unregistered");
    let input = File::new(
        "partial-readable.json",
        Some(&serde_json::to_vec(&template).unwrap()),
    );
    let output = File::new("refused.cbor", None);
    let result = generate(&input, &output);
    assert_eq!(
        result.status.code(),
        Some(4),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    assert!(!output.0.exists());
}

#[test]
fn lossless_wrapper_annotations_are_not_silently_stripped() {
    let root: Value = cbor::decode_exact(&sample()).unwrap();
    let mut json = corim::json::value_to_json(&root).unwrap();
    json["$comment"] = serde_json::json!("not an annotation in the raw codec");
    let input = File::new(
        "invalid-lossless.json",
        Some(&serde_json::to_vec(&json).unwrap()),
    );
    let output = File::new("refused.cbor", None);
    let result = generate(&input, &output);
    assert!(!result.status.success());
    assert!(!output.0.exists());
}

#[test]
fn mixed_document_formats_are_rejected_without_parser_fallback() {
    let root: Value = cbor::decode_exact(&sample()).unwrap();
    let mut json = corim::json::value_to_json(&root).unwrap();
    json["corim-id"] = serde_json::json!("not an authoring fallback");
    let input = File::new("ambiguous.json", Some(&serde_json::to_vec(&json).unwrap()));
    let output = File::new("refused.cbor", None);
    let result = generate(&input, &output);
    assert!(!result.status.success());
    assert!(String::from_utf8_lossy(&result.stderr).contains("ambiguous document JSON"));
    assert!(!output.0.exists());
}

#[test]
fn readable_projection_never_silently_drops_unmodeled_unsigned_data() {
    use corim::types::tags::TAG_CORIM;
    // Exercise the forward-compatible extension point without assigning a
    // profile-specific meaning to the unregistered label.
    const EXTENSION: i128 = 10001;
    let mut source: Value = cbor::decode_exact(&sample()).unwrap();
    let Value::Tag(TAG_CORIM, map) = &mut source else {
        panic!("CoRIM");
    };
    let Value::Map(fields) = map.as_mut() else {
        panic!("CoRIM map");
    };
    fields.push((Value::Integer(EXTENSION), Value::Bytes(vec![0xde, 0xad])));
    let bytes = cbor::encode(&source).unwrap();
    let input = File::new("extended.cbor", Some(&bytes));
    let output = File::new("readable.json", None);
    let result = Command::new(env!("CARGO_BIN_EXE_corim-cli"))
        .arg("convert")
        .arg(&input.0)
        .arg("-o")
        .arg(&output.0)
        .output()
        .unwrap();
    if result.status.success() {
        let generated = File::new("regenerated.cbor", None);
        let regenerated = generate(&output, &generated);
        assert!(
            regenerated.status.success(),
            "{}",
            String::from_utf8_lossy(&regenerated.stderr)
        );
        assert_eq!(std::fs::read(&generated.0).unwrap(), bytes);
    } else {
        assert!(String::from_utf8_lossy(&result.stderr).contains("--lossless"));
        assert!(!output.0.exists());
    }
}

#[test]
fn readable_roundtrips_cover_coswid_and_cotl_without_a_comid() {
    use corim::builder::CotlBuilder;
    use corim::types::coswid::{ConciseSwidTag, SwidEntity};
    use corim::types::measurement::Digest;
    use corim::types::tags::SWID_ROLE_TAG_CREATOR;
    let mut entity = SwidEntity::new("Vendor", vec![SWID_ROLE_TAG_CREATOR]);
    entity.thumbprint = Some(Digest::new(7, vec![1; 32]));
    let swid = ConciseSwidTag::new(TagIdChoice::Uuid([3; 16]), "Readable OS", 0, vec![entity]);
    let swid = CorimBuilder::new(CorimId::Text("readable-swid".into()))
        .add_coswid(swid)
        .unwrap()
        .build_bytes()
        .unwrap();
    let list = CotlBuilder::new(TagIdChoice::Text("list".into()), i64::MAX)
        .add_tag_id(TagIdChoice::Text("member".into()))
        .build()
        .unwrap();
    let list = CorimBuilder::new(CorimId::Text("readable-list".into()))
        .add_cotl(list)
        .unwrap()
        .build_bytes()
        .unwrap();
    for bytes in [swid, list] {
        let input = File::new("tag-only.cbor", Some(&bytes));
        let result = Command::new(env!("CARGO_BIN_EXE_corim-cli"))
            .arg("convert")
            .arg(&input.0)
            .output()
            .unwrap();
        assert!(
            result.status.success(),
            "{}",
            String::from_utf8_lossy(&result.stderr)
        );
        let template = File::new("tag-only.json", Some(&result.stdout));
        let output = File::new("regenerated.cbor", None);
        let result = generate(&template, &output);
        assert!(
            result.status.success(),
            "{}",
            String::from_utf8_lossy(&result.stderr)
        );
        assert_eq!(std::fs::read(&output.0).unwrap(), bytes);
    }
}
