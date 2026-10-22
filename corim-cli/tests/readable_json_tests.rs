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
