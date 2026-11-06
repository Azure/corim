use corim::builder::{ComidBuilder, CorimBuilder};
use corim::cbor::{self, value::Value};
use corim::types::common::TagIdChoice;
use corim::types::corim::CorimId;
use corim::types::environment::EnvironmentMap;
use corim::types::measurement::{MeasurementMap, MeasurementValuesMap, SvnChoice};
use corim::types::signed::*;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

struct Files(PathBuf);
impl Files {
    fn new() -> Self {
        static NEXT: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
        let path = std::env::temp_dir().join(format!(
            "corim_multisign_{}_{}",
            std::process::id(),
            NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
        ));
        std::fs::create_dir(&path).unwrap();
        Self(path)
    }
    fn path(&self, name: &str) -> PathBuf { self.0.join(name) }
}
impl Drop for Files {
    fn drop(&mut self) {
        for entry in std::fs::read_dir(&self.0).unwrap() {
            std::fs::remove_file(entry.unwrap().path()).unwrap();
        }
        std::fs::remove_dir(&self.0).unwrap();
    }
}

fn header(name: &str, alg: CoseAlgorithm) -> ProtectedCorimHeaderMap {
    ProtectedCorimHeaderMapBuilder::new(alg)
        .content_type(CORIM_CONTENT_TYPE)
        .cwt_claims(CwtClaims::new(name))
        .build()
}
fn payload() -> Vec<u8> {
    let mut values = MeasurementValuesMap::default();
    values.svn = Some(SvnChoice::ExactValue(1));
    let comid = ComidBuilder::new(TagIdChoice::Text("multi-cli".into()))
        .add_reference_triple(corim::types::triples::ReferenceTriple::new(
            EnvironmentMap::for_class("vendor", "model"),
            vec![MeasurementMap { mkey: None, mval: values, authorized_by: None }],
        ))
        .build().unwrap();
    CorimBuilder::new(CorimId::Text("multi-cli".into()))
        .add_comid_tag(comid).unwrap().build_bytes().unwrap()
}
fn envelope(second: &str) -> Vec<u8> {
    MultiSignedCorimBuilder::new(header("creator", CoseAlgorithm::Esp256), payload()).unwrap()
        .add_signer(header(second, CoseAlgorithm::Esp384)).unwrap()
        .build_with_signatures(vec![vec![1], vec![2]]).unwrap()
}
fn run(input: &Path, args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_corim-cli")).args(args).arg(input).output().unwrap()
}
fn success(output: &Output) {
    assert!(output.status.success(), "stdout={} stderr={}", String::from_utf8_lossy(&output.stdout), String::from_utf8_lossy(&output.stderr));
}

#[test]
fn validate_diagnose_and_edn_include_every_signature() {
    let files = Files::new();
    let input = files.path("input.cbor");
    std::fs::write(&input, envelope("second")).unwrap();
    let output = run(&input, &["validate", "--format", "json"]);
    success(&output);
    let json: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(json["signed"]["tag"], 98);
    assert_eq!(json["signed"]["signatures"].as_array().unwrap().len(), 2);
    assert_eq!(json["signed"]["signature_verified"], false);
    let output = run(&input, &["validate", "--diagnose"]);
    success(&output);
    let text = String::from_utf8(output.stdout).unwrap();
    assert!(text.contains("$.signatures[1].protected.15"), "{text}");
    let output = run(&input, &["validate", "--edn"]);
    success(&output);
    let text = String::from_utf8(output.stdout).unwrap();
    assert!(text.starts_with("#6.98("));
    assert!(text.contains("\"second\""));
}

#[test]
fn extraction_selects_body_or_indexed_header_and_refuses_bad_index_before_output() {
    let files = Files::new();
    let input = files.path("input.cbor");
    let output = files.path("output.cbor");
    std::fs::write(&input, envelope("second")).unwrap();
    success(&run(&input, &["extract", "--validate", "-o", output.to_str().unwrap()]));
    assert_eq!(std::fs::read(&output).unwrap(), payload());
    success(&run(&input, &["extract", "--header", "--signature-index", "1", "-o", output.to_str().unwrap()]));
    assert_eq!(
        std::fs::read(&output).unwrap(),
        cbor::encode(&header("second", CoseAlgorithm::Esp384)).unwrap()
    );
    std::fs::write(&output, b"preserve").unwrap();
    assert!(!run(&input, &["extract", "--header", "--signature-index", "99", "-o", output.to_str().unwrap()]).status.success());
    assert_eq!(std::fs::read(&output).unwrap(), b"preserve");
}

#[test]
fn readable_projection_and_lossless_generation_preserve_their_contracts() {
    let files = Files::new();
    let input = files.path("input.cbor");
    let json = files.path("input.json");
    let rebuilt = files.path("rebuilt.cbor");
    let bytes = envelope("second");
    std::fs::write(&input, &bytes).unwrap();
    let output = run(&input, &["convert"]);
    success(&output);
    let template: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(template["protected-header"]["signatures"].as_array().unwrap().len(), 2);
    let output = run(&input, &["convert", "--lossless"]);
    success(&output);
    std::fs::write(&json, &output.stdout).unwrap();
    success(&run(&json, &["generate", "-o", rebuilt.to_str().unwrap()]));
    assert_eq!(std::fs::read(rebuilt).unwrap(), bytes);
}

#[test]
fn baseline_comparison_does_not_ignore_secondary_signer_changes() {
    let files = Files::new();
    let input = files.path("input.cbor");
    let baseline = files.path("baseline.cbor");
    std::fs::write(&input, envelope("changed")).unwrap();
    std::fs::write(&baseline, envelope("second")).unwrap();
    let output = run(&input, &["validate", "--format", "json", "--baseline", baseline.to_str().unwrap()]);
    success(&output);
    let json: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    let text = json.to_string();
    assert!(text.contains("signatures"), "{text}");
    assert!(text.contains("changed"), "{text}");
    let mut value: Value = cbor::decode_exact(&envelope("second")).unwrap();
    let Value::Tag(_, inner) = &mut value else { panic!("tag") };
    let Value::Array(parts) = inner.as_mut() else { panic!("array") };
    let Value::Array(signers) = &mut parts[3] else { panic!("signers") };
    signers.pop();
    std::fs::write(&input, cbor::encode(&value).unwrap()).unwrap();
    let output = run(&input, &["validate", "--baseline", baseline.to_str().unwrap()]);
    assert_eq!(output.status.code(), Some(3));
}
