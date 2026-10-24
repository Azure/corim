use std::io::Write;
use std::process::{Command, Output, Stdio};

use corim::builder::{ComidBuilder, CorimBuilder};
use corim::cbor::{self, value::Value};
use corim::types::common::TagIdChoice;
use corim::types::corim::{CorimId, CorimMetaMap, CorimSignerMap};
use corim::types::environment::EnvironmentMap;
use corim::types::measurement::{MeasurementMap, MeasurementValuesMap, SvnChoice};
use corim::types::signed::*;
use corim::types::tags::TAG_SIGNED_CORIM;
use corim::types::triples::ReferenceTriple;

fn input() -> Vec<u8> {
    let comid = ComidBuilder::new(TagIdChoice::Text("maintenance".into()))
        .add_reference_triple(ReferenceTriple::new(
            EnvironmentMap::for_class("vendor", "model"),
            vec![MeasurementMap {
                mkey: None,
                mval: MeasurementValuesMap {
                    svn: Some(SvnChoice::ExactValue(1)),
                    ..Default::default()
                },
                authorized_by: None,
            }],
        ))
        .build()
        .unwrap();
    CorimBuilder::new(CorimId::Text("document".into()))
        .add_comid_tag(comid)
        .unwrap()
        .build_bytes()
        .unwrap()
}

fn signed_input(svn: Value) -> Vec<u8> {
    let claims = Value::Map(vec![
        (
            Value::Integer(i128::from(CWT_CLAIM_ISS)),
            Value::Text("Signer".into()),
        ),
        (
            Value::Integer(i128::from(CWT_CLAIM_SUB)),
            Value::Text("Subject\n\"quoted\"".into()),
        ),
        (Value::Text("svn".into()), svn),
    ]);
    let protected = cbor::encode(&Value::Map(vec![
        (
            Value::Integer(i128::from(COSE_HEADER_ALG)),
            Value::Integer(i128::from(CoseAlgorithm::Esp256.to_i64())),
        ),
        (
            Value::Integer(i128::from(COSE_HEADER_CONTENT_TYPE)),
            Value::Text(CORIM_CONTENT_TYPE.into()),
        ),
        (Value::Integer(i128::from(COSE_HEADER_CWT_CLAIMS)), claims),
    ]))
    .unwrap();
    cbor::encode(&Value::Tag(
        TAG_SIGNED_CORIM,
        Box::new(Value::Array(vec![
            Value::Bytes(protected),
            Value::Map(vec![]),
            Value::Bytes(input()),
            Value::Bytes(vec![1]),
        ])),
    ))
    .unwrap()
}

fn run(bytes: &[u8], arguments: &[&str]) -> Output {
    let mut child = Command::new(env!("CARGO_BIN_EXE_corim-cli"))
        .args(arguments)
        .arg("-")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    if let Err(error) = child.stdin.take().unwrap().write_all(bytes) {
        assert_eq!(error.kind(), std::io::ErrorKind::BrokenPipe);
    }
    child.wait_with_output().unwrap()
}

#[test]
fn signed_text_and_json_surface_signer_subject_and_text_keyed_svn() {
    for svn in [Value::Integer(7), Value::Text("1.2".into())] {
        let bytes = signed_input(svn);
        let text = run(&bytes, &[]);
        assert!(text.status.success(), "{:?}", text);
        let text = String::from_utf8(text.stdout).unwrap();
        assert!(text.contains("Signer:       Signer"), "{text}");
        assert!(
            text.contains("Subject:      Subject\\n\\\"quoted\\\""),
            "{text}"
        );
        assert!(text.contains("\"svn\""), "{text}");
        let json = run(&bytes, &["--format", "json"]);
        assert!(json.status.success(), "{:?}", json);
        let report: serde_json::Value = serde_json::from_slice(&json.stdout).unwrap();
        assert_eq!(report["signed"]["signer"], "Signer");
        assert_eq!(report["signed"]["subject"], "Subject\n\"quoted\"");
        let claims = report["signed"]["cwt_claims_edn"].as_str().unwrap();
        assert!(claims.contains("\"svn\""), "{claims}");
    }
}

#[test]
fn metadata_signer_remains_available_without_cwt() {
    let signed_bytes = SignedCorimBuilder::new(CoseAlgorithm::Esp256, input())
        .set_corim_meta(CorimMetaMap {
            signer: CorimSignerMap {
                signer_name: "Metadata signer".into(),
                signer_uri: None,
            },
            signature_validity: None,
        })
        .build_with_signature(vec![1])
        .unwrap();
    let output = run(&signed_bytes, &["--format", "json"]);
    assert!(output.status.success(), "{output:?}");
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(report["signed"]["signer"], "Metadata signer");
    assert!(report["signed"]["cwt_claims_edn"].is_null());
}

#[test]
fn unsigned_json_shape_is_unchanged() {
    let output = run(&input(), &["--format", "json"]);
    assert!(output.status.success(), "{output:?}");
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(report["valid"], true);
    assert_eq!(report["id"], "document");
    assert_eq!(report["comid_count"], 1);
    assert!(report.get("signed").is_none());
}

#[test]
fn document_framing_and_bounded_stdin_are_enforced() {
    let mut bytes = input();
    bytes.push(0);
    assert_eq!(run(&bytes, &[]).status.code(), Some(2));
    assert_eq!(run(&bytes, &["--edn"]).status.code(), Some(1));
    let oversized = vec![0; cbor::DEFAULT_MAX_INPUT_BYTES + 1];
    let output = run(&oversized, &[]);
    assert!(!output.status.success());
    assert!(String::from_utf8(output.stderr)
        .unwrap()
        .contains("maximum"));
}
