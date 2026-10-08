// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! CLI document readers must not silently discard trailing CBOR data.

use corim::builder::{ComidBuilder, CorimBuilder};
use corim::cbor::{self, constants as c, value::Value};
use corim::types::common::TagIdChoice;
use corim::types::corim::CorimId;
use corim::types::environment::EnvironmentMap;
use corim::types::measurement::{MeasurementMap, MeasurementValuesMap, SvnChoice};
use corim::types::signed::*;
use corim::types::tags::*;
use corim::types::triples::ReferenceTriple;
use std::{
    fs,
    path::PathBuf,
    process::Command,
    sync::atomic::{AtomicU64, Ordering},
};

/// Break stop code (RFC 8949 §3.2.1).
const BREAK: u8 = (c::MAJOR_SIMPLE << 5) | c::AI_INDEFINITE;
struct Input(PathBuf);
impl Input {
    fn new(bytes: &[u8]) -> Self {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let path = std::env::temp_dir().join(format!(
            "corim-framing-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::write(&path, bytes).unwrap();
        Self(path)
    }
    fn path(&self) -> &str {
        self.0.to_str().unwrap()
    }
}
impl Drop for Input {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.0);
    }
}
fn success(args: &[&str]) -> bool {
    Command::new(env!("CARGO_BIN_EXE_corim-cli"))
        .args(args)
        .output()
        .unwrap()
        .status
        .success()
}
fn unsigned() -> Vec<u8> {
    let comid = ComidBuilder::new(TagIdChoice::Text("framing".into()))
        .add_reference_triple(ReferenceTriple::new(
            EnvironmentMap::for_class("V", "M"),
            vec![MeasurementMap {
                mkey: None,
                authorized_by: None,
                mval: MeasurementValuesMap {
                    svn: Some(SvnChoice::ExactValue(1)),
                    ..Default::default()
                },
            }],
        ))
        .build()
        .unwrap();
    CorimBuilder::new(CorimId::Text("framing".into()))
        .add_comid_tag(comid)
        .unwrap()
        .build_bytes()
        .unwrap()
}
fn signed(payload: Vec<u8>) -> Vec<u8> {
    SignedCorimBuilder::new(CoseAlgorithm::Es256.to_i64(), payload)
        .set_cwt_claims(CwtClaims::new("Signer"))
        .build_with_signature(vec![0xab; 64])
        .unwrap()
}
fn trailing(mut bytes: Vec<u8>, suffix: u8) -> Vec<u8> {
    bytes.push(suffix);
    bytes
}
fn embedded(suffix: u8) -> Vec<u8> {
    let Value::Tag(_, map) = cbor::decode::<Value>(&unsigned()).unwrap() else {
        panic!("CoRIM tag")
    };
    let Value::Map(mut fields) = *map else {
        panic!("CoRIM map")
    };
    let (_, Value::Array(tags)) = fields
        .iter_mut()
        .find(|(k, _)| *k == Value::Integer(i128::from(CORIM_KEY_TAGS)))
        .unwrap()
    else {
        panic!("tags")
    };
    let Value::Tag(_, body) = &mut tags[0] else {
        panic!("CoMID tag")
    };
    let Value::Bytes(bytes) = body.as_mut() else {
        panic!("CoMID body")
    };
    bytes.push(suffix);
    cbor::encode(&Value::Tag(TAG_CORIM, Box::new(Value::Map(fields)))).unwrap()
}

#[test]
fn validation_modes_reject_top_and_embedded_trailing_data() {
    let clean = Input::new(&unsigned());
    let mut accepted = Vec::new();
    for flag in [None, Some("--edn"), Some("--diagnose")] {
        let run = |path: &str| {
            let mut a = vec!["validate", path];
            a.extend(flag);
            success(&a)
        };
        assert!(run(clean.path()), "clean control: {flag:?}");
        for suffix in [BREAK, c::BYTE_NULL] {
            for (name, bytes) in [
                ("outer", trailing(unsigned(), suffix)),
                ("embedded", embedded(suffix)),
                ("signed payload", signed(trailing(unsigned(), suffix))),
                ("signed tag", signed(embedded(suffix))),
            ] {
                let input = Input::new(&bytes);
                if run(input.path()) {
                    accepted.push((flag, name, suffix));
                }
            }
        }
    }
    assert!(accepted.is_empty(), "accepted trailing data: {accepted:?}");
}

#[test]
fn edn_rejects_trailing_data_in_tcg_bare_bstr_tags() {
    for suffix in [None, Some(BREAK), Some(c::BYTE_NULL)] {
        let Value::Tag(_, map) = cbor::decode::<Value>(&unsigned()).unwrap() else {
            panic!("CoRIM tag")
        };
        let Value::Map(mut fields) = *map else {
            panic!("CoRIM map")
        };
        let (_, Value::Array(tags)) = fields
            .iter_mut()
            .find(|(k, _)| *k == Value::Integer(i128::from(CORIM_KEY_TAGS)))
            .unwrap()
        else {
            panic!("tags")
        };
        let Value::Tag(_, body) = &tags[0] else {
            panic!("CoMID tag")
        };
        let Value::Bytes(mut bytes) = *body.clone() else {
            panic!("CoMID body")
        };
        bytes.extend(suffix);
        tags[0] = Value::Bytes(bytes);
        let payload = cbor::encode(&Value::Map(fields)).unwrap();
        for (name, bytes) in [
            ("bare unsigned", payload.clone()),
            ("signed payload", signed(payload)),
        ] {
            let input = Input::new(&bytes);
            assert_eq!(
                success(&["validate", input.path(), "--edn"]),
                suffix.is_none(),
                "{name}: {suffix:?}"
            );
        }
    }
}

#[test]
fn convert_extract_and_finalize_enforce_document_framing() {
    let signature = Input::new(&[0xab; 64]);
    let output = Input::new(&[]);
    let clean = Input::new(&signed(unsigned()));
    let mut accepted = Vec::new();
    for command in ["convert", "extract", "finalize"] {
        let run = |path: &str| match command {
            "finalize" => success(&[
                "sign",
                "finalize",
                path,
                "--signature",
                signature.path(),
                "-o",
                output.path(),
            ]),
            _ => success(&[command, path, "-o", output.path()]),
        };
        assert!(run(clean.path()), "clean control: {command}");
        for suffix in [BREAK, c::BYTE_NULL] {
            for (name, bytes) in [
                ("outer", trailing(signed(unsigned()), suffix)),
                ("payload", signed(trailing(unsigned(), suffix))),
                ("tag", signed(embedded(suffix))),
            ] {
                let input = Input::new(&bytes);
                if run(input.path()) {
                    accepted.push((command, name, suffix));
                }
            }
        }
    }
    assert!(accepted.is_empty(), "accepted trailing data: {accepted:?}");
}

#[test]
fn edn_keeps_unknown_extension_tag_contents_opaque() {
    let mut extensions: Vec<_> = [TAG_COSWID, TAG_COMID, TAG_COTL]
        .into_iter()
        .map(|tag| Value::Tag(tag, Box::new(Value::Bytes(vec![0, 1]))))
        .collect();
    extensions.push(Value::Tag(
        TAG_SIGNED_CORIM,
        Box::new(Value::Array(vec![
            Value::Bytes(vec![0, 1]),
            Value::Map(vec![]),
            Value::Null,
            Value::Bytes(vec![]),
        ])),
    ));
    for extension in extensions {
        for boundary in ["outer", "comid", "header"] {
            let mut root: Value = cbor::decode(&unsigned()).unwrap();
            let Value::Tag(_, map) = &mut root else {
                panic!("CoRIM")
            };
            let Value::Map(fields) = map.as_mut() else {
                panic!("CoRIM map")
            };
            let extra = (Value::Integer(10001), Value::Array(vec![extension.clone()]));
            if boundary == "outer" {
                fields.push(extra);
            } else if boundary == "comid" {
                let (_, Value::Array(tags)) = fields
                    .iter_mut()
                    .find(|(key, _)| *key == Value::Integer(i128::from(CORIM_KEY_TAGS)))
                    .unwrap()
                else {
                    panic!("tags")
                };
                let Value::Tag(_, body) = &mut tags[0] else {
                    panic!("CoMID tag")
                };
                let Value::Bytes(bytes) = body.as_mut() else {
                    panic!("CoMID bytes")
                };
                let Value::Map(mut fields) = cbor::decode(bytes).unwrap() else {
                    panic!("CoMID map")
                };
                fields.push(extra);
                *bytes = cbor::encode(&Value::Map(fields)).unwrap();
            } else {
                root = cbor::decode(&signed(cbor::encode(&root).unwrap())).unwrap();
                let Value::Tag(_, array) = &mut root else {
                    panic!("COSE tag")
                };
                let Value::Array(parts) = array.as_mut() else {
                    panic!("COSE array")
                };
                let Value::Bytes(bytes) = &mut parts[0] else {
                    panic!("protected bytes")
                };
                let Value::Map(mut fields) = cbor::decode(bytes).unwrap() else {
                    panic!("header map")
                };
                fields.push(extra);
                *bytes = cbor::encode(&Value::Map(fields)).unwrap();
            }
            let encoded = cbor::encode(&root).unwrap();
            let control = Input::new(&encoded);
            assert!(
                success(&["validate", control.path()]),
                "control: {boundary}"
            );
            let mut inputs = vec![encoded.clone()];
            if boundary != "header" {
                let Value::Tag(_, inner) = &root else {
                    panic!("CoRIM")
                };
                let bare = cbor::encode(inner.as_ref()).unwrap();
                inputs.extend([bare.clone(), signed(encoded), signed(bare)]);
                inputs.push(cbor::encode(&Value::Tag(TAG_LEGACY_TOP, Box::new(root))).unwrap());
            }
            for bytes in inputs {
                let input = Input::new(&bytes);
                let output = Command::new(env!("CARGO_BIN_EXE_corim-cli"))
                    .args(["validate", input.path(), "--edn"])
                    .output()
                    .unwrap();
                assert!(
                    output.status.success(),
                    "{boundary}: {}",
                    String::from_utf8_lossy(&output.stderr)
                );
                assert!(String::from_utf8(output.stdout)
                    .unwrap()
                    .contains("h'0001'"));
            }
        }
    }
}
