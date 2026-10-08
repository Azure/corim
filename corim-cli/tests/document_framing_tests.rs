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
