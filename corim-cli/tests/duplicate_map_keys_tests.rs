// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Duplicate schema keys must fail even inspection-oriented CLI modes.

use corim::builder::{ComidBuilder, CorimBuilder};
use corim::cbor::{self, value::Value};
use corim::types::common::TagIdChoice;
use corim::types::corim::CorimId;
use corim::types::environment::EnvironmentMap;
use corim::types::signed::*;
use corim::types::tags::*;
use std::io::Write;
use std::process::{Command, Output, Stdio};

fn run(args: &[&str], bytes: &[u8], valid: bool) -> Output {
    let mut child = Command::new(env!("CARGO_BIN_EXE_corim-cli"))
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child.stdin.take().unwrap().write_all(bytes).unwrap();
    let out = child.wait_with_output().unwrap();
    assert_eq!(out.status.success(), valid, "{args:?}: {out:?}");
    if !valid {
        let mut diagnostic = out.stdout.clone();
        diagnostic.extend_from_slice(&out.stderr);
        assert!(
            String::from_utf8_lossy(&diagnostic)
                .to_lowercase()
                .contains("duplicate"),
            "{args:?}: {out:?}"
        );
    }
    out
}
fn int(n: i64) -> Value {
    Value::Integer(n.into())
}
fn map(v: &mut Value) -> &mut Vec<(Value, Value)> {
    match v {
        Value::Tag(_, inner) => map(inner),
        Value::Map(m) => m,
        _ => panic!("expected map"),
    }
}
fn duplicate(bytes: &[u8], key: i64) -> Vec<u8> {
    let mut v: Value = cbor::decode(bytes).unwrap();
    let m = map(&mut v);
    m.push(m.iter().find(|(k, _)| *k == int(key)).unwrap().clone());
    cbor::encode(&v).unwrap()
}
fn unsigned() -> Vec<u8> {
    let env = EnvironmentMap::for_class("V", "M");
    let comid = ComidBuilder::new(TagIdChoice::Text("comid".into()))
        .add_dependency_triple_for(env.clone(), vec![env.into()])
        .build()
        .unwrap();
    CorimBuilder::new(CorimId::Text("corim".into()))
        .add_comid_tag(comid)
        .unwrap()
        .build_bytes()
        .unwrap()
}
fn header() -> Vec<u8> {
    let h = ProtectedCorimHeaderMapBuilder::new(CoseAlgorithm::Es256)
        .content_type(CORIM_CONTENT_TYPE)
        .cwt_claims(CwtClaims::new("issuer"))
        .build();
    cbor::encode(&h).unwrap()
}
fn signed(h: Vec<u8>, payload: Option<Vec<u8>>) -> Vec<u8> {
    let arr = Value::Array(vec![
        Value::Bytes(h),
        Value::Map(vec![]),
        payload.map_or(Value::Null, Value::Bytes),
        Value::Bytes(vec![0; 64]),
    ]);
    cbor::encode(&Value::Tag(TAG_SIGNED_CORIM, Box::new(arr))).unwrap()
}
fn cases() -> Vec<Vec<u8>> {
    let clean = unsigned();
    let id = duplicate(&clean, CORIM_KEY_ID);
    let mut tag: Value = cbor::decode(&clean).unwrap();
    let (_, Value::Array(tags)) = map(&mut tag)
        .iter_mut()
        .find(|(k, _)| *k == int(CORIM_KEY_TAGS))
        .unwrap()
    else {
        panic!("tags")
    };
    let Value::Tag(_, inner) = &mut tags[0] else {
        panic!("CoMID")
    };
    let Value::Bytes(bytes) = inner.as_mut() else {
        panic!("CoMID bytes")
    };
    *bytes = duplicate(bytes, COMID_KEY_TAG_IDENTITY);
    let tag = cbor::encode(&tag).unwrap();
    let signer = (
        int(META_KEY_SIGNER),
        Value::Map(vec![(int(SIGNER_KEY_NAME), Value::Text("issuer".into()))]),
    );
    let meta = cbor::encode(&Value::Map(vec![signer.clone(), signer])).unwrap();
    let mut h: Value = cbor::decode(&header()).unwrap();
    map(&mut h).push((int(COSE_HEADER_CORIM_META), Value::Bytes(meta)));
    vec![
        signed(header(), Some(id.clone())),
        signed(header(), Some(tag.clone())),
        signed(cbor::encode(&h).unwrap(), Some(clean.clone())),
        signed(duplicate(&header(), COSE_HEADER_ALG), Some(clean)),
        id,
        tag,
    ]
}

#[test]
fn validate_and_convert_reject_duplicate_document_components() {
    for args in [
        vec!["validate", "-"],
        vec!["validate", "-", "-f", "json"],
        vec!["validate", "-", "--diagnose"],
        vec!["validate", "-", "--edn"],
        vec!["convert", "-"],
    ] {
        for clean in [unsigned(), signed(header(), Some(unsigned()))] {
            run(&args, &clean, true);
        }
        for bytes in cases() {
            run(&args, &bytes, false);
        }
    }
}

#[test]
fn extract_rejects_duplicate_header_metadata_payload_and_tag() {
    let out = run(&["extract", "-"], &signed(header(), Some(unsigned())), true);
    assert_eq!(out.stdout, unsigned());
    for bytes in cases().into_iter().take(4) {
        run(&["extract", "-"], &bytes, false);
    }
}

#[test]
fn detached_flat_alg_issuer_pair_remains_accepted_and_header_bytes_are_retained() {
    let mut h: Value = cbor::decode(&header()).unwrap();
    map(&mut h).retain(|(k, _)| *k != int(COSE_HEADER_CWT_CLAIMS));
    map(&mut h).push((int(CWT_CLAIM_ISS), Value::Text("issuer".into())));
    let bytes = cbor::encode(&h).unwrap();
    let envelope = signed(bytes.clone(), None);
    // Diagnose's separate schema walker does not model legacy flat claims.
    for flags in [vec![], vec!["-f", "json"], vec!["--edn"]] {
        let args: Vec<_> = ["validate", "-"].into_iter().chain(flags).collect();
        run(&args, &envelope, true);
    }
    let out = run(&["extract", "-", "--header"], &envelope, true);
    assert_eq!(out.stdout, bytes);
}

#[test]
fn duplicate_maps_in_tolerated_cose_slots_cannot_disappear() {
    for slot in [2, 3, 4] {
        let mut value: Value = cbor::decode(&signed(header(), None)).unwrap();
        let Value::Tag(_, inner) = &mut value else {
            panic!("tag")
        };
        let Value::Array(parts) = inner.as_mut() else {
            panic!("array")
        };
        let pair = (int(COSE_HEADER_ALG), Value::Null);
        let duplicate = Value::Map(vec![pair.clone(), pair]);
        if slot == parts.len() {
            parts.push(duplicate);
        } else {
            parts[slot] = duplicate;
        }
        let bytes = cbor::encode(&value).unwrap();
        assert!(decode_signed_corim(&bytes).is_err());
        for args in [
            vec!["validate", "-", "-f", "json"],
            vec!["validate", "-", "--edn"],
            vec!["validate", "-", "--diagnose"],
        ] {
            run(&args, &bytes, false);
        }
    }
}
