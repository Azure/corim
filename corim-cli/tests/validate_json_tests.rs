// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Integration tests for `validate --format json`, covering the `signed`
//! object that mirrors the fields the text renderer shows for a signed CoRIM.

use std::process::Command;

use corim::builder::{ComidBuilder, CorimBuilder};
use corim::types::common::{MeasuredElement, TagIdChoice};
use corim::types::corim::{CorimId, CorimMetaMap, CorimSignerMap};
use corim::types::environment::{ClassMap, EnvironmentMap};
use corim::types::measurement::{MeasurementMap, MeasurementValuesMap, SvnChoice};
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
                signer_name: "Test Signer Ltd.".into(),
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
    serde_json::from_str(&stdout)
        .unwrap_or_else(|e| panic!("output is not valid JSON: {e}\n{stdout}"))
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
    assert_eq!(p["signer_name"], "Test Signer Ltd.");
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

/// A detached signed CoRIM has no payload to decode; `-f json` must still
/// emit JSON rather than falling back to the text header view.
#[test]
fn detached_signed_corim_json_emits_header_only_object() {
    let signed = make_signed(&sample_unsigned_corim(), true);
    let v = validate_json(&signed, "cose");

    assert_eq!(v["valid"], true);
    assert_eq!(v["payload_decoded"], false);
    assert_eq!(v["signed"]["payload"]["detached"], true);
    assert_eq!(v["signed"]["protected"]["issuer"], "test-issuer");
}

#[test]
fn unsigned_corim_json_has_no_signed_object() {
    let v = validate_json(&sample_unsigned_corim(), "cbor");
    assert_eq!(v["valid"], true);
    assert!(v.get("signed").is_none(), "unsigned CoRIM has no envelope");
    assert_eq!(v["id"], "json-corim");
}
