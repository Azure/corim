// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Integration tests for `corim-cli validate --baseline`.

use std::process::Command;

use corim::builder::{ComidBuilder, CorimBuilder};
use corim::types::common::{MeasuredElement, TagIdChoice};
use corim::types::corim::CorimId;
use corim::types::environment::{ClassMap, EnvironmentMap};
use corim::types::measurement::{Digest, MeasurementMap, MeasurementValuesMap, SvnChoice};
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

/// Build a one-reference-triple CoRIM; `with_svn` toggles the svn field.
fn corim_bytes(digest: Vec<u8>, with_svn: bool) -> Vec<u8> {
    let env = EnvironmentMap {
        class: Some(ClassMap {
            class_id: None,
            vendor: Some("Intel".into()),
            model: Some("TDX".into()),
            layer: None,
            index: None,
        }),
        instance: None,
        group: None,
    };
    let meas = MeasurementMap {
        mkey: Some(MeasuredElement::Text("MRTD".into())),
        mval: MeasurementValuesMap {
            digests: Some(vec![Digest::new(7, digest)]),
            svn: with_svn.then_some(SvnChoice::MinValue(1)),
            ..MeasurementValuesMap::default()
        },
        authorized_by: None,
    };
    let comid = ComidBuilder::new(TagIdChoice::Text("c1".into()))
        .add_reference_triple(ReferenceTriple::new(env, vec![meas]))
        .build()
        .unwrap();
    CorimBuilder::new(CorimId::Text("corim-1".into()))
        .add_comid_tag(comid)
        .unwrap()
        .build_bytes()
        .unwrap()
}

fn write(stem: &str, bytes: &[u8]) -> std::path::PathBuf {
    let p = unique_temp(stem, "cbor");
    std::fs::write(&p, bytes).unwrap();
    p
}

fn tcg_bytes(bytes: &[u8]) -> Vec<u8> {
    use corim::cbor::{self, value::Tagged, value::Value};
    use corim::types::corim::{ConciseTagChoice, CorimMap};

    let mut doc: Tagged<CorimMap> = cbor::decode(bytes).unwrap();
    for tag in &mut doc.value.tags {
        if let ConciseTagChoice::Comid(inner) = tag {
            *tag = cbor::decode(&cbor::encode(&Value::Bytes(inner.clone())).unwrap()).unwrap();
        }
    }
    cbor::encode(&doc).unwrap()
}

fn compare_tcg_input(with_svn: bool) -> (Option<i32>, serde_json::Value) {
    let b = write("tcg_base", &tcg_bytes(&corim_bytes(vec![0xAA; 48], true)));
    let i = write(
        "tcg_input",
        &tcg_bytes(&corim_bytes(vec![0xBB; 48], with_svn)),
    );
    let out = Command::new(bin())
        .args([
            "validate",
            i.to_str().unwrap(),
            "--baseline",
            b.to_str().unwrap(),
            "--format",
            "json",
        ])
        .output()
        .expect("run TCG baseline comparison");
    for f in [&b, &i] {
        std::fs::remove_file(f).unwrap();
    }
    let report = serde_json::from_slice(&out.stdout).expect("JSON report");
    (out.status.code(), report)
}

#[test]
fn tcg_digest_difference_is_reported_with_exit_0() {
    let (code, report) = compare_tcg_input(true);
    assert_eq!(code, Some(0));
    assert_eq!(report["result"], "value-differences");
    assert_eq!(report["conformant"], true);
    assert_eq!(report["summary"]["value_differences"], 1);
}

#[test]
fn tcg_missing_svn_is_a_structural_mismatch_exit_3() {
    let (code, report) = compare_tcg_input(false);
    assert_eq!(code, Some(3));
    assert_eq!(report["result"], "structural-mismatch");
    assert_eq!(report["conformant"], false);
    assert_eq!(report["summary"]["structural_mismatches"], 1);
}

#[test]
fn identical_input_is_conformant_exit_0() {
    let b = write("bl_base", &corim_bytes(vec![0xAA; 48], true));
    let i = write("bl_in", &corim_bytes(vec![0xAA; 48], true));
    let code = Command::new(bin())
        .args([
            "validate",
            i.to_str().unwrap(),
            "--baseline",
            b.to_str().unwrap(),
        ])
        .status()
        .expect("run")
        .code();
    assert_eq!(code, Some(0));
    for f in [&b, &i] {
        let _ = std::fs::remove_file(f);
    }
}

#[test]
fn different_digest_is_conformant_with_value_difference() {
    let b = write("bl_base2", &corim_bytes(vec![0xAA; 48], true));
    let i = write("bl_in2", &corim_bytes(vec![0xBB; 48], true));
    let out = Command::new(bin())
        .args([
            "validate",
            i.to_str().unwrap(),
            "--baseline",
            b.to_str().unwrap(),
        ])
        .output()
        .expect("run");
    assert_eq!(out.status.code(), Some(0), "digest bytes may differ");
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("value difference"), "got: {stdout}");
    for f in [&b, &i] {
        let _ = std::fs::remove_file(f);
    }
}

#[test]
fn missing_field_is_structural_mismatch_exit_3() {
    let b = write("bl_base3", &corim_bytes(vec![0xAA; 48], true)); // has svn
    let i = write("bl_in3", &corim_bytes(vec![0xAA; 48], false)); // no svn
    let code = Command::new(bin())
        .args([
            "validate",
            i.to_str().unwrap(),
            "--baseline",
            b.to_str().unwrap(),
        ])
        .status()
        .expect("run")
        .code();
    assert_eq!(code, Some(3), "missing svn field is a structural mismatch");
    for f in [&b, &i] {
        let _ = std::fs::remove_file(f);
    }
}

#[test]
fn json_output_reports_result() {
    let b = write("bl_base4", &corim_bytes(vec![0xAA; 48], true));
    let i = write("bl_in4", &corim_bytes(vec![0xBB; 48], true));
    let out = Command::new(bin())
        .args([
            "validate",
            i.to_str().unwrap(),
            "--baseline",
            b.to_str().unwrap(),
            "--format",
            "json",
        ])
        .output()
        .expect("run");
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).expect("json");
    assert_eq!(v["result"], "value-differences");
    assert_eq!(v["conformant"], true);
    assert_eq!(v["summary"]["value_differences"], 1);
    for f in [&b, &i] {
        let _ = std::fs::remove_file(f);
    }
}
