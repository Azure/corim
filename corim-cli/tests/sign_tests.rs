// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Integration tests for the `extract` and `sign prepare` / `sign finalize`
//! CLI subcommands.

use std::process::Command;

use corim::builder::{ComidBuilder, CorimBuilder};
use corim::types::common::{MeasuredElement, TagIdChoice};
use corim::types::corim::CorimId;
use corim::types::environment::{ClassMap, EnvironmentMap};
use corim::types::measurement::{Digest, MeasurementMap, MeasurementValuesMap};
use corim::types::signed::{CwtClaims, SignedCorimBuilder};
use corim::types::triples::ReferenceTriple;

fn bin() -> &'static str {
    env!("CARGO_BIN_EXE_corim-cli")
}

/// A unique temp path so parallel tests never collide on a fixed name.
fn unique_temp(stem: &str, ext: &str) -> std::path::PathBuf {
    use std::sync::atomic::{AtomicU64, Ordering};
    static N: AtomicU64 = AtomicU64::new(0);
    let n = N.fetch_add(1, Ordering::Relaxed);
    std::env::temp_dir().join(format!("corim_cli_{stem}_{}_{n}.{ext}", std::process::id()))
}

/// Build a minimal unsigned CoRIM (`tagged-unsigned-corim-map`) for tests.
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
            digests: Some(vec![Digest::new(7, vec![0xBB; 48])]),
            ..MeasurementValuesMap::default()
        },
        authorized_by: None,
    };
    let comid = ComidBuilder::new(TagIdChoice::Text("sign-cli-comid".into()))
        .add_reference_triple(ReferenceTriple::new(env, vec![meas]))
        .build()
        .unwrap();
    CorimBuilder::new(CorimId::Text("sign-cli-corim".into()))
        .add_comid_tag(comid)
        .unwrap()
        .build_bytes()
        .unwrap()
}

/// Build a signed CoRIM with a placeholder signature (attached or detached).
fn make_signed(unsigned: &[u8], detached: bool) -> Vec<u8> {
    let builder = SignedCorimBuilder::new(-7, unsigned.to_vec())
        .set_cwt_claims(CwtClaims::new("Test Signer"));
    if detached {
        builder
            .build_detached_with_signature(vec![0xAB; 64])
            .unwrap()
    } else {
        builder.build_with_signature(vec![0xAB; 64]).unwrap()
    }
}

#[test]
fn extract_returns_attached_payload_bytes() {
    let unsigned = sample_unsigned_corim();
    let signed = make_signed(&unsigned, false);

    let sc = unique_temp("extract_signed", "cose");
    let out = unique_temp("extract_out", "cbor");
    std::fs::write(&sc, &signed).unwrap();

    let status = Command::new(bin())
        .args(["extract", sc.to_str().unwrap(), "-o", out.to_str().unwrap()])
        .status()
        .expect("run extract");
    assert!(status.success(), "extract should succeed");

    let extracted = std::fs::read(&out).unwrap();
    assert_eq!(
        extracted, unsigned,
        "extracted payload must equal the original"
    );

    for f in [&sc, &out] {
        let _ = std::fs::remove_file(f);
    }
}

#[test]
fn extract_detached_payload_errors() {
    let unsigned = sample_unsigned_corim();
    let signed = make_signed(&unsigned, true);

    let sc = unique_temp("extract_detached", "cose");
    std::fs::write(&sc, &signed).unwrap();

    let status = Command::new(bin())
        .args(["extract", sc.to_str().unwrap(), "-o", "/dev/null"])
        .status()
        .expect("run extract");
    assert!(!status.success(), "extract must fail on a detached payload");

    let _ = std::fs::remove_file(&sc);
}

#[test]
fn sign_prepare_then_finalize_round_trip() {
    let unsigned = sample_unsigned_corim();
    let ut = unique_temp("sign_unsigned", "cbor");
    let staging = unique_temp("sign_staging", "cose");
    let tbs = unique_temp("sign_tbs", "bin");
    let sig = unique_temp("sign_sig", "bin");
    let signed = unique_temp("sign_signed", "cose");
    let extracted = unique_temp("sign_extracted", "cbor");
    std::fs::write(&ut, &unsigned).unwrap();

    // prepare
    let status = Command::new(bin())
        .args([
            "sign",
            "prepare",
            ut.to_str().unwrap(),
            "--alg",
            "ES256",
            "--signer-name",
            "Test Signer",
            "--out-staging",
            staging.to_str().unwrap(),
            "--out-tbs",
            tbs.to_str().unwrap(),
        ])
        .status()
        .expect("run sign prepare");
    assert!(status.success(), "sign prepare should succeed");
    assert!(
        !std::fs::read(&tbs).unwrap().is_empty(),
        "tbs must be non-empty"
    );

    // external signature (dummy — verification is out of scope)
    std::fs::write(&sig, vec![0xCDu8; 64]).unwrap();

    // finalize
    let status = Command::new(bin())
        .args([
            "sign",
            "finalize",
            staging.to_str().unwrap(),
            "--signature",
            sig.to_str().unwrap(),
            "-o",
            signed.to_str().unwrap(),
        ])
        .status()
        .expect("run sign finalize");
    assert!(status.success(), "sign finalize should succeed");

    // validate the final signed CoRIM (structure only)
    let status = Command::new(bin())
        .args(["validate", signed.to_str().unwrap()])
        .status()
        .expect("run validate");
    assert!(status.success(), "signed CoRIM must validate structurally");

    // extract must return the original unsigned payload byte-for-byte
    let status = Command::new(bin())
        .args([
            "extract",
            signed.to_str().unwrap(),
            "-o",
            extracted.to_str().unwrap(),
        ])
        .status()
        .expect("run extract");
    assert!(status.success());
    assert_eq!(std::fs::read(&extracted).unwrap(), unsigned);

    for f in [&ut, &staging, &tbs, &sig, &signed, &extracted] {
        let _ = std::fs::remove_file(f);
    }
}

#[test]
fn sign_prepare_rejects_unknown_algorithm() {
    let unsigned = sample_unsigned_corim();
    let ut = unique_temp("sign_badalg", "cbor");
    let staging = unique_temp("sign_badalg_staging", "cose");
    let tbs = unique_temp("sign_badalg_tbs", "bin");
    std::fs::write(&ut, &unsigned).unwrap();

    let status = Command::new(bin())
        .args([
            "sign",
            "prepare",
            ut.to_str().unwrap(),
            "--alg",
            "NOT-AN-ALG",
            "--signer-name",
            "X",
            "--out-staging",
            staging.to_str().unwrap(),
            "--out-tbs",
            tbs.to_str().unwrap(),
        ])
        .status()
        .expect("run sign prepare");
    assert!(!status.success(), "unknown algorithm must be rejected");

    let _ = std::fs::remove_file(&ut);
}
