// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Integration tests for `corim-cli generate`.

use std::process::Command;

fn bin() -> &'static str {
    env!("CARGO_BIN_EXE_corim-cli")
}

fn template_path() -> String {
    format!("{}/templates/azure_ndpa.json", env!("CARGO_MANIFEST_DIR"))
}

/// The sample Azure NDPA template generates a valid CoRIM, and the
/// `tcbstatus` alias resolves to the profile's integer key -700
/// (CBOR negative int `0x39 0x02 0xbb`).
#[test]
fn generate_azure_ndpa_template_is_valid_and_resolves_alias() {
    let out = std::env::temp_dir().join("corim_cli_generate_ndpa.cbor");
    let _ = std::fs::remove_file(&out);

    let status = Command::new(bin())
        .args(["generate", &template_path(), "-o", out.to_str().unwrap()])
        .status()
        .expect("run corim-cli generate");
    assert!(status.success(), "generate exited non-zero");

    let bytes = std::fs::read(&out).expect("read generated CoRIM");

    // Must decode + validate cleanly.
    let (_corim, comids) =
        corim::validate::decode_and_validate(&bytes).expect("generated CoRIM must validate");
    assert_eq!(comids.len(), 1, "expected one CoMID tag");
    assert!(
        comids[0].triples.conditional_endorsement_series.is_some(),
        "expected a conditional-endorsement-series triple"
    );

    // The `tcbstatus` alias must have become integer key -700, encoded
    // as the CBOR negative integer 0x39 0x02 0xbb.
    let needle = [0x39u8, 0x02, 0xbb];
    assert!(
        bytes.windows(3).any(|w| w == needle),
        "expected mval key -700 (tcbstatus) in output"
    );

    let _ = std::fs::remove_file(&out);
}

/// A template without a `comids` array is rejected with a non-zero exit.
#[test]
fn generate_rejects_template_without_comids() {
    let tmp = std::env::temp_dir().join("corim_cli_generate_bad.json");
    std::fs::write(&tmp, br#"{"corim-id":"x"}"#).unwrap();

    let status = Command::new(bin())
        .args(["generate", tmp.to_str().unwrap()])
        .status()
        .expect("run corim-cli generate");
    assert!(!status.success(), "expected failure for missing comids");

    let _ = std::fs::remove_file(&tmp);
}
