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

/// The sample Azure NDPA template (authored with **prose** keys) generates
/// a valid CoRIM, and the `tcbstatus` alias resolves to the profile's
/// integer key -700 (CBOR negative int `0x39 0x02 0xbb`).
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

/// A prose-keyed template and the equivalent integer-keyed template
/// produce byte-identical output — the prose pass is a lossless rewrite
/// and is idempotent on integer keys.
#[test]
fn generate_prose_and_integer_templates_match() {
    let dir = std::env::temp_dir();
    let prose_t = dir.join("corim_cli_prose.json");
    let int_t = dir.join("corim_cli_int.json");
    let prose_out = dir.join("corim_cli_prose.cbor");
    let int_out = dir.join("corim_cli_int.cbor");

    // Same CoRIM, one authored with prose keys, one with integer keys.
    std::fs::write(
        &prose_t,
        r#"{
          "corim-id": "id-1",
          "comids": [
            { "tag-identity": { "id": "c1" },
              "triples": { "reference-triples": [
                [ { "class": { "vendor": "ACME", "model": "Widget" } },
                  [ { "value": { "svn": { "type": "svn", "value": 3 } } } ] ]
              ] } }
          ]
        }"#,
    )
    .unwrap();
    std::fs::write(
        &int_t,
        r#"{
          "corim-id": "id-1",
          "comids": [
            { "1": { "0": "c1" },
              "4": { "0": [
                [ { "0": { "1": "ACME", "2": "Widget" } },
                  [ { "1": { "1": { "type": "svn", "value": 3 } } } ] ]
              ] } }
          ]
        }"#,
    )
    .unwrap();

    for (t, o) in [(&prose_t, &prose_out), (&int_t, &int_out)] {
        let status = Command::new(bin())
            .args(["generate", t.to_str().unwrap(), "-o", o.to_str().unwrap()])
            .status()
            .expect("run corim-cli generate");
        assert!(status.success(), "generate exited non-zero for {t:?}");
    }

    let prose_bytes = std::fs::read(&prose_out).unwrap();
    let int_bytes = std::fs::read(&int_out).unwrap();
    assert_eq!(
        prose_bytes, int_bytes,
        "prose and integer templates must produce identical CBOR"
    );

    for f in [&prose_t, &int_t, &prose_out, &int_out] {
        let _ = std::fs::remove_file(f);
    }
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

/// A digest reference value can be authored: the digest `val` is a bare
/// `bstr`, written as base64 text, and coerced to CBOR bytes so the
/// CoMID deserializes and the exact bytes survive to the wire.
#[test]
fn generate_digest_reference_value() {
    let dir = std::env::temp_dir();
    let t = dir.join("corim_cli_digest.json");
    let o = dir.join("corim_cli_digest.cbor");

    // 0x3q2+7w== base64 == deadbeef; alg 7 == SHA-256.
    std::fs::write(
        &t,
        r#"{
          "corim-id": "id-1",
          "comids": [
            { "tag-identity": { "id": "c1" },
              "triples": { "reference-triples": [
                [ { "class": { "vendor": "ACME" } },
                  [ { "value": { "digests": [ [ 7, "3q2+7w==" ] ] } } ] ]
              ] } }
          ]
        }"#,
    )
    .unwrap();

    let status = Command::new(bin())
        .args(["generate", t.to_str().unwrap(), "-o", o.to_str().unwrap()])
        .status()
        .expect("run corim-cli generate");
    assert!(status.success(), "digest generate exited non-zero");

    let bytes = std::fs::read(&o).unwrap();
    let (_c, comids) =
        corim::validate::decode_and_validate(&bytes).expect("digest CoRIM must validate");
    let digests = comids[0].triples.reference_triples.as_ref().unwrap()[0].measurements()[0]
        .mval
        .digests
        .as_ref()
        .expect("expected a digests field");
    assert_eq!(
        digests[0].value(),
        &[0xde, 0xad, 0xbe, 0xef],
        "digest bytes"
    );

    let _ = std::fs::remove_file(&t);
    let _ = std::fs::remove_file(&o);
}
