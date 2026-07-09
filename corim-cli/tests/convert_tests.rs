// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Integration tests for `corim-cli convert` and the
//! `convert -> generate` round trip.

use std::process::Command;

fn bin() -> &'static str {
    env!("CARGO_BIN_EXE_corim-cli")
}

/// Generate a CoRIM from a template, convert it back to a template, then
/// generate again — the two CBOR outputs must be byte-identical.
fn assert_round_trip(name: &str, template: &str) {
    let dir = std::env::temp_dir();
    let src_t = dir.join(format!("corim_cli_conv_{name}_src.json"));
    let src_c = dir.join(format!("corim_cli_conv_{name}_src.cbor"));
    let back_t = dir.join(format!("corim_cli_conv_{name}_back.json"));
    let back_c = dir.join(format!("corim_cli_conv_{name}_back.cbor"));

    std::fs::write(&src_t, template).unwrap();

    // template -> CBOR
    let s = Command::new(bin())
        .args([
            "generate",
            src_t.to_str().unwrap(),
            "-o",
            src_c.to_str().unwrap(),
        ])
        .status()
        .expect("generate src");
    assert!(s.success(), "{name}: generate src failed");

    // CBOR -> template
    let s = Command::new(bin())
        .args([
            "convert",
            src_c.to_str().unwrap(),
            "-o",
            back_t.to_str().unwrap(),
        ])
        .status()
        .expect("convert");
    assert!(s.success(), "{name}: convert failed");

    // template -> CBOR again
    let s = Command::new(bin())
        .args([
            "generate",
            back_t.to_str().unwrap(),
            "-o",
            back_c.to_str().unwrap(),
        ])
        .status()
        .expect("generate back");
    assert!(s.success(), "{name}: generate back failed");

    let a = std::fs::read(&src_c).unwrap();
    let b = std::fs::read(&back_c).unwrap();
    assert_eq!(a, b, "{name}: convert -> generate must be byte-identical");

    for f in [&src_t, &src_c, &back_t, &back_c] {
        let _ = std::fs::remove_file(f);
    }
}

/// A minimal CoMID-only CoRIM round-trips through convert.
#[test]
fn convert_round_trip_minimal_comid() {
    assert_round_trip(
        "minimal",
        r#"{
          "corim-id": "id-1",
          "comids": [
            { "tag-identity": { "id": "c1" },
              "triples": { "reference-triples": [
                [ { "class": { "vendor": "ACME" } },
                  [ { "value": { "svn": { "type": "svn", "value": 3 } } } ] ]
              ] } }
          ]
        }"#,
    );
}

/// All CoRIM-level fields (UUID id, OID profile, validity, entities,
/// dependent-rims), integrity-registers, and a CoTL round-trip.
#[test]
fn convert_round_trip_full_fields() {
    assert_round_trip(
        "full",
        r#"{
          "corim-id": { "type": "uuid", "value": "550e8400-e29b-41d4-a716-446655440000" },
          "profile": { "type": "oid", "value": "BgYrBgEEAQ==" },
          "rim-validity": { "not-before": 1700000000, "not-after": 1900000000 },
          "entities": [ { "entity-name": "ACME", "reg-id": "https://acme.example", "role": [1] } ],
          "dependent-rims": [ { "href": "https://example.com/rim1", "thumbprint": [7, "3q2+7w=="] } ],
          "comids": [
            { "tag-identity": { "id": "c1" },
              "triples": { "reference-triples": [
                [ { "class": { "vendor": "ACME" } },
                  [ { "value": { "integrity-registers": {
                        "0": [ [7, "3q2+7w=="] ],
                        "cfg": [ [2, "3q2+7w=="] ] } } } ] ]
              ] } }
          ],
          "cotls": [
            { "tag-identity": { "id": "tl1" },
              "tags-list": [ { "id": "c1" } ],
              "tl-validity": { "not-after": 1900000000 } }
          ]
        }"#,
    );
}

/// An identity triple with a cert-thumbprint crypto key round-trips
/// (digest bytes inside a type-choice tag).
#[test]
fn convert_round_trip_cert_thumbprint() {
    assert_round_trip(
        "thumbprint",
        r#"{
          "corim-id": "id-1",
          "comids": [
            { "tag-identity": { "id": "c1" },
              "triples": { "identity-triples": [
                [ { "class": { "vendor": "ACME" } },
                  [ { "type": "cert-thumbprint", "value": [ 2, "3q2+7w==" ] } ] ]
              ] } }
          ]
        }"#,
    );
}

/// Convert rejects a signed CoRIM with a clear message.
#[test]
fn convert_rejects_signed_corim() {
    // Minimal tag-18 (0xD2) wrapper prefix is enough to trip the check.
    let dir = std::env::temp_dir();
    let f = dir.join("corim_cli_conv_signed.cbor");
    std::fs::write(&f, [0xD2u8, 0x84, 0x40, 0xA0, 0xF6, 0x40]).unwrap();

    let out = Command::new(bin())
        .args(["convert", f.to_str().unwrap()])
        .output()
        .expect("run convert");
    assert!(!out.status.success(), "expected failure on signed input");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("signed CoRIM"),
        "expected signed-CoRIM error, got: {stderr}"
    );

    let _ = std::fs::remove_file(&f);
}

/// Convert uses profile-aware alias names for mval extension keys
/// (Azure: -700 -> tcbstatus).
#[test]
fn convert_emits_azure_mval_alias_name() {
        let dir = std::env::temp_dir();
        let src_t = dir.join("corim_cli_conv_azure_alias_src.json");
        let src_c = dir.join("corim_cli_conv_azure_alias_src.cbor");
        let back_t = dir.join("corim_cli_conv_azure_alias_back.json");

        let template = r#"{
            "corim-id": "id-azure-1",
            "profile": "tag:microsoft.com,2026:azure-profile#1.0.0",
            "comids": [
                {
                    "tag-identity": { "id": "c1" },
                    "triples": {
                        "reference-triples": [
                            [
                                { "class": { "vendor": "Microsoft" } },
                                [ { "value": { "-700": "UpToDate" } } ]
                            ]
                        ]
                    }
                }
            ]
        }"#;

        std::fs::write(&src_t, template).unwrap();

        let s = Command::new(bin())
                .args([
                        "generate",
                        src_t.to_str().unwrap(),
                        "-o",
                        src_c.to_str().unwrap(),
                ])
                .status()
                .expect("generate src");
        assert!(s.success(), "azure alias test: generate src failed");

        let s = Command::new(bin())
                .args(["convert", src_c.to_str().unwrap(), "-o", back_t.to_str().unwrap()])
                .status()
                .expect("convert");
        assert!(s.success(), "azure alias test: convert failed");

        let back = std::fs::read_to_string(&back_t).unwrap();
        assert!(
                back.contains("\"tcbstatus\": \"UpToDate\""),
                "expected tcbstatus alias in output JSON, got: {back}"
        );
        assert!(
                !back.contains("\"-700\": \"UpToDate\""),
                "did not expect raw -700 key in output JSON, got: {back}"
        );

        for f in [&src_t, &src_c, &back_t] {
                let _ = std::fs::remove_file(f);
        }
}
