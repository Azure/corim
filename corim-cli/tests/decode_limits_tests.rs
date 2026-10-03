// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! CLI input and recursive EDN resource-limit regressions.

use std::fs::{self, File};
use std::io::Write;
use std::path::PathBuf;
use std::process::{Command, Output, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};

use corim::cbor::{self, constants as c, value::Value, DecodeLimits};
use corim::types::signed::{
    CoseAlgorithm, CwtClaims, ProtectedCorimHeaderMapBuilder, SignedCorimBuilder,
    CORIM_CONTENT_TYPE,
};
use corim::types::tags::{TAG_COMID, TAG_CORIM, TAG_COSWID, TAG_COTL, TAG_SIGNED_CORIM};

/// Break stop code, invalid outside indefinite-length items (RFC 8949 §3.2.1).
const BYTE_BREAK: u8 = (c::MAJOR_SIMPLE << 5) | c::AI_INDEFINITE;
/// SHA-256 COSE algorithm identifier (RFC 9054 §2.1).
const COSE_SHA_256: i64 = -16;
/// SHA-256 digest length in bytes (RFC 9054 §2.1).
const SHA_256_BYTES: usize = 32;

fn bin() -> &'static str {
    env!("CARGO_BIN_EXE_corim-cli")
}

struct InputFile(PathBuf);

impl InputFile {
    fn new(bytes: &[u8]) -> Self {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let path = std::env::temp_dir().join(format!(
            "corim_cli_limits_{}_{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed),
        ));
        fs::write(&path, bytes).unwrap();
        Self(path)
    }

    fn oversized() -> Self {
        let file = Self::new(&[]);
        File::options()
            .write(true)
            .open(&file.0)
            .unwrap()
            .set_len(u64::try_from(DecodeLimits::default().max_input_bytes + 1).unwrap())
            .unwrap();
        file
    }

    fn path(&self) -> &str {
        self.0.to_str().unwrap()
    }
}

impl Drop for InputFile {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.0);
    }
}

fn run(args: &[&str]) -> Output {
    Command::new(bin()).args(args).output().unwrap()
}

fn assert_failure(output: &Output, expected: &str) {
    assert!(
        !output.status.success(),
        "unexpected success: {}",
        String::from_utf8_lossy(&output.stdout)
    );
    let error = String::from_utf8_lossy(&output.stderr);
    assert!(
        error.contains(expected),
        "expected {expected:?}, got {error:?}"
    );
    assert!(
        output.status.code().is_some(),
        "terminated by a signal: {error}"
    );
}

fn edn(bytes: &[u8]) -> Output {
    let file = InputFile::new(bytes);
    run(&["validate", file.path(), "--edn"])
}

fn encoded(value: Value) -> Vec<u8> {
    cbor::encode(&value).unwrap()
}

fn embedded(tag: u64, bytes: Vec<u8>) -> Value {
    Value::Tag(tag, Box::new(Value::Bytes(bytes)))
}

fn array_bytes(count: usize) -> Vec<u8> {
    let mut bytes = vec![(c::MAJOR_ARRAY << 5) | c::AI_FOUR_BYTES];
    bytes.extend_from_slice(&u32::try_from(count).unwrap().to_be_bytes());
    bytes.resize(bytes.len() + count, 0);
    bytes
}

fn cose(protected: Vec<u8>, payload: Vec<u8>) -> Value {
    Value::Tag(
        TAG_SIGNED_CORIM,
        Box::new(Value::Array(vec![
            Value::Bytes(protected),
            Value::Map(vec![]),
            Value::Bytes(payload),
            Value::Bytes(vec![]),
        ])),
    )
}

#[test]
fn oversized_document_files_fail_in_every_reader() {
    let file = InputFile::oversized();
    for args in [
        vec!["validate", file.path()],
        vec!["validate", file.path(), "--edn"],
        vec!["validate", file.path(), "--diagnose"],
        vec!["convert", file.path()],
        vec!["extract", file.path()],
        vec!["generate", file.path(), "-o", "/dev/null"],
        vec![
            "sign",
            "prepare",
            file.path(),
            "--alg",
            "ES256",
            "--signer-name",
            "test",
            "--out-staging",
            "/dev/null",
            "--out-tbs",
            "/dev/null",
        ],
        vec![
            "sign",
            "finalize",
            file.path(),
            "--signature",
            file.path(),
            "-o",
            "/dev/null",
        ],
    ] {
        assert_failure(&run(&args), "input exceeds maximum size");
    }
}

#[test]
fn oversized_piped_stdin_fails_with_and_without_dash() {
    let bytes = vec![0; DecodeLimits::default().max_input_bytes + 1];
    for command in ["validate", "convert", "extract"] {
        for explicit_dash in [false, true] {
            let mut cmd = Command::new(bin());
            cmd.arg(command);
            if explicit_dash {
                cmd.arg("-");
            }
            let mut child = cmd
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .spawn()
                .unwrap();
            let result = child.stdin.take().unwrap().write_all(&bytes);
            if let Err(e) = result {
                assert_eq!(e.kind(), std::io::ErrorKind::BrokenPipe);
            }
            assert_failure(
                &child.wait_with_output().unwrap(),
                "input exceeds maximum size",
            );
        }
    }
}

#[test]
fn input_at_size_limit_is_not_rejected_by_reader() {
    // The existing decoder accepts a first item with trailing bytes. This test
    // only pins the inclusive reader boundary, not a new trailing-data policy.
    let file = InputFile::new(&[0xf6]);
    File::options()
        .write(true)
        .open(&file.0)
        .unwrap()
        .set_len(u64::try_from(DecodeLimits::default().max_input_bytes).unwrap())
        .unwrap();
    let output = run(&["validate", file.path(), "--edn"]);
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(output.stdout, b"null\n");
}

#[test]
fn oversized_baseline_is_rejected_before_json_parsing() {
    let bytes = SignedCorimBuilder::new(-7, vec![0xf6])
        .set_cwt_claims(CwtClaims::new("test"))
        .build_detached_with_signature(vec![0xab])
        .unwrap();
    let target = InputFile::new(&bytes);
    let baseline = InputFile::oversized();
    let mut file = File::options().write(true).open(&baseline.0).unwrap();
    file.write_all(b"{").unwrap();
    let output = run(&["validate", target.path(), "--baseline", baseline.path()]);
    assert_failure(&output, "reading baseline");
    assert_failure(&output, "input exceeds maximum size");
}

#[test]
fn oversized_signing_auxiliary_inputs_keep_context() {
    let small = InputFile::new(&[0xf6]);
    let large = InputFile::oversized();
    for (option, context) in [
        ("--external-aad", "reading external-aad"),
        ("--x5chain", "reading cert"),
    ] {
        let output = run(&[
            "sign",
            "prepare",
            small.path(),
            "--alg",
            "ES256",
            "--signer-name",
            "test",
            "--out-staging",
            "/dev/null",
            "--out-tbs",
            "/dev/null",
            option,
            large.path(),
        ]);
        assert_failure(&output, context);
        assert_failure(&output, "input exceeds maximum size");
    }
    let output = run(&[
        "sign",
        "finalize",
        small.path(),
        "--signature",
        large.path(),
        "-o",
        "/dev/null",
    ]);
    assert_failure(&output, "input exceeds maximum size");
}

#[test]
fn edn_normal_embedded_rendering_is_unchanged() {
    let output = edn(&encoded(embedded(
        TAG_COMID,
        encoded(Value::Map(vec![(
            Value::Integer(0),
            Value::Text("test".into()),
        )])),
    )));
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        String::from_utf8(output.stdout).unwrap(),
        "#6.506(<<{\n  0: \"test\"\n}>>)\n"
    );

    let output = edn(&encoded(cose(
        encoded(Value::Map(vec![(
            Value::Integer(8),
            Value::Bytes(encoded(Value::Map(vec![]))),
        )])),
        encoded(embedded(TAG_COTL, encoded(Value::Null))),
    )));
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        String::from_utf8(output.stdout).unwrap(),
        "#6.18([\n  <<{\n    8: <<{}>>\n  }>>,\n  {},\n  <<#6.508(<<null>>)>>,\n  h''\n])\n"
    );
}

#[test]
fn edn_syntax_failure_still_falls_back_to_hex() {
    let output = edn(&encoded(embedded(TAG_COSWID, vec![0xff])));
    assert!(output.status.success());
    assert_eq!(output.stdout, b"#6.505(h'ff')\n");
}

#[test]
fn edn_embedded_tag_depth_is_independent_of_indentation() {
    let mut bytes = encoded(Value::Null);
    for tag in [TAG_COSWID, TAG_COMID, TAG_COTL]
        .into_iter()
        .cycle()
        .take(33)
    {
        bytes = encoded(embedded(tag, bytes));
    }
    assert_failure(&edn(&bytes), "depth");
}

#[test]
fn edn_embedded_tag_depth_boundary_succeeds() {
    let mut bytes = encoded(Value::Null);
    for _ in 0..32 {
        bytes = encoded(embedded(TAG_COMID, bytes));
    }
    let output = edn(&bytes);
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn edn_nested_cose_payloads_and_protected_headers_are_bounded() {
    for protected in [false, true] {
        let mut bytes = encoded(Value::Null);
        for _ in 0..22 {
            bytes = if protected {
                encoded(cose(bytes, encoded(Value::Null)))
            } else {
                encoded(cose(encoded(Value::Map(vec![])), bytes))
            };
        }
        assert_failure(&edn(&bytes), "depth");
    }
}

#[test]
fn edn_mixed_container_and_bstr_depth_is_bounded() {
    let mut bytes = encoded(Value::Null);
    for _ in 0..17 {
        bytes = encoded(Value::Map(vec![(
            Value::Integer(0),
            Value::Array(vec![embedded(TAG_COMID, bytes)]),
        )]));
    }
    assert_failure(&edn(&bytes), "depth");
}

#[test]
fn edn_embedded_resource_failure_never_falls_back_to_hex() {
    let too_many = array_bytes(DecodeLimits::default().max_values);
    assert_failure(&edn(&encoded(embedded(TAG_COMID, too_many))), "values");
}

#[test]
fn edn_arbitrary_nested_embedded_values_share_one_budget() {
    let half = array_bytes(DecodeLimits::default().max_values / 2);
    // Neither embedded array alone exceeds a default parser budget. Place the
    // second behind another arbitrary tag so schema-only preflight is not enough.
    let root = Value::Array(vec![
        embedded(TAG_COSWID, half.clone()),
        embedded(TAG_COMID, encoded(embedded(TAG_COTL, half))),
    ]);
    assert_failure(&edn(&encoded(root)), "values");
}

#[test]
fn edn_cose_header_meta_and_payload_share_one_budget() {
    let half = array_bytes(DecodeLimits::default().max_values / 2);
    let header = encoded(Value::Map(vec![(
        Value::Integer(8),
        Value::Bytes(half.clone()),
    )]));
    assert_failure(&edn(&encoded(cose(header, half))), "values");
}

#[test]
fn edn_malformed_attempts_cannot_reset_the_budget() {
    // The outer array, two tags, and two bstrs cost five values. The inner
    // array costs one more, so its claimed count exactly fits the remaining
    // budget at collection precheck. All but its final item are valid nodes;
    // the final break consumes the last value before failing syntactically.
    let mut malformed = array_bytes(DecodeLimits::default().max_values - 6);
    *malformed.last_mut().unwrap() = BYTE_BREAK;
    let root = Value::Array(vec![
        embedded(TAG_COMID, malformed),
        embedded(TAG_COTL, encoded(Value::Null)),
    ]);
    assert_failure(&edn(&encoded(root)), "values");
}

#[test]
fn edn_early_syntax_failure_does_not_charge_unparsed_bytes() {
    // Only the initial break is visited. The remaining bytes must not be
    // fabricated into value consumption that prevents decoding the next bstr.
    let mut malformed = vec![0; DecodeLimits::default().max_values];
    malformed[0] = BYTE_BREAK;
    let expected = format!(
        "[\n  #6.{TAG_COMID}(h'{}'),\n  #6.{TAG_COTL}(<<null>>)\n]\n",
        hex::encode(&malformed)
    );
    let root = Value::Array(vec![
        embedded(TAG_COMID, malformed),
        embedded(TAG_COTL, encoded(Value::Null)),
    ]);
    let output = edn(&encoded(root));
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(String::from_utf8(output.stdout).unwrap(), expected);
}

#[test]
fn hash_envelope_digest_is_opaque_in_all_cli_modes() {
    // A valid-length digest beginning 9affffffff would claim u32::MAX array
    // entries if incorrectly interpreted as embedded CBOR (RFC 8949 §3.1).
    let mut digest = vec![(c::MAJOR_ARRAY << 5) | c::AI_FOUR_BYTES];
    digest.extend_from_slice(&u32::MAX.to_be_bytes());
    digest.resize(SHA_256_BYTES, 0);

    for hash_envelope in [true, false] {
        let header = ProtectedCorimHeaderMapBuilder::new(CoseAlgorithm::Es256)
            .cwt_claims(CwtClaims::new("test"));
        let header = if hash_envelope {
            header
                .payload_hash_alg(COSE_SHA_256)
                .payload_preimage_content_type(CORIM_CONTENT_TYPE)
        } else {
            header.content_type(CORIM_CONTENT_TYPE)
        }
        .build();
        corim::Validate::valid(&header).unwrap();
        let bytes = encoded(Value::Tag(
            TAG_SIGNED_CORIM,
            Box::new(Value::Array(vec![
                Value::Bytes(cbor::encode(&header).unwrap()),
                Value::Map(vec![]),
                Value::Bytes(digest.clone()),
                Value::Bytes(vec![0xab]),
            ])),
        ));
        let file = InputFile::new(&bytes);
        for mode in [None, Some("--edn"), Some("--diagnose")] {
            let mut args = vec!["validate", file.path()];
            if let Some(flag) = mode {
                args.push(flag);
            }
            let output = run(&args);
            let stdout = String::from_utf8_lossy(&output.stdout);
            let stderr = String::from_utf8_lossy(&output.stderr);
            if hash_envelope {
                assert!(
                    output.status.success(),
                    "{mode:?}: stdout={stdout}, stderr={stderr}"
                );
                match mode {
                    Some("--edn") => {
                        assert!(stdout.contains(&format!("h'{}'", hex::encode(&digest))));
                    }
                    Some("--diagnose") => {
                        assert!(stdout.contains("hash-envelope digest (opaque bytes"));
                    }
                    _ => assert!(stdout.contains("header decoded")),
                }
            } else if mode == Some("--diagnose") {
                // Diagnose reports resource errors on stdout, not stderr.
                assert_eq!(output.status.code(), Some(2));
                assert!(stdout.contains("collection entries"), "{stdout}");
            } else {
                assert_failure(&output, "collection entries");
            }
        }
    }
}

#[test]
fn unsigned_preflight_runs_before_schema_failure_and_compatibility_peeling() {
    let half = array_bytes(DecodeLimits::default().max_values / 2);
    // Deliberately omit corim-id: a typed decode must not hide the embedded
    // budget failure behind a missing-field error.
    let root = Value::Tag(
        TAG_CORIM,
        Box::new(Value::Map(vec![(
            Value::Integer(1),
            Value::Array(vec![
                embedded(TAG_COSWID, half.clone()),
                embedded(TAG_COTL, half),
            ]),
        )])),
    );
    for legacy in [false, true] {
        let value = if legacy {
            Value::Tag(corim::types::tags::TAG_LEGACY_TOP, Box::new(root.clone()))
        } else {
            root.clone()
        };
        let file = InputFile::new(&encoded(value));
        for command in ["validate", "convert"] {
            assert_failure(&run(&[command, file.path()]), "values");
        }
    }
}
