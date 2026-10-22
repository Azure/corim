// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Inspection must preserve the entire raw CBOR tree, not a typed subset.
use corim::cbor::{self, value::Value};
use corim::types::tags::*;
use std::{path::PathBuf, process::Command};

fn bin() -> &'static str {
    env!("CARGO_BIN_EXE_corim-cli")
}

struct Files(Vec<PathBuf>);
impl Files {
    fn new() -> Self {
        Self(Vec::new())
    }
    fn path(&mut self, ext: &str) -> PathBuf {
        use std::sync::atomic::{AtomicU64, Ordering};
        static N: AtomicU64 = AtomicU64::new(0);
        let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("target-json-tests");
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join(format!(
            "convert_{}_{}.{}",
            std::process::id(),
            N.fetch_add(1, Ordering::Relaxed),
            ext
        ));
        self.0.push(path.clone());
        path
    }
}
impl Drop for Files {
    fn drop(&mut self) {
        for p in &self.0 {
            let _ = std::fs::remove_file(p);
        }
    }
}

fn convert(bytes: &[u8]) -> String {
    let mut files = Files::new();
    let input = files.path("cbor");
    let output = files.path("json");
    std::fs::write(&input, bytes).unwrap();
    let result = Command::new(bin())
        .arg("convert")
        .arg(&input)
        .arg("-o")
        .arg(&output)
        .output()
        .unwrap();
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    std::fs::read_to_string(output).unwrap()
}

fn assert_value_round_trip(value: &Value) {
    let bytes = cbor::encode(value).unwrap();
    let raw: Value = cbor::decode_exact(&bytes).unwrap();
    let text = convert(&bytes);
    let decoded: Value = corim::json::from_json(&text).unwrap();
    // Compare encoded nodes, rather than PartialEq, to check NaN payload bits.
    assert_eq!(
        corim::json::value_to_json(&decoded).unwrap(),
        corim::json::value_to_json(&raw).unwrap()
    );
    assert_eq!(cbor::encode(&decoded).unwrap(), bytes);
}

#[test]
fn convert_round_trip_minimal_and_all_shipped_templates() {
    for name in [
        "azure_ndpa",
        "azure_sfua",
        "azure_socmana",
        "azure_manticore_auth_keyattest",
        "azure_manticore_trust_keyattest",
        "cca_realm_vr72",
    ] {
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("templates")
            .join(format!("{name}.json"));
        let value: Value = corim::json::from_json(&std::fs::read_to_string(path).unwrap()).unwrap();
        assert_value_round_trip(&value);
    }
}

#[test]
fn convert_preserves_distinct_integer_text_and_complex_keys_without_aliases() {
    assert_value_round_trip(&Value::Map(vec![
        (Value::Integer(-700), Value::Text("UpToDate".into())),
        (Value::Integer(100), Value::Text("PSA certificate".into())),
        (Value::Integer(1), Value::Bool(false)),
        (Value::Text("1".into()), Value::Bytes(vec![0, 255])),
        (Value::Integer(2), Value::Bool(true)),
        (Value::Array(vec![Value::Null]), Value::Map(vec![])),
        (Value::Map(vec![]), Value::Text("map key".into())),
    ]));
}

#[test]
fn convert_rejects_duplicate_schema_keys_while_generic_json_preserves_them() {
    let root = Value::Tag(
        TAG_CORIM,
        Box::new(Value::Map(vec![
            (
                Value::Integer(i128::from(CORIM_KEY_ID)),
                Value::Text("first".into()),
            ),
            (
                Value::Integer(i128::from(CORIM_KEY_ID)),
                Value::Text("second".into()),
            ),
            (
                Value::Integer(i128::from(CORIM_KEY_TAGS)),
                Value::Array(vec![]),
            ),
        ])),
    );
    let json = corim::json::value_to_json(&root).unwrap();
    assert_eq!(corim::json::json_to_value(&json).unwrap(), root);

    let mut files = Files::new();
    let input = files.path("cbor");
    let output = files.path("json");
    std::fs::write(&input, cbor::encode(&root).unwrap()).unwrap();
    let result = Command::new(bin())
        .arg("convert")
        .arg(&input)
        .arg("-o")
        .arg(&output)
        .output()
        .unwrap();
    assert!(!result.status.success());
    assert!(String::from_utf8_lossy(&result.stderr).contains("duplicate map key: 0"));
    assert!(!output.exists());
}

#[test]
fn convert_rejects_oversized_json_expansion_without_partial_output() {
    let mut files = Files::new();
    let input = files.path("cbor");
    let output = files.path("json");
    let root = Value::Bytes(vec![0; corim::json::DEFAULT_MAX_JSON_BYTES / 2]);
    std::fs::write(&input, cbor::encode(&root).unwrap()).unwrap();
    std::fs::write(&output, b"existing output must survive").unwrap();
    let result = Command::new(bin())
        .arg("convert")
        .arg(&input)
        .arg("-o")
        .arg(&output)
        .output()
        .unwrap();
    assert!(!result.status.success());
    assert!(result.stdout.is_empty());
    assert!(String::from_utf8_lossy(&result.stderr).contains("JSON output"));
    assert_eq!(
        std::fs::read(&output).unwrap(),
        b"existing output must survive"
    );
    let result = Command::new(bin())
        .arg("convert")
        .arg(&input)
        .output()
        .unwrap();
    assert!(!result.status.success());
    assert!(
        result.stdout.is_empty(),
        "failed conversion must not leak a JSON prefix"
    );
}

#[test]
fn convert_round_trip_opaque_tagged_uri_and_unknown_extensions() {
    assert_value_round_trip(&Value::Tag(
        TAG_CORIM,
        Box::new(Value::Map(vec![
            (
                Value::Integer(-999),
                Value::Tag(TAG_URI, Box::new(Value::Text("https://example.com".into()))),
            ),
            (Value::Text("type".into()), Value::Text("integer".into())),
            (Value::Text("value".into()), Value::Text("42".into())),
            (
                Value::Integer(10001),
                Value::Tag(u64::MAX, Box::new(Value::Null)),
            ),
        ])),
    ));
}

#[test]
fn convert_round_trip_measurement_matchers_and_float_bits() {
    for value in [
        Value::Bool(false),
        Value::Text("abc".into()),
        Value::Bytes(vec![0, 255]),
        Value::Tag(
            TAG_MATCHER_SET,
            Box::new(Value::Array(vec![Value::Integer(1), Value::Float(1.5)])),
        ),
        Value::Tag(
            TAG_NUMBER_RANGE,
            Box::new(Value::Array(vec![Value::Null, Value::Float(f64::INFINITY)])),
        ),
        Value::Float(f64::from_bits(0x7ff8_0000_0000_1234)),
        Value::Float(-0.0),
        Value::Integer(-(1_i128 << 64)),
        Value::Integer(i128::from(u64::MAX)),
    ] {
        assert_value_round_trip(&value);
    }
}

#[test]
fn convert_preserves_full_signed_and_detached_envelopes_without_validation() {
    // Deliberately noncanonical protected CBOR, unknown fields, a placeholder
    // signature, and an opaque payload. Inspection must not validate or rewrite.
    let protected = vec![0xa1, 0x18, 0x01, 0x38, 0x06];
    for payload in [Value::Bytes(vec![0xd9, 0x01, 0xf5, 0xa0]), Value::Null] {
        let root = Value::Tag(
            TAG_SIGNED_CORIM,
            Box::new(Value::Array(vec![
                Value::Bytes(protected.clone()),
                Value::Map(vec![(Value::Integer(10001), Value::Bytes(vec![0xaa]))]),
                payload.clone(),
                Value::Bytes(vec![0x55; 64]),
            ])),
        );
        let text = convert(&cbor::encode(&root).unwrap());
        let decoded: Value = corim::json::from_json(&text).unwrap();
        assert_eq!(decoded, root);
        assert!(
            !text.contains("protected-header"),
            "no informational fields in document JSON"
        );
        let Value::Tag(_, inner) = decoded else {
            panic!()
        };
        let Value::Array(elements) = *inner else {
            panic!()
        };
        assert_eq!(elements[0], Value::Bytes(protected.clone()));
        assert_eq!(elements[2], payload);
    }
}

#[test]
fn convert_does_not_peel_legacy_wrappers_or_interpret_embedded_bytes() {
    let inner = Value::Tag(
        TAG_CORIM,
        Box::new(Value::Map(vec![(
            Value::Integer(CORIM_KEY_TAGS.into()),
            Value::Array(vec![Value::Bytes(vec![0xd9, 0x01, 0xfa, 0xa0])]),
        )])),
    );
    assert_value_round_trip(&Value::Tag(
        TAG_LEGACY_TOP,
        Box::new(Value::Tag(TAG_LEGACY_SIGNED, Box::new(inner))),
    ));
}

#[test]
fn convert_rejects_truncated_or_concatenated_cbor_before_creating_output() {
    let mut files = Files::new();
    for bytes in [vec![], vec![0xd2], vec![0xd2, 0x84, 0x40], vec![0xf6, 0xf6]] {
        let input = files.path("cbor");
        let output = files.path("json");
        std::fs::write(&input, bytes).unwrap();
        let result = Command::new(bin())
            .arg("convert")
            .arg(input)
            .arg("-o")
            .arg(&output)
            .output()
            .unwrap();
        assert!(!result.status.success());
        assert!(!output.exists());
    }
}

#[test]
fn convert_reads_stdin_and_emits_raw_scalar() {
    use std::io::Write;
    use std::process::Stdio;
    let mut child = Command::new(bin())
        .args(["convert", "-"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    child.stdin.take().unwrap().write_all(&[0x01]).unwrap();
    let output = child.wait_with_output().unwrap();
    assert!(output.status.success());
    let json: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(json, serde_json::json!({"type":"integer","value":"1"}));
}

#[test]
fn convert_sixty_four_nested_maps_exceeding_default_json_depth() {
    let mut root = Value::Null;
    for _ in 0..64 {
        root = Value::Map(vec![(Value::Null, root)]);
    }
    assert_value_round_trip(&root);
}

#[test]
fn matcher_cli_diagnoses_bad_shapes_and_displays_valid_fields() {
    let mut files = Files::new();
    let source = files.path("cbor");
    let key = |n: i64| Value::Integer(i128::from(n));
    for invalid in [false, true] {
        let mval = Value::Map(vec![
            (key(MVAL_KEY_BOOL), Value::Bool(false)),
            (
                key(MVAL_KEY_NUMBER),
                if invalid {
                    Value::Tag(
                        TAG_MATCHER_SET,
                        Box::new(Value::Array(vec![Value::Integer(1)])),
                    )
                } else {
                    Value::Integer(2)
                },
            ),
            (key(MVAL_KEY_TEXT), Value::Text("abc".into())),
            (key(MVAL_KEY_BYTES), Value::Bytes(vec![0, 255])),
        ]);
        let environment = Value::Map(vec![(
            key(ENV_KEY_CLASS),
            Value::Map(vec![(key(CLASS_KEY_VENDOR), Value::Text("ACME".into()))]),
        )]);
        let measurement = Value::Map(vec![(key(MEAS_KEY_MVAL), mval)]);
        let comid = Value::Map(vec![
            (
                key(COMID_KEY_TAG_IDENTITY),
                Value::Map(vec![(
                    key(TAG_IDENTITY_KEY_TAG_ID),
                    Value::Text("c1".into()),
                )]),
            ),
            (
                key(COMID_KEY_TRIPLES),
                Value::Map(vec![(
                    key(TRIPLES_KEY_REFERENCE),
                    Value::Array(vec![Value::Array(vec![
                        environment,
                        Value::Array(vec![measurement]),
                    ])]),
                )]),
            ),
        ]);
        let root = Value::Tag(
            TAG_CORIM,
            Box::new(Value::Map(vec![
                (key(CORIM_KEY_ID), Value::Text("matcher".into())),
                (
                    key(CORIM_KEY_TAGS),
                    Value::Array(vec![Value::Tag(
                        TAG_COMID,
                        Box::new(Value::Bytes(cbor::encode(&comid).unwrap())),
                    )]),
                ),
            ])),
        );
        std::fs::write(&source, cbor::encode(&root).unwrap()).unwrap();
        for mode in [None, Some("--diagnose")] {
            let mut command = Command::new(bin());
            command.arg("validate").arg(&source);
            if let Some(mode) = mode {
                command.arg(mode);
            }
            let output = command.output().unwrap();
            assert_eq!(
                output.status.success(),
                !invalid,
                "{}",
                String::from_utf8_lossy(&output.stdout)
            );
            if !invalid && mode.is_none() {
                let text = String::from_utf8(output.stdout).unwrap();
                for field in ["bool: false", "number:", "text:", "bytes:"] {
                    assert!(text.contains(field), "{text}");
                }
            }
        }
    }
}
