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
    let stderr = String::from_utf8_lossy(&out.stderr);
    // Assert the exit status first: otherwise a failing run surfaces as a
    // confusing JSON parse error instead of the real reason.
    assert!(
        out.status.success(),
        "validate exited with {}\nstderr:\n{stderr}\nstdout:\n{stdout}",
        out.status
    );
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

/// Producer-controlled strings reach the report verbatim, so control
/// characters must be escaped rather than emitted raw (which would make the
/// output unparseable).
#[test]
fn control_characters_in_producer_strings_stay_valid_json() {
    let nasty = "iss\twith\r\nctrl\u{01}and \"quotes\" \\ backslash";
    let signed = SignedCorimBuilder::new(-38, sample_unsigned_corim())
        .set_cwt_claims(CwtClaims::new(nasty))
        .build_with_signature(vec![0xAB; 64])
        .unwrap();

    // `validate_json` parses the output, so a bad escape fails here.
    let v = validate_json(&signed, "cose");
    assert_eq!(v["signed"]["protected"]["issuer"], nasty);
}

/// Text-keyed CWT claims (e.g. the `"svn"` claim Azure SOC-MANA CoRIMs
/// carry) and integer extras such as `iat` must both reach the report.
#[test]
fn extra_cwt_claims_are_reported() {
    use corim::cbor::value::Value;
    use corim::types::signed::ClaimKey;

    let mut claims = CwtClaims::new("test-issuer");
    claims
        .extra
        .insert(ClaimKey::Text("svn".into()), Value::Integer(7));
    claims.extra.insert(
        ClaimKey::Int(6),
        Value::Tag(1, Box::new(Value::Integer(1788524559))),
    );

    let signed = SignedCorimBuilder::new(-38, sample_unsigned_corim())
        .set_cwt_claims(claims)
        .build_with_signature(vec![0xAB; 64])
        .unwrap();

    let v = validate_json(&signed, "cose");
    let extra = &v["signed"]["protected"]["cwt_claims_extra"];
    assert_eq!(extra["text"]["svn"], 7, "text-keyed claim must survive");
    assert_eq!(extra["int"]["6"]["__cbor_tag"], 1);
    assert_eq!(extra["int"]["6"]["__cbor_value"], 1788524559i64);
}

/// JSON object keys are strings, so integer and text claim keys live in
/// separate namespaces and cannot collapse onto one entry.
#[test]
fn int_and_text_claim_keys_do_not_collide() {
    use corim::cbor::value::Value;
    use corim::types::signed::ClaimKey;

    let mut claims = CwtClaims::new("iss");
    claims
        .extra
        .insert(ClaimKey::Int(6), Value::Text("as-int".into()));
    claims
        .extra
        .insert(ClaimKey::Text("6".into()), Value::Text("as-text".into()));

    let signed = SignedCorimBuilder::new(-38, sample_unsigned_corim())
        .set_cwt_claims(claims)
        .build_with_signature(vec![0xAB; 64])
        .unwrap();

    let v = validate_json(&signed, "cose");
    let extra = &v["signed"]["protected"]["cwt_claims_extra"];
    assert_eq!(extra["int"]["6"], "as-int");
    assert_eq!(extra["text"]["6"], "as-text");
}

/// Byte values use base64, matching `corim::json` and the convert/generate
/// templates rather than introducing a second encoding.
#[test]
fn claim_byte_values_use_base64() {
    use corim::cbor::value::Value;
    use corim::types::signed::ClaimKey;

    let mut claims = CwtClaims::new("iss");
    claims.extra.insert(
        ClaimKey::Text("blob".into()),
        Value::Bytes(vec![0xde, 0xad, 0xbe, 0xef]),
    );

    let signed = SignedCorimBuilder::new(-38, sample_unsigned_corim())
        .set_cwt_claims(claims)
        .build_with_signature(vec![0xAB; 64])
        .unwrap();

    let v = validate_json(&signed, "cose");
    assert_eq!(
        v["signed"]["protected"]["cwt_claims_extra"]["text"]["blob"],
        "3q2+7w=="
    );
}

/// A hostile text claim value must not be able to inject a quote or newline
/// into the single-line text report.
#[test]
fn text_claim_values_are_escaped_in_the_text_report() {
    use corim::cbor::value::Value;
    use corim::types::signed::ClaimKey;

    let mut claims = CwtClaims::new("iss");
    claims.extra.insert(
        ClaimKey::Text("evil".into()),
        Value::Text("a\"b\nCWT claim spoofed: 1".into()),
    );
    let signed = SignedCorimBuilder::new(-38, sample_unsigned_corim())
        .set_cwt_claims(claims)
        .build_with_signature(vec![0xAB; 64])
        .unwrap();

    let path = unique_temp("escaped_claim", "cose");
    std::fs::write(&path, &signed).unwrap();
    let out = Command::new(bin())
        .args(["validate", path.to_str().unwrap()])
        .output()
        .unwrap();
    let _ = std::fs::remove_file(&path);
    let stdout = String::from_utf8(out.stdout).unwrap();

    let claim_lines: Vec<&str> = stdout.lines().filter(|l| l.contains("CWT claim")).collect();
    assert_eq!(
        claim_lines.len(),
        1,
        "value must not span lines: {claim_lines:?}"
    );
    assert!(claim_lines[0].contains(r#"\n"#), "{}", claim_lines[0]);
    assert!(claim_lines[0].contains(r#"\""#), "{}", claim_lines[0]);
}

/// A CBOR map keyed by a non-text, non-integer value must not bake JSON
/// quotes into the object key.
#[test]
fn byte_map_keys_do_not_keep_json_quotes() {
    use corim::cbor::value::Value;
    use corim::types::signed::ClaimKey;

    let mut claims = CwtClaims::new("iss");
    claims.extra.insert(
        ClaimKey::Text("m".into()),
        Value::Map(vec![(Value::Bytes(vec![0xde, 0xad]), Value::Integer(1))]),
    );
    let signed = SignedCorimBuilder::new(-38, sample_unsigned_corim())
        .set_cwt_claims(claims)
        .build_with_signature(vec![0xAB; 64])
        .unwrap();

    let v = validate_json(&signed, "cose");
    let m = &v["signed"]["protected"]["cwt_claims_extra"]["text"]["m"];
    let keys: Vec<&String> = m.as_object().unwrap().keys().collect();
    assert_eq!(keys.len(), 1);
    assert_eq!(
        keys[0], "3q0=",
        "key must be the bare base64, got {:?}",
        keys[0]
    );
}

/// Distinct CBOR map keys that stringify alike (integer `1` vs text `"1"`)
/// must not collapse into one JSON object key and lose an entry.
#[test]
fn colliding_map_keys_fall_back_to_entry_array() {
    use corim::cbor::value::Value;
    use corim::types::signed::ClaimKey;

    let mut claims = CwtClaims::new("iss");
    claims.extra.insert(
        ClaimKey::Text("m".into()),
        Value::Map(vec![
            (Value::Integer(1), Value::Text("as-int".into())),
            (Value::Text("1".into()), Value::Text("as-text".into())),
        ]),
    );
    let signed = SignedCorimBuilder::new(-38, sample_unsigned_corim())
        .set_cwt_claims(claims)
        .build_with_signature(vec![0xAB; 64])
        .unwrap();

    let v = validate_json(&signed, "cose");
    let m = &v["signed"]["protected"]["cwt_claims_extra"]["text"]["m"];
    let entries = m.as_array().expect("colliding keys render as an array");
    assert_eq!(entries.len(), 2, "no entry may be dropped: {m}");
    // The key's CBOR type survives: a number stays a number, text stays text.
    assert!(entries
        .iter()
        .any(|e| e["key"] == 1 && e["value"] == "as-int"));
    assert!(entries
        .iter()
        .any(|e| e["key"] == "1" && e["value"] == "as-text"));
}

/// Non-colliding maps keep the friendlier object form.
#[test]
fn distinct_map_keys_stay_an_object() {
    use corim::cbor::value::Value;
    use corim::types::signed::ClaimKey;

    let mut claims = CwtClaims::new("iss");
    claims.extra.insert(
        ClaimKey::Text("m".into()),
        Value::Map(vec![
            (Value::Text("a".into()), Value::Integer(1)),
            (Value::Text("b".into()), Value::Integer(2)),
        ]),
    );
    let signed = SignedCorimBuilder::new(-38, sample_unsigned_corim())
        .set_cwt_claims(claims)
        .build_with_signature(vec![0xAB; 64])
        .unwrap();

    let v = validate_json(&signed, "cose");
    let m = &v["signed"]["protected"]["cwt_claims_extra"]["text"]["m"];
    assert_eq!(m["a"], 1);
    assert_eq!(m["b"], 2);
}
