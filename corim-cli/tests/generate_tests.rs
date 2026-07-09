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

/// An identity triple whose key list contains a `cert-thumbprint` crypto
/// key can be authored: the thumbprint is a digest `[alg, bstr]` nested
/// inside the tag-559 type-choice, and its base64 `bstr` is coerced to
/// bytes so the CoMID deserializes. Regression for the ovl3 SFUA example.
#[test]
fn generate_identity_triple_cert_thumbprint() {
    let dir = std::env::temp_dir();
    let t = dir.join("corim_cli_thumbprint.json");
    let o = dir.join("corim_cli_thumbprint.cbor");

    // 3q2+7w== base64 == deadbeef; alg 2 == SHA-256.
    std::fs::write(
        &t,
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
    )
    .unwrap();

    let status = Command::new(bin())
        .args(["generate", t.to_str().unwrap(), "-o", o.to_str().unwrap()])
        .status()
        .expect("run corim-cli generate");
    assert!(status.success(), "cert-thumbprint generate exited non-zero");

    let bytes = std::fs::read(&o).unwrap();
    let (_c, comids) =
        corim::validate::decode_and_validate(&bytes).expect("thumbprint CoRIM must validate");
    let keys = comids[0].triples.identity_triples.as_ref().unwrap()[0].keys();
    match &keys[0] {
        corim::types::common::CryptoKey::CertThumbprint(d) => {
            assert_eq!(d.value(), &[0xde, 0xad, 0xbe, 0xef], "thumbprint bytes");
        }
        other => panic!("expected CertThumbprint, got {other:?}"),
    }

    let _ = std::fs::remove_file(&t);
    let _ = std::fs::remove_file(&o);
}

/// A template exercising the CoRIM-level fields (UUID corim-id, OID
/// profile, rim-validity, entities, dependent-rims), an
/// integrity-registers mval, and a CoTL tag builds and validates, with
/// bytes correctly coerced throughout.
#[test]
fn generate_corim_level_fields_and_cotl() {
    let dir = std::env::temp_dir();
    let t = dir.join("corim_cli_full.json");
    let o = dir.join("corim_cli_full.cbor");

    std::fs::write(
        &t,
        r#"{
          "corim-id": { "type": "uuid", "value": "550e8400-e29b-41d4-a716-446655440000" },
          "profile": { "type": "oid", "value": "BgYrBgEEAQ==" },
          "rim-validity": { "not-before": 1700000000, "not-after": 1900000000 },
          "entities": [
            { "entity-name": "ACME", "reg-id": "https://acme.example", "role": [1] }
          ],
          "dependent-rims": [
            { "href": "https://example.com/rim1", "thumbprint": [7, "3q2+7w=="] }
          ],
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
    )
    .unwrap();

    let status = Command::new(bin())
        .args(["generate", t.to_str().unwrap(), "-o", o.to_str().unwrap()])
        .status()
        .expect("run corim-cli generate");
    assert!(status.success(), "full-fields generate exited non-zero");

    let bytes = std::fs::read(&o).unwrap();
    let (corim, comids) =
        corim::validate::decode_and_validate(&bytes).expect("full CoRIM must validate");

    // UUID corim-id.
    assert!(
        matches!(corim.id, corim::types::corim::CorimId::Uuid(_)),
        "expected UUID corim-id"
    );
    // OID profile.
    assert!(
        matches!(
            corim.profile,
            Some(corim::types::corim::ProfileChoice::Oid(_))
        ),
        "expected OID profile"
    );
    // rim-validity present, entities present, dependent-rims present.
    assert!(corim.rim_validity.is_some(), "expected rim-validity");
    assert_eq!(corim.entities.as_ref().unwrap().len(), 1, "one entity");
    assert_eq!(
        corim.dependent_rims.as_ref().unwrap().len(),
        1,
        "one dependent-rim"
    );

    // integrity-registers digests coerced to bytes.
    let regs = comids[0].triples.reference_triples.as_ref().unwrap()[0].measurements()[0]
        .mval
        .integrity_registers
        .as_ref()
        .expect("expected integrity-registers");
    let any_deadbeef = regs
        .0
        .values()
        .flatten()
        .any(|d| d.value() == [0xde, 0xad, 0xbe, 0xef]);
    assert!(any_deadbeef, "integrity-register digest bytes coerced");

    let _ = std::fs::remove_file(&t);
    let _ = std::fs::remove_file(&o);
}

/// A CoSWID tag can be authored with prose keys, including an entity
/// thumbprint digest whose `bstr` is coerced.
#[test]
fn generate_coswid_tag() {
    let dir = std::env::temp_dir();
    let t = dir.join("corim_cli_coswid.json");
    let o = dir.join("corim_cli_coswid.cbor");

    // role 1 == tag-creator (required by ConciseSwidTag::valid).
    std::fs::write(
        &t,
        r#"{
          "corim-id": "id-1",
          "coswids": [
            { "tag-id": "swid-1",
              "software-name": "ACME OS",
              "tag-version": 0,
              "entity": [
                { "entity-name": "ACME", "role": [1],
                  "thumbprint": [2, "3q2+7w=="] }
              ] }
          ]
        }"#,
    )
    .unwrap();

    let status = Command::new(bin())
        .args(["generate", t.to_str().unwrap(), "-o", o.to_str().unwrap()])
        .status()
        .expect("run corim-cli generate");
    assert!(status.success(), "coswid generate exited non-zero");

    let bytes = std::fs::read(&o).unwrap();
    // A CoSWID-only CoRIM has no CoMID, so use a structural tag-501
    // decode rather than the CoMID-requiring strict validator.
    let tagged: corim::cbor::value::Tagged<corim::types::corim::CorimMap> =
        corim::cbor::decode(&bytes).expect("coswid CoRIM must decode");
    assert_eq!(tagged.value.tags.len(), 1, "expected one CoSWID tag");

    let _ = std::fs::remove_file(&t);
    let _ = std::fs::remove_file(&o);
}

/// A CES triple authored with **labeled** record fields
/// (`condition`/`series`/`selection`/`addition`) and the equivalent
/// legacy positional-array form produce byte-identical output.
#[test]
fn generate_labeled_and_positional_records_match() {
    let dir = std::env::temp_dir();
    let lt = dir.join("corim_cli_labeled.json");
    let pt = dir.join("corim_cli_positional.json");
    let lo = dir.join("corim_cli_labeled.cbor");
    let po = dir.join("corim_cli_positional.cbor");

    std::fs::write(
        &lt,
        r#"{
          "corim-id": "id-1",
          "comids": [
            { "tag-identity": { "id": "c1" },
              "triples": { "conditional-endorsement-series-triples": [
                { "condition": { "environment": { "class": { "vendor": "ACME" } },
                                 "claims-list": [] },
                  "series": [
                    { "selection": [ { "value": { "svn": { "type": "min-svn", "value": 1 } } } ],
                      "addition":  [ { "value": { "svn": { "type": "svn", "value": 1 } } } ] }
                  ] }
              ] } }
          ]
        }"#,
    )
    .unwrap();
    std::fs::write(
        &pt,
        r#"{
          "corim-id": "id-1",
          "comids": [
            { "tag-identity": { "id": "c1" },
              "triples": { "conditional-endorsement-series-triples": [
                [ [ { "class": { "vendor": "ACME" } }, [] ],
                  [ [ [ { "value": { "svn": { "type": "min-svn", "value": 1 } } } ],
                      [ { "value": { "svn": { "type": "svn", "value": 1 } } } ] ] ] ]
              ] } }
          ]
        }"#,
    )
    .unwrap();

    for (t, o) in [(&lt, &lo), (&pt, &po)] {
        let s = Command::new(bin())
            .args(["generate", t.to_str().unwrap(), "-o", o.to_str().unwrap()])
            .status()
            .expect("run generate");
        assert!(s.success(), "generate failed for {t:?}");
    }
    assert_eq!(
        std::fs::read(&lo).unwrap(),
        std::fs::read(&po).unwrap(),
        "labeled and positional records must produce identical CBOR"
    );

    for f in [&lt, &pt, &lo, &po] {
        let _ = std::fs::remove_file(f);
    }
}

/// `$comment` and `//` keys are stripped: a commented template and the
/// same template without comments produce byte-identical CBOR, and no
/// comment text leaks into the output.
#[test]
fn generate_strips_comments() {
    let dir = std::env::temp_dir();
    let ct = dir.join("corim_cli_commented.json");
    let ut = dir.join("corim_cli_uncommented.json");
    let co = dir.join("corim_cli_commented.cbor");
    let uo = dir.join("corim_cli_uncommented.cbor");

    std::fs::write(
        &ct,
        r#"{
          "$comment": "top-level note",
          "corim-id": "id-1",
          "comids": [
            { "//": "the CoMID",
              "tag-identity": { "id": "c1" },
              "triples": {
                "$comment": ["multi", "line"],
                "reference-triples": [
                  { "$comment": "ACME reference values",
                    "ref-env": { "class": { "vendor": "ACME" } },
                    "ref-claims": [ { "value": { "svn": { "type": "svn", "value": 3 } } } ] }
                ] } }
          ]
        }"#,
    )
    .unwrap();
    std::fs::write(
        &ut,
        r#"{
          "corim-id": "id-1",
          "comids": [
            { "tag-identity": { "id": "c1" },
              "triples": { "reference-triples": [
                { "ref-env": { "class": { "vendor": "ACME" } },
                  "ref-claims": [ { "value": { "svn": { "type": "svn", "value": 3 } } } ] }
              ] } }
          ]
        }"#,
    )
    .unwrap();

    for (t, o) in [(&ct, &co), (&ut, &uo)] {
        let s = Command::new(bin())
            .args(["generate", t.to_str().unwrap(), "-o", o.to_str().unwrap()])
            .status()
            .expect("run generate");
        assert!(s.success(), "generate failed for {t:?}");
    }

    let cbytes = std::fs::read(&co).unwrap();
    assert_eq!(
        cbytes,
        std::fs::read(&uo).unwrap(),
        "commented and uncommented templates must produce identical CBOR"
    );
    // No comment text survived into the CBOR.
    assert!(
        !cbytes.windows(4).any(|w| w == b"note") && !cbytes.windows(4).any(|w| w == b"line"),
        "comment text must not appear in the output"
    );

    for f in [&ct, &ut, &co, &uo] {
        let _ = std::fs::remove_file(f);
    }
}
