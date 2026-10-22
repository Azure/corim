// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Readable-authoring regressions, including byte baselines from a742bf9.

use super::*;
use corim::cbor::value::Value as Cbor;
use serde_json::{json, Value};

const TEMPLATES: [&str; 6] = [
    include_str!("../../templates/azure_ndpa.json"),
    include_str!("../../templates/azure_sfua.json"),
    include_str!("../../templates/azure_socmana.json"),
    include_str!("../../templates/azure_manticore_auth_keyattest.json"),
    include_str!("../../templates/azure_manticore_trust_keyattest.json"),
    include_str!("../../templates/cca_realm_vr72.json"),
];

// Generated with the unmodified a742bf9 CLI from its six shipped
// templates. These fixtures lock the original authoring wire bytes.
const ORIGINAL_BYTES: [&[u8]; 6] = [
    include_bytes!("../../tests/fixtures/authoring/azure_ndpa.cbor"),
    include_bytes!("../../tests/fixtures/authoring/azure_sfua.cbor"),
    include_bytes!("../../tests/fixtures/authoring/azure_socmana.cbor"),
    include_bytes!("../../tests/fixtures/authoring/azure_manticore_auth_keyattest.cbor"),
    include_bytes!("../../tests/fixtures/authoring/azure_manticore_trust_keyattest.cbor"),
    include_bytes!("../../tests/fixtures/authoring/cca_realm_vr72.cbor"),
];

fn template() -> Value {
    serde_json::from_str(TEMPLATES[0]).unwrap()
}

#[test]
fn six_readable_templates_roundtrip_with_comments_and_aliases() {
    for (source, original) in TEMPLATES.into_iter().zip(ORIGINAL_BYTES) {
        let template: Value = serde_json::from_str(source).unwrap();
        let bytes = encode_template(template, None).unwrap();
        assert_eq!(bytes, original);
        let projection = to_template(&bytes).unwrap();
        assert!(projection["comids"][0]["triples"].is_object());
        let text = to_json_pretty(&projection).unwrap();
        assert!(text.ends_with('\n'));
        assert!(!text.contains("\"$comment\""));
        assert_eq!(
            encode_template(serde_json::from_str(&text).unwrap(), None).unwrap(),
            bytes
        );
    }
}

#[test]
fn comments_are_only_authoring_annotations() {
    let original = template();
    let mut annotated = original.clone();
    annotated["//"] = json!({"anything": [null, true]});
    annotated["comids"][0]["triples"]["$comment"] = json!("nested annotation");
    assert_eq!(
        encode_template(original, None).unwrap(),
        encode_template(annotated, None).unwrap()
    );
}

#[test]
fn invalid_validity_is_rejected_before_optional_coercion() {
    for invalid in [
        Value::Null,
        json!(true),
        json!("bad"),
        json!(1.5),
        json!({"__cbor_tag": 1, "__cbor_value": null}),
    ] {
        let mut input = template();
        input["rim-validity"] = json!({"not-before": invalid, "not-after": 1900000000});
        assert!(encode_template(input, None)
            .unwrap_err()
            .contains("not-before"));
        let mut input = template();
        input["cotls"] = json!([{
            "tag-identity": {"id": "tl"},
            "tags-list": [{"id": "included"}],
            "tl-validity": {"not-before": invalid, "not-after": 1900000000}
        }]);
        assert!(encode_template(input, None)
            .unwrap_err()
            .contains("validity"));
    }
}

#[test]
fn pure_encoder_does_not_reject_expired_document() {
    let mut input = template();
    input["rim-validity"] = json!({"not-before": 0, "not-after": 1});
    assert!(encode_template(input, None).is_ok());
}

#[test]
fn prose_and_profile_alias_collisions_fail() {
    let mut input = template();
    input["comids"][0]["1"] = input["comids"][0]["tag-identity"].clone();
    assert!(encode_template(input, None)
        .unwrap_err()
        .contains("conflicting"));
    let mut value = json!({"tcbstatus": "UpToDate", "-700": "Revoked"});
    let registry = crate::profiles::build_registry();
    let profile = registry
        .get(&corim::types::corim::ProfileChoice::Uri(
            "tag:microsoft.com,2026:azure-profile#1.0.0".into(),
        ))
        .unwrap();
    assert!(encode::resolve_mval_aliases(&mut value, profile).is_err());
}

#[test]
fn pretty_writer_reserves_final_newline_and_preserves_native_object() {
    let value = json!({"corim-id": "native"});
    let text = to_json_pretty(&value).unwrap();
    assert_eq!(serde_json::from_str::<Value>(&text).unwrap(), value);
    assert!(pretty_with_limit(&value, text.len()).is_ok());
    assert!(pretty_with_limit(&value, text.len() - 1).is_err());
    assert!(pretty_with_limit(&Value::Null, 0).is_err());
}

#[test]
fn semantic_scalars_keep_large_integers_and_nonfinite_bits() {
    for value in [
        Cbor::Integer(i128::MAX),
        Cbor::Integer(i128::from(u64::MAX)),
        Cbor::Float(f64::INFINITY),
        Cbor::Float(f64::NEG_INFINITY),
        Cbor::Float(f64::from_bits(0x7ff8000000000042)),
    ] {
        let json = value_conv::value_to_json(&value).unwrap();
        let rebuilt = value_conv::json_to_value(&json).unwrap();
        match (value, rebuilt) {
            (Cbor::Float(a), Cbor::Float(b)) => assert_eq!(a.to_bits(), b.to_bits()),
            (a, b) => assert_eq!(a, b),
        }
    }
}

#[test]
fn semantic_key_collisions_do_not_overwrite_data() {
    let value = Cbor::Map(vec![
        (Cbor::Integer(31), Cbor::Bool(true)),
        (Cbor::Text("entity-name".into()), Cbor::Bool(false)),
    ]);
    assert!(value_conv::value_to_json(&value).is_err());
    assert!(value_conv::json_to_value(&json!({"01": 1, "1": 2})).is_err());
}

#[test]
fn readable_projection_refuses_unmodeled_source_data() {
    let bytes = encode_template(template(), None).unwrap();
    let mut value: Cbor = corim::cbor::decode_exact(&bytes).unwrap();
    let Cbor::Tag(_, inner) = &mut value else {
        panic!("tagged CoRIM")
    };
    let Cbor::Map(map) = inner.as_mut() else {
        panic!("CoRIM map")
    };
    map.push((
        Cbor::Integer(10001),
        Cbor::Text("unmodeled root field".into()),
    ));
    let error = to_template(&corim::cbor::encode(&value).unwrap()).unwrap_err();
    assert!(error.contains("--lossless"));
    assert!(error.contains("would change"));

    let input = json!({
        "corim-id": "opaque-bytes",
        "comids": [{
            "tag-identity": {"id": "comid"},
            "triples": {"reference-triples": [{
                "ref-env": {"class": {"vendor": "Example"}},
                "ref-claims": [{"value": {
                    "10001": {"type": "byte-string", "value": "0102"}
                }}]
            }]}
        }]
    });
    let bytes = encode_template(input, None).unwrap();
    assert!(to_template(&bytes).unwrap_err().contains("--lossless"));
}

#[test]
fn signed_projection_extracts_only_attached_unsigned_payload() {
    use corim::types::signed::{
        encode_signed_corim, CoseSign1Corim, CwtClaims, ProtectedCorimHeaderMapBuilder,
        SignedCorimBuilder,
    };
    let payload = encode_template(template(), None).unwrap();
    let signed = SignedCorimBuilder::new(-7, payload.clone())
        .set_cwt_claims(CwtClaims::new("fixture issuer"))
        .build_with_signature(vec![0; 64])
        .unwrap();
    let projection = to_template(&signed).unwrap();
    assert_eq!(projection["protected-header"]["issuer"], "fixture issuer");
    assert_eq!(encode_template(projection, None).unwrap(), payload);
    let detached = SignedCorimBuilder::new(-7, payload)
        .set_cwt_claims(CwtClaims::new("fixture issuer"))
        .build_detached_with_signature(vec![0; 64])
        .unwrap();
    let error = to_template(&detached).unwrap_err();
    assert!(error.contains("detached") && error.contains("--lossless"));

    let header = ProtectedCorimHeaderMapBuilder::new(corim::types::CoseAlgorithm::Es256)
        .cwt_claims(CwtClaims::new("fixture issuer"))
        .payload_hash_alg(-16)
        .payload_preimage_content_type("application/rim+cbor")
        .build();
    let envelope = CoseSign1Corim::from_parts(
        corim::cbor::encode(&header).unwrap(),
        vec![],
        Some(vec![0; 32]),
        vec![0; 64],
    )
    .unwrap();
    let error = to_template(&encode_signed_corim(&envelope).unwrap()).unwrap_err();
    assert!(error.contains("hash-envelope") && error.contains("--lossless"));
}

#[test]
fn malformed_tag_array_never_silently_generates_a_partial_document() {
    for field in ["comids", "coswids", "cotls", "entities", "dependent-rims"] {
        let mut input = template();
        input[field] = json!("not an array");
        assert!(encode_template(input, None).unwrap_err().contains(field));
    }
}

#[test]
fn native_pretty_json_expansion_obeys_default_budget() {
    let input = json!({"expanded": "\0".repeat(corim::json::DEFAULT_MAX_JSON_BYTES / 6)});
    assert!(to_json_pretty(&input).unwrap_err().contains("limit"));
}

#[test]
fn profile_override_drives_aliases_without_document_validation() {
    let original = template();
    let expected = encode_template(original.clone(), None).unwrap();
    let mut input = original;
    input["profile"] = json!("urn:unregistered:profile");
    assert_eq!(
        encode_template(
            input,
            Some("tag:microsoft.com,2026:azure-profile#1.0.0")
        ).unwrap(),
        expected
    );
}

#[test]
fn scalar_choices_and_text_digest_algorithm_remain_authorable() {
    let input = json!({
        "corim-id": {"type": "uuid", "value": "00112233-4455-6677-8899-aabbccddeeff"},
        "profile": {"type": "oid", "value": "KgM="},
        "dependent-rims": [{
            "href": "https://example.test/reference",
            "thumbprint": ["sha-256", "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="]
        }],
        "comids": [{
            "tag-identity": {"id": "typed"},
            "triples": {"reference-triples": [{
                "ref-env": {
                    "class": {"vendor": "Example"},
                    "instance": {"type": "ueid", "value": "AQID"}
                },
                "ref-claims": [{"value": {"svn": {"type": "svn", "value": 7}}}]
            }]}
        }]
    });
    let bytes = encode_template(input, None).unwrap();
    let projection = to_template(&bytes).unwrap();
    assert_eq!(projection["corim-id"]["type"], "uuid");
    assert_eq!(projection["profile"]["type"], "oid");
    assert_eq!(encode_template(projection, None).unwrap(), bytes);
}
