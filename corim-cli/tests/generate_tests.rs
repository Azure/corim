// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Lossless document generation and its mandatory validation gate.
use corim::builder::{ComidBuilder, CorimBuilder, CotlBuilder};
use corim::cbor::{self, value::Value};
use corim::types::common::{CryptoKey, EntityMap, MeasuredElement, TagIdChoice};
use corim::types::corim::{
    CorimId, CorimLocator, CorimLocatorHref, CorimLocatorThumbprint, ProfileChoice,
};
use corim::types::coswid::{ConciseSwidTag, SwidEntity};
use corim::types::environment::{ClassMap, EnvironmentMap};
use corim::types::measurement::{
    Digest, IntegrityRegisterId, IntegrityRegisters, MeasurementMap, MeasurementValuesMap,
    SvnChoice,
};
use corim::types::tags::*;
use corim::types::triples::ReferenceTriple;
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
            "generate_{}_{}.{}",
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

fn generate(
    files: &mut Files,
    text: &str,
    profile: Option<&str>,
) -> (std::process::Output, PathBuf) {
    let input = files.path("json");
    let output = files.path("cbor");
    std::fs::write(&input, text).unwrap();
    let mut command = Command::new(bin());
    command.arg("generate").arg(&input).arg("-o").arg(&output);
    if let Some(uri) = profile {
        command.args(["--profile", uri]);
    }
    (command.output().unwrap(), output)
}

fn assert_generated(bytes: &[u8]) -> Vec<u8> {
    let mut files = Files::new();
    let value: Value = cbor::decode_exact(bytes).unwrap();
    let (result, path) = generate(&mut files, &corim::json::to_json(&value).unwrap(), None);
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    let output = std::fs::read(path).unwrap();
    assert_eq!(output, bytes);
    output
}

fn reference_builder() -> CorimBuilder {
    let mut mval = MeasurementValuesMap::default();
    mval.digests = Some(vec![Digest::new(7, vec![0xde, 0xad, 0xbe, 0xef])]);
    mval.svn = Some(SvnChoice::ExactValue(3));
    mval.integrity_registers = Some(IntegrityRegisters(
        [
            (
                IntegrityRegisterId::Uint(0),
                vec![Digest::new(7, vec![0xde, 0xad, 0xbe, 0xef])],
            ),
            (
                IntegrityRegisterId::Text("cfg".into()),
                vec![Digest::new(2, vec![0xde, 0xad, 0xbe, 0xef])],
            ),
        ]
        .into_iter()
        .collect(),
    ));
    let measurement = MeasurementMap {
        mkey: None,
        mval,
        authorized_by: None,
    };
    let comid = ComidBuilder::new(TagIdChoice::Text("c1".into()))
        .add_reference_triple(ReferenceTriple::new(
            EnvironmentMap::for_class("ACME", "Widget"),
            vec![measurement],
        ))
        .build()
        .unwrap();
    CorimBuilder::new(CorimId::Text("id-1".into()))
        .add_comid_tag(comid)
        .unwrap()
}

#[test]
fn generate_digest_reference_and_exact_svn_survive_bytes() {
    let bytes = reference_builder().build_bytes().unwrap();
    let output = assert_generated(&bytes);
    let (_, comids) = corim::validate::decode_and_validate(&output).unwrap();
    let mval = &comids[0].triples.reference_triples.as_ref().unwrap()[0].measurements()[0].mval;
    assert_eq!(
        mval.digests.as_ref().unwrap()[0].value(),
        &[0xde, 0xad, 0xbe, 0xef]
    );
    assert_eq!(mval.svn, Some(SvnChoice::ExactValue(3)));
    let registers = &mval.integrity_registers.as_ref().unwrap().0;
    assert_eq!(registers.len(), 2);
    assert_eq!(
        registers[&IntegrityRegisterId::Uint(0)][0].value(),
        &[0xde, 0xad, 0xbe, 0xef]
    );
    assert_eq!(
        registers[&IntegrityRegisterId::Text("cfg".into())][0].value(),
        &[0xde, 0xad, 0xbe, 0xef]
    );
}

#[test]
fn generate_identity_triple_cert_thumbprint() {
    let comid = ComidBuilder::new(TagIdChoice::Text("identity".into()))
        .add_identity_triple_for(
            EnvironmentMap::for_class("ACME", "Widget"),
            vec![CryptoKey::CertThumbprint(Digest::new(
                2,
                vec![0xde, 0xad, 0xbe, 0xef],
            ))],
            None,
        )
        .build()
        .unwrap();
    let bytes = CorimBuilder::new(CorimId::Text("thumbprint".into()))
        .add_comid_tag(comid)
        .unwrap()
        .build_bytes()
        .unwrap();
    let (_, comids) = corim::validate::decode_and_validate(&assert_generated(&bytes)).unwrap();
    assert!(
        matches!(&comids[0].triples.identity_triples.as_ref().unwrap()[0].keys()[0],
        CryptoKey::CertThumbprint(d) if d.value() == [0xde, 0xad, 0xbe, 0xef])
    );
}

#[test]
fn generate_corim_level_uuid_validity_entities_locators_and_cotl() {
    let cotl = CotlBuilder::new(TagIdChoice::Text("tl1".into()), 1_900_000_000)
        .add_tag_id(TagIdChoice::Text("c1".into()))
        .build()
        .unwrap();
    let builder = reference_builder().build().unwrap();
    let bytes = CorimBuilder::new(CorimId::Uuid([1; 16]))
        .set_validity(Some(1_700_000_000), 1_900_000_000)
        .unwrap()
        .add_entity(EntityMap {
            entity_name: "ACME".into(),
            reg_id: Some("https://acme.example".into()),
            role: vec![1],
        })
        .add_dependent_rim(CorimLocator {
            href: CorimLocatorHref::Single("https://example.com/rim".into()),
            thumbprint: Some(CorimLocatorThumbprint::Single(Digest::new(
                7,
                vec![0xde, 0xad, 0xbe, 0xef],
            ))),
        })
        .add_tag(builder.tags[0].clone())
        .add_cotl(cotl)
        .unwrap()
        .build_bytes()
        .unwrap();
    let full = corim::validate::decode_and_validate_full(&assert_generated(&bytes)).unwrap();
    assert!(matches!(full.corim.id, CorimId::Uuid(_)));
    assert!(full.corim.rim_validity.is_some());
    assert_eq!(full.corim.entities.unwrap().len(), 1);
    assert_eq!(full.corim.dependent_rims.unwrap().len(), 1);
    assert_eq!(full.cotls.len(), 1);
}

#[test]
fn generate_coswid_tag() {
    let mut entity = SwidEntity::new("ACME", vec![SWID_ROLE_TAG_CREATOR]);
    entity.thumbprint = Some(Digest::new(2, vec![0xde, 0xad, 0xbe, 0xef]));
    let swid = ConciseSwidTag::new(
        TagIdChoice::Text("swid-1".into()),
        "ACME OS",
        0,
        vec![entity],
    );
    let bytes = CorimBuilder::new(CorimId::Text("coswid".into()))
        .add_coswid(swid)
        .unwrap()
        .build_bytes()
        .unwrap();
    let full = corim::validate::decode_and_validate_document_at_with_limits(
        &assert_generated(&bytes),
        0,
        &corim::cbor::DecodeLimits::default(),
    )
    .unwrap();
    assert_eq!(full.coswids[0].software_name, "ACME OS");
    assert_eq!(
        full.coswids[0].entities[0]
            .thumbprint
            .as_ref()
            .unwrap()
            .value(),
        &[0xde, 0xad, 0xbe, 0xef]
    );
}

#[test]
fn generate_all_migrated_shipped_templates_and_roundtrip() {
    let mut files = Files::new();
    for name in [
        "azure_ndpa",
        "azure_sfua",
        "azure_socmana",
        "azure_manticore_auth_keyattest",
        "azure_manticore_trust_keyattest",
        "cca_realm_vr72",
    ] {
        let template = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("templates")
            .join(format!("{name}.json"));
        let text = std::fs::read_to_string(template).unwrap();
        let (result, output) = generate(&mut files, &text, None);
        assert!(
            result.status.success(),
            "{name}: {}",
            String::from_utf8_lossy(&result.stderr)
        );
        let bytes = std::fs::read(&output).unwrap();
        assert_generated(&bytes);
        let full = corim::validate::decode_and_validate_full(&bytes).unwrap();
        assert_eq!(full.comids.len(), 1);
        if name == "azure_ndpa" {
            assert!(full.comids[0]
                .triples
                .conditional_endorsement_series
                .is_some());
            assert!(
                bytes.windows(3).any(|w| w == [0x39, 0x02, 0xbb]),
                "preserve profile extension key -700"
            );
        }
    }
}

#[cfg(feature = "cca")]
#[test]
fn generate_vr72_realm_template_preserves_references_and_conditional_svn() {
    use corim::types::measurement::RawValueChoice;
    use corim::types::triples::{
        ConditionalEndorsementTriple, EndorsedTriple, StatefulEnvironmentRecord,
    };
    let text = include_str!("../templates/cca_realm_vr72.json");
    let mut files = Files::new();
    let (result, path) = generate(&mut files, text, None);
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    let full = corim::validate::decode_and_validate_full(&std::fs::read(path).unwrap()).unwrap();
    let rim =
        hex::decode("723218af5344b4f87311ef2809703cfaf5d0dd7736bd4ec8e191abd43441f069").unwrap();
    let mut class = ClassMap::new("NVIDIA", "VR72");
    class.class_id = Some(corim::types::common::ClassIdChoice::Bytes(rim.clone()));
    let env = EnvironmentMap {
        class: Some(class),
        instance: None,
        group: None,
    };
    let mut rim_mval = MeasurementValuesMap::default();
    rim_mval.digests = Some(vec![Digest::new_text("sha-256", rim)]);
    let rim_measurement = MeasurementMap {
        mkey: Some(MeasuredElement::Text("cca.rim".into())),
        mval: rim_mval,
        authorized_by: None,
    };
    let mut rpv_mval = MeasurementValuesMap::default();
    rpv_mval.raw_value = Some(RawValueChoice::Bytes(vec![0; 64]));
    let rpv = MeasurementMap {
        mkey: Some(MeasuredElement::Text("cca.rpv".into())),
        mval: rpv_mval,
        authorized_by: None,
    };
    let triples = &full.comids[0].triples;
    assert_eq!(
        triples.reference_triples,
        Some(vec![ReferenceTriple::new(
            env.clone(),
            vec![rim_measurement.clone(), rpv]
        )])
    );
    let mut svn_mval = MeasurementValuesMap::default();
    svn_mval.svn = Some(SvnChoice::ExactValue(0));
    assert_eq!(
        triples.conditional_endorsement,
        Some(vec![ConditionalEndorsementTriple(
            vec![StatefulEnvironmentRecord(
                env.clone(),
                vec![rim_measurement]
            )],
            vec![EndorsedTriple::new(
                env,
                vec![MeasurementMap {
                    mkey: None,
                    mval: svn_mval,
                    authorized_by: None
                }]
            )],
        )])
    );
}

#[test]
fn generate_rejects_legacy_prose_integer_keys_comments_and_malformed_wrappers() {
    let mut files = Files::new();
    for text in [
        r#"{"corim-id":"x","comids":[]}"#,
        r#"{"0":"x","1":[]}"#,
        r#"{"type":"map","value":[],"$comment":"not ignored"}"#,
        r#"{"type":"integer","value":"1","value":"2"}"#,
        r#"{"type":"uuid","value":"550e8400-e29b-41d4-a716-446655440000"}"#,
        r#"{"type":"tag","tag":"501","value":{"type":"map","value":[]}}"#,
    ] {
        let (result, output) = generate(&mut files, text, None);
        assert!(!result.status.success(), "accepted {text}");
        assert!(!output.exists());
    }
}

#[test]
fn generate_rejects_invalid_cca_profile_document_without_writing() {
    let mut mval = MeasurementValuesMap::default();
    mval.digests = Some(vec![Digest::new_text("sha-256", vec![0x11; 32])]);
    mval.cryptokeys = Some(vec![CryptoKey::Bytes(vec![0xaa; 32])]);
    let mut class = ClassMap::default();
    class.class_id = Some(corim::types::common::ClassIdChoice::Bytes(vec![0x5a; 32]));
    let environment = EnvironmentMap {
        class: Some(class),
        instance: None,
        group: None,
    };
    let comid = ComidBuilder::new(TagIdChoice::Text("cca-platform".into()))
        .add_reference_triple(ReferenceTriple::new(
            environment,
            vec![MeasurementMap {
                mkey: Some(MeasuredElement::Text("cca.software-component".into())),
                mval,
                authorized_by: None,
            }],
        ))
        .build()
        .unwrap();
    let bytes = CorimBuilder::new(CorimId::Text("invalid-cca".into()))
        .set_profile(ProfileChoice::Uri(
            "tag:arm.com,2025:endorsements/cca_platform#1.0.0".into(),
        ))
        .add_comid_tag(comid)
        .unwrap()
        .build_bytes()
        .unwrap();
    let raw: Value = cbor::decode_exact(&bytes).unwrap();
    let mut files = Files::new();
    let (result, output) = generate(&mut files, &corim::json::to_json(&raw).unwrap(), None);
    assert!(!result.status.success());
    assert!(String::from_utf8_lossy(&result.stderr).contains("exactly one platform configuration"));
    assert!(!output.exists());
}

#[test]
fn generate_profile_override_is_unsigned_only_and_preserves_tag_bytes() {
    let bytes = reference_builder().build_bytes().unwrap();
    let root: Value = cbor::decode_exact(&bytes).unwrap();
    let mut files = Files::new();
    let profile = "tag:microsoft.com,2026:azure-profile#1.0.0";
    let (result, path) = generate(
        &mut files,
        &corim::json::to_json(&root).unwrap(),
        Some(profile),
    );
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    let original = corim::validate::decode_and_validate_full(&bytes).unwrap();
    let changed = corim::validate::decode_and_validate_full(&std::fs::read(path).unwrap()).unwrap();
    assert_eq!(changed.corim.tags, original.corim.tags);
    assert_eq!(
        changed.corim.profile,
        Some(ProfileChoice::Uri(profile.into()))
    );
    for payload in [Value::Bytes(bytes.clone()), Value::Null] {
        let signed = Value::Tag(
            TAG_SIGNED_CORIM,
            Box::new(Value::Array(vec![
                Value::Bytes(vec![0xa1, 0x01, 0x26]),
                Value::Map(vec![]),
                payload,
                Value::Bytes(vec![0; 64]),
            ])),
        );
        let text = corim::json::to_json(&signed).unwrap();
        let (result, path) = generate(&mut files, &text, Some("https://changed.example"));
        assert!(!result.status.success());
        assert!(
            String::from_utf8_lossy(&result.stderr).contains("signed protected and payload bytes")
        );
        assert!(!path.exists());
    }
}

#[test]
fn generate_signed_preserves_entire_envelope_and_exact_protected_bstr() {
    use corim::types::signed::{CwtClaims, SignedCorimBuilder};
    let payload = reference_builder().build_bytes().unwrap();
    let envelope = SignedCorimBuilder::new(-7, payload)
        .set_cwt_claims(CwtClaims::new("Test Signer"))
        .build_with_signature(vec![0x55; 64])
        .unwrap();
    let mut root: Value = cbor::decode_exact(&envelope).unwrap();
    let Value::Tag(_, inner) = &mut root else {
        panic!()
    };
    let Value::Array(elements) = inner.as_mut() else {
        panic!()
    };
    let Value::Bytes(protected) = &mut elements[0] else {
        panic!()
    };
    // Make the alg label noncanonical without changing its meaning.
    assert_eq!(protected[1], 1);
    protected.splice(1..2, [0x18, 0x01]);
    let expected = protected.clone();
    let bytes = cbor::encode(&root).unwrap();
    let regenerated = assert_generated(&bytes);
    let decoded: Value = cbor::decode_exact(&regenerated).unwrap();
    let Value::Tag(_, inner) = decoded else {
        panic!()
    };
    let Value::Array(elements) = *inner else {
        panic!()
    };
    assert_eq!(elements[0], Value::Bytes(expected));
    assert_eq!(elements[3], Value::Bytes(vec![0x55; 64]));
}

#[test]
fn generate_partial_unknown_profile_or_tag_exits_four_without_output() {
    let profiles = [
        ProfileChoice::Uri("https://unregistered.example/profile".into()),
        ProfileChoice::Oid(vec![0x2b, 0x06, 0x01, 0x04, 0x01]),
    ];
    let mut documents: Vec<Vec<u8>> = profiles
        .into_iter()
        .map(|profile| {
            reference_builder()
                .set_profile(profile)
                .build_bytes()
                .unwrap()
        })
        .collect();
    documents.push(
        reference_builder()
            .add_tag(corim::types::corim::ConciseTagChoice::Unknown(
                10001,
                vec![0xf6],
            ))
            .build_bytes()
            .unwrap(),
    );
    let mut files = Files::new();
    for bytes in documents {
        let root: Value = cbor::decode_exact(&bytes).unwrap();
        let (result, output) = generate(&mut files, &corim::json::to_json(&root).unwrap(), None);
        assert_eq!(
            result.status.code(),
            Some(4),
            "{}",
            String::from_utf8_lossy(&result.stderr)
        );
        assert!(String::from_utf8_lossy(&result.stderr).contains("PARTIAL"));
        assert!(!output.exists());
    }
}

#[test]
fn validate_and_diagnose_render_azure_mval_key_names() {
    let mut files = Files::new();
    let (generated, path) = generate(
        &mut files,
        include_str!("../templates/azure_ndpa.json"),
        None,
    );
    assert!(generated.status.success());
    let result = Command::new(bin())
        .arg("validate")
        .arg(&path)
        .output()
        .unwrap();
    assert!(result.status.success());
    assert!(String::from_utf8_lossy(&result.stdout).contains("tcbstatus"));
    let result = Command::new(bin())
        .arg("validate")
        .arg(&path)
        .arg("--diagnose")
        .output()
        .unwrap();
    assert!(result.status.success());
    let text = String::from_utf8_lossy(&result.stdout);
    assert!(text.contains("matched registered profile") && text.contains("azure-profile"));
}
