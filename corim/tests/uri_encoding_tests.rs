// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use corim::cbor;
use corim::cbor::value::Value;
use corim::types::common::EntityMap;
use corim::types::corim::{CorimLocatorHref, CorimSignerMap, ProfileChoice};
use corim::types::tags::{CORIM_ROLE_MANIFEST_CREATOR, TAG_URI};

const TEST_URI: &str = "https://example.com/profile";

fn tagged_uri() -> Value {
    Value::Tag(TAG_URI, Box::new(Value::Text(TEST_URI.into())))
}

fn assert_encodes_as_tagged_uri<T: serde::Serialize>(value: &T) {
    let encoded = cbor::encode(value).unwrap();
    let decoded: Value = cbor::decode(&encoded).unwrap();
    assert_eq!(decoded, tagged_uri());
}

#[test]
fn profile_uri_encodes_with_tag_32() {
    assert_encodes_as_tagged_uri(&ProfileChoice::Uri(TEST_URI.into()));
}

#[test]
fn profile_uri_decodes_tagged_and_legacy_bare_forms() {
    let tagged = cbor::encode(&tagged_uri()).unwrap();
    let bare = cbor::encode(&Value::Text(TEST_URI.into())).unwrap();

    assert_eq!(
        cbor::decode::<ProfileChoice>(&tagged).unwrap(),
        ProfileChoice::Uri(TEST_URI.into())
    );
    assert_eq!(
        cbor::decode::<ProfileChoice>(&bare).unwrap(),
        ProfileChoice::Uri(TEST_URI.into())
    );
}

#[test]
fn profile_uri_rejects_tag_32_with_non_text_content() {
    let encoded = cbor::encode(&Value::Tag(TAG_URI, Box::new(Value::Integer(1i128)))).unwrap();

    let error = cbor::decode::<ProfileChoice>(&encoded).unwrap_err();
    assert!(error.to_string().contains("tag #6.32 must wrap text"));
}

#[test]
fn signer_uri_encodes_with_tag_32() {
    let signer = CorimSignerMap {
        signer_name: "Example signer".into(),
        signer_uri: Some(TEST_URI.into()),
    };

    let encoded = cbor::encode(&signer).unwrap();
    let decoded: Value = cbor::decode(&encoded).unwrap();
    let Value::Map(entries) = decoded else {
        panic!("expected signer map");
    };
    assert!(entries
        .iter()
        .any(|(key, value)| *key == Value::Integer(1i128) && *value == tagged_uri()));
}

#[test]
fn signer_uri_decodes_tagged_and_legacy_bare_forms() {
    for uri in [tagged_uri(), Value::Text(TEST_URI.into())] {
        let value = Value::Map(vec![
            (Value::Integer(0i128), Value::Text("Example signer".into())),
            (Value::Integer(1i128), uri),
        ]);
        let encoded = cbor::encode(&value).unwrap();
        let signer: CorimSignerMap = cbor::decode(&encoded).unwrap();
        assert_eq!(signer.signer_uri.as_deref(), Some(TEST_URI));
    }
}

#[test]
fn locator_uris_encode_with_tag_32() {
    assert_encodes_as_tagged_uri(&CorimLocatorHref::Single(TEST_URI.into()));

    let encoded = cbor::encode(&CorimLocatorHref::Multiple(vec![
        TEST_URI.into(),
        "https://example.com/other".into(),
    ]))
    .unwrap();
    let decoded: Value = cbor::decode(&encoded).unwrap();
    let Value::Array(uris) = decoded else {
        panic!("expected URI array");
    };
    assert!(uris.iter().all(|uri| matches!(uri, Value::Tag(TAG_URI, _))));
}

#[test]
fn entity_registration_uri_encodes_with_tag_32() {
    let entity = EntityMap {
        entity_name: "Example entity".into(),
        reg_id: Some(TEST_URI.into()),
        role: vec![CORIM_ROLE_MANIFEST_CREATOR],
    };

    let encoded = cbor::encode(&entity).unwrap();
    let decoded: Value = cbor::decode(&encoded).unwrap();
    let Value::Map(entries) = decoded else {
        panic!("expected entity map");
    };
    assert!(entries
        .iter()
        .any(|(key, value)| *key == Value::Integer(1i128) && *value == tagged_uri()));
}

#[test]
fn entity_registration_uri_decodes_tagged_and_legacy_bare_forms() {
    for uri in [tagged_uri(), Value::Text(TEST_URI.into())] {
        let value = Value::Map(vec![
            (Value::Integer(0i128), Value::Text("Example entity".into())),
            (Value::Integer(1i128), uri),
            (
                Value::Integer(2i128),
                Value::Array(vec![Value::Integer(i128::from(
                    CORIM_ROLE_MANIFEST_CREATOR,
                ))]),
            ),
        ]);
        let encoded = cbor::encode(&value).unwrap();
        let entity: EntityMap = cbor::decode(&encoded).unwrap();
        assert_eq!(entity.reg_id.as_deref(), Some(TEST_URI));
    }
}

#[cfg(feature = "json")]
#[test]
fn tagged_uri_fields_render_as_plain_json_strings() {
    let rendered = [
        corim::json::to_json(&ProfileChoice::Uri(TEST_URI.into())).unwrap(),
        corim::json::to_json(&CorimLocatorHref::Single(TEST_URI.into())).unwrap(),
        corim::json::to_json(&CorimSignerMap {
            signer_name: "Example signer".into(),
            signer_uri: Some(TEST_URI.into()),
        })
        .unwrap(),
        corim::json::to_json(&EntityMap {
            entity_name: "Example entity".into(),
            reg_id: Some(TEST_URI.into()),
            role: vec![CORIM_ROLE_MANIFEST_CREATOR],
        })
        .unwrap(),
    ];

    for json in rendered {
        assert!(json.contains(TEST_URI), "URI missing from JSON: {json}");
        assert!(
            !json.contains("__cbor_tag"),
            "URI tag leaked into JSON: {json}"
        );
    }
}
