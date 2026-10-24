use corim::cbor::{self, value::Value, DecodeLimits};
use corim::types::signed::*;
use corim::types::tags::TAG_SIGNED_CORIM;

fn int(key: i64) -> Value {
    Value::Integer(i128::from(key))
}

fn text(value: &str) -> Value {
    Value::Text(value.into())
}

fn nested_claims() -> Value {
    let claims = Value::Map(vec![
        (int(CWT_CLAIM_ISS), text("Signer")),
        (int(CWT_CLAIM_SUB), text("Subject")),
        (text("svn"), text("1.2")),
        (int(100), text("integer label")),
        (text("100"), text("text label")),
        (int(CWT_CLAIM_EXP), Value::Float(1_900_000_000.25)),
    ]);
    cbor::decode(&cbor::encode(&claims).unwrap()).unwrap()
}

fn signed(claims: Option<Value>) -> CoseSign1Corim {
    let mut header = vec![
        (int(COSE_HEADER_ALG), int(CoseAlgorithm::Es256.to_i64())),
        (int(COSE_HEADER_CONTENT_TYPE), text(CORIM_CONTENT_TYPE)),
    ];
    if let Some(claims) = claims {
        header.push((int(COSE_HEADER_CWT_CLAIMS), claims));
    }
    let protected_header_bytes = cbor::encode(&Value::Map(header)).unwrap();
    CoseSign1Corim {
        protected_header_bytes,
        protected: ProtectedCorimHeaderMapBuilder::new(CoseAlgorithm::Es256).build(),
        unprotected: vec![],
        payload: None,
        signature: vec![1],
    }
}

#[test]
fn original_claims_retain_string_values_text_labels_and_numeric_identity() {
    let original = signed(Some(nested_claims()));
    let bytes = encode_signed_corim(&original).unwrap();
    let mut decoded = decode_signed_corim(&bytes).unwrap();
    let typed = decoded.protected.cwt_claims.as_ref().unwrap();
    assert_eq!(typed.iss, "Signer");
    assert_eq!(typed.sub.as_deref(), Some("Subject"));
    assert_eq!(typed.extra.get(&100), Some(&text("integer label")));
    assert_eq!(decoded.cwt_claims_value().unwrap(), Some(nested_claims()));
    let tbs = decoded.to_be_signed_detached(b"payload", b"aad").unwrap();
    decoded.protected.cwt_claims.as_mut().unwrap().iss = "Edited typed view".into();
    assert_eq!(decoded.cwt_claims_value().unwrap(), Some(nested_claims()));
    assert_eq!(
        decoded.to_be_signed_detached(b"payload", b"aad").unwrap(),
        tbs
    );
    assert_eq!(encode_signed_corim(&decoded).unwrap(), bytes);
    assert_eq!(
        decoded.protected_header_bytes,
        original.protected_header_bytes
    );
}

#[test]
fn integer_and_string_svn_values_are_both_available() {
    for svn in [Value::Integer(7), text("7")] {
        let claims = Value::Map(vec![
            (int(CWT_CLAIM_ISS), text("Signer")),
            (text("svn"), svn),
        ]);
        assert_eq!(
            signed(Some(claims.clone())).cwt_claims_value().unwrap(),
            Some(claims)
        );
    }
}

#[test]
fn flat_registered_claims_do_not_absorb_text_cose_extensions() {
    let header = Value::Map(vec![
        (int(COSE_HEADER_ALG), int(CoseAlgorithm::Es256.to_i64())),
        (int(CWT_CLAIM_ISS), text("Signer")),
        (int(CWT_CLAIM_SUB), text("Subject")),
        (text("svn"), int(7)),
    ]);
    let mut envelope = signed(None);
    envelope.protected_header_bytes = cbor::encode(&header).unwrap();
    assert_eq!(
        envelope.cwt_claims_value().unwrap(),
        Some(Value::Map(vec![
            (int(CWT_CLAIM_ISS), text("Signer")),
            (int(CWT_CLAIM_SUB), text("Subject")),
        ]))
    );
}

#[test]
fn absent_claims_are_none_and_invalid_headers_fail_explicitly() {
    assert_eq!(signed(None).cwt_claims_value().unwrap(), None);
    assert!(signed(Some(Value::Null)).cwt_claims_value().is_err());
    let mut envelope = signed(None);
    envelope.protected_header_bytes = cbor::encode(&Value::Array(vec![])).unwrap();
    assert!(envelope.cwt_claims_value().is_err());
    envelope.protected_header_bytes = vec![0xff];
    assert!(envelope.cwt_claims_value().is_err());
    envelope = signed(Some(nested_claims()));
    envelope.protected_header_bytes.push(0);
    assert!(envelope.cwt_claims_value().is_err());
}

#[test]
fn view_rejects_duplicate_claims_and_honors_explicit_limits() {
    let duplicate = Value::Map(vec![
        (int(CWT_CLAIM_ISS), text("Signer")),
        (text("svn"), int(1)),
        (text("svn"), int(2)),
    ]);
    assert!(signed(Some(duplicate)).cwt_claims_value().is_err());
    let envelope = signed(Some(nested_claims()));
    let mut limits = DecodeLimits::default();
    limits.max_values = 1;
    assert!(envelope.cwt_claims_value_with_limits(&limits).is_err());
    let bytes = encode_signed_corim(&envelope).unwrap();
    assert!(matches!(
        cbor::decode::<Value>(&bytes).unwrap(),
        Value::Tag(TAG_SIGNED_CORIM, _)
    ));
}
