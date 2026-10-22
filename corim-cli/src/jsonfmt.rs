// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Shared JSON rendering helpers.
//!
//! The COSE protected header is built once here as a `serde_json::Value` and
//! reused by `validate -f json` and `extract --header --json`.
//! `convert` renders the entire raw envelope instead of a header summary.

use corim::cbor::value::Value;
use corim::error::EncodeError;
use corim::types::signed::{ClaimKey, ProtectedCorimHeaderMap};
use serde_json::{json, Map, Value as JsonValue};

/// Render CBOR-valued report data with the shared lossless codec.
pub fn cbor_to_json(v: &Value) -> Result<JsonValue, EncodeError> {
    corim::json::value_to_json(v)
}

/// Build the COSE protected header as a JSON object.
///
/// `size` is the length of the protected `bstr` as it appears in the
/// envelope (the bytes that go into `Sig_structure1`).
pub fn protected_header_value(
    p: &ProtectedCorimHeaderMap,
    size: usize,
) -> Result<JsonValue, EncodeError> {
    let mut o = Map::new();
    o.insert("size".into(), json!(size));
    o.insert("alg".into(), json!(p.alg.name()));
    o.insert("alg_id".into(), json!(p.alg.to_i64()));
    if let Some(ct) = p.content_type.as_ref() {
        o.insert("content_type".into(), json!(ct));
    }
    if let Some(alg) = p.payload_hash_alg {
        o.insert("payload_hash_alg".into(), json!(alg));
    }
    if let Some(ct) = p.payload_preimage_content_type.as_ref() {
        o.insert("payload_preimage_content_type".into(), json!(ct));
    }
    if let Some(loc) = p.payload_location.as_ref() {
        o.insert("payload_location".into(), json!(loc));
    }
    if let Some(claims) = p.cwt_claims.as_ref() {
        o.insert("issuer".into(), json!(claims.iss));
        if let Some(subject) = claims.sub.as_ref() {
            o.insert("subject".into(), json!(subject));
        }
        if let Some(exp) = claims.exp {
            let value = corim::cbor::value::to_value(&exp).map_err(EncodeError::Serialization)?;
            o.insert("exp".into(), cbor_to_json(&value)?);
        }
        if let Some(nbf) = claims.nbf {
            let value = corim::cbor::value::to_value(&nbf).map_err(EncodeError::Serialization)?;
            o.insert("nbf".into(), cbor_to_json(&value)?);
        }
        if let Some(extra) = claim_extras(&claims.extra)? {
            o.insert("cwt_claims_extra".into(), extra);
        }
    }
    if let Some(meta) = p.corim_meta.as_ref() {
        o.insert("signer_name".into(), json!(meta.signer.signer_name));
        if let Some(uri) = meta.signer.signer_uri.as_ref() {
            o.insert("signer_uri".into(), json!(uri));
        }
    }
    o.insert("has_cwt_claims".into(), json!(p.cwt_claims.is_some()));
    o.insert("has_corim_meta".into(), json!(p.corim_meta.is_some()));
    o.insert("has_kid".into(), json!(p.kid.is_some()));
    o.insert(
        "x5chain_count".into(),
        json!(p.x5chain.as_ref().map(|x| x.certs().len()).unwrap_or(0)),
    );
    o.insert("has_x5t".into(), json!(p.x5t.is_some()));
    if let Some(extra) = claim_extras(&p.extra)? {
        o.insert("header_extra".into(), extra);
    }
    Ok(JsonValue::Object(o))
}

/// Render the protected header as pretty JSON, with every line after the
/// first prefixed by `indent` so it can be embedded in a larger report.
pub fn protected_header(
    p: &ProtectedCorimHeaderMap,
    size: usize,
    indent: &str,
) -> Result<String, EncodeError> {
    let text = serde_json::to_string_pretty(&protected_header_value(p, size)?)
        .map_err(|e| EncodeError::Serialization(e.to_string()))?;
    let mut out = String::with_capacity(text.len());
    for (i, line) in text.lines().enumerate() {
        if i > 0 {
            out.push('\n');
            out.push_str(indent);
        }
        out.push_str(line);
    }
    Ok(out)
}

/// Extra CWT/header claims encoded as one lossless map with typed keys.
fn claim_extras(
    extra: &std::collections::BTreeMap<ClaimKey, Value>,
) -> Result<Option<JsonValue>, EncodeError> {
    if extra.is_empty() {
        return Ok(None);
    }
    let mut entries = Vec::new();
    for (k, v) in extra {
        let key = match k {
            ClaimKey::Int(n) => Value::Integer(i128::from(*n)),
            ClaimKey::Text(t) => Value::Text(t.clone()),
            _ => {
                return Err(EncodeError::Serialization(
                    "unsupported claim key type".into(),
                ))
            }
        };
        entries.push((key, v.clone()));
    }
    Ok(Some(cbor_to_json(&Value::Map(entries))?))
}

#[cfg(test)]
mod tests {
    use super::*;
    use corim::types::signed::{CoseAlgorithm, CwtClaims, ProtectedCorimHeaderMapBuilder};

    #[test]
    fn header_metadata_stays_native_while_extensions_are_lossless() {
        let mut claims = CwtClaims::new("Issuer");
        claims.exp = Some(1_i64.into());
        claims.nbf = Some(corim::types::signed::NumericDate::Float(-0.0));
        claims.extra.insert(
            ClaimKey::Int(10001),
            Value::Float(f64::from_bits(0x7ff8_0000_0000_0123)),
        );
        claims
            .extra
            .insert(ClaimKey::Text("10001".into()), Value::Bytes(vec![0, 255]));
        let mut header = ProtectedCorimHeaderMapBuilder::new(CoseAlgorithm::Es256)
            .cwt_claims(claims)
            .build();
        header.extra.insert(
            ClaimKey::Int(10001),
            Value::Map(vec![
                (Value::Integer(1), Value::Bool(false)),
                (Value::Text("1".into()), Value::Bool(true)),
                (Value::Integer(1), Value::Null),
            ]),
        );
        let rendered = protected_header_value(&header, 27).unwrap();
        assert_eq!(rendered["size"], 27);
        assert_eq!(rendered["alg_id"], -7);
        assert_eq!(rendered["issuer"], "Issuer");
        assert_eq!(rendered["has_cwt_claims"], true);
        assert_eq!(rendered["exp"], json!({"type":"integer","value":"1"}));
        assert_eq!(
            rendered["nbf"],
            json!({"type":"float-bits","value":"8000000000000000"})
        );
        assert_eq!(rendered["cwt_claims_extra"]["type"], "map");
        let extra = corim::json::json_to_value(&rendered["header_extra"]).unwrap();
        assert_eq!(
            extra,
            Value::Map(vec![(
                Value::Integer(10001),
                header.extra[&ClaimKey::Int(10001)].clone()
            )])
        );
        assert!(protected_header(&header, 27, "  ")
            .unwrap()
            .contains("\n  "));
    }

    #[test]
    fn rendering_errors_are_propagated_not_replaced_with_null_or_empty_object() {
        let mut header = ProtectedCorimHeaderMapBuilder::new(CoseAlgorithm::Es256).build();
        header
            .extra
            .insert(ClaimKey::Int(10001), Value::Integer(i128::MAX));
        assert!(protected_header_value(&header, 0).is_err());
        assert!(protected_header(&header, 0, "").is_err());
        assert!(cbor_to_json(&Value::Integer(i128::MAX)).is_err());
    }
}
