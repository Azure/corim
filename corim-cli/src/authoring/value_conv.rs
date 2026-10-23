// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! CLI-private semantic values for readable authoring, not an arbitrary CBOR codec.

use base64::{engine::general_purpose::STANDARD, Engine};
use corim::cbor::value::Value;
use corim::types::tags::*;
use serde_json::{Map, Value as Json};
use std::collections::BTreeSet;

use super::key_maps as keys;

const CHOICES: &[(u64, &str)] = &[
    (TAG_UUID, "uuid"),
    (TAG_OID, "oid"),
    (TAG_UEID, "ueid"),
    (TAG_SVN, "svn"),
    (TAG_MIN_SVN, "min-svn"),
    (TAG_PKIX_BASE64_KEY, "pkix-base64-key"),
    (TAG_PKIX_BASE64_CERT, "pkix-base64-cert"),
    (TAG_PKIX_BASE64_CERT_PATH, "pkix-base64-cert-path"),
    (TAG_KEY_THUMBPRINT, "key-thumbprint"),
    (TAG_COSE_KEY, "cose-key"),
    (TAG_CERT_THUMBPRINT, "cert-thumbprint"),
    (TAG_BYTES, "bytes"),
    (TAG_CERT_PATH_THUMBPRINT, "cert-path-thumbprint"),
    (TAG_PKIX_ASN1DER_CERT, "pkix-asn1der-cert"),
    (TAG_MASKED_RAW_VALUE, "masked-raw-value"),
    (TAG_INT_RANGE, "int-range"),
];

fn choice(name: &str, value: Json) -> Json {
    serde_json::json!({"type": name, "value": value})
}

pub(super) fn value_to_json(value: &Value) -> Result<Json, String> {
    Ok(match value {
        Value::Null => Json::Null,
        Value::Bool(b) => Json::Bool(*b),
        Value::Integer(n) => {
            if let Ok(n) = i64::try_from(*n) {
                Json::from(n)
            } else if let Ok(n) = u64::try_from(*n) {
                Json::from(n)
            } else {
                choice("integer", Json::String(n.to_string()))
            }
        }
        Value::Float(f) => match serde_json::Number::from_f64(*f) {
            Some(n) => Json::Number(n),
            None => choice("float-bits", Json::String(format!("{:016x}", f.to_bits()))),
        },
        Value::Text(t) => Json::String(t.clone()),
        Value::Bytes(b) => Json::String(STANDARD.encode(b)),
        Value::Array(items) => {
            Json::Array(items.iter().map(value_to_json).collect::<Result<_, _>>()?)
        }
        Value::Map(entries) => {
            let mut map = Map::new();
            for (key, value) in entries {
                let key = match key {
                    Value::Integer(n) => i64::try_from(*n)
                        .ok()
                        .and_then(keys::int_to_string_key)
                        .map(str::to_owned)
                        .unwrap_or_else(|| n.to_string()),
                    Value::Text(t) => t.clone(),
                    _ => return Err(
                        "map key cannot be represented in readable JSON; use convert --lossless"
                            .into(),
                    ),
                };
                if map.insert(key.clone(), value_to_json(value)?).is_some() {
                    return Err(format!(
                        "readable map key collision at {key}; use convert --lossless"
                    ));
                }
            }
            Json::Object(map)
        }
        Value::Tag(tag, inner) => {
            if *tag == TAG_UUID {
                if let Value::Bytes(bytes) = inner.as_ref() {
                    if bytes.len() == 16 {
                        let h = hex::encode(bytes);
                        return Ok(choice(
                            "uuid",
                            Json::String(format!(
                                "{}-{}-{}-{}-{}",
                                &h[..8],
                                &h[8..12],
                                &h[12..16],
                                &h[16..20],
                                &h[20..]
                            )),
                        ));
                    }
                }
            }
            if let Some((_, name)) = CHOICES.iter().find(|(number, _)| number == tag) {
                choice(name, value_to_json(inner)?)
            } else {
                serde_json::json!({"__cbor_tag": tag, "__cbor_value": value_to_json(inner)?})
            }
        }
    })
}

pub(super) fn json_to_value(value: &Json) -> Result<Value, String> {
    Ok(match value {
        Json::Null => Value::Null,
        Json::Bool(b) => Value::Bool(*b),
        Json::Number(n) => {
            if let Some(n) = n.as_i64() {
                Value::Integer(i128::from(n))
            } else if let Some(n) = n.as_u64() {
                Value::Integer(i128::from(n))
            } else {
                Value::Float(n.as_f64().ok_or("invalid readable JSON number")?)
            }
        }
        Json::String(t) => Value::Text(t.clone()),
        Json::Array(items) => {
            Value::Array(items.iter().map(json_to_value).collect::<Result<_, _>>()?)
        }
        Json::Object(map) => {
            if let Some(tag) = map.get("__cbor_tag") {
                if map.len() != 2 {
                    return Err(
                        "CBOR tag wrapper requires exactly __cbor_tag and __cbor_value".into(),
                    );
                }
                return Ok(Value::Tag(
                    tag.as_u64().ok_or("CBOR tag must be an unsigned integer")?,
                    Box::new(json_to_value(
                        map.get("__cbor_value").ok_or("missing __cbor_value")?,
                    )?),
                ));
            }
            if let (Some(Json::String(name)), Some(inner)) = (map.get("type"), map.get("value")) {
                if map.len() == 2 {
                    return type_choice_to_value(name, inner);
                }
            }
            let mut entries = Vec::new();
            let mut integers = BTreeSet::new();
            let mut texts = BTreeSet::new();
            for (key, value) in map {
                let integer = keys::string_to_int_key(key)
                    .map(i128::from)
                    .or_else(|| key.parse::<i128>().ok());
                let key = if let Some(integer) = integer {
                    if !integers.insert(integer) {
                        return Err(
                            "conflicting readable JSON keys after integer conversion".into()
                        );
                    }
                    Value::Integer(integer)
                } else {
                    if !texts.insert(key.as_str()) {
                        return Err("conflicting readable JSON text keys".into());
                    }
                    Value::Text(key.clone())
                };
                entries.push((key, json_to_value(value)?));
            }
            Value::Map(entries)
        }
    })
}

fn type_choice_to_value(name: &str, value: &Json) -> Result<Value, String> {
    let invalid = || format!("invalid {name} type-choice value");
    match name {
        "integer" => value
            .as_str()
            .and_then(|s| s.parse::<i128>().ok())
            .map(Value::Integer)
            .ok_or_else(invalid),
        "float-bits" => value
            .as_str()
            .filter(|s| s.len() == 16)
            .and_then(|s| u64::from_str_radix(s, 16).ok())
            .map(|bits| Value::Float(f64::from_bits(bits)))
            .ok_or_else(invalid),
        "byte-string" => value
            .as_str()
            .and_then(|s| hex::decode(s).ok())
            .map(Value::Bytes)
            .ok_or_else(invalid),
        "number-range" => Ok(Value::Tag(
            TAG_NUMBER_RANGE,
            Box::new(json_to_value(value)?),
        )),
        "number-set" | "text-set" | "bytes-set" => {
            Ok(Value::Tag(TAG_MATCHER_SET, Box::new(json_to_value(value)?)))
        }
        _ => {
            let tag = CHOICES
                .iter()
                .find(|(_, candidate)| *candidate == name)
                .map(|(tag, _)| *tag)
                .ok_or_else(|| format!("unknown readable type-choice {name}"))?;
            let inner = match tag {
                TAG_UUID => {
                    let text = value.as_str().ok_or_else(invalid)?;
                    let bytes = hex::decode(text.replace('-', "")).map_err(|_| invalid())?;
                    if bytes.len() != 16 {
                        return Err(invalid());
                    }
                    Value::Bytes(bytes)
                }
                TAG_UEID | TAG_BYTES => Value::Bytes(
                    STANDARD
                        .decode(value.as_str().ok_or_else(invalid)?)
                        .map_err(|_| invalid())?,
                ),
                _ => json_to_value(value)?,
            };
            Ok(Value::Tag(tag, Box::new(inner)))
        }
    }
}
