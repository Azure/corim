// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Conversion between `cbor::value::Value` (integer keys) and
//! `serde_json::Value` (string keys).

use crate::cbor::value::Value;

use super::key_maps as keys;

/// Convert a `Value` to a `serde_json::Value`, remapping integer map keys
/// to JSON string names.
///
/// CBOR tags are represented in JSON as `{"__cbor_tag": <tag_num>, "__cbor_value": <inner>}`.
/// Type-choice tagged values (UUID, OID, etc.) are converted to the
/// `{"type": "...", "value": ...}` format.
pub fn value_to_json(v: &Value) -> serde_json::Value {
    match v {
        Value::Null => serde_json::Value::Null,
        Value::Bool(b) => serde_json::Value::Bool(*b),
        Value::Integer(n) => {
            // JSON numbers: try i64 first, fall back to string for very large values
            if let Ok(i) = i64::try_from(*n) {
                serde_json::Value::Number(serde_json::Number::from(i))
            } else {
                serde_json::Value::String(n.to_string())
            }
        }
        Value::Float(f) => serde_json::Number::from_f64(*f)
            .map(serde_json::Value::Number)
            .unwrap_or(serde_json::Value::Null),
        Value::Text(t) => serde_json::Value::String(t.clone()),
        Value::Bytes(b) => {
            // Bytes → base64 string (standard convention for JSON)
            serde_json::Value::String(base64_encode(b))
        }
        Value::Array(arr) => serde_json::Value::Array(arr.iter().map(value_to_json).collect()),
        Value::Map(entries) => {
            let mut obj = serde_json::Map::new();
            for (k, v) in entries {
                let key_str = match k {
                    Value::Integer(n) => {
                        // Safe: key mapping only covers small i64-range keys.
                        // Fall back to the full i128 string for out-of-range keys.
                        match i64::try_from(*n) {
                            Ok(n_i64) => keys::int_to_string_key(n_i64)
                                .map(|s| s.to_string())
                                .unwrap_or_else(|| n_i64.to_string()),
                            Err(_) => n.to_string(),
                        }
                    }
                    Value::Text(t) => t.clone(),
                    _ => format!("{:?}", k),
                };
                obj.insert(key_str, value_to_json(v));
            }
            serde_json::Value::Object(obj)
        }
        Value::Tag(tag, inner) => tag_to_json(*tag, inner),
    }
}

/// Convert a `serde_json::Value` to a `Value`, remapping string map keys
/// back to integer keys.
pub fn json_to_value(j: &serde_json::Value) -> Value {
    match j {
        serde_json::Value::Null => Value::Null,
        serde_json::Value::Bool(b) => Value::Bool(*b),
        serde_json::Value::Number(n) => {
            if let Some(i) = n.as_i64() {
                Value::Integer(i as i128)
            } else if let Some(u) = n.as_u64() {
                Value::Integer(u as i128)
            } else if let Some(f) = n.as_f64() {
                Value::Float(f)
            } else {
                Value::Integer(0)
            }
        }
        serde_json::Value::String(s) => {
            // Check if this looks like a base64-encoded bytes value
            // (we can't distinguish text from bytes in JSON without context)
            Value::Text(s.clone())
        }
        serde_json::Value::Array(arr) => Value::Array(arr.iter().map(json_to_value).collect()),
        serde_json::Value::Object(obj) => {
            // Check for CBOR tag representation
            if let Some(tag_num) = obj.get("__cbor_tag") {
                if let Some(tag_val) = obj.get("__cbor_value") {
                    if let Some(n) = tag_num.as_u64() {
                        return Value::Tag(n, Box::new(json_to_value(tag_val)));
                    }
                }
            }

            // Check for type-choice format: {"type": "...", "value": ...}
            if let (Some(serde_json::Value::String(type_name)), Some(value)) =
                (obj.get("type"), obj.get("value"))
            {
                if obj.len() == 2 {
                    return type_choice_to_value(type_name, value);
                }
            }

            // Regular object → map with integer keys where possible
            let entries: Vec<(Value, Value)> = obj
                .iter()
                .map(|(k, v)| {
                    let key = keys::string_to_int_key(k)
                        .map(|i| Value::Integer(i as i128))
                        .unwrap_or_else(|| {
                            // Try parsing as integer
                            k.parse::<i64>()
                                .map(|i| Value::Integer(i as i128))
                                .unwrap_or_else(|_| Value::Text(k.clone()))
                        });
                    (key, json_to_value(v))
                })
                .collect();
            Value::Map(entries)
        }
    }
}

// ---------------------------------------------------------------------------
// CBOR tag → JSON conversion (type-choice enums)
// ---------------------------------------------------------------------------

/// Known CBOR tags for type-choice → JSON format.
fn tag_to_json(tag: u64, inner: &Value) -> serde_json::Value {
    match tag {
        // Tag 1: epoch time → just the integer
        1 => value_to_json(inner),
        // Tag 37: UUID → {"type": "uuid", "value": "xxxxxxxx-xxxx-..."}
        37 => match inner {
            Value::Bytes(b) if b.len() == 16 => {
                type_choice_json("uuid", serde_json::Value::String(format_uuid(b)))
            }
            _ => type_choice_json("uuid", value_to_json(inner)),
        },
        // Tag 111: OID → {"type": "oid", "value": "<base64>"}
        111 => type_choice_json("oid", value_to_json(inner)),
        // Tag 550: UEID → {"type": "ueid", "value": "<base64>"}
        550 => match inner {
            Value::Bytes(b) => {
                type_choice_json("ueid", serde_json::Value::String(base64_encode(b)))
            }
            _ => type_choice_json("ueid", value_to_json(inner)),
        },
        // Tag 552: SVN → {"type": "svn", "value": <n>}
        552 => type_choice_json("svn", value_to_json(inner)),
        // Tag 553: min-SVN → {"type": "min-svn", "value": <n>}
        553 => type_choice_json("min-svn", value_to_json(inner)),
        // Tag 554-562: crypto key types
        554 => type_choice_json("pkix-base64-key", value_to_json(inner)),
        555 => type_choice_json("pkix-base64-cert", value_to_json(inner)),
        556 => type_choice_json("pkix-base64-cert-path", value_to_json(inner)),
        557 => type_choice_json("key-thumbprint", value_to_json(inner)),
        558 => type_choice_json("cose-key", value_to_json(inner)),
        559 => type_choice_json("cert-thumbprint", value_to_json(inner)),
        560 => type_choice_json("bytes", value_to_json(inner)),
        561 => type_choice_json("cert-path-thumbprint", value_to_json(inner)),
        562 => type_choice_json("pkix-asn1der-cert", value_to_json(inner)),
        563 => type_choice_json("masked-raw-value", value_to_json(inner)),
        564 => type_choice_json("int-range", value_to_json(inner)),
        // Tag 505, 506, 508: CoSWID/CoMID/CoTL inside tags array → base64 bytes
        505 | 506 | 508 => {
            let mut obj = serde_json::Map::new();
            obj.insert("__cbor_tag".into(), serde_json::Value::Number(tag.into()));
            obj.insert("__cbor_value".into(), value_to_json(inner));
            serde_json::Value::Object(obj)
        }
        // Default: preserve as explicit tag object
        _ => {
            let mut obj = serde_json::Map::new();
            obj.insert("__cbor_tag".into(), serde_json::Value::Number(tag.into()));
            obj.insert("__cbor_value".into(), value_to_json(inner));
            serde_json::Value::Object(obj)
        }
    }
}

/// Convert `{"type": ..., "value": ...}` JSON back to CBOR tagged value.
fn type_choice_to_value(type_name: &str, value: &serde_json::Value) -> Value {
    match type_name {
        "uuid" => {
            if let Some(s) = value.as_str() {
                if let Some(bytes) = parse_uuid(s) {
                    return Value::Tag(37, Box::new(Value::Bytes(bytes)));
                }
            }
            Value::Tag(37, Box::new(json_to_value(value)))
        }
        "oid" => Value::Tag(111, Box::new(json_to_value(value))),
        "ueid" => {
            if let Some(s) = value.as_str() {
                if let Ok(bytes) = base64_decode(s) {
                    return Value::Tag(550, Box::new(Value::Bytes(bytes)));
                }
            }
            Value::Tag(550, Box::new(json_to_value(value)))
        }
        "bytes" => {
            if let Some(s) = value.as_str() {
                if let Ok(bytes) = base64_decode(s) {
                    return Value::Tag(560, Box::new(Value::Bytes(bytes)));
                }
            }
            Value::Tag(560, Box::new(json_to_value(value)))
        }
        "svn" => Value::Tag(552, Box::new(json_to_value(value))),
        "min-svn" => Value::Tag(553, Box::new(json_to_value(value))),
        "pkix-base64-key" => Value::Tag(554, Box::new(json_to_value(value))),
        "pkix-base64-cert" => Value::Tag(555, Box::new(json_to_value(value))),
        "pkix-base64-cert-path" => Value::Tag(556, Box::new(json_to_value(value))),
        "key-thumbprint" => Value::Tag(557, Box::new(json_to_value(value))),
        "cose-key" => Value::Tag(558, Box::new(json_to_value(value))),
        "cert-thumbprint" => Value::Tag(559, Box::new(json_to_value(value))),
        "cert-path-thumbprint" => Value::Tag(561, Box::new(json_to_value(value))),
        "pkix-asn1der-cert" => Value::Tag(562, Box::new(json_to_value(value))),
        "masked-raw-value" => Value::Tag(563, Box::new(json_to_value(value))),
        "int-range" => Value::Tag(564, Box::new(json_to_value(value))),
        _ => {
            // Unknown type-choice → preserve as-is in a map
            let entries = vec![
                (Value::Text("type".into()), Value::Text(type_name.into())),
                (Value::Text("value".into()), json_to_value(value)),
            ];
            Value::Map(entries)
        }
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn type_choice_json(type_name: &str, value: serde_json::Value) -> serde_json::Value {
    let mut obj = serde_json::Map::new();
    obj.insert("type".into(), serde_json::Value::String(type_name.into()));
    obj.insert("value".into(), value);
    serde_json::Value::Object(obj)
}

fn format_uuid(bytes: &[u8]) -> String {
    let hex = |s: &[u8]| -> String { s.iter().map(|b| format!("{:02x}", b)).collect() };
    format!(
        "{}-{}-{}-{}-{}",
        hex(&bytes[0..4]),
        hex(&bytes[4..6]),
        hex(&bytes[6..8]),
        hex(&bytes[8..10]),
        hex(&bytes[10..16])
    )
}

fn parse_uuid(s: &str) -> Option<Vec<u8>> {
    let hex: String = s.chars().filter(|c| *c != '-').collect();
    if hex.len() != 32 {
        return None;
    }
    let mut bytes = Vec::with_capacity(16);
    for i in (0..32).step_by(2) {
        bytes.push(u8::from_str_radix(&hex[i..i + 2], 16).ok()?);
    }
    Some(bytes)
}

fn base64_encode(bytes: &[u8]) -> String {
    // Simple base64 encoding (RFC 4648 standard alphabet)
    const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut result = String::new();
    for chunk in bytes.chunks(3) {
        let b0 = chunk[0] as u32;
        let b1 = if chunk.len() > 1 { chunk[1] as u32 } else { 0 };
        let b2 = if chunk.len() > 2 { chunk[2] as u32 } else { 0 };
        let n = (b0 << 16) | (b1 << 8) | b2;
        result.push(ALPHABET[((n >> 18) & 63) as usize] as char);
        result.push(ALPHABET[((n >> 12) & 63) as usize] as char);
        if chunk.len() > 1 {
            result.push(ALPHABET[((n >> 6) & 63) as usize] as char);
        } else {
            result.push('=');
        }
        if chunk.len() > 2 {
            result.push(ALPHABET[(n & 63) as usize] as char);
        } else {
            result.push('=');
        }
    }
    result
}

fn base64_decode(s: &str) -> Result<Vec<u8>, ()> {
    fn val(c: u8) -> Result<u32, ()> {
        match c {
            b'A'..=b'Z' => Ok((c - b'A') as u32),
            b'a'..=b'z' => Ok((c - b'a' + 26) as u32),
            b'0'..=b'9' => Ok((c - b'0' + 52) as u32),
            b'+' => Ok(62),
            b'/' => Ok(63),
            b'=' => Ok(0),
            _ => Err(()),
        }
    }
    let bytes: Vec<u8> = s.bytes().filter(|b| !b.is_ascii_whitespace()).collect();
    if !bytes.len().is_multiple_of(4) {
        return Err(());
    }
    let mut result = Vec::new();
    for chunk in bytes.chunks(4) {
        let a = val(chunk[0])?;
        let b = val(chunk[1])?;
        let c = val(chunk[2])?;
        let d = val(chunk[3])?;
        let n = (a << 18) | (b << 12) | (c << 6) | d;
        result.push((n >> 16) as u8);
        if chunk[2] != b'=' {
            result.push(((n >> 8) & 0xFF) as u8);
        }
        if chunk[3] != b'=' {
            result.push((n & 0xFF) as u8);
        }
    }
    Ok(result)
}
