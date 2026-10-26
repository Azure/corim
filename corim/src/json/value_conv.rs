// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use crate::cbor::value::Value;
use crate::error::{DecodeError, EncodeError};
use crate::nostd_prelude::*;
use serde_json::{json, Value as Json};

const MAX_DEPTH: usize = 64;
const MAX_VALUES: usize = 1_000_000;
const MAX_SCALAR_BYTES: usize = 16 * 1024 * 1024;
const MIN_INTEGER: i128 = -(1_i128 << 64);
const MAX_INTEGER: i128 = u64::MAX as i128;

struct Budget {
    values: usize,
    bytes: usize,
}

impl Budget {
    fn new() -> Self {
        Self {
            values: MAX_VALUES,
            bytes: MAX_SCALAR_BYTES,
        }
    }

    fn node(&mut self, depth: usize, container: bool) -> Result<(), String> {
        if depth > MAX_DEPTH || (container && depth == MAX_DEPTH) {
            return Err("lossless JSON CBOR nesting exceeds 64".into());
        }
        self.values = self.values.checked_sub(1).ok_or("value budget exceeded")?;
        Ok(())
    }

    fn bytes(&mut self, count: usize) -> Result<(), String> {
        self.bytes = self
            .bytes
            .checked_sub(count)
            .ok_or("scalar byte budget exceeded")?;
        Ok(())
    }
}

fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8] = b"0123456789abcdef";
    let mut result = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        result.push(char::from(DIGITS[usize::from(byte >> 4)]));
        result.push(char::from(DIGITS[usize::from(byte & 15)]));
    }
    result
}

fn unhex(text: &str) -> Result<Vec<u8>, String> {
    if text.len() % 2 != 0
        || !text
            .bytes()
            .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
    {
        return Err("expected even-length lowercase hexadecimal".into());
    }
    text.as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            let digit = |c: u8| if c <= b'9' { c - b'0' } else { c - b'a' + 10 };
            Ok(digit(pair[0]) * 16 + digit(pair[1]))
        })
        .collect()
}

fn integer(text: &str) -> Result<i128, String> {
    let n: i128 = text.parse().map_err(|_| "invalid decimal integer")?;
    if n.to_string() != text || !(MIN_INTEGER..=MAX_INTEGER).contains(&n) {
        return Err("expected canonical decimal CBOR integer in [-2^64, 2^64-1]".into());
    }
    Ok(n)
}

/// Encode the RFC 8949 §3 data model without JSON key coercion or float loss.
///
/// Maps are ordered entry arrays, integers are decimal strings, byte strings
/// are lowercase hex, and every float retains its exact IEEE 754 binary64 bits.
/// Values outside CBOR integer, depth, node, or scalar-byte limits are rejected.
pub fn value_to_json(value: &Value) -> Result<Json, EncodeError> {
    encode(value, 0, &mut Budget::new()).map_err(EncodeError::Serialization)
}

fn encode(value: &Value, depth: usize, budget: &mut Budget) -> Result<Json, String> {
    budget.node(
        depth,
        matches!(value, Value::Array(_) | Value::Map(_) | Value::Tag(..)),
    )?;
    Ok(match value {
        Value::Null => Json::Null,
        Value::Bool(b) => Json::Bool(*b),
        Value::Text(s) => {
            budget.bytes(s.len())?;
            Json::String(s.clone())
        }
        Value::Integer(n) => {
            if !(MIN_INTEGER..=MAX_INTEGER).contains(n) {
                return Err("integer outside RFC 8949 §3 CBOR range".into());
            }
            json!({"type": "integer", "value": n.to_string()})
        }
        Value::Float(f) => json!({"type": "float-bits", "value": format!("{:016x}", f.to_bits())}),
        Value::Bytes(b) => {
            budget.bytes(b.len())?;
            json!({"type": "byte-string", "value": hex(b)})
        }
        Value::Array(a) => Json::Array(
            a.iter()
                .map(|v| encode(v, depth + 1, budget))
                .collect::<Result<_, _>>()?,
        ),
        Value::Map(m) => {
            let entries = m
                .iter()
                .map(|(k, v)| {
                    Ok(Json::Array(vec![
                        encode(k, depth + 1, budget)?,
                        encode(v, depth + 1, budget)?,
                    ]))
                })
                .collect::<Result<Vec<_>, String>>()?;
            json!({"type": "map", "value": entries})
        }
        Value::Tag(tag, inner) => json!({
            "type": "tag", "tag": tag.to_string(), "value": encode(inner, depth + 1, budget)?
        }),
    })
}

/// Decode only the lossless JSON contract, with RFC 8949 §10 resource bounds.
///
/// Untyped JSON numbers and arbitrary objects (including old prose templates)
/// are rejected. Wrapper members must match exactly; decimal and hex strings
/// must be canonical. Maps preserve order, key types, and duplicate entries.
pub fn json_to_value(value: &Json) -> Result<Value, DecodeError> {
    decode(value, 0, &mut Budget::new()).map_err(DecodeError::Deserialization)
}

fn decode(value: &Json, depth: usize, budget: &mut Budget) -> Result<Value, String> {
    let kind = value.get("type").and_then(Json::as_str);
    budget.node(
        depth,
        value.is_array() || matches!(kind, Some("map" | "tag")),
    )?;
    Ok(match value {
        Json::Null => Value::Null,
        Json::Bool(b) => Value::Bool(*b),
        Json::String(s) => {
            budget.bytes(s.len())?;
            Value::Text(s.clone())
        }
        Json::Array(a) => Value::Array(
            a.iter()
                .map(|v| decode(v, depth + 1, budget))
                .collect::<Result<_, _>>()?,
        ),
        Json::Object(o) => {
            let kind = kind.ok_or("expected lossless JSON wrapper type")?;
            let expected = if kind == "tag" { 3 } else { 2 };
            if o.len() != expected
                || !o.contains_key("value")
                || (kind == "tag" && !o.contains_key("tag"))
            {
                return Err("unexpected or missing lossless JSON wrapper members".into());
            }
            let v = &o["value"];
            let text = || {
                v.as_str()
                    .ok_or_else(|| "expected wrapper string value".to_string())
            };
            match kind {
                "integer" => Value::Integer(integer(text()?)?),
                "float-bits" => {
                    let s = text()?;
                    if s.len() != 16 {
                        return Err("float-bits requires exactly 16 lowercase hex digits".into());
                    }
                    let bytes: [u8; 8] = unhex(s)?.try_into().map_err(|_| "invalid float bits")?;
                    Value::Float(f64::from_bits(u64::from_be_bytes(bytes)))
                }
                "byte-string" => {
                    let s = text()?;
                    budget.bytes(s.len() / 2)?;
                    Value::Bytes(unhex(s)?)
                }
                "tag" => {
                    let s = o["tag"].as_str().ok_or("expected decimal string tag")?;
                    let n = integer(s)?;
                    let tag = u64::try_from(n).map_err(|_| "tag outside u64 range")?;
                    Value::Tag(tag, Box::new(decode(v, depth + 1, budget)?))
                }
                "map" => {
                    let entries = v.as_array().ok_or("map value must be an entry array")?;
                    let map = entries
                        .iter()
                        .map(|entry| {
                            let pair = entry
                                .as_array()
                                .filter(|a| a.len() == 2)
                                .ok_or("map entry must be a pair")?;
                            Ok((
                                decode(&pair[0], depth + 1, budget)?,
                                decode(&pair[1], depth + 1, budget)?,
                            ))
                        })
                        .collect::<Result<_, String>>()?;
                    Value::Map(map)
                }
                _ => return Err(format!("unknown lossless JSON wrapper type: {kind}")),
            }
        }
        _ => return Err("JSON numbers must use integer or float-bits wrappers".into()),
    })
}
