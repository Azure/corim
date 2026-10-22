// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use crate::error::DecodeError;
use serde::de::{self, DeserializeSeed, MapAccess, SeqAccess, Visitor};
use serde_json::{Map, Value};
use std::fmt;

// A CBOR map adds three JSON containers: wrapper, entries, and entry pair.
const MAX_JSON_DEPTH: usize = 3 * 64 + 4;
const MAX_JSON_BYTES: usize = 64 * 1024 * 1024;
const MAX_JSON_NODES: usize = 8_000_000;

/// Parse JSON with bounded depth, input size, and node count (RFC 8949 §10).
///
/// The bound accounts for wrapper expansion of 64-deep CBOR maps; serde_json's
/// default 128-level limit is too small. Its recursion limit is disabled only
/// behind this independently bounded visitor. Duplicate object members are
/// rejected rather than silently overwriting wrapper fields.
pub fn parse_json(text: &str) -> Result<Value, DecodeError> {
    if text.len() > MAX_JSON_BYTES {
        return Err(DecodeError::Deserialization(
            "JSON input exceeds 64 MiB".into(),
        ));
    }
    let mut remaining = MAX_JSON_NODES;
    let mut parser = serde_json::Deserializer::from_str(text);
    parser.disable_recursion_limit();
    let value = Seed {
        depth: 0,
        remaining: &mut remaining,
    }
    .deserialize(&mut parser)
    .map_err(|e| DecodeError::Deserialization(e.to_string()))?;
    parser
        .end()
        .map_err(|e| DecodeError::Deserialization(e.to_string()))?;
    Ok(value)
}

struct Seed<'a> {
    depth: usize,
    remaining: &'a mut usize,
}

impl<'de> DeserializeSeed<'de> for Seed<'_> {
    type Value = Value;
    fn deserialize<D: de::Deserializer<'de>>(self, d: D) -> Result<Value, D::Error> {
        if self.depth > MAX_JSON_DEPTH {
            return Err(de::Error::custom("JSON nesting limit exceeded"));
        }
        *self.remaining = self
            .remaining
            .checked_sub(1)
            .ok_or_else(|| de::Error::custom("JSON node budget exceeded"))?;
        d.deserialize_any(self)
    }
}

impl<'de> Visitor<'de> for Seed<'_> {
    type Value = Value;
    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("bounded JSON value")
    }
    fn visit_unit<E: de::Error>(self) -> Result<Value, E> {
        Ok(Value::Null)
    }
    fn visit_bool<E: de::Error>(self, b: bool) -> Result<Value, E> {
        Ok(Value::Bool(b))
    }
    fn visit_i64<E: de::Error>(self, n: i64) -> Result<Value, E> {
        Ok(Value::from(n))
    }
    fn visit_u64<E: de::Error>(self, n: u64) -> Result<Value, E> {
        Ok(Value::from(n))
    }
    fn visit_f64<E: de::Error>(self, n: f64) -> Result<Value, E> {
        serde_json::Number::from_f64(n)
            .map(Value::Number)
            .ok_or_else(|| E::custom("invalid JSON number"))
    }
    fn visit_str<E: de::Error>(self, s: &str) -> Result<Value, E> {
        Ok(Value::String(s.into()))
    }
    fn visit_string<E: de::Error>(self, s: String) -> Result<Value, E> {
        Ok(Value::String(s))
    }
    fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Value, A::Error> {
        let mut values = Vec::new();
        while let Some(value) = seq.next_element_seed(Seed {
            depth: self.depth + 1,
            remaining: self.remaining,
        })? {
            values.push(value);
        }
        Ok(Value::Array(values))
    }
    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Value, A::Error> {
        let mut values = Map::new();
        while let Some(key) = map.next_key::<String>()? {
            if values.contains_key(&key) {
                return Err(de::Error::custom("duplicate JSON object member"));
            }
            let value = map.next_value_seed(Seed {
                depth: self.depth + 1,
                remaining: self.remaining,
            })?;
            values.insert(key, value);
        }
        Ok(Value::Object(values))
    }
}
