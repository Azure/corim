// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Minimal-backend serde impls for `Value` and `Tagged<T>`,
//! plus `serialize_tagged` / `serialize_tagged_bytes` helpers.
//!
//! These mirror the ciborium_value_serde API exactly so the rest of the
//! crate works unchanged.

use super::{Tagged, Value};
use crate::cbor::minimal_backend::value_de;
use crate::cbor::minimal_backend::value_ser;
#[allow(unused_imports)]
use crate::nostd_prelude::*;
use serde::de::{self, Deserializer};
use serde::ser::Serializer;
use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// Value serde — go through minimal_backend's value_ser/value_de
// ---------------------------------------------------------------------------

impl Serialize for Value {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        // Encode to CBOR bytes, then present as serde bytes
        // Actually this is wrong — we need to map Value → serde data model
        // directly, not to CBOR bytes. The serializer is the thing that
        // converts serde data model → CBOR bytes.
        //
        // For the minimal backend, the codec goes:
        //   T.serialize(ValueSerializer) → Value → encode_value → bytes
        //
        // So when Value itself is T, we need Value.serialize(ValueSerializer)
        // to produce... Value. That's circular.
        //
        // The solution: Value implements Serialize by mapping directly to
        // serde primitives. The ValueSerializer captures those into a new Value.
        // When the outer codec calls T.serialize(ValueSerializer), and T is
        // Value, the ValueSerializer produces a clone of the Value.
        match self {
            Value::Integer(n) => {
                if *n >= 0 {
                    if *n <= u64::MAX as i128 {
                        s.serialize_u64(*n as u64)
                    } else {
                        s.serialize_u128(*n as u128)
                    }
                } else if *n >= i64::MIN as i128 {
                    s.serialize_i64(*n as i64)
                } else {
                    s.serialize_i128(*n)
                }
            }
            Value::Bytes(b) => s.serialize_bytes(b),
            Value::Text(t) => s.serialize_str(t),
            Value::Array(arr) => {
                use serde::ser::SerializeSeq;
                let mut seq = s.serialize_seq(Some(arr.len()))?;
                for item in arr {
                    seq.serialize_element(item)?;
                }
                seq.end()
            }
            Value::Map(entries) => {
                use serde::ser::SerializeMap;
                let mut map = s.serialize_map(Some(entries.len()))?;
                for (k, v) in entries {
                    map.serialize_entry(k, v)?;
                }
                map.end()
            }
            Value::Tag(tag, inner) => {
                // Use a sentinel struct name so ValueSerializer can detect
                // this and produce Value::Tag instead of a flat array.
                use serde::ser::SerializeTupleStruct;
                let mut ts = s.serialize_tuple_struct("__cbor_tag", 2)?;
                ts.serialize_field(&(*tag as i128))?;
                ts.serialize_field(inner.as_ref())?;
                ts.end()
            }
            Value::Bool(b) => s.serialize_bool(*b),
            Value::Null => s.serialize_none(),
            Value::Float(f) => s.serialize_f64(*f),
        }
    }
}

impl<'de> Deserialize<'de> for Value {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        // For the minimal backend, Value goes through our ValueDeserializer
        // which presents the raw Value tree. Tags are presented as seqs
        // [tag_number, inner] by the ValueDeserializer. We detect this
        // pattern in visit_seq by checking if the SeqAccess is our
        // TagSeqDeserializer (via a size_hint marker).
        d.deserialize_any(ValueVisitor)
    }
}

struct ValueVisitor;

impl<'de> de::Visitor<'de> for ValueVisitor {
    type Value = Value;

    fn expecting(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("any CBOR value")
    }

    fn visit_bool<E: de::Error>(self, v: bool) -> Result<Value, E> {
        Ok(Value::Bool(v))
    }
    fn visit_i64<E: de::Error>(self, v: i64) -> Result<Value, E> {
        Ok(Value::Integer(v as i128))
    }
    fn visit_i128<E: de::Error>(self, v: i128) -> Result<Value, E> {
        Ok(Value::Integer(v))
    }
    fn visit_u64<E: de::Error>(self, v: u64) -> Result<Value, E> {
        Ok(Value::Integer(v as i128))
    }
    fn visit_u128<E: de::Error>(self, v: u128) -> Result<Value, E> {
        let n = i128::try_from(v).map_err(|_| E::custom("u128 value exceeds i128 range"))?;
        Ok(Value::Integer(n))
    }
    fn visit_f64<E: de::Error>(self, v: f64) -> Result<Value, E> {
        Ok(Value::Float(v))
    }
    fn visit_str<E: de::Error>(self, v: &str) -> Result<Value, E> {
        Ok(Value::Text(v.to_owned()))
    }
    fn visit_string<E: de::Error>(self, v: String) -> Result<Value, E> {
        Ok(Value::Text(v))
    }
    fn visit_bytes<E: de::Error>(self, v: &[u8]) -> Result<Value, E> {
        Ok(Value::Bytes(v.to_vec()))
    }
    fn visit_byte_buf<E: de::Error>(self, v: Vec<u8>) -> Result<Value, E> {
        Ok(Value::Bytes(v))
    }
    fn visit_none<E: de::Error>(self) -> Result<Value, E> {
        Ok(Value::Null)
    }
    fn visit_unit<E: de::Error>(self) -> Result<Value, E> {
        Ok(Value::Null)
    }

    fn visit_some<D: Deserializer<'de>>(self, d: D) -> Result<Value, D::Error> {
        Value::deserialize(d)
    }

    fn visit_seq<A: de::SeqAccess<'de>>(self, mut seq: A) -> Result<Value, A::Error> {
        // Use the size_hint to detect TagSeqDeserializer which returns
        // Some(usize::MAX) as a sentinel value.
        let is_tag = seq.size_hint() == Some(usize::MAX);

        let mut arr = Vec::new();
        while let Some(item) = seq.next_element::<Value>()? {
            arr.push(item);
        }

        if is_tag && arr.len() == 2 {
            let inner = arr
                .pop()
                .ok_or_else(|| de::Error::custom("tag sequence must have 2 elements"))?;
            let tag_val = arr
                .pop()
                .ok_or_else(|| de::Error::custom("tag sequence must have 2 elements"))?;
            if let Value::Integer(t) = tag_val {
                if let Ok(tag) = u64::try_from(t) {
                    return Ok(Value::Tag(tag, Box::new(inner)));
                }
                // Negative or oversized tag number — fall through to array
                return Ok(Value::Array(vec![Value::Integer(t), inner]));
            }
        }
        Ok(Value::Array(arr))
    }

    fn visit_map<A: de::MapAccess<'de>>(self, mut map: A) -> Result<Value, A::Error> {
        let mut entries = Vec::new();
        while let Some((k, v)) = map.next_entry::<Value, Value>()? {
            entries.push((k, v));
        }
        Ok(Value::Map(entries))
    }
}

// ---------------------------------------------------------------------------
// Tagged<T> serde
// ---------------------------------------------------------------------------

impl<T: Serialize> Serialize for Tagged<T> {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        // Convert inner T to Value, wrap in Tag, then serialize.
        // The Value::Tag variant's Serialize uses the __cbor_tag sentinel
        // so that ValueSerializer preserves the tag structure.
        let inner_value = value_ser::to_value(&self.value).map_err(serde::ser::Error::custom)?;
        let tagged = Value::Tag(self.tag, Box::new(inner_value));
        tagged.serialize(s)
    }
}

impl<'de, T: serde::de::DeserializeOwned> Deserialize<'de> for Tagged<T> {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        // Deserialize as Value, extract tag, deserialize inner
        let val = Value::deserialize(d)?;
        match val {
            Value::Tag(tag, inner) => {
                let value: T = value_de::from_value(*inner)
                    .map_err(|e| de::Error::custom(format!("inner value: {}", e)))?;
                Ok(Tagged { tag, value })
            }
            _ => Err(de::Error::custom("expected CBOR tag")),
        }
    }
}

// ---------------------------------------------------------------------------
// Helper functions (same API as ciborium_value_serde)
// ---------------------------------------------------------------------------

/// Serialize a value wrapped in a specific CBOR tag number.
pub fn serialize_tagged<T: Serialize, S: Serializer>(
    tag: u64,
    value: &T,
    s: S,
) -> Result<S::Ok, S::Error> {
    let inner_value = value_ser::to_value(value).map_err(serde::ser::Error::custom)?;
    let tagged = Value::Tag(tag, Box::new(inner_value));
    tagged.serialize(s)
}

/// Serialize bytes wrapped in a specific CBOR tag number.
pub fn serialize_tagged_bytes<S: Serializer>(
    tag: u64,
    bytes: &[u8],
    s: S,
) -> Result<S::Ok, S::Error> {
    let tagged = Value::Tag(tag, Box::new(Value::Bytes(bytes.to_vec())));
    tagged.serialize(s)
}
