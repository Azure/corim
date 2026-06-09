// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Serde `Deserializer` that replays a [`Value`] tree.

use crate::cbor::value::Value;
#[allow(unused_imports)]
use crate::nostd_prelude::*;
use serde::de::{self, DeserializeSeed, MapAccess, SeqAccess, Visitor};
use serde::Deserialize;

/// Deserialize a `T` from a [`Value`].
pub fn from_value<T: for<'de> Deserialize<'de>>(val: Value) -> Result<T, String> {
    T::deserialize(ValueDeserializer(val)).map_err(|e| e.0)
}

#[derive(Debug)]
struct Error(String);

impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{}", self.0)
    }
}

#[cfg(feature = "std")]
impl std::error::Error for Error {}

// Compile-time regression guard: serde's `de::Error: Sized + StdError`
// supertrait is active whenever any crate in the dep graph enables
// `serde/std`. If this `Error` type only implements the trait under our own
// `feature = "std"`, a downstream `--no-default-features` build that
// nevertheless unifies `serde/std` will fail with `Error: StdError`
// unsatisfied. This assertion catches that regression at compile time in the
// `cargo build -p corim --no-default-features` CI step.
const _: fn() = || {
    fn assert_core_error<E: core::error::Error>() {}
    assert_core_error::<Error>();
};

impl de::Error for Error {
    fn custom<T: core::fmt::Display>(msg: T) -> Self {
        Error(msg.to_string())
    }
}

struct ValueDeserializer(Value);

impl<'de> de::Deserializer<'de> for ValueDeserializer {
    type Error = Error;

    fn deserialize_any<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, Error> {
        match self.0 {
            Value::Integer(n) => {
                if n >= 0 && n <= u64::MAX as i128 {
                    visitor.visit_u64(n as u64)
                } else if n >= i64::MIN as i128 {
                    visitor.visit_i64(n as i64)
                } else {
                    visitor.visit_i128(n)
                }
            }
            Value::Bytes(b) => visitor.visit_bytes(&b),
            Value::Text(t) => visitor.visit_string(t),
            Value::Array(arr) => visitor.visit_seq(SeqDeserializer {
                iter: arr.into_iter(),
            }),
            Value::Map(entries) => visitor.visit_map(MapDeserializer {
                iter: entries.into_iter(),
                pending_value: None,
            }),
            Value::Tag(tag, inner) => {
                // Present as a 2-element sequence [tag_number, inner_value].
                // The ValueVisitor in minimal_value_serde recognizes this as
                // a special 2-element seq where the first item is a u64,
                // producing Value::Tag. Other visitors (like Tagged<T>) see
                // a seq and handle it accordingly.
                visitor.visit_seq(TagSeqDeserializer {
                    tag: Some(tag),
                    inner: Some(*inner),
                })
            }
            Value::Bool(b) => visitor.visit_bool(b),
            Value::Null => visitor.visit_none(),
            Value::Float(f) => visitor.visit_f64(f),
        }
    }

    fn deserialize_option<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, Error> {
        match self.0 {
            Value::Null => visitor.visit_none(),
            other => visitor.visit_some(ValueDeserializer(other)),
        }
    }

    fn deserialize_newtype_struct<V: Visitor<'de>>(
        self,
        _name: &'static str,
        visitor: V,
    ) -> Result<V::Value, Error> {
        visitor.visit_newtype_struct(self)
    }

    fn deserialize_seq<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, Error> {
        match self.0 {
            Value::Array(arr) => visitor.visit_seq(SeqDeserializer {
                iter: arr.into_iter(),
            }),
            other => Err(Error(format!(
                "expected array, got {:?}",
                core::mem::discriminant(&other)
            ))),
        }
    }

    fn deserialize_tuple<V: Visitor<'de>>(
        self,
        _len: usize,
        visitor: V,
    ) -> Result<V::Value, Error> {
        self.deserialize_seq(visitor)
    }

    fn deserialize_tuple_struct<V: Visitor<'de>>(
        self,
        _name: &'static str,
        _len: usize,
        visitor: V,
    ) -> Result<V::Value, Error> {
        self.deserialize_seq(visitor)
    }

    fn deserialize_map<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, Error> {
        match self.0 {
            Value::Map(entries) => visitor.visit_map(MapDeserializer {
                iter: entries.into_iter(),
                pending_value: None,
            }),
            other => Err(Error(format!(
                "expected map, got {:?}",
                core::mem::discriminant(&other)
            ))),
        }
    }

    fn deserialize_struct<V: Visitor<'de>>(
        self,
        _name: &'static str,
        _fields: &'static [&'static str],
        visitor: V,
    ) -> Result<V::Value, Error> {
        self.deserialize_map(visitor)
    }

    fn deserialize_bytes<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, Error> {
        match self.0 {
            Value::Bytes(b) => visitor.visit_bytes(&b),
            _ => self.deserialize_any(visitor),
        }
    }

    fn deserialize_byte_buf<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, Error> {
        match self.0 {
            Value::Bytes(b) => visitor.visit_byte_buf(b),
            _ => self.deserialize_any(visitor),
        }
    }

    fn deserialize_string<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, Error> {
        self.deserialize_any(visitor)
    }

    fn deserialize_str<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, Error> {
        self.deserialize_any(visitor)
    }

    fn deserialize_ignored_any<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, Error> {
        visitor.visit_unit()
    }

    // Forward all other deserialize_* methods to deserialize_any
    serde::forward_to_deserialize_any! {
        bool i8 i16 i32 i64 i128 u8 u16 u32 u64 u128 f32 f64 char
        unit unit_struct enum identifier
    }
}

// ---------------------------------------------------------------------------
// Seq access
// ---------------------------------------------------------------------------

struct SeqDeserializer {
    iter: alloc::vec::IntoIter<Value>,
}

impl<'de> SeqAccess<'de> for SeqDeserializer {
    type Error = Error;

    fn next_element_seed<T: DeserializeSeed<'de>>(
        &mut self,
        seed: T,
    ) -> Result<Option<T::Value>, Error> {
        match self.iter.next() {
            Some(val) => seed.deserialize(ValueDeserializer(val)).map(Some),
            None => Ok(None),
        }
    }

    fn size_hint(&self) -> Option<usize> {
        let (lo, hi) = self.iter.size_hint();
        hi.or(Some(lo))
    }
}

// ---------------------------------------------------------------------------
// Map access
// ---------------------------------------------------------------------------

struct MapDeserializer {
    iter: alloc::vec::IntoIter<(Value, Value)>,
    pending_value: Option<Value>,
}

impl<'de> MapAccess<'de> for MapDeserializer {
    type Error = Error;

    fn next_key_seed<K: DeserializeSeed<'de>>(
        &mut self,
        seed: K,
    ) -> Result<Option<K::Value>, Error> {
        match self.iter.next() {
            Some((k, v)) => {
                self.pending_value = Some(v);
                seed.deserialize(ValueDeserializer(k)).map(Some)
            }
            None => Ok(None),
        }
    }

    fn next_value_seed<V: DeserializeSeed<'de>>(&mut self, seed: V) -> Result<V::Value, Error> {
        let val = self
            .pending_value
            .take()
            .ok_or_else(|| Error("value without key".into()))?;
        seed.deserialize(ValueDeserializer(val))
    }
}

// ---------------------------------------------------------------------------
// Tag as seq [tag_number, inner]
// ---------------------------------------------------------------------------

struct TagSeqDeserializer {
    tag: Option<u64>,
    inner: Option<Value>,
}

impl<'de> SeqAccess<'de> for TagSeqDeserializer {
    type Error = Error;

    fn next_element_seed<T: DeserializeSeed<'de>>(
        &mut self,
        seed: T,
    ) -> Result<Option<T::Value>, Error> {
        if let Some(tag) = self.tag.take() {
            return seed
                .deserialize(ValueDeserializer(Value::Integer(tag as i128)))
                .map(Some);
        }
        if let Some(inner) = self.inner.take() {
            return seed.deserialize(ValueDeserializer(inner)).map(Some);
        }
        Ok(None)
    }

    fn size_hint(&self) -> Option<usize> {
        // Sentinel value to distinguish tags from regular arrays.
        // The ValueVisitor in minimal_value_serde checks for this.
        Some(usize::MAX)
    }
}
