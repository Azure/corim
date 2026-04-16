// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Serde `Serializer` that captures output into a [`Value`] tree.

use crate::cbor::value::Value;
#[allow(unused_imports)]
use crate::nostd_prelude::*;
use serde::ser::{self, Serialize};

/// Serialize any `T: Serialize` into a [`Value`].
pub fn to_value<T: Serialize>(value: &T) -> Result<Value, String> {
    value.serialize(ValueSerializer).map_err(|e| e.0)
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

impl ser::Error for Error {
    fn custom<T: core::fmt::Display>(msg: T) -> Self {
        Error(msg.to_string())
    }
}

struct ValueSerializer;

impl ser::Serializer for ValueSerializer {
    type Ok = Value;
    type Error = Error;
    type SerializeSeq = SeqSerializer;
    type SerializeTuple = SeqSerializer;
    type SerializeTupleStruct = SeqSerializer;
    type SerializeTupleVariant = SeqSerializer;
    type SerializeMap = MapSerializer;
    type SerializeStruct = MapSerializer;
    type SerializeStructVariant = MapSerializer;

    fn serialize_bool(self, v: bool) -> Result<Value, Error> {
        Ok(Value::Bool(v))
    }
    fn serialize_i8(self, v: i8) -> Result<Value, Error> {
        Ok(Value::Integer(v as i128))
    }
    fn serialize_i16(self, v: i16) -> Result<Value, Error> {
        Ok(Value::Integer(v as i128))
    }
    fn serialize_i32(self, v: i32) -> Result<Value, Error> {
        Ok(Value::Integer(v as i128))
    }
    fn serialize_i64(self, v: i64) -> Result<Value, Error> {
        Ok(Value::Integer(v as i128))
    }
    fn serialize_i128(self, v: i128) -> Result<Value, Error> {
        Ok(Value::Integer(v))
    }
    fn serialize_u8(self, v: u8) -> Result<Value, Error> {
        Ok(Value::Integer(v as i128))
    }
    fn serialize_u16(self, v: u16) -> Result<Value, Error> {
        Ok(Value::Integer(v as i128))
    }
    fn serialize_u32(self, v: u32) -> Result<Value, Error> {
        Ok(Value::Integer(v as i128))
    }
    fn serialize_u64(self, v: u64) -> Result<Value, Error> {
        Ok(Value::Integer(v as i128))
    }
    fn serialize_u128(self, v: u128) -> Result<Value, Error> {
        let n = i128::try_from(v).map_err(|_| Error("u128 value exceeds i128 range".into()))?;
        Ok(Value::Integer(n))
    }
    fn serialize_f32(self, v: f32) -> Result<Value, Error> {
        Ok(Value::Float(v as f64))
    }
    fn serialize_f64(self, v: f64) -> Result<Value, Error> {
        Ok(Value::Float(v))
    }
    fn serialize_char(self, v: char) -> Result<Value, Error> {
        Ok(Value::Text(v.to_string()))
    }
    fn serialize_str(self, v: &str) -> Result<Value, Error> {
        Ok(Value::Text(v.to_owned()))
    }
    fn serialize_bytes(self, v: &[u8]) -> Result<Value, Error> {
        Ok(Value::Bytes(v.to_vec()))
    }
    fn serialize_none(self) -> Result<Value, Error> {
        Ok(Value::Null)
    }
    fn serialize_some<T: ?Sized + Serialize>(self, value: &T) -> Result<Value, Error> {
        value.serialize(self)
    }
    fn serialize_unit(self) -> Result<Value, Error> {
        Ok(Value::Null)
    }
    fn serialize_unit_struct(self, _name: &'static str) -> Result<Value, Error> {
        Ok(Value::Null)
    }
    fn serialize_unit_variant(
        self,
        _name: &'static str,
        idx: u32,
        _variant: &'static str,
    ) -> Result<Value, Error> {
        Ok(Value::Integer(idx as i128))
    }
    fn serialize_newtype_struct<T: ?Sized + Serialize>(
        self,
        _name: &'static str,
        value: &T,
    ) -> Result<Value, Error> {
        value.serialize(self)
    }
    fn serialize_newtype_variant<T: ?Sized + Serialize>(
        self,
        _name: &'static str,
        _idx: u32,
        _variant: &'static str,
        value: &T,
    ) -> Result<Value, Error> {
        value.serialize(self)
    }

    fn serialize_seq(self, len: Option<usize>) -> Result<SeqSerializer, Error> {
        Ok(SeqSerializer {
            items: Vec::with_capacity(len.unwrap_or(0)),
            tag_mode: false,
        })
    }
    fn serialize_tuple(self, len: usize) -> Result<SeqSerializer, Error> {
        Ok(SeqSerializer {
            items: Vec::with_capacity(len),
            tag_mode: false,
        })
    }
    fn serialize_tuple_struct(
        self,
        name: &'static str,
        len: usize,
    ) -> Result<SeqSerializer, Error> {
        Ok(SeqSerializer {
            items: Vec::with_capacity(len),
            tag_mode: name == "__cbor_tag",
        })
    }
    fn serialize_tuple_variant(
        self,
        _name: &'static str,
        _idx: u32,
        _variant: &'static str,
        len: usize,
    ) -> Result<SeqSerializer, Error> {
        Ok(SeqSerializer {
            items: Vec::with_capacity(len),
            tag_mode: false,
        })
    }
    fn serialize_map(self, len: Option<usize>) -> Result<MapSerializer, Error> {
        Ok(MapSerializer {
            entries: Vec::with_capacity(len.unwrap_or(0)),
            pending_key: None,
        })
    }
    fn serialize_struct(self, _name: &'static str, len: usize) -> Result<MapSerializer, Error> {
        Ok(MapSerializer {
            entries: Vec::with_capacity(len),
            pending_key: None,
        })
    }
    fn serialize_struct_variant(
        self,
        _name: &'static str,
        _idx: u32,
        _variant: &'static str,
        len: usize,
    ) -> Result<MapSerializer, Error> {
        Ok(MapSerializer {
            entries: Vec::with_capacity(len),
            pending_key: None,
        })
    }
}

struct SeqSerializer {
    items: Vec<Value>,
    tag_mode: bool,
}

impl ser::SerializeSeq for SeqSerializer {
    type Ok = Value;
    type Error = Error;
    fn serialize_element<T: ?Sized + Serialize>(&mut self, value: &T) -> Result<(), Error> {
        self.items.push(value.serialize(ValueSerializer)?);
        Ok(())
    }
    fn end(self) -> Result<Value, Error> {
        Ok(Value::Array(self.items))
    }
}

impl ser::SerializeTuple for SeqSerializer {
    type Ok = Value;
    type Error = Error;
    fn serialize_element<T: ?Sized + Serialize>(&mut self, value: &T) -> Result<(), Error> {
        ser::SerializeSeq::serialize_element(self, value)
    }
    fn end(self) -> Result<Value, Error> {
        ser::SerializeSeq::end(self)
    }
}

impl ser::SerializeTupleStruct for SeqSerializer {
    type Ok = Value;
    type Error = Error;
    fn serialize_field<T: ?Sized + Serialize>(&mut self, value: &T) -> Result<(), Error> {
        ser::SerializeSeq::serialize_element(self, value)
    }
    fn end(self) -> Result<Value, Error> {
        if self.tag_mode && self.items.len() == 2 {
            let mut items = self.items;
            let inner = items.pop().unwrap();
            let tag_val = items.pop().unwrap();
            if let Value::Integer(n) = tag_val {
                if let Ok(tag) = u64::try_from(n) {
                    return Ok(Value::Tag(tag, Box::new(inner)));
                }
                // Negative or oversized — not a valid tag, fall through to array
                return Ok(Value::Array(vec![Value::Integer(n), inner]));
            }
            // Not a valid tag pattern — fall through to array
            return Ok(Value::Array(vec![tag_val, inner]));
        }
        Ok(Value::Array(self.items))
    }
}

impl ser::SerializeTupleVariant for SeqSerializer {
    type Ok = Value;
    type Error = Error;
    fn serialize_field<T: ?Sized + Serialize>(&mut self, value: &T) -> Result<(), Error> {
        ser::SerializeSeq::serialize_element(self, value)
    }
    fn end(self) -> Result<Value, Error> {
        ser::SerializeSeq::end(self)
    }
}

struct MapSerializer {
    entries: Vec<(Value, Value)>,
    pending_key: Option<Value>,
}

impl ser::SerializeMap for MapSerializer {
    type Ok = Value;
    type Error = Error;
    fn serialize_key<T: ?Sized + Serialize>(&mut self, key: &T) -> Result<(), Error> {
        self.pending_key = Some(key.serialize(ValueSerializer)?);
        Ok(())
    }
    fn serialize_value<T: ?Sized + Serialize>(&mut self, value: &T) -> Result<(), Error> {
        let k = self
            .pending_key
            .take()
            .ok_or_else(|| Error("key missing".into()))?;
        self.entries.push((k, value.serialize(ValueSerializer)?));
        Ok(())
    }
    fn end(self) -> Result<Value, Error> {
        Ok(Value::Map(self.entries))
    }
}

impl ser::SerializeStruct for MapSerializer {
    type Ok = Value;
    type Error = Error;
    fn serialize_field<T: ?Sized + Serialize>(
        &mut self,
        key: &'static str,
        value: &T,
    ) -> Result<(), Error> {
        self.entries.push((
            Value::Text(key.to_owned()),
            value.serialize(ValueSerializer)?,
        ));
        Ok(())
    }
    fn end(self) -> Result<Value, Error> {
        Ok(Value::Map(self.entries))
    }
}

impl ser::SerializeStructVariant for MapSerializer {
    type Ok = Value;
    type Error = Error;
    fn serialize_field<T: ?Sized + Serialize>(
        &mut self,
        key: &'static str,
        value: &T,
    ) -> Result<(), Error> {
        ser::SerializeStruct::serialize_field(self, key, value)
    }
    fn end(self) -> Result<Value, Error> {
        ser::SerializeStruct::end(self)
    }
}
