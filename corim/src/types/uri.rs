// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Shared CBOR encoding for the CDDL `uri` type.

use crate::cbor::value::Value;
use crate::nostd_prelude::*;

use super::tags::TAG_URI;

pub(crate) fn uri_value(uri: &str) -> Value {
    Value::Tag(TAG_URI, Box::new(Value::Text(uri.into())))
}

pub(crate) struct UriRef<'a>(pub(crate) &'a str);

impl serde::Serialize for UriRef<'_> {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        if serializer.is_human_readable() {
            serializer.serialize_str(self.0)
        } else {
            uri_value(self.0).serialize(serializer)
        }
    }
}

pub(crate) fn deserialize_uri<E: serde::de::Error>(value: Value) -> Result<String, E> {
    match value {
        Value::Tag(TAG_URI, inner) => match *inner {
            Value::Text(uri) => Ok(uri),
            other => Err(E::custom(format!(
                "URI tag #6.{TAG_URI} must wrap text, found {}",
                value_kind(&other)
            ))),
        },
        // Decode-only compatibility for documents emitted by older versions
        // of this crate and other producers that interpreted `uri` as `tstr`.
        Value::Text(uri) => Ok(uri),
        other => Err(E::custom(format!(
            "expected URI tag #6.{TAG_URI}(text), found {}",
            value_kind(&other)
        ))),
    }
}

fn value_kind(value: &Value) -> &'static str {
    match value {
        Value::Integer(_) => "integer",
        Value::Bytes(_) => "bytes",
        Value::Text(_) => "text",
        Value::Array(_) => "array",
        Value::Map(_) => "map",
        Value::Tag(_, _) => "tag",
        Value::Bool(_) => "bool",
        Value::Null => "null",
        Value::Float(_) => "float",
    }
}
