// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Lossless JSON representation of the RFC 8949 §3 CBOR data model.
//!
//! Null, booleans, text, and arrays are native JSON. All other nodes use
//! strict `type`/`value` wrappers: `integer` (decimal string), `float-bits`
//! (16 lowercase hex digits), `byte-string` (lowercase hex), `map` (ordered
//! arrays of key/value pairs), and `tag` (with an additional decimal-string
//! `tag` member). No semantic/prose-key JSON format is accepted.
//!
//! Generic serialization uses CBOR-mode serde; opaque byte strings, including
//! COSE protected headers and embedded CBOR payloads, remain opaque.

use crate::cbor;
use crate::error::{DecodeError, EncodeError};
mod parse;
mod value_conv;

pub use parse::parse_json;
pub use value_conv::{json_to_value, value_to_json};

/// Encode a type through CBOR-mode serde to lossless JSON (RFC 8949 §3).
pub fn to_json<T: serde::Serialize>(value: &T) -> Result<String, EncodeError> {
    let value = cbor::value::to_value(value).map_err(EncodeError::Serialization)?;
    serde_json::to_string(&value_to_json(&value)?)
        .map_err(|e| EncodeError::Serialization(e.to_string()))
}

/// Encode a type through CBOR-mode serde to pretty lossless JSON.
pub fn to_json_pretty<T: serde::Serialize>(value: &T) -> Result<String, EncodeError> {
    let value = cbor::value::to_value(value).map_err(EncodeError::Serialization)?;
    serde_json::to_string_pretty(&value_to_json(&value)?)
        .map_err(|e| EncodeError::Serialization(e.to_string()))
}

/// Decode strict lossless JSON with bounded parsing (RFC 8949 §10).
pub fn from_json<T: serde::de::DeserializeOwned>(text: &str) -> Result<T, DecodeError> {
    let value = json_to_value(&parse_json(text)?)?;
    cbor::value::from_value(&value).map_err(DecodeError::Deserialization)
}
