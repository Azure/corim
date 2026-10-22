// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Lossless JSON representation of the RFC 8949 §3 CBOR data model.
//!
//! Null, booleans, text, and arrays are native JSON. All other nodes use
//! strict `type`/`value` wrappers: `integer` (decimal string), `float-bits`
//! (16 lowercase hex digits), `byte-string` (lowercase hex), `map` (ordered
//! arrays of key/value pairs), and `tag` (with an additional decimal-string
//! `tag` member). These library helpers do not parse the CLI's separate
//! readable, commented authoring format.
//!
//! Generic serialization uses CBOR-mode serde; opaque byte strings, including
//! COSE protected headers and embedded CBOR payloads, remain opaque.
//! Document strings are bounded by [`DEFAULT_MAX_JSON_BYTES`] on input and
//! output. Hex, escaping, wrappers, or pretty-printing can expand valid CBOR
//! past this bound; serialization then returns an error, never truncated JSON.

use crate::cbor;
use crate::error::{DecodeError, EncodeError};
mod parse;
mod string;
mod value_conv;

pub use parse::parse_json;
pub use value_conv::{json_to_value, value_to_json};

/// Default JSON document byte limit, matching CBOR input policy.
///
/// This is an implementation resource policy per RFC 8949 §10, not a wire
/// format constraint. The cap applies after JSON escaping and hex expansion.
pub const DEFAULT_MAX_JSON_BYTES: usize = cbor::DEFAULT_MAX_INPUT_BYTES;

/// Encode a type through CBOR-mode serde to lossless JSON (RFC 8949 §3).
/// Returns an error if expansion exceeds [`DEFAULT_MAX_JSON_BYTES`].
pub fn to_json<T: serde::Serialize>(value: &T) -> Result<String, EncodeError> {
    let value = cbor::value::to_value(value).map_err(EncodeError::Serialization)?;
    string::encode(&value_to_json(&value)?, false, DEFAULT_MAX_JSON_BYTES)
}

/// Encode a type through CBOR-mode serde to pretty lossless JSON.
/// Returns an error if expansion exceeds [`DEFAULT_MAX_JSON_BYTES`].
pub fn to_json_pretty<T: serde::Serialize>(value: &T) -> Result<String, EncodeError> {
    let value = cbor::value::to_value(value).map_err(EncodeError::Serialization)?;
    string::encode(&value_to_json(&value)?, true, DEFAULT_MAX_JSON_BYTES)
}

/// Decode strict lossless JSON with bounded parsing (RFC 8949 §10).
pub fn from_json<T: serde::de::DeserializeOwned>(text: &str) -> Result<T, DecodeError> {
    let value = json_to_value(&parse_json(text)?)?;
    cbor::value::from_value(&value).map_err(DecodeError::Deserialization)
}
