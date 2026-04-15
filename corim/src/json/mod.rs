// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! JSON serialization for CoRIM/CoMID types.
//!
//! This module provides `to_json` / `from_json` functions that convert between
//! Rust types and JSON using string-key format compatible with the CoRIM
//! JSON representation.
//!
//! # Architecture
//!
//! Our types implement `serde::Serialize`/`Deserialize` with integer keys (for
//! CBOR). For JSON, we:
//! 1. Serialize to `cbor::value::Value` (integer-keyed maps)
//! 2. Convert `Value` → `serde_json::Value` using per-type key mapping tables
//! 3. Reverse for deserialization
//!
//! This avoids duplicating `Serialize`/`Deserialize` impls.
//!
//! # Feature gate
//!
//! This module is only available with the `json` feature enabled.
//!
//! ```toml
//! [dependencies]
//! corim = { version = "0.1", features = ["json"] }
//! ```

mod key_maps;
mod value_conv;

use crate::cbor;
use crate::error::{DecodeError, EncodeError};
use serde::de::DeserializeOwned;
use serde::Serialize;
use serde_json;

pub use value_conv::{json_to_value, value_to_json};

/// Encode a CoRIM/CoMID type to a JSON string.
///
/// Serializes to `cbor::value::Value` first, then converts to JSON using
/// the RFC-specified string key names.
///
/// # Example
///
/// ```rust
/// use corim::types::environment::ClassMap;
/// let class = ClassMap::new("ACME", "Widget");
/// let json = corim::json::to_json(&class).unwrap();
/// // Keys 0-30 use integer-as-string (context-dependent); keys 31+ use names
/// assert!(json.contains("ACME"));
/// assert!(json.contains("Widget"));
/// ```
pub fn to_json<T: Serialize>(value: &T) -> Result<String, EncodeError> {
    // Serialize to our Value intermediate
    let cbor_value = cbor::value::to_value(value)
        .map_err(|e| EncodeError::Serialization(format!("to_value: {e}")))?;
    // Convert to JSON value with string keys
    let json_value = value_to_json(&cbor_value);
    // Serialize to string
    serde_json::to_string(&json_value).map_err(|e| EncodeError::Serialization(format!("json: {e}")))
}

/// Encode a CoRIM/CoMID type to a pretty-printed JSON string.
pub fn to_json_pretty<T: Serialize>(value: &T) -> Result<String, EncodeError> {
    let cbor_value = cbor::value::to_value(value)
        .map_err(|e| EncodeError::Serialization(format!("to_value: {e}")))?;
    let json_value = value_to_json(&cbor_value);
    serde_json::to_string_pretty(&json_value)
        .map_err(|e| EncodeError::Serialization(format!("json: {e}")))
}

/// Decode a CoRIM/CoMID type from a JSON string.
///
/// Parses the JSON, converts string keys back to integer keys, then
/// deserializes into the target type.
pub fn from_json<T: DeserializeOwned>(json_str: &str) -> Result<T, DecodeError> {
    let json_value: serde_json::Value = serde_json::from_str(json_str)
        .map_err(|e| DecodeError::Deserialization(format!("json parse: {e}")))?;
    let cbor_value = json_to_value(&json_value);
    cbor::value::from_value(&cbor_value)
        .map_err(|e| DecodeError::Deserialization(format!("from_value: {e}")))
}
