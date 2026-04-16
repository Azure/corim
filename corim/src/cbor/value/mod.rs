// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Backend-agnostic CBOR value types.
//!
//! This module provides a `Value` enum and `Tagged<T>` wrapper that abstract
//! over the underlying CBOR library. All type-choice serde impls in `types/`
//! use these types instead of importing `ciborium` directly.
//!
//! When switching CBOR backends, only this module (and the backend impl in
//! `cbor/ciborium_backend.rs`) need to change — the rest of the crate is
//! unaffected.

// ---------------------------------------------------------------------------
// Value — dynamic CBOR representation
// ---------------------------------------------------------------------------

/// Backend-agnostic dynamic CBOR value.
///
/// Mirrors the common CBOR data model. Used in custom `Serialize`/`Deserialize`
/// impls for type-choice enums that need to inspect CBOR tags at runtime.
#[allow(unused_imports)]
use crate::nostd_prelude::*;
#[derive(Clone, Debug, PartialEq)]
pub enum Value {
    /// Unsigned or negative integer.
    Integer(i128),
    /// Byte string.
    Bytes(Vec<u8>),
    /// UTF-8 text string.
    Text(String),
    /// Ordered array.
    Array(Vec<Value>),
    /// Ordered map (preserves insertion order).
    Map(Vec<(Value, Value)>),
    /// CBOR semantic tag wrapping an inner value.
    Tag(u64, Box<Value>),
    /// Boolean.
    Bool(bool),
    /// Null.
    Null,
    /// IEEE 754 float.
    Float(f64),
}

impl Value {
    /// Try to extract as integer.
    pub fn into_integer(self) -> Option<i128> {
        match self {
            Value::Integer(n) => Some(n),
            _ => None,
        }
    }

    /// Try to extract as bytes.
    pub fn into_bytes(self) -> Option<Vec<u8>> {
        match self {
            Value::Bytes(b) => Some(b),
            _ => None,
        }
    }

    /// Try to extract as text.
    pub fn into_text(self) -> Option<String> {
        match self {
            Value::Text(t) => Some(t),
            _ => None,
        }
    }

    /// Try to extract as array.
    pub fn into_array(self) -> Option<Vec<Value>> {
        match self {
            Value::Array(a) => Some(a),
            _ => None,
        }
    }

    /// Try to unwrap a tag, returning `(tag_number, inner_value)`.
    pub fn into_tag(self) -> Option<(u64, Value)> {
        match self {
            Value::Tag(t, v) => Some((t, *v)),
            _ => None,
        }
    }
}

// ---------------------------------------------------------------------------
// Serde for Value — delegates to the active backend
// ---------------------------------------------------------------------------

// The Serialize/Deserialize impls for Value convert to/from the backend's
// native value type. These are implemented in the backend module.

mod minimal_value_serde;
pub use minimal_value_serde::*;

// ---------------------------------------------------------------------------
// Tagged<T> — CBOR semantic tag wrapper
// ---------------------------------------------------------------------------

/// A value wrapped in a CBOR semantic tag.
///
/// This is the backend-agnostic equivalent of `ciborium::tag::Required`.
/// It requires a specific tag number on deserialization and always emits it
/// on serialization.
#[derive(Clone, Debug, PartialEq)]
pub struct Tagged<T> {
    pub tag: u64,
    pub value: T,
}

impl<T> Tagged<T> {
    pub fn new(tag: u64, value: T) -> Self {
        Self { tag, value }
    }
}

// Serialize/Deserialize for Tagged<T> are in the backend-specific module.

// ---------------------------------------------------------------------------
// Value conversion helpers (for JSON bridge)
// ---------------------------------------------------------------------------

/// Serialize a Rust type into a `Value` using serde.
///
/// This is the first step in JSON encoding: `T → Value → serde_json::Value`.
pub fn to_value<T: serde::Serialize>(value: &T) -> Result<Value, String> {
    // Use our minimal backend serializer to get a Value
    let bytes = crate::cbor::encode(value).map_err(|e| e.to_string())?;
    let val: Value = crate::cbor::decode(&bytes).map_err(|e| e.to_string())?;
    Ok(val)
}

/// Deserialize a `Value` back into a Rust type using serde.
///
/// This is the last step in JSON decoding: `serde_json::Value → Value → T`.
pub fn from_value<T: serde::de::DeserializeOwned>(value: &Value) -> Result<T, String> {
    // Encode the Value to CBOR bytes, then decode into T
    let bytes = crate::cbor::encode(value).map_err(|e| e.to_string())?;
    crate::cbor::decode(&bytes).map_err(|e| e.to_string())
}
