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

/// Escape a CBOR text string for the quoted form used in diagnostic
/// notation (RFC 8949 §8): the quote and reverse solidus, the short forms
/// for backspace/formfeed/newline/return/tab, and `\uXXXX` for every other
/// Unicode control character (U+0000..U+001F, U+007F..U+009F) plus the
/// line and paragraph separators U+2028/U+2029.
///
/// Use this anywhere a text string is rendered inside quotes, so an
/// attacker-controlled value cannot inject a quote or a line break into a
/// single-line report.
pub fn escape_text(s: &str) -> String {
    use core::fmt::Write as _;
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\u{08}' => out.push_str("\\b"),
            '\u{0c}' => out.push_str("\\f"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            // Every remaining Unicode control character (Cc): C0 + DEL +
            // the C1 range, any of which can garble a terminal or log line.
            // U+2028/U+2029 are not Cc but still break lines in some
            // renderers and log viewers.
            c if c.is_control() || c == '\u{2028}' || c == '\u{2029}' => {
                let _ = write!(out, "\\u{:04x}", c as u32);
            }
            c => out.push(c),
        }
    }
    out
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
/// Checks CBOR integer range and default decode resource limits without
/// re-encoding, sorting maps, or discarding duplicate entries.
pub fn to_value<T: serde::Serialize>(value: &T) -> Result<Value, String> {
    let value = super::minimal_backend::value_ser::to_value(value)?;
    check_tree(&value)?;
    Ok(value)
}

/// Serialize a Rust type into a human-readable `Value` using serde.
///
/// Typed serializers may omit CBOR-only representation details while raw
/// [`Value`] tags remain intact for lossless conversion.
pub fn to_human_readable_value<T: serde::Serialize>(value: &T) -> Result<Value, String> {
    super::minimal_backend::value_ser::to_human_readable_value(value)
}

/// Deserialize a `Value` back into a Rust type using serde.
///
/// This is the last step in JSON decoding: `serde_json::Value → Value → T`.
/// Checks the entire tree before cloning or replay, including ignored fields,
/// under the same wire range and default resource limits as [`to_value`].
pub fn from_value<T: serde::de::DeserializeOwned>(value: &Value) -> Result<T, String> {
    check_tree(value)?;
    super::minimal_backend::value_de::from_value(value.clone())
}

/// Major-type argument for a CBOR integer, per RFC 8949 §3.1.
pub(crate) fn integer_argument(n: i128) -> Result<u64, String> {
    if n >= 0 {
        u64::try_from(n)
            .map_err(|_| "positive integer above 2^64-1 cannot be encoded in CBOR".into())
    } else {
        u64::try_from(-1_i128 - n)
            .map_err(|_| "negative integer below -(2^64) cannot be encoded in CBOR".into())
    }
}

// Check the hypothetical deterministic wire size without allocating encoded
// bytes or sorting map keys. Float encoding is binary64 in this backend.
fn check_tree(value: &Value) -> Result<(), String> {
    let limits = super::DecodeLimits::default();
    let mut budget = super::DecodeBudget::new(&limits).map_err(|e| e.to_string())?;
    let mut remaining_bytes = limits.max_input_bytes;
    check_node(value, 0, &mut budget, &mut remaining_bytes)
}

fn head_size(argument: u64) -> usize {
    if argument <= u64::from(super::constants::AI_MAX_INLINE) {
        1
    } else if argument <= u64::from(u8::MAX) {
        2
    } else if argument <= u64::from(u16::MAX) {
        3
    } else if argument <= u64::from(u32::MAX) {
        5
    } else {
        9
    }
}

fn check_node(
    value: &Value,
    depth: usize,
    budget: &mut super::DecodeBudget,
    remaining_bytes: &mut usize,
) -> Result<(), String> {
    budget.value().map_err(|e| e.to_string())?;
    let sized_head = |len: usize| -> Result<usize, String> {
        let argument = u64::try_from(len).map_err(|_| "CBOR length exceeds u64 range")?;
        Ok(head_size(argument))
    };
    let bytes = match value {
        Value::Integer(n) => Some(head_size(integer_argument(*n)?)),
        Value::Bytes(b) => sized_head(b.len())?.checked_add(b.len()),
        Value::Text(t) => sized_head(t.len())?.checked_add(t.len()),
        Value::Array(a) => {
            budget.container(depth).map_err(|e| e.to_string())?;
            budget
                .collection(a.len(), false)
                .map_err(|e| e.to_string())?;
            Some(sized_head(a.len())?)
        }
        Value::Map(m) => {
            budget.container(depth).map_err(|e| e.to_string())?;
            budget
                .collection(m.len(), true)
                .map_err(|e| e.to_string())?;
            Some(sized_head(m.len())?)
        }
        Value::Tag(tag, _) => {
            budget.container(depth).map_err(|e| e.to_string())?;
            Some(head_size(*tag))
        }
        Value::Float(_) => Some(9),
        Value::Bool(_) | Value::Null => Some(1),
    };
    let bytes = bytes.ok_or("CBOR encoded size exceeds usize range")?;
    *remaining_bytes = remaining_bytes.checked_sub(bytes).ok_or_else(|| {
        crate::error::DecodeError::LimitExceeded {
            resource: "input bytes",
            limit: budget.limits.max_input_bytes,
        }
        .to_string()
    })?;
    match value {
        Value::Array(a) => {
            for item in a {
                check_node(item, depth + 1, budget, remaining_bytes)?;
            }
        }
        Value::Map(m) => {
            for (key, value) in m {
                check_node(key, depth + 1, budget, remaining_bytes)?;
                check_node(value, depth + 1, budget, remaining_bytes)?;
            }
        }
        Value::Tag(_, inner) => check_node(inner, depth + 1, budget, remaining_bytes)?,
        _ => {}
    }
    Ok(())
}
