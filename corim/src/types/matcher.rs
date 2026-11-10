//! Generic measurement matchers, draft-ietf-rats-corim-12 §5.1.4.9
//! and §8.3.4.4.5.11-12.
//!
//! ```text
//! bool-matcher = bool
//! integer-matcher = int / #6.565([int / null, int / null]) / #6.566([2* int])
//! float-matcher = float / #6.565([float / null, float / null]) / #6.566([2* float])
//! text-matcher = text / #6.566([2* text])
//! bytes-matcher = bytes / #6.566([2* bytes])
//! ```
//!
//! Sets and ranges express conditions, not observations. Set/range observations
//! never match. Integer and float domains are distinct. NaN is invalid, exact/set
//! infinities are allowed, and range bounds must be finite and ordered. At least
//! one bound must be present. Sets require two entries; duplicates are allowed.
//!
//! Human-readable serialization uses `type`/`value` objects for sets/ranges,
//! `integer` with a decimal string for integers outside i64, `float-bits` with
//! 16 hexadecimal digits for non-finite f64 values, and `byte-string` with hex
//! for bare byte strings. Use `crate::json` to read these representations back.
//!
//! ```
//! use corim::types::{MeasurementValuesMap, IntegerMatcher};
//! use corim::Validate;
//!
//! let mut values = MeasurementValuesMap::default();
//! values.r#bool = Some(false);
//! values.integer = Some(IntegerMatcher::Range {
//!         min: Some(1),
//!         max: Some(3),
//!     });
//! assert!(values.valid().is_ok());
//! assert!(values.integer.as_ref().unwrap().matches(
//!     &IntegerMatcher::Exact(2)
//! ));
//! ```

use super::tags::{TAG_MATCHER_SET, TAG_NUMERIC_RANGE};
use crate::cbor::value::Value;
use crate::nostd_prelude::*;
use crate::Validate;
use serde::{Deserialize, Serialize};

/// Exact boolean matcher, editor's draft (2026-10-07) Section 5.1.4.9.
pub type BoolMatcher = bool;

fn json_choice(kind: &str, value: Value) -> Value {
    Value::Map(vec![
        (Value::Text("type".into()), Value::Text(kind.into())),
        (Value::Text("value".into()), value),
    ])
}

fn human_scalar(value: Value) -> Value {
    match value {
        Value::Integer(integer) if i64::try_from(integer).is_err() => {
            json_choice("integer", Value::Text(integer.to_string()))
        }
        Value::Float(float) if !float.is_finite() => json_choice(
            "float-bits",
            Value::Text(format!("{:016x}", float.to_bits())),
        ),
        Value::Bytes(bytes) => json_choice(
            "byte-string",
            Value::Text(bytes.iter().map(|byte| format!("{byte:02x}")).collect()),
        ),
        value => value,
    }
}

fn valid_integer(value: i128, _bound: bool) -> Result<(), String> {
    if value < -1 - i128::from(u64::MAX) || value > i128::from(u64::MAX) {
        return Err("integer is outside the CBOR range (RFC 8949 §3.1)".into());
    }
    Ok(())
}

fn valid_float(value: f64, bound: bool) -> Result<(), String> {
    if value.is_nan() || (bound && !value.is_finite()) {
        return Err("float must not be NaN; range bounds must be finite".into());
    }
    Ok(())
}

macro_rules! numeric_matcher {
    ($name:ident, $type:ty, $variant:ident, $validate:ident, $range:literal, $set:literal, $doc:literal $(, $eq:ident)?) => {
        #[doc = $doc]
        #[derive(Clone, Debug, PartialEq $(, $eq)?)]
        #[non_exhaustive]
        pub enum $name {
            /// Bare assertion or exact condition, draft-12 §5.1.4.9.
            Exact($type),
            /// Inclusive condition; null is the only unbounded endpoint.
            Range {
                /// Inclusive lower bound.
                min: Option<$type>,
                /// Inclusive upper bound.
                max: Option<$type>,
            },
            /// Condition with at least two alternatives (duplicates allowed).
            Set(Vec<$type>),
        }

        impl $name {
            /// Whether an exact assertion satisfies this condition (draft-12 §8.3.4.4.5.11-12).
            pub fn matches(&self, observed: &Self) -> bool {
                if self.valid().is_err() || observed.valid().is_err() {
                    return false;
                }
                let Self::Exact(value) = observed else { return false; };
                match self {
                    Self::Exact(expected) => expected == value,
                    Self::Set(values) => values.contains(value),
                    Self::Range { min, max } =>
                        min.is_none_or(|min| *value >= min)
                            && max.is_none_or(|max| *value <= max),
                }
            }
        }

        impl Validate for $name {
            fn valid(&self) -> Result<(), String> {
                match self {
                    Self::Exact(value) => $validate(*value, false),
                    Self::Set(values) => {
                        if values.len() < 2 {
                            return Err("matcher set requires at least two entries".into());
                        }
                        for value in values { $validate(*value, false)?; }
                        Ok(())
                    }
                    Self::Range { min, max } => {
                        if min.is_none() && max.is_none() {
                            return Err("numeric range requires at least one bound".into());
                        }
                        for value in min.iter().chain(max.iter()) { $validate(*value, true)?; }
                        if matches!((min, max), (Some(min), Some(max)) if min > max) {
                            return Err("range minimum exceeds maximum".into());
                        }
                        Ok(())
                    }
                }
            }
        }

        impl Serialize for $name {
            fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
                self.valid().map_err(serde::ser::Error::custom)?;
                let human = serializer.is_human_readable();
                let scalar = |value| {
                    let value = Value::$variant(value);
                    if human { human_scalar(value) } else { value }
                };
                let value = match self {
                    Self::Exact(value) => scalar(*value),
                    Self::Range { min, max } => {
                        let bounds = Value::Array(vec![
                            min.map_or(Value::Null, scalar),
                            max.map_or(Value::Null, scalar),
                        ]);
                        if human { json_choice($range, bounds) }
                        else { Value::Tag(TAG_NUMERIC_RANGE, Box::new(bounds)) }
                    }
                    Self::Set(values) => {
                        let values = Value::Array(values.iter().copied().map(scalar).collect());
                        if human { json_choice($set, values) }
                        else { Value::Tag(TAG_MATCHER_SET, Box::new(values)) }
                    }
                };
                value.serialize(serializer)
            }
        }

        impl<'de> Deserialize<'de> for $name {
            fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
                let scalar = |value| match value {
                    Value::$variant(value) => Ok(value),
                    _ => Err(serde::de::Error::custom("wrong numeric matcher primitive")),
                };
                let parsed = match Value::deserialize(deserializer)? {
                    Value::$variant(value) => Self::Exact(value),
                    Value::Tag(TAG_NUMERIC_RANGE, inner) => {
                        let Value::Array(bounds) = *inner else {
                            return Err(serde::de::Error::custom("numeric range must be an array"));
                        };
                        let [min, max]: [Value; 2] = bounds.try_into().map_err(|_|
                            serde::de::Error::custom("numeric range requires two bounds"))?;
                        let bound = |value| match value {
                            Value::Null => Ok(None),
                            value => scalar(value).map(Some),
                        };
                        Self::Range { min: bound(min)?, max: bound(max)? }
                    }
                    Value::Tag(TAG_MATCHER_SET, inner) => {
                        let Value::Array(values) = *inner else {
                            return Err(serde::de::Error::custom("numeric set must be an array"));
                        };
                        Self::Set(values.into_iter().map(scalar).collect::<Result<_, D::Error>>()?)
                    }
                    _ => return Err(serde::de::Error::custom("unexpected numeric matcher type or tag")),
                };
                parsed.valid().map_err(serde::de::Error::custom)?;
                Ok(parsed)
            }
        }
    };
}

numeric_matcher!(
    IntegerMatcher,
    i128,
    Integer,
    valid_integer,
    "integer-range",
    "integer-set",
    "Integer condition or assertion, draft-ietf-rats-corim-12 §5.1.4.9 and §8.3.4.4.5.11.",
    Eq
);
numeric_matcher!(
    FloatMatcher,
    f64,
    Float,
    valid_float,
    "float-range",
    "float-set",
    "Float condition or assertion, draft-ietf-rats-corim-12 §5.1.4.9 and §8.3.4.4.5.12."
);

macro_rules! string_matcher {
    ($name:ident, $type:ty, $variant:ident, $json_set:literal, $doc:literal) => {
        #[doc = $doc]
        #[derive(Clone, Debug, PartialEq, Eq)]
        #[non_exhaustive]
        pub enum $name {
            /// Bare value, compared for exact equality.
            Exact($type),
            /// At least two alternatives, encoded with tag 566.
            Set(Vec<$type>),
        }
        impl $name {
            /// Test an exact observation; set observations never match (Sections 8.3.4.4.5.11-12).
            pub fn matches(&self, observed: &Self) -> bool {
                if self.valid().is_err() { return false; }
                let Self::Exact(value) = observed else { return false; };
                match self {
                    Self::Exact(expected) => expected == value,
                    Self::Set(values) => values.contains(value),
                }
            }
        }
        impl Validate for $name {
            fn valid(&self) -> Result<(), String> {
                if matches!(self, Self::Set(values) if values.len() < 2) {
                    return Err("matcher set requires at least two entries".into());
                }
                Ok(())
            }
        }
        impl Serialize for $name {
            fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
                self.valid().map_err(serde::ser::Error::custom)?;
                if serializer.is_human_readable() {
                    return match self {
                        Self::Exact(value) => human_scalar(Value::$variant(value.clone())),
                        Self::Set(values) => json_choice($json_set, Value::Array(values.iter().cloned().map(Value::$variant).map(human_scalar).collect())),
                    }.serialize(serializer);
                }
                match self {
                    Self::Exact(value) => Value::$variant(value.clone()),
                    Self::Set(values) => Value::Tag(TAG_MATCHER_SET, Box::new(Value::Array(values.iter().cloned().map(Value::$variant).collect()))),
                }.serialize(serializer)
            }
        }
        impl<'de> Deserialize<'de> for $name {
            fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
                let parsed = match Value::deserialize(deserializer)? {
                    Value::$variant(value) => Self::Exact(value),
                    Value::Tag(TAG_MATCHER_SET, inner) => {
                        let Value::Array(values) = *inner else { return Err(serde::de::Error::custom("matcher set must be an array")); };
                        Self::Set(values.into_iter().map(|value| match value {
                            Value::$variant(value) => Ok(value),
                            _ => Err(serde::de::Error::custom("wrong matcher set member type")),
                        }).collect::<Result<_, D::Error>>()?)
                    }
                    _ => return Err(serde::de::Error::custom("unexpected matcher type or tag")),
                };
                parsed.valid().map_err(serde::de::Error::custom)?;
                Ok(parsed)
            }
        }
    };
}

string_matcher!(
    TextMatcher,
    String,
    Text,
    "text-set",
    "Text condition or observation, editor's draft (2026-10-07) Section 5.1.4.9."
);
string_matcher!(
    BytesMatcher,
    Vec<u8>,
    Bytes,
    "bytes-set",
    "Byte-string condition or observation, editor's draft (2026-10-07) Section 5.1.4.9."
);
