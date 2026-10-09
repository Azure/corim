//! Generic measurement matchers from the CoRIM editor's draft (2026-10-07)
//! Sections 5.1.4.9 and 8.3.4.4.5.10-12.
//!
//! ```text
//! bool-matcher = bool
//! number-matcher = number / #6.565([number / null, number / null]) / #6.566([2* number])
//! text-matcher = text / #6.566([2* text])
//! bytes-matcher = bytes / #6.566([2* bytes])
//! ```
//!
//! Sets and ranges express conditions, not observations. Set/range observations
//! never match. Numeric comparisons are mathematical across integer/float types;
//! NaN never matches, infinities compare normally, and range bounds cannot be NaN
//! or reversed. Sets require at least two entries (duplicates are not removed).
//!
//! Human-readable serialization uses `type`/`value` objects for sets/ranges,
//! `integer` with a decimal string for integers outside i64, `float-bits` with
//! 16 hexadecimal digits for non-finite f64 values, and `byte-string` with hex
//! for bare byte strings. Use `crate::json` to read these representations back.
//!
//! ```
//! use corim::types::{MeasurementValuesMap, Number, NumberMatcher};
//! use corim::Validate;
//!
//! let values = MeasurementValuesMap {
//!     r#bool: Some(false),
//!     number: Some(NumberMatcher::Range {
//!         min: Some(Number::Int(1)),
//!         max: Some(Number::Float(3.5)),
//!     }),
//!     ..Default::default()
//! };
//! assert!(values.valid().is_ok());
//! assert!(values.number.as_ref().unwrap().matches(
//!     &NumberMatcher::Exact(Number::Float(2.5))
//! ));
//! ```

use super::tags::{TAG_MATCHER_SET, TAG_NUMBER_RANGE};
use crate::cbor::value::Value;
use crate::nostd_prelude::*;
use crate::Validate;
use core::cmp::Ordering;
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

/// A CBOR integer or IEEE 754 number (Section 5.1.4.9). Integer identity is preserved.
#[derive(Clone, Copy, Debug, PartialEq)]
#[non_exhaustive]
pub enum Number {
    /// CBOR integer, from -2^64 through 2^64-1 (RFC 8949 Section 3.1).
    Int(i128),
    /// Floating point, including infinities and NaN (RFC 8949 Section 3.3).
    Float(f64),
}

impl Number {
    fn compare(self, other: Self) -> Option<Ordering> {
        match (self, other) {
            (Self::Int(left), Self::Int(right)) => Some(left.cmp(&right)),
            (Self::Float(left), Self::Float(right)) => left.partial_cmp(&right),
            (Self::Int(integer), Self::Float(float)) => compare_integer_float(integer, float),
            (Self::Float(float), Self::Int(integer)) => {
                compare_integer_float(integer, float).map(Ordering::reverse)
            }
        }
    }

    fn into_value(self) -> Value {
        match self {
            Self::Int(value) => Value::Integer(value),
            Self::Float(value) => Value::Float(value),
        }
    }

    fn from_value(value: Value) -> Result<Self, String> {
        let number = match value {
            Value::Integer(value) => Self::Int(value),
            Value::Float(value) => Self::Float(value),
            _ => return Err("expected integer or float".into()),
        };
        number.valid()?;
        Ok(number)
    }
}

fn compare_integer_float(integer: i128, float: f64) -> Option<Ordering> {
    if float.is_nan() {
        return None;
    }
    let bound = 18_446_744_073_709_551_616.0_f64;
    if float >= bound {
        return Some(Ordering::Less);
    }
    if float < -bound {
        return Some(Ordering::Greater);
    }
    let truncated = float as i128;
    match integer.cmp(&truncated) {
        Ordering::Equal => (truncated as f64).partial_cmp(&float),
        ordering => Some(ordering),
    }
}

impl Validate for Number {
    fn valid(&self) -> Result<(), String> {
        if let Self::Int(value) = self {
            if *value < -1 - i128::from(u64::MAX) || *value > i128::from(u64::MAX) {
                return Err("number integer is outside the CBOR range".into());
            }
        }
        Ok(())
    }
}

impl Serialize for Number {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        self.valid().map_err(serde::ser::Error::custom)?;
        let value = self.into_value();
        if serializer.is_human_readable() {
            human_scalar(value)
        } else {
            value
        }
        .serialize(serializer)
    }
}
impl<'de> Deserialize<'de> for Number {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        Self::from_value(Value::deserialize(deserializer)?).map_err(serde::de::Error::custom)
    }
}

/// Numeric condition or observation (Section 5.1.4.9). Only `Exact` is an observation.
#[derive(Clone, Debug, PartialEq)]
#[non_exhaustive]
pub enum NumberMatcher {
    /// Bare numeric value, compared by numeric equality.
    Exact(Number),
    /// Inclusive bounds; `None` is unbounded in that direction.
    Range {
        /// Lower bound.
        min: Option<Number>,
        /// Upper bound.
        max: Option<Number>,
    },
    /// At least two numeric alternatives, encoded with tag 566.
    Set(Vec<Number>),
}

impl NumberMatcher {
    /// Whether an exact observation satisfies this condition (Section 8.3.4.4.5.10).
    /// NaN never matches. Set/range observations and invalid conditions do not match.
    pub fn matches(&self, observed: &Self) -> bool {
        if self.valid().is_err() || observed.valid().is_err() {
            return false;
        }
        let Self::Exact(value) = observed else {
            return false;
        };
        if value.compare(*value).is_none() {
            return false;
        }
        match self {
            Self::Exact(expected) => expected.compare(*value) == Some(Ordering::Equal),
            Self::Set(values) => values
                .iter()
                .any(|expected| expected.compare(*value) == Some(Ordering::Equal)),
            Self::Range { min, max } => {
                min.is_none_or(|min| {
                    matches!(
                        value.compare(min),
                        Some(Ordering::Equal | Ordering::Greater)
                    )
                }) && max.is_none_or(|max| {
                    matches!(value.compare(max), Some(Ordering::Equal | Ordering::Less))
                })
            }
        }
    }
}

impl Validate for NumberMatcher {
    fn valid(&self) -> Result<(), String> {
        match self {
            Self::Exact(value) => value.valid(),
            Self::Set(values) => {
                if values.len() < 2 {
                    return Err("number set requires at least two entries".into());
                }
                for value in values {
                    value.valid()?;
                }
                Ok(())
            }
            Self::Range { min, max } => {
                for value in min.iter().chain(max.iter()) {
                    value.valid()?;
                    if value.compare(*value).is_none() {
                        return Err("range bounds must not be NaN".into());
                    }
                }
                if let (Some(min), Some(max)) = (min, max) {
                    if min.compare(*max) == Some(Ordering::Greater) {
                        return Err("range minimum exceeds maximum".into());
                    }
                }
                Ok(())
            }
        }
    }
}

impl Serialize for NumberMatcher {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        self.valid().map_err(serde::ser::Error::custom)?;
        if serializer.is_human_readable() {
            let value = match self {
                Self::Exact(number) => human_scalar(number.into_value()),
                Self::Range { min, max } => json_choice(
                    "number-range",
                    Value::Array(vec![
                        min.map_or(Value::Null, |value| human_scalar(value.into_value())),
                        max.map_or(Value::Null, |value| human_scalar(value.into_value())),
                    ]),
                ),
                Self::Set(values) => json_choice(
                    "number-set",
                    Value::Array(
                        values
                            .iter()
                            .map(|value| human_scalar(value.into_value()))
                            .collect(),
                    ),
                ),
            };
            return value.serialize(serializer);
        }
        let value = match self {
            Self::Exact(number) => number.into_value(),
            Self::Range { min, max } => Value::Tag(
                TAG_NUMBER_RANGE,
                Box::new(Value::Array(vec![
                    min.map_or(Value::Null, Number::into_value),
                    max.map_or(Value::Null, Number::into_value),
                ])),
            ),
            Self::Set(values) => Value::Tag(
                TAG_MATCHER_SET,
                Box::new(Value::Array(
                    values.iter().map(|value| value.into_value()).collect(),
                )),
            ),
        };
        value.serialize(serializer)
    }
}
impl<'de> Deserialize<'de> for NumberMatcher {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let parsed = match Value::deserialize(deserializer)? {
            Value::Tag(TAG_NUMBER_RANGE, inner) => {
                let Value::Array(bounds) = *inner else {
                    return Err(serde::de::Error::custom("number range must be an array"));
                };
                let [min, max]: [Value; 2] = bounds
                    .try_into()
                    .map_err(|_| serde::de::Error::custom("number range requires two bounds"))?;
                let bound = |value| match value {
                    Value::Null => Ok(None),
                    value => Number::from_value(value).map(Some),
                };
                Self::Range {
                    min: bound(min).map_err(serde::de::Error::custom)?,
                    max: bound(max).map_err(serde::de::Error::custom)?,
                }
            }
            Value::Tag(TAG_MATCHER_SET, inner) => {
                let Value::Array(values) = *inner else {
                    return Err(serde::de::Error::custom("number set must be an array"));
                };
                Self::Set(
                    values
                        .into_iter()
                        .map(Number::from_value)
                        .collect::<Result<_, _>>()
                        .map_err(serde::de::Error::custom)?,
                )
            }
            value => Self::Exact(Number::from_value(value).map_err(serde::de::Error::custom)?),
        };
        parsed.valid().map_err(serde::de::Error::custom)?;
        Ok(parsed)
    }
}

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
