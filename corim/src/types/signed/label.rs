// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Integer-or-text labels shared by COSE headers and CWT claims
//! (RFC 9052 §3 and RFC 8392 §3).

use crate::cbor::value::Value;
use crate::nostd_prelude::*;
use serde::{Deserialize, Serialize};

/// An integer or text label, per RFC 9052 §3 and RFC 8392 §3.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[non_exhaustive]
pub enum Label {
    /// An integer label.
    Int(i64),
    /// A text label.
    Text(String),
}

impl From<i64> for Label {
    fn from(value: i64) -> Self {
        Self::Int(value)
    }
}

impl From<&str> for Label {
    fn from(value: &str) -> Self {
        Self::Text(value.into())
    }
}

impl core::fmt::Display for Label {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Int(value) => write!(formatter, "{value}"),
            Self::Text(value) => {
                write!(formatter, "\"{}\"", crate::cbor::value::escape_text(value))
            }
        }
    }
}

impl Serialize for Label {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        match self {
            Self::Int(value) => serializer.serialize_i64(*value),
            Self::Text(value) => serializer.serialize_str(value),
        }
    }
}

impl<'de> Deserialize<'de> for Label {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        match Value::deserialize(deserializer)? {
            Value::Integer(value) => i64::try_from(value)
                .map(Self::Int)
                .map_err(serde::de::Error::custom),
            Value::Text(value) => Ok(Self::Text(value)),
            _ => Err(serde::de::Error::custom("label must be integer or text")),
        }
    }
}
