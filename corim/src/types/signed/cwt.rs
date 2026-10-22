// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! CWT claims used inside the protected COSE_Sign1 header for signed
//! CoRIMs, per [RFC 8392](https://www.rfc-editor.org/rfc/rfc8392.html)
//! and [RFC 9597](https://www.rfc-editor.org/rfc/rfc9597.html).

#[allow(unused_imports)]
use crate::nostd_prelude::*;
use serde::{Deserialize, Serialize};

use crate::cbor::value::Value;

// ===================================================================
// CWT Claim Keys (RFC 8392 §4)
// ===================================================================

/// CWT claim: `iss` (key 1) — Issuer.
pub const CWT_CLAIM_ISS: i64 = 1;
/// CWT claim: `sub` (key 2) — Subject.
pub const CWT_CLAIM_SUB: i64 = 2;
/// CWT claim: `exp` (key 4) — Expiration Time.
pub const CWT_CLAIM_EXP: i64 = 4;
/// CWT claim: `nbf` (key 5) — Not Before.
pub const CWT_CLAIM_NBF: i64 = 5;
/// CWT claim: `iat` (key 6) — Issued At. Not parsed into a dedicated field;
/// when present in the CWT claims map it is preserved in [`CwtClaims::extra`].
pub const CWT_CLAIM_IAT: i64 = 6;

// ===================================================================
// CWT Claims (RFC 8392 / RFC 9597)
// ===================================================================

/// An integer-or-text CWT claim key (RFC 8392 §3).
pub use super::label::Label as ClaimKey;

/// A CWT NumericDate preserving integer or fractional seconds (RFC 8392 §2).
///
/// This implementation accepts integer seconds in the `i64` range and finite
/// floats in the same half-open range, without truncating their precision.
#[derive(Clone, Copy, Debug, PartialEq)]
#[non_exhaustive]
pub enum NumericDate {
    /// Integer seconds since the Unix epoch.
    Int(i64),
    /// Floating-point seconds since the Unix epoch.
    Float(f64),
}

impl NumericDate {
    pub(crate) fn from_value(value: &Value) -> Result<Self, String> {
        match value {
            Value::Integer(value) => i64::try_from(*value)
                .map(Self::Int)
                .map_err(|_| "epoch time out of i64 range".into()),
            Value::Float(value)
                if value.is_finite()
                    && *value >= -9_223_372_036_854_775_808.0
                    && *value < 9_223_372_036_854_775_808.0 =>
            {
                Ok(Self::Float(*value))
            }
            _ => Err("epoch time must be finite and within i64 range".into()),
        }
    }

    pub(crate) fn value(self) -> Value {
        match self {
            Self::Int(value) => Value::Integer(value.into()),
            Self::Float(value) => Value::Float(value),
        }
    }

    pub(crate) fn number(self) -> crate::types::matcher::Number {
        match self {
            Self::Int(value) => crate::types::matcher::Number::Int(value.into()),
            Self::Float(value) => crate::types::matcher::Number::Float(value),
        }
    }
}

impl From<i64> for NumericDate {
    fn from(value: i64) -> Self {
        Self::Int(value)
    }
}

impl crate::Validate for NumericDate {
    fn valid(&self) -> Result<(), String> {
        Self::from_value(&self.value()).map(|_| ())
    }
}

impl core::fmt::Display for NumericDate {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Int(value) => write!(formatter, "{value}"),
            Self::Float(value) => write!(formatter, "{value}"),
        }
    }
}

impl Serialize for NumericDate {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let value = self.value();
        Self::from_value(&value).map_err(serde::ser::Error::custom)?;
        value.serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for NumericDate {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        Self::from_value(&Value::deserialize(deserializer)?).map_err(serde::de::Error::custom)
    }
}

/// CWT Claims map, used in the protected header of a signed CoRIM (§4.2.2).
///
/// ```text
/// cwt-claims = {
///   &(iss: 1) => tstr,
///   ? &(sub: 2) => tstr,
///   ? &(exp: 4) => int / float,
///   ? &(nbf: 5) => int / float,
///   * (int / tstr) => any,
/// }
/// ```
///
/// **Note on `Eq`:** This type derives `PartialEq` but not `Eq` because
/// the `extra` map contains [`Value`] entries which may hold CBOR
/// floating-point values. IEEE 754 floats do not satisfy the reflexive
/// property (`NaN != NaN`), so `Eq` cannot be soundly derived.
#[derive(Clone, Debug, PartialEq)]
pub struct CwtClaims {
    /// `iss` (key 1): Issuer — identifies the CoRIM signer.
    pub iss: String,
    /// `sub` (key 2): Subject — optional, identifies the CoRIM document.
    pub sub: Option<String>,
    /// `exp` (key 4): Expiration time as epoch seconds.
    pub exp: Option<NumericDate>,
    /// `nbf` (key 5): Not-before time as epoch seconds.
    pub nbf: Option<NumericDate>,
    /// Additional CWT claims beyond the standard ones, keyed by integer or
    /// text claim key.
    pub extra: BTreeMap<ClaimKey, Value>,
}

impl CwtClaims {
    /// Create a new `CwtClaims` with just the required issuer.
    pub fn new(iss: impl Into<String>) -> Self {
        Self {
            iss: iss.into(),
            sub: None,
            exp: None,
            nbf: None,
            extra: BTreeMap::new(),
        }
    }

    /// Set the subject.
    pub fn with_sub(mut self, sub: impl Into<String>) -> Self {
        self.sub = Some(sub.into());
        self
    }

    /// Set the expiration time.
    pub fn with_exp(mut self, exp: impl Into<NumericDate>) -> Self {
        self.exp = Some(exp.into());
        self
    }

    /// Set the not-before time.
    pub fn with_nbf(mut self, nbf: impl Into<NumericDate>) -> Self {
        self.nbf = Some(nbf.into());
        self
    }
}

impl Serialize for CwtClaims {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        use serde::ser::SerializeMap;
        // Count entries
        let mut count = 1; // iss is required
        if self.sub.is_some() {
            count += 1;
        }
        if self.exp.is_some() {
            count += 1;
        }
        if self.nbf.is_some() {
            count += 1;
        }
        count += self.extra.len();

        let mut map = s.serialize_map(Some(count))?;
        map.serialize_entry(&CWT_CLAIM_ISS, &self.iss)?;
        if let Some(ref sub) = self.sub {
            map.serialize_entry(&CWT_CLAIM_SUB, sub)?;
        }
        if let Some(exp) = self.exp {
            map.serialize_entry(&CWT_CLAIM_EXP, &exp)?;
        }
        if let Some(nbf) = self.nbf {
            map.serialize_entry(&CWT_CLAIM_NBF, &nbf)?;
        }
        for (k, v) in &self.extra {
            if matches!(
                k,
                ClaimKey::Int(CWT_CLAIM_ISS | CWT_CLAIM_SUB | CWT_CLAIM_EXP | CWT_CLAIM_NBF)
            ) {
                return Err(serde::ser::Error::custom(format!(
                    "extra claim key {k} collides with a modeled claim"
                )));
            }
            map.serialize_entry(k, v)?;
        }
        map.end()
    }
}

impl<'de> Deserialize<'de> for CwtClaims {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let val = Value::deserialize(d)?;
        let map = match val {
            Value::Map(m) => m,
            _ => return Err(serde::de::Error::custom("cwt-claims must be a map")),
        };

        let mut iss: Option<String> = None;
        let mut sub: Option<String> = None;
        let mut exp = None;
        let mut nbf = None;
        let mut extra = BTreeMap::new();

        for (k, v) in map {
            let key = match k {
                Value::Integer(n) => i64::try_from(n)
                    .map_err(|_| serde::de::Error::custom("cwt key out of range"))?,
                // Text-keyed claims are not registered in RFC 8392 but are
                // emitted in practice; keep them rather than dropping them.
                Value::Text(t) => {
                    match extra.entry(ClaimKey::Text(t)) {
                        alloc::collections::btree_map::Entry::Vacant(slot) => {
                            slot.insert(v);
                        }
                        alloc::collections::btree_map::Entry::Occupied(slot) => {
                            return Err(serde::de::Error::custom(alloc::format!(
                                "cwt-claims: duplicate claim key {}",
                                slot.key()
                            )));
                        }
                    }
                    continue;
                }
                _ => continue,
            };
            // A CBOR map must not repeat a key (RFC 8949 §5.6). Silently
            // letting a later entry win would make the signer identity and
            // validity window ambiguous between parsers.
            macro_rules! set_once {
                ($slot:ident, $name:literal, $value:expr) => {{
                    if $slot.is_some() {
                        return Err(serde::de::Error::custom(concat!(
                            "cwt-claims: duplicate ",
                            $name,
                            " claim"
                        )));
                    }
                    $slot = Some($value);
                }};
            }
            match key {
                CWT_CLAIM_ISS => set_once!(
                    iss,
                    "iss",
                    match v {
                        Value::Text(t) => t,
                        _ => return Err(serde::de::Error::custom("iss must be tstr")),
                    }
                ),
                CWT_CLAIM_SUB => set_once!(
                    sub,
                    "sub",
                    match v {
                        Value::Text(t) => t,
                        _ => return Err(serde::de::Error::custom("sub must be tstr")),
                    }
                ),
                CWT_CLAIM_EXP => set_once!(
                    exp,
                    "exp",
                    NumericDate::from_value(&v).map_err(serde::de::Error::custom)?
                ),
                CWT_CLAIM_NBF => set_once!(
                    nbf,
                    "nbf",
                    NumericDate::from_value(&v).map_err(serde::de::Error::custom)?
                ),
                _ => {
                    if extra.insert(ClaimKey::Int(key), v).is_some() {
                        return Err(serde::de::Error::custom(alloc::format!(
                            "cwt-claims: duplicate claim key {key}"
                        )));
                    }
                }
            }
        }

        let iss = iss.ok_or_else(|| serde::de::Error::custom("cwt-claims: missing iss (key 1)"))?;
        Ok(CwtClaims {
            iss,
            sub,
            exp,
            nbf,
            extra,
        })
    }
}
