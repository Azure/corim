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
pub(super) const CWT_CLAIM_ISS: i64 = 1;
/// CWT claim: `sub` (key 2) — Subject.
pub(super) const CWT_CLAIM_SUB: i64 = 2;
/// CWT claim: `exp` (key 4) — Expiration Time.
pub(super) const CWT_CLAIM_EXP: i64 = 4;
/// CWT claim: `nbf` (key 5) — Not Before.
pub(super) const CWT_CLAIM_NBF: i64 = 5;
/// CWT claim: `iat` (key 6) — Issued At.
#[allow(dead_code)] // Defined for documentation; key 6 values stored in `extra`.
pub(super) const CWT_CLAIM_IAT: i64 = 6;

// ===================================================================
// CWT Claims (RFC 8392 / RFC 9597)
// ===================================================================

/// CWT Claims map, used in the protected header of a signed CoRIM (§4.2.2).
///
/// ```text
/// cwt-claims = {
///   &(iss: 1) => tstr,
///   ? &(sub: 2) => tstr,
///   ? &(exp: 4) => int / float,
///   ? &(nbf: 5) => int / float,
///   * int => any,
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
    pub exp: Option<i64>,
    /// `nbf` (key 5): Not-before time as epoch seconds.
    pub nbf: Option<i64>,
    /// Additional CWT claims beyond the standard ones.
    pub extra: BTreeMap<i64, Value>,
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
    pub fn with_exp(mut self, exp: i64) -> Self {
        self.exp = Some(exp);
        self
    }

    /// Set the not-before time.
    pub fn with_nbf(mut self, nbf: i64) -> Self {
        self.nbf = Some(nbf);
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
        let mut exp: Option<i64> = None;
        let mut nbf: Option<i64> = None;
        let mut extra = BTreeMap::new();

        for (k, v) in map {
            let key = match &k {
                Value::Integer(n) => i64::try_from(*n)
                    .map_err(|_| serde::de::Error::custom("cwt key out of range"))?,
                _ => {
                    // Non-integer keys: skip
                    continue;
                }
            };
            match key {
                CWT_CLAIM_ISS => {
                    iss = Some(match v {
                        Value::Text(t) => t,
                        _ => return Err(serde::de::Error::custom("iss must be tstr")),
                    });
                }
                CWT_CLAIM_SUB => {
                    sub = Some(match v {
                        Value::Text(t) => t,
                        _ => return Err(serde::de::Error::custom("sub must be tstr")),
                    });
                }
                CWT_CLAIM_EXP => {
                    exp = Some(value_to_epoch(&v).map_err(serde::de::Error::custom)?);
                }
                CWT_CLAIM_NBF => {
                    nbf = Some(value_to_epoch(&v).map_err(serde::de::Error::custom)?);
                }
                _ => {
                    extra.insert(key, v);
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

/// Convert a Value (integer or float) to epoch seconds.
///
/// Accepts CBOR integers (preferred) and CBOR floats (RFC 8392 allows
/// `int / float` for time claims). Floats are rejected if they are NaN,
/// infinite, or outside the representable `i64` range.
pub(super) fn value_to_epoch(v: &Value) -> Result<i64, String> {
    match v {
        Value::Integer(n) => i64::try_from(*n).map_err(|_| "epoch time out of i64 range".into()),
        Value::Float(f) => {
            let n = *f;
            // Reject NaN, infinity, and values outside i64 range before cast.
            if n.is_nan() || n.is_infinite() || n < (i64::MIN as f64) || n > (i64::MAX as f64) {
                return Err("epoch float out of i64 range".into());
            }
            Ok(n as i64)
        }
        _ => Err("epoch time must be int or float".into()),
    }
}
