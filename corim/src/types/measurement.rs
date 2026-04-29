// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Measurement types: `measurement-map`, `measurement-values-map`,
//! `digest`, `svn-type-choice`, `flags-map`, `integrity-registers`,
//! `int-range`, and address types.

#[allow(unused_imports)]
use crate::nostd_prelude::*;
use corim_macros::{CborDeserialize, CborSerialize};
use serde::{Deserialize, Serialize};

use super::common::{CryptoKey, MeasuredElement, VersionMap};
use super::tags::*;
use crate::cbor::value::{self, Value};
use crate::Validate;

// ---------------------------------------------------------------------------
// digest = [alg: int / text, val: bytes]
// ---------------------------------------------------------------------------

/// Algorithm identifier for a digest — integer (IANA Named Information
/// registry) or text (profile-defined).
///
/// The CDDL says `alg: int / text`. Most real-world digests use integer
/// algorithm IDs from the COSE Algorithms registry. Text IDs are accepted
/// for forward-compatibility.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum DigestAlg {
    /// Integer algorithm identifier (e.g., 1 = SHA-256, 7 = SHA-384).
    Int(i64),
    /// Text algorithm identifier (profile-defined).
    Text(String),
}

impl DigestAlg {
    /// Returns the integer algorithm ID, or `None` for text algorithms.
    pub fn as_int(&self) -> Option<i64> {
        match self {
            DigestAlg::Int(n) => Some(*n),
            DigestAlg::Text(_) => None,
        }
    }
    /// Returns the text algorithm ID, or `None` for integer algorithms.
    pub fn as_text(&self) -> Option<&str> {
        match self {
            DigestAlg::Text(s) => Some(s),
            DigestAlg::Int(_) => None,
        }
    }
}

impl core::fmt::Display for DigestAlg {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            DigestAlg::Int(n) => write!(f, "{}", n),
            DigestAlg::Text(s) => write!(f, "{}", s),
        }
    }
}

impl From<i64> for DigestAlg {
    fn from(n: i64) -> Self {
        DigestAlg::Int(n)
    }
}

impl From<String> for DigestAlg {
    fn from(s: String) -> Self {
        DigestAlg::Text(s)
    }
}

impl From<&str> for DigestAlg {
    fn from(s: &str) -> Self {
        DigestAlg::Text(s.to_owned())
    }
}

/// `eatmc.digest` — a `[algorithm-id, digest-value]` pair.
///
/// The algorithm identifier can be an integer (from the COSE Algorithms
/// registry) or a text string (profile-defined).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Digest(pub DigestAlg, #[allow(missing_docs)] pub Vec<u8>);

impl Digest {
    /// Create a new digest with an integer algorithm identifier.
    pub fn new(alg: i64, value: Vec<u8>) -> Self {
        Self(DigestAlg::Int(alg), value)
    }
    /// Create a new digest with a text algorithm identifier.
    pub fn new_text(alg: impl Into<String>, value: Vec<u8>) -> Self {
        Self(DigestAlg::Text(alg.into()), value)
    }
    /// Get the algorithm identifier.
    pub fn alg(&self) -> &DigestAlg {
        &self.0
    }
    /// Get the digest value bytes.
    pub fn value(&self) -> &[u8] {
        &self.1
    }
}

impl Serialize for Digest {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        let alg_val = match &self.0 {
            DigestAlg::Int(n) => Value::Integer(*n as i128),
            DigestAlg::Text(t) => Value::Text(t.clone()),
        };
        let arr = Value::Array(vec![alg_val, Value::Bytes(self.1.clone())]);
        arr.serialize(s)
    }
}

impl<'de> Deserialize<'de> for Digest {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let val = Value::deserialize(d)?;
        match val {
            Value::Array(arr) if arr.len() == 2 => {
                let mut it = arr.into_iter();
                let alg = match it
                    .next()
                    .ok_or_else(|| serde::de::Error::custom("digest must be [alg, val]"))?
                {
                    Value::Integer(n) => DigestAlg::Int(
                        i64::try_from(n)
                            .map_err(|_| serde::de::Error::custom("digest alg out of i64 range"))?,
                    ),
                    Value::Text(t) => DigestAlg::Text(t),
                    _ => return Err(serde::de::Error::custom("digest alg must be int or text")),
                };
                let val = match it
                    .next()
                    .ok_or_else(|| serde::de::Error::custom("digest must be [alg, val]"))?
                {
                    Value::Bytes(b) => b,
                    _ => return Err(serde::de::Error::custom("digest val must be bytes")),
                };
                Ok(Digest(alg, val))
            }
            _ => Err(serde::de::Error::custom("digest must be [alg, val]")),
        }
    }
}

// ---------------------------------------------------------------------------
// svn-type-choice = svn / tagged-svn / tagged-min-svn
// ---------------------------------------------------------------------------

/// `svn-type-choice` — SVN with exact-value or minimum-value semantics.
///
/// - Untagged `uint` or `#6.552(uint)`: exact SVN.
/// - `#6.553(uint)`: minimum SVN.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum SvnChoice {
    /// Exact SVN value (untagged or tag 552).
    ExactValue(u64),
    /// Minimum acceptable SVN (tag 553).
    MinValue(u64),
}

impl Serialize for SvnChoice {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        match self {
            SvnChoice::ExactValue(v) => value::serialize_tagged(TAG_SVN, v, s),
            SvnChoice::MinValue(v) => value::serialize_tagged(TAG_MIN_SVN, v, s),
        }
    }
}

impl<'de> Deserialize<'de> for SvnChoice {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let val = Value::deserialize(d)?;
        match val {
            Value::Tag(TAG_SVN, inner) => {
                let n = inner
                    .into_integer()
                    .ok_or_else(|| serde::de::Error::custom("tag 552 must wrap uint"))?;
                Ok(SvnChoice::ExactValue(n.try_into().map_err(|_| {
                    serde::de::Error::custom("SVN must be unsigned")
                })?))
            }
            Value::Tag(TAG_MIN_SVN, inner) => {
                let n = inner
                    .into_integer()
                    .ok_or_else(|| serde::de::Error::custom("tag 553 must wrap uint"))?;
                Ok(SvnChoice::MinValue(n.try_into().map_err(|_| {
                    serde::de::Error::custom("min-SVN must be unsigned")
                })?))
            }
            Value::Integer(i) => {
                Ok(SvnChoice::ExactValue(i.try_into().map_err(|_| {
                    serde::de::Error::custom("SVN must be unsigned")
                })?))
            }
            _ => Err(serde::de::Error::custom(
                "expected uint, tag 552, or tag 553",
            )),
        }
    }
}

// ---------------------------------------------------------------------------
// flags-map
// ---------------------------------------------------------------------------

/// `flags-map` — boolean operational mode flags.
#[derive(Clone, Debug, PartialEq, CborSerialize, CborDeserialize)]
#[cbor(non_empty)]
pub struct FlagsMap {
    /// `is-configured` (key 0).
    #[cbor(key = 0, optional)]
    pub is_configured: Option<bool>,
    /// `is-secure` (key 1).
    #[cbor(key = 1, optional)]
    pub is_secure: Option<bool>,
    /// `is-recovery` (key 2).
    #[cbor(key = 2, optional)]
    pub is_recovery: Option<bool>,
    /// `is-debug` (key 3).
    #[cbor(key = 3, optional)]
    pub is_debug: Option<bool>,
    /// `is-replay-protected` (key 4).
    #[cbor(key = 4, optional)]
    pub is_replay_protected: Option<bool>,
    /// `is-integrity-protected` (key 5).
    #[cbor(key = 5, optional)]
    pub is_integrity_protected: Option<bool>,
    /// `is-runtime-meas` (key 6).
    #[cbor(key = 6, optional)]
    pub is_runtime_meas: Option<bool>,
    /// `is-immutable` (key 7).
    #[cbor(key = 7, optional)]
    pub is_immutable: Option<bool>,
    /// `is-tcb` (key 8).
    #[cbor(key = 8, optional)]
    pub is_tcb: Option<bool>,
    /// `is-confidentiality-protected` (key 9).
    #[cbor(key = 9, optional)]
    pub is_confidentiality_protected: Option<bool>,
}

// ---------------------------------------------------------------------------
// raw-value-type-choice
// ---------------------------------------------------------------------------

/// `$raw-value-type-choice` — tagged bytes or masked raw value.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum RawValueChoice {
    /// Plain bytes (CBOR tag 560).
    Bytes(Vec<u8>),
    /// Masked value `[value, mask]` (CBOR tag 563).
    Masked {
        /// The raw value bytes.
        value: Vec<u8>,
        /// The comparison mask bytes.
        mask: Vec<u8>,
    },
}

impl Serialize for RawValueChoice {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        match self {
            RawValueChoice::Bytes(b) => value::serialize_tagged_bytes(TAG_BYTES, b, s),
            RawValueChoice::Masked { value, mask } => {
                let arr = Value::Array(vec![
                    Value::Bytes(value.clone()),
                    Value::Bytes(mask.clone()),
                ]);
                value::serialize_tagged(TAG_MASKED_RAW_VALUE, &arr, s)
            }
        }
    }
}

impl<'de> Deserialize<'de> for RawValueChoice {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let val = Value::deserialize(d)?;
        match val {
            Value::Tag(TAG_BYTES, inner) => match *inner {
                Value::Bytes(b) => Ok(RawValueChoice::Bytes(b)),
                _ => Err(serde::de::Error::custom("tag 560 must wrap bytes")),
            },
            Value::Tag(TAG_MASKED_RAW_VALUE, inner) => match *inner {
                Value::Array(mut a) if a.len() == 2 => {
                    let mask = match a.pop().ok_or_else(|| {
                        serde::de::Error::custom("tag 563 must wrap [value, mask]")
                    })? {
                        Value::Bytes(b) => b,
                        _ => return Err(serde::de::Error::custom("mask must be bytes")),
                    };
                    let value = match a.pop().ok_or_else(|| {
                        serde::de::Error::custom("tag 563 must wrap [value, mask]")
                    })? {
                        Value::Bytes(b) => b,
                        _ => return Err(serde::de::Error::custom("value must be bytes")),
                    };
                    Ok(RawValueChoice::Masked { value, mask })
                }
                _ => Err(serde::de::Error::custom("tag 563 must wrap [value, mask]")),
            },
            _ => Err(serde::de::Error::custom("expected tag 560 or 563")),
        }
    }
}

// ---------------------------------------------------------------------------
// mac-addr-type-choice
// ---------------------------------------------------------------------------

/// `mac-addr-type-choice` — EUI-48 or EUI-64 MAC address.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum MacAddr {
    /// EUI-48 (6 bytes).
    Eui48([u8; 6]),
    /// EUI-64 (8 bytes).
    Eui64([u8; 8]),
}

impl Serialize for MacAddr {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        match self {
            MacAddr::Eui48(b) => s.serialize_bytes(b),
            MacAddr::Eui64(b) => s.serialize_bytes(b),
        }
    }
}

impl<'de> Deserialize<'de> for MacAddr {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let val = Value::deserialize(d)?;
        match val {
            Value::Bytes(b) if b.len() == 6 => {
                let arr: [u8; 6] = b
                    .try_into()
                    .map_err(|_| serde::de::Error::custom("MAC address must be 6 bytes"))?;
                Ok(MacAddr::Eui48(arr))
            }
            Value::Bytes(b) if b.len() == 8 => {
                let arr: [u8; 8] = b
                    .try_into()
                    .map_err(|_| serde::de::Error::custom("MAC address must be 8 bytes"))?;
                Ok(MacAddr::Eui64(arr))
            }
            Value::Bytes(_) => Err(serde::de::Error::custom("MAC address must be 6 or 8 bytes")),
            _ => Err(serde::de::Error::custom("expected bytes for MAC address")),
        }
    }
}

// ---------------------------------------------------------------------------
// ip-addr-type-choice
// ---------------------------------------------------------------------------

/// `ip-addr-type-choice` — IPv4 or IPv6 address.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum IpAddr {
    /// IPv4 address (4 bytes).
    V4([u8; 4]),
    /// IPv6 address (16 bytes).
    V6([u8; 16]),
}

impl Serialize for IpAddr {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        match self {
            IpAddr::V4(b) => s.serialize_bytes(b),
            IpAddr::V6(b) => s.serialize_bytes(b),
        }
    }
}

impl<'de> Deserialize<'de> for IpAddr {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let val = Value::deserialize(d)?;
        match val {
            Value::Bytes(b) if b.len() == 4 => {
                let arr: [u8; 4] = b
                    .try_into()
                    .map_err(|_| serde::de::Error::custom("IP address must be 4 bytes"))?;
                Ok(IpAddr::V4(arr))
            }
            Value::Bytes(b) if b.len() == 16 => {
                let arr: [u8; 16] = b
                    .try_into()
                    .map_err(|_| serde::de::Error::custom("IP address must be 16 bytes"))?;
                Ok(IpAddr::V6(arr))
            }
            Value::Bytes(_) => Err(serde::de::Error::custom("IP address must be 4 or 16 bytes")),
            _ => Err(serde::de::Error::custom("expected bytes for IP address")),
        }
    }
}

// ---------------------------------------------------------------------------
// int-range-type-choice
// ---------------------------------------------------------------------------

/// `int-range-type-choice` — integer or tagged int range.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum IntRangeChoice {
    /// A single integer value.
    Int(i64),
    /// A range `[min, max]` (CBOR tag 564). `None` represents infinity.
    Range {
        /// Minimum (inclusive), or `None` for negative infinity.
        min: Option<i64>,
        /// Maximum (inclusive), or `None` for positive infinity.
        max: Option<i64>,
    },
}

impl Serialize for IntRangeChoice {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        match self {
            IntRangeChoice::Int(v) => s.serialize_i64(*v),
            IntRangeChoice::Range { min, max } => {
                let min_val = match min {
                    Some(n) => Value::Integer(*n as i128),
                    None => Value::Null,
                };
                let max_val = match max {
                    Some(n) => Value::Integer(*n as i128),
                    None => Value::Null,
                };
                let arr = Value::Array(vec![min_val, max_val]);
                value::serialize_tagged(TAG_INT_RANGE, &arr, s)
            }
        }
    }
}

impl<'de> Deserialize<'de> for IntRangeChoice {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let val = Value::deserialize(d)?;
        match val {
            Value::Integer(n) => {
                Ok(IntRangeChoice::Int(i64::try_from(n).map_err(|_| {
                    serde::de::Error::custom("int-range value out of i64 range")
                })?))
            }
            Value::Tag(TAG_INT_RANGE, inner) => match *inner {
                Value::Array(a) if a.len() == 2 => {
                    let min = match &a[0] {
                        Value::Null => None,
                        Value::Integer(n) => Some(i64::try_from(*n).map_err(|_| {
                            serde::de::Error::custom("int-range min out of i64 range")
                        })?),
                        _ => {
                            return Err(serde::de::Error::custom(
                                "int-range min must be int or null",
                            ))
                        }
                    };
                    let max = match &a[1] {
                        Value::Null => None,
                        Value::Integer(n) => Some(i64::try_from(*n).map_err(|_| {
                            serde::de::Error::custom("int-range max out of i64 range")
                        })?),
                        _ => {
                            return Err(serde::de::Error::custom(
                                "int-range max must be int or null",
                            ))
                        }
                    };
                    Ok(IntRangeChoice::Range { min, max })
                }
                _ => Err(serde::de::Error::custom("tag 564 must wrap [min, max]")),
            },
            _ => Err(serde::de::Error::custom("expected int or tag 564")),
        }
    }
}

// ---------------------------------------------------------------------------
// integrity-registers
// ---------------------------------------------------------------------------

/// `integrity-register-id-type-choice` — uint or text key.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[non_exhaustive]
pub enum IntegrityRegisterId {
    /// Unsigned integer register ID.
    Uint(u64),
    /// Text register ID.
    Text(String),
}

impl Serialize for IntegrityRegisterId {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        match self {
            IntegrityRegisterId::Uint(n) => s.serialize_u64(*n),
            IntegrityRegisterId::Text(t) => s.serialize_str(t),
        }
    }
}

impl<'de> Deserialize<'de> for IntegrityRegisterId {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let val = Value::deserialize(d)?;
        match val {
            Value::Integer(n) => {
                Ok(IntegrityRegisterId::Uint(n.try_into().map_err(|_| {
                    serde::de::Error::custom("register id must be unsigned")
                })?))
            }
            Value::Text(t) => Ok(IntegrityRegisterId::Text(t)),
            _ => Err(serde::de::Error::custom(
                "expected uint or text for register id",
            )),
        }
    }
}

/// `integrity-registers` — map of register IDs to digest lists.
///
/// CDDL: `{+ integrity-register-id-type-choice => digests-type}`
#[derive(Clone, Debug, PartialEq)]
pub struct IntegrityRegisters(pub BTreeMap<IntegrityRegisterId, Vec<Digest>>);

impl Serialize for IntegrityRegisters {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        use serde::ser::SerializeMap;
        let mut map = s.serialize_map(Some(self.0.len()))?;
        for (k, v) in &self.0 {
            map.serialize_entry(k, v)?;
        }
        map.end()
    }
}

impl<'de> Deserialize<'de> for IntegrityRegisters {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let val = Value::deserialize(d)?;
        match val {
            Value::Map(entries) => {
                let mut map = BTreeMap::new();
                for (k, v) in entries {
                    let key = match k {
                        Value::Integer(n) => {
                            IntegrityRegisterId::Uint(n.try_into().map_err(|_| {
                                serde::de::Error::custom("register id must be unsigned")
                            })?)
                        }
                        Value::Text(t) => IntegrityRegisterId::Text(t),
                        _ => {
                            return Err(serde::de::Error::custom(
                                "register id must be uint or text",
                            ))
                        }
                    };
                    let digests: Vec<Digest> = match v {
                        Value::Array(arr) => {
                            let mut ds = Vec::new();
                            for item in arr {
                                match item {
                                    Value::Array(pair) if pair.len() == 2 => {
                                        let mut it = pair.into_iter();
                                        let alg = match it.next().ok_or_else(|| {
                                            serde::de::Error::custom("digest must be [alg, val]")
                                        })? {
                                            Value::Integer(n) => {
                                                i64::try_from(n).map_err(|_| {
                                                    serde::de::Error::custom(
                                                        "digest alg out of i64 range",
                                                    )
                                                })?
                                            }
                                            _ => {
                                                return Err(serde::de::Error::custom(
                                                    "digest alg must be int",
                                                ))
                                            }
                                        };
                                        let val = match it.next().ok_or_else(|| {
                                            serde::de::Error::custom("digest must be [alg, val]")
                                        })? {
                                            Value::Bytes(b) => b,
                                            _ => {
                                                return Err(serde::de::Error::custom(
                                                    "digest val must be bytes",
                                                ))
                                            }
                                        };
                                        ds.push(Digest::new(alg, val));
                                    }
                                    _ => {
                                        return Err(serde::de::Error::custom(
                                            "digest must be [alg, val]",
                                        ))
                                    }
                                }
                            }
                            ds
                        }
                        _ => return Err(serde::de::Error::custom("digests must be an array")),
                    };
                    map.insert(key, digests);
                }
                Ok(IntegrityRegisters(map))
            }
            _ => Err(serde::de::Error::custom(
                "expected map for integrity-registers",
            )),
        }
    }
}

// ---------------------------------------------------------------------------
// measurement-values-map
// ---------------------------------------------------------------------------

/// `measurement-values-map` — all possible measurement value fields.
#[derive(Clone, Debug, PartialEq, CborSerialize, CborDeserialize)]
#[cbor(non_empty)]
pub struct MeasurementValuesMap {
    /// `version` (key 0).
    #[cbor(key = 0, optional)]
    pub version: Option<VersionMap>,
    /// `svn` (key 1).
    #[cbor(key = 1, optional)]
    pub svn: Option<SvnChoice>,
    /// `digests` (key 2).
    #[cbor(key = 2, optional)]
    pub digests: Option<Vec<Digest>>,
    /// `flags` (key 3).
    #[cbor(key = 3, optional)]
    pub flags: Option<FlagsMap>,
    /// `raw-value` (key 4).
    #[cbor(key = 4, optional)]
    pub raw_value: Option<RawValueChoice>,
    /// `mac-addr` (key 6).
    #[cbor(key = 6, optional)]
    pub mac_addr: Option<MacAddr>,
    /// `ip-addr` (key 7).
    #[cbor(key = 7, optional)]
    pub ip_addr: Option<IpAddr>,
    /// `serial-number` (key 8).
    #[cbor(key = 8, optional)]
    pub serial_number: Option<String>,
    /// `ueid` (key 9).
    #[cbor(key = 9, optional, bytes)]
    pub ueid: Option<Vec<u8>>,
    /// `uuid` (key 10).
    #[cbor(key = 10, optional, bytes)]
    pub uuid: Option<Vec<u8>>,
    /// `name` (key 11).
    #[cbor(key = 11, optional)]
    pub name: Option<String>,
    /// `cryptokeys` (key 13).
    #[cbor(key = 13, optional)]
    pub cryptokeys: Option<Vec<CryptoKey>>,
    /// `integrity-registers` (key 14).
    #[cbor(key = 14, optional)]
    pub integrity_registers: Option<IntegrityRegisters>,
    /// `int-range` (key 15).
    #[cbor(key = 15, optional)]
    pub int_range: Option<IntRangeChoice>,
}

impl MeasurementValuesMap {
    /// Create a new empty `MeasurementValuesMap`.
    ///
    /// Note: encoding will fail due to `non_empty` unless at least one field is set.
    pub fn new() -> Self {
        Self {
            version: None,
            svn: None,
            digests: None,
            flags: None,
            raw_value: None,
            mac_addr: None,
            ip_addr: None,
            serial_number: None,
            ueid: None,
            uuid: None,
            name: None,
            cryptokeys: None,
            integrity_registers: None,
            int_range: None,
        }
    }
}

impl Default for MeasurementValuesMap {
    fn default() -> Self {
        Self::new()
    }
}

impl Validate for MeasurementValuesMap {
    fn valid(&self) -> Result<(), String> {
        // CDDL: non-empty<{ ... }>
        if self.version.is_none()
            && self.svn.is_none()
            && self.digests.is_none()
            && self.flags.is_none()
            && self.raw_value.is_none()
            && self.mac_addr.is_none()
            && self.ip_addr.is_none()
            && self.serial_number.is_none()
            && self.ueid.is_none()
            && self.uuid.is_none()
            && self.name.is_none()
            && self.cryptokeys.is_none()
            && self.integrity_registers.is_none()
            && self.int_range.is_none()
        {
            return Err("no measurement value set".into());
        }
        // Validate digests if present: at least one digest required
        if let Some(ref digests) = self.digests {
            if digests.is_empty() {
                return Err("digests list must not be empty".into());
            }
        }
        Ok(())
    }
}

impl Validate for MeasurementMap {
    fn valid(&self) -> Result<(), String> {
        self.mval
            .valid()
            .map_err(|e| format!("measurement values: {e}"))?;
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// measurement-map
// ---------------------------------------------------------------------------

/// `measurement-map` — a single measurement within a triple.
#[derive(Clone, Debug, PartialEq, CborSerialize, CborDeserialize)]
pub struct MeasurementMap {
    /// `mkey` (key 0): optional measurement key.
    #[cbor(key = 0, optional)]
    pub mkey: Option<MeasuredElement>,
    /// `mval` (key 1): measurement values.
    #[cbor(key = 1)]
    pub mval: MeasurementValuesMap,
    /// `authorized-by` (key 2): optional authority keys.
    #[cbor(key = 2, optional)]
    pub authorized_by: Option<Vec<CryptoKey>>,
}
