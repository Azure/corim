// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Common types shared across CoRIM and CoMID structures.
//!
//! All custom serde impls use [`crate::cbor::value::Value`] for tag dispatch
//! rather than importing any specific CBOR backend directly.

use corim_macros::{CborDeserialize, CborSerialize};
use serde::{Deserialize, Serialize};

use super::tags::*;
use crate::cbor::value::{self, Value};
use crate::types::measurement::Digest;

// ---------------------------------------------------------------------------
// CborTime — CBOR epoch-based date/time (#6.1)
// ---------------------------------------------------------------------------

/// CBOR epoch-based date/time per RFC 8949 §3.4.2.
///
/// Serializes as `#6.1(int)`. Deserializes accepting both tagged (`#6.1(int)`)
/// and untagged `int` for interoperability.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct CborTime(pub i64);

impl CborTime {
    /// Create a new epoch time value.
    pub fn new(epoch_secs: i64) -> Self {
        Self(epoch_secs)
    }

    /// Get the epoch seconds value.
    pub fn epoch_secs(self) -> i64 {
        self.0
    }
}

impl From<i64> for CborTime {
    fn from(v: i64) -> Self {
        Self(v)
    }
}

impl From<CborTime> for i64 {
    fn from(t: CborTime) -> Self {
        t.0
    }
}

impl core::fmt::Display for CborTime {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl Serialize for CborTime {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        // Serialize as #6.1(int) per RFC 8949 §3.4.2
        value::serialize_tagged(TAG_EPOCH_TIME, &self.0, s)
    }
}

impl<'de> Deserialize<'de> for CborTime {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let val = Value::deserialize(d)?;
        match val {
            // Accept tagged #6.1(int)
            Value::Tag(TAG_EPOCH_TIME, inner) => {
                let n = inner
                    .into_integer()
                    .ok_or_else(|| serde::de::Error::custom("tag 1 must wrap integer"))?;
                let n: i64 = n
                    .try_into()
                    .map_err(|_| serde::de::Error::custom("epoch time out of i64 range"))?;
                Ok(CborTime(n))
            }
            // Also accept untagged int for interop with non-conformant producers
            Value::Integer(n) => {
                let n: i64 = n
                    .try_into()
                    .map_err(|_| serde::de::Error::custom("epoch time out of i64 range"))?;
                Ok(CborTime(n))
            }
            _ => Err(serde::de::Error::custom("expected time (tag 1 or integer)")),
        }
    }
}

// ---------------------------------------------------------------------------
// tag-identity-map  { tag-id: 0, tag-version: 1 }
// ---------------------------------------------------------------------------

/// `tag-identity-map` — identifies a CoMID tag.
#[derive(Clone, Debug, PartialEq, CborSerialize, CborDeserialize)]
pub struct TagIdentity {
    /// `tag-id` (key 0): globally unique tag identifier.
    #[cbor(key = 0)]
    pub tag_id: TagIdChoice,
    /// `tag-version` (key 1): optional revision number.
    ///
    /// Per CDDL `uint .default 0`, absent means version 0.
    /// Use [`tag_version_or_default`](TagIdentity::tag_version_or_default)
    /// to get the effective value.
    #[cbor(key = 1, optional)]
    pub tag_version: Option<u64>,
}

impl TagIdentity {
    /// Returns the tag version, treating `None` as the CDDL default of 0.
    pub fn tag_version_or_default(&self) -> u64 {
        self.tag_version.unwrap_or(0)
    }
}

// ---------------------------------------------------------------------------
// validity-map  { not-before: 0, not-after: 1 }
// ---------------------------------------------------------------------------

/// `validity-map` — time window.
///
/// Time values are CBOR epoch-based date/time (`#6.1(int)`) per RFC 8949 §3.4.2.
/// [`CborTime`] handles both tagged and untagged integers on decode.
#[derive(Clone, Debug, PartialEq, CborSerialize, CborDeserialize)]
pub struct ValidityMap {
    /// `not-before` (key 0): optional start of validity.
    #[cbor(key = 0, optional)]
    pub not_before: Option<CborTime>,
    /// `not-after` (key 1): end of validity.
    #[cbor(key = 1)]
    pub not_after: CborTime,
}

// ---------------------------------------------------------------------------
// entity-map  { entity-name: 0, reg-id: 1, role: 2 }
// ---------------------------------------------------------------------------

/// `entity-map` — describes an entity (creator, signer, etc.).
#[derive(Clone, Debug, PartialEq, CborSerialize, CborDeserialize)]
pub struct EntityMap {
    /// `entity-name` (key 0): name of the entity.
    #[cbor(key = 0)]
    pub entity_name: String,
    /// `reg-id` (key 1): optional URI for the organization.
    #[cbor(key = 1, optional)]
    pub reg_id: Option<String>,
    /// `role` (key 2): list of roles.
    #[cbor(key = 2)]
    pub role: Vec<i64>,
}

// ---------------------------------------------------------------------------
// version-map  { version: 0, version-scheme: 1 }
// ---------------------------------------------------------------------------

/// `version-map` — software version info.
#[derive(Clone, Debug, PartialEq, CborSerialize, CborDeserialize)]
pub struct VersionMap {
    /// `version` (key 0): the version string.
    #[cbor(key = 0)]
    pub version: String,
    /// `version-scheme` (key 1): optional versioning convention.
    #[cbor(key = 1, optional)]
    pub version_scheme: Option<i64>,
}

// ---------------------------------------------------------------------------
// Type-choice enums
// ---------------------------------------------------------------------------

/// `$tag-id-type-choice` — text string or UUID.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum TagIdChoice {
    /// A textual tag identifier.
    Text(String),
    /// A 16-byte UUID (CBOR tag 37).
    Uuid([u8; 16]),
}

impl Serialize for TagIdChoice {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        match self {
            TagIdChoice::Text(t) => s.serialize_str(t),
            TagIdChoice::Uuid(u) => value::serialize_tagged_bytes(TAG_UUID, u.as_slice(), s),
        }
    }
}

impl<'de> Deserialize<'de> for TagIdChoice {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let val = Value::deserialize(d)?;
        match val {
            Value::Text(t) => Ok(TagIdChoice::Text(t)),
            Value::Tag(TAG_UUID, inner) => {
                let b = inner
                    .into_bytes()
                    .ok_or_else(|| serde::de::Error::custom("tag 37 must wrap bytes"))?;
                let arr: [u8; 16] = b
                    .try_into()
                    .map_err(|_| serde::de::Error::custom("UUID must be 16 bytes"))?;
                Ok(TagIdChoice::Uuid(arr))
            }
            _ => Err(serde::de::Error::custom("expected text or tagged UUID")),
        }
    }
}

/// `$class-id-type-choice` — OID, UUID, or generic bytes.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum ClassIdChoice {
    /// OID (CBOR tag 111).
    Oid(Vec<u8>),
    /// UUID (CBOR tag 37).
    Uuid([u8; 16]),
    /// Generic tagged bytes (CBOR tag 560).
    Bytes(Vec<u8>),
}

impl Serialize for ClassIdChoice {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        match self {
            ClassIdChoice::Oid(b) => value::serialize_tagged_bytes(TAG_OID, b, s),
            ClassIdChoice::Uuid(u) => value::serialize_tagged_bytes(TAG_UUID, u, s),
            ClassIdChoice::Bytes(b) => value::serialize_tagged_bytes(TAG_BYTES, b, s),
        }
    }
}

impl<'de> Deserialize<'de> for ClassIdChoice {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let val = Value::deserialize(d)?;
        match val {
            Value::Tag(TAG_OID, inner) => {
                Ok(ClassIdChoice::Oid(inner.into_bytes().ok_or_else(|| {
                    serde::de::Error::custom("tag 111 must wrap bytes")
                })?))
            }
            Value::Tag(TAG_UUID, inner) => {
                let b = inner
                    .into_bytes()
                    .ok_or_else(|| serde::de::Error::custom("tag 37 must wrap bytes"))?;
                Ok(ClassIdChoice::Uuid(b.try_into().map_err(|_| {
                    serde::de::Error::custom("UUID must be 16 bytes")
                })?))
            }
            Value::Tag(TAG_BYTES, inner) => {
                Ok(ClassIdChoice::Bytes(inner.into_bytes().ok_or_else(
                    || serde::de::Error::custom("tag 560 must wrap bytes"),
                )?))
            }
            _ => Err(serde::de::Error::custom(
                "expected tagged OID, UUID, or bytes",
            )),
        }
    }
}

/// `$instance-id-type-choice` — UEID, UUID, bytes, or crypto key types.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum InstanceIdChoice {
    /// UEID (CBOR tag 550).
    Ueid(Vec<u8>),
    /// UUID (CBOR tag 37).
    Uuid([u8; 16]),
    /// Generic tagged bytes (CBOR tag 560).
    Bytes(Vec<u8>),
    /// PEM SubjectPublicKeyInfo (CBOR tag 554).
    PkixBase64Key(String),
    /// PEM X.509 certificate (CBOR tag 555).
    PkixBase64Cert(String),
    /// CBOR-encoded COSE_Key (CBOR tag 558).
    CoseKey(Vec<u8>),
    /// Key thumbprint digest (CBOR tag 557).
    KeyThumbprint(Digest),
    /// Cert thumbprint digest (CBOR tag 559).
    CertThumbprint(Digest),
    /// ASN.1 DER X.509 certificate (CBOR tag 562).
    PkixAsn1DerCert(Vec<u8>),
}

impl Serialize for InstanceIdChoice {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        match self {
            InstanceIdChoice::Ueid(b) => value::serialize_tagged_bytes(TAG_UEID, b, s),
            InstanceIdChoice::Uuid(u) => value::serialize_tagged_bytes(TAG_UUID, u, s),
            InstanceIdChoice::Bytes(b) => value::serialize_tagged_bytes(TAG_BYTES, b, s),
            InstanceIdChoice::PkixBase64Key(t) => {
                value::serialize_tagged(TAG_PKIX_BASE64_KEY, t, s)
            }
            InstanceIdChoice::PkixBase64Cert(t) => {
                value::serialize_tagged(TAG_PKIX_BASE64_CERT, t, s)
            }
            InstanceIdChoice::CoseKey(b) => value::serialize_tagged_bytes(TAG_COSE_KEY, b, s),
            InstanceIdChoice::KeyThumbprint(d) => value::serialize_tagged(TAG_KEY_THUMBPRINT, d, s),
            InstanceIdChoice::CertThumbprint(d) => {
                value::serialize_tagged(TAG_CERT_THUMBPRINT, d, s)
            }
            InstanceIdChoice::PkixAsn1DerCert(b) => {
                value::serialize_tagged_bytes(TAG_PKIX_ASN1DER_CERT, b, s)
            }
        }
    }
}

impl<'de> Deserialize<'de> for InstanceIdChoice {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let val = Value::deserialize(d)?;
        match val {
            Value::Tag(TAG_UEID, inner) => {
                let b = inner
                    .into_bytes()
                    .ok_or_else(|| serde::de::Error::custom("tag 550 must wrap bytes"))?;
                if b.len() < 7 || b.len() > 33 {
                    return Err(serde::de::Error::custom(format!(
                        "UEID must be 7-33 bytes, got {}",
                        b.len()
                    )));
                }
                Ok(InstanceIdChoice::Ueid(b))
            }
            Value::Tag(TAG_UUID, inner) => {
                let b = inner
                    .into_bytes()
                    .ok_or_else(|| serde::de::Error::custom("tag 37 must wrap bytes"))?;
                Ok(InstanceIdChoice::Uuid(b.try_into().map_err(|_| {
                    serde::de::Error::custom("UUID must be 16 bytes")
                })?))
            }
            Value::Tag(TAG_PKIX_BASE64_KEY, inner) => match *inner {
                Value::Text(t) => Ok(InstanceIdChoice::PkixBase64Key(t)),
                _ => Err(serde::de::Error::custom("tag 554 must wrap text")),
            },
            Value::Tag(TAG_PKIX_BASE64_CERT, inner) => match *inner {
                Value::Text(t) => Ok(InstanceIdChoice::PkixBase64Cert(t)),
                _ => Err(serde::de::Error::custom("tag 555 must wrap text")),
            },
            Value::Tag(TAG_COSE_KEY, inner) => {
                Ok(InstanceIdChoice::CoseKey(inner.into_bytes().ok_or_else(
                    || serde::de::Error::custom("tag 558 must wrap bytes"),
                )?))
            }
            Value::Tag(TAG_KEY_THUMBPRINT, inner) => {
                let arr = inner
                    .into_array()
                    .ok_or_else(|| serde::de::Error::custom("tag 557 must wrap array"))?;
                Ok(InstanceIdChoice::KeyThumbprint(digest_from_value_array(
                    arr,
                )?))
            }
            Value::Tag(TAG_CERT_THUMBPRINT, inner) => {
                let arr = inner
                    .into_array()
                    .ok_or_else(|| serde::de::Error::custom("tag 559 must wrap array"))?;
                Ok(InstanceIdChoice::CertThumbprint(digest_from_value_array(
                    arr,
                )?))
            }
            Value::Tag(TAG_PKIX_ASN1DER_CERT, inner) => Ok(InstanceIdChoice::PkixAsn1DerCert(
                inner
                    .into_bytes()
                    .ok_or_else(|| serde::de::Error::custom("tag 562 must wrap bytes"))?,
            )),
            Value::Tag(TAG_BYTES, inner) => {
                Ok(InstanceIdChoice::Bytes(inner.into_bytes().ok_or_else(
                    || serde::de::Error::custom("tag 560 must wrap bytes"),
                )?))
            }
            _ => Err(serde::de::Error::custom(
                "expected tagged UEID, UUID, bytes, or crypto key",
            )),
        }
    }
}

/// `$group-id-type-choice` — UUID or bytes.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum GroupIdChoice {
    /// UUID (CBOR tag 37).
    Uuid([u8; 16]),
    /// Generic tagged bytes (CBOR tag 560).
    Bytes(Vec<u8>),
}

impl Serialize for GroupIdChoice {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        match self {
            GroupIdChoice::Uuid(u) => value::serialize_tagged_bytes(TAG_UUID, u, s),
            GroupIdChoice::Bytes(b) => value::serialize_tagged_bytes(TAG_BYTES, b, s),
        }
    }
}

impl<'de> Deserialize<'de> for GroupIdChoice {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let val = Value::deserialize(d)?;
        match val {
            Value::Tag(TAG_UUID, inner) => {
                let b = inner
                    .into_bytes()
                    .ok_or_else(|| serde::de::Error::custom("tag 37 must wrap bytes"))?;
                Ok(GroupIdChoice::Uuid(b.try_into().map_err(|_| {
                    serde::de::Error::custom("UUID must be 16 bytes")
                })?))
            }
            Value::Tag(TAG_BYTES, inner) => {
                Ok(GroupIdChoice::Bytes(inner.into_bytes().ok_or_else(
                    || serde::de::Error::custom("tag 560 must wrap bytes"),
                )?))
            }
            _ => Err(serde::de::Error::custom("expected tagged UUID or bytes")),
        }
    }
}

/// `$measured-element-type-choice` — OID, UUID, uint, or text.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum MeasuredElement {
    /// OID (CBOR tag 111).
    Oid(Vec<u8>),
    /// UUID (CBOR tag 37).
    Uuid([u8; 16]),
    /// Unsigned integer.
    Uint(u64),
    /// Text string.
    Text(String),
}

impl Serialize for MeasuredElement {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        match self {
            MeasuredElement::Oid(b) => value::serialize_tagged_bytes(TAG_OID, b, s),
            MeasuredElement::Uuid(u) => value::serialize_tagged_bytes(TAG_UUID, u, s),
            MeasuredElement::Uint(n) => s.serialize_u64(*n),
            MeasuredElement::Text(t) => s.serialize_str(t),
        }
    }
}

impl<'de> Deserialize<'de> for MeasuredElement {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let val = Value::deserialize(d)?;
        match val {
            Value::Tag(TAG_OID, inner) => {
                Ok(MeasuredElement::Oid(inner.into_bytes().ok_or_else(
                    || serde::de::Error::custom("tag 111 must wrap bytes"),
                )?))
            }
            Value::Tag(TAG_UUID, inner) => {
                let b = inner
                    .into_bytes()
                    .ok_or_else(|| serde::de::Error::custom("tag 37 must wrap bytes"))?;
                Ok(MeasuredElement::Uuid(b.try_into().map_err(|_| {
                    serde::de::Error::custom("UUID must be 16 bytes")
                })?))
            }
            Value::Integer(n) => {
                Ok(MeasuredElement::Uint(n.try_into().map_err(|_| {
                    serde::de::Error::custom("expected unsigned integer")
                })?))
            }
            Value::Text(t) => Ok(MeasuredElement::Text(t)),
            _ => Err(serde::de::Error::custom(
                "expected OID, UUID, uint, or text",
            )),
        }
    }
}

/// `$crypto-key-type-choice` — covers CBOR tags 554–562.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum CryptoKey {
    /// PEM SubjectPublicKeyInfo (CBOR tag 554).
    PkixBase64Key(String),
    /// PEM X.509 certificate (CBOR tag 555).
    PkixBase64Cert(String),
    /// PEM X.509 certificate chain (CBOR tag 556).
    PkixBase64CertPath(String),
    /// Key thumbprint `[alg, val]` (CBOR tag 557).
    KeyThumbprint(Digest),
    /// CBOR-encoded COSE_Key (CBOR tag 558).
    CoseKey(Vec<u8>),
    /// Certificate thumbprint (CBOR tag 559).
    CertThumbprint(Digest),
    /// Certification path thumbprint (CBOR tag 561).
    CertPathThumbprint(Digest),
    /// ASN.1 DER X.509 certificate (CBOR tag 562).
    PkixAsn1DerCert(Vec<u8>),
    /// Opaque key identifier (CBOR tag 560).
    Bytes(Vec<u8>),
}

impl Serialize for CryptoKey {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        match self {
            CryptoKey::PkixBase64Key(v) => value::serialize_tagged(TAG_PKIX_BASE64_KEY, v, s),
            CryptoKey::PkixBase64Cert(v) => value::serialize_tagged(TAG_PKIX_BASE64_CERT, v, s),
            CryptoKey::PkixBase64CertPath(v) => {
                value::serialize_tagged(TAG_PKIX_BASE64_CERT_PATH, v, s)
            }
            CryptoKey::KeyThumbprint(v) => value::serialize_tagged(TAG_KEY_THUMBPRINT, v, s),
            CryptoKey::CoseKey(v) => value::serialize_tagged_bytes(TAG_COSE_KEY, v, s),
            CryptoKey::CertThumbprint(v) => value::serialize_tagged(TAG_CERT_THUMBPRINT, v, s),
            CryptoKey::CertPathThumbprint(v) => {
                value::serialize_tagged(TAG_CERT_PATH_THUMBPRINT, v, s)
            }
            CryptoKey::PkixAsn1DerCert(v) => {
                value::serialize_tagged_bytes(TAG_PKIX_ASN1DER_CERT, v, s)
            }
            CryptoKey::Bytes(v) => value::serialize_tagged_bytes(TAG_BYTES, v, s),
        }
    }
}

impl<'de> Deserialize<'de> for CryptoKey {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let val = Value::deserialize(d)?;
        match val {
            Value::Tag(TAG_PKIX_BASE64_KEY, inner) => match *inner {
                Value::Text(t) => Ok(CryptoKey::PkixBase64Key(t)),
                _ => Err(serde::de::Error::custom("tag 554 must wrap text")),
            },
            Value::Tag(TAG_PKIX_BASE64_CERT, inner) => match *inner {
                Value::Text(t) => Ok(CryptoKey::PkixBase64Cert(t)),
                _ => Err(serde::de::Error::custom("tag 555 must wrap text")),
            },
            Value::Tag(TAG_PKIX_BASE64_CERT_PATH, inner) => match *inner {
                Value::Text(t) => Ok(CryptoKey::PkixBase64CertPath(t)),
                _ => Err(serde::de::Error::custom("tag 556 must wrap text")),
            },
            Value::Tag(TAG_KEY_THUMBPRINT, inner) => {
                let arr = inner
                    .into_array()
                    .ok_or_else(|| serde::de::Error::custom("tag 557 must wrap array"))?;
                Ok(CryptoKey::KeyThumbprint(digest_from_value_array(arr)?))
            }
            Value::Tag(TAG_COSE_KEY, inner) => match *inner {
                Value::Bytes(b) => Ok(CryptoKey::CoseKey(b)),
                _ => Err(serde::de::Error::custom("tag 558 must wrap bytes")),
            },
            Value::Tag(TAG_CERT_THUMBPRINT, inner) => {
                let arr = inner
                    .into_array()
                    .ok_or_else(|| serde::de::Error::custom("tag 559 must wrap array"))?;
                Ok(CryptoKey::CertThumbprint(digest_from_value_array(arr)?))
            }
            Value::Tag(TAG_CERT_PATH_THUMBPRINT, inner) => {
                let arr = inner
                    .into_array()
                    .ok_or_else(|| serde::de::Error::custom("tag 561 must wrap array"))?;
                Ok(CryptoKey::CertPathThumbprint(digest_from_value_array(arr)?))
            }
            Value::Tag(TAG_PKIX_ASN1DER_CERT, inner) => match *inner {
                Value::Bytes(b) => Ok(CryptoKey::PkixAsn1DerCert(b)),
                _ => Err(serde::de::Error::custom("tag 562 must wrap bytes")),
            },
            Value::Tag(TAG_BYTES, inner) => match *inner {
                Value::Bytes(b) => Ok(CryptoKey::Bytes(b)),
                _ => Err(serde::de::Error::custom("tag 560 must wrap bytes")),
            },
            _ => Err(serde::de::Error::custom("expected a tagged crypto key")),
        }
    }
}

/// `linked-tag-map` — references another tag.
#[derive(Clone, Debug, PartialEq, CborSerialize, CborDeserialize)]
pub struct LinkedTagMap {
    /// `linked-tag-id` (key 0).
    #[cbor(key = 0)]
    pub linked_tag_id: TagIdChoice,
    /// `tag-rel` (key 1): supplements(0) or replaces(1).
    #[cbor(key = 1)]
    pub tag_rel: i64,
}

// ---------------------------------------------------------------------------
// Digest helper
// ---------------------------------------------------------------------------

/// Deserialize a `[alg, val]` array of [`Value`]s into a [`Digest`].
fn digest_from_value_array<E: serde::de::Error>(arr: Vec<Value>) -> Result<Digest, E> {
    if arr.len() != 2 {
        return Err(E::custom("digest must be [alg, val]"));
    }
    let mut it = arr.into_iter();
    let alg = match it.next().unwrap() {
        Value::Integer(n) => {
            i64::try_from(n).map_err(|_| E::custom("digest alg out of i64 range"))?
        }
        _ => return Err(E::custom("digest alg must be int")),
    };
    let val = match it.next().unwrap() {
        Value::Bytes(b) => b,
        _ => return Err(E::custom("digest val must be bytes")),
    };
    Ok(Digest::new(alg, val))
}

// ---------------------------------------------------------------------------
// From conversions for type-choice enums
// ---------------------------------------------------------------------------

impl From<String> for TagIdChoice {
    fn from(s: String) -> Self {
        Self::Text(s)
    }
}

impl From<&str> for TagIdChoice {
    fn from(s: &str) -> Self {
        Self::Text(s.to_owned())
    }
}

impl From<[u8; 16]> for TagIdChoice {
    fn from(u: [u8; 16]) -> Self {
        Self::Uuid(u)
    }
}

impl From<String> for MeasuredElement {
    fn from(s: String) -> Self {
        Self::Text(s)
    }
}

impl From<&str> for MeasuredElement {
    fn from(s: &str) -> Self {
        Self::Text(s.to_owned())
    }
}

impl From<u64> for MeasuredElement {
    fn from(n: u64) -> Self {
        Self::Uint(n)
    }
}

// ---------------------------------------------------------------------------
// Display impls
// ---------------------------------------------------------------------------

fn hex_short(bytes: &[u8]) -> String {
    if bytes.len() <= 16 {
        hex_encode(bytes)
    } else {
        format!("{}..({} bytes)", hex_encode(&bytes[..8]), bytes.len())
    }
}

fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

fn format_uuid(bytes: &[u8; 16]) -> String {
    format!(
        "{}-{}-{}-{}-{}",
        hex_encode(&bytes[0..4]),
        hex_encode(&bytes[4..6]),
        hex_encode(&bytes[6..8]),
        hex_encode(&bytes[8..10]),
        hex_encode(&bytes[10..16]),
    )
}

impl core::fmt::Display for TagIdChoice {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            TagIdChoice::Text(t) => write!(f, "{}", t),
            TagIdChoice::Uuid(u) => write!(f, "{}", format_uuid(u)),
        }
    }
}

impl core::fmt::Display for ClassIdChoice {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            ClassIdChoice::Oid(b) => write!(f, "oid:{}", hex_encode(b)),
            ClassIdChoice::Uuid(u) => write!(f, "{}", format_uuid(u)),
            ClassIdChoice::Bytes(b) => write!(f, "bytes:{}", hex_short(b)),
        }
    }
}

impl core::fmt::Display for InstanceIdChoice {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            InstanceIdChoice::Ueid(b) => write!(f, "ueid:{}", hex_short(b)),
            InstanceIdChoice::Uuid(u) => write!(f, "{}", format_uuid(u)),
            InstanceIdChoice::Bytes(b) => write!(f, "bytes:{}", hex_short(b)),
            InstanceIdChoice::PkixBase64Key(s) => write!(f, "pkix-key:{:.32}...", s),
            InstanceIdChoice::PkixBase64Cert(s) => write!(f, "pkix-cert:{:.32}...", s),
            InstanceIdChoice::CoseKey(b) => write!(f, "cose-key:({} bytes)", b.len()),
            InstanceIdChoice::KeyThumbprint(d) => {
                write!(f, "key-tp:alg={}:{}", d.alg(), hex_short(d.value()))
            }
            InstanceIdChoice::CertThumbprint(d) => {
                write!(f, "cert-tp:alg={}:{}", d.alg(), hex_short(d.value()))
            }
            InstanceIdChoice::PkixAsn1DerCert(b) => write!(f, "asn1-cert:({} bytes)", b.len()),
        }
    }
}

impl core::fmt::Display for GroupIdChoice {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            GroupIdChoice::Uuid(u) => write!(f, "{}", format_uuid(u)),
            GroupIdChoice::Bytes(b) => write!(f, "bytes:{}", hex_short(b)),
        }
    }
}

impl core::fmt::Display for MeasuredElement {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            MeasuredElement::Oid(b) => write!(f, "oid:{}", hex_encode(b)),
            MeasuredElement::Uuid(u) => write!(f, "{}", format_uuid(u)),
            MeasuredElement::Uint(n) => write!(f, "{}", n),
            MeasuredElement::Text(t) => write!(f, "{}", t),
        }
    }
}

impl core::fmt::Display for CryptoKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            CryptoKey::PkixBase64Key(s) => write!(f, "pkix-key:{:.40}...", s),
            CryptoKey::PkixBase64Cert(s) => write!(f, "pkix-cert:{:.40}...", s),
            CryptoKey::PkixBase64CertPath(s) => write!(f, "pkix-cert-path:{:.40}...", s),
            CryptoKey::KeyThumbprint(d) => {
                write!(f, "key-tp:alg={}:{}", d.alg(), hex_short(d.value()))
            }
            CryptoKey::CoseKey(b) => write!(f, "cose-key:({} bytes)", b.len()),
            CryptoKey::CertThumbprint(d) => {
                write!(f, "cert-tp:alg={}:{}", d.alg(), hex_short(d.value()))
            }
            CryptoKey::CertPathThumbprint(d) => {
                write!(f, "cert-path-tp:alg={}:{}", d.alg(), hex_short(d.value()))
            }
            CryptoKey::PkixAsn1DerCert(b) => write!(f, "asn1-cert:({} bytes)", b.len()),
            CryptoKey::Bytes(b) => write!(f, "bytes:{}", hex_short(b)),
        }
    }
}
