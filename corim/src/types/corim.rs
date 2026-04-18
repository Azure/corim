// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Top-level `corim-map` and related types.

#[allow(unused_imports)]
use crate::nostd_prelude::*;
use corim_macros::{CborDeserialize, CborSerialize};
use serde::{Deserialize, Serialize};

use super::common::{EntityMap, TagIdentity, ValidityMap};
use super::measurement::{Digest, DigestAlg};
use super::tags::*;
use crate::cbor;
use crate::cbor::value::{self, Value};
use crate::Validate;

// ---------------------------------------------------------------------------
// corim-id
// ---------------------------------------------------------------------------

/// `$corim-id-type-choice` — text or UUID.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum CorimId {
    /// A text CoRIM identifier.
    Text(String),
    /// A UUID CoRIM identifier (CBOR tag 37).
    Uuid([u8; 16]),
}

impl Serialize for CorimId {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        match self {
            CorimId::Text(t) => s.serialize_str(t),
            CorimId::Uuid(u) => value::serialize_tagged_bytes(TAG_UUID, u, s),
        }
    }
}

impl<'de> Deserialize<'de> for CorimId {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let val = Value::deserialize(d)?;
        match val {
            Value::Text(t) => Ok(CorimId::Text(t)),
            Value::Tag(TAG_UUID, inner) => {
                let b = inner
                    .into_bytes()
                    .ok_or_else(|| serde::de::Error::custom("tag 37 must wrap bytes"))?;
                Ok(CorimId::Uuid(b.try_into().map_err(|_| {
                    serde::de::Error::custom("UUID must be 16 bytes")
                })?))
            }
            // Accept bare 16-byte bytes as untagged UUID for interop.
            Value::Bytes(b) if b.len() == 16 => {
                Ok(CorimId::Uuid(b.try_into().map_err(|_| {
                    serde::de::Error::custom("UUID must be 16 bytes")
                })?))
            }
            _ => Err(serde::de::Error::custom("expected text or tagged UUID")),
        }
    }
}

impl core::fmt::Display for CorimId {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            CorimId::Text(t) => write!(f, "{}", t),
            CorimId::Uuid(u) => {
                let hex = |s: &[u8]| -> String { s.iter().map(|b| format!("{:02x}", b)).collect() };
                write!(
                    f,
                    "{}-{}-{}-{}-{}",
                    hex(&u[0..4]),
                    hex(&u[4..6]),
                    hex(&u[6..8]),
                    hex(&u[8..10]),
                    hex(&u[10..16])
                )
            }
        }
    }
}

impl From<String> for CorimId {
    fn from(s: String) -> Self {
        Self::Text(s)
    }
}

impl From<&str> for CorimId {
    fn from(s: &str) -> Self {
        Self::Text(s.to_owned())
    }
}

impl From<[u8; 16]> for CorimId {
    fn from(u: [u8; 16]) -> Self {
        Self::Uuid(u)
    }
}

// ---------------------------------------------------------------------------
// profile
// ---------------------------------------------------------------------------

/// `$profile-type-choice` — URI or OID.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum ProfileChoice {
    /// A URI profile identifier.
    Uri(String),
    /// An OID profile identifier (CBOR tag 111).
    Oid(Vec<u8>),
}

impl Serialize for ProfileChoice {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        match self {
            ProfileChoice::Uri(u) => s.serialize_str(u),
            ProfileChoice::Oid(b) => value::serialize_tagged_bytes(TAG_OID, b, s),
        }
    }
}

impl<'de> Deserialize<'de> for ProfileChoice {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let val = Value::deserialize(d)?;
        match val {
            Value::Text(t) => Ok(ProfileChoice::Uri(t)),
            Value::Tag(TAG_OID, inner) => {
                Ok(ProfileChoice::Oid(inner.into_bytes().ok_or_else(|| {
                    serde::de::Error::custom("tag 111 must wrap bytes")
                })?))
            }
            _ => Err(serde::de::Error::custom("expected text URI or tagged OID")),
        }
    }
}

impl core::fmt::Display for ProfileChoice {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            ProfileChoice::Uri(u) => write!(f, "{}", u),
            ProfileChoice::Oid(b) => {
                write!(f, "oid:")?;
                for byte in b {
                    write!(f, "{:02x}", byte)?;
                }
                Ok(())
            }
        }
    }
}

// ---------------------------------------------------------------------------
// ConciseTagChoice
// ---------------------------------------------------------------------------

/// A tag entry in the CoRIM `tags` array.
///
/// Only CoMID (tag 506) is fully modeled. CoSWID (505) and CoTL (508)
/// are stored as opaque bytes.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum ConciseTagChoice {
    /// CoMID tag (CBOR tag 506 wrapping bytes).
    Comid(Vec<u8>),
    /// CoSWID tag (CBOR tag 505 wrapping bytes).
    Coswid(Vec<u8>),
    /// CoTL tag (CBOR tag 508 wrapping bytes).
    Cotl(Vec<u8>),
    /// Unknown tag type.
    Unknown(u64, Vec<u8>),
}

impl Serialize for ConciseTagChoice {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        match self {
            ConciseTagChoice::Comid(bytes) => value::serialize_tagged_bytes(TAG_COMID, bytes, s),
            ConciseTagChoice::Coswid(bytes) => value::serialize_tagged_bytes(TAG_COSWID, bytes, s),
            ConciseTagChoice::Cotl(bytes) => value::serialize_tagged_bytes(TAG_COTL, bytes, s),
            ConciseTagChoice::Unknown(tag, bytes) => {
                let val = Value::Tag(*tag, Box::new(Value::Bytes(bytes.clone())));
                val.serialize(s)
            }
        }
    }
}

impl<'de> Deserialize<'de> for ConciseTagChoice {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let val = Value::deserialize(d)?;
        match val {
            Value::Tag(TAG_COMID, inner) => match *inner {
                Value::Bytes(b) => Ok(ConciseTagChoice::Comid(b)),
                _ => Err(serde::de::Error::custom("tag 506 must wrap bytes")),
            },
            Value::Tag(TAG_COSWID, inner) => match *inner {
                Value::Bytes(b) => Ok(ConciseTagChoice::Coswid(b)),
                _ => Err(serde::de::Error::custom("tag 505 must wrap bytes")),
            },
            Value::Tag(TAG_COTL, inner) => match *inner {
                Value::Bytes(b) => Ok(ConciseTagChoice::Cotl(b)),
                _ => Err(serde::de::Error::custom("tag 508 must wrap bytes")),
            },
            Value::Tag(tag, inner) => {
                let raw_bytes = cbor::encode(&*inner).map_err(serde::de::Error::custom)?;
                Ok(ConciseTagChoice::Unknown(tag, raw_bytes))
            }
            _ => Err(serde::de::Error::custom("expected a tagged concise tag")),
        }
    }
}

// ---------------------------------------------------------------------------
// corim-locator-map
// ---------------------------------------------------------------------------

/// `corim-locator-map` — locator for dependent manifests.
///
/// CDDL:
/// ```text
/// corim-locator-map = {
///   &(href: 0) => uri / [+ uri],
///   ? &(thumbprint: 1) => eatmc.digest / [eatmc.digest],
/// }
/// ```
#[derive(Clone, Debug, PartialEq, CborSerialize, CborDeserialize)]
pub struct CorimLocator {
    /// `href` (key 0): URI or array of URIs.
    #[cbor(key = 0)]
    pub href: CorimLocatorHref,
    /// `thumbprint` (key 1): optional digest(s).
    #[cbor(key = 1, optional)]
    pub thumbprint: Option<CorimLocatorThumbprint>,
}

/// Href can be a single URI string or an array of URI strings.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum CorimLocatorHref {
    /// Single URI.
    Single(String),
    /// Multiple URIs.
    Multiple(Vec<String>),
}

impl Serialize for CorimLocatorHref {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        match self {
            CorimLocatorHref::Single(uri) => s.serialize_str(uri),
            CorimLocatorHref::Multiple(uris) => uris.serialize(s),
        }
    }
}

impl<'de> Deserialize<'de> for CorimLocatorHref {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let val = Value::deserialize(d)?;
        match val {
            Value::Text(t) => Ok(CorimLocatorHref::Single(t)),
            Value::Array(arr) => {
                let mut uris = Vec::new();
                for v in arr {
                    match v {
                        Value::Text(t) => uris.push(t),
                        _ => {
                            return Err(serde::de::Error::custom("href array must contain strings"))
                        }
                    }
                }
                Ok(CorimLocatorHref::Multiple(uris))
            }
            _ => Err(serde::de::Error::custom("expected text or array for href")),
        }
    }
}

/// Thumbprint can be a single digest or array of digests.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum CorimLocatorThumbprint {
    /// Single digest.
    Single(Digest),
    /// Multiple digests.
    Multiple(Vec<Digest>),
}

impl Serialize for CorimLocatorThumbprint {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        match self {
            CorimLocatorThumbprint::Single(d) => d.serialize(s),
            CorimLocatorThumbprint::Multiple(ds) => ds.serialize(s),
        }
    }
}

impl<'de> Deserialize<'de> for CorimLocatorThumbprint {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let val = Value::deserialize(d)?;
        match val {
            Value::Array(arr) if !arr.is_empty() => {
                // Check if it's a single digest [alg, val] or array of digests [[alg,val],...]
                match &arr[0] {
                    Value::Array(_) => {
                        // Array of digests: [[alg, val], ...]
                        let mut ds = Vec::new();
                        for item in arr {
                            match item {
                                Value::Array(pair) if pair.len() == 2 => {
                                    let mut it = pair.into_iter();
                                    let alg = match it.next().ok_or_else(|| {
                                        serde::de::Error::custom("digest must be [alg, val]")
                                    })? {
                                        Value::Integer(n) => {
                                            DigestAlg::Int(i64::try_from(n).map_err(|_| {
                                                serde::de::Error::custom(
                                                    "digest alg out of i64 range",
                                                )
                                            })?)
                                        }
                                        Value::Text(t) => DigestAlg::Text(t),
                                        _ => {
                                            return Err(serde::de::Error::custom(
                                                "digest alg must be int or text",
                                            ))
                                        }
                                    };
                                    let v = match it.next().ok_or_else(|| {
                                        serde::de::Error::custom("digest must be [alg, val]")
                                    })? {
                                        Value::Bytes(b) => b,
                                        _ => {
                                            return Err(serde::de::Error::custom(
                                                "digest val must be bytes",
                                            ))
                                        }
                                    };
                                    ds.push(Digest(alg, v));
                                }
                                _ => {
                                    return Err(serde::de::Error::custom(
                                        "digest must be [alg, val]",
                                    ))
                                }
                            }
                        }
                        Ok(CorimLocatorThumbprint::Multiple(ds))
                    }
                    _ => {
                        // Single digest [alg, val]
                        if arr.len() != 2 {
                            return Err(serde::de::Error::custom("digest must be [alg, val]"));
                        }
                        let mut it = arr.into_iter();
                        let alg = match it
                            .next()
                            .ok_or_else(|| serde::de::Error::custom("digest must be [alg, val]"))?
                        {
                            Value::Integer(n) => {
                                DigestAlg::Int(i64::try_from(n).map_err(|_| {
                                    serde::de::Error::custom("digest alg out of i64 range")
                                })?)
                            }
                            Value::Text(t) => DigestAlg::Text(t),
                            _ => {
                                return Err(serde::de::Error::custom(
                                    "digest alg must be int or text",
                                ))
                            }
                        };
                        let v = match it
                            .next()
                            .ok_or_else(|| serde::de::Error::custom("digest must be [alg, val]"))?
                        {
                            Value::Bytes(b) => b,
                            _ => return Err(serde::de::Error::custom("digest val must be bytes")),
                        };
                        Ok(CorimLocatorThumbprint::Single(Digest(alg, v)))
                    }
                }
            }
            _ => Err(serde::de::Error::custom("expected array for thumbprint")),
        }
    }
}

// ---------------------------------------------------------------------------
// corim-signer-map
// ---------------------------------------------------------------------------

/// `corim-signer-map` — identifies the signer of a CoRIM.
#[derive(Clone, Debug, PartialEq, CborSerialize, CborDeserialize)]
pub struct CorimSignerMap {
    /// `signer-name` (key 0).
    #[cbor(key = 0)]
    pub signer_name: String,
    /// `signer-uri` (key 1).
    #[cbor(key = 1, optional)]
    pub signer_uri: Option<String>,
}

// ---------------------------------------------------------------------------
// corim-meta-map
// ---------------------------------------------------------------------------

/// `corim-meta-map` — metadata about a signed CoRIM.
#[derive(Clone, Debug, PartialEq, CborSerialize, CborDeserialize)]
pub struct CorimMetaMap {
    /// `signer` (key 0).
    #[cbor(key = 0)]
    pub signer: CorimSignerMap,
    /// `signature-validity` (key 1).
    #[cbor(key = 1, optional)]
    pub signature_validity: Option<ValidityMap>,
}

// ---------------------------------------------------------------------------
// concise-tl-tag (CoTL)
// ---------------------------------------------------------------------------

/// `concise-tl-tag` — a tag list.
#[derive(Clone, Debug, PartialEq, CborSerialize, CborDeserialize)]
pub struct ConciseTlTag {
    /// `tag-identity` (key 0).
    #[cbor(key = 0)]
    pub tag_identity: TagIdentity,
    /// `tags-list` (key 1): list of tag identities.
    #[cbor(key = 1)]
    pub tags_list: Vec<TagIdentity>,
    /// `tl-validity` (key 2): validity period.
    #[cbor(key = 2)]
    pub tl_validity: ValidityMap,
}

// ---------------------------------------------------------------------------
// corim-map
// ---------------------------------------------------------------------------

/// `corim-map` — top-level CoRIM structure.
#[derive(Clone, Debug, PartialEq, CborSerialize, CborDeserialize)]
pub struct CorimMap {
    /// `id` (key 0): CoRIM identifier.
    #[cbor(key = 0)]
    pub id: CorimId,
    /// `tags` (key 1): array of concise tags.
    #[cbor(key = 1)]
    pub tags: Vec<ConciseTagChoice>,
    /// `dependent-rims` (key 2): optional locators.
    #[cbor(key = 2, optional)]
    pub dependent_rims: Option<Vec<CorimLocator>>,
    /// `profile` (key 3): optional profile identifier.
    #[cbor(key = 3, optional)]
    pub profile: Option<ProfileChoice>,
    /// `rim-validity` (key 4): optional validity period.
    #[cbor(key = 4, optional)]
    pub rim_validity: Option<ValidityMap>,
    /// `entities` (key 5): optional entity list.
    #[cbor(key = 5, optional)]
    pub entities: Option<Vec<EntityMap>>,
}

impl Validate for ConciseTlTag {
    fn valid(&self) -> Result<(), String> {
        // tags-list must be non-empty (CDDL: [+ tag-identity-map])
        if self.tags_list.is_empty() {
            return Err("tags-list must not be empty".into());
        }
        // Validate validity window consistency
        if let Some(nb) = self.tl_validity.not_before {
            if nb.epoch_secs() > self.tl_validity.not_after.epoch_secs() {
                return Err("not-before must be <= not-after".into());
            }
        }
        Ok(())
    }
}

impl Validate for CorimMap {
    fn valid(&self) -> Result<(), String> {
        // tags must be non-empty
        if self.tags.is_empty() {
            return Err("tags list must not be empty".into());
        }
        // Validate validity window consistency
        if let Some(ref validity) = self.rim_validity {
            if let Some(nb) = validity.not_before {
                if nb.epoch_secs() > validity.not_after.epoch_secs() {
                    return Err("rim-validity: not-before must be <= not-after".into());
                }
            }
        }
        // Validate entities if present
        if let Some(ref entities) = self.entities {
            if entities.is_empty() {
                return Err("entities list must not be empty".into());
            }
        }
        Ok(())
    }
}
