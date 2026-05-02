// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Protected COSE_Sign1 header for signed CoRIMs (draft-ietf-rats-corim-10
//! §4.2.1).
//!
//! Models the decoded contents of the `protected` `bstr` element of a
//! `#6.18(COSE_Sign1)` signed CoRIM:
//!
//! ```text
//! protected-corim-header-map-inline = {
//!   &(alg: 1) => int,
//!   &(content-type: 3) => "application/rim+cbor",
//!   meta-group,
//!   * cose-label => cose-value,
//! }
//! ```
//!
//! Also handles the hash-envelope (draft-ietf-cose-hash-envelope) variant
//! and the X.509 header parameters from RFC 9360.

#[allow(unused_imports)]
use crate::nostd_prelude::*;
use serde::{Deserialize, Serialize};

use super::super::corim::CorimMetaMap;
use super::super::measurement::DigestAlg;
use super::algorithm::CoseAlgorithm;
use super::cwt::{value_to_epoch, CwtClaims, CWT_CLAIM_EXP, CWT_CLAIM_NBF, CWT_CLAIM_SUB};
use super::x509::{
    deserialize_cose_cert_hash, deserialize_cose_x509, serialize_cose_x509, CoseCertHash, CoseX509,
    COSE_HEADER_KID, COSE_HEADER_X5BAG, COSE_HEADER_X5CHAIN, COSE_HEADER_X5T, COSE_HEADER_X5U,
};
use crate::cbor;
use crate::cbor::value::Value;
use crate::Validate;

// ===================================================================
// COSE Header Label Constants (RFC 9052 / draft-ietf-rats-corim-10 §4.2)
// ===================================================================

/// COSE header: `alg` (key 1) — Algorithm identifier.
pub const COSE_HEADER_ALG: i64 = 1;
/// COSE header: `content-type` (key 3).
pub const COSE_HEADER_CONTENT_TYPE: i64 = 3;
/// CoRIM protected header: `corim-meta` (key 8).
pub const COSE_HEADER_CORIM_META: i64 = 8;
/// CoRIM protected header: `CWT-Claims` (key 15) per RFC 9597.
pub const COSE_HEADER_CWT_CLAIMS: i64 = 15;
/// COSE Hash Envelope: `payload_hash_alg` (key 258).
pub const COSE_HEADER_PAYLOAD_HASH_ALG: i64 = 258;
/// COSE Hash Envelope: `payload_preimage_content_type` (key 259).
pub const COSE_HEADER_PAYLOAD_PREIMAGE_CT: i64 = 259;
/// COSE Hash Envelope: `payload_location` (key 260).
pub const COSE_HEADER_PAYLOAD_LOCATION: i64 = 260;

/// Expected `content-type` value for inline CoRIM signing.
pub const CORIM_CONTENT_TYPE: &str = "application/rim+cbor";

// ===================================================================
// Protected CoRIM Header Map (§4.2.1)
// ===================================================================

/// Protected CoRIM header map (§4.2.1).
///
/// Contains the algorithm identifier, content type, and signer metadata.
/// Supports both inline signing and hash-envelope modes.
///
/// ```text
/// protected-corim-header-map-inline = {
///   &(alg: 1) => int,
///   &(content-type: 3) => "application/rim+cbor",
///   meta-group,
///   * cose-label => cose-value,
/// }
/// ```
#[derive(Clone, Debug, PartialEq)]
pub struct ProtectedCorimHeaderMap {
    /// COSE algorithm identifier (key 1).
    pub alg: CoseAlgorithm,
    /// Content type (key 3) — present for inline signing.
    /// Should be "application/rim+cbor" per the spec.
    pub content_type: Option<String>,

    // Hash-envelope fields (draft-ietf-cose-hash-envelope)
    /// `payload_hash_alg` (key 258) — hash algorithm for hash-envelope mode.
    pub payload_hash_alg: Option<i64>,
    /// `payload_preimage_content_type` (key 259) — content type for hash-envelope mode.
    pub payload_preimage_content_type: Option<String>,
    /// `payload_location` (key 260) — resource locator for hash-envelope mode.
    pub payload_location: Option<String>,

    /// `corim-meta` (key 8): Metadata about the CoRIM signer (legacy).
    /// Stored as the decoded `CorimMetaMap`.
    pub corim_meta: Option<CorimMetaMap>,
    /// `CWT-Claims` (key 15): CWT claims identifying the signer.
    pub cwt_claims: Option<CwtClaims>,

    // X.509 certificate fields (RFC 9360)
    /// `kid` (key 4): Key identifier (opaque bytes).
    pub kid: Option<Vec<u8>>,
    /// `x5bag` (key 32): Unordered bag of X.509 certificates.
    pub x5bag: Option<CoseX509>,
    /// `x5chain` (key 33): Ordered chain of X.509 certificates.
    pub x5chain: Option<CoseX509>,
    /// `x5t` (key 34): Hash of the end-entity X.509 certificate.
    pub x5t: Option<CoseCertHash>,
    /// `x5u` (key 35): URI pointing to an X.509 certificate.
    pub x5u: Option<String>,

    /// Any additional COSE header labels not explicitly modeled above.
    pub extra: BTreeMap<i64, Value>,
}

impl ProtectedCorimHeaderMap {
    /// Check whether this header uses hash-envelope mode.
    pub fn is_hash_envelope(&self) -> bool {
        self.payload_hash_alg.is_some()
    }
}

/// Builder for [`ProtectedCorimHeaderMap`].
///
/// The only required field is `alg`. At least one of `corim_meta` or
/// `cwt_claims` should be set to satisfy the meta-group constraint (§4.2.1),
/// but this is validated at sign time, not build time.
///
/// # Example
///
/// ```
/// use corim::types::{CoseAlgorithm, ProtectedCorimHeaderMapBuilder};
/// use corim::types::corim::{CorimMetaMap, CorimSignerMap};
///
/// let header = ProtectedCorimHeaderMapBuilder::new(CoseAlgorithm::Es256)
///     .content_type("application/rim+cbor")
///     .corim_meta(CorimMetaMap {
///         signer: CorimSignerMap {
///             signer_name: "ACME Ltd.".into(),
///             signer_uri: None,
///         },
///         signature_validity: None,
///     })
///     .build();
/// ```
#[must_use]
pub struct ProtectedCorimHeaderMapBuilder {
    inner: ProtectedCorimHeaderMap,
}

impl ProtectedCorimHeaderMapBuilder {
    /// Create a new builder with the required algorithm identifier.
    pub fn new(alg: CoseAlgorithm) -> Self {
        Self {
            inner: ProtectedCorimHeaderMap {
                alg,
                content_type: None,
                payload_hash_alg: None,
                payload_preimage_content_type: None,
                payload_location: None,
                corim_meta: None,
                cwt_claims: None,
                kid: None,
                x5bag: None,
                x5chain: None,
                x5t: None,
                x5u: None,
                extra: BTreeMap::new(),
            },
        }
    }

    /// Set the content type (key 3) for inline signing mode.
    pub fn content_type(mut self, ct: impl Into<String>) -> Self {
        self.inner.content_type = Some(ct.into());
        self
    }

    /// Set `corim-meta` (key 8).
    pub fn corim_meta(mut self, meta: CorimMetaMap) -> Self {
        self.inner.corim_meta = Some(meta);
        self
    }

    /// Set CWT claims (key 15).
    pub fn cwt_claims(mut self, claims: CwtClaims) -> Self {
        self.inner.cwt_claims = Some(claims);
        self
    }

    /// Set the key identifier (key 4).
    pub fn kid(mut self, kid: Vec<u8>) -> Self {
        self.inner.kid = Some(kid);
        self
    }

    /// Set the X.509 certificate bag (key 32).
    pub fn x5bag(mut self, bag: CoseX509) -> Self {
        self.inner.x5bag = Some(bag);
        self
    }

    /// Set the X.509 certificate chain (key 33).
    pub fn x5chain(mut self, chain: CoseX509) -> Self {
        self.inner.x5chain = Some(chain);
        self
    }

    /// Set the X.509 certificate thumbprint (key 34).
    pub fn x5t(mut self, hash: CoseCertHash) -> Self {
        self.inner.x5t = Some(hash);
        self
    }

    /// Set the X.509 certificate URI (key 35).
    pub fn x5u(mut self, uri: impl Into<String>) -> Self {
        self.inner.x5u = Some(uri.into());
        self
    }

    /// Set hash-envelope payload hash algorithm (key 258).
    pub fn payload_hash_alg(mut self, alg: i64) -> Self {
        self.inner.payload_hash_alg = Some(alg);
        self
    }

    /// Set hash-envelope payload preimage content type (key 259).
    pub fn payload_preimage_content_type(mut self, ct: impl Into<String>) -> Self {
        self.inner.payload_preimage_content_type = Some(ct.into());
        self
    }

    /// Set hash-envelope payload location (key 260).
    pub fn payload_location(mut self, loc: impl Into<String>) -> Self {
        self.inner.payload_location = Some(loc.into());
        self
    }

    /// Add an extra COSE header label.
    pub fn extra(mut self, key: i64, value: Value) -> Self {
        self.inner.extra.insert(key, value);
        self
    }

    /// Build the [`ProtectedCorimHeaderMap`].
    pub fn build(self) -> ProtectedCorimHeaderMap {
        self.inner
    }
}

impl Serialize for ProtectedCorimHeaderMap {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        use serde::ser::SerializeMap;

        let mut count = 1; // alg is required
        if self.content_type.is_some() {
            count += 1;
        }
        if self.payload_hash_alg.is_some() {
            count += 1;
        }
        if self.payload_preimage_content_type.is_some() {
            count += 1;
        }
        if self.payload_location.is_some() {
            count += 1;
        }
        if self.corim_meta.is_some() {
            count += 1;
        }
        if self.cwt_claims.is_some() {
            count += 1;
        }
        if self.kid.is_some() {
            count += 1;
        }
        if self.x5bag.is_some() {
            count += 1;
        }
        if self.x5chain.is_some() {
            count += 1;
        }
        if self.x5t.is_some() {
            count += 1;
        }
        if self.x5u.is_some() {
            count += 1;
        }
        count += self.extra.len();

        let mut map = s.serialize_map(Some(count))?;
        map.serialize_entry(&COSE_HEADER_ALG, &self.alg.to_i64())?;
        if let Some(ref ct) = self.content_type {
            map.serialize_entry(&COSE_HEADER_CONTENT_TYPE, ct)?;
        }
        if let Some(ref meta) = self.corim_meta {
            // corim-meta is CBOR-encoded as bstr .cbor corim-meta-map
            let meta_bytes =
                cbor::encode(meta).map_err(|e| serde::ser::Error::custom(e.to_string()))?;
            // Wrap in a Value::Bytes for proper CBOR bstr encoding
            let meta_val = Value::Bytes(meta_bytes);
            map.serialize_entry(&COSE_HEADER_CORIM_META, &meta_val)?;
        }
        if let Some(ref claims) = self.cwt_claims {
            map.serialize_entry(&COSE_HEADER_CWT_CLAIMS, claims)?;
        }
        // X.509 fields (RFC 9360)
        if let Some(ref kid) = self.kid {
            let kid_val = Value::Bytes(kid.clone());
            map.serialize_entry(&COSE_HEADER_KID, &kid_val)?;
        }
        if let Some(ref x5bag) = self.x5bag {
            map.serialize_entry(&COSE_HEADER_X5BAG, &serialize_cose_x509(x5bag))?;
        }
        if let Some(ref x5chain) = self.x5chain {
            map.serialize_entry(&COSE_HEADER_X5CHAIN, &serialize_cose_x509(x5chain))?;
        }
        if let Some(ref x5t) = self.x5t {
            let alg_val = match &x5t.hash_alg {
                DigestAlg::Int(n) => Value::Integer(*n as i128),
                DigestAlg::Text(t) => Value::Text(t.clone()),
            };
            let arr = Value::Array(alloc::vec![alg_val, Value::Bytes(x5t.hash_value.clone()),]);
            map.serialize_entry(&COSE_HEADER_X5T, &arr)?;
        }
        if let Some(ref x5u) = self.x5u {
            map.serialize_entry(&COSE_HEADER_X5U, x5u)?;
        }
        if let Some(alg) = self.payload_hash_alg {
            map.serialize_entry(&COSE_HEADER_PAYLOAD_HASH_ALG, &alg)?;
        }
        if let Some(ref ct) = self.payload_preimage_content_type {
            map.serialize_entry(&COSE_HEADER_PAYLOAD_PREIMAGE_CT, ct)?;
        }
        if let Some(ref loc) = self.payload_location {
            map.serialize_entry(&COSE_HEADER_PAYLOAD_LOCATION, &loc)?;
        }
        for (k, v) in &self.extra {
            map.serialize_entry(k, v)?;
        }
        map.end()
    }
}

impl<'de> Deserialize<'de> for ProtectedCorimHeaderMap {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let val = Value::deserialize(d)?;
        let map = match val {
            Value::Map(m) => m,
            _ => {
                return Err(serde::de::Error::custom(
                    "protected header must be a CBOR map",
                ))
            }
        };

        let mut alg: Option<i64> = None;
        let mut content_type: Option<String> = None;
        let mut payload_hash_alg: Option<i64> = None;
        let mut payload_preimage_content_type: Option<String> = None;
        let mut payload_location: Option<String> = None;
        let mut corim_meta: Option<CorimMetaMap> = None;
        let mut cwt_claims: Option<CwtClaims> = None;
        let mut kid: Option<Vec<u8>> = None;
        let mut x5bag: Option<CoseX509> = None;
        let mut x5chain: Option<CoseX509> = None;
        let mut x5t: Option<CoseCertHash> = None;
        let mut x5u: Option<String> = None;
        let mut extra = BTreeMap::new();

        // CWT claims may appear flat in the header (keys 1/2/4/5) rather than
        // nested under key 15. Track them separately and synthesize at the end.
        let mut cwt_iss: Option<String> = None;
        let mut cwt_sub: Option<String> = None;
        let mut cwt_exp: Option<i64> = None;
        let mut cwt_nbf: Option<i64> = None;

        for (k, v) in map {
            let key = match &k {
                Value::Integer(n) => i64::try_from(*n)
                    .map_err(|_| serde::de::Error::custom("header key out of range"))?,
                Value::Text(_) => {
                    // Text COSE labels are valid per RFC 9052 but not modeled;
                    // skip since our extra map uses i64 keys only.
                    continue;
                }
                _ => continue,
            };
            match key {
                COSE_HEADER_ALG => {
                    // Key 1 is shared: COSE `alg` (int) vs CWT `iss` (tstr).
                    // Type-dispatch: integer → alg, text → CWT iss.
                    match v {
                        Value::Integer(n) => {
                            alg = Some(
                                i64::try_from(n)
                                    .map_err(|_| serde::de::Error::custom("alg out of range"))?,
                            );
                        }
                        Value::Text(t) => {
                            // CWT `iss` (key 1) appearing flat in the protected header
                            cwt_iss = Some(t);
                        }
                        _ => {
                            return Err(serde::de::Error::custom(
                                "key 1 must be int (alg) or tstr (iss)",
                            ))
                        }
                    }
                }
                CWT_CLAIM_SUB => {
                    // Key 2: CWT `sub` (tstr) or COSE `kid` (bstr).
                    match v {
                        Value::Text(t) => {
                            cwt_sub = Some(t);
                        }
                        _ => {
                            extra.insert(key, v);
                        }
                    }
                }
                COSE_HEADER_CONTENT_TYPE => {
                    content_type = Some(match v {
                        Value::Text(t) => t,
                        _ => return Err(serde::de::Error::custom("content-type must be tstr")),
                    });
                }
                CWT_CLAIM_EXP => {
                    // Key 4: CWT `exp` (int/float) or COSE `kid` (bstr).
                    match v {
                        Value::Integer(_) | Value::Float(_) => {
                            cwt_exp = Some(value_to_epoch(&v).map_err(serde::de::Error::custom)?);
                        }
                        Value::Bytes(b) => {
                            kid = Some(b);
                        }
                        _ => {
                            extra.insert(key, v);
                        }
                    }
                }
                CWT_CLAIM_NBF => {
                    // Key 5: CWT `nbf` (int/float) or COSE header (other).
                    match &v {
                        Value::Integer(_) | Value::Float(_) => {
                            cwt_nbf = Some(value_to_epoch(&v).map_err(serde::de::Error::custom)?);
                        }
                        _ => {
                            extra.insert(key, v);
                        }
                    }
                }
                COSE_HEADER_CORIM_META => {
                    // bstr .cbor corim-meta-map — try to decode, skip on failure
                    match v {
                        Value::Bytes(b) => {
                            match cbor::decode::<CorimMetaMap>(&b) {
                                Ok(meta) => {
                                    corim_meta = Some(meta);
                                }
                                Err(_) => {
                                    // Store the raw bytes in extra for forward-compat;
                                    // some producers emit malformed corim-meta.
                                    extra.insert(key, Value::Bytes(b));
                                }
                            }
                        }
                        _ => {
                            extra.insert(key, v);
                        }
                    }
                }
                COSE_HEADER_CWT_CLAIMS => {
                    // CWT-Claims is directly a map (not bstr-wrapped)
                    let claims: CwtClaims = cbor::value::from_value(&v).map_err(|e| {
                        serde::de::Error::custom(format!("cwt-claims decode: {}", e))
                    })?;
                    cwt_claims = Some(claims);
                }
                COSE_HEADER_PAYLOAD_HASH_ALG => {
                    payload_hash_alg = Some(match &v {
                        Value::Integer(n) => i64::try_from(*n).map_err(|_| {
                            serde::de::Error::custom("payload_hash_alg out of range")
                        })?,
                        _ => return Err(serde::de::Error::custom("payload_hash_alg must be int")),
                    });
                }
                COSE_HEADER_PAYLOAD_PREIMAGE_CT => {
                    payload_preimage_content_type = Some(match v {
                        Value::Text(t) => t,
                        _ => {
                            return Err(serde::de::Error::custom(
                                "payload_preimage_content_type must be tstr",
                            ))
                        }
                    });
                }
                COSE_HEADER_PAYLOAD_LOCATION => {
                    payload_location = Some(match v {
                        Value::Text(t) => t,
                        _ => return Err(serde::de::Error::custom("payload_location must be tstr")),
                    });
                }
                // X.509 certificate header parameters (RFC 9360)
                COSE_HEADER_X5BAG => {
                    x5bag = Some(deserialize_cose_x509(v)?);
                }
                COSE_HEADER_X5CHAIN => {
                    x5chain = Some(deserialize_cose_x509(v)?);
                }
                COSE_HEADER_X5T => {
                    x5t = Some(deserialize_cose_cert_hash(v)?);
                }
                COSE_HEADER_X5U => {
                    x5u = Some(match v {
                        Value::Text(t) => t,
                        _ => return Err(serde::de::Error::custom("x5u must be tstr")),
                    });
                }
                _ => {
                    extra.insert(key, v);
                }
            }
        }

        let alg = alg
            .ok_or_else(|| serde::de::Error::custom("protected header: missing alg (key 1)"))?
            .into();

        // If CWT claims were found flat in the header (not under key 15),
        // synthesize a CwtClaims struct from the individual fields.
        if cwt_claims.is_none() {
            if let Some(iss) = cwt_iss {
                cwt_claims = Some(CwtClaims {
                    iss,
                    sub: cwt_sub,
                    exp: cwt_exp,
                    nbf: cwt_nbf,
                    extra: BTreeMap::new(),
                });
            }
        }

        // meta-group validation: at least one of corim-meta or cwt-claims must be present
        if corim_meta.is_none() && cwt_claims.is_none() {
            return Err(serde::de::Error::custom(
                "protected header: at least one of corim-meta (8) or CWT-Claims (15) must be present",
            ));
        }

        Ok(ProtectedCorimHeaderMap {
            alg,
            content_type,
            payload_hash_alg,
            payload_preimage_content_type,
            payload_location,
            corim_meta,
            cwt_claims,
            kid,
            x5bag,
            x5chain,
            x5t,
            x5u,
            extra,
        })
    }
}

impl Validate for ProtectedCorimHeaderMap {
    fn valid(&self) -> Result<(), String> {
        // Must have at least one of corim-meta or cwt-claims
        if self.corim_meta.is_none() && self.cwt_claims.is_none() {
            return Err(
                "protected header: at least one of corim-meta or CWT-Claims required".into(),
            );
        }

        // For inline mode, content-type should be present
        if !self.is_hash_envelope() && self.content_type.is_none() {
            return Err("inline mode: content-type (key 3) is required".into());
        }

        // For hash-envelope mode, payload_preimage_content_type should be present
        if self.is_hash_envelope() && self.payload_preimage_content_type.is_none() {
            return Err(
                "hash-envelope mode: payload_preimage_content_type (key 259) is required".into(),
            );
        }

        // If both corim-meta and cwt-claims are present, validate consistency
        // (§4.2.1: iss must match signer-name, nbf/exp must match signature-validity)
        if let (Some(meta), Some(cwt)) = (&self.corim_meta, &self.cwt_claims) {
            if meta.signer.signer_name != cwt.iss {
                return Err(format!(
                    "corim-meta signer-name '{}' != cwt-claims iss '{}'",
                    meta.signer.signer_name, cwt.iss
                ));
            }
        }

        Ok(())
    }
}
