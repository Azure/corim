// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Signed CoRIM (`#6.18(COSE-Sign1-corim)`) types per §4.2.
//!
//! Provides types for parsing and constructing signed CoRIM documents
//! without requiring any cryptographic dependencies. The caller performs
//! the actual signature creation/verification externally.
//!
//! # Wire format
//!
//! ```text
//! signed-corim = #6.18(COSE-Sign1-corim)
//!
//! COSE-Sign1-corim = [
//!   protected: bstr .cbor protected-corim-header-map,
//!   unprotected: unprotected-corim-header-map,
//!   payload: bstr .cbor tagged-unsigned-corim-map / nil,
//!   signature: bstr,
//! ]
//! ```

#[allow(unused_imports)]
use crate::nostd_prelude::*;
use serde::{Deserialize, Serialize};

use super::corim::CorimMetaMap;
use super::tags::*;
use crate::cbor;
use crate::cbor::value::Value;
use crate::Validate;

// ===================================================================
// COSE Algorithm Identifiers (IANA "COSE Algorithms" registry)
// Updated per RFC 9864 — fully-specified algorithm identifiers.
// ===================================================================

/// COSE signing algorithm identifier per
/// [IANA COSE Algorithms](https://www.iana.org/assignments/cose/cose.xhtml#algorithms),
/// updated by [RFC 9864](https://www.rfc-editor.org/rfc/rfc9864.html).
///
/// RFC 9864 deprecates polymorphic algorithm identifiers (ES256, ES384,
/// ES512, EdDSA) and defines fully-specified replacements (ESP256, ESP384,
/// ESP512, Ed25519, Ed448). The deprecated variants are retained for
/// decode interop but marked with `#[deprecated]` doc attributes.
///
/// Used in the `alg` (key 1) field of the COSE_Sign1 protected header.
/// The `Unknown` variant provides forward compatibility with algorithm
/// identifiers not yet modeled here.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum CoseAlgorithm {
    // --- Fully-specified algorithms (RFC 9864 §2) ---
    /// ESP256 (-9) — ECDSA using P-256 curve and SHA-256. Replaces ES256.
    Esp256,
    /// Ed25519 (-19) — EdDSA using the Ed25519 parameter set. Replaces EdDSA.
    Ed25519,
    /// PS256 (-37) — RSASSA-PSS w/ SHA-256.
    Ps256,
    /// PS384 (-38) — RSASSA-PSS w/ SHA-384.
    Ps384,
    /// PS512 (-39) — RSASSA-PSS w/ SHA-512.
    Ps512,
    /// ESP384 (-51) — ECDSA using P-384 curve and SHA-384. Replaces ES384.
    Esp384,
    /// ESP512 (-52) — ECDSA using P-521 curve and SHA-512. Replaces ES512.
    Esp512,
    /// Ed448 (-53) — EdDSA using the Ed448 parameter set. Replaces EdDSA.
    Ed448,

    // --- Deprecated polymorphic algorithms (RFC 9864 §4.2.2) ---
    // Retained for decode interop with existing signed CoRIM documents.
    /// ES256 (-7) — **Deprecated per RFC 9864.** Use [`Esp256`](Self::Esp256).
    Es256,
    /// EdDSA (-8) — **Deprecated per RFC 9864.** Use [`Ed25519`](Self::Ed25519) or [`Ed448`](Self::Ed448).
    EdDsa,
    /// ES384 (-35) — **Deprecated per RFC 9864.** Use [`Esp384`](Self::Esp384).
    Es384,
    /// ES512 (-36) — **Deprecated per RFC 9864.** Use [`Esp512`](Self::Esp512).
    Es512,

    /// An algorithm identifier not explicitly modeled above.
    Unknown(i64),
}

impl CoseAlgorithm {
    /// Convert from the IANA integer identifier.
    pub fn from_i64(n: i64) -> Self {
        match n {
            -7 => Self::Es256,
            -8 => Self::EdDsa,
            -9 => Self::Esp256,
            -19 => Self::Ed25519,
            -35 => Self::Es384,
            -36 => Self::Es512,
            -37 => Self::Ps256,
            -38 => Self::Ps384,
            -39 => Self::Ps512,
            -51 => Self::Esp384,
            -52 => Self::Esp512,
            -53 => Self::Ed448,
            other => Self::Unknown(other),
        }
    }

    /// Convert to the IANA integer identifier.
    pub fn to_i64(self) -> i64 {
        match self {
            Self::Es256 => -7,
            Self::EdDsa => -8,
            Self::Esp256 => -9,
            Self::Ed25519 => -19,
            Self::Es384 => -35,
            Self::Es512 => -36,
            Self::Ps256 => -37,
            Self::Ps384 => -38,
            Self::Ps512 => -39,
            Self::Esp384 => -51,
            Self::Esp512 => -52,
            Self::Ed448 => -53,
            Self::Unknown(n) => n,
        }
    }

    /// Human-readable name for display.
    pub fn name(&self) -> &'static str {
        match self {
            Self::Esp256 => "ESP256",
            Self::Ed25519 => "Ed25519",
            Self::Ps256 => "PS256",
            Self::Ps384 => "PS384",
            Self::Ps512 => "PS512",
            Self::Esp384 => "ESP384",
            Self::Esp512 => "ESP512",
            Self::Ed448 => "Ed448",
            Self::Es256 => "ES256 (deprecated)",
            Self::EdDsa => "EdDSA (deprecated)",
            Self::Es384 => "ES384 (deprecated)",
            Self::Es512 => "ES512 (deprecated)",
            Self::Unknown(_) => "Unknown",
        }
    }

    /// Returns `true` if this algorithm is deprecated per RFC 9864.
    pub fn is_deprecated(&self) -> bool {
        matches!(self, Self::Es256 | Self::EdDsa | Self::Es384 | Self::Es512)
    }
}

impl core::fmt::Display for CoseAlgorithm {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Unknown(n) => write!(f, "Unknown({})", n),
            _ => write!(f, "{} ({})", self.name(), self.to_i64()),
        }
    }
}

impl From<i64> for CoseAlgorithm {
    fn from(n: i64) -> Self {
        Self::from_i64(n)
    }
}

impl From<CoseAlgorithm> for i64 {
    fn from(alg: CoseAlgorithm) -> Self {
        alg.to_i64()
    }
}

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

// ===================================================================
// X.509 COSE Header Parameters (RFC 9360)
// ===================================================================

/// COSE header: `kid` (key 4) — Key identifier.
pub const COSE_HEADER_KID: i64 = 4;
/// COSE header: `x5bag` (key 32) — Unordered bag of X.509 certificates.
pub const COSE_HEADER_X5BAG: i64 = 32;
/// COSE header: `x5chain` (key 33) — Ordered chain of X.509 certificates.
pub const COSE_HEADER_X5CHAIN: i64 = 33;
/// COSE header: `x5t` (key 34) — Hash of an X.509 certificate.
pub const COSE_HEADER_X5T: i64 = 34;
/// COSE header: `x5u` (key 35) — URI pointing to an X.509 certificate.
pub const COSE_HEADER_X5U: i64 = 35;

/// X.509 certificate chain or single certificate per RFC 9360.
///
/// ```text
/// COSE_X509 = bstr / [ 2*certs: bstr ]
/// ```
///
/// Each `bstr` contains DER-encoded X.509 certificate bytes.
/// For `x5chain`, certificates are ordered: end-entity first, then issuer chain.
/// For `x5bag`, the order is unspecified.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum CoseX509 {
    /// A single DER-encoded X.509 certificate.
    Single(Vec<u8>),
    /// Multiple DER-encoded X.509 certificates.
    Chain(Vec<Vec<u8>>),
}

impl CoseX509 {
    /// Return all certificates as a slice of byte vectors.
    pub fn certs(&self) -> Vec<&[u8]> {
        match self {
            Self::Single(c) => alloc::vec![c.as_slice()],
            Self::Chain(cs) => cs.iter().map(|c| c.as_slice()).collect(),
        }
    }

    /// Return the end-entity (leaf) certificate bytes, if present.
    pub fn end_entity(&self) -> &[u8] {
        match self {
            Self::Single(c) => c,
            Self::Chain(cs) => &cs[0],
        }
    }
}

/// X.509 certificate thumbprint per RFC 9360.
///
/// ```text
/// COSE_CertHash = [ hashAlg: (int / tstr), hashValue: bstr ]
/// ```
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CoseCertHash {
    /// Hash algorithm identifier (typically an integer from the COSE Algorithms registry).
    pub hash_alg: i64,
    /// The hash value computed over the DER-encoded certificate.
    pub hash_value: Vec<u8>,
}

// ===================================================================
// CWT Claim Keys (RFC 8392 §4)
// ===================================================================

/// CWT claim: `iss` (key 1) — Issuer.
const CWT_CLAIM_ISS: i64 = 1;
/// CWT claim: `sub` (key 2) — Subject.
const CWT_CLAIM_SUB: i64 = 2;
/// CWT claim: `exp` (key 4) — Expiration Time.
const CWT_CLAIM_EXP: i64 = 4;
/// CWT claim: `nbf` (key 5) — Not Before.
const CWT_CLAIM_NBF: i64 = 5;
/// CWT claim: `iat` (key 6) — Issued At.
#[allow(dead_code)] // Defined for documentation; key 6 values stored in `extra`.
const CWT_CLAIM_IAT: i64 = 6;

/// Expected `content-type` value for inline CoRIM signing.
pub const CORIM_CONTENT_TYPE: &str = "application/rim+cbor";

/// COSE `Sig_structure1` context string (RFC 9052 §4.4).
const SIG_STRUCTURE1_CONTEXT: &str = "Signature1";

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
fn value_to_epoch(v: &Value) -> Result<i64, String> {
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

/// Serialize a `CoseX509` to a `Value` (bstr or array of bstr).
fn serialize_cose_x509(x: &CoseX509) -> Value {
    match x {
        CoseX509::Single(c) => Value::Bytes(c.clone()),
        CoseX509::Chain(cs) => Value::Array(cs.iter().map(|c| Value::Bytes(c.clone())).collect()),
    }
}

/// Deserialize a `Value` into a `CoseX509` (bstr or array of bstr).
fn deserialize_cose_x509<E: serde::de::Error>(v: Value) -> Result<CoseX509, E> {
    match v {
        Value::Bytes(b) => Ok(CoseX509::Single(b)),
        Value::Array(arr) => {
            let mut certs = Vec::with_capacity(arr.len());
            for item in arr {
                match item {
                    Value::Bytes(b) => certs.push(b),
                    _ => return Err(E::custom("x5chain/x5bag cert must be bstr")),
                }
            }
            Ok(CoseX509::Chain(certs))
        }
        _ => Err(E::custom("COSE_X509 must be bstr or array of bstr")),
    }
}

/// Deserialize a `Value` into a `CoseCertHash` ([hashAlg, hashValue]).
fn deserialize_cose_cert_hash<E: serde::de::Error>(v: Value) -> Result<CoseCertHash, E> {
    let arr = match v {
        Value::Array(a) if a.len() == 2 => a,
        _ => return Err(E::custom("COSE_CertHash must be [hashAlg, hashValue]")),
    };
    let mut it = arr.into_iter();
    let hash_alg = match it.next().unwrap() {
        Value::Integer(n) => i64::try_from(n).map_err(|_| E::custom("x5t hashAlg out of range"))?,
        _ => return Err(E::custom("x5t hashAlg must be int")),
    };
    let hash_value = match it.next().unwrap() {
        Value::Bytes(b) => b,
        _ => return Err(E::custom("x5t hashValue must be bstr")),
    };
    Ok(CoseCertHash {
        hash_alg,
        hash_value,
    })
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
            let arr = Value::Array(alloc::vec![
                Value::Integer(x5t.hash_alg as i128),
                Value::Bytes(x5t.hash_value.clone()),
            ]);
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

// ===================================================================
// CoseSign1Corim — the decoded COSE_Sign1-corim structure
// ===================================================================

/// A decoded `COSE_Sign1-corim` structure (§4.2).
///
/// This is the parsed form of `#6.18([protected, unprotected, payload, signature])`.
/// The crypto verification is NOT performed by this crate — the caller must
/// verify the signature externally using the TBS and algorithm from the
/// protected header.
///
/// # Decode flow
///
/// ```text
/// bytes → CBOR tag 18 → 4-element array
///   [0] protected: bstr → decode as ProtectedCorimHeaderMap
///   [1] unprotected: map
///   [2] payload: bstr | nil
///   [3] signature: bstr
/// ```
#[derive(Clone, Debug, PartialEq)]
pub struct CoseSign1Corim {
    /// The raw CBOR-encoded protected header bytes.
    /// This is the exact `bstr` from the COSE structure, needed for
    /// signature verification (it is signed as-is).
    pub protected_header_bytes: Vec<u8>,

    /// The decoded protected header.
    pub protected: ProtectedCorimHeaderMap,

    /// The unprotected header map.
    /// Stored as CBOR map entries since it contains arbitrary COSE labels.
    pub unprotected: Vec<(Value, Value)>,

    /// The payload bytes, or `None` if the payload is detached (nil).
    /// When present, this is `bstr .cbor tagged-unsigned-corim-map`.
    pub payload: Option<Vec<u8>>,

    /// The COSE signature bytes.
    pub signature: Vec<u8>,
}

impl CoseSign1Corim {
    /// Construct the COSE `Sig_structure1` to-be-signed bytes per RFC 9052 §4.4.
    ///
    /// ```text
    /// Sig_structure1 = [
    ///   context : "Signature1",
    ///   body_protected : bstr,
    ///   external_aad : bstr,
    ///   payload : bstr,
    /// ]
    /// ```
    ///
    /// For attached payloads, this uses the embedded payload. For detached
    /// payloads (where `self.payload` is `None`), this returns an error —
    /// use [`to_be_signed_detached`](Self::to_be_signed_detached) instead
    /// to supply the payload externally.
    ///
    /// The `external_aad` is application-supplied additional authenticated data.
    /// Pass `&[]` if not used.
    ///
    /// Returns the CBOR-encoded `Sig_structure1` bytes.
    pub fn to_be_signed(&self, external_aad: &[u8]) -> Result<Vec<u8>, crate::EncodeError> {
        let payload = self.payload.as_deref().ok_or_else(|| {
            crate::EncodeError::Serialization(
                "payload is detached (nil); use to_be_signed_detached() with the payload".into(),
            )
        })?;
        build_sig_structure1(&self.protected_header_bytes, external_aad, payload)
    }

    /// Construct the COSE `Sig_structure1` TBS bytes for a **detached** payload.
    ///
    /// Per RFC 9052 §4.4, the `Sig_structure1` always contains the actual
    /// payload bytes, even when the COSE_Sign1 envelope carries `nil`.
    /// This method allows the caller to supply the detached payload for
    /// TBS construction.
    ///
    /// Also works for attached payloads — the `detached_payload` parameter
    /// takes precedence over any embedded payload.
    pub fn to_be_signed_detached(
        &self,
        detached_payload: &[u8],
        external_aad: &[u8],
    ) -> Result<Vec<u8>, crate::EncodeError> {
        build_sig_structure1(&self.protected_header_bytes, external_aad, detached_payload)
    }

    /// Returns `true` if this envelope has a detached (nil) payload.
    pub fn is_detached(&self) -> bool {
        self.payload.is_none()
    }
}

/// Build a COSE `Sig_structure1` for signing (RFC 9052 §4.4).
///
/// ```text
/// Sig_structure1 = [
///   context : "Signature1",
///   body_protected : bstr,
///   external_aad : bstr,
///   payload : bstr,
/// ]
/// ```
pub fn build_sig_structure1(
    protected_header_bytes: &[u8],
    external_aad: &[u8],
    payload: &[u8],
) -> Result<Vec<u8>, crate::EncodeError> {
    let sig_structure = Value::Array(vec![
        Value::Text(SIG_STRUCTURE1_CONTEXT.into()),
        Value::Bytes(protected_header_bytes.to_vec()),
        Value::Bytes(external_aad.to_vec()),
        Value::Bytes(payload.to_vec()),
    ]);
    cbor::encode(&sig_structure)
}

/// Encode a `CoseSign1Corim` into CBOR bytes with tag 18 wrapper.
///
/// Produces `#6.18([protected, unprotected, payload, signature])`.
pub fn encode_signed_corim(signed: &CoseSign1Corim) -> Result<Vec<u8>, crate::EncodeError> {
    let payload_val = match &signed.payload {
        Some(p) => Value::Bytes(p.clone()),
        None => Value::Null,
    };

    let arr = Value::Array(vec![
        Value::Bytes(signed.protected_header_bytes.clone()),
        Value::Map(signed.unprotected.clone()),
        payload_val,
        Value::Bytes(signed.signature.clone()),
    ]);

    let tagged = Value::Tag(TAG_SIGNED_CORIM, Box::new(arr));
    cbor::encode(&tagged)
}

/// Decode CBOR bytes as a signed CoRIM (`#6.18(COSE_Sign1-corim)`).
///
/// This does NOT verify the cryptographic signature. It only parses the
/// COSE_Sign1 structure and decodes the protected header.
///
/// The caller should:
/// 1. Use [`CoseSign1Corim::to_be_signed`] to get the TBS bytes.
/// 2. Verify the signature using the algorithm from `protected.alg`.
/// 3. Use [`validate_signed_corim_payload`] to validate the payload.
pub fn decode_signed_corim(bytes: &[u8]) -> Result<CoseSign1Corim, crate::DecodeError> {
    use crate::error::DecodeError;

    if bytes.len() > crate::validate::MAX_PAYLOAD_SIZE {
        return Err(DecodeError::InvalidStructure(format!(
            "payload too large: {} bytes (max {})",
            bytes.len(),
            crate::validate::MAX_PAYLOAD_SIZE,
        )));
    }

    // Decode the top-level tagged value
    let val: Value = cbor::decode(bytes)
        .map_err(|e| DecodeError::Deserialization(format!("cannot decode CBOR: {}", e)))?;

    // Must be tag 18
    let (tag, inner) = match val {
        Value::Tag(t, inner) => (t, *inner),
        _ => {
            return Err(DecodeError::InvalidStructure(
                "expected CBOR tag 18 for signed-corim".into(),
            ));
        }
    };
    if tag != TAG_SIGNED_CORIM {
        return Err(DecodeError::UnexpectedTag {
            expected: TAG_SIGNED_CORIM,
            found: tag,
        });
    }

    // Must be a 4-element array
    let arr = match inner {
        Value::Array(a) if a.len() == 4 => a,
        Value::Array(a) => {
            return Err(DecodeError::InvalidStructure(format!(
                "COSE_Sign1 must be a 4-element array, got {}",
                a.len()
            )));
        }
        _ => {
            return Err(DecodeError::InvalidStructure(
                "COSE_Sign1 must be an array".into(),
            ));
        }
    };

    let mut it = arr.into_iter();
    let protected_val = it.next().unwrap();
    let unprotected_val = it.next().unwrap();
    let payload_val = it.next().unwrap();
    let signature_val = it.next().unwrap();

    // [0] protected: bstr
    let protected_header_bytes = match protected_val {
        Value::Bytes(b) => b,
        _ => {
            return Err(DecodeError::InvalidStructure(
                "COSE_Sign1 protected must be bstr".into(),
            ));
        }
    };

    // Decode the protected header from the bstr
    let protected: ProtectedCorimHeaderMap = cbor::decode(&protected_header_bytes)
        .map_err(|e| DecodeError::InvalidStructure(format!("protected header decode: {}", e)))?;

    // [1] unprotected: map (tolerate non-map values from non-standard producers)
    let unprotected = match unprotected_val {
        Value::Map(m) => m,
        _ => {
            // Some producers emit non-standard unprotected headers;
            // treat as empty for forward compatibility.
            Vec::new()
        }
    };

    // [2] payload: bstr / nil (tolerate other types from non-standard producers)
    let payload = match payload_val {
        Value::Bytes(b) => Some(b),
        Value::Null => None,
        _ => {
            // Non-standard payload type; treat as detached (nil).
            None
        }
    };

    // [3] signature: bstr (tolerate other types from non-standard producers)
    let signature = match signature_val {
        Value::Bytes(b) => b,
        _ => {
            // Non-standard signature type; store empty.
            Vec::new()
        }
    };

    Ok(CoseSign1Corim {
        protected_header_bytes,
        protected,
        unprotected,
        payload,
        signature,
    })
}

/// Validate the payload of a signed CoRIM without verifying the signature.
///
/// For **attached** payloads, extracts the `tagged-unsigned-corim-map` from
/// the embedded payload bytes and runs structural validation.
///
/// For **detached** payloads, returns an error — use
/// [`validate_signed_corim_payload_detached`] instead to supply the payload.
///
/// This is useful when the caller has already verified the signature externally
/// and wants to inspect/validate the inner CoRIM.
pub fn validate_signed_corim_payload(
    signed: &CoseSign1Corim,
    now_epoch_secs: i64,
) -> Result<crate::validate::ValidatedCorim, crate::ValidationError> {
    let payload = signed.payload.as_ref().ok_or_else(|| {
        crate::ValidationError::Invalid(
            "signed CoRIM has detached (nil) payload; use validate_signed_corim_payload_detached()"
                .into(),
        )
    })?;

    // Validate the protected header structure
    signed
        .protected
        .valid()
        .map_err(crate::ValidationError::Invalid)?;

    // Delegate to the existing validation implementation
    crate::validate::decode_and_validate_full_at(payload, now_epoch_secs)
}

/// Validate a **detached** signed CoRIM payload without verifying the signature.
///
/// The `detached_payload` parameter supplies the CoRIM payload that was
/// transported separately from the COSE_Sign1 envelope.
///
/// The caller should verify the signature *before* calling this function:
/// 1. Reconstruct the TBS via
///    [`CoseSign1Corim::to_be_signed_detached(detached_payload, &external_aad)`].
/// 2. Verify the signature using the algorithm from `protected.alg`.
/// 3. Call this function with the same `detached_payload` to validate the
///    inner CoRIM structure.
pub fn validate_signed_corim_payload_detached(
    signed: &CoseSign1Corim,
    detached_payload: &[u8],
    now_epoch_secs: i64,
) -> Result<crate::validate::ValidatedCorim, crate::ValidationError> {
    // Validate the protected header structure
    signed
        .protected
        .valid()
        .map_err(crate::ValidationError::Invalid)?;

    // Delegate to the existing validation implementation
    crate::validate::decode_and_validate_full_at(detached_payload, now_epoch_secs)
}

// ===================================================================
// SignedCorimBuilder
// ===================================================================

/// Builder for constructing signed CoRIM documents.
///
/// This builder creates the COSE_Sign1 structure without a cryptographic
/// signature. The caller uses [`to_be_signed`](SignedCorimBuilder::to_be_signed)
/// to obtain the data that must be signed externally, then calls
/// [`build_with_signature`](SignedCorimBuilder::build_with_signature) to produce
/// the final signed CoRIM bytes.
///
/// # Example
///
/// ```rust,no_run
/// use corim::types::signed::SignedCorimBuilder;
/// use corim::types::signed::CwtClaims;
/// use corim::builder::CorimBuilder;
/// use corim::types::corim::CorimId;
///
/// // 1. Build the unsigned CoRIM payload
/// let corim_bytes = CorimBuilder::new(CorimId::Text("test".into()))
///     // ... add tags ...
///     # ;
///
/// // 2. Create the signed CoRIM builder
/// # let corim_bytes = vec![];
/// let mut builder = SignedCorimBuilder::new(-7, corim_bytes) // ES256 = -7
///     .set_cwt_claims(CwtClaims::new("ACME Corp"));
///
/// // 3. Get the TBS blob
/// let tbs = builder.to_be_signed(&[]).unwrap();
///
/// // 4. Sign externally (e.g., with ring, openssl, etc.)
/// let signature = vec![0u8; 64]; // placeholder
///
/// // 5. Produce the final signed CoRIM
/// let signed_bytes = builder.build_with_signature(signature).unwrap();
/// ```
#[must_use]
pub struct SignedCorimBuilder {
    alg: CoseAlgorithm,
    content_type: String,
    corim_meta: Option<CorimMetaMap>,
    cwt_claims: Option<CwtClaims>,
    payload: Vec<u8>,
    unprotected: Vec<(Value, Value)>,
    extra_protected: BTreeMap<i64, Value>,
    // Cached protected header bytes (computed lazily)
    cached_protected_bytes: Option<Vec<u8>>,
}

impl SignedCorimBuilder {
    /// Create a new builder with the specified COSE algorithm and CoRIM payload bytes.
    ///
    /// The `alg` parameter is the COSE algorithm identifier. Use
    /// [`CoseAlgorithm`] variants (e.g., `CoseAlgorithm::Es256`) or convert
    /// from an integer with `.into()` (e.g., `(-7i64).into()`).
    ///
    /// The `corim_payload` must be the CBOR-encoded `tagged-unsigned-corim-map`
    /// (i.e., tag-501-wrapped bytes as produced by [`crate::builder::CorimBuilder::build_bytes`]).
    pub fn new(alg: impl Into<CoseAlgorithm>, corim_payload: Vec<u8>) -> Self {
        Self {
            alg: alg.into(),
            content_type: CORIM_CONTENT_TYPE.into(),
            corim_meta: None,
            cwt_claims: None,
            payload: corim_payload,
            unprotected: Vec::new(),
            extra_protected: BTreeMap::new(),
            cached_protected_bytes: None,
        }
    }

    /// Set the `corim-meta` (key 8) in the protected header.
    pub fn set_corim_meta(mut self, meta: CorimMetaMap) -> Self {
        self.corim_meta = Some(meta);
        self.cached_protected_bytes = None;
        self
    }

    /// Set the `CWT-Claims` (key 15) in the protected header.
    pub fn set_cwt_claims(mut self, claims: CwtClaims) -> Self {
        self.cwt_claims = Some(claims);
        self.cached_protected_bytes = None;
        self
    }

    /// Override the content-type header value (default: "application/rim+cbor").
    pub fn set_content_type(mut self, ct: impl Into<String>) -> Self {
        self.content_type = ct.into();
        self.cached_protected_bytes = None;
        self
    }

    /// Add an entry to the unprotected header map.
    pub fn add_unprotected(mut self, key: Value, value: Value) -> Self {
        self.unprotected.push((key, value));
        self
    }

    /// Add an extra entry to the protected header map.
    pub fn add_protected(mut self, key: i64, value: Value) -> Self {
        self.extra_protected.insert(key, value);
        self.cached_protected_bytes = None;
        self
    }

    /// Build the protected header and return its CBOR-encoded bytes.
    fn build_protected_bytes(&mut self) -> Result<Vec<u8>, crate::EncodeError> {
        if let Some(ref cached) = self.cached_protected_bytes {
            return Ok(cached.clone());
        }

        let header = self.build_protected_header()?;
        let bytes = cbor::encode(&header)?;
        self.cached_protected_bytes = Some(bytes.clone());
        Ok(bytes)
    }

    /// Construct the `ProtectedCorimHeaderMap` from builder state.
    fn build_protected_header(&self) -> Result<ProtectedCorimHeaderMap, crate::EncodeError> {
        if self.corim_meta.is_none() && self.cwt_claims.is_none() {
            return Err(crate::EncodeError::Serialization(
                "at least one of corim-meta or cwt-claims must be set".into(),
            ));
        }

        Ok(ProtectedCorimHeaderMap {
            alg: self.alg,
            content_type: Some(self.content_type.clone()),
            payload_hash_alg: None,
            payload_preimage_content_type: None,
            payload_location: None,
            corim_meta: self.corim_meta.clone(),
            cwt_claims: self.cwt_claims.clone(),
            kid: None,
            x5bag: None,
            x5chain: None,
            x5t: None,
            x5u: None,
            extra: self.extra_protected.clone(),
        })
    }

    /// Compute the COSE `Sig_structure1` to-be-signed (TBS) bytes.
    ///
    /// This is the data that must be signed by the external crypto operation.
    /// The `external_aad` is application-supplied additional authenticated data;
    /// pass `&[]` if not used.
    ///
    /// ```text
    /// Sig_structure1 = [
    ///   "Signature1",
    ///   body_protected,  // CBOR-encoded protected header
    ///   external_aad,
    ///   payload,          // the CoRIM payload bytes
    /// ]
    /// ```
    pub fn to_be_signed(&mut self, external_aad: &[u8]) -> Result<Vec<u8>, crate::EncodeError> {
        let protected_bytes = self.build_protected_bytes()?;
        build_sig_structure1(&protected_bytes, external_aad, &self.payload)
    }

    /// Produce the final signed CoRIM CBOR bytes with the given signature.
    ///
    /// The `signature` must be the cryptographic signature over the TBS bytes
    /// returned by [`to_be_signed`](SignedCorimBuilder::to_be_signed).
    ///
    /// The payload is **attached** (embedded in the COSE_Sign1 envelope).
    ///
    /// Returns `#6.18([protected, unprotected, payload, signature])` as CBOR bytes.
    pub fn build_with_signature(
        mut self,
        signature: Vec<u8>,
    ) -> Result<Vec<u8>, crate::EncodeError> {
        let protected_bytes = self.build_protected_bytes()?;
        let protected = self.build_protected_header()?;

        let signed = CoseSign1Corim {
            protected_header_bytes: protected_bytes,
            protected,
            unprotected: self.unprotected,
            payload: Some(self.payload),
            signature,
        };

        encode_signed_corim(&signed)
    }

    /// Produce the final signed CoRIM CBOR bytes in **detached payload** mode.
    ///
    /// The payload is NOT embedded in the COSE_Sign1 envelope (the payload
    /// field is set to `nil`). The payload must be transported separately.
    ///
    /// The `signature` must be the cryptographic signature over the TBS bytes
    /// returned by [`to_be_signed`](SignedCorimBuilder::to_be_signed).
    /// Note: the TBS is computed over the *actual* payload even though the
    /// envelope will carry `nil`.
    ///
    /// Returns `#6.18([protected, unprotected, nil, signature])` as CBOR bytes.
    pub fn build_detached_with_signature(
        mut self,
        signature: Vec<u8>,
    ) -> Result<Vec<u8>, crate::EncodeError> {
        let protected_bytes = self.build_protected_bytes()?;
        let protected = self.build_protected_header()?;

        let signed = CoseSign1Corim {
            protected_header_bytes: protected_bytes,
            protected,
            unprotected: self.unprotected,
            payload: None,
            signature,
        };

        encode_signed_corim(&signed)
    }
}
