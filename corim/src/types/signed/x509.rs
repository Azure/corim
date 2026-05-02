// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! X.509 COSE header parameters per [RFC 9360](https://www.rfc-editor.org/rfc/rfc9360.html).
//!
//! Defines the wire-level types used by the protected COSE_Sign1 header for
//! certificate-based key discovery: `kid`, `x5bag`, `x5chain`, `x5t`, `x5u`.
//! No PKI parsing is performed; certificates are stored as raw DER bytes.

#[allow(unused_imports)]
use crate::nostd_prelude::*;

use super::super::measurement::DigestAlg;
use crate::cbor::value::Value;

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
    /// Hash algorithm identifier (integer from COSE Algorithms registry, or text).
    pub hash_alg: DigestAlg,
    /// The hash value computed over the DER-encoded certificate.
    pub hash_value: Vec<u8>,
}

/// Serialize a `CoseX509` to a `Value` (bstr or array of bstr).
pub(super) fn serialize_cose_x509(x: &CoseX509) -> Value {
    match x {
        CoseX509::Single(c) => Value::Bytes(c.clone()),
        CoseX509::Chain(cs) => Value::Array(cs.iter().map(|c| Value::Bytes(c.clone())).collect()),
    }
}

/// Deserialize a `Value` into a `CoseX509` (bstr or array of bstr).
pub(super) fn deserialize_cose_x509<E: serde::de::Error>(v: Value) -> Result<CoseX509, E> {
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
pub(super) fn deserialize_cose_cert_hash<E: serde::de::Error>(v: Value) -> Result<CoseCertHash, E> {
    let arr = match v {
        Value::Array(a) if a.len() == 2 => a,
        _ => return Err(E::custom("COSE_CertHash must be [hashAlg, hashValue]")),
    };
    let mut it = arr.into_iter();
    let hash_alg = match it.next().unwrap() {
        Value::Integer(n) => {
            DigestAlg::Int(i64::try_from(n).map_err(|_| E::custom("x5t hashAlg out of range"))?)
        }
        Value::Text(t) => DigestAlg::Text(t),
        _ => return Err(E::custom("x5t hashAlg must be int or text")),
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
