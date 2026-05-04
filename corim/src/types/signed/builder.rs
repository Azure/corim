// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Builder for constructing signed CoRIM documents.
//!
//! Produces `#6.18([protected, unprotected, payload, signature])` CBOR
//! bytes without performing any cryptographic operations — the caller
//! supplies the signature externally via
//! [`SignedCorimBuilder::to_be_signed`] +
//! [`SignedCorimBuilder::build_with_signature`].

#[allow(unused_imports)]
use crate::nostd_prelude::*;

use super::super::corim::CorimMetaMap;
use super::algorithm::CoseAlgorithm;
use super::cwt::CwtClaims;
use super::envelope::{build_sig_structure1, encode_signed_corim, CoseSign1Corim};
use super::header::{ProtectedCorimHeaderMap, CORIM_CONTENT_TYPE};
use crate::cbor;
use crate::cbor::value::Value;

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
