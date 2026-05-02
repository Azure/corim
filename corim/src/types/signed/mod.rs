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

use super::corim::CorimMetaMap;
use super::tags::*;
use crate::cbor;
use crate::cbor::value::Value;
use crate::Validate;

pub mod algorithm;
pub use algorithm::CoseAlgorithm;
pub mod x509;
pub use x509::{
    CoseCertHash, CoseX509, COSE_HEADER_KID, COSE_HEADER_X5BAG, COSE_HEADER_X5CHAIN,
    COSE_HEADER_X5T, COSE_HEADER_X5U,
};
pub mod cwt;
pub use cwt::CwtClaims;
pub mod header;
pub use header::{
    ProtectedCorimHeaderMap, ProtectedCorimHeaderMapBuilder, CORIM_CONTENT_TYPE, COSE_HEADER_ALG,
    COSE_HEADER_CONTENT_TYPE, COSE_HEADER_CORIM_META, COSE_HEADER_CWT_CLAIMS,
    COSE_HEADER_PAYLOAD_HASH_ALG, COSE_HEADER_PAYLOAD_LOCATION, COSE_HEADER_PAYLOAD_PREIMAGE_CT,
};

// ===================================================================
// COSE_Sign1 wire-format constants
// ===================================================================

/// COSE `Sig_structure1` context string (RFC 9052 §4.4).
const SIG_STRUCTURE1_CONTEXT: &str = "Signature1";

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

    // Decode interop: peel legacy `#6.500` / `#6.502` outer wrappers if
    // present. See `crate::compat::peel_tcg_wrappers`.
    let peeled = crate::compat::peel_tcg_wrappers(bytes)?;
    let bytes = peeled.as_bytes();

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
    let protected_val = it.next().ok_or_else(|| {
        DecodeError::InvalidStructure("COSE_Sign1 missing protected header".into())
    })?;
    let unprotected_val = it.next().ok_or_else(|| {
        DecodeError::InvalidStructure("COSE_Sign1 missing unprotected header".into())
    })?;
    let payload_val = it
        .next()
        .ok_or_else(|| DecodeError::InvalidStructure("COSE_Sign1 missing payload".into()))?;
    let signature_val = it
        .next()
        .ok_or_else(|| DecodeError::InvalidStructure("COSE_Sign1 missing signature".into()))?;

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
