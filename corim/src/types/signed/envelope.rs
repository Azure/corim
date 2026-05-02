// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! `COSE_Sign1` envelope handling for signed CoRIMs.
//!
//! Decoded form of `#6.18([protected, unprotected, payload, signature])`
//! per RFC 9052 §4 plus encode/decode/TBS/validate helpers. This module
//! does NOT perform cryptographic signature verification; the caller
//! supplies signatures via [`CoseSign1Corim::to_be_signed`] /
//! [`build_with_signature`](super::SignedCorimBuilder::build_with_signature).

#[allow(unused_imports)]
use crate::nostd_prelude::*;

use super::super::tags::TAG_SIGNED_CORIM;
use super::header::ProtectedCorimHeaderMap;
use crate::cbor;
use crate::cbor::value::Value;
use crate::Validate;

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
