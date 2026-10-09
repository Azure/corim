//! Strict structural and temporal signed-document validation.
//!
//! Per draft-ietf-rats-corim-11 Section 4.2 and RFC 9052 Section 4.
//! These APIs do not authenticate signatures, certificates, or hash preimages.
//! Use the existing decode APIs for tolerant inspection of incomplete documents.
//!
//! ```no_run
//! use corim::types::signed::decode_and_validate_signed_corim_at;
//! # let envelope_bytes: &[u8] = &[];
//! let (envelope, payload) = decode_and_validate_signed_corim_at(
//!     envelope_bytes, None, 1_800_000_000,
//! )?;
//! let to_be_signed = envelope.to_be_signed(&[])?;
//! // Authenticate to_be_signed and envelope.signature externally before use.
//! assert!(!payload.comids.is_empty());
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! ```

use super::{
    CoseSign1Corim, ProtectedCorimHeaderMap, CORIM_CONTENT_TYPE, COSE_HEADER_CONTENT_TYPE,
    COSE_HEADER_CORIM_META, COSE_HEADER_CWT_CLAIMS, COSE_HEADER_PAYLOAD_PREIMAGE_CT, CWT_CLAIM_EXP,
    CWT_CLAIM_ISS, CWT_CLAIM_NBF, CWT_CLAIM_SUB,
};
use crate::cbor::{self, value::Value, DecodeLimits};
use crate::nostd_prelude::*;
use crate::types::matcher::{Number, NumberMatcher};
use crate::types::tags::TAG_SIGNED_CORIM;
use crate::validate::ValidatedCorim;
use crate::{Validate, ValidationError};

/// Decode and validate a complete signed document with an explicit clock.
///
/// Per draft-ietf-rats-corim-11 Section 4.2, RFC 9052 Section 4 and RFC 8392
/// Sections 3, 4.4 and 4.5. Checks COSE slot shapes, exact media type, header
/// time windows and CWT/metadata agreement, then validates the inline CoRIM.
/// CWT `exp` is exclusive; CoRIM validity `not-after` is inclusive. Fractional
/// CWT times are checked from their original values before legacy conversion.
/// The returned envelope retains the exact protected bytes; its existing CWT
/// fields still expose integer seconds. Use the raw bytes for signature work.
///
/// Supply `detached_payload` for a nil payload. If also supplied for an attached
/// envelope, it must equal the attached bytes. Missing detached payloads and
/// hash-envelope digests are errors, never successful partial validation.
/// Legacy TCG wrapper compatibility is retained; unknown header fields may be
/// skipped by the existing typed representation.
/// Opaque CoSWID fallback content is rejected because it was not validated.
///
/// **No signature, certificate, critical-header processing, or hash verification
/// is performed.** The caller must authenticate the same envelope/payload using
/// its own policy and cryptography. Profile-specific validation is not performed.
/// Existing inspection and payload-validation APIs remain available unchanged.
pub fn decode_and_validate_signed_corim_at(
    bytes: &[u8],
    detached_payload: Option<&[u8]>,
    now_epoch_secs: i64,
) -> Result<(CoseSign1Corim, ValidatedCorim), ValidationError> {
    decode_and_validate_signed_corim_at_with_limits(
        bytes,
        detached_payload,
        now_epoch_secs,
        &DecodeLimits::default(),
    )
}

/// Strict validation with shared parser limits (RFC 8949 Section 10).
///
/// Envelope, protected header, metadata, selected payload and tag bodies share
/// one aggregate budget. No budget reset or redundant CBOR parse is performed.
/// Has the same non-cryptographic contract as [`decode_and_validate_signed_corim_at`].
pub fn decode_and_validate_signed_corim_at_with_limits(
    bytes: &[u8],
    detached_payload: Option<&[u8]>,
    now_epoch_secs: i64,
    limits: &DecodeLimits,
) -> Result<(CoseSign1Corim, ValidatedCorim), ValidationError> {
    let mut budget = cbor::DecodeBudget::new(limits)?;
    let value = crate::compat::peel_value(budget.decode_value_exact(bytes)?);
    let Value::Tag(TAG_SIGNED_CORIM, inner) = value else {
        return Err(invalid("expected signed CoRIM tag 18"));
    };
    let Value::Array(parts) = *inner else {
        return Err(invalid("COSE_Sign1 must be an array"));
    };
    let [protected, unprotected, payload, signature]: [Value; 4] = parts
        .try_into()
        .map_err(|_| invalid("COSE_Sign1 must have four elements"))?;
    let Value::Bytes(protected_header_bytes) = protected else {
        return Err(invalid("COSE protected header must be bstr"));
    };
    let Value::Map(unprotected) = unprotected else {
        return Err(invalid("COSE unprotected header must be a map"));
    };
    header_labels(&unprotected)?;
    cbor::map_keys::check(&Value::Map(unprotected.clone()))?;
    let payload = match payload {
        Value::Bytes(bytes) => Some(bytes),
        Value::Null => None,
        _ => return Err(invalid("COSE payload must be bstr or nil")),
    };
    let Value::Bytes(signature) = signature else {
        return Err(invalid("COSE signature must be bstr"));
    };
    let header = budget.decode_value_exact(&protected_header_bytes)?;
    cbor::map_keys::check_header(&header)?;
    let Value::Map(fields) = &header else {
        return Err(invalid("protected header must be a map"));
    };
    header_labels(fields)?;
    let window = original_claims(fields)?;
    check_window(window.0, window.1, now_epoch_secs, true)?;
    let metadata_present = field(fields, COSE_HEADER_CORIM_META).is_some();
    let mut nested_error = None;
    let protected = ProtectedCorimHeaderMap::from_value_with_budget::<serde::de::value::Error>(
        header,
        &mut budget,
        &mut nested_error,
        true,
    );
    budget.check()?;
    if let Some(error) = nested_error {
        return Err(error.into());
    }
    let protected = protected.map_err(|error| invalid(&error.to_string()))?;
    protected.valid().map_err(ValidationError::Invalid)?;
    let (content_type, label) = if protected.is_hash_envelope() {
        (
            protected.payload_preimage_content_type.as_deref(),
            COSE_HEADER_PAYLOAD_PREIMAGE_CT,
        )
    } else {
        (protected.content_type.as_deref(), COSE_HEADER_CONTENT_TYPE)
    };
    if content_type != Some(CORIM_CONTENT_TYPE) {
        return Err(invalid(&format!(
            "header {label} must be {CORIM_CONTENT_TYPE}"
        )));
    }
    if metadata_present && protected.corim_meta.is_none() {
        return Err(invalid("corim-meta must be a valid encoded metadata map"));
    }
    if let Some(meta) = &protected.corim_meta {
        let (not_before, not_after) =
            meta.signature_validity
                .as_ref()
                .map_or((None, None), |validity| {
                    (
                        validity
                            .not_before
                            .map(|value| Number::Int(value.epoch_secs().into())),
                        Some(Number::Int(validity.not_after.epoch_secs().into())),
                    )
                });
        if protected.cwt_claims.is_some()
            && (!same_time(window.0, not_before) || !same_time(window.1, not_after))
        {
            return Err(invalid(
                "CWT nbf/exp must agree with corim-meta signature-validity",
            ));
        }
        check_window(not_before, not_after, now_epoch_secs, false)?;
    }
    if protected.is_hash_envelope() {
        return Err(invalid(
            "hash-envelope requires an authenticated preimage; digest is not an inline CoRIM",
        ));
    }
    let selected = match (&payload, detached_payload) {
        (Some(attached), Some(detached)) if attached.as_slice() != detached => {
            return Err(invalid("supplied payload differs from attached payload"))
        }
        (Some(attached), _) => attached.as_slice(),
        (None, Some(detached)) => detached,
        (None, None) => {
            return Err(invalid(
                "detached payload is required for complete validation",
            ))
        }
    };
    let validated =
        crate::validate::decode_and_validate_budget(selected, now_epoch_secs, &mut budget)?;
    if validated.coswid_opaque_count != 0 {
        return Err(invalid(
            "strict validation cannot validate opaque CoSWID content",
        ));
    }
    let signed = CoseSign1Corim {
        protected_header_bytes,
        protected,
        unprotected,
        payload,
        signature,
    };
    Ok((signed, validated))
}

fn invalid(message: &str) -> ValidationError {
    ValidationError::Invalid(message.into())
}

fn field(fields: &[(Value, Value)], key: i64) -> Option<&Value> {
    fields
        .iter()
        .find(|(label, _)| *label == Value::Integer(key.into()))
        .map(|(_, value)| value)
}

fn header_labels(fields: &[(Value, Value)]) -> Result<(), ValidationError> {
    if fields
        .iter()
        .any(|(key, _)| !matches!(key, Value::Integer(_) | Value::Text(_)))
    {
        return Err(invalid("COSE header labels must be integer or text"));
    }
    Ok(())
}

fn timestamp(value: &Value) -> Result<Number, ValidationError> {
    match value {
        Value::Integer(value) => {
            i64::try_from(*value).map_err(|_| invalid("CWT time is outside i64 range"))?;
            Ok(Number::Int(*value))
        }
        Value::Float(value)
            if value.is_finite()
                && *value >= -9_223_372_036_854_775_808.0
                && *value < 9_223_372_036_854_775_808.0 =>
        {
            Ok(Number::Float(*value))
        }
        _ => Err(invalid("CWT time must be finite and within i64 range")),
    }
}

fn same_time(left: Option<Number>, right: Option<Number>) -> bool {
    match (left, right) {
        (None, None) => true,
        (Some(left), Some(right)) => {
            NumberMatcher::Exact(left).matches(&NumberMatcher::Exact(right))
        }
        _ => false,
    }
}

fn check_window(
    min: Option<Number>,
    max: Option<Number>,
    now: i64,
    exclusive_end: bool,
) -> Result<(), ValidationError> {
    let range = NumberMatcher::Range { min, max };
    range.valid().map_err(ValidationError::Invalid)?;
    if exclusive_end && min.is_some() && same_time(min, max) {
        return Err(invalid("CWT validity interval is empty"));
    }
    let clock = Number::Int(now.into());
    let observation = NumberMatcher::Exact(clock);
    if !(NumberMatcher::Range { min, max: None }).matches(&observation) {
        return Err(ValidationError::NotYetValid);
    }
    if !(NumberMatcher::Range { min: None, max }).matches(&observation)
        || exclusive_end && same_time(max, Some(clock))
    {
        return Err(ValidationError::Expired);
    }
    Ok(())
}

fn original_claims(
    fields: &[(Value, Value)],
) -> Result<(Option<Number>, Option<Number>), ValidationError> {
    let mut flat_issuer = None;
    let mut flat_subject = None;
    let mut flat_nbf = None;
    let mut flat_exp = None;
    for (key, value) in fields {
        match (key, value) {
            (Value::Integer(key), Value::Text(text)) if *key == i128::from(CWT_CLAIM_ISS) => {
                flat_issuer = Some(text)
            }
            (Value::Integer(key), Value::Text(text)) if *key == i128::from(CWT_CLAIM_SUB) => {
                flat_subject = Some(text)
            }
            (Value::Integer(key), Value::Integer(_) | Value::Float(_))
                if *key == i128::from(CWT_CLAIM_NBF) =>
            {
                flat_nbf = Some(timestamp(value)?)
            }
            (Value::Integer(key), Value::Integer(_) | Value::Float(_))
                if *key == i128::from(CWT_CLAIM_EXP) =>
            {
                flat_exp = Some(timestamp(value)?)
            }
            _ => {}
        }
    }
    if let Some(nested) = field(fields, COSE_HEADER_CWT_CLAIMS) {
        let Value::Map(claims) = nested else {
            return Err(invalid("CWT-Claims must be a map"));
        };
        let nbf = field(claims, CWT_CLAIM_NBF).map(timestamp).transpose()?;
        let exp = field(claims, CWT_CLAIM_EXP).map(timestamp).transpose()?;
        for (flat, key) in [(flat_issuer, CWT_CLAIM_ISS), (flat_subject, CWT_CLAIM_SUB)] {
            if let Some(flat) = flat {
                if field(claims, key) != Some(&Value::Text(flat.clone())) {
                    return Err(invalid("flat and nested CWT identity claims disagree"));
                }
            }
        }
        if flat_nbf.is_some() && !same_time(flat_nbf, nbf)
            || flat_exp.is_some() && !same_time(flat_exp, exp)
        {
            return Err(invalid("flat and nested CWT time claims disagree"));
        }
        Ok((nbf, exp))
    } else {
        if flat_issuer.is_none()
            && (flat_subject.is_some() || flat_nbf.is_some() || flat_exp.is_some())
        {
            return Err(invalid("flat CWT claims require an issuer"));
        }
        Ok((flat_nbf, flat_exp))
    }
}
