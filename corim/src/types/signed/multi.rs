//! Multi-signature CoRIM per draft-ietf-rats-corim-12 §4.2.3 and RFC 9052 §4.
//!
//! ```text
//! signed-corim /= #6.98([protected, unprotected, payload, [+ signature]])
//! signature = [protected, unprotected, signature-bytes]
//! ```
//!
//! Headers retain their original bytes. Cryptographic operations, creator
//! authorization and signature acceptance policy remain the caller's job.

use super::{validation, CoseSign1Corim, ProtectedCorimHeaderMap};
use crate::cbor::{self, value::Value, DecodeLimits};
use crate::nostd_prelude::*;
use crate::types::tags::{TAG_MULTI_SIGNED_CORIM, TAG_SIGNED_CORIM};
use crate::{BuilderError, DecodeError, EncodeError, ValidationError};

/// COSE multi-signature context, RFC 9052 §4.4.
const SIGNATURE_CONTEXT: &str = "Signature";

/// A signature entry in a COSE_Sign envelope (RFC 9052 §4.1).
#[derive(Clone, Debug, PartialEq)]
pub struct CoseSignature {
    protected_bytes: Vec<u8>,
    protected: ProtectedCorimHeaderMap,
    /// Unprotected signature headers, which are not authenticated.
    pub unprotected: Vec<(Value, Value)>,
    /// Signature bytes to authenticate externally.
    pub signature: Vec<u8>,
}

impl CoseSignature {
    /// Parse an original per-signature header without rewriting it (§4.2.3.1).
    pub fn from_parts(
        protected_bytes: Vec<u8>,
        unprotected: Vec<(Value, Value)>,
        signature: Vec<u8>,
    ) -> Result<Self, DecodeError> {
        let protected = ProtectedCorimHeaderMap::decode_with_limits(
            &protected_bytes,
            &DecodeLimits::default(),
        )?;
        Ok(Self {
            protected_bytes,
            protected,
            unprotected,
            signature,
        })
    }

    /// Header derived from the original signature protected bytes (§4.2.3.1).
    pub fn protected(&self) -> &ProtectedCorimHeaderMap {
        &self.protected
    }
    /// Exact bytes included in the signature structure (RFC 9052 §4.4).
    pub fn protected_header_bytes(&self) -> &[u8] {
        &self.protected_bytes
    }
}

/// A COSE_Sign CoRIM envelope (draft-12 §4.2.3).
#[derive(Clone, Debug, PartialEq)]
pub struct CoseSignCorim {
    protected_bytes: Vec<u8>,
    protected: ProtectedCorimHeaderMap,
    /// Unprotected body headers, which are not authenticated.
    pub unprotected: Vec<(Value, Value)>,
    /// Attached bytes or a detached (nil) payload.
    pub payload: Option<Vec<u8>>,
    signatures: Vec<CoseSignature>,
}

impl CoseSignCorim {
    /// Assemble and check a multi-signature envelope (§4.2.3.1–§4.2.3.2).
    ///
    /// Every header must be complete; the first signer must agree with the
    /// body creator identity and algorithm. No signature is authenticated.
    pub fn from_parts(
        protected_bytes: Vec<u8>,
        unprotected: Vec<(Value, Value)>,
        payload: Option<Vec<u8>>,
        signatures: Vec<CoseSignature>,
    ) -> Result<Self, DecodeError> {
        let value = wire_value(
            &protected_bytes,
            &unprotected,
            payload.as_deref(),
            &signatures,
        );
        let bytes = cbor::encode(&value)
            .map_err(|error| DecodeError::InvalidStructure(error.to_string()))?;
        decode_multi_signed_corim(&bytes)
    }
    /// Read the creator's body protected header (§4.2.3.2).
    pub fn protected(&self) -> &ProtectedCorimHeaderMap {
        &self.protected
    }
    /// Exact original body protected bytes (RFC 9052 §4.4).
    pub fn protected_header_bytes(&self) -> &[u8] {
        &self.protected_bytes
    }
    /// All signature entries in their original order (§4.2.3.2).
    pub fn signatures(&self) -> &[CoseSignature] {
        &self.signatures
    }
    /// Whether this envelope carries a nil payload (RFC 9052 §4.1).
    pub fn is_detached(&self) -> bool {
        self.payload.is_none()
    }
    /// Construct the indexed signer's attached-payload TBS (RFC 9052 §4.4).
    pub fn to_be_signed(&self, index: usize, aad: &[u8]) -> Result<Vec<u8>, EncodeError> {
        let payload = self.payload.as_deref().ok_or_else(|| {
            EncodeError::Serialization("payload is detached; use to_be_signed_detached".into())
        })?;
        self.to_be_signed_detached(index, payload, aad)
    }
    /// Construct the indexed signer's TBS with supplied payload (RFC 9052 §4.4).
    pub fn to_be_signed_detached(
        &self,
        index: usize,
        payload: &[u8],
        aad: &[u8],
    ) -> Result<Vec<u8>, EncodeError> {
        let signer = self
            .signatures
            .get(index)
            .ok_or_else(|| EncodeError::Serialization("signature index out of range".into()))?;
        build_sig_structure(&self.protected_bytes, &signer.protected_bytes, aad, payload)
    }
}

/// Signed-envelope dispatch for generic document consumers (draft-12 §4.2).
#[derive(Clone, Debug, PartialEq)]
#[non_exhaustive]
pub enum SignedEnvelope {
    /// Single-signature COSE_Sign1 (tag 18).
    Sign1(CoseSign1Corim),
    /// Multi-signature COSE_Sign (tag 98).
    Sign(CoseSignCorim),
}

impl SignedEnvelope {
    /// Body protected header; this identifies the creator in COSE_Sign.
    pub fn protected(&self) -> &ProtectedCorimHeaderMap {
        match self {
            Self::Sign1(value) => value.protected(),
            Self::Sign(value) => value.protected(),
        }
    }
    /// Original protected body bytes used for verification (RFC 9052 §4.4).
    pub fn protected_header_bytes(&self) -> &[u8] {
        match self {
            Self::Sign1(value) => value.protected_header_bytes(),
            Self::Sign(value) => value.protected_header_bytes(),
        }
    }
    /// Attached payload, if any (RFC 9052 §4).
    pub fn payload(&self) -> Option<&[u8]> {
        match self {
            Self::Sign1(value) => value.payload.as_deref(),
            Self::Sign(value) => value.payload.as_deref(),
        }
    }
    /// Unprotected body headers (RFC 9052 §4).
    pub fn unprotected(&self) -> &[(Value, Value)] {
        match self {
            Self::Sign1(value) => &value.unprotected,
            Self::Sign(value) => &value.unprotected,
        }
    }
    /// The envelope's CBOR tag, draft-12 §4.2.
    pub fn tag(&self) -> u64 {
        match self {
            Self::Sign1(_) => TAG_SIGNED_CORIM,
            Self::Sign(_) => TAG_MULTI_SIGNED_CORIM,
        }
    }
    /// Whether the envelope carries a nil payload (RFC 9052 §4).
    pub fn is_detached(&self) -> bool {
        self.payload().is_none()
    }
}

/// Compare signed-envelope shape and all protected headers (draft-12 §4.2).
///
/// Signer order is significant: entry zero identifies the creator. Signature
/// bytes are not compared, and this does not authenticate either envelope.
pub fn compare_signed_envelopes(
    input: &SignedEnvelope,
    baseline: &SignedEnvelope,
) -> Result<crate::baseline::ConformanceReport, ValidationError> {
    use crate::baseline::{ConformanceReport, MismatchKind, PathSegment, StructuralMismatch};
    let mut report = ConformanceReport::default();
    if input.tag() != baseline.tag() {
        report.structural_mismatches.push(StructuralMismatch {
            path: vec![PathSegment::Field("signed-envelope")],
            kind: MismatchKind::TypeMismatch {
                baseline: baseline.tag().to_string(),
                input: input.tag().to_string(),
            },
            detail: "signed-envelope types differ".into(),
        });
        return Ok(report);
    }
    report.merge(crate::baseline::compare_headers(
        input.protected(),
        baseline.protected(),
    )?);
    if let (SignedEnvelope::Sign(input), SignedEnvelope::Sign(baseline)) = (input, baseline) {
        if input.signatures.len() != baseline.signatures.len() {
            report.structural_mismatches.push(StructuralMismatch {
                path: vec![PathSegment::Field("signatures")],
                kind: MismatchKind::TypeMismatch {
                    baseline: baseline.signatures.len().to_string(),
                    input: input.signatures.len().to_string(),
                },
                detail: "signature counts differ".into(),
            });
        }
        for (index, (input, baseline)) in input
            .signatures
            .iter()
            .zip(&baseline.signatures)
            .enumerate()
        {
            let mut signer =
                crate::baseline::compare_headers(input.protected(), baseline.protected())?;
            for mismatch in &mut signer.structural_mismatches {
                mismatch.path.splice(
                    0..0,
                    [PathSegment::Field("signatures"), PathSegment::Index(index)],
                );
            }
            for difference in &mut signer.value_differences {
                difference.path.splice(
                    0..0,
                    [PathSegment::Field("signatures"), PathSegment::Index(index)],
                );
            }
            report.merge(signer);
        }
    }
    Ok(report)
}

/// Build `["Signature", body, signer, aad, payload]` (RFC 9052 §4.4).
pub fn build_sig_structure(
    body: &[u8],
    signer: &[u8],
    aad: &[u8],
    payload: &[u8],
) -> Result<Vec<u8>, EncodeError> {
    cbor::encode(&Value::Array(vec![
        Value::Text(SIGNATURE_CONTEXT.into()),
        Value::Bytes(body.to_vec()),
        Value::Bytes(signer.to_vec()),
        Value::Bytes(aad.to_vec()),
        Value::Bytes(payload.to_vec()),
    ]))
}

fn wire_value(
    body: &[u8],
    unprotected: &[(Value, Value)],
    payload: Option<&[u8]>,
    signatures: &[CoseSignature],
) -> Value {
    Value::Tag(
        TAG_MULTI_SIGNED_CORIM,
        Box::new(Value::Array(vec![
            Value::Bytes(body.to_vec()),
            Value::Map(unprotected.to_vec()),
            payload.map_or(Value::Null, |bytes| Value::Bytes(bytes.to_vec())),
            Value::Array(
                signatures
                    .iter()
                    .map(|signature| {
                        Value::Array(vec![
                            Value::Bytes(signature.protected_bytes.clone()),
                            Value::Map(signature.unprotected.clone()),
                            Value::Bytes(signature.signature.clone()),
                        ])
                    })
                    .collect(),
            ),
        ])),
    )
}

/// Encode without rewriting either protected-header byte string (§4.2.3).
pub fn encode_multi_signed_corim(envelope: &CoseSignCorim) -> Result<Vec<u8>, EncodeError> {
    let value = wire_value(
        &envelope.protected_bytes,
        &envelope.unprotected,
        envelope.payload.as_deref(),
        &envelope.signatures,
    );
    cbor::map_keys::check(&value).map_err(|error| EncodeError::Serialization(error.to_string()))?;
    if envelope.signatures.is_empty() {
        return Err(EncodeError::Serialization(
            "COSE_Sign requires at least one signature".into(),
        ));
    }
    cbor::encode(&value)
}

/// Decode multi-signature CoRIM with default limits (§4.2.3, RFC 8949 §10).
pub fn decode_multi_signed_corim(bytes: &[u8]) -> Result<CoseSignCorim, DecodeError> {
    decode_multi_signed_corim_with_limits(bytes, &DecodeLimits::default())
}

/// Decode with one budget for body, signer headers and payload (§4.2.3).
///
/// Header consistency and framing are checked, not current time, payload
/// semantics, signatures or certificate trust.
pub fn decode_multi_signed_corim_with_limits(
    bytes: &[u8],
    limits: &DecodeLimits,
) -> Result<CoseSignCorim, DecodeError> {
    let mut budget = cbor::DecodeBudget::new(limits)?;
    let value = budget.decode_value_exact(bytes)?;
    let prepared = prepare(value, &mut budget).map_err(decode_error)?;
    if !prepared.is_hash() {
        if let Some(payload) = &prepared.payload {
            budget.check_corim(payload)?;
        }
    }
    finish(prepared, None, &mut budget)
        .map(|(envelope, _)| envelope)
        .map_err(decode_error)
}

/// Decode either signed wire format with default limits (draft-12 §4.2).
pub fn decode_signed_envelope(bytes: &[u8]) -> Result<SignedEnvelope, DecodeError> {
    decode_signed_envelope_with_limits(bytes, &DecodeLimits::default())
}

/// Dispatch once and share limits across known embedded CBOR (RFC 8949 §10).
pub fn decode_signed_envelope_with_limits(
    bytes: &[u8],
    limits: &DecodeLimits,
) -> Result<SignedEnvelope, DecodeError> {
    let mut budget = cbor::DecodeBudget::new(limits)?;
    let value = crate::compat::peel_value(budget.decode_value_exact(bytes)?);
    let envelope = match value {
        value @ Value::Tag(TAG_SIGNED_CORIM, _) => SignedEnvelope::Sign1(
            super::envelope::decode_parsed_signed_budget(value, &mut budget)?,
        ),
        value @ Value::Tag(TAG_MULTI_SIGNED_CORIM, _) => {
            let prepared = prepare(value, &mut budget).map_err(decode_error)?;
            SignedEnvelope::Sign(finish(prepared, None, &mut budget).map_err(decode_error)?.0)
        }
        _ => {
            return Err(DecodeError::InvalidStructure(
                "expected signed CoRIM tag 18 or 98".into(),
            ))
        }
    };
    if !envelope.protected().is_hash_envelope() {
        if let Some(payload) = envelope.payload() {
            budget.check_corim(payload)?;
        }
    }
    Ok(envelope)
}

fn decode_error(error: ValidationError) -> DecodeError {
    match error {
        ValidationError::Decode(error) => error,
        other => DecodeError::InvalidStructure(other.to_string()),
    }
}
fn invalid(message: &str) -> ValidationError {
    ValidationError::Invalid(message.into())
}

struct PreparedSignature {
    bytes: Vec<u8>,
    tree: Value,
    metadata: Option<Value>,
    unprotected: Vec<(Value, Value)>,
    signature: Vec<u8>,
}
struct Prepared {
    body: PreparedSignature,
    payload: Option<Vec<u8>>,
    signatures: Vec<PreparedSignature>,
}
impl Prepared {
    fn is_hash(&self) -> bool {
        matches!(&self.body.tree, Value::Map(fields) if fields.iter().any(|(key,_)| *key == Value::Integer(i128::from(super::COSE_HEADER_PAYLOAD_HASH_ALG))))
    }
}
fn prepare_signature(
    bytes: Value,
    unprotected: Value,
    signature: Value,
    budget: &mut cbor::DecodeBudget,
) -> Result<PreparedSignature, ValidationError> {
    let Value::Bytes(bytes) = bytes else {
        return Err(invalid("protected header must be bstr"));
    };
    let Value::Map(unprotected) = unprotected else {
        return Err(invalid("unprotected header must be a map"));
    };
    let Value::Bytes(signature) = signature else {
        return Err(invalid("signature must be bstr"));
    };
    let (tree, metadata) = validation::prepare_header(&bytes, budget)?;
    Ok(PreparedSignature {
        bytes,
        tree,
        metadata,
        unprotected,
        signature,
    })
}
fn prepare(value: Value, budget: &mut cbor::DecodeBudget) -> Result<Prepared, ValidationError> {
    let Value::Tag(TAG_MULTI_SIGNED_CORIM, inner) = crate::compat::peel_value(value) else {
        return Err(invalid("expected COSE_Sign tag 98"));
    };
    let Value::Array(parts) = *inner else {
        return Err(invalid("COSE_Sign must be an array"));
    };
    for part in &parts {
        cbor::map_keys::check(part)?;
    }
    let [body, unprotected, payload, signatures]: [Value; 4] = parts
        .try_into()
        .map_err(|_| invalid("COSE_Sign requires four elements"))?;
    let body = prepare_signature(body, unprotected, Value::Bytes(Vec::new()), budget)?;
    let payload = match payload {
        Value::Bytes(bytes) => Some(bytes),
        Value::Null => None,
        _ => return Err(invalid("payload must be bstr or nil")),
    };
    let Value::Array(entries) = signatures else {
        return Err(invalid("signatures must be an array"));
    };
    if entries.is_empty() {
        return Err(invalid("COSE_Sign requires at least one signature"));
    }
    let mut signatures = Vec::with_capacity(entries.len());
    for entry in entries {
        let Value::Array(parts) = entry else {
            return Err(invalid("signature entry must be an array"));
        };
        let [protected, unprotected, signature]: [Value; 3] = parts
            .try_into()
            .map_err(|_| invalid("signature entry requires three elements"))?;
        signatures.push(prepare_signature(
            protected,
            unprotected,
            signature,
            budget,
        )?);
    }
    Ok(Prepared {
        body,
        payload,
        signatures,
    })
}
fn finish(
    prepared: Prepared,
    now: Option<i64>,
    budget: &mut cbor::DecodeBudget,
) -> Result<(CoseSignCorim, bool), ValidationError> {
    let body = prepared.body;
    let (protected, mut used_flat) =
        validation::validate_header(body.tree, body.metadata, &body.unprotected, now, budget)?;
    let mut signatures = Vec::with_capacity(prepared.signatures.len());
    for (index, signature) in prepared.signatures.into_iter().enumerate() {
        let (header, flat) = validation::validate_header(
            signature.tree,
            signature.metadata,
            &signature.unprotected,
            now,
            budget,
        )?;
        used_flat |= flat;
        HeaderIdentity::from_header(&header)
            .check_against(&HeaderIdentity::from_header(&protected), index)
            .map_err(invalid)?;
        signatures.push(CoseSignature {
            protected_bytes: signature.bytes,
            protected: header,
            unprotected: signature.unprotected,
            signature: signature.signature,
        });
    }
    Ok((
        CoseSignCorim {
            protected_bytes: body.bytes,
            protected,
            unprotected: body.unprotected,
            payload: prepared.payload,
            signatures,
        },
        used_flat,
    ))
}

fn issuer(header: &ProtectedCorimHeaderMap) -> Option<&str> {
    header
        .cwt_claims
        .as_ref()
        .map(|claims| claims.iss.as_str())
        .or_else(|| {
            header
                .corim_meta
                .as_ref()
                .map(|meta| meta.signer.signer_name.as_str())
        })
}

#[derive(Default)]
pub(crate) struct HeaderIdentity {
    pub alg: Option<i64>,
    pub cwt_issuer: Option<String>,
    pub flat_issuer: Option<String>,
    pub metadata_issuer: Option<String>,
    pub hash_payload: bool,
}

impl HeaderIdentity {
    fn from_header(header: &ProtectedCorimHeaderMap) -> Self {
        Self {
            alg: Some(header.alg.to_i64()),
            cwt_issuer: issuer(header).map(ToOwned::to_owned),
            flat_issuer: None,
            metadata_issuer: None,
            hash_payload: header.is_hash_envelope(),
        }
    }
    fn issuer(&self) -> Option<&str> {
        self.cwt_issuer
            .as_deref()
            .or(self.flat_issuer.as_deref())
            .or(self.metadata_issuer.as_deref())
    }
    pub(crate) fn check_against(&self, body: &Self, index: usize) -> Result<(), &'static str> {
        if self.hash_payload != body.hash_payload {
            return Err("body and signer payload modes disagree");
        }
        if index == 0 && (self.alg != body.alg || self.issuer() != body.issuer()) {
            return Err("first signer must agree with body creator algorithm and metadata");
        }
        Ok(())
    }
}

pub(crate) fn validate_parsed_multi(
    value: Value,
    detached: Option<&[u8]>,
    now: Option<i64>,
    budget: &mut cbor::DecodeBudget,
) -> Result<(CoseSignCorim, crate::validate::ValidatedCorim, bool), ValidationError> {
    let prepared = prepare(value, budget)?;
    let payload = if prepared.is_hash() {
        None
    } else {
        let selected = match (prepared.payload.as_deref(), detached) {
            (Some(attached), Some(detached)) if attached != detached => {
                return Err(invalid("supplied payload differs from attached payload"))
            }
            (Some(attached), _) => attached,
            (None, Some(detached)) => detached,
            (None, None) => {
                return Err(invalid(
                    "detached payload is required for complete validation",
                ))
            }
        };
        let value = budget.decode_value_exact(selected)?;
        Some(crate::validate::prepare_parsed_corim(value, budget)?)
    };
    let (envelope, flat) = finish(prepared, now, budget)?;
    let payload =
        payload.ok_or_else(|| invalid("hash-envelope requires an authenticated preimage"))?;
    let payload = crate::validate::validate_prepared_corim(payload, now)?;
    Ok((envelope, payload, flat))
}

/// Builder for external multi-signature operations (RFC 9052 §4.4).
#[derive(Clone, Debug, PartialEq)]
#[must_use]
pub struct MultiSignedCorimBuilder {
    body: Vec<u8>,
    payload: Vec<u8>,
    signers: Vec<Vec<u8>>,
}
impl MultiSignedCorimBuilder {
    /// Set the creator and payload; signature index zero is the creator (§4.2.3.2).
    pub fn new(creator: ProtectedCorimHeaderMap, payload: Vec<u8>) -> Result<Self, BuilderError> {
        let body = cbor::encode(&creator)?;
        Ok(Self {
            signers: vec![body.clone()],
            body,
            payload,
        })
    }
    /// Add a signer with its own complete header (§4.2.3.1).
    pub fn add_signer(mut self, header: ProtectedCorimHeaderMap) -> Result<Self, BuilderError> {
        self.signers.push(cbor::encode(&header)?);
        Ok(self)
    }
    /// Return the indexed signer's TBS without cryptography (RFC 9052 §4.4).
    pub fn to_be_signed(&self, index: usize, aad: &[u8]) -> Result<Vec<u8>, BuilderError> {
        let signer = self
            .signers
            .get(index)
            .ok_or_else(|| BuilderError::Validation("signature index out of range".into()))?;
        Ok(build_sig_structure(&self.body, signer, aad, &self.payload)?)
    }
    /// Attach externally produced signatures and payload (§4.2.3).
    pub fn build_with_signatures(self, signatures: Vec<Vec<u8>>) -> Result<Vec<u8>, BuilderError> {
        self.build(signatures, false)
    }
    /// Attach signatures but emit nil for the payload (RFC 9052 §4.1).
    pub fn build_detached_with_signatures(
        self,
        signatures: Vec<Vec<u8>>,
    ) -> Result<Vec<u8>, BuilderError> {
        self.build(signatures, true)
    }
    fn build(self, signatures: Vec<Vec<u8>>, detached: bool) -> Result<Vec<u8>, BuilderError> {
        if signatures.len() != self.signers.len() {
            return Err(BuilderError::Validation(
                "signature count differs from signer count".into(),
            ));
        }
        let signers = self
            .signers
            .into_iter()
            .zip(signatures)
            .map(|(header, signature)| CoseSignature::from_parts(header, Vec::new(), signature))
            .collect::<Result<Vec<_>, _>>()
            .map_err(|error| BuilderError::Validation(error.to_string()))?;
        let envelope = CoseSignCorim::from_parts(
            self.body,
            Vec::new(),
            if detached { None } else { Some(self.payload) },
            signers,
        )
        .map_err(|error| BuilderError::Validation(error.to_string()))?;
        Ok(encode_multi_signed_corim(&envelope)?)
    }
}
