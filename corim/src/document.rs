// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! One document-validation operation with explicit coverage (RFC 9334 §8).
//! Signed and unsigned documents share one parser budget. Authentication is
//! always the caller's responsibility; successful validation is not trust.

use crate::cbor::{self, value::Value, DecodeLimits};
use crate::nostd_prelude::*;
use crate::profile::ProfileRegistry;
use crate::types::corim::{ConciseTagChoice, ProfileChoice};
use crate::types::signed::{validation::validate_parsed_signed, CoseSign1Corim};
use crate::types::tags::{TAG_LEGACY_SIGNED, TAG_LEGACY_TOP, TAG_SIGNED_CORIM};
use crate::validate::ValidatedCorim;
use crate::{Validate, ValidationError};

/// Inspect framing and shared resource limits while retaining the original tree.
///
/// Known embedded CBOR boundaries are checked, but payload schemas, clocks,
/// profile semantics and signatures are not validated. Byte strings remain
/// byte strings in the returned value; no legacy encoding is normalized.
pub fn inspect(bytes: &[u8], limits: &DecodeLimits) -> Result<Value, crate::DecodeError> {
    cbor::DecodeBudget::new(limits)?.inspect_document_value(bytes)
}

/// Temporal validation requested for an operation (RFC 9334 §8).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum TimeCheck {
    /// Check validity at these Unix epoch seconds.
    At(i64),
    /// Deliberately omit clock comparisons; the outcome is partial.
    Skip,
}

impl TimeCheck {
    fn timestamp(self) -> Option<i64> {
        match self {
            Self::At(now) => Some(now),
            Self::Skip => None,
        }
    }
}

/// Immutable settings; parser counters are created once by [`validate`].
#[derive(Clone, Debug)]
pub struct ValidationContext<'a> {
    time: TimeCheck,
    registry: &'a ProfileRegistry,
    limits: DecodeLimits,
    detached_payload: Option<&'a [u8]>,
}

impl<'a> ValidationContext<'a> {
    /// Select the clock policy and profile implementations for this operation.
    pub fn new(time: TimeCheck, registry: &'a ProfileRegistry) -> Self {
        Self {
            time,
            registry,
            limits: DecodeLimits::default(),
            detached_payload: None,
        }
    }

    /// Set parser limits. Invalid ceilings fail when validation starts.
    #[must_use]
    pub fn with_limits(mut self, limits: DecodeLimits) -> Self {
        self.limits = limits;
        self
    }

    /// Supply the actual payload of a detached signed envelope (RFC 9052 §4).
    /// An attached envelope must contain identical bytes; unsigned input rejects
    /// this setting rather than silently ignoring it.
    #[must_use]
    pub fn with_detached_payload(mut self, payload: &'a [u8]) -> Self {
        self.detached_payload = Some(payload);
        self
    }
}

/// Profile checks actually performed (RFC 9334 §8).
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum ProfileCoverage {
    /// No profile was declared.
    NotDeclared,
    /// The declared profile was checked.
    Checked(ProfileChoice),
    /// No implementation was available; the outcome is partial.
    Unregistered(ProfileChoice),
}

/// Decode-only document-level compatibility observed by the parser.
///
/// These notes describe envelope/tag normalization, not every legacy scalar
/// representation. See `diagnose` for detailed value-level interoperability.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum CompatibilityNote {
    /// An obsolete outer tag was accepted.
    LegacyOuterTag(u64),
    /// An unsigned payload omitted its CoRIM tag.
    BareCorimMap,
    /// A tag entry used the legacy untagged CoMID byte-string form.
    BareComidTag(usize),
    /// CWT claims appeared directly in the protected header.
    FlatCwtClaims,
}

/// Checks and deliberate omissions for a validated document.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ValidationCoverage {
    time: TimeCheck,
    profile: ProfileCoverage,
    unexamined_tags: Vec<usize>,
    compatibility: Vec<CompatibilityNote>,
}

impl ValidationCoverage {
    /// The temporal checks requested and performed.
    pub fn time(&self) -> TimeCheck {
        self.time
    }
    /// Profile checks performed or unavailable.
    pub fn profile(&self) -> &ProfileCoverage {
        &self.profile
    }
    /// Unknown tag indexes not examined by this implementation.
    pub fn unexamined_tags(&self) -> &[usize] {
        &self.unexamined_tags
    }
    /// Accepted document-level interoperability forms.
    pub fn compatibility(&self) -> &[CompatibilityNote] {
        &self.compatibility
    }
    /// Whether all checks within this non-cryptographic contract ran.
    pub fn is_complete(&self) -> bool {
        let profile_complete = match &self.profile {
            ProfileCoverage::NotDeclared | ProfileCoverage::Checked(_) => true,
            ProfileCoverage::Unregistered(_) => false,
        };
        matches!(self.time, TimeCheck::At(_)) && profile_complete && self.unexamined_tags.is_empty()
    }
}

/// A read-only document and the checks performed on that exact document.
///
/// Clone decoded data to edit it, then validate the resulting document again.
/// Signature and certificate authentication are never implied (RFC 9334 §8).
#[derive(Clone, Debug, PartialEq)]
pub struct ValidatedDocument {
    payload: ValidatedCorim,
    envelope: Option<CoseSign1Corim>,
    coverage: ValidationCoverage,
}

impl ValidatedDocument {
    /// Read the decoded unsigned document and its known tag contents.
    pub fn payload(&self) -> &ValidatedCorim {
        &self.payload
    }
    /// Read the original signed envelope, when present.
    pub fn envelope(&self) -> Option<&CoseSign1Corim> {
        self.envelope.as_ref()
    }
    /// Inspect check coverage before consuming the document.
    pub fn coverage(&self) -> &ValidationCoverage {
        &self.coverage
    }
    /// Consume the outcome to obtain editable data and its historical coverage.
    pub fn into_parts(self) -> (ValidatedCorim, Option<CoseSign1Corim>, ValidationCoverage) {
        (self.payload, self.envelope, self.coverage)
    }
}

/// Validate a complete signed or unsigned document with one parser budget.
///
/// Malformed documents, missing detached payloads and unauthenticated hash
/// preimages are errors. Skipped time checks, unregistered profiles and unknown
/// tag contents return an explicit partial outcome. Unknown extension keys do
/// not by themselves make an outcome partial. Accepted legacy envelope/tag
/// encodings are noted without changing original protected bytes.
pub fn validate(
    bytes: &[u8],
    context: &ValidationContext<'_>,
) -> Result<ValidatedDocument, ValidationError> {
    let mut budget = cbor::DecodeBudget::new(&context.limits)?;
    let mut value = budget.decode_value_exact(bytes)?;
    let mut compatibility = Vec::new();
    while let Value::Tag(tag @ (TAG_LEGACY_TOP | TAG_LEGACY_SIGNED), inner) = value {
        compatibility.push(CompatibilityNote::LegacyOuterTag(tag));
        value = *inner;
    }
    let (envelope, payload) = if matches!(value, Value::Tag(TAG_SIGNED_CORIM, _)) {
        let validated = validate_parsed_signed(
            value,
            context.detached_payload,
            context.time.timestamp(),
            &mut budget,
        )?;
        if validated.used_flat_cwt {
            compatibility.push(CompatibilityNote::FlatCwtClaims);
        }
        if validated
            .envelope
            .payload
            .as_deref()
            .or(context.detached_payload)
            .and_then(|bytes| bytes.first())
            .is_some_and(|byte| byte >> 5 == cbor::constants::MAJOR_MAP)
        {
            compatibility.push(CompatibilityNote::BareCorimMap);
        }
        (Some(validated.envelope), validated.payload)
    } else {
        if context.detached_payload.is_some() {
            return Err(ValidationError::Invalid(
                "detached payload supplied for unsigned document".into(),
            ));
        }
        if matches!(value, Value::Map(_)) {
            compatibility.push(CompatibilityNote::BareCorimMap);
        }
        (
            None,
            crate::validate::validate_parsed_corim(value, context.time.timestamp(), &mut budget)?,
        )
    };
    payload.corim.valid().map_err(ValidationError::Invalid)?;
    if payload.coswid_opaque_count != 0 {
        return Err(ValidationError::Invalid(
            "cannot validate opaque CoSWID content".into(),
        ));
    }
    let mut unexamined_tags = Vec::new();
    for (index, tag) in payload.corim.tags.iter().enumerate() {
        match tag {
            ConciseTagChoice::BareBstr(_) => {
                compatibility.push(CompatibilityNote::BareComidTag(index))
            }
            ConciseTagChoice::Comid(_)
            | ConciseTagChoice::Cotl(_)
            | ConciseTagChoice::Coswid(_) => {}
            _ => unexamined_tags.push(index),
        }
    }
    let profile = match &payload.corim.profile {
        None => ProfileCoverage::NotDeclared,
        Some(id) if context.registry.get(id).is_none() => ProfileCoverage::Unregistered(id.clone()),
        Some(id) => {
            crate::validate::validate_corim_profile(
                &payload.corim,
                &payload.comids,
                context.registry,
            )?;
            ProfileCoverage::Checked(id.clone())
        }
    };
    Ok(ValidatedDocument {
        payload,
        envelope,
        coverage: ValidationCoverage {
            time: context.time,
            profile,
            compatibility,
            unexamined_tags,
        },
    })
}
