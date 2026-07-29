// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Error types for the corim crate.

#[allow(unused_imports)]
use crate::nostd_prelude::*;
use thiserror::Error;

/// Errors from CBOR encoding.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum EncodeError {
    /// CBOR serialization failed.
    #[error("CBOR serialization failed: {0}")]
    Serialization(String),
}

/// Errors from CBOR decoding.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum DecodeError {
    /// CBOR deserialization failed.
    #[error("CBOR deserialization failed: {0}")]
    Deserialization(String),

    /// Expected a specific CBOR tag but found a different one.
    #[error("expected CBOR tag {expected}, found {found}")]
    UnexpectedTag {
        /// The tag number that was expected.
        expected: u64,
        /// The tag number that was found.
        found: u64,
    },

    /// The decoded structure is invalid.
    #[error("invalid structure: {0}")]
    InvalidStructure(String),
}

/// Errors from the builder API.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum BuilderError {
    /// A required field was not set.
    #[error("missing required field: {0}")]
    MissingField(&'static str),

    /// The triples map is empty.
    #[error("triples map is empty — at least one triple type must be populated")]
    EmptyTriples,

    /// No CoMID tags were added to the CoRIM.
    #[error("at least one CoMID tag is required")]
    NoTags,

    /// A list that must be non-empty (CDDL `[+ T]`) was empty.
    #[error("CDDL requires [+ {field}] but the list is empty")]
    EmptyList {
        /// Name of the field.
        field: &'static str,
    },

    /// Validity constraint violated (not_before > not_after).
    #[error("invalid validity: not_before must be <= not_after")]
    InvalidValidity,

    /// A validation error from a type's `Valid()` check.
    #[error("validation error: {0}")]
    Validation(String),

    /// A triple with "condition" semantics (e.g. conditional-endorsement-series,
    /// conditional-endorsement, endorsed) references an environment that does
    /// not match any reference-triple environment in the same CoMID.
    ///
    /// Only produced when `ComidBuilder::strict_links(true)` is set; the wire
    /// format itself imposes no such constraint.
    #[error("{triple_kind} triple at index {index} references an environment not characterised by any reference-triple")]
    UnanchoredConditionEnv {
        /// Which triple list the offending entry came from.
        triple_kind: &'static str,
        /// Position of the entry within that list (0-based).
        index: usize,
    },

    /// A condition-side measurement on a conditional triple (a CES
    /// `claims_list`, a CES series `condition`, or a CE
    /// `stateful-environment-record` measurement list) does not
    /// structurally equal any measurement in a reference triple **for
    /// the same env**.
    ///
    /// Only produced when `ComidBuilder::strict_links(true)` is set; the
    /// wire format itself imposes no such constraint, and the lint
    /// deliberately uses structural equality rather than the richer
    /// matching rules verifiers apply at appraisal time.
    #[error(
        "{triple_kind} triple at index {triple_index}, measurement {measurement_index}: \
         not anchored by any reference-triple measurement for the same env"
    )]
    UnanchoredConditionMeasurement {
        /// Which triple list / sub-list the offending entry came from.
        /// One of: `"conditional-endorsement-series"` (the CES
        /// `claims_list`), `"conditional-endorsement-series-condition"`
        /// (a series record's `condition`), or
        /// `"conditional-endorsement"` (a CE stateful-environment-record
        /// measurement).
        triple_kind: &'static str,
        /// Position of the offending triple within its list (0-based).
        triple_index: usize,
        /// Position of the offending measurement within the to-anchor
        /// list (0-based).
        measurement_index: usize,
    },

    /// `declare_env` was called twice with the same label on one builder.
    #[error("environment label {label:?} already declared on this builder")]
    DuplicateEnvLabel {
        /// The duplicated label.
        label: String,
    },

    /// An `EnvRef` produced by one `ComidBuilder` was passed to a different
    /// `ComidBuilder`'s `add_*_for` method.
    #[error("environment ref {label:?} was produced by a different builder")]
    RefFromOtherBuilder {
        /// The label carried by the foreign ref.
        label: String,
    },

    /// An encoding error occurred during building.
    #[error("encoding error: {0}")]
    Encode(#[from] EncodeError),
}

/// Errors from validation / appraisal.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum ValidationError {
    /// A decode error occurred during validation.
    #[error("decode error: {0}")]
    Decode(#[from] DecodeError),

    /// The CoRIM has expired.
    #[error("CoRIM has expired (not-after is in the past)")]
    Expired,

    /// The CoRIM is not yet valid (not-before is in the future).
    #[error("CoRIM is not yet valid (not-before is in the future)")]
    NotYetValid,

    /// No CoMID tags were found in the CoRIM.
    #[error("no CoMID tags found in the CoRIM")]
    NoComidTags,

    /// The CoMID tag-identity is missing tag-id.
    #[error("CoMID tag-identity is missing tag-id")]
    MissingTagId,

    /// The CoMID triples map is empty.
    #[error("CoMID triples map is empty")]
    EmptyTriples,

    /// The CoTL tags-list is empty.
    #[error("CoTL tags-list is empty")]
    EmptyTagsList,

    /// A type-level validation failed.
    #[error("{0}")]
    Invalid(String),

    /// A non-empty constraint was violated.
    #[error("non-empty constraint violated: {0}")]
    NonEmpty(String),

    /// No common digest algorithms between reference and evidence.
    #[error("no common digest algorithms between reference and evidence")]
    NoCommonAlgorithms,

    /// Digest values do not match for a given algorithm.
    #[error("digest mismatch for algorithm {alg}")]
    DigestMismatch {
        /// The algorithm identifier where the mismatch occurred.
        alg: i64,
    },

    /// SVN values do not match.
    #[error("SVN mismatch: expected {expected}, got {actual}")]
    SvnMismatch {
        /// The expected SVN value.
        expected: u64,
        /// The actual SVN value.
        actual: u64,
    },

    /// Conditional endorsement series entries use inconsistent mkeys.
    #[error("conditional-endorsement-series entries use inconsistent mkeys")]
    InconsistentMkeys,

    /// System clock error.
    #[error("system clock error: {0}")]
    Clock(String),

    /// Input payload exceeds maximum allowed size.
    #[error("input payload too large: {size} bytes (max {max})")]
    PayloadTooLarge {
        /// Actual size in bytes.
        size: usize,
        /// Maximum allowed size in bytes.
        max: usize,
    },
}
