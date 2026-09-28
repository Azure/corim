// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! CBOR encoding/decoding abstraction layer.
//!
//! Provides a [`CborCodec`] trait for deterministic CBOR encoding/decoding,
//! plus a backend-agnostic [`value::Value`] enum and [`value::Tagged`] wrapper.
//!
//! The default (and currently only) backend is the in-house minimal CBOR
//! implementation in [`minimal`], which guarantees RFC 8949 §4.2.1
//! deterministic encoding with zero external dependencies.
//!
//! The [`CborCodec`] trait is designed so that alternative backends (e.g.,
//! ciborium) can be added behind feature gates in the future without
//! changing any type definitions or public APIs.

#[allow(unused_imports)]
use crate::nostd_prelude::*;
pub mod constants;
mod limits;
pub(crate) mod map_keys;
pub mod minimal;
mod minimal_backend;

pub mod value;

pub(crate) use limits::DecodeBudget;
pub use limits::{
    DecodeLimits, DecodeSession, DEFAULT_MAX_INPUT_BYTES, DEFAULT_MAX_VALUES, MAX_COLLECTION_ITEMS,
    MAX_DECODE_DEPTH,
};

use crate::error::{DecodeError, EncodeError};
use serde::{de::DeserializeOwned, Serialize};

/// Trait abstracting CBOR encode/decode operations.
///
/// Only deterministic encoding is provided. Map keys are emitted in ascending
/// integer order by the `CborSerialize` derive macro, satisfying RFC 8949
/// §4.2.1 (CBOR Core Deterministic Encoding).
///
/// This trait exists so that alternative CBOR backends can be plugged in
/// behind feature gates without changing the rest of the crate.
pub trait CborCodec {
    /// Encode a value as deterministic CBOR bytes.
    fn encode_deterministic<T: Serialize>(value: &T) -> Result<Vec<u8>, EncodeError>;

    /// Decode a value from CBOR bytes.
    fn decode<T: DeserializeOwned>(bytes: &[u8]) -> Result<T, DecodeError>;
}

/// The active CBOR codec.
pub type DefaultCodec = minimal_backend::MinimalCodec;

/// Convenience: encode using the default codec.
pub fn encode<T: Serialize>(value: &T) -> Result<Vec<u8>, EncodeError> {
    DefaultCodec::encode_deterministic(value)
}

/// Legacy convenience decoder: consumes the first item and ignores trailing bytes.
///
/// Retained in 0.2.x for compatibility; planned for deprecation in favor of
/// [`decode_exact`] for documents or [`decode_prefix`] for sequences. No
/// compiler deprecation warning is emitted yet. Default resource limits apply.
pub fn decode<T: DeserializeOwned>(bytes: &[u8]) -> Result<T, DecodeError> {
    DefaultCodec::decode(bytes)
}

/// Decode with explicit parser limits (RFC 8949 §10).
///
/// Byte strings remain opaque at this level. Use limits-aware document APIs
/// when embedded CBOR must share the outer document's budget. Arbitrary
/// allocations/recursive decoding in user `Deserialize` code are not bounded.
/// Existing [`decode`] uses [`DecodeLimits::default`].
/// Like [`decode`], this legacy API ignores trailing data. Prefer
/// [`decode_exact_with_limits`] or [`decode_prefix_with_limits`] in new code.
pub fn decode_with_limits<T: DeserializeOwned>(
    bytes: &[u8],
    limits: &DecodeLimits,
) -> Result<T, DecodeError> {
    DecodeBudget::new(limits)?.decode(bytes)
}

/// Decode exactly one CBOR item with default resource limits (RFC 8949 §3).
/// Rejects any remaining bytes, including whitespace or another valid item.
/// Byte-string contents remain opaque; use document APIs for embedded CBOR.
pub fn decode_exact<T: DeserializeOwned>(bytes: &[u8]) -> Result<T, DecodeError> {
    decode_exact_with_limits(bytes, &DecodeLimits::default())
}

/// Decode exactly one CBOR item with explicit resource limits.
pub fn decode_exact_with_limits<T: DeserializeOwned>(
    bytes: &[u8],
    limits: &DecodeLimits,
) -> Result<T, DecodeError> {
    DecodeBudget::new(limits)?.decode_exact(bytes)
}

/// Decode the first CBOR item and return a borrowed, unparsed remainder.
/// Suitable for CBOR sequences (RFC 8742 §2). Default input-size limits
/// apply to the entire supplied slice, not only the first item.
pub fn decode_prefix<T: DeserializeOwned>(bytes: &[u8]) -> Result<(T, &[u8]), DecodeError> {
    decode_prefix_with_limits(bytes, &DecodeLimits::default())
}

/// Decode a prefix with explicit resource limits and return the unparsed suffix.
/// Only the parsed item consumes values; for a cumulative sequence budget use
/// [`DecodeSession::decode_prefix`]. Values are owned; only the suffix borrows.
pub fn decode_prefix_with_limits<'a, T: DeserializeOwned>(
    bytes: &'a [u8],
    limits: &DecodeLimits,
) -> Result<(T, &'a [u8]), DecodeError> {
    DecodeBudget::new(limits)?.decode_prefix(bytes)
}
