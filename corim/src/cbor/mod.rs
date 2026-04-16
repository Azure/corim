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
pub mod minimal;
mod minimal_backend;

pub mod value;

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

/// Convenience: decode using the default codec.
pub fn decode<T: DeserializeOwned>(bytes: &[u8]) -> Result<T, DecodeError> {
    DefaultCodec::decode(bytes)
}
