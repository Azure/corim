// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Minimal CBOR backend: [`MinimalCodec`] implementation using
//! the in-house encoder/decoder.
//!
//! This backend avoids the ciborium dependency entirely. It goes through
//! the backend-agnostic [`Value`](super::value::Value) as an intermediate
//! representation:
//!
//! ```text
//! Encode: T →(serde)→ Value →(minimal::encode_value)→ CBOR bytes
//! Decode: CBOR bytes →(minimal::decode_value)→ Value →(serde)→ T
//! ```
//!
//! To enable: set `features = ["cbor-minimal"]` and disable `cbor-ciborium`.

#![allow(dead_code)] // Only used when cbor-ciborium is disabled

use crate::cbor::CborCodec;
use crate::error::{DecodeError, EncodeError};
use serde::{de::DeserializeOwned, Serialize};

pub(crate) mod value_de;
pub(crate) mod value_ser;

/// CBOR codec using the in-house minimal encoder/decoder.
pub struct MinimalCodec;

impl CborCodec for MinimalCodec {
    fn encode_deterministic<T: Serialize>(value: &T) -> Result<Vec<u8>, EncodeError> {
        // Step 1: Serialize T into a Value tree via serde
        let val = value_ser::to_value(value).map_err(EncodeError::Serialization)?;
        // Step 2: Encode Value to deterministic CBOR bytes
        let mut buf = Vec::new();
        super::minimal::encode_value(&mut buf, &val)
            .map_err(|e| EncodeError::Serialization(e.to_string()))?;
        Ok(buf)
    }

    fn decode<T: DeserializeOwned>(bytes: &[u8]) -> Result<T, DecodeError> {
        // Step 1: Decode CBOR bytes into a Value tree (preserves tags)
        let mut cursor = std::io::Cursor::new(bytes);
        let val = super::minimal::decode_value(&mut cursor)
            .map_err(|e| DecodeError::Deserialization(e.to_string()))?;

        // Step 2: Deserialize Value into T via serde.
        // Tags are preserved in the Value tree. The value_de module
        // presents Value::Tag as a 2-element seq to the serde visitor.
        // Types that expect tags (Tagged<T>, type-choice enums) handle
        // this correctly because their Deserialize impls go through
        // Value::deserialize which calls deserialize_any, and our
        // ValueDeserializer presents the tag data appropriately.
        let result = value_de::from_value(val).map_err(DecodeError::Deserialization)?;
        Ok(result)
    }
}
