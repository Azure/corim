// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Resource-limit regressions for untrusted CBOR (RFC 8949 §10).

use corim::cbor::{self, constants as c, value::Value};

fn nested_arrays(depth: usize) -> Vec<u8> {
    let mut bytes = vec![(c::MAJOR_ARRAY << 5) | 1; depth];
    bytes.push(c::BYTE_NULL);
    bytes
}

#[test]
fn default_decoder_rejects_depth_65() {
    assert!(cbor::decode::<Value>(&nested_arrays(65)).is_err());
}

#[test]
fn default_decoder_accepts_depth_64() {
    assert!(cbor::decode::<Value>(&nested_arrays(64)).is_ok());
}

#[test]
fn default_decoder_rejects_more_than_one_million_values() {
    let mut bytes = vec![(c::MAJOR_ARRAY << 5) | c::AI_FOUR_BYTES];
    bytes.extend_from_slice(&1_000_000_u32.to_be_bytes());
    bytes.resize(bytes.len() + 1_000_000, c::BYTE_NULL);
    // The array itself is also a decoded value.
    assert!(cbor::decode::<Value>(&bytes).is_err());
}

#[test]
fn default_decoder_rejects_input_over_16_mib() {
    let mut bytes = vec![(c::MAJOR_BYTES << 5) | c::AI_FOUR_BYTES];
    bytes.extend_from_slice(&(16_u32 * 1024 * 1024).to_be_bytes());
    bytes.resize(bytes.len() + 16 * 1024 * 1024, 0);
    assert!(cbor::decode::<Value>(&bytes).is_err());
}
