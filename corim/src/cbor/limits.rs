// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Decode resource budgets, following RFC 8949 §10. Limits are implementation
//! policy, not wire-format constraints mandated by the RFC.

use crate::error::DecodeError;
use crate::nostd_prelude::*;
use serde::de::DeserializeOwned;

use super::{minimal, minimal_backend, value::Value};

/// Hard ceiling on enclosing CBOR arrays, maps, and tags (RFC 8949 §10).
/// Callers may tighten this limit but cannot raise it for the recursive codec.
pub const MAX_DECODE_DEPTH: usize = 64;
/// Default maximum input size, matching the CoRIM document limit.
pub const DEFAULT_MAX_INPUT_BYTES: usize = 16 * 1024 * 1024;
/// Default aggregate number of decoded values, including map keys.
pub const DEFAULT_MAX_VALUES: usize = 1_000_000;
/// Hard ceiling on entries in a single array or map (RFC 8949 §10).
pub const MAX_COLLECTION_ITEMS: usize = 2_000_000;

/// Limits for decoding untrusted CBOR, including with `no_std + alloc`.
///
/// A scalar root has depth zero; every array, map, or tag adds one level.
/// Byte strings are opaque to the generic codec. Document entry points share
/// an aggregate value budget with their embedded CBOR decodes; each embedded
/// CBOR item has its own depth. These are parser limits, not an exact heap
/// quota or a bound on allocations in arbitrary user `Deserialize` code.
///
/// Depth and collection limits above the hard ceilings are rejected, not
/// silently clamped. Byte and value budgets may be raised by trusted callers.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub struct DecodeLimits {
    /// Maximum bytes in each input slice; document APIs check the outer input too.
    pub max_input_bytes: usize,
    /// Maximum enclosing arrays, maps, and tags; at most [`MAX_DECODE_DEPTH`].
    pub max_depth: usize,
    /// Aggregate values across a decode operation, including containers and keys.
    pub max_values: usize,
    /// Maximum entries per array/map; at most [`MAX_COLLECTION_ITEMS`].
    pub max_collection_items: usize,
}

impl Default for DecodeLimits {
    fn default() -> Self {
        Self {
            max_input_bytes: DEFAULT_MAX_INPUT_BYTES,
            max_depth: MAX_DECODE_DEPTH,
            max_values: DEFAULT_MAX_VALUES,
            max_collection_items: MAX_COLLECTION_ITEMS,
        }
    }
}

/// Explicit operation-local state; never thread-local or global.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct DecodeBudget {
    pub(crate) limits: DecodeLimits,
    remaining: usize,
    failure: Option<(&'static str, usize)>,
    inspect_framing: bool,
}

/// An operation-local decoder sharing limits across multiple embedded items.
///
/// Values consumed by failed syntax decodes still count toward the budget.
/// A resource failure is sticky: subsequent calls return a limit error rather
/// than resetting the budget. Start a new session only for a new operation.
/// No global/thread-local state is used; works with `no_std + alloc`.
/// Limits apply to CBOR parsing, not arbitrary user `Deserialize` code.
/// Cloning snapshots the remaining budget; it is not a shared counter.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DecodeSession {
    budget: DecodeBudget,
}

impl DecodeSession {
    /// Start a shared decode operation; rejects settings beyond hard ceilings.
    pub fn new(limits: &DecodeLimits) -> Result<Self, DecodeError> {
        Ok(Self {
            budget: DecodeBudget::new(limits)?,
        })
    }

    /// Legacy first-item decoding, charging the same aggregate value budget.
    /// Byte strings remain opaque unless explicitly decoded in this session.
    /// Trailing bytes are ignored; prefer [`Self::decode_exact`] for documents
    /// or [`Self::decode_prefix`] for sequences. Planned for future deprecation.
    pub fn decode<T: DeserializeOwned>(&mut self, bytes: &[u8]) -> Result<T, DecodeError> {
        self.budget.decode(bytes)
    }

    /// Decode exactly one item, rejecting trailing data (RFC 8949 §3).
    /// Failed framing checks still charge the parsed item's value budget.
    pub fn decode_exact<T: DeserializeOwned>(&mut self, bytes: &[u8]) -> Result<T, DecodeError> {
        self.budget.decode_exact(bytes)
    }

    /// Decode the first item and return its borrowed, unparsed remainder.
    /// The input byte limit applies to the entire supplied slice; values in
    /// the remainder consume no value budget until decoded in another call.
    pub fn decode_prefix<'a, T: DeserializeOwned>(
        &mut self,
        bytes: &'a [u8],
    ) -> Result<(T, &'a [u8]), DecodeError> {
        self.budget.decode_prefix(bytes)
    }

    /// Decode exactly one embedded item at the caller's enclosing depth.
    /// Preserves the shared budget across byte-string boundaries.
    pub fn decode_nested_exact<T: DeserializeOwned>(
        &mut self,
        bytes: &[u8],
        enclosing_depth: usize,
    ) -> Result<T, DecodeError> {
        let value = self
            .budget
            .decode_value_exact_at_depth(bytes, enclosing_depth)?;
        minimal_backend::value_de::from_value(value).map_err(DecodeError::Deserialization)
    }

    /// Decode embedded CBOR while retaining enclosing traversal depth.
    ///
    /// `enclosing_depth` counts arrays/maps/tags already traversed by the
    /// caller. Use this when recursive inspection crosses byte-string
    /// boundaries so shallow individual items cannot form an unbounded chain.
    /// This legacy method ignores trailing bytes; prefer [`Self::decode_nested_exact`]
    /// for embedded documents. No compiler deprecation warning is emitted yet.
    pub fn decode_nested<T: DeserializeOwned>(
        &mut self,
        bytes: &[u8],
        enclosing_depth: usize,
    ) -> Result<T, DecodeError> {
        let value = self.budget.decode_value_at_depth(bytes, enclosing_depth)?;
        minimal_backend::value_de::from_value(value).map_err(DecodeError::Deserialization)
    }
}

impl Default for DecodeBudget {
    fn default() -> Self {
        Self {
            limits: DecodeLimits::default(),
            remaining: DEFAULT_MAX_VALUES,
            failure: None,
            inspect_framing: false,
        }
    }
}

impl DecodeBudget {
    pub(crate) fn inspect_document(&mut self, bytes: &[u8]) -> Result<(), DecodeError> {
        self.inspect_bytes(bytes, ScanContext::Document, 0)
    }

    pub(crate) fn inspect_document_framing(&mut self, bytes: &[u8]) -> Result<(), DecodeError> {
        self.inspect_framing = true;
        self.inspect_document(bytes)
    }

    fn inspect_bytes(
        &mut self,
        bytes: &[u8],
        context: ScanContext,
        depth: usize,
    ) -> Result<(), DecodeError> {
        self.check_input(bytes)?;
        // Bound combined traversal across byte-string boundaries as well as
        // ordinary CBOR nesting. Syntax errors can be diagnosed separately.
        let value = if self.inspect_framing {
            self.decode_value_exact_at_depth(bytes, depth)
        } else {
            self.decode_value_at_depth(bytes, depth)
        };
        self.check()?;
        if let Err(e @ DecodeError::TrailingData { .. }) = value {
            return Err(e);
        }
        if let Ok(value) = value {
            self.inspect_value(&value, context, depth)?;
        }
        Ok(())
    }

    fn inspect_value(
        &mut self,
        value: &Value,
        context: ScanContext,
        depth: usize,
    ) -> Result<(), DecodeError> {
        use crate::types::signed::{COSE_HEADER_CORIM_META, COSE_HEADER_PAYLOAD_HASH_ALG};
        use crate::types::tags::{
            CORIM_KEY_TAGS, TAG_COMID, TAG_CORIM, TAG_COSWID, TAG_COTL, TAG_LEGACY_SIGNED,
            TAG_LEGACY_TOP, TAG_SIGNED_CORIM,
        };
        if depth > self.limits.max_depth {
            self.fail("depth", self.limits.max_depth);
            return self.check();
        }
        match value {
            Value::Tag(TAG_SIGNED_CORIM, inner) if matches!(context, ScanContext::Document) => {
                if let Value::Array(parts) = inner.as_ref() {
                    // Only the header/payload slots are CBOR-in-bstr. Inspect
                    // even malformed envelopes so diagnostics cannot reset budgets.
                    let mut hash = false;
                    if let Some(Value::Bytes(bytes)) = parts.first() {
                        self.check_input(bytes)?;
                        let header = if self.inspect_framing {
                            self.decode_value_exact_at_depth(bytes, depth + 2)
                        } else {
                            self.decode_value_at_depth(bytes, depth + 2)
                        };
                        self.check()?;
                        if let Err(e @ DecodeError::TrailingData { .. }) = header {
                            return Err(e);
                        }
                        if let Ok(header) = header {
                            if let Value::Map(fields) = &header {
                                hash = fields.iter().any(|(k, _)| {
                                    k == &Value::Integer(i128::from(COSE_HEADER_PAYLOAD_HASH_ALG))
                                });
                            }
                            self.inspect_value(&header, ScanContext::Header, depth + 2)?;
                        }
                    }
                    if !hash {
                        if let Some(Value::Bytes(bytes)) = parts.get(2) {
                            self.inspect_bytes(bytes, ScanContext::Document, depth + 2)?;
                        }
                    }
                }
            }
            Value::Tag(TAG_CORIM, inner) if matches!(context, ScanContext::Document) => {
                self.inspect_value(inner, ScanContext::Document, depth + 1)?
            }
            Value::Tag(TAG_COMID | TAG_COSWID | TAG_COTL, inner)
                if matches!(context, ScanContext::TagEntry) =>
            {
                if let Value::Bytes(bytes) = inner.as_ref() {
                    self.inspect_bytes(bytes, ScanContext::Opaque, depth + 1)?;
                }
            }
            Value::Tag(TAG_LEGACY_TOP | TAG_LEGACY_SIGNED, inner)
                if matches!(context, ScanContext::Document) =>
            {
                self.inspect_value(inner, context, depth + 1)?;
            }
            Value::Tag(_, inner) => self.inspect_value(inner, ScanContext::Opaque, depth + 1)?,
            Value::Map(fields) => {
                for (k, v) in fields {
                    if matches!(context, ScanContext::Header)
                        && k == &Value::Integer(i128::from(COSE_HEADER_CORIM_META))
                    {
                        if let Value::Bytes(bytes) = v {
                            self.inspect_bytes(bytes, ScanContext::Opaque, depth + 1)?;
                        }
                    }
                    if matches!(context, ScanContext::Document)
                        && k == &Value::Integer(i128::from(CORIM_KEY_TAGS))
                    {
                        if let Value::Array(tags) = v {
                            for tag in tags {
                                if let Value::Bytes(bytes) = tag {
                                    self.inspect_bytes(bytes, ScanContext::Opaque, depth + 2)?;
                                } else {
                                    self.inspect_value(tag, ScanContext::TagEntry, depth + 2)?;
                                }
                            }
                        }
                    }
                    self.inspect_value(k, ScanContext::Opaque, depth + 1)?;
                    self.inspect_value(v, ScanContext::Opaque, depth + 1)?;
                }
            }
            Value::Array(items) => {
                for item in items {
                    self.inspect_value(item, ScanContext::Opaque, depth + 1)?;
                }
            }
            _ => {}
        }
        Ok(())
    }

    pub(crate) fn new(limits: &DecodeLimits) -> Result<Self, DecodeError> {
        if limits.max_depth > MAX_DECODE_DEPTH {
            return Err(DecodeError::InvalidStructure(format!(
                "max_depth must not exceed {MAX_DECODE_DEPTH}"
            )));
        }
        if limits.max_collection_items > MAX_COLLECTION_ITEMS {
            return Err(DecodeError::InvalidStructure(format!(
                "max_collection_items must not exceed {MAX_COLLECTION_ITEMS}"
            )));
        }
        Ok(Self {
            limits: *limits,
            remaining: limits.max_values,
            failure: None,
            inspect_framing: false,
        })
    }

    pub(crate) fn check_input(&mut self, bytes: &[u8]) -> Result<(), DecodeError> {
        self.check()?;
        if bytes.len() > self.limits.max_input_bytes {
            self.failure = Some(("input bytes", self.limits.max_input_bytes));
        }
        self.check()
    }

    pub(crate) fn check(&self) -> Result<(), DecodeError> {
        match self.failure {
            Some((resource, limit)) => Err(DecodeError::LimitExceeded { resource, limit }),
            None => Ok(()),
        }
    }

    fn fail(&mut self, resource: &'static str, limit: usize) -> minimal::CborError {
        self.failure.get_or_insert((resource, limit));
        minimal::CborError::Invalid(format!("decode limit exceeded: {resource} (limit {limit})"))
    }

    pub(crate) fn value(&mut self) -> Result<(), minimal::CborError> {
        if self.remaining == 0 {
            return Err(self.fail("values", self.limits.max_values));
        }
        self.remaining -= 1;
        Ok(())
    }

    pub(crate) fn container(&mut self, depth: usize) -> Result<(), minimal::CborError> {
        if depth >= self.limits.max_depth {
            return Err(self.fail("depth", self.limits.max_depth));
        }
        Ok(())
    }

    pub(crate) fn collection(&mut self, count: usize, map: bool) -> Result<(), minimal::CborError> {
        if count > self.limits.max_collection_items {
            return Err(self.fail("collection entries", self.limits.max_collection_items));
        }
        // Every array slot costs at least one value; every map entry costs two.
        // Reject before allocating even the small initial vector.
        let minimum = count.checked_mul(if map { 2 } else { 1 });
        if minimum.is_none_or(|n| n > self.remaining) {
            return Err(self.fail("values", self.limits.max_values));
        }
        Ok(())
    }

    pub(crate) fn decode_value(&mut self, bytes: &[u8]) -> Result<Value, DecodeError> {
        self.decode_value_at_depth(bytes, 0)
    }

    fn decode_value_at_depth(&mut self, bytes: &[u8], depth: usize) -> Result<Value, DecodeError> {
        self.decode_value_prefix_at_depth(bytes, depth)
            .map(|(value, _)| value)
    }

    fn decode_value_prefix_at_depth<'a>(
        &mut self,
        bytes: &'a [u8],
        depth: usize,
    ) -> Result<(Value, &'a [u8]), DecodeError> {
        self.check_input(bytes)?;
        if depth > self.limits.max_depth {
            self.fail("depth", self.limits.max_depth);
            self.check()?;
        }
        let mut reader = minimal::SliceReader::new(bytes);
        let result = minimal::decode_value_budget(&mut reader, self, depth);
        // A limit is fatal even if an enclosing compatibility path catches an error.
        self.check()?;
        result
            .map(|value| (value, reader.remaining()))
            .map_err(|e| DecodeError::Deserialization(e.to_string()))
    }

    fn decode_value_exact_at_depth(
        &mut self,
        bytes: &[u8],
        depth: usize,
    ) -> Result<Value, DecodeError> {
        let (value, rest) = self.decode_value_prefix_at_depth(bytes, depth)?;
        if !rest.is_empty() {
            return Err(DecodeError::TrailingData {
                remaining: rest.len(),
            });
        }
        Ok(value)
    }

    pub(crate) fn decode_value_exact(&mut self, bytes: &[u8]) -> Result<Value, DecodeError> {
        self.decode_value_exact_at_depth(bytes, 0)
    }

    pub(crate) fn decode_exact<T: DeserializeOwned>(
        &mut self,
        bytes: &[u8],
    ) -> Result<T, DecodeError> {
        let value = self.decode_value_exact(bytes)?;
        minimal_backend::value_de::from_value(value).map_err(DecodeError::Deserialization)
    }

    pub(crate) fn decode_prefix<'a, T: DeserializeOwned>(
        &mut self,
        bytes: &'a [u8],
    ) -> Result<(T, &'a [u8]), DecodeError> {
        let (value, rest) = self.decode_value_prefix_at_depth(bytes, 0)?;
        let typed =
            minimal_backend::value_de::from_value(value).map_err(DecodeError::Deserialization)?;
        Ok((typed, rest))
    }

    pub(crate) fn decode<T: DeserializeOwned>(&mut self, bytes: &[u8]) -> Result<T, DecodeError> {
        let value = self.decode_value(bytes)?;
        minimal_backend::value_de::from_value(value).map_err(DecodeError::Deserialization)
    }

    /// Resource-only inspection of embedded CoRIM CBOR. Syntax/semantic
    /// failures remain the caller's responsibility, but limits are fatal.
    pub(crate) fn check_corim(&mut self, bytes: &[u8]) -> Result<(), DecodeError> {
        use crate::types::tags::{CORIM_KEY_TAGS, TAG_COMID, TAG_CORIM, TAG_COSWID, TAG_COTL};
        let value = self.decode_value_exact(bytes);
        self.check()?;
        if let Err(e @ DecodeError::TrailingData { .. }) = value {
            return Err(e);
        }
        let Ok(value) = value else {
            return Ok(());
        };
        let value = crate::compat::peel_value(value);
        let map = match &value {
            Value::Tag(TAG_CORIM, inner) => inner.as_ref(),
            other => other,
        };
        if let Value::Map(fields) = map {
            for (key, value) in fields {
                if key != &Value::Integer(i128::from(CORIM_KEY_TAGS)) {
                    continue;
                }
                if let Value::Array(tags) = value {
                    for tag in tags {
                        let body = match tag {
                            Value::Tag(TAG_COMID | TAG_COSWID | TAG_COTL, inner) => inner.as_ref(),
                            Value::Bytes(_) => tag,
                            _ => continue,
                        };
                        if let Value::Bytes(bytes) = body {
                            let result = self.decode_value_exact(bytes);
                            self.check()?;
                            if let Err(e @ DecodeError::TrailingData { .. }) = result {
                                return Err(e);
                            }
                        }
                    }
                }
            }
        }
        Ok(())
    }
}

#[derive(Clone, Copy)]
enum ScanContext {
    Document,
    Header,
    TagEntry,
    Opaque,
}
