// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Decode-only interop helpers.
//!
//! This module contains relaxations applied **before** strict decoding so
//! that real-world CoRIM files that were produced against early drafts or
//! the TCG Endorsement spec can still be parsed. None of these helpers
//! affect encoding — encoding always emits draft-ietf-rats-corim-10
//! wire format.
//!
//! See the README "Decode interop relaxations" section for the complete
//! list of relaxations and their justifications.

use crate::cbor;
use crate::cbor::value::Value;
use crate::error::DecodeError;
use crate::nostd_prelude::*;
use crate::types::tags::{TAG_LEGACY_SIGNED, TAG_LEGACY_TOP};
use core::borrow::Borrow;

/// Strip legacy outer CBOR tags (`#6.500`, `#6.502`) that some producers
/// (notably the TCG Endorsement spec and NVIDIA firmware CoRIMs) wrap
/// around an otherwise-compliant draft-10 CoRIM.
///
/// Behavior:
///
/// - If `bytes` does not start with `#6.500` or `#6.502`, the input is
///   returned unchanged (zero-copy: a borrow into the original slice).
/// - Otherwise the bytes are decoded as a generic [`Value`], the outer
///   `#6.500`/`#6.502` tags are peeled (in any order, possibly multiple
///   layers), and the innermost value is re-encoded.
/// - The result is the inner CBOR — typically `#6.18(COSE_Sign1)` for
///   signed, or `#6.501(corim-map)` for unsigned.
///
/// This is a decode-only relaxation. Encoding paths in this crate never
/// emit `#6.500` or `#6.502`.
///
/// # Errors
///
/// Returns [`DecodeError::Deserialization`] if the input is not valid CBOR.
/// Returns [`DecodeError::InvalidStructure`] if peeling produced an inner
/// value that could not be re-encoded.
///
/// # Reference
///
/// Issue [ietf-rats-wg/draft-ietf-rats-corim#333][i] and
/// PR [#337][p] removed `#6.500` and `#6.502` from the IETF spec
/// in January 2025.
///
/// NVIDIA's "Device Attestation and CoRIM-based Reference Measurement
/// Sharing v5.0" specification (last updated 2026-03-05) still uses
/// the pre-PR-#337 wire format with `#6.500` as the top-level tag and
/// `#6.501` / `#6.502` as the type-choice members. See [their CoRIM
/// Structure page][nv] for the published CDDL. This is therefore a
/// *documented*, *intentional* divergence from the IETF draft, not a
/// producer bug.
///
/// [i]: https://github.com/ietf-rats-wg/draft-ietf-rats-corim/issues/333
/// [p]: https://github.com/ietf-rats-wg/draft-ietf-rats-corim/pull/337
/// [nv]: https://docs.nvidia.com/networking/display/dpunicattestation/corim-structure
pub fn peel_tcg_wrappers(bytes: &[u8]) -> Result<PeelOutcome<'_>, DecodeError> {
    // Fast path: no legacy wrapper byte signature.
    //
    // Tag 500 = 0xD9 0x01 0xF4
    // Tag 502 = 0xD9 0x01 0xF6
    if !starts_with_legacy_tag(bytes) {
        return Ok(PeelOutcome::Unchanged(bytes));
    }

    let mut v: Value = cbor::decode(bytes)
        .map_err(|e| DecodeError::Deserialization(format!("peel: cannot decode CBOR: {}", e)))?;

    let mut peeled = false;
    loop {
        match v {
            Value::Tag(TAG_LEGACY_TOP, inner) | Value::Tag(TAG_LEGACY_SIGNED, inner) => {
                v = *inner;
                peeled = true;
            }
            other => {
                v = other;
                break;
            }
        }
    }

    if !peeled {
        // Only possible if `starts_with_legacy_tag` had a false positive,
        // which it doesn't (the byte pattern is unambiguous), but be safe.
        return Ok(PeelOutcome::Unchanged(bytes));
    }

    let out = cbor::encode(&v).map_err(|e| {
        DecodeError::InvalidStructure(format!("peel: failed to re-encode inner CBOR: {}", e))
    })?;
    Ok(PeelOutcome::Peeled(out))
}

/// Result of [`peel_tcg_wrappers`].
///
/// `Borrow<[u8]>` lets callers pass either variant to functions taking `&[u8]`.
#[derive(Debug)]
pub enum PeelOutcome<'a> {
    /// The input had no legacy wrappers; original slice returned.
    Unchanged(&'a [u8]),
    /// Wrappers were stripped; this owned `Vec<u8>` is the inner CBOR.
    Peeled(Vec<u8>),
}

impl<'a> PeelOutcome<'a> {
    /// Borrow the resulting bytes (zero-copy for the `Unchanged` case).
    pub fn as_bytes(&self) -> &[u8] {
        match self {
            PeelOutcome::Unchanged(b) => b,
            PeelOutcome::Peeled(v) => v.as_slice(),
        }
    }

    /// True if the input carried legacy `#6.500` / `#6.502` wrappers.
    pub fn was_peeled(&self) -> bool {
        matches!(self, PeelOutcome::Peeled(_))
    }
}

impl<'a> Borrow<[u8]> for PeelOutcome<'a> {
    fn borrow(&self) -> &[u8] {
        self.as_bytes()
    }
}

/// Quick byte-level check: does `bytes` start with CBOR tag 500 or 502?
///
/// Tag 500 encodes as `0xD9 0x01 0xF4`; tag 502 as `0xD9 0x01 0xF6`.
fn starts_with_legacy_tag(bytes: &[u8]) -> bool {
    matches!(bytes, [0xD9, 0x01, 0xF4, ..] | [0xD9, 0x01, 0xF6, ..])
}

// ===========================================================================
// Untagged corim-map payload
// ===========================================================================

/// Wrap a bare CBOR map in a synthetic `#6.501` tag if it is not already
/// tagged, allowing downstream strict decode to treat both shapes uniformly.
///
/// **Background.** Draft-ietf-rats-corim-10 §4.2 says the COSE_Sign1 payload
/// is `bstr .cbor tagged-unsigned-corim-map`, where
/// `tagged-unsigned-corim-map = #6.501(unsigned-corim-map)`. Some real-world
/// producers — including NVIDIA NIC firmware CoRIMs and other TCG-style
/// implementations — emit the inner CoRIM as a **bare** `corim-map` (no
/// `#6.501` wrapping) because the surrounding `#6.500` / `#6.502` tags
/// historically provided enough type discrimination. See `peel_tcg_wrappers`
/// for the related outer-tag relaxation.
///
/// Behavior:
///
/// - If `bytes` already starts with `#6.501` (`0xD9 0x01 0xF5`) the input is
///   returned unchanged (zero-copy).
/// - If `bytes` starts with a definite-length CBOR map header (major type 5,
///   first byte in `0xA0..=0xBB`), the input is prefixed with the 3-byte
///   `#6.501` tag header and returned as an owned `Vec<u8>`.
/// - Anything else passes through unchanged; the strict decoder will reject
///   it with a normal `UnexpectedTag` / `Deserialization` error.
///
/// This is a decode-only relaxation. Encoding paths in this crate always
/// emit the `#6.501` wrapper.
///
/// # Reference
///
/// The pre-PR-#337 CDDL allowed `payload: bstr .cbor (tagged-corim-map /
/// corim-map)` because the outer `#6.502` provided context. The IETF
/// dropped 500/502 in [PR #337][p] but did not migrate existing producers.
/// NVIDIA's [CoRIM Structure spec][nv] still publishes the pre-PR-#337
/// shape, so the inner-payload divergence persists in deployed fleets.
///
/// [p]: https://github.com/ietf-rats-wg/draft-ietf-rats-corim/pull/337
/// [nv]: https://docs.nvidia.com/networking/display/dpunicattestation/corim-structure
pub fn wrap_bare_corim_map<'a>(bytes: &'a [u8]) -> WrapOutcome<'a> {
    if bytes.is_empty() {
        return WrapOutcome::Unchanged(bytes);
    }
    // Already tagged-501? Pass through.
    if bytes.len() >= 3 && bytes[0] == 0xD9 && bytes[1] == 0x01 && bytes[2] == 0xF5 {
        return WrapOutcome::Unchanged(bytes);
    }
    // Definite-length CBOR map? Prefix the #6.501 header.
    //
    // Major type 5 (map) definite-length headers span 0xA0..=0xBB:
    //   0xA0..=0xB7: immediate length 0..=23
    //   0xB8: 1-byte length follows
    //   0xB9: 2-byte length follows
    //   0xBA: 4-byte length follows
    //   0xBB: 8-byte length follows
    //
    // We deliberately reject 0xBF (indefinite-length map) here because the
    // strict CBOR decoder rejects it anyway and we don't want to silently
    // promote it to a tagged form.
    let first = bytes[0];
    if (0xA0..=0xBB).contains(&first) {
        let mut out = Vec::with_capacity(3 + bytes.len());
        out.extend_from_slice(&[0xD9, 0x01, 0xF5]);
        out.extend_from_slice(bytes);
        return WrapOutcome::Wrapped(out);
    }
    WrapOutcome::Unchanged(bytes)
}

/// Result of [`wrap_bare_corim_map`].
#[derive(Debug)]
pub enum WrapOutcome<'a> {
    /// The input either was already `#6.501`-tagged or is not a CBOR map;
    /// original slice returned (zero-copy).
    Unchanged(&'a [u8]),
    /// The input was a bare CBOR map; this owned `Vec<u8>` carries the
    /// synthetic `#6.501` prefix followed by the original bytes.
    Wrapped(Vec<u8>),
}

impl<'a> WrapOutcome<'a> {
    /// Borrow the resulting bytes (zero-copy for the `Unchanged` case).
    pub fn as_bytes(&self) -> &[u8] {
        match self {
            WrapOutcome::Unchanged(b) => b,
            WrapOutcome::Wrapped(v) => v.as_slice(),
        }
    }

    /// True if the input was a bare `corim-map` and a synthetic `#6.501`
    /// header was prepended.
    pub fn was_wrapped(&self) -> bool {
        matches!(self, WrapOutcome::Wrapped(_))
    }
}

impl<'a> Borrow<[u8]> for WrapOutcome<'a> {
    fn borrow(&self) -> &[u8] {
        self.as_bytes()
    }
}

// ===========================================================================
// Tag-tolerant CoMID decode (TCG-style nesting)
// ===========================================================================

/// Decode a [`crate::types::comid::ComidTag`] from bytes that may use the
/// TCG-style "swapped" nesting observed in NVIDIA NIC firmware CoRIMs.
///
/// **Background.** The IETF spec encodes CoMID `tags[]` entries as
/// `#6.506(bytes .cbor concise-mid-tag)` — i.e. an outer CBOR tag wrapping
/// a byte string whose contents are the CBOR-encoded `concise-mid-tag` map.
/// TCG-style producers (notably NVIDIA) swap the layers and emit
/// `bytes .cbor #6.506(concise-mid-tag)` instead — the byte string is on the
/// outside, the tag on the inside, and the tag's content is the bare
/// `concise-mid-tag` map (no inner `bytes .cbor` indirection).
///
/// This helper accepts either shape and returns a [`crate::types::comid::ComidTag`]:
///
/// - `0xD9 0x01 0xFA <map>` (tag-then-map): peel the tag, decode the map.
/// - `0xA0..=0xBB <map body>` (bare map): decode directly.
///
/// Use this after extracting the inner bytes from a
/// [`crate::types::corim::ConciseTagChoice::BareBstr`] or after any other
/// out-of-band byte extraction (e.g. walking a generic CBOR tree).
///
/// # Errors
///
/// Returns [`DecodeError::Deserialization`] if the bytes are not valid CBOR.
/// Returns [`DecodeError::InvalidStructure`] if the bytes are valid CBOR but
/// neither a `#6.506`-wrapped map nor a bare map (e.g. an array, integer, or
/// `#6.{other}`-tagged value).
///
/// # Example
///
/// ```no_run
/// use corim::compat::decode_comid_from_tcg_bstr;
/// use corim::types::corim::ConciseTagChoice;
/// # let corim: corim::types::corim::CorimMap = unimplemented!();
/// for tag in &corim.tags {
///     if let ConciseTagChoice::BareBstr(bytes) = tag {
///         let comid = decode_comid_from_tcg_bstr(bytes)?;
///         println!("CoMID: {:?}", comid.tag_identity);
///     }
/// }
/// # Ok::<(), corim::error::DecodeError>(())
/// ```
pub fn decode_comid_from_tcg_bstr(
    bytes: &[u8],
) -> Result<crate::types::comid::ComidTag, DecodeError> {
    use crate::types::tags::TAG_COMID;

    // Decode the bytes as a generic CBOR Value so we can inspect the wire
    // shape without committing to a specific schema.
    let v: Value = cbor::decode(bytes)
        .map_err(|e| DecodeError::Deserialization(format!("decode_comid_from_tcg_bstr: {}", e)))?;

    // Two accepted shapes:
    //   1. Tag(506, Map(...)) — TCG-style with inner #6.506 tag wrapper.
    //   2. Map(...) — bare concise-mid-tag map.
    let map_value = match v {
        Value::Tag(TAG_COMID, boxed) => match *boxed {
            map @ Value::Map(_) => map,
            other => {
                return Err(DecodeError::InvalidStructure(format!(
                    "expected #6.{}(map), got #6.{}({})",
                    TAG_COMID,
                    TAG_COMID,
                    value_kind(&other),
                )));
            }
        },
        map @ Value::Map(_) => map,
        Value::Tag(t, _) => {
            return Err(DecodeError::InvalidStructure(format!(
                "expected bare map or #6.{}(map), got unrelated tag #6.{}",
                TAG_COMID, t
            )));
        }
        other => {
            return Err(DecodeError::InvalidStructure(format!(
                "expected bare map or #6.{}(map), got {}",
                TAG_COMID,
                value_kind(&other),
            )));
        }
    };

    // Re-encode the inner map and feed it to the strict ComidTag decoder,
    // which expects a CBOR map at the top (no leading tag).
    let map_bytes = cbor::encode(&map_value).map_err(|e| {
        DecodeError::InvalidStructure(format!(
            "decode_comid_from_tcg_bstr: re-encode failed: {}",
            e
        ))
    })?;
    cbor::decode(&map_bytes).map_err(|e| {
        DecodeError::Deserialization(format!(
            "decode_comid_from_tcg_bstr: ComidTag decode: {}",
            e
        ))
    })
}

/// Brief human name for a [`Value`] kind, used in error messages.
fn value_kind(v: &Value) -> &'static str {
    match v {
        Value::Integer(_) => "integer",
        Value::Bytes(_) => "bytes",
        Value::Text(_) => "text",
        Value::Array(_) => "array",
        Value::Map(_) => "map",
        Value::Tag(_, _) => "tag",
        Value::Bool(_) => "bool",
        Value::Null => "null",
        Value::Float(_) => "float",
    }
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cbor::value::Tagged;
    use crate::types::tags::{TAG_CORIM, TAG_SIGNED_CORIM};

    #[test]
    fn no_legacy_wrapper_returns_unchanged() {
        // A normal #6.501(map{}) — should pass through untouched.
        let bytes = cbor::encode(&Tagged::new(TAG_CORIM, Value::Map(vec![]))).unwrap();
        let out = peel_tcg_wrappers(&bytes).unwrap();
        assert!(!out.was_peeled());
        assert_eq!(out.as_bytes(), bytes.as_slice());
    }

    #[test]
    fn peels_500_wrapper() {
        // #6.500(#6.501({})) -> #6.501({})
        let inner = Value::Tag(TAG_CORIM, Box::new(Value::Map(vec![])));
        let bytes = cbor::encode(&Tagged::new(TAG_LEGACY_TOP, inner.clone())).unwrap();
        let out = peel_tcg_wrappers(&bytes).unwrap();
        assert!(out.was_peeled());
        let expected = cbor::encode(&inner).unwrap();
        assert_eq!(out.as_bytes(), expected.as_slice());
    }

    #[test]
    fn peels_502_wrapper() {
        // #6.502(#6.18([...])) -> #6.18([...])
        let cose = Value::Tag(TAG_SIGNED_CORIM, Box::new(Value::Array(vec![])));
        let bytes = cbor::encode(&Tagged::new(TAG_LEGACY_SIGNED, cose.clone())).unwrap();
        let out = peel_tcg_wrappers(&bytes).unwrap();
        assert!(out.was_peeled());
        let expected = cbor::encode(&cose).unwrap();
        assert_eq!(out.as_bytes(), expected.as_slice());
    }

    #[test]
    fn peels_nested_500_502_wrappers() {
        // The NVIDIA shape: #6.500(#6.502(#6.18(...)))
        let cose = Value::Tag(TAG_SIGNED_CORIM, Box::new(Value::Array(vec![])));
        let inner502 = Value::Tag(TAG_LEGACY_SIGNED, Box::new(cose.clone()));
        let bytes = cbor::encode(&Tagged::new(TAG_LEGACY_TOP, inner502)).unwrap();
        let out = peel_tcg_wrappers(&bytes).unwrap();
        assert!(out.was_peeled());
        let expected = cbor::encode(&cose).unwrap();
        assert_eq!(out.as_bytes(), expected.as_slice());
    }

    #[test]
    fn malformed_cbor_after_legacy_marker_returns_decode_error() {
        // Starts with the 500 magic bytes but is otherwise garbage.
        let garbage = [0xD9, 0x01, 0xF4, 0xFF, 0xFF, 0xFF];
        let err = peel_tcg_wrappers(&garbage).unwrap_err();
        match err {
            DecodeError::Deserialization(msg) => assert!(msg.starts_with("peel:")),
            other => panic!("expected Deserialization, got {:?}", other),
        }
    }

    // -------- wrap_bare_corim_map --------

    #[test]
    fn wrap_passes_through_already_tagged_corim_map() {
        // #6.501({}) — should not be re-wrapped.
        let bytes = cbor::encode(&Tagged::new(TAG_CORIM, Value::Map(vec![]))).unwrap();
        let out = wrap_bare_corim_map(&bytes);
        assert!(!out.was_wrapped());
        assert_eq!(out.as_bytes(), bytes.as_slice());
    }

    #[test]
    fn wrap_prefixes_bare_small_map() {
        // {} — empty map, header byte 0xA0.
        let bytes = cbor::encode(&Value::Map(vec![])).unwrap();
        assert_eq!(bytes[0], 0xA0);
        let out = wrap_bare_corim_map(&bytes);
        assert!(out.was_wrapped());
        // Resulting bytes must round-trip as #6.501({}).
        let tagged: Tagged<Value> = cbor::decode(out.as_bytes()).unwrap();
        assert_eq!(tagged.tag, TAG_CORIM);
        assert_eq!(tagged.value, Value::Map(vec![]));
    }

    #[test]
    fn wrap_prefixes_bare_larger_map() {
        // A 24-entry map uses 0xB8 0x18 header — exercises the upper end of the
        // definite-length range we accept.
        let entries: Vec<(Value, Value)> = (0..24)
            .map(|i| (Value::Integer(i as i128), Value::Integer(0)))
            .collect();
        let bytes = cbor::encode(&Value::Map(entries.clone())).unwrap();
        assert_eq!(bytes[0], 0xB8);
        let out = wrap_bare_corim_map(&bytes);
        assert!(out.was_wrapped());
        let tagged: Tagged<Value> = cbor::decode(out.as_bytes()).unwrap();
        assert_eq!(tagged.tag, TAG_CORIM);
        assert_eq!(tagged.value, Value::Map(entries));
    }

    #[test]
    fn wrap_passes_through_non_map() {
        // bare integer — not something we should wrap.
        let bytes = cbor::encode(&Value::Integer(42)).unwrap();
        let out = wrap_bare_corim_map(&bytes);
        assert!(!out.was_wrapped());
        assert_eq!(out.as_bytes(), bytes.as_slice());
    }

    #[test]
    fn wrap_passes_through_other_tags() {
        // #6.18(...) — a COSE_Sign1 envelope must not be misclassified as a
        // bare corim-map.
        let bytes = cbor::encode(&Tagged::new(TAG_SIGNED_CORIM, Value::Array(vec![]))).unwrap();
        let out = wrap_bare_corim_map(&bytes);
        assert!(!out.was_wrapped());
        assert_eq!(out.as_bytes(), bytes.as_slice());
    }

    #[test]
    fn wrap_passes_through_empty_input() {
        let out = wrap_bare_corim_map(&[]);
        assert!(!out.was_wrapped());
        assert_eq!(out.as_bytes(), &[] as &[u8]);
    }

    // -------- decode_comid_from_tcg_bstr --------

    /// Build a minimal valid `concise-mid-tag` map: `{ 1: { 0: "test-id" }, 4: { 0: [...] } }`.
    /// Key 1 = tag-identity (a map with key 0 = tag-id).
    /// Key 4 = triples-map with one reference-triple (key 0) so the
    /// non-empty constraint on `triples-map` is satisfied.
    fn minimal_comid_map_value() -> Value {
        let tag_identity = Value::Map(vec![(Value::Integer(0), Value::Text("test-id".into()))]);
        // reference-triple-record = [environment-map, [+ measurement-map]]
        // environment-map needs at least one entry; use class with vendor.
        let env = Value::Map(vec![(
            Value::Integer(0),                                                 // class
            Value::Map(vec![(Value::Integer(1), Value::Text("acme".into()))]), // vendor
        )]);
        // measurement-map needs mval (key 1).
        // measurement-values-map needs at least one entry; use name (key 11).
        let meas = Value::Map(vec![(
            Value::Integer(1), // mval
            Value::Map(vec![(Value::Integer(11), Value::Text("fw".into()))]),
        )]);
        let ref_triple = Value::Array(vec![env, Value::Array(vec![meas])]);
        let triples = Value::Map(vec![(
            Value::Integer(0), // reference-triples
            Value::Array(vec![ref_triple]),
        )]);
        Value::Map(vec![
            (Value::Integer(1), tag_identity),
            (Value::Integer(4), triples),
        ])
    }

    #[test]
    fn decode_comid_accepts_tag_then_map_shape() {
        // TCG/NVIDIA shape: bytes contain #6.506(map(...))
        let inner = minimal_comid_map_value();
        let bytes =
            cbor::encode(&Value::Tag(crate::types::tags::TAG_COMID, Box::new(inner))).unwrap();
        let comid = decode_comid_from_tcg_bstr(&bytes).expect("must decode");
        match &comid.tag_identity.tag_id {
            crate::types::common::TagIdChoice::Text(s) => assert_eq!(s, "test-id"),
            other => panic!("unexpected tag-id: {:?}", other),
        }
    }

    #[test]
    fn decode_comid_accepts_bare_map_shape() {
        // Pre-PR-#337 shape: bytes contain just the concise-mid-tag map
        let bytes = cbor::encode(&minimal_comid_map_value()).unwrap();
        let comid = decode_comid_from_tcg_bstr(&bytes).expect("must decode");
        match &comid.tag_identity.tag_id {
            crate::types::common::TagIdChoice::Text(s) => assert_eq!(s, "test-id"),
            other => panic!("unexpected tag-id: {:?}", other),
        }
    }

    #[test]
    fn decode_comid_rejects_unrelated_tag() {
        // #6.999(map) — a tag that's not 506
        let bytes = cbor::encode(&Value::Tag(999, Box::new(minimal_comid_map_value()))).unwrap();
        let err = decode_comid_from_tcg_bstr(&bytes).unwrap_err();
        match err {
            DecodeError::InvalidStructure(msg) => {
                assert!(msg.contains("unrelated tag"), "got: {}", msg);
                assert!(msg.contains("999"), "got: {}", msg);
            }
            other => panic!("expected InvalidStructure, got {:?}", other),
        }
    }

    #[test]
    fn decode_comid_rejects_non_map_value() {
        let bytes = cbor::encode(&Value::Integer(42)).unwrap();
        let err = decode_comid_from_tcg_bstr(&bytes).unwrap_err();
        match err {
            DecodeError::InvalidStructure(msg) => {
                assert!(msg.contains("integer"), "got: {}", msg);
            }
            other => panic!("expected InvalidStructure, got {:?}", other),
        }
    }

    #[test]
    fn decode_comid_rejects_invalid_cbor() {
        let garbage = [0xFF, 0xFE, 0xFD];
        let err = decode_comid_from_tcg_bstr(&garbage).unwrap_err();
        match err {
            DecodeError::Deserialization(msg) => {
                assert!(
                    msg.starts_with("decode_comid_from_tcg_bstr:"),
                    "got: {}",
                    msg
                );
            }
            other => panic!("expected Deserialization, got {:?}", other),
        }
    }
}
