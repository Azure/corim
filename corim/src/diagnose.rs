// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Diagnostic decoder — best-effort structural inspection of a CoRIM document.
//!
//! # Stability
//!
//! **This module is a debugging aid, not part of the spec-conformance API.**
//! The shapes of [`DecodeReport`](crate::diagnose::DecodeReport),
//! [`DecodeIssue`](crate::diagnose::DecodeIssue),
//! [`Severity`](crate::diagnose::Severity), and
//! [`EnvelopeKind`](crate::diagnose::EnvelopeKind) may change between minor
//! versions without a deprecation cycle. Production decode/validate code
//! should use [`crate::validate::decode_and_validate`] instead.
//!
//! Unlike [`crate::validate::decode_and_validate`], the functions in this
//! module do **not** abort on the first error. They walk the CBOR tree as
//! a generic [`Value`](crate::cbor::value::Value) and emit a
//! [`DecodeReport`](crate::diagnose::DecodeReport) containing every
//! structural problem they recognize, with a path expression, the expected
//! shape, and what was actually found.
//!
//! Coverage (current scope, draft-ietf-rats-corim-10):
//!
//! - Top-level envelope: tag `#6.18` (signed) or tag `#6.501` (unsigned)
//! - `COSE_Sign1-corim` 4-element array (`protected`, `unprotected`, `payload`,
//!   `signature`) — types of each element
//! - `protected-corim-header-map` — every known key, including the
//!   `bstr .cbor corim-meta-map` constraint on key 8 and the
//!   inline-vs-hash-envelope mode requirements (§4.2.1)
//! - `unsigned-corim-map` — `id`/`tags`/`profile`/`rim-validity`/`entities` types
//! - `tags[]` — top-level tag dispatch (`#6.505` CoSWID, `#6.506` CoMID,
//!   `#6.508` CoTL); inner CBOR is *not* walked yet
//!
//! Per-triple/measurement diagnostics are intentionally not yet implemented;
//! see the issue tracker for the planned expansion.
//!
//! # Example
//!
//! ```no_run
//! let bytes = std::fs::read("some.corim").unwrap();
//! let report = corim::diagnose::inspect(&bytes);
//! print!("{}", report);
//! ```

use crate::cbor;
use crate::cbor::value::{Tagged, Value};
use crate::nostd_prelude::*;
use crate::types::signed::{
    CORIM_CONTENT_TYPE, COSE_HEADER_ALG, COSE_HEADER_CONTENT_TYPE, COSE_HEADER_CORIM_META,
    COSE_HEADER_CWT_CLAIMS, COSE_HEADER_KID, COSE_HEADER_PAYLOAD_HASH_ALG,
    COSE_HEADER_PAYLOAD_LOCATION, COSE_HEADER_PAYLOAD_PREIMAGE_CT, COSE_HEADER_X5BAG,
    COSE_HEADER_X5CHAIN, COSE_HEADER_X5T, COSE_HEADER_X5U,
};
use crate::types::tags::{
    CORIM_KEY_DEPENDENT_RIMS, CORIM_KEY_ENTITIES, CORIM_KEY_ID, CORIM_KEY_PROFILE,
    CORIM_KEY_RIM_VALIDITY, CORIM_KEY_TAGS, TAG_COMID, TAG_CORIM, TAG_COSWID, TAG_COTL, TAG_OID,
    TAG_SIGNED_CORIM, TAG_UUID,
};

use core::fmt;

// ===========================================================================
// Public types
// ===========================================================================

/// Severity of a decoding diagnostic.
#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Severity {
    /// A structural violation that prevents strict decoding.
    Error,
    /// A spec-level concern (e.g. SHOULD violation) that does not prevent decoding.
    Warning,
    /// Informational — typically used to confirm a section was recognized.
    Info,
}

impl fmt::Display for Severity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Severity::Error => f.write_str("error"),
            Severity::Warning => f.write_str("warn "),
            Severity::Info => f.write_str("ok   "),
        }
    }
}

/// One structural issue (or recognized section) discovered during inspection.
///
/// Field layout is **unstable**; access via the [`severity`](Self::severity),
/// [`path`](Self::path), [`message`](Self::message), and [`hint`](Self::hint)
/// accessors.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DecodeIssue {
    pub(crate) severity: Severity,
    pub(crate) path: String,
    pub(crate) message: String,
    pub(crate) hint: Option<&'static str>,
}

impl DecodeIssue {
    /// Severity of this diagnostic.
    pub fn severity(&self) -> Severity {
        self.severity
    }
    /// JSON-pointer-like path within the CBOR document (e.g. `$.protected.8`).
    pub fn path(&self) -> &str {
        &self.path
    }
    /// Short description: what was expected vs. what was found.
    pub fn message(&self) -> &str {
        &self.message
    }
    /// Optional remediation hint for the producer.
    pub fn hint(&self) -> Option<&'static str> {
        self.hint
    }
}

/// Result of [`inspect`] — a flat list of issues plus the detected envelope kind.
///
/// Field layout is **unstable**; access via [`issues`](Self::issues),
/// [`envelope`](Self::envelope), [`error_count`](Self::error_count), and
/// [`warning_count`](Self::warning_count).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct DecodeReport {
    pub(crate) issues: Vec<DecodeIssue>,
    pub(crate) envelope: EnvelopeKind,
}

/// What the top-level CBOR tag indicates.
#[non_exhaustive]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum EnvelopeKind {
    #[default]
    Unknown,
    /// `#6.18(...)` — COSE_Sign1-corim.
    Signed,
    /// `#6.501(...)` — tagged-unsigned-corim-map.
    Unsigned,
}

impl DecodeReport {
    /// All issues in walk order (errors, warnings, and informational entries).
    pub fn issues(&self) -> &[DecodeIssue] {
        &self.issues
    }
    /// What the top-level CBOR tag indicated.
    pub fn envelope(&self) -> EnvelopeKind {
        self.envelope
    }
    /// Number of `Error`-severity issues.
    pub fn error_count(&self) -> usize {
        self.issues
            .iter()
            .filter(|i| i.severity == Severity::Error)
            .count()
    }
    /// Number of `Warning`-severity issues.
    pub fn warning_count(&self) -> usize {
        self.issues
            .iter()
            .filter(|i| i.severity == Severity::Warning)
            .count()
    }
}

impl fmt::Display for DecodeReport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let kind = match self.envelope {
            EnvelopeKind::Signed => "signed CoRIM (tag 18)",
            EnvelopeKind::Unsigned => "unsigned CoRIM (tag 501)",
            EnvelopeKind::Unknown => "unrecognized envelope",
        };
        writeln!(f, "Diagnose: {}", kind)?;
        for issue in &self.issues {
            writeln!(f, "  [{}] {}", issue.severity, issue.path)?;
            writeln!(f, "         {}", issue.message)?;
            if let Some(hint) = issue.hint {
                writeln!(f, "         hint: {}", hint)?;
            }
        }
        writeln!(
            f,
            "Summary: {} error(s), {} warning(s)",
            self.error_count(),
            self.warning_count()
        )?;
        Ok(())
    }
}

// ===========================================================================
// Inspector — accumulator with helpers
// ===========================================================================

struct Inspector {
    report: DecodeReport,
}

impl Inspector {
    fn new() -> Self {
        Self {
            report: DecodeReport::default(),
        }
    }

    fn err(&mut self, path: impl Into<String>, msg: impl Into<String>) {
        self.report.issues.push(DecodeIssue {
            severity: Severity::Error,
            path: path.into(),
            message: msg.into(),
            hint: None,
        });
    }

    fn err_hint(&mut self, path: impl Into<String>, msg: impl Into<String>, hint: &'static str) {
        self.report.issues.push(DecodeIssue {
            severity: Severity::Error,
            path: path.into(),
            message: msg.into(),
            hint: Some(hint),
        });
    }

    fn warn(&mut self, path: impl Into<String>, msg: impl Into<String>) {
        self.report.issues.push(DecodeIssue {
            severity: Severity::Warning,
            path: path.into(),
            message: msg.into(),
            hint: None,
        });
    }

    fn info(&mut self, path: impl Into<String>, msg: impl Into<String>) {
        self.report.issues.push(DecodeIssue {
            severity: Severity::Info,
            path: path.into(),
            message: msg.into(),
            hint: None,
        });
    }
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
// Public entrypoint
// ===========================================================================

/// Inspect a CBOR-encoded CoRIM document and return a structural report.
///
/// This walks the document as a generic [`Value`] tree (see [module-level
/// docs][self] for coverage) and never aborts on the first error — every
/// recognizable structural problem is appended to the [`DecodeReport`].
pub fn inspect(bytes: &[u8]) -> DecodeReport {
    let mut ins = Inspector::new();

    if bytes.is_empty() {
        ins.err("$", "input is empty");
        return ins.report;
    }

    // First decode as a generic Value so we can inspect the top-level tag
    // without committing to any schema.
    let top: Value = match cbor::decode::<Value>(bytes) {
        Ok(v) => v,
        Err(e) => {
            ins.err("$", format!("not valid CBOR: {}", e));
            return ins.report;
        }
    };

    match top {
        Value::Tag(TAG_SIGNED_CORIM, inner) => {
            ins.report.envelope = EnvelopeKind::Signed;
            ins.info(
                "$",
                format!("recognized CBOR tag {} (signed-corim)", TAG_SIGNED_CORIM),
            );
            inspect_cose_sign1(&mut ins, *inner);
        }
        Value::Tag(TAG_CORIM, inner) => {
            ins.report.envelope = EnvelopeKind::Unsigned;
            ins.info(
                "$",
                format!(
                    "recognized CBOR tag {} (tagged-unsigned-corim-map)",
                    TAG_CORIM
                ),
            );
            inspect_corim_map(&mut ins, "$", *inner);
        }
        Value::Tag(t, _) => {
            ins.err(
                "$",
                format!(
                    "expected CBOR tag {} (unsigned-corim) or {} (signed-corim), found tag {}",
                    TAG_CORIM, TAG_SIGNED_CORIM, t
                ),
            );
        }
        other => {
            ins.err(
                "$",
                format!(
                    "expected a CBOR-tagged value (#6.{} or #6.{}), found bare {}",
                    TAG_CORIM,
                    TAG_SIGNED_CORIM,
                    value_kind(&other)
                ),
            );
        }
    }

    ins.report
}

// ===========================================================================
// COSE_Sign1-corim envelope (RFC 9052 §4.2)
// ===========================================================================

fn inspect_cose_sign1(ins: &mut Inspector, v: Value) {
    let arr = match v {
        Value::Array(a) => a,
        other => {
            ins.err_hint(
                "$",
                format!(
                    "COSE_Sign1 must be a 4-element array, found {}",
                    value_kind(&other)
                ),
                "RFC 9052 §4: COSE_Sign1 = [protected, unprotected, payload, signature]",
            );
            return;
        }
    };

    if arr.len() != 4 {
        ins.err_hint(
            "$",
            format!("COSE_Sign1 array has {} element(s), expected 4", arr.len()),
            "RFC 9052 §4: COSE_Sign1 = [protected, unprotected, payload, signature]",
        );
        // Continue with as many elements as we have.
    }

    let mut it = arr.into_iter();
    if let Some(protected) = it.next() {
        inspect_cose_protected(ins, protected);
    }
    if let Some(unprotected) = it.next() {
        inspect_cose_unprotected(ins, unprotected);
    }
    if let Some(payload) = it.next() {
        inspect_cose_payload(ins, payload);
    }
    if let Some(signature) = it.next() {
        inspect_cose_signature(ins, signature);
    }
}

fn inspect_cose_protected(ins: &mut Inspector, v: Value) {
    let bytes = match v {
        Value::Bytes(b) => b,
        other => {
            ins.err_hint(
                "$.protected",
                format!(
                    "protected header must be a byte string (bstr .cbor protected-corim-header-map), found {}",
                    value_kind(&other)
                ),
                "RFC 9052 §4: protected MUST be `bstr .cbor header_map`",
            );
            return;
        }
    };

    if bytes.is_empty() {
        ins.err(
            "$.protected",
            "protected header byte string is empty (must encode a non-empty CBOR map)",
        );
        return;
    }

    let inner: Value = match cbor::decode::<Value>(&bytes) {
        Ok(v) => v,
        Err(e) => {
            ins.err(
                "$.protected",
                format!("inner CBOR of protected header is not valid: {}", e),
            );
            return;
        }
    };

    inspect_protected_header_map(ins, inner);
}

fn inspect_cose_unprotected(ins: &mut Inspector, v: Value) {
    match v {
        Value::Map(_) => {
            // Unprotected header is `* cose-label => cose-value`. We don't
            // type-check individual entries.
            ins.info(
                "$.unprotected",
                "unprotected header is a CBOR map (contents not inspected)",
            );
        }
        other => ins.err(
            "$.unprotected",
            format!(
                "unprotected header must be a CBOR map, found {}",
                value_kind(&other)
            ),
        ),
    }
}

fn inspect_cose_payload(ins: &mut Inspector, v: Value) {
    match v {
        Value::Null => {
            ins.info(
                "$.payload",
                "payload is nil (detached or hash-envelope mode)",
            );
        }
        Value::Bytes(b) => {
            if b.is_empty() {
                ins.warn("$.payload", "payload byte string is empty");
                return;
            }
            // The payload is `bstr .cbor tagged-unsigned-corim-map / hash-envelope-digest`.
            // Try decoding as CBOR first; if it parses as #6.501, walk it.
            match cbor::decode::<Value>(&b) {
                Ok(Value::Tag(TAG_CORIM, inner)) => {
                    ins.info(
                        "$.payload",
                        format!(
                            "payload decodes as #6.{}(unsigned-corim-map) ({} bytes)",
                            TAG_CORIM,
                            b.len()
                        ),
                    );
                    inspect_corim_map(ins, "$.payload", *inner);
                }
                Ok(Value::Tag(t, _)) => {
                    ins.err_hint(
                        "$.payload",
                        format!(
                            "payload CBOR is tagged #6.{}; expected #6.{} (tagged-unsigned-corim-map)",
                            t, TAG_CORIM
                        ),
                        "If this is a hash-envelope, payload should be raw digest bytes (no CBOR wrapping)",
                    );
                }
                Ok(other) => {
                    // Could be a hash-envelope digest (raw bytes that happen to be valid CBOR).
                    ins.warn(
                        "$.payload",
                        format!(
                            "payload bytes parse as bare CBOR {} (not tagged); could be a hash-envelope digest or malformed payload",
                            value_kind(&other)
                        ),
                    );
                }
                Err(_) => {
                    // Likely a raw digest in hash-envelope mode.
                    ins.info(
                        "$.payload",
                        format!(
                            "payload is {} bytes that do not parse as CBOR; treated as hash-envelope digest",
                            b.len()
                        ),
                    );
                }
            }
        }
        other => ins.err(
            "$.payload",
            format!(
                "payload must be a byte string or nil, found {}",
                value_kind(&other)
            ),
        ),
    }
}

fn inspect_cose_signature(ins: &mut Inspector, v: Value) {
    match v {
        Value::Bytes(b) => {
            if b.is_empty() {
                ins.err("$.signature", "signature byte string is empty");
            } else {
                ins.info("$.signature", format!("signature is {} bytes", b.len()));
            }
        }
        other => ins.err(
            "$.signature",
            format!(
                "signature must be a byte string, found {}",
                value_kind(&other)
            ),
        ),
    }
}

// ===========================================================================
// protected-corim-header-map  (§4.2.1)
// ===========================================================================

fn inspect_protected_header_map(ins: &mut Inspector, v: Value) {
    let map = match v {
        Value::Map(m) => m,
        other => {
            ins.err(
                "$.protected",
                format!(
                    "protected header inner CBOR must be a map, found {}",
                    value_kind(&other)
                ),
            );
            return;
        }
    };

    let mut have_alg = false;
    let mut have_corim_meta = false;
    let mut have_cwt_claims = false;
    let mut have_content_type = false;
    let mut have_payload_preimage_ct = false;
    let mut have_cwt_iss_flat = false;

    for (k, val) in map {
        let key = match &k {
            Value::Integer(n) => match i64::try_from(*n) {
                Ok(k) => k,
                Err(_) => {
                    ins.warn(
                        "$.protected",
                        format!("integer header key {} is out of i64 range; skipped", n),
                    );
                    continue;
                }
            },
            other => {
                ins.warn(
                    "$.protected",
                    format!(
                        "non-integer header key ({}); RFC 9052 expects int/tstr labels",
                        value_kind(other)
                    ),
                );
                continue;
            }
        };

        let path = format!("$.protected.{}", key);

        match key {
            COSE_HEADER_ALG => {
                have_alg = true;
                if !matches!(val, Value::Integer(_)) {
                    ins.err(
                        path,
                        format!(
                            "alg (key 1) must be int (COSE algorithm registry), found {}",
                            value_kind(&val)
                        ),
                    );
                }
            }
            COSE_HEADER_CONTENT_TYPE => match val {
                Value::Text(t) => {
                    have_content_type = true;
                    if t != CORIM_CONTENT_TYPE {
                        ins.warn(
                            path,
                            format!(
                                "content-type (key 3) is {:?}, expected {:?}",
                                t, CORIM_CONTENT_TYPE
                            ),
                        );
                    }
                }
                Value::Integer(_) => {
                    have_content_type = true;
                    ins.warn(
                        path,
                        "content-type (key 3) is an integer (CoAP content-format); CoRIM §4.2.1 requires the tstr form",
                    );
                }
                _ => ins.err(
                    path,
                    format!(
                        "content-type (key 3) must be tstr, found {}",
                        value_kind(&val)
                    ),
                ),
            },
            COSE_HEADER_KID => match val {
                Value::Bytes(_) => {
                    ins.warn(
                        path,
                        "kid (key 4) appears in the protected header; RFC 9052 §3.1 puts kid in unprotected",
                    );
                }
                Value::Text(_) => {
                    // CWT iss carried flat — common producer pattern.
                    have_cwt_iss_flat = true;
                    ins.info(
                        path,
                        "key 4 is a tstr — interpreted as CWT iss claim placed flat in protected header",
                    );
                }
                _ => ins.err(
                    path,
                    format!(
                        "key 4 must be bstr (kid) or tstr (CWT iss), found {}",
                        value_kind(&val)
                    ),
                ),
            },
            COSE_HEADER_CORIM_META => match val {
                Value::Bytes(b) => {
                    have_corim_meta = true;
                    match cbor::decode::<Value>(&b) {
                        Ok(Value::Map(_)) => ins.info(
                            path,
                            format!(
                                "corim-meta (key 8) decoded as bstr .cbor map ({} bytes)",
                                b.len()
                            ),
                        ),
                        Ok(other) => ins.err(
                            path,
                            format!(
                                "corim-meta (key 8) byte-string contents are CBOR {}, expected map",
                                value_kind(&other)
                            ),
                        ),
                        Err(e) => ins.err(
                            path,
                            format!("corim-meta (key 8) inner CBOR did not parse: {}", e),
                        ),
                    }
                }
                Value::Map(_) => {
                    ins.err_hint(
                        path,
                        "corim-meta (key 8) is a bare CBOR map, but the spec requires `bstr .cbor corim-meta-map` (a byte string wrapping the CBOR-encoded map)",
                        "Producer should encode the corim-meta-map to bytes, then store those bytes as a CBOR byte string at key 8",
                    );
                }
                _ => ins.err(
                    path,
                    format!(
                        "corim-meta (key 8) must be a byte string wrapping a CBOR map, found {}",
                        value_kind(&val)
                    ),
                ),
            },
            COSE_HEADER_CWT_CLAIMS => match val {
                Value::Map(_) => {
                    have_cwt_claims = true;
                    ins.info(path, "CWT-Claims (key 15) is a CBOR map");
                }
                _ => ins.err(
                    path,
                    format!(
                        "CWT-Claims (key 15) must be a map, found {}",
                        value_kind(&val)
                    ),
                ),
            },
            COSE_HEADER_PAYLOAD_HASH_ALG => {
                if !matches!(val, Value::Integer(_)) {
                    ins.err(
                        path,
                        format!(
                            "payload_hash_alg (key 258) must be int, found {}",
                            value_kind(&val)
                        ),
                    );
                }
            }
            COSE_HEADER_PAYLOAD_PREIMAGE_CT => match val {
                Value::Text(_) => have_payload_preimage_ct = true,
                _ => ins.err(
                    path,
                    format!(
                        "payload_preimage_content_type (key 259) must be tstr, found {}",
                        value_kind(&val)
                    ),
                ),
            },
            COSE_HEADER_PAYLOAD_LOCATION => {
                if !matches!(val, Value::Text(_)) {
                    ins.err(
                        path,
                        format!(
                            "payload_location (key 260) must be tstr, found {}",
                            value_kind(&val)
                        ),
                    );
                }
            }
            COSE_HEADER_X5BAG | COSE_HEADER_X5CHAIN => {
                if !matches!(val, Value::Bytes(_) | Value::Array(_)) {
                    ins.err(
                        path,
                        format!(
                            "x5bag/x5chain (key {}) must be bstr or array of bstr per RFC 9360, found {}",
                            key,
                            value_kind(&val)
                        ),
                    );
                }
            }
            COSE_HEADER_X5T => {
                if !matches!(val, Value::Array(_)) {
                    ins.err(
                        path,
                        format!(
                            "x5t (key 34) must be a [hashAlg, hashValue] array, found {}",
                            value_kind(&val)
                        ),
                    );
                }
            }
            COSE_HEADER_X5U => {
                if !matches!(val, Value::Text(_)) {
                    ins.err(
                        path,
                        format!(
                            "x5u (key 35) must be tstr (URI), found {}",
                            value_kind(&val)
                        ),
                    );
                }
            }
            _ => {
                ins.info(
                    path,
                    format!("unrecognized header key {} (passed through as extra)", key),
                );
            }
        }
    }

    // §4.2.1 structural rules.
    if !have_alg {
        ins.err("$.protected", "missing required key 1 (alg)");
    }
    let inline_mode = have_content_type;
    let hash_envelope_mode = have_payload_preimage_ct;
    if !inline_mode && !hash_envelope_mode {
        ins.err_hint(
            "$.protected",
            "missing both content-type (key 3, inline mode) and payload_preimage_content_type (key 259, hash-envelope mode)",
            "draft-ietf-rats-corim-10 §4.2.1 requires exactly one of these",
        );
    } else if inline_mode && hash_envelope_mode {
        ins.warn(
            "$.protected",
            "both content-type (key 3) and payload_preimage_content_type (key 259) are present; pick one mode",
        );
    }
    if !have_corim_meta && !have_cwt_claims && !have_cwt_iss_flat {
        ins.err_hint(
            "$.protected",
            "meta-group violation: at least one of corim-meta (key 8) or CWT-Claims (key 15) must be present",
            "draft-ietf-rats-corim-10 §4.2.1 meta-group: ((corim-meta-identity, ?cwt-claims-identity) // cwt-claims-identity)",
        );
    }
}

// ===========================================================================
// unsigned-corim-map  (§4.1)
// ===========================================================================

fn inspect_corim_map(ins: &mut Inspector, base_path: &str, v: Value) {
    let map = match v {
        Value::Map(m) => m,
        other => {
            ins.err(
                base_path,
                format!(
                    "tagged-unsigned-corim-map inner value must be a map, found {}",
                    value_kind(&other)
                ),
            );
            return;
        }
    };

    let mut have_id = false;
    let mut have_tags = false;
    let mut tags_value: Option<Value> = None;

    for (k, val) in map {
        let key = match &k {
            Value::Integer(n) => match i64::try_from(*n) {
                Ok(v) => v,
                Err(_) => {
                    ins.warn(
                        base_path,
                        format!("corim-map key {} out of i64 range; skipped", n),
                    );
                    continue;
                }
            },
            other => {
                ins.warn(
                    base_path,
                    format!(
                        "corim-map has non-integer key ({}); ignored",
                        value_kind(other)
                    ),
                );
                continue;
            }
        };

        let path = format!("{}.{}", base_path, key);

        match key {
            CORIM_KEY_ID => {
                have_id = true;
                match val {
                    Value::Text(_) => {}
                    Value::Bytes(b) if b.len() == 16 => {} // bare uuid (interop)
                    Value::Tag(TAG_UUID, inner) => match *inner {
                        Value::Bytes(b) if b.len() == 16 => {}
                        other => ins.err(
                            path,
                            format!(
                                "id (key 0) tagged-uuid inner must be 16-byte bstr, found {} of len {}",
                                value_kind(&other),
                                if let Value::Bytes(ref b) = other { b.len() } else { 0 }
                            ),
                        ),
                    },
                    other => ins.err(
                        path,
                        format!(
                            "id (key 0) must be tstr or (tagged-)uuid-type, found {}",
                            value_kind(&other)
                        ),
                    ),
                }
            }
            CORIM_KEY_TAGS => {
                have_tags = true;
                tags_value = Some(val);
            }
            CORIM_KEY_DEPENDENT_RIMS => {
                if !matches!(val, Value::Array(_)) {
                    ins.err(
                        path,
                        format!(
                            "dependent-rims (key 2) must be array of corim-locator-map, found {}",
                            value_kind(&val)
                        ),
                    );
                }
            }
            CORIM_KEY_PROFILE => match val {
                Value::Text(_) => {}
                Value::Tag(TAG_OID, _) => {}
                _ => ins.err(
                    path,
                    format!(
                        "profile (key 3) must be uri (tstr) or tagged-oid-type, found {}",
                        value_kind(&val)
                    ),
                ),
            },
            CORIM_KEY_RIM_VALIDITY => {
                if !matches!(val, Value::Map(_)) {
                    ins.err(
                        path,
                        format!(
                            "rim-validity (key 4) must be a validity-map, found {}",
                            value_kind(&val)
                        ),
                    );
                }
            }
            CORIM_KEY_ENTITIES => {
                if !matches!(val, Value::Array(_)) {
                    ins.err(
                        path,
                        format!(
                            "entities (key 5) must be array of corim-entity-map, found {}",
                            value_kind(&val)
                        ),
                    );
                }
            }
            _ => {
                ins.info(
                    path,
                    format!("unrecognized corim-map key {} (extension)", key),
                );
            }
        }
    }

    if !have_id {
        ins.err(base_path, "missing required key 0 (id)");
    }
    if !have_tags {
        ins.err(base_path, "missing required key 1 (tags)");
    }

    if let Some(v) = tags_value {
        inspect_tags_array(ins, &format!("{}.1", base_path), v);
    }
}

// ===========================================================================
// tags[] — top-level tag dispatch only (no recursion into inner CBOR)
// ===========================================================================

fn inspect_tags_array(ins: &mut Inspector, base_path: &str, v: Value) {
    let arr = match v {
        Value::Array(a) => a,
        other => {
            ins.err(
                base_path,
                format!(
                    "tags (key 1) must be a non-empty array, found {}",
                    value_kind(&other)
                ),
            );
            return;
        }
    };

    if arr.is_empty() {
        ins.err(
            base_path,
            "tags array is empty (CDDL requires at least one)",
        );
        return;
    }

    for (i, tag) in arr.into_iter().enumerate() {
        let path = format!("{}[{}]", base_path, i);
        match tag {
            Value::Tag(TAG_COMID, inner) => match *inner {
                Value::Bytes(b) => ins.info(
                    path,
                    format!(
                        "tagged-concise-mid-tag (#6.{}), {} bytes inner CBOR",
                        TAG_COMID,
                        b.len()
                    ),
                ),
                other => ins.err(
                    path,
                    format!(
                        "#6.{} (CoMID) inner must be bstr .cbor concise-mid-tag, found {}",
                        TAG_COMID,
                        value_kind(&other)
                    ),
                ),
            },
            Value::Tag(TAG_COSWID, inner) => match *inner {
                Value::Bytes(b) => ins.info(
                    path,
                    format!(
                        "tagged-concise-swid-tag (#6.{}), {} bytes inner CBOR",
                        TAG_COSWID,
                        b.len()
                    ),
                ),
                other => ins.err(
                    path,
                    format!(
                        "#6.{} (CoSWID) inner must be bstr .cbor concise-swid-tag, found {}",
                        TAG_COSWID,
                        value_kind(&other)
                    ),
                ),
            },
            Value::Tag(TAG_COTL, inner) => match *inner {
                Value::Bytes(b) => ins.info(
                    path,
                    format!(
                        "tagged-concise-tl-tag (#6.{}), {} bytes inner CBOR",
                        TAG_COTL,
                        b.len()
                    ),
                ),
                other => ins.err(
                    path,
                    format!(
                        "#6.{} (CoTL) inner must be bstr .cbor concise-tl-tag, found {}",
                        TAG_COTL,
                        value_kind(&other)
                    ),
                ),
            },
            Value::Tag(t, _) => ins.warn(
                path,
                format!(
                    "tag #6.{} is not a recognized CoRIM tag type ({}/{}/{} expected)",
                    t, TAG_COSWID, TAG_COMID, TAG_COTL
                ),
            ),
            other => ins.err(
                path,
                format!(
                    "tags[] entry must be a CBOR-tagged item, found bare {}",
                    value_kind(&other)
                ),
            ),
        }
    }
}

// Suppress unused-import warning of Tagged in no-std builds.
#[allow(dead_code)]
fn _unused_tagged_marker(_t: Tagged<()>) {}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cbor::encode;

    fn empty_report_has_envelope(bytes: &[u8], kind: EnvelopeKind) {
        let r = inspect(bytes);
        assert_eq!(r.envelope, kind);
    }

    #[test]
    fn empty_input_reports_error() {
        let r = inspect(&[]);
        assert_eq!(r.envelope, EnvelopeKind::Unknown);
        assert!(r.error_count() >= 1);
    }

    #[test]
    fn unknown_top_tag_reports_error() {
        // #6.999(0)
        let bytes = encode(&Tagged::new(999u64, Value::Integer(0))).unwrap();
        let r = inspect(&bytes);
        assert_eq!(r.envelope, EnvelopeKind::Unknown);
        assert!(r.issues.iter().any(|i| i.severity == Severity::Error));
    }

    #[test]
    fn signed_envelope_recognized_even_when_payload_missing_inner_decode() {
        // Build a #6.18([protected_bytes, {}, nil, sig]) where protected encodes
        // a map missing alg and meta-group — diagnose should still classify
        // the envelope and report multiple issues without aborting.
        let protected_inner = Value::Map(vec![(
            Value::Integer(3),
            Value::Text(CORIM_CONTENT_TYPE.into()),
        )]);
        let protected_bytes = encode(&protected_inner).unwrap();
        let arr = Value::Array(vec![
            Value::Bytes(protected_bytes),
            Value::Map(vec![]),
            Value::Null,
            Value::Bytes(vec![0x55; 64]),
        ]);
        let bytes = encode(&Tagged::new(TAG_SIGNED_CORIM, arr)).unwrap();
        empty_report_has_envelope(&bytes, EnvelopeKind::Signed);
        let r = inspect(&bytes);
        // Must flag missing alg AND missing meta-group, both as errors.
        assert!(r
            .issues
            .iter()
            .any(|i| i.severity == Severity::Error && i.message.contains("alg")));
        assert!(r
            .issues
            .iter()
            .any(|i| i.severity == Severity::Error && i.message.contains("meta-group")));
    }

    #[test]
    fn corim_meta_as_bare_map_is_flagged_with_hint() {
        // Reproduce the producer bug from data/sample_qtd_identity_corim.cbor:
        // key 8 carries a CBOR map directly, instead of bstr .cbor map.
        let protected_inner = Value::Map(vec![
            (Value::Integer(1), Value::Integer(-35)),
            (Value::Integer(3), Value::Text(CORIM_CONTENT_TYPE.into())),
            (
                Value::Integer(8),
                Value::Map(vec![(
                    Value::Integer(0),
                    Value::Map(vec![(Value::Integer(0), Value::Text("Intel".into()))]),
                )]),
            ),
        ]);
        let protected_bytes = encode(&protected_inner).unwrap();
        let arr = Value::Array(vec![
            Value::Bytes(protected_bytes),
            Value::Map(vec![]),
            Value::Null,
            Value::Bytes(vec![0x00; 32]),
        ]);
        let bytes = encode(&Tagged::new(TAG_SIGNED_CORIM, arr)).unwrap();
        let r = inspect(&bytes);
        let bad = r
            .issues
            .iter()
            .find(|i| i.path == "$.protected.8" && i.severity == Severity::Error)
            .expect("expected an Error at $.protected.8");
        assert!(bad.message.contains("bare CBOR map"));
        assert!(bad.hint.is_some());
    }

    #[test]
    fn unsigned_corim_with_one_comid_tag_reports_no_errors() {
        // Build a minimal valid #6.501(corim-map) with one CoMID tag.
        let inner_comid = Value::Map(vec![(Value::Integer(1), Value::Text("t".into()))]);
        let comid_bytes = encode(&inner_comid).unwrap();
        let corim_inner = Value::Map(vec![
            (Value::Integer(0), Value::Text("my-id".into())),
            (
                Value::Integer(1),
                Value::Array(vec![Value::Tag(
                    TAG_COMID,
                    Box::new(Value::Bytes(comid_bytes)),
                )]),
            ),
        ]);
        let bytes = encode(&Tagged::new(TAG_CORIM, corim_inner)).unwrap();
        let r = inspect(&bytes);
        assert_eq!(r.envelope, EnvelopeKind::Unsigned);
        assert_eq!(r.error_count(), 0, "issues: {:#?}", r.issues);
    }

    #[test]
    fn cose_sign1_wrong_arity_is_reported_but_decoding_continues() {
        let arr = Value::Array(vec![Value::Bytes(vec![]), Value::Map(vec![])]);
        let bytes = encode(&Tagged::new(TAG_SIGNED_CORIM, arr)).unwrap();
        let r = inspect(&bytes);
        assert!(r
            .issues
            .iter()
            .any(|i| i.message.contains("4") && i.severity == Severity::Error));
        // Element 0 (empty protected bstr) should still be inspected.
        assert!(r.issues.iter().any(|i| i.path == "$.protected"));
    }
}
