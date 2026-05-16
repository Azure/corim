// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#![cfg_attr(not(feature = "std"), no_std)]
#![deny(missing_docs)]

//! Intel CoRIM profile plug-in for the [`corim`] crate.
//!
//! Implements the [Intel Profile for Remote Attestation][spec]
//! (`draft-cds-rats-intel-corim-profile-03`, profile OID
//! `2.16.840.1.113741.1.16.1`).
//!
//! This crate is a thin profile registration: it teaches `corim` to
//! recognize the Intel profile identifier and to render Intel-defined
//! `measurement-values-map` extension keys in `--diagnose` output. The
//! core `corim` crate continues to preserve every Intel-defined key
//! verbatim in
//! [`MeasurementValuesMap::extra_entries`][corim::types::measurement::MeasurementValuesMap::extra_entries];
//! this crate only provides the human-readable labels.
//!
//! Typed accessors, the `#6.60010` expression tag, and profile-aware
//! matching live in follow-up crates and are not implemented here.
//!
//! [spec]: https://www.ietf.org/archive/id/draft-cds-rats-intel-corim-profile-03.html
//!
//! # Example
//!
//! ```no_run
//! use corim::diagnose;
//! use corim::profile::ProfileRegistry;
//! use corim_profile_intel::IntelProfile;
//!
//! # let bytes: Vec<u8> = Vec::new();
//! let mut registry = ProfileRegistry::new();
//! registry.register(Box::new(IntelProfile::new()));
//!
//! let report = diagnose::inspect(&bytes, &registry);
//! print!("{}", report);
//! ```

extern crate alloc;
use alloc::format;
use alloc::string::{String, ToString};

use corim::cbor::value::Value;
use corim::profile::Profile;
use corim::types::corim::ProfileChoice;
use corim::types::measurement::MeasurementMap;

mod eval;
pub mod expression;
pub use expression::{
    display_expression, Expression, ExpressionDecodeError, Numeric, NumericOp, SetOfSetOp, SetOp,
    TAG_INTEL_EXPRESSION,
};

// ---------------------------------------------------------------------------
// Profile identifier — §4.1 of draft-cds-rats-intel-corim-profile-03
// ---------------------------------------------------------------------------

/// Intel profile OID `2.16.840.1.113741.1.16.1`, DER-encoded.
///
/// Per RFC 6256, OIDs in CoRIM are encoded as the BER/DER subset that
/// omits the leading tag and length octets and represents only the
/// content (the arc-encoded body). The first byte combines the first
/// two arcs as `40*arc1 + arc2` (here `40*2 + 16 = 96 = 0x60`); each
/// remaining arc is encoded in base-128 with continuation bits.
///
/// Arc breakdown:
/// - `2.16`                 → `0x60`
/// - `840` (us)             → `0x86 0x48`
/// - `1`  (organization)    → `0x01`
/// - `113741` (intel)       → `0x86 0xF8 0x4D`
/// - `1`                    → `0x01`
/// - `16` (intel-comid)     → `0x10`
/// - `1`  (profile)         → `0x01`
pub const INTEL_PROFILE_OID_DER: &[u8] =
    &[0x60, 0x86, 0x48, 0x01, 0x86, 0xF8, 0x4D, 0x01, 0x10, 0x01];

// ---------------------------------------------------------------------------
// Measurement-values-map extension keys — §8.2 of the draft.
// All keys are negative integers; the spec assigns them outside the
// 0..=15 range used by the base CoRIM measurement-values-map.
// ---------------------------------------------------------------------------

/// `tee.vendor` (§8.2.16) — TEE vendor name (`tstr`).
pub const MVAL_TEE_VENDOR: i64 = -70;
/// `tee.model` (§8.2.10) — TEE model string (`tstr`).
pub const MVAL_TEE_MODEL: i64 = -71;
/// `tee.tcbdate` (§8.2.4) — TCB validity date (`tdate` / expression).
pub const MVAL_TEE_TCBDATE: i64 = -72;
/// `tee.isvsvn` (§8.2.12) — ISV SVN (numeric / `tagged-numeric-ge`).
pub const MVAL_TEE_ISVSVN: i64 = -73;
/// `tee.instance-id` (§8.2.7) — instance identifier (`uint` / `bstr`).
pub const MVAL_TEE_INSTANCE_ID: i64 = -77;
/// `tee.pceid` (§8.2.11) — PCE identifier (`tstr`).
pub const MVAL_TEE_PCEID: i64 = -80;
/// `tee.miscselect` (§8.2.9) — SGX MISCSELECT (`bstr` / `tagged-exp-mask-eq`).
pub const MVAL_TEE_MISCSELECT: i64 = -81;
/// `tee.attributes` (§8.2.2) — TEE attributes (`bstr` / `tagged-exp-mask-eq`).
pub const MVAL_TEE_ATTRIBUTES: i64 = -82;
/// `tee.mrtee` (§8.2.5) — measurement of the TEE (`digest` / `tagged-exp-member`).
pub const MVAL_TEE_MRTEE: i64 = -83;
/// `tee.mrsigner` (§8.2.5) — measurement of the TEE signer (`digest` / `tagged-exp-member`).
pub const MVAL_TEE_MRSIGNER: i64 = -84;
/// `tee.isvprodid` (§8.2.8) — ISV product ID (`uint` / `bstr`).
pub const MVAL_TEE_ISVPRODID: i64 = -85;
/// `tee.tcb-eval-num` (§8.2.14) — TCB evaluation number (`uint` / `tagged-numeric-ge`).
pub const MVAL_TEE_TCB_EVAL_NUM: i64 = -86;
/// `tee.tcbstatus` (§8.2.15) — TCB status (`set-type` / `tagged-exp-member`).
pub const MVAL_TEE_TCBSTATUS: i64 = -88;
/// `tee.advisory-ids` (§8.2.1) — security advisory IDs (`set-type` / `tagged-exp-not-member`).
pub const MVAL_TEE_ADVISORY_IDS: i64 = -89;
/// `tee.epoch` (§8.2.6) — epoch timestamp (`tdate` / `tagged-exp-epoch-gt`).
pub const MVAL_TEE_EPOCH: i64 = -90;
/// `tee.cryptokeys` (§8.2.3) — TEE cryptographic keys (`[+ crypto-key]`).
pub const MVAL_TEE_CRYPTOKEYS: i64 = -91;
/// `tee.tcb-comp-svn` (§8.2.13) — per-component TCB SVNs (`[16*16 svn]`).
pub const MVAL_TEE_TCB_COMP_SVN: i64 = -125;

// ---------------------------------------------------------------------------
// IntelProfile
// ---------------------------------------------------------------------------

/// Intel CoRIM profile implementation.
///
/// Construct with [`IntelProfile::new`] and register with a
/// [`corim::profile::ProfileRegistry`]:
///
/// ```
/// use corim::profile::ProfileRegistry;
/// use corim_profile_intel::IntelProfile;
///
/// let mut registry = ProfileRegistry::new();
/// registry.register(Box::new(IntelProfile::new()));
/// assert_eq!(registry.len(), 1);
/// ```
#[derive(Debug)]
pub struct IntelProfile {
    id: ProfileChoice,
}

impl IntelProfile {
    /// Create a new Intel profile instance with the OID identifier.
    pub fn new() -> Self {
        Self {
            id: ProfileChoice::Oid(INTEL_PROFILE_OID_DER.to_vec()),
        }
    }
}

impl Default for IntelProfile {
    fn default() -> Self {
        Self::new()
    }
}

impl Profile for IntelProfile {
    fn identifier(&self) -> &ProfileChoice {
        &self.id
    }

    /// Profile-aware matching for the Intel CoRIM extension keys.
    ///
    /// Iterates the Intel-defined entries in
    /// [`reference.mval.extra_entries`][corim::types::measurement::MeasurementValuesMap::extra_entries]
    /// (any integer key recognised by [`intel_mval_name`]) and evaluates
    /// each one against the corresponding entry in `evidence` under the
    /// operator semantics of `#6.60010(...)` expressions per
    /// `draft-cds-rats-intel-corim-profile-03` §8.1. See
    /// [`crate::eval`][mod@eval] for the per-key verdict policy.
    ///
    /// Composition with the core structural fields (`mkey`, `digests`,
    /// `svn`, `name`, ...) uses
    /// [`corim::validate::core_fields_match`]: a `Some(true)` return
    /// therefore certifies that BOTH the Intel extension constraints AND
    /// the core fields agree between the pair.
    ///
    /// Per-key verdicts roll up as follows:
    /// - any Intel-keyed `Fail` → `Some(false)` (early exit; structural
    ///   check skipped)
    /// - all evaluatable Intel keys `Pass` and at least one was
    ///   evaluated → `Some(core_fields_match(...))`
    /// - the reference contains only `Skip`-class Intel keys (tdate,
    ///   epoch, set-of-set) → `None` (defer entirely to core's
    ///   non-extension comparison; the time constraint is silently
    ///   skipped pending the future time-semantics design)
    /// - the reference has no Intel keys → `None` (defer)
    ///
    /// If the reference references an Intel key whose entry is missing
    /// from evidence, the verdict is `Some(false)` — a verifier MUST
    /// reject when a required Reference Value has no Evidence to
    /// compare against.
    fn match_measurement(
        &self,
        reference: &MeasurementMap,
        evidence: &MeasurementMap,
    ) -> Option<bool> {
        let mut verdicts: alloc::vec::Vec<eval::Verdict> = alloc::vec::Vec::new();
        for (key, ref_val) in reference.mval.extra_entries.iter() {
            if intel_mval_name(*key).is_none() {
                // Not an Intel-defined key; ignore (other profiles, or
                // unknown extras, are not this profile's business).
                continue;
            }
            match evidence.mval.extra_entries.get(key) {
                Some(ev_val) => verdicts.push(eval::evaluate_one_key(ref_val, ev_val)),
                None => return Some(false),
            }
        }
        match eval::combine(&verdicts) {
            Some(true) => Some(corim::validate::core_fields_match(reference, evidence)),
            other => other, // Some(false) or None
        }
    }

    fn diagnose_mval_entry(&self, key: i64, value: &Value) -> Option<String> {
        let name = intel_mval_name(key)?;
        Some(format!("{} = {}", name, value_summary(value)))
    }
}

/// Return the Intel-spec name for a `measurement-values-map` extension
/// key (e.g. `tee.mrtee` for `-83`), or `None` if the key is not
/// defined by this profile.
///
/// Useful for callers that want to format Intel keys themselves
/// without going through the [`Profile`] trait.
pub fn intel_mval_name(key: i64) -> Option<&'static str> {
    Some(match key {
        MVAL_TEE_VENDOR => "tee.vendor",
        MVAL_TEE_MODEL => "tee.model",
        MVAL_TEE_TCBDATE => "tee.tcbdate",
        MVAL_TEE_ISVSVN => "tee.isvsvn",
        MVAL_TEE_INSTANCE_ID => "tee.instance-id",
        MVAL_TEE_PCEID => "tee.pceid",
        MVAL_TEE_MISCSELECT => "tee.miscselect",
        MVAL_TEE_ATTRIBUTES => "tee.attributes",
        MVAL_TEE_MRTEE => "tee.mrtee",
        MVAL_TEE_MRSIGNER => "tee.mrsigner",
        MVAL_TEE_ISVPRODID => "tee.isvprodid",
        MVAL_TEE_TCB_EVAL_NUM => "tee.tcb-eval-num",
        MVAL_TEE_TCBSTATUS => "tee.tcbstatus",
        MVAL_TEE_ADVISORY_IDS => "tee.advisory-ids",
        MVAL_TEE_EPOCH => "tee.epoch",
        MVAL_TEE_CRYPTOKEYS => "tee.cryptokeys",
        MVAL_TEE_TCB_COMP_SVN => "tee.tcb-comp-svn",
        _ => return None,
    })
}

/// Render a CBOR value as a short, human-readable shape description
/// suitable for one-line diagnostic output.
///
/// `#6.60010(...)` expressions are decoded via [`Expression::from_tag`]
/// and rendered as e.g. `"ge 5"` or `"member (3 items)"`. Tags that
/// either are not `60010` or fail expression decode are rendered as
/// `"#6.<tag>(…)"`.
fn value_summary(v: &Value) -> String {
    match v {
        Value::Integer(n) => format!("{}", n),
        Value::Text(t) => {
            if t.len() <= 48 {
                format!("\"{}\"", t)
            } else {
                format!("\"{}…\" ({} chars)", &t[..47], t.len())
            }
        }
        Value::Bytes(b) => format!("<{}-byte bstr>", b.len()),
        Value::Array(a) => format!("array[{}]", a.len()),
        Value::Map(m) => format!("map({} entries)", m.len()),
        Value::Tag(tag, _) if *tag == TAG_INTEL_EXPRESSION => match Expression::from_tag(v) {
            Ok(expr) => display_expression(&expr),
            Err(_) => format!("#6.{}(…)", tag),
        },
        Value::Tag(tag, _) => format!("#6.{}(…)", tag),
        Value::Bool(b) => {
            if *b {
                "true".to_string()
            } else {
                "false".to_string()
            }
        }
        Value::Null => "null".to_string(),
        Value::Float(f) => format!("{}", f),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn oid_round_trips_through_profile_choice() {
        let p = IntelProfile::new();
        match p.identifier() {
            ProfileChoice::Oid(b) => assert_eq!(b.as_slice(), INTEL_PROFILE_OID_DER),
            other => panic!("expected Oid, got {:?}", other),
        }
    }

    #[test]
    fn known_mval_keys_map_to_names() {
        assert_eq!(intel_mval_name(-70), Some("tee.vendor"));
        assert_eq!(intel_mval_name(-83), Some("tee.mrtee"));
        assert_eq!(intel_mval_name(-125), Some("tee.tcb-comp-svn"));
    }

    #[test]
    fn unknown_mval_keys_return_none() {
        assert_eq!(intel_mval_name(-1), None);
        assert_eq!(intel_mval_name(0), None);
        assert_eq!(intel_mval_name(-100), None);
        assert_eq!(intel_mval_name(-126), None);
    }

    #[test]
    fn diagnose_renders_known_keys() {
        let p = IntelProfile::new();
        let label = p.diagnose_mval_entry(MVAL_TEE_VENDOR, &Value::Text("Intel".to_string()));
        assert_eq!(label.as_deref(), Some("tee.vendor = \"Intel\""));

        let digest_array = Value::Array(alloc::vec![
            Value::Integer(1),
            Value::Bytes(alloc::vec![0u8; 32]),
        ]);
        let label = p.diagnose_mval_entry(MVAL_TEE_MRTEE, &digest_array);
        assert_eq!(label.as_deref(), Some("tee.mrtee = array[2]"));

        let label = p.diagnose_mval_entry(MVAL_TEE_ISVSVN, &Value::Integer(3));
        assert_eq!(label.as_deref(), Some("tee.isvsvn = 3"));
    }

    #[test]
    fn diagnose_returns_none_for_unknown_keys() {
        let p = IntelProfile::new();
        assert_eq!(p.diagnose_mval_entry(-1, &Value::Integer(0)), None);
        assert_eq!(p.diagnose_mval_entry(9999, &Value::Null), None);
    }

    #[test]
    fn long_text_is_truncated() {
        let p = IntelProfile::new();
        let long = "x".repeat(100);
        let label = p
            .diagnose_mval_entry(MVAL_TEE_VENDOR, &Value::Text(long))
            .expect("known key");
        assert!(label.contains("…"));
        assert!(label.contains("(100 chars)"));
    }
}
