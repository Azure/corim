// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Intel CoRIM profile (`draft-cds-rats-intel-corim-profile-07`,
//! profile OID `2.16.840.1.113741.1.16.1`).
//!
//! Gated on the `profile-intel` Cargo feature. Provides:
//!
//! - [`IntelProfile`](crate::profile::intel::IntelProfile) — the [`Profile`](crate::profile::Profile) implementation, registerable
//!   with [`ProfileRegistry`](crate::profile::ProfileRegistry).
//! - [`expression`](crate::profile::intel::expression) — the operator-shaped reference-value decoder
//!   for tags `#6.60010` (numeric), `#6.60020` (set-of-digests),
//!   `#6.60021` (set-of-tstr), `#6.564` (`tagged-int-range`), and
//!   `#6.553` (`tagged-min-svn`).
//! - Internal per-key evaluator (see `eval` module, private).
//!
//! The core `corim` crate already preserves every Intel-defined key
//! verbatim in
//! [`MeasurementValuesMap::extra_entries`][crate::types::measurement::MeasurementValuesMap::extra_entries];
//! this module adds spec-aware labelling for diagnose output and
//! profile-aware matching semantics.
//!
//! [Intel Profile for Remote Attestation][spec]
//!
//! [spec]: https://www.ietf.org/archive/id/draft-cds-rats-intel-corim-profile-07.html
//!
//! # Example
//!
//! ```no_run
//! use corim::diagnose;
//! use corim::profile::ProfileRegistry;
//! use corim::profile::intel::IntelProfile;
//!
//! # let bytes: Vec<u8> = Vec::new();
//! let mut registry = ProfileRegistry::new();
//! registry.register(Box::new(IntelProfile::new()));
//!
//! let report = diagnose::inspect(&bytes, &registry);
//! print!("{}", report);
//! ```

use crate::cbor::value::Value;
use crate::nostd_prelude::*;
use crate::profile::{MatchContext, Profile};
use crate::types::corim::ProfileChoice;
use crate::types::measurement::MeasurementMap;

mod eval;
pub mod expression;
mod tcbdate;
pub use expression::{
    display_expression, Expression, ExpressionDecodeError, Numeric, NumericOp, SetOp,
    TAG_INTEL_EXPRESSION, TAG_INTEL_SET_DIGEST_EXPRESSION, TAG_INTEL_SET_TSTR_EXPRESSION,
};

// ---------------------------------------------------------------------------
// Profile identifier — §4.1 of draft-cds-rats-intel-corim-profile-07
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
// Measurement-values-map extension keys — §8.3 of v07.
// All keys are negative integers; the spec assigns them outside the
// 0..=15 range used by the base CoRIM measurement-values-map.
// ---------------------------------------------------------------------------

/// `tee.vendor` (§8.3.15) — TEE vendor name (`tstr`).
pub const MVAL_TEE_VENDOR: i64 = -70;
/// `tee.model` (§8.3.9) — TEE model string (`tstr`).
pub const MVAL_TEE_MODEL: i64 = -71;
/// `tee.tcbdate` (§8.3.4) — TCB validity date
/// (`tdate` / `time` / `etime` / `period`).
pub const MVAL_TEE_TCBDATE: i64 = -72;
/// `tee.isvsvn` (§8.3.11) — ISV SVN
/// (`svn-type` / `tagged-numeric-ge` / `tagged-int-range` / `tagged-min-svn`).
pub const MVAL_TEE_ISVSVN: i64 = -73;
/// `tee.pceid` (§8.3.10) — PCE identifier (`tstr` / `uint`).
pub const MVAL_TEE_PCEID: i64 = -80;
/// `tee.miscselect` (§8.3.8) — SGX MISCSELECT (`$masked-value-type`).
pub const MVAL_TEE_MISCSELECT: i64 = -81;
/// `tee.attributes` (§8.3.2) — TEE attributes (`$masked-value-type`).
pub const MVAL_TEE_ATTRIBUTES: i64 = -82;
/// `tee.mrtee` (§8.3.5) — measurement of the TEE
/// (`digest` / `digests-type` / `tagged-exp-digest-{member,not-member}`).
pub const MVAL_TEE_MRTEE: i64 = -83;
/// `tee.mrsigner` (§8.3.5) — measurement of the TEE signer
/// (`digest` / `digests-type` / `tagged-exp-digest-{member,not-member}`).
pub const MVAL_TEE_MRSIGNER: i64 = -84;
/// `tee.isvprodid` (§8.3.7) — ISV product ID (`uint` / `bstr`).
pub const MVAL_TEE_ISVPRODID: i64 = -85;
/// `tee.tcb-eval-num` (§8.3.13) — TCB evaluation number
/// (`uint` / `tagged-numeric-ge` / `tagged-int-range`).
pub const MVAL_TEE_TCB_EVAL_NUM: i64 = -86;
/// `tee.tcbstatus` (§8.3.14) — TCB status
/// (`set-tstr-type` / `tagged-exp-tstr-{member,not-member}`).
pub const MVAL_TEE_TCBSTATUS: i64 = -88;
/// `tee.advisory-ids` (§8.3.1) — security advisory IDs
/// (`set-tstr-type` / `tagged-exp-tstr-{member,not-member}`).
pub const MVAL_TEE_ADVISORY_IDS: i64 = -89;
/// `tee.cryptokeys` (§8.3.3) — TEE cryptographic keys (`[+ crypto-key]`).
pub const MVAL_TEE_CRYPTOKEYS: i64 = -91;
/// `tee.platform-instance-id` (§8.3.6) — platform instance ID (`bstr`).
///
/// Replaces the v03 `tee.instance-id` (code point `-77`), which was
/// removed in v07.
pub const MVAL_TEE_PLATFORM_INSTANCE_ID: i64 = -101;
/// `tee.tcb-comp-svn` (§8.3.12) — per-component TCB SVNs
/// (`[16*16 svn-type / tagged-numeric-ge / tagged-int-range / tagged-min-svn]`).
pub const MVAL_TEE_TCB_COMP_SVN: i64 = -125;

// ---------------------------------------------------------------------------
// IntelProfile
// ---------------------------------------------------------------------------

/// Intel CoRIM profile implementation.
///
/// Construct with [`IntelProfile::new`] and register with a
/// [`ProfileRegistry`](crate::profile::ProfileRegistry):
///
/// ```
/// use corim::profile::ProfileRegistry;
/// use corim::profile::intel::IntelProfile;
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
    /// [`reference.mval.extra_entries`][crate::types::measurement::MeasurementValuesMap::extra_entries]
    /// (any integer key recognised by [`intel_mval_name`]) and evaluates
    /// each one against the corresponding entry in `evidence` per the
    /// v07 §8.2 operator-shaped tags (`#6.60010` / `60020` / `60021`)
    /// and the base-CoRIM `tagged-int-range` (`#6.564`) /
    /// `tagged-min-svn` (`#6.553`). See the `eval` submodule for the
    /// per-key verdict policy.
    ///
    /// Composition with the core structural fields (`mkey`, `digests`,
    /// `svn`, `name`, ...) uses
    /// [`crate::validate::core_fields_match`]: a `Some(true)` return
    /// therefore certifies that BOTH the Intel extension constraints AND
    /// the core fields agree between the pair.
    ///
    /// Per-key verdicts roll up as follows:
    /// - any Intel-keyed `Fail` → `Some(false)` (early exit; structural
    ///   check skipped)
    /// - all Intel keys `Pass` → `Some(core_fields_match(...))`
    /// - the reference has no Intel keys → `None` (defer to core)
    ///
    /// If the reference references an Intel key whose entry is missing
    /// from evidence, the verdict is `Some(false)` — a verifier MUST
    /// reject when a required Reference Value has no Evidence to
    /// compare against.
    fn match_measurement(
        &self,
        reference: &MeasurementMap,
        evidence: &MeasurementMap,
        ctx: &MatchContext,
    ) -> Option<bool> {
        let mut verdicts: Vec<eval::Verdict> = Vec::new();
        for (key, ref_val) in reference.mval.extra_entries.iter() {
            if intel_mval_name(*key).is_none() {
                // Not an Intel-defined key; ignore (other profiles, or
                // unknown extras, are not this profile's business).
                continue;
            }
            match evidence.mval.extra_entries.get(key) {
                Some(ev_val) => verdicts.push(eval::evaluate_one_key(*key, ref_val, ev_val, ctx)),
                None => return Some(false),
            }
        }
        match eval::combine(&verdicts) {
            Some(true) => Some(crate::validate::core_fields_match(reference, evidence)),
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
        MVAL_TEE_PCEID => "tee.pceid",
        MVAL_TEE_MISCSELECT => "tee.miscselect",
        MVAL_TEE_ATTRIBUTES => "tee.attributes",
        MVAL_TEE_MRTEE => "tee.mrtee",
        MVAL_TEE_MRSIGNER => "tee.mrsigner",
        MVAL_TEE_ISVPRODID => "tee.isvprodid",
        MVAL_TEE_TCB_EVAL_NUM => "tee.tcb-eval-num",
        MVAL_TEE_TCBSTATUS => "tee.tcbstatus",
        MVAL_TEE_ADVISORY_IDS => "tee.advisory-ids",
        MVAL_TEE_CRYPTOKEYS => "tee.cryptokeys",
        MVAL_TEE_PLATFORM_INSTANCE_ID => "tee.platform-instance-id",
        MVAL_TEE_TCB_COMP_SVN => "tee.tcb-comp-svn",
        _ => return None,
    })
}

/// Render a CBOR value as a short, human-readable shape description
/// suitable for one-line diagnostic output.
///
/// The five Intel expression tags
/// (`#6.60010` / `60020` / `60021` / `564` / `553`) are decoded via
/// [`Expression::from_tag`] and rendered as e.g. `"ge 5"` or
/// `"member (3 strings)"`. RFC 9581 time tags (`#6.1001` etime,
/// `#6.1002` duration, `#6.1003` period — referenced by v07 §8.3.4
/// for `tee.tcbdate`) are labelled by name. Other tags are rendered
/// as `"#6.<tag>(…)"`.
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
        Value::Tag(tag, _) if Expression::is_intel_expression_tag(*tag) => {
            match Expression::from_tag(v) {
                Ok(expr) => display_expression(&expr),
                Err(_) => format!("#6.{}(…)", tag),
            }
        }
        // RFC 9581 time wrappers, referenced by v07 §8.3.4 `tee.tcbdate`.
        Value::Tag(1001, _) => "etime(…)".to_string(),
        Value::Tag(1002, _) => "duration(…)".to_string(),
        Value::Tag(1003, _) => "period(…)".to_string(),
        // RFC 8949 standard time tags.
        Value::Tag(0, inner) => match inner.as_ref() {
            Value::Text(t) => format!("tdate(\"{}\")", t),
            _ => "#6.0(…)".to_string(),
        },
        Value::Tag(1, inner) => match inner.as_ref() {
            Value::Integer(n) => format!("time({})", n),
            Value::Float(f) => format!("time({})", f),
            _ => "#6.1(…)".to_string(),
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
        assert_eq!(intel_mval_name(-77), None); // v03 tee.instance-id (removed in v07)
        assert_eq!(intel_mval_name(-90), None); // v03 tee.epoch (removed in v07)
        assert_eq!(intel_mval_name(-100), None);
        assert_eq!(intel_mval_name(-126), None);
    }

    #[test]
    fn platform_instance_id_is_recognised() {
        // v07 §8.3.6 replaces -77 with -101.
        assert_eq!(intel_mval_name(-101), Some("tee.platform-instance-id"));
    }

    #[test]
    fn diagnose_renders_known_keys() {
        let p = IntelProfile::new();
        let label = p.diagnose_mval_entry(MVAL_TEE_VENDOR, &Value::Text("Intel".to_string()));
        assert_eq!(label.as_deref(), Some("tee.vendor = \"Intel\""));

        let digest_array = Value::Array(vec![Value::Integer(1), Value::Bytes(vec![0u8; 32])]);
        let label = p.diagnose_mval_entry(MVAL_TEE_MRTEE, &digest_array);
        assert_eq!(label.as_deref(), Some("tee.mrtee = array[2]"));

        let label = p.diagnose_mval_entry(MVAL_TEE_ISVSVN, &Value::Integer(3));
        assert_eq!(label.as_deref(), Some("tee.isvsvn = 3"));
    }

    #[test]
    fn diagnose_renders_v07_set_tstr_expression() {
        let p = IntelProfile::new();
        let expr = Value::Tag(
            TAG_INTEL_SET_TSTR_EXPRESSION,
            Box::new(Value::Array(vec![
                Value::Integer(6), // op.mem
                Value::Array(vec![
                    Value::Text("UpToDate".into()),
                    Value::Text("Hardening".into()),
                ]),
            ])),
        );
        let label = p.diagnose_mval_entry(MVAL_TEE_TCBSTATUS, &expr);
        assert_eq!(label.as_deref(), Some("tee.tcbstatus = member (2 strings)"));
    }

    #[test]
    fn diagnose_renders_int_range_expression() {
        let p = IntelProfile::new();
        let expr = Value::Tag(
            crate::types::tags::TAG_INT_RANGE,
            Box::new(Value::Array(vec![Value::Integer(0), Value::Integer(15)])),
        );
        let label = p.diagnose_mval_entry(MVAL_TEE_ISVSVN, &expr);
        assert_eq!(label.as_deref(), Some("tee.isvsvn = range [0..15]"));
    }

    #[test]
    fn diagnose_renders_min_svn_expression() {
        let p = IntelProfile::new();
        let expr = Value::Tag(crate::types::tags::TAG_MIN_SVN, Box::new(Value::Integer(7)));
        let label = p.diagnose_mval_entry(MVAL_TEE_ISVSVN, &expr);
        assert_eq!(label.as_deref(), Some("tee.isvsvn = min-svn 7"));
    }

    #[test]
    fn diagnose_renders_masked_raw_value_expression() {
        let p = IntelProfile::new();
        let expr = Value::Tag(
            crate::types::tags::TAG_MASKED_RAW_VALUE,
            Box::new(Value::Array(vec![
                Value::Bytes(vec![0xF0, 0x00, 0x00, 0x00]),
                Value::Bytes(vec![0xF0, 0xFF, 0xFF, 0xFF]),
            ])),
        );
        let label = p.diagnose_mval_entry(MVAL_TEE_ATTRIBUTES, &expr);
        assert_eq!(
            label.as_deref(),
            Some("tee.attributes = masked-bstr <4-byte value, 4-byte mask>")
        );
    }

    #[test]
    fn diagnose_labels_rfc9581_time_tags() {
        let p = IntelProfile::new();
        // tee.tcbdate may carry etime / duration / period per v07 §8.3.4.
        let etime = Value::Tag(1001, Box::new(Value::Map(vec![])));
        let label = p.diagnose_mval_entry(MVAL_TEE_TCBDATE, &etime);
        assert_eq!(label.as_deref(), Some("tee.tcbdate = etime(…)"));
        let period = Value::Tag(1003, Box::new(Value::Array(vec![])));
        let label = p.diagnose_mval_entry(MVAL_TEE_TCBDATE, &period);
        assert_eq!(label.as_deref(), Some("tee.tcbdate = period(…)"));
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
