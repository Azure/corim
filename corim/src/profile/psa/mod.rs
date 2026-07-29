// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Arm PSA CoRIM profile (`tag:arm.com,2025:psa#1.0.0`).
//!
//! This module implements the `psa-cert-num` (key 100)
//! `measurement-values-map` extension defined in the base CoRIM CDDL of
//! draft-ietf-rats-corim-11 (Appendix A):
//!
//! ```text
//! $$measurement-values-map-extension //= (&(psa-cert-num: 100) => psa-cert-num-type)
//! psa-cert-num-type = text .regexp "[0-9]{13} - [0-9]{5}"
//! ```
//!
//! `psa-cert-num` carries a PSA Certified certificate number, e.g.
//! `"1234567890123 - 12345"`, as shown in the PSA appraisal example of
//! draft-11 §8.2.6. The complete PSA endorsements profile is specified
//! separately in `I-D.fdb-rats-psa-endorsements`; that draft reuses base
//! CoRIM features (string measured-element identifiers such as
//! `psa.software-component`) and adds no further wire elements beyond
//! `psa-cert-num`, so this module covers the profile's sole
//! measurement-values extension key.
//!
//! Gated on the `profile-psa` Cargo feature. Like every profile, the
//! core crate already preserves the `psa-cert-num` entry verbatim in
//! [`MeasurementValuesMap::extra_entries`][crate::types::measurement::MeasurementValuesMap::extra_entries];
//! this module adds format validation, diagnose labelling, JSON template
//! aliasing, and profile-aware matching.
//!
//! # Example
//!
//! ```
//! use corim::profile::psa::{is_valid_cert_num, PsaProfile, PSA_PROFILE_URI};
//! use corim::profile::Profile;
//! use corim::types::corim::ProfileChoice;
//!
//! assert!(is_valid_cert_num("1234567890123 - 12345"));
//! assert!(!is_valid_cert_num("1234567890123-12345"));
//!
//! let profile = PsaProfile::new();
//! assert_eq!(
//!     profile.identifier(),
//!     &ProfileChoice::Uri(PSA_PROFILE_URI.into())
//! );
//! ```

use crate::cbor::value::Value;
use crate::nostd_prelude::*;
use crate::profile::{MatchContext, Profile};
use crate::types::corim::ProfileChoice;
use crate::types::measurement::MeasurementMap;

/// Profile URI used by [`PsaProfile`] (draft-ietf-rats-corim-11 §8.2.6).
pub const PSA_PROFILE_URI: &str = "tag:arm.com,2025:psa#1.0.0";

/// Profile-defined `measurement-values-map` key for `psa-cert-num`
/// (draft-ietf-rats-corim-11 Appendix A, `$$measurement-values-map-extension`).
pub const MVAL_PSA_CERT_NUM: i64 = 100;

/// Returns `true` if `s` satisfies `psa-cert-num-type`
/// (`text .regexp "[0-9]{13} - [0-9]{5}"`).
///
/// A valid value is exactly thirteen ASCII digits, a space-hyphen-space
/// separator (`" - "`), then five ASCII digits — 21 characters total.
/// The CDDL `.regexp` constraint is a full-string (anchored) match per
/// RFC 8610, so length and every character are checked.
pub fn is_valid_cert_num(s: &str) -> bool {
    let b = s.as_bytes();
    // 13 digits + " - " (3) + 5 digits = 21 bytes.
    if b.len() != 21 {
        return false;
    }
    let all_digits = |slice: &[u8]| slice.iter().all(u8::is_ascii_digit);
    all_digits(&b[0..13]) && &b[13..16] == b" - " && all_digits(&b[16..21])
}

/// [`Profile`] implementation for the Arm PSA profile extension.
#[derive(Debug)]
pub struct PsaProfile {
    id: ProfileChoice,
}

impl PsaProfile {
    /// Construct a new profile instance.
    pub fn new() -> Self {
        Self {
            id: ProfileChoice::Uri(PSA_PROFILE_URI.into()),
        }
    }
}

impl Default for PsaProfile {
    fn default() -> Self {
        Self::new()
    }
}

/// Extract a well-formed `psa-cert-num` string from a CBOR value, or
/// `None` if the value is not text or does not match `psa-cert-num-type`.
fn cert_num(value: &Value) -> Option<&str> {
    match value {
        Value::Text(s) if is_valid_cert_num(s) => Some(s),
        _ => None,
    }
}

impl Profile for PsaProfile {
    fn identifier(&self) -> &ProfileChoice {
        &self.id
    }

    fn match_measurement(
        &self,
        reference: &MeasurementMap,
        evidence: &MeasurementMap,
        _ctx: &MatchContext,
    ) -> Option<bool> {
        // Only take a position when the reference carries psa-cert-num;
        // otherwise defer to the crate's default matching.
        let ref_val = reference.mval.extra_entries.get(&MVAL_PSA_CERT_NUM)?;

        let ev_val = match evidence.mval.extra_entries.get(&MVAL_PSA_CERT_NUM) {
            Some(v) => v,
            None => return Some(false),
        };

        let ref_num = match cert_num(ref_val) {
            Some(s) => s,
            None => return Some(false),
        };
        let ev_num = match cert_num(ev_val) {
            Some(s) => s,
            None => return Some(false),
        };

        if ref_num != ev_num {
            return Some(false);
        }

        Some(crate::validate::core_fields_match(reference, evidence))
    }

    fn diagnose_mval_entry(&self, key: i64, value: &Value) -> Option<String> {
        if key != MVAL_PSA_CERT_NUM {
            return None;
        }
        match cert_num(value) {
            Some(s) => Some(format!("psa-cert-num = {s}")),
            None => Some("psa-cert-num = <invalid>".into()),
        }
    }

    fn mval_json_alias(&self, name: &str) -> Option<i64> {
        match name {
            "psa-cert-num" => Some(MVAL_PSA_CERT_NUM),
            _ => None,
        }
    }

    fn mval_json_name(&self, key: i64) -> Option<&'static str> {
        match key {
            MVAL_PSA_CERT_NUM => Some("psa-cert-num"),
            _ => None,
        }
    }
}
