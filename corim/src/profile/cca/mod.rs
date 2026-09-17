// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Minimal Arm CCA endorsements profile support for
//! `draft-ydb-rats-cca-endorsements-04`.
//!
//! The draft defines two specific CoRIM profile URIs:
//!
//! - `tag:arm.com,2025:endorsements/cca_platform#1.0.0`
//! - `tag:arm.com,2025:endorsements/cca_realm#1.0.0`
//!
//! and a set of characteristic `measurement-map` names:
//!
//! - Platform: `cca.software-component`, `cca.platform-config`,
//!   `cca.rotpk.CM.<idx>.<slot>`, `cca.rotpk.DM.<idx>.<slot>`,
//!   `cca.platform-manufacturing-config`
//! - Realm: `cca.rim`, `cca.rem0`..`cca.rem3`, `cca.rpv`
//!
//! The core crate already knows how to compare most underlying CBOR value
//! shapes (`digests`, `raw-value`, etc.) for these maps, so this minimal
//! profile support focuses on:
//!
//! - identifying the CCA profile URI,
//! - validating the CCA-specific `mkey` names,
//! - enforcing the CCA-specific measurement-map shapes.

use crate::nostd_prelude::*;
use crate::profile::{MatchContext, Profile};
use crate::types::common::{CryptoKey, MeasuredElement};
use crate::types::corim::ProfileChoice;
use crate::types::measurement::{
    Digest, DigestAlg, MeasurementMap, MeasurementValuesMap, RawValueChoice,
};

/// Profile URI for CCA Platform endorsements.
pub const CCA_PLATFORM_PROFILE_URI: &str = "tag:arm.com,2025:endorsements/cca_platform#1.0.0";
/// Profile URI for CCA Realm endorsements.
pub const CCA_REALM_PROFILE_URI: &str = "tag:arm.com,2025:endorsements/cca_realm#1.0.0";

/// Maximum ROTPK array index from draft-ydb-rats-cca-endorsements-04 §3.1.3.3.
const CCA_ROTPK_MAX_INDEX: u8 = 7;
/// Maximum ROTPK slot index from draft-ydb-rats-cca-endorsements-04 §3.1.3.3.
const CCA_ROTPK_MAX_SLOT: u8 = 5;
/// CCA hash size in bytes from draft-ydb-rats-cca-endorsements-04 §3.1.3.1 and §3.1.3.3.
const CCA_HASH_SIZE_256: usize = 32;
/// CCA hash size in bytes from draft-ydb-rats-cca-endorsements-04 §3.1.3.1 and §3.1.3.3.
const CCA_HASH_SIZE_384: usize = 48;
/// CCA hash size in bytes from draft-ydb-rats-cca-endorsements-04 §3.1.3.1 and §3.1.3.3.
const CCA_HASH_SIZE_512: usize = 64;
/// CCA Realm personalization value size in bytes from draft-ydb-rats-cca-endorsements-04 §3.2.3.
const CCA_RPV_SIZE: usize = 64;

/// Recognize a CCA Platform measurement key, per draft-ydb-rats-cca-endorsements-04.
pub fn is_cca_platform_mkey(name: &str) -> bool {
    match name {
        "cca.software-component" | "cca.platform-config" | "cca.platform-manufacturing-config" => {
            true
        }
        _ => {
            let Some(rest) = name.strip_prefix("cca.rotpk.") else {
                return false;
            };
            let mut parts = rest.split('.');
            let family = parts.next();
            let idx = parts.next();
            let slot = parts.next();
            if parts.next().is_some() {
                return false;
            }
            matches!(family, Some("CM") | Some("DM"))
                && one_digit_at_most(idx, CCA_ROTPK_MAX_INDEX)
                && one_digit_at_most(slot, CCA_ROTPK_MAX_SLOT)
        }
    }
}

fn one_digit_at_most(value: Option<&str>, max: u8) -> bool {
    let Some(value) = value else {
        return false;
    };

    let [digit] = value.as_bytes() else {
        return false;
    };
    digit.is_ascii_digit() && digit - b'0' <= max
}

/// Recognize a CCA Realm measurement key.
pub fn is_cca_realm_mkey(name: &str) -> bool {
    matches!(
        name,
        "cca.rim" | "cca.rem0" | "cca.rem1" | "cca.rem2" | "cca.rem3" | "cca.rpv"
    )
}

fn mkey_name(mkey: &Option<MeasuredElement>) -> Option<String> {
    match mkey {
        Some(MeasuredElement::Text(s)) => Some(s.clone()),
        _ => None,
    }
}

fn has_single_signer_key(mval: &MeasurementValuesMap) -> bool {
    mval.cryptokeys.as_ref().is_some_and(|keys| {
        keys.len() == 1
            && keys.iter().all(|k| match k {
                CryptoKey::Bytes(b) => matches!(
                    b.len(),
                    CCA_HASH_SIZE_256 | CCA_HASH_SIZE_384 | CCA_HASH_SIZE_512
                ),
                _ => false,
            })
    })
}

fn has_no_mval_fields_except(
    mval: &MeasurementValuesMap,
    allow_version: bool,
    allow_digests: bool,
    allow_raw_value: bool,
    allow_name: bool,
    allow_cryptokeys: bool,
) -> bool {
    (allow_version || mval.version.is_none())
        && (allow_digests || mval.digests.is_none())
        && (allow_raw_value || mval.raw_value.is_none())
        && (allow_name || mval.name.is_none())
        && (allow_cryptokeys || mval.cryptokeys.is_none())
        && mval.svn.is_none()
        && mval.flags.is_none()
        && mval.mac_addr.is_none()
        && mval.ip_addr.is_none()
        && mval.serial_number.is_none()
        && mval.ueid.is_none()
        && mval.uuid.is_none()
        && mval.integrity_registers.is_none()
        && mval.int_range.is_none()
        && mval.extra_entries.is_empty()
}

fn has_cca_digests(mval: &MeasurementValuesMap) -> bool {
    mval.digests.as_ref().is_some_and(|digests| {
        !digests.is_empty()
            && digests.iter().all(is_cca_digest)
            && digests.iter().enumerate().all(|(i, digest)| {
                digests
                    .iter()
                    .skip(i + 1)
                    .all(|other| digest.alg() != other.alg())
            })
    })
}

fn is_cca_digest(digest: &Digest) -> bool {
    matches!(digest.alg(), DigestAlg::Text(_)) && is_cca_hash_size(digest.value().len())
}

fn is_cca_hash_size(len: usize) -> bool {
    matches!(
        len,
        CCA_HASH_SIZE_256 | CCA_HASH_SIZE_384 | CCA_HASH_SIZE_512
    )
}

fn is_masked_raw_value(mval: &MeasurementValuesMap) -> bool {
    matches!(mval.raw_value, Some(RawValueChoice::Masked { .. }))
}

fn is_bytes_raw_value(mval: &MeasurementValuesMap) -> bool {
    matches!(mval.raw_value, Some(RawValueChoice::Bytes(_)))
}

fn is_bytes_raw_value_of_len(mval: &MeasurementValuesMap, len: usize) -> bool {
    matches!(&mval.raw_value, Some(RawValueChoice::Bytes(bytes)) if bytes.len() == len)
}

fn is_cca_software_component_mval(mval: &MeasurementValuesMap) -> bool {
    has_no_mval_fields_except(mval, true, true, false, true, true)
        && mval
            .version
            .as_ref()
            .is_none_or(|version| version.version_scheme.is_none())
        && has_cca_digests(mval)
        && has_single_signer_key(mval)
}

fn is_cca_rotpk_mval(mval: &MeasurementValuesMap) -> bool {
    has_no_mval_fields_except(mval, false, false, false, false, true) && has_single_signer_key(mval)
}

fn is_cca_masked_config_reference_mval(mval: &MeasurementValuesMap) -> bool {
    has_no_mval_fields_except(mval, false, false, true, false, false) && is_masked_raw_value(mval)
}

fn is_cca_raw_config_evidence_mval(mval: &MeasurementValuesMap) -> bool {
    has_no_mval_fields_except(mval, false, false, true, false, false) && is_bytes_raw_value(mval)
}

fn is_cca_realm_digest_mval(mval: &MeasurementValuesMap) -> bool {
    has_no_mval_fields_except(mval, false, true, false, false, false) && has_cca_digests(mval)
}

fn is_cca_rpv_mval(mval: &MeasurementValuesMap) -> bool {
    has_no_mval_fields_except(mval, false, false, true, false, false)
        && is_bytes_raw_value_of_len(mval, CCA_RPV_SIZE)
}

fn is_valid_cca_platform_reference_measurement(m: &MeasurementMap) -> bool {
    if m.authorized_by.is_some() {
        return false;
    }

    let Some(mkey) = mkey_name(&m.mkey) else {
        return false;
    };

    match mkey.as_str() {
        "cca.software-component" => is_cca_software_component_mval(&m.mval),
        "cca.platform-config" | "cca.platform-manufacturing-config" => {
            is_cca_masked_config_reference_mval(&m.mval)
        }
        _ if is_cca_platform_mkey(&mkey) => is_cca_rotpk_mval(&m.mval),
        _ => false,
    }
}

fn is_valid_cca_platform_evidence_measurement(m: &MeasurementMap) -> bool {
    if m.authorized_by.is_some() {
        return false;
    }

    let Some(mkey) = mkey_name(&m.mkey) else {
        return false;
    };

    match mkey.as_str() {
        "cca.software-component" => is_cca_software_component_mval(&m.mval),
        "cca.platform-config" | "cca.platform-manufacturing-config" => {
            is_cca_raw_config_evidence_mval(&m.mval)
        }
        _ if is_cca_platform_mkey(&mkey) => is_cca_rotpk_mval(&m.mval),
        _ => false,
    }
}

fn cca_platform_measurements_match(reference: &MeasurementMap, evidence: &MeasurementMap) -> bool {
    let Some(mkey) = mkey_name(&reference.mkey) else {
        return false;
    };

    match mkey.as_str() {
        "cca.platform-config" | "cca.platform-manufacturing-config" => {
            raw_value_matches_with_reference_mask(
                &reference.mval.raw_value,
                &evidence.mval.raw_value,
            )
        }
        _ => {
            crate::validate::core_fields_match(reference, evidence)
                && reference.mval.cryptokeys == evidence.mval.cryptokeys
        }
    }
}

fn raw_value_matches_with_reference_mask(
    reference: &Option<RawValueChoice>,
    evidence: &Option<RawValueChoice>,
) -> bool {
    match (reference, evidence) {
        (Some(RawValueChoice::Masked { value, mask }), Some(RawValueChoice::Bytes(evidence))) => {
            masked_bytes_match(value, evidence, mask)
        }
        _ => reference == evidence,
    }
}

fn masked_bytes_match(reference: &[u8], evidence: &[u8], mask: &[u8]) -> bool {
    reference.len() == evidence.len()
        && reference.len() == mask.len()
        && reference
            .iter()
            .zip(evidence)
            .zip(mask)
            .all(|((r, e), m)| (r & m) == (e & m))
}

fn is_valid_cca_realm_measurement(m: &MeasurementMap) -> bool {
    if m.authorized_by.is_some() {
        return false;
    }

    let Some(mkey) = mkey_name(&m.mkey) else {
        return false;
    };

    match mkey.as_str() {
        "cca.rim" | "cca.rem0" | "cca.rem1" | "cca.rem2" | "cca.rem3" => {
            is_cca_realm_digest_mval(&m.mval)
        }
        "cca.rpv" => is_cca_rpv_mval(&m.mval),
        _ => false,
    }
}

/// Profile implementation for Arm CCA Platform endorsements.
#[derive(Clone, Debug, PartialEq)]
pub struct CcaPlatformProfile {
    id: ProfileChoice,
}

impl CcaPlatformProfile {
    /// Construct a new CCA Platform profile instance.
    pub fn new() -> Self {
        Self {
            id: ProfileChoice::Uri(CCA_PLATFORM_PROFILE_URI.into()),
        }
    }
}

impl Default for CcaPlatformProfile {
    fn default() -> Self {
        Self::new()
    }
}

/// Profile implementation for Arm CCA Realm endorsements.
#[derive(Clone, Debug, PartialEq)]
pub struct CcaRealmProfile {
    id: ProfileChoice,
}

impl CcaRealmProfile {
    /// Construct a new CCA Realm profile instance.
    pub fn new() -> Self {
        Self {
            id: ProfileChoice::Uri(CCA_REALM_PROFILE_URI.into()),
        }
    }
}

impl Default for CcaRealmProfile {
    fn default() -> Self {
        Self::new()
    }
}

impl Profile for CcaPlatformProfile {
    fn identifier(&self) -> &ProfileChoice {
        &self.id
    }

    fn reference_measurements_valid(&self, measurements: &[MeasurementMap]) -> bool {
        let mut platform_config_count = 0usize;
        let mut manufacturing_config_count = 0usize;

        for measurement in measurements {
            let Some(mkey) = mkey_name(&measurement.mkey) else {
                continue;
            };

            if !is_cca_platform_mkey(&mkey) {
                continue;
            }
            if !is_valid_cca_platform_reference_measurement(measurement) {
                return false;
            }

            match mkey.as_str() {
                "cca.platform-config" => platform_config_count += 1,
                "cca.platform-manufacturing-config" => manufacturing_config_count += 1,
                _ => {}
            }
        }

        platform_config_count <= 1 && manufacturing_config_count <= 1
    }

    fn match_measurement(
        &self,
        reference: &MeasurementMap,
        evidence: &MeasurementMap,
        _ctx: &MatchContext,
    ) -> Option<bool> {
        let ref_mkey = mkey_name(&reference.mkey)?;
        let ev_mkey = mkey_name(&evidence.mkey)?;

        if ref_mkey != ev_mkey {
            return Some(false);
        }
        if !is_cca_platform_mkey(&ref_mkey) {
            return None;
        }
        if !is_valid_cca_platform_reference_measurement(reference)
            || !is_valid_cca_platform_evidence_measurement(evidence)
        {
            return Some(false);
        }

        Some(cca_platform_measurements_match(reference, evidence))
    }
}

impl Profile for CcaRealmProfile {
    fn identifier(&self) -> &ProfileChoice {
        &self.id
    }

    fn reference_measurements_valid(&self, measurements: &[MeasurementMap]) -> bool {
        let mut has_rim = false;

        for measurement in measurements {
            let Some(mkey) = mkey_name(&measurement.mkey) else {
                continue;
            };

            if is_cca_realm_mkey(&mkey) {
                if !is_valid_cca_realm_measurement(measurement) {
                    return false;
                }
                has_rim |= mkey == "cca.rim";
            }
        }

        has_rim
    }

    fn match_measurement(
        &self,
        reference: &MeasurementMap,
        evidence: &MeasurementMap,
        _ctx: &MatchContext,
    ) -> Option<bool> {
        let ref_mkey = mkey_name(&reference.mkey)?;
        let ev_mkey = mkey_name(&evidence.mkey)?;

        if ref_mkey != ev_mkey {
            return Some(false);
        }
        if !is_cca_realm_mkey(&ref_mkey) {
            return None;
        }
        if !is_valid_cca_realm_measurement(reference) || !is_valid_cca_realm_measurement(evidence) {
            return Some(false);
        }

        Some(crate::validate::core_fields_match(reference, evidence))
    }
}
