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
//! shapes (`digests`, `raw-value`, etc.) for these maps. This profile adds
//! CCA-specific checks for fields the generic matcher does not own, including:
//!
//! - identifying the CCA profile URI,
//! - validating the CCA-specific `mkey` names,
//! - enforcing the CCA-specific measurement-map shapes,
//! - matching cryptokeys, ROTPK raw evidence, and masked configuration
//!   reference values,
//! - enforcing the triple-level constraints: the environment subject
//!   (Platform Implementation ID / Realm RIM) and the measurement
//!   cardinality a reference triple must satisfy.

use crate::nostd_prelude::*;
use crate::profile::{MatchContext, Profile};
use crate::types::common::{ClassIdChoice, CryptoKey, InstanceIdChoice, MeasuredElement};
use crate::types::corim::ProfileChoice;
use crate::types::environment::EnvironmentMap;
use crate::types::measurement::{
    Digest, DigestAlg, MeasurementMap, MeasurementValuesMap, RawValueChoice,
};
use crate::types::triples::ReferenceTriple;

/// Profile URI for CCA Platform endorsements.
pub const CCA_PLATFORM_PROFILE_URI: &str = "tag:arm.com,2025:endorsements/cca_platform#1.0.0";
/// Profile URI for CCA Realm endorsements.
pub const CCA_REALM_PROFILE_URI: &str = "tag:arm.com,2025:endorsements/cca_realm#1.0.0";

/// CCA Platform software-component measurement key.
pub const CCA_MKEY_SOFTWARE_COMPONENT: &str = "cca.software-component";
/// CCA Platform configuration measurement key.
pub const CCA_MKEY_PLATFORM_CONFIG: &str = "cca.platform-config";
/// CCA Platform manufacturing configuration measurement key.
pub const CCA_MKEY_PLATFORM_MANUFACTURING_CONFIG: &str = "cca.platform-manufacturing-config";
/// Prefix for CCA Platform ROTPK measurement keys.
pub const CCA_MKEY_ROTPK_PREFIX: &str = "cca.rotpk.";
/// CCA Realm initial measurement key.
pub const CCA_MKEY_RIM: &str = "cca.rim";
/// CCA Realm extended measurement key for bank 0.
pub const CCA_MKEY_REM0: &str = "cca.rem0";
/// CCA Realm extended measurement key for bank 1.
pub const CCA_MKEY_REM1: &str = "cca.rem1";
/// CCA Realm extended measurement key for bank 2.
pub const CCA_MKEY_REM2: &str = "cca.rem2";
/// CCA Realm extended measurement key for bank 3.
pub const CCA_MKEY_REM3: &str = "cca.rem3";
/// CCA Realm personalization value measurement key.
pub const CCA_MKEY_RPV: &str = "cca.rpv";

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
/// CCA Platform Implementation ID size in bytes from draft-ydb-rats-cca-endorsements-04 §3.1.2.
const CCA_IMPLEMENTATION_ID_SIZE: usize = 32;
/// CCA Platform Instance ID (UEID) size in bytes, including the type byte,
/// from draft-ydb-rats-cca-endorsements-04 §3.1.2.
const CCA_INSTANCE_ID_SIZE: usize = 33;
/// UEID `RAND` type byte required by draft-ydb-rats-cca-endorsements-04 §3.1.2.
const CCA_INSTANCE_ID_RAND_TYPE: u8 = 0x01;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum RotpkFamily {
    Cm,
    Dm,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct RotpkMkey {
    family: RotpkFamily,
    index: u8,
    slot: u8,
}

/// Recognize a CCA Platform measurement key, per draft-ydb-rats-cca-endorsements-04.
pub fn is_cca_platform_mkey(name: &str) -> bool {
    match name {
        CCA_MKEY_SOFTWARE_COMPONENT
        | CCA_MKEY_PLATFORM_CONFIG
        | CCA_MKEY_PLATFORM_MANUFACTURING_CONFIG => true,
        _ => parse_rotpk_mkey(name).is_some(),
    }
}

fn one_digit_at_most(value: Option<&str>, max: u8) -> Option<u8> {
    let value = value?;

    let [digit] = value.as_bytes() else {
        return None;
    };
    if !digit.is_ascii_digit() {
        return None;
    }

    let value = digit - b'0';
    (value <= max).then_some(value)
}

fn parse_rotpk_mkey(name: &str) -> Option<RotpkMkey> {
    let rest = name.strip_prefix(CCA_MKEY_ROTPK_PREFIX)?;
    let mut parts = rest.split('.');
    let family = match parts.next()? {
        "CM" => RotpkFamily::Cm,
        "DM" => RotpkFamily::Dm,
        _ => return None,
    };
    let index = one_digit_at_most(parts.next(), CCA_ROTPK_MAX_INDEX)?;
    let slot = one_digit_at_most(parts.next(), CCA_ROTPK_MAX_SLOT)?;
    if parts.next().is_some() {
        return None;
    }

    Some(RotpkMkey {
        family,
        index,
        slot,
    })
}

/// Recognize a CCA Realm measurement key.
pub fn is_cca_realm_mkey(name: &str) -> bool {
    matches!(
        name,
        CCA_MKEY_RIM | CCA_MKEY_REM0 | CCA_MKEY_REM1 | CCA_MKEY_REM2 | CCA_MKEY_REM3 | CCA_MKEY_RPV
    )
}

fn mkey_name(mkey: &Option<MeasuredElement>) -> Option<String> {
    match mkey {
        Some(MeasuredElement::Text(s)) => Some(s.clone()),
        _ => None,
    }
}

fn has_single_signer_key(mval: &MeasurementValuesMap) -> bool {
    single_signer_key_bytes(mval).is_some_and(|bytes| is_cca_hash_size(bytes.len()))
}

fn single_signer_key_bytes(mval: &MeasurementValuesMap) -> Option<&[u8]> {
    match mval.cryptokeys.as_ref()?.as_slice() {
        [CryptoKey::Bytes(bytes)] => Some(bytes),
        _ => None,
    }
}

fn raw_value_bytes(mval: &MeasurementValuesMap) -> Option<&[u8]> {
    match &mval.raw_value {
        Some(RawValueChoice::Bytes(bytes)) => Some(bytes),
        _ => None,
    }
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
    raw_value_bytes(mval).is_some()
}

fn is_bytes_raw_value_of_len(mval: &MeasurementValuesMap, len: usize) -> bool {
    raw_value_bytes(mval).is_some_and(|bytes| bytes.len() == len)
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

fn is_cca_rotpk_evidence_mval(mval: &MeasurementValuesMap) -> bool {
    has_no_mval_fields_except(mval, false, false, true, false, false)
        && raw_value_bytes(mval).is_some_and(|bytes| is_cca_hash_size(bytes.len()))
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
        CCA_MKEY_SOFTWARE_COMPONENT => is_cca_software_component_mval(&m.mval),
        CCA_MKEY_PLATFORM_CONFIG | CCA_MKEY_PLATFORM_MANUFACTURING_CONFIG => {
            is_cca_masked_config_reference_mval(&m.mval)
        }
        _ if parse_rotpk_mkey(&mkey).is_some() => is_cca_rotpk_mval(&m.mval),
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
        CCA_MKEY_SOFTWARE_COMPONENT => is_cca_software_component_mval(&m.mval),
        CCA_MKEY_PLATFORM_CONFIG | CCA_MKEY_PLATFORM_MANUFACTURING_CONFIG => {
            is_cca_raw_config_evidence_mval(&m.mval)
        }
        _ if parse_rotpk_mkey(&mkey).is_some() => is_cca_rotpk_evidence_mval(&m.mval),
        _ => false,
    }
}

fn cca_platform_measurements_match(reference: &MeasurementMap, evidence: &MeasurementMap) -> bool {
    let Some(mkey) = mkey_name(&reference.mkey) else {
        return false;
    };

    match mkey.as_str() {
        CCA_MKEY_PLATFORM_CONFIG | CCA_MKEY_PLATFORM_MANUFACTURING_CONFIG => {
            raw_value_matches_with_reference_mask(
                &reference.mval.raw_value,
                &evidence.mval.raw_value,
            )
        }
        _ if parse_rotpk_mkey(&mkey).is_some() => {
            single_signer_key_bytes(&reference.mval) == raw_value_bytes(&evidence.mval)
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
        CCA_MKEY_RIM | CCA_MKEY_REM0 | CCA_MKEY_REM1 | CCA_MKEY_REM2 | CCA_MKEY_REM3 => {
            is_cca_realm_digest_mval(&m.mval)
        }
        CCA_MKEY_RPV => is_cca_rpv_mval(&m.mval),
        _ => false,
    }
}

fn valid_rotpk_group(measurements: &[MeasurementMap]) -> bool {
    let mut group = None;
    let mut slots = [false; (CCA_ROTPK_MAX_SLOT as usize) + 1];

    for measurement in measurements {
        let Some(mkey) = mkey_name(&measurement.mkey) else {
            continue;
        };
        let Some(rotpk) = parse_rotpk_mkey(&mkey) else {
            continue;
        };

        let current_group = (rotpk.family, rotpk.index);
        if group.is_some_and(|group| group != current_group) {
            return false;
        }
        group = Some(current_group);

        let slot = usize::from(rotpk.slot);
        if slots[slot] {
            return false;
        }
        slots[slot] = true;
    }

    true
}

fn has_duplicate_mkeys(measurements: &[MeasurementMap], recognized: fn(&str) -> bool) -> bool {
    measurements.iter().enumerate().any(|(i, measurement)| {
        let Some(mkey) = mkey_name(&measurement.mkey) else {
            return false;
        };
        if !recognized(&mkey) {
            return false;
        }
        measurements
            .iter()
            .skip(i + 1)
            .any(|other| mkey_name(&other.mkey).as_ref() == Some(&mkey))
    })
}

fn class_id_bytes(environment: &EnvironmentMap) -> Option<&[u8]> {
    match environment.class.as_ref()?.class_id.as_ref()? {
        ClassIdChoice::Bytes(bytes) => Some(bytes),
        _ => None,
    }
}

/// The subject of a CCA Platform triple is the Implementation ID, encoded as
/// `#6.560(bytes .size 32)` in `environment.class.class-id`, optionally
/// narrowed to a single instance by a `#6.550` UEID
/// (draft-ydb-rats-cca-endorsements-04 §3.1.2).
fn is_valid_cca_platform_environment(environment: &EnvironmentMap) -> bool {
    let Some(impl_id) = class_id_bytes(environment) else {
        return false;
    };
    if impl_id.len() != CCA_IMPLEMENTATION_ID_SIZE {
        return false;
    }

    match &environment.instance {
        None => true,
        Some(InstanceIdChoice::Ueid(ueid)) => {
            ueid.len() == CCA_INSTANCE_ID_SIZE && ueid[0] == CCA_INSTANCE_ID_RAND_TYPE
        }
        Some(_) => false,
    }
}

/// The subject of a CCA Realm triple is the RIM itself, encoded as
/// `#6.560(cca-hash-type)` in `environment.class.class-id`
/// (draft-ydb-rats-cca-endorsements-04 §3.2.2). The same value is also
/// carried as the mandatory `cca.rim` digest, so the two MUST agree.
fn is_valid_cca_realm_environment(environment: &EnvironmentMap) -> bool {
    environment.instance.is_none()
        && class_id_bytes(environment).is_some_and(|rim| is_cca_hash_size(rim.len()))
}

/// The `cca.rim` measurement may report the RIM under more than one hash
/// algorithm, and the class-id carries exactly one of those values, so one
/// matching digest is what the linkage requires.
fn realm_rim_matches_environment(environment: &EnvironmentMap, rim: &MeasurementMap) -> bool {
    let Some(class_rim) = class_id_bytes(environment) else {
        return false;
    };
    rim.mval
        .digests
        .as_ref()
        .is_some_and(|digests| digests.iter().any(|digest| digest.value() == class_rim))
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

    fn reference_triple_valid(&self, triple: &ReferenceTriple) -> bool {
        if !is_valid_cca_platform_environment(triple.environment()) {
            return false;
        }

        let mut software_component_count = 0usize;
        let mut platform_config_count = 0usize;
        let mut manufacturing_config_count = 0usize;
        let mut rotpk_count = 0usize;

        for measurement in triple.measurements() {
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
                CCA_MKEY_SOFTWARE_COMPONENT => software_component_count += 1,
                CCA_MKEY_PLATFORM_CONFIG => platform_config_count += 1,
                CCA_MKEY_PLATFORM_MANUFACTURING_CONFIG => manufacturing_config_count += 1,
                _ => rotpk_count += 1,
            }
        }

        // §3.1.3.3: each ROTPK array entry is carried in its own reference
        // triple, so a ROTPK triple describes no other platform measurement.
        if rotpk_count > 0 {
            return software_component_count == 0
                && platform_config_count == 0
                && manufacturing_config_count == 0
                && rotpk_count == triple.measurements().len()
                && valid_rotpk_group(triple.measurements());
        }

        // §3.1.3: a single reference triple MUST completely describe the CCA
        // Platform measurements — a mandatory platform configuration
        // (§3.1.3.2, "only one") and the platform software components
        // (§3.1.3.1), plus at most one manufacturing configuration (§3.1.3.4).
        software_component_count >= 1
            && platform_config_count == 1
            && manufacturing_config_count <= 1
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

    fn reference_triple_valid(&self, triple: &ReferenceTriple) -> bool {
        if !is_valid_cca_realm_environment(triple.environment()) {
            return false;
        }

        let mut has_rim = false;

        for measurement in triple.measurements() {
            let Some(mkey) = mkey_name(&measurement.mkey) else {
                continue;
            };

            if is_cca_realm_mkey(&mkey) {
                if !is_valid_cca_realm_measurement(measurement) {
                    return false;
                }
                // §3.2.2: the environment class-id carries the RIM, so the
                // mandatory `cca.rim` measurement MUST report the same value.
                if mkey == CCA_MKEY_RIM {
                    if !realm_rim_matches_environment(triple.environment(), measurement) {
                        return false;
                    }
                    has_rim = true;
                }
            }
        }

        has_rim && !has_duplicate_mkeys(triple.measurements(), is_cca_realm_mkey)
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
