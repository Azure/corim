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
//! The core crate already knows how to compare the underlying CBOR value
//! shape (`digests`, `raw-value`, `cryptokeys`, etc.) for these maps, so this
//! minimal profile support focuses on:
//!
//! - identifying the CCA profile URI,
//! - validating the CCA-specific `mkey` names,
//! - providing diagnosis labels for those names,
//! - enforcing the CCA-specific measurement-map shapes.

use crate::cbor::value::Value;
use crate::nostd_prelude::*;
use crate::profile::{MatchContext, Profile};
use crate::types::common::MeasuredElement;
use crate::types::corim::ProfileChoice;
use crate::types::measurement::MeasurementMap;

/// Profile URI for CCA Platform endorsements.
pub const CCA_PLATFORM_PROFILE_URI: &str = "tag:arm.com,2025:endorsements/cca_platform#1.0.0";
/// Profile URI for CCA Realm endorsements.
pub const CCA_REALM_PROFILE_URI: &str = "tag:arm.com,2025:endorsements/cca_realm#1.0.0";

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
                && idx
                    .and_then(|s| s.parse::<u8>().ok())
                    .is_some_and(|n| n <= 7)
                && slot
                    .and_then(|s| s.parse::<u8>().ok())
                    .is_some_and(|n| n <= 5)
        }
    }
}

/// Recognize a CCA Realm measurement key.
pub fn is_cca_realm_mkey(name: &str) -> bool {
    match name {
        "cca.rim" | "cca.rpv" => true,
        _ => {
            let Some(rest) = name.strip_prefix("cca.rem") else {
                return false;
            };
            rest.parse::<u8>().is_ok_and(|n| n <= 3)
        }
    }
}

fn mkey_name(mkey: &Option<MeasuredElement>) -> Option<String> {
    match mkey {
        Some(MeasuredElement::Text(s)) => Some(s.clone()),
        _ => None,
    }
}

fn is_valid_cca_platform_measurement(m: &MeasurementMap) -> bool {
    let Some(mkey) = mkey_name(&m.mkey) else {
        return false;
    };

    match mkey.as_str() {
        "cca.software-component" => {
            m.mval.digests.as_ref().is_some_and(|d| !d.is_empty())
                && m.mval.cryptokeys.as_ref().is_some_and(|keys| {
                    !keys.is_empty()
                        && keys.iter().all(|k| match k {
                            crate::types::common::CryptoKey::Bytes(b) => {
                                matches!(b.len(), 32 | 48 | 64)
                            }
                            _ => false,
                        })
                })
        }
        "cca.platform-config" | "cca.platform-manufacturing-config" => m.mval.raw_value.is_some(),
        _ if is_cca_platform_mkey(&mkey) => m.mval.cryptokeys.as_ref().is_some_and(|keys| {
            !keys.is_empty()
                && keys.len() == 1
                && keys.iter().all(|k| match k {
                    crate::types::common::CryptoKey::Bytes(b) => matches!(b.len(), 32 | 48 | 64),
                    _ => false,
                })
        }),
        _ => false,
    }
}

fn is_valid_cca_realm_measurement(m: &MeasurementMap) -> bool {
    let Some(mkey) = mkey_name(&m.mkey) else {
        return false;
    };

    match mkey.as_str() {
        "cca.rim" | "cca.rem0" | "cca.rem1" | "cca.rem2" | "cca.rem3" => {
            m.mval.digests.as_ref().is_some_and(|d| !d.is_empty())
        }
        "cca.rpv" => m.mval.raw_value.is_some(),
        _ => false,
    }
}

#[derive(Debug)]
pub struct CcaPlatformProfile {
    id: ProfileChoice,
}

impl CcaPlatformProfile {
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

#[derive(Debug)]
pub struct CcaRealmProfile {
    id: ProfileChoice,
}

impl CcaRealmProfile {
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
        if !is_valid_cca_platform_measurement(reference)
            || !is_valid_cca_platform_measurement(evidence)
        {
            return Some(false);
        }

        Some(crate::validate::core_fields_match(reference, evidence))
    }

    fn diagnose_mval_entry(&self, _key: i64, value: &Value) -> Option<String> {
        match value {
            Value::Text(s) if is_cca_platform_mkey(s) => Some(format!("{} = {}", s, s)),
            _ => None,
        }
    }
}

impl Profile for CcaRealmProfile {
    fn identifier(&self) -> &ProfileChoice {
        &self.id
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

    fn diagnose_mval_entry(&self, _key: i64, value: &Value) -> Option<String> {
        match value {
            Value::Text(s) if is_cca_realm_mkey(s) => Some(format!("{} = {}", s, s)),
            _ => None,
        }
    }
}
