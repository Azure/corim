// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Azure profile that extends `measurement-values-map` with `tcbstatus`.
//!
//! This module demonstrates a strict enum-style profile extension where
//! the profile-defined key accepts only two values:
//!
//! - `UpToDate`
//! - `OutOfDate`

use crate::cbor::value::Value;
use crate::profile::{MatchContext, Profile};
use crate::types::corim::ProfileChoice;
use crate::types::measurement::MeasurementMap;

/// Profile URI used by [`AzureProfile`].
pub const AZURE_PROFILE_URI: &str = "tag:microsoft.com,2026:azure-profile#1.0.0";

/// Profile-defined `measurement-values-map` key for `tcbstatus`.
pub const MVAL_TCBSTATUS: i64 = -700;

/// Allowed `tcbstatus` values.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TcbStatus {
    /// The measured TCB is up-to-date.
    UpToDate,
    /// The measured TCB is out-of-date.
    OutOfDate,
}

impl TcbStatus {
    fn parse(v: &Value) -> Option<Self> {
        match v {
            Value::Text(s) if s == "UpToDate" => Some(Self::UpToDate),
            Value::Text(s) if s == "OutOfDate" => Some(Self::OutOfDate),
            _ => None,
        }
    }
}

/// Profile implementation for the Azure profile extension.
#[derive(Debug)]
pub struct AzureProfile {
    id: ProfileChoice,
}

impl AzureProfile {
    /// Construct a new profile instance.
    pub fn new() -> Self {
        Self {
            id: ProfileChoice::Uri(AZURE_PROFILE_URI.into()),
        }
    }
}

impl Default for AzureProfile {
    fn default() -> Self {
        Self::new()
    }
}

impl Profile for AzureProfile {
    fn identifier(&self) -> &ProfileChoice {
        &self.id
    }

    fn match_measurement(
        &self,
        reference: &MeasurementMap,
        evidence: &MeasurementMap,
        _ctx: &MatchContext,
    ) -> Option<bool> {
        let ref_val = match reference.mval.extra_entries.get(&MVAL_TCBSTATUS) {
            Some(v) => v,
            None => return None,
        };

        let ev_val = match evidence.mval.extra_entries.get(&MVAL_TCBSTATUS) {
            Some(v) => v,
            None => return Some(false),
        };

        let ref_status = match TcbStatus::parse(ref_val) {
            Some(v) => v,
            None => return Some(false),
        };
        let ev_status = match TcbStatus::parse(ev_val) {
            Some(v) => v,
            None => return Some(false),
        };

        if ref_status != ev_status {
            return Some(false);
        }

        Some(crate::validate::core_fields_match(reference, evidence))
    }

    fn diagnose_mval_entry(&self, key: i64, value: &Value) -> Option<String> {
        if key != MVAL_TCBSTATUS {
            return None;
        }

        match TcbStatus::parse(value) {
            Some(TcbStatus::UpToDate) => Some("tcbstatus = UpToDate".into()),
            Some(TcbStatus::OutOfDate) => Some("tcbstatus = OutOfDate".into()),
            None => Some("tcbstatus = <invalid>".into()),
        }
    }
}
