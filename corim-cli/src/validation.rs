//! Shared non-cryptographic document validation for CLI inputs and baselines.

use corim::document::{
    self, CompatibilityNote, ProfileCoverage, TimeCheck, ValidationContext, ValidationCoverage,
};
use corim::profile::ProfileRegistry;
use corim::types::signed::CoseSign1Corim;
use corim::validate::ValidatedCorim;

pub(crate) const PARTIAL_EXIT_CODE: i32 = 4;

pub(crate) struct Document {
    pub payload: ValidatedCorim,
    pub signed: Option<CoseSign1Corim>,
    pub legacy_wrappers: bool,
    pub coverage: ValidationCoverage,
}

pub(crate) fn now() -> Result<i64, String> {
    let seconds = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|error| format!("system clock: {error}"))?
        .as_secs();
    i64::try_from(seconds).map_err(|_| "system clock exceeds i64 range".into())
}

pub(crate) fn document(
    bytes: &[u8],
    now: Option<i64>,
    registry: &ProfileRegistry,
) -> Result<Document, String> {
    let time = now.map_or(TimeCheck::Skip, TimeCheck::At);
    let outcome = document::validate(bytes, &ValidationContext::new(time, registry))
        .map_err(|error| error.to_string())?;
    let (payload, signed, coverage) = outcome.into_parts();
    let legacy_wrappers = coverage
        .compatibility()
        .iter()
        .any(|note| matches!(note, CompatibilityNote::LegacyOuterTag(_)));
    Ok(Document {
        payload,
        signed,
        legacy_wrappers,
        coverage,
    })
}

pub(crate) fn coverage_json(coverage: &ValidationCoverage) -> serde_json::Value {
    use serde_json::json;
    let time = match coverage.time() {
        TimeCheck::At(now) => json!({"status": "checked", "at": now}),
        TimeCheck::Skip => json!({"status": "skipped"}),
        _ => json!({"status": "unexamined"}),
    };
    let profile = match coverage.profile() {
        ProfileCoverage::NotDeclared => json!({"status": "not-declared"}),
        ProfileCoverage::Checked(id) => json!({"status": "checked", "id": id.to_string()}),
        ProfileCoverage::Unregistered(id) => {
            json!({"status": "unregistered", "id": id.to_string()})
        }
        _ => json!({"status": "unexamined"}),
    };
    let compatibility: Vec<_> = coverage
        .compatibility()
        .iter()
        .map(|note| match note {
            CompatibilityNote::LegacyOuterTag(tag) => {
                json!({"kind": "legacy-outer-tag", "tag": tag})
            }
            CompatibilityNote::BareCorimMap => json!({"kind": "bare-corim-map"}),
            CompatibilityNote::BareComidTag(index) => {
                json!({"kind": "bare-comid-tag", "index": index})
            }
            CompatibilityNote::FlatCwtClaims => json!({"kind": "flat-cwt-claims"}),
            _ => json!({"kind": "unexamined"}),
        })
        .collect();
    json!({
        "complete": coverage.is_complete(),
        "time": time,
        "profile": profile,
        "unexamined_tags": coverage.unexamined_tags(),
        "compatibility": compatibility,
        "signature_verified": false,
    })
}
