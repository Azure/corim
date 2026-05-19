// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Validation and appraisal logic per draft-ietf-rats-corim-10 §9.
//!
//! Covers reference value matching (Phase 3) and conditional-endorsement-series
//! application (Phase 4).

#[allow(unused_imports)]
use crate::nostd_prelude::*;
#[cfg(feature = "std")]
use std::time::{SystemTime, UNIX_EPOCH};

use crate::cbor;
use crate::error::ValidationError;
use crate::profile::{MatchContext, Profile};
use crate::types::comid::ComidTag;
use crate::types::corim::{ConciseTagChoice, ConciseTlTag, CorimMap};
use crate::types::coswid::ConciseSwidTag;
use crate::types::environment::EnvironmentMap;
use crate::types::measurement::{Digest, MeasurementMap, SvnChoice};
use crate::types::tags::TAG_CORIM;
use crate::types::triples::{
    ConditionalEndorsementSeriesTriple, ConditionalSeriesRecord, ReferenceTriple,
};
use crate::Validate;

// ---------------------------------------------------------------------------
// Phase 1: Input validation (§9.2)
// ---------------------------------------------------------------------------

/// Maximum allowed CoRIM payload size (16 MiB).
///
/// Prevents denial-of-service from unbounded memory allocation when decoding
/// untrusted input.
pub const MAX_PAYLOAD_SIZE: usize = 16 * 1024 * 1024;

/// Result of decoding and validating a CoRIM document.
///
/// Contains the decoded `CorimMap` and all extracted/validated tags.
#[derive(Clone, Debug)]
pub struct ValidatedCorim {
    /// The decoded top-level CoRIM map.
    pub corim: CorimMap,
    /// Decoded CoMID tags (tag 506).
    pub comids: Vec<ComidTag>,
    /// Decoded CoTL tags (tag 508).
    pub cotls: Vec<ConciseTlTag>,
    /// Decoded CoSWID tags (tag 505).
    pub coswids: Vec<ConciseSwidTag>,
    /// Number of CoSWID tags that failed structured decoding (opaque).
    pub coswid_opaque_count: usize,
}

/// Decode CBOR bytes as a CoRIM and validate structural requirements.
///
/// Expects the bytes to be a CBOR tag-501-wrapped `corim-map`. Validates:
/// - Payload does not exceed [`MAX_PAYLOAD_SIZE`]
/// - `rim-validity` is not expired (if present)
/// - Each CoMID tag decodes correctly and has non-empty triples
///
/// Uses the system clock for validity checks. For deterministic testing,
/// use [`decode_and_validate_at`] with an explicit timestamp.
#[cfg(feature = "std")]
pub fn decode_and_validate(bytes: &[u8]) -> Result<(CorimMap, Vec<ComidTag>), ValidationError> {
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|e| ValidationError::Clock(e.to_string()))?
        .as_secs();
    let now = i64::try_from(secs)
        .map_err(|_| ValidationError::Clock("system clock beyond i64 range".into()))?;
    decode_and_validate_at(bytes, now)
}

/// Decode and validate a CoRIM with an explicit "now" timestamp.
///
/// Same as [`decode_and_validate`] but uses the provided `now_epoch_secs`
/// instead of the system clock. This is useful for deterministic testing.
pub fn decode_and_validate_at(
    bytes: &[u8],
    now_epoch_secs: i64,
) -> Result<(CorimMap, Vec<ComidTag>), ValidationError> {
    let validated = decode_and_validate_full_impl(bytes, now_epoch_secs)?;
    Ok((validated.corim, validated.comids))
}

/// Validate a single CoMID tag.
fn validate_comid(comid: &ComidTag) -> Result<(), ValidationError> {
    comid.valid().map_err(ValidationError::Invalid)
}

/// Validate a single CoTL tag (§6.1).
///
/// Checks:
/// - `tags-list` is non-empty
/// - `tl-validity` is within the current time window
fn validate_cotl(cotl: &ConciseTlTag, now_epoch_secs: i64) -> Result<(), ValidationError> {
    if cotl.tags_list.is_empty() {
        return Err(ValidationError::EmptyTagsList);
    }

    // Check CoTL validity window
    if let Some(nb) = cotl.tl_validity.not_before {
        if now_epoch_secs < nb.epoch_secs() {
            return Err(ValidationError::NotYetValid);
        }
    }
    if cotl.tl_validity.not_after.epoch_secs() < now_epoch_secs {
        return Err(ValidationError::Expired);
    }

    Ok(())
}

/// Decode and validate a CoRIM, returning all extracted tag types.
///
/// Like [`decode_and_validate`] but returns a [`ValidatedCorim`] with
/// CoMID, CoTL, and CoSWID counts.
#[cfg(feature = "std")]
pub fn decode_and_validate_full(bytes: &[u8]) -> Result<ValidatedCorim, ValidationError> {
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|e| ValidationError::Clock(e.to_string()))?
        .as_secs();
    let now = i64::try_from(secs)
        .map_err(|_| ValidationError::Clock("system clock beyond i64 range".into()))?;
    decode_and_validate_full_at(bytes, now)
}

/// Decode and validate a CoRIM with an explicit timestamp, returning all tag types.
pub fn decode_and_validate_full_at(
    bytes: &[u8],
    now_epoch_secs: i64,
) -> Result<ValidatedCorim, ValidationError> {
    decode_and_validate_full_impl(bytes, now_epoch_secs)
}

/// Internal unified implementation — decodes all tags in a single pass.
fn decode_and_validate_full_impl(
    bytes: &[u8],
    now_epoch_secs: i64,
) -> Result<ValidatedCorim, ValidationError> {
    if bytes.len() > MAX_PAYLOAD_SIZE {
        return Err(ValidationError::PayloadTooLarge {
            size: bytes.len(),
            max: MAX_PAYLOAD_SIZE,
        });
    }
    // Decode interop: peel legacy `#6.500` / `#6.502` outer wrappers if
    // present (TCG Endorsement spec / NVIDIA producers). See
    // `crate::compat::peel_tcg_wrappers`.
    let peeled = crate::compat::peel_tcg_wrappers(bytes).map_err(ValidationError::Decode)?;
    let bytes = peeled.as_bytes();
    // Decode interop: if the input is a bare `corim-map` (no #6.501 wrapper),
    // synthesize the wrapper so strict decode succeeds. Same producer family
    // as above (TCG-style implementations omit the inner tag because the
    // outer #6.500/#6.502 historically provided disambiguation).
    let wrapped = crate::compat::wrap_bare_corim_map(bytes);
    let bytes = wrapped.as_bytes();
    // Decode the tag-501 wrapped CoRIM
    let tagged: cbor::value::Tagged<CorimMap> =
        cbor::decode(bytes).map_err(ValidationError::Decode)?;
    if tagged.tag != TAG_CORIM {
        return Err(ValidationError::Decode(
            crate::error::DecodeError::UnexpectedTag {
                expected: TAG_CORIM,
                found: tagged.tag,
            },
        ));
    }
    let corim = tagged.value;

    // Check rim-validity
    if let Some(ref validity) = corim.rim_validity {
        if let Some(nb) = validity.not_before {
            if now_epoch_secs < nb.epoch_secs() {
                return Err(ValidationError::NotYetValid);
            }
        }
        if validity.not_after.epoch_secs() < now_epoch_secs {
            return Err(ValidationError::Expired);
        }
    }

    // Extract and validate each tag — single pass
    let mut comids = Vec::new();
    let mut cotls = Vec::new();
    let mut coswids = Vec::new();
    let mut coswid_opaque_count = 0usize;
    for tag in &corim.tags {
        match tag {
            ConciseTagChoice::Comid(comid_bytes) => {
                let comid: ComidTag = cbor::decode(comid_bytes).map_err(ValidationError::Decode)?;
                validate_comid(&comid)?;
                comids.push(comid);
            }
            ConciseTagChoice::Cotl(cotl_bytes) => {
                let cotl: ConciseTlTag =
                    cbor::decode(cotl_bytes).map_err(ValidationError::Decode)?;
                validate_cotl(&cotl, now_epoch_secs)?;
                cotls.push(cotl);
            }
            ConciseTagChoice::Coswid(coswid_bytes) => {
                // Try structured decode; fall back to opaque count
                match cbor::decode::<ConciseSwidTag>(coswid_bytes) {
                    Ok(coswid) => {
                        coswid.valid().map_err(ValidationError::Invalid)?;
                        coswids.push(coswid);
                    }
                    Err(_) => coswid_opaque_count += 1,
                }
            }
            ConciseTagChoice::BareBstr(bytes) => {
                // TCG-style interop: producers (e.g. NVIDIA) emit `tags[]`
                // entries as bare `bstr` whose contents are either a
                // `#6.506`-wrapped CoMID or a bare CoMID map. Use the
                // tag-tolerant compat decoder; failure here is fatal because
                // we have no other interpretation for a bare bstr in this
                // position.
                let comid = crate::compat::decode_comid_from_tcg_bstr(bytes)
                    .map_err(ValidationError::Decode)?;
                validate_comid(&comid)?;
                comids.push(comid);
            }
            _ => {
                // Unknown tag types: forward-compat, skip silently
            }
        }
    }

    if comids.is_empty() {
        return Err(ValidationError::NoComidTags);
    }

    Ok(ValidatedCorim {
        corim,
        comids,
        cotls,
        coswids,
        coswid_opaque_count,
    })
}

// ---------------------------------------------------------------------------
// Phase 3: Reference value matching (§9.3.3)
// ---------------------------------------------------------------------------

/// A claim that has been corroborated by reference value matching.
#[derive(Clone, Debug)]
pub struct CorroboratedClaim {
    /// The environment that was matched.
    pub environment: EnvironmentMap,
    /// The measurement(s) that matched.
    pub measurements: Vec<MeasurementMap>,
}

/// Match reference values against evidence digests.
///
/// For each `ReferenceTriple`, compares the environment and digests per
/// §9.4.2 (environment) and §9.4.6.1.3 (digests):
/// - Absent condition field = wildcard
/// - All common algorithms must agree
pub fn match_reference_values(
    ref_triples: &[ReferenceTriple],
    evidence: &[EvidenceClaim],
) -> Vec<CorroboratedClaim> {
    let mut corroborated = Vec::new();

    for triple in ref_triples {
        for ev in evidence {
            if !environment_matches(triple.environment(), &ev.environment) {
                continue;
            }

            let mut matched_measurements = Vec::new();
            for ref_meas in triple.measurements() {
                if measurement_matches(ref_meas, &ev.measurements) {
                    matched_measurements.push(ref_meas.clone());
                }
            }

            if !matched_measurements.is_empty() {
                corroborated.push(CorroboratedClaim {
                    environment: triple.environment().clone(),
                    measurements: matched_measurements,
                });
            }
        }
    }

    corroborated
}

/// An evidence claim (from the attestation report).
#[derive(Clone, Debug)]
pub struct EvidenceClaim {
    /// The environment this evidence belongs to.
    pub environment: EnvironmentMap,
    /// The measurements reported in evidence.
    pub measurements: Vec<MeasurementMap>,
}

/// Like [`match_reference_values`] but consults a profile's
/// [`Profile::match_measurement`] hook for each candidate
/// (reference, evidence) measurement pair before falling back to the
/// crate's default exact-match logic.
///
/// Per-pair semantics:
/// - `Some(true)` from the profile — the pair is treated as matching
///   even if core fields would disagree.
/// - `Some(false)` from the profile — the pair is treated as not
///   matching even if core fields would agree.
/// - `None` from the profile — defer to the default per-pair logic
///   (the same comparison performed by [`match_reference_values`]).
///
/// The profile is consulted independently for each (reference, evidence)
/// pair within a triple. Pass `None` for `profile` to get behavior
/// identical to [`match_reference_values`].
///
/// Profile lookup is the caller's responsibility:
///
/// ```ignore
/// let profile = registry.get(corim.profile.as_ref()?);
/// let ctx = MatchContext::system_now();
/// let claims = match_reference_values_with_profile(&triples, &evidence, profile, &ctx);
/// ```
///
/// The `P: ?Sized + Profile` bound lets callers pass any of:
/// `&dyn Profile`, `&(dyn Profile + Send + Sync)` (e.g. from
/// [`crate::profile::ProfileRegistry::get`]), or `&SomeConcreteProfile`.
/// When passing `None`, the type must be annotated:
/// `None::<&dyn Profile>`.
pub fn match_reference_values_with_profile<P: ?Sized + Profile>(
    ref_triples: &[ReferenceTriple],
    evidence: &[EvidenceClaim],
    profile: Option<&P>,
    ctx: &MatchContext,
) -> Vec<CorroboratedClaim> {
    let mut corroborated = Vec::new();

    for triple in ref_triples {
        for ev in evidence {
            if !environment_matches(triple.environment(), &ev.environment) {
                continue;
            }

            let mut matched_measurements = Vec::new();
            for ref_meas in triple.measurements() {
                if measurement_matches_with_profile(ref_meas, &ev.measurements, profile, ctx) {
                    matched_measurements.push(ref_meas.clone());
                }
            }

            if !matched_measurements.is_empty() {
                corroborated.push(CorroboratedClaim {
                    environment: triple.environment().clone(),
                    measurements: matched_measurements,
                });
            }
        }
    }

    corroborated
}

/// Profile-aware analogue of [`measurement_matches`]: for each evidence
/// entry, asks the profile first; on `None`, falls back to
/// [`single_measurement_matches`].
fn measurement_matches_with_profile<P: ?Sized + Profile>(
    reference: &MeasurementMap,
    evidence: &[MeasurementMap],
    profile: Option<&P>,
    ctx: &MatchContext,
) -> bool {
    evidence.iter().any(
        |ev| match profile.and_then(|p| p.match_measurement(reference, ev, ctx)) {
            Some(verdict) => verdict,
            None => single_measurement_matches(reference, ev),
        },
    )
}

// ---------------------------------------------------------------------------
// Phase 4: Conditional endorsement series (§9.3.4.3)
// ---------------------------------------------------------------------------

/// An endorsed claim produced by conditional endorsement series matching.
#[derive(Clone, Debug)]
pub struct EndorsedClaim {
    /// The environment that was matched.
    pub environment: EnvironmentMap,
    /// The endorsement values that were applied.
    pub endorsements: Vec<MeasurementMap>,
}

/// Apply conditional-endorsement-series triples to produce endorsed claims.
///
/// Per §9.3.4.3:
/// 1. Match condition environment against provided evidence
/// 2. Iterate series in order — first `selection` match wins
/// 3. Apply the corresponding `addition` as endorsed values
pub fn apply_endorsement_series(
    ces_triples: &[ConditionalEndorsementSeriesTriple],
    evidence: &[EvidenceClaim],
) -> Result<Vec<EndorsedClaim>, ValidationError> {
    apply_endorsement_series_with_profile::<dyn Profile>(
        ces_triples,
        evidence,
        None,
        &MatchContext::new(),
    )
}

/// Like [`apply_endorsement_series`] but consults a profile's
/// [`Profile::match_measurement`] hook when comparing each series
/// `selection` entry against evidence. Per-pair semantics are identical
/// to those of [`match_reference_values_with_profile`].
///
/// Pass `None::<&dyn Profile>` for `profile` to get behavior identical
/// to [`apply_endorsement_series`].
pub fn apply_endorsement_series_with_profile<P: ?Sized + Profile>(
    ces_triples: &[ConditionalEndorsementSeriesTriple],
    evidence: &[EvidenceClaim],
    profile: Option<&P>,
    ctx: &MatchContext,
) -> Result<Vec<EndorsedClaim>, ValidationError> {
    let mut endorsed = Vec::new();

    for triple in ces_triples {
        let condition = triple.condition();

        let matching_evidence: Vec<_> = evidence
            .iter()
            .filter(|ev| environment_matches(&condition.environment, &ev.environment))
            .collect();

        if matching_evidence.is_empty() {
            continue;
        }

        validate_series_mkeys(triple.series())?;

        for ev in &matching_evidence {
            if let Some(addition) =
                find_matching_series(triple.series(), &ev.measurements, profile, ctx)
            {
                endorsed.push(EndorsedClaim {
                    environment: condition.environment.clone(),
                    endorsements: addition,
                });
            }
        }
    }

    Ok(endorsed)
}

/// Validate that all series entries use the same `mkey`s (§5.1.8.1.1).
///
/// Comparison is set-based (order-independent) to handle producers that
/// may reorder measurement-map entries within a series record.
fn validate_series_mkeys(series: &[ConditionalSeriesRecord]) -> Result<(), ValidationError> {
    if series.len() <= 1 {
        return Ok(());
    }

    let collect_mkeys = |record: &ConditionalSeriesRecord| -> Vec<String> {
        let mut keys: Vec<String> = record
            .selection()
            .iter()
            .map(|m| format!("{:?}", m.mkey))
            .collect();
        keys.sort();
        keys
    };

    let first_mkeys = collect_mkeys(&series[0]);

    for record in &series[1..] {
        if collect_mkeys(record) != first_mkeys {
            return Err(ValidationError::InconsistentMkeys);
        }
    }

    Ok(())
}

/// Find the first matching series entry and return its addition.
///
/// When `profile` is `Some`, each `selection` entry is compared via
/// [`measurement_matches_with_profile`]; otherwise the default
/// [`measurement_matches`] is used.
fn find_matching_series<P: ?Sized + Profile>(
    series: &[ConditionalSeriesRecord],
    evidence_measurements: &[MeasurementMap],
    profile: Option<&P>,
    ctx: &MatchContext,
) -> Option<Vec<MeasurementMap>> {
    for record in series {
        let all_match = record.selection().iter().all(|sel| match profile {
            Some(_) => measurement_matches_with_profile(sel, evidence_measurements, profile, ctx),
            None => measurement_matches(sel, evidence_measurements),
        });

        if all_match {
            return Some(record.addition().to_vec());
        }
    }
    None
}

// ---------------------------------------------------------------------------
// SVN comparison (§9.4.6.1.2)
// ---------------------------------------------------------------------------

/// Compare an SVN value against evidence.
///
/// - `ExactValue(n)`: evidence SVN must equal `n`
/// - `MinValue(n)`: evidence SVN must be `>= n`
pub fn svn_matches(reference: &SvnChoice, evidence_svn: u64) -> bool {
    match reference {
        SvnChoice::ExactValue(n) => evidence_svn == *n,
        SvnChoice::MinValue(n) => evidence_svn >= *n,
    }
}

// ---------------------------------------------------------------------------
// Comparison helpers (§9.4)
// ---------------------------------------------------------------------------

/// Compare two environments per §9.4.2.
///
/// Absent fields in the condition are wildcards.
fn environment_matches(condition: &EnvironmentMap, target: &EnvironmentMap) -> bool {
    if let Some(ref cond_class) = condition.class {
        match &target.class {
            None => return false,
            Some(tgt_class) => {
                if !class_matches(cond_class, tgt_class) {
                    return false;
                }
            }
        }
    }

    if condition.instance.is_some() && condition.instance != target.instance {
        return false;
    }

    if condition.group.is_some() && condition.group != target.group {
        return false;
    }

    true
}

/// Compare two class-maps. Absent condition fields are wildcards.
fn class_matches(
    condition: &crate::types::environment::ClassMap,
    target: &crate::types::environment::ClassMap,
) -> bool {
    if condition.class_id.is_some() && condition.class_id != target.class_id {
        return false;
    }
    if condition.vendor.is_some() && condition.vendor != target.vendor {
        return false;
    }
    if condition.model.is_some() && condition.model != target.model {
        return false;
    }
    if condition.layer.is_some() && condition.layer != target.layer {
        return false;
    }
    if condition.index.is_some() && condition.index != target.index {
        return false;
    }
    true
}

/// Check if a reference measurement matches any evidence measurement.
///
/// Matching is per §9.4.6: compares `mkey`, and then for each field in
/// `measurement-values-map`, if the reference specifies the field, the
/// evidence must also have it and the values must match.
///
/// Covered codepoints:
/// - `digests` (key 2) — §9.4.6.1.3, per-algorithm comparison
/// - `svn` (key 1) — §9.4.6.1.2, exact or minimum
/// - `version` (key 0) — exact match
/// - `flags` (key 3) — exact match
/// - `raw-value` (key 4) — exact match
/// - `mac-addr` (key 6) — exact match
/// - `ip-addr` (key 7) — exact match
/// - `serial-number` (key 8) — exact match
/// - `ueid` (key 9) — exact match
/// - `uuid` (key 10) — exact match
/// - `name` (key 11) — exact match
/// - `integrity-registers` (key 14) — exact match
/// - `int-range` (key 15) — exact match
///
/// Note: `cryptokeys` (key 13) is not compared — it carries authorized
/// keys, not a measurement value to match against evidence. Profile-defined
/// extension entries in [`MeasurementValuesMap::extra_entries`][crate::types::measurement::MeasurementValuesMap::extra_entries]
/// are not compared by this function; profile-aware matching is provided
/// by [`match_reference_values_with_profile`].
fn measurement_matches(reference: &MeasurementMap, evidence: &[MeasurementMap]) -> bool {
    evidence
        .iter()
        .any(|ev| single_measurement_matches(reference, ev))
}

/// Per-pair core matching primitive: tests whether a single reference
/// measurement matches a single evidence measurement under the crate's
/// default exact-match semantics. Used by both the loop in
/// [`measurement_matches`] and by the profile-aware fallback path in
/// [`measurement_matches_with_profile`].
///
/// Public companion: [`core_fields_match`] (same logic, stable name for
/// out-of-crate [`Profile`][crate::profile::Profile] implementations).
fn single_measurement_matches(reference: &MeasurementMap, ev_meas: &MeasurementMap) -> bool {
    // Match mkey if specified in reference
    if let Some(ref ref_mkey) = reference.mkey {
        match &ev_meas.mkey {
            Some(ev_mkey) if ev_mkey == ref_mkey => {}
            _ => return false,
        }
    }

    // Match digests if present in reference (§9.4.6.1.3)
    if let Some(ref ref_digests) = reference.mval.digests {
        if let Some(ref ev_digests) = ev_meas.mval.digests {
            if !digests_match(ref_digests, ev_digests) {
                return false;
            }
        } else {
            return false;
        }
    }

    // Match SVN if present in reference (§9.4.6.1.2)
    if let Some(ref ref_svn) = reference.mval.svn {
        if let Some(ref ev_svn) = ev_meas.mval.svn {
            let ev_val = match ev_svn {
                SvnChoice::ExactValue(n) | SvnChoice::MinValue(n) => *n,
            };
            if !svn_matches(ref_svn, ev_val) {
                return false;
            }
        } else {
            return false;
        }
    }

    // Match version if present in reference
    if reference.mval.version.is_some() && reference.mval.version != ev_meas.mval.version {
        return false;
    }

    // Match flags if present in reference
    if reference.mval.flags.is_some() && reference.mval.flags != ev_meas.mval.flags {
        return false;
    }

    // Match raw-value if present in reference
    if reference.mval.raw_value.is_some() && reference.mval.raw_value != ev_meas.mval.raw_value {
        return false;
    }

    // Match mac-addr if present in reference
    if reference.mval.mac_addr.is_some() && reference.mval.mac_addr != ev_meas.mval.mac_addr {
        return false;
    }

    // Match ip-addr if present in reference
    if reference.mval.ip_addr.is_some() && reference.mval.ip_addr != ev_meas.mval.ip_addr {
        return false;
    }

    // Match serial-number if present in reference
    if reference.mval.serial_number.is_some()
        && reference.mval.serial_number != ev_meas.mval.serial_number
    {
        return false;
    }

    // Match ueid if present in reference
    if reference.mval.ueid.is_some() && reference.mval.ueid != ev_meas.mval.ueid {
        return false;
    }

    // Match uuid if present in reference
    if reference.mval.uuid.is_some() && reference.mval.uuid != ev_meas.mval.uuid {
        return false;
    }

    // Match name if present in reference
    if reference.mval.name.is_some() && reference.mval.name != ev_meas.mval.name {
        return false;
    }

    // Match integrity-registers if present in reference
    if reference.mval.integrity_registers.is_some()
        && reference.mval.integrity_registers != ev_meas.mval.integrity_registers
    {
        return false;
    }

    // Match int-range if present in reference
    if reference.mval.int_range.is_some() && reference.mval.int_range != ev_meas.mval.int_range {
        return false;
    }

    true
}

/// Tests whether a reference measurement's core (non-extension) fields
/// agree with an evidence measurement under the crate's default
/// exact-match semantics.
///
/// This is the stable public entry point for the per-pair comparison
/// performed internally by [`match_reference_values`]. It is intended for
/// out-of-crate [`Profile`] implementations that
/// own the extension keys (the negative-integer range in
/// [`MeasurementValuesMap::extra_entries`][crate::types::measurement::MeasurementValuesMap::extra_entries])
/// but want to delegate the structural fields (`mkey`, `digests`, `svn`,
/// `version`, `name`, `flags`, `raw-value`, `mac-addr`, `ip-addr`,
/// `serial-number`, `ueid`, `uuid`, `integrity-registers`, `int-range`)
/// to the crate's default matcher.
///
/// Note: this function does NOT inspect
/// [`MeasurementValuesMap::extra_entries`][crate::types::measurement::MeasurementValuesMap::extra_entries].
/// Profile-aware comparison of extension keys is the caller's
/// responsibility — typically inside a
/// [`Profile::match_measurement`]
/// impl that AND-combines its extension verdict with the result of this
/// function.
pub fn core_fields_match(reference: &MeasurementMap, evidence: &MeasurementMap) -> bool {
    single_measurement_matches(reference, evidence)
}

/// Compare digest lists per §9.4.6.1.3.
fn digests_match(reference: &[Digest], evidence: &[Digest]) -> bool {
    let mut has_common = false;

    for ref_d in reference {
        for ev_d in evidence {
            if ref_d.alg() == ev_d.alg() {
                has_common = true;
                if ref_d.value() != ev_d.value() {
                    return false;
                }
            }
        }
    }

    has_common
}

// ---------------------------------------------------------------------------
// Appraisal context
// ---------------------------------------------------------------------------

/// The type of a claim in the Appraisal Context Set.
#[derive(Clone, Debug, PartialEq)]
pub enum ClaimType {
    /// Claim from attestation evidence.
    Evidence,
    /// Claim corroborated by reference values (Phase 3).
    ReferenceValues,
    /// Claim endorsed by endorsement triples (Phase 4).
    Endorsement,
}

/// An entry in the Appraisal Context Set (ACS).
#[derive(Clone, Debug)]
pub struct EnvironmentClaimTuple {
    /// The environment this claim is about.
    pub environment: EnvironmentMap,
    /// The measurements/endorsements.
    pub measurements: Vec<MeasurementMap>,
    /// The claim type.
    pub claim_type: ClaimType,
}

/// The Appraisal Context Set — accumulates claims across appraisal phases.
#[derive(Clone, Debug, Default)]
pub struct AppraisalContext {
    /// All claim entries.
    pub entries: Vec<EnvironmentClaimTuple>,
}

impl AppraisalContext {
    /// Create a new empty appraisal context.
    pub fn new() -> Self {
        Self::default()
    }

    /// Initialize with evidence claims (Phase 2).
    pub fn add_evidence(&mut self, claims: Vec<EvidenceClaim>) {
        for claim in claims {
            self.entries.push(EnvironmentClaimTuple {
                environment: claim.environment,
                measurements: claim.measurements,
                claim_type: ClaimType::Evidence,
            });
        }
    }

    /// Apply reference value matching (Phase 3).
    pub fn apply_reference_values(
        &mut self,
        ref_triples: &[ReferenceTriple],
    ) -> Vec<CorroboratedClaim> {
        let evidence: Vec<EvidenceClaim> = self
            .entries
            .iter()
            .filter(|e| e.claim_type == ClaimType::Evidence)
            .map(|e| EvidenceClaim {
                environment: e.environment.clone(),
                measurements: e.measurements.clone(),
            })
            .collect();

        let corroborated = match_reference_values(ref_triples, &evidence);

        for claim in &corroborated {
            self.entries.push(EnvironmentClaimTuple {
                environment: claim.environment.clone(),
                measurements: claim.measurements.clone(),
                claim_type: ClaimType::ReferenceValues,
            });
        }

        corroborated
    }

    /// Apply conditional endorsement series (Phase 4).
    pub fn apply_conditional_endorsements(
        &mut self,
        ces_triples: &[ConditionalEndorsementSeriesTriple],
    ) -> Result<Vec<EndorsedClaim>, ValidationError> {
        let evidence: Vec<EvidenceClaim> = self
            .entries
            .iter()
            .map(|e| EvidenceClaim {
                environment: e.environment.clone(),
                measurements: e.measurements.clone(),
            })
            .collect();

        let endorsed = apply_endorsement_series(ces_triples, &evidence)?;

        for claim in &endorsed {
            self.entries.push(EnvironmentClaimTuple {
                environment: claim.environment.clone(),
                measurements: claim.endorsements.clone(),
                claim_type: ClaimType::Endorsement,
            });
        }

        Ok(endorsed)
    }
}
