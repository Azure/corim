// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Tests for the profile-aware appraisal entry points
//! `match_reference_values_with_profile` and
//! `apply_endorsement_series_with_profile`.

use corim::profile::Profile;
use corim::types::common::MeasuredElement;
use corim::types::corim::ProfileChoice;
use corim::types::environment::EnvironmentMap;
use corim::types::measurement::{Digest, MeasurementMap, MeasurementValuesMap};
use corim::types::triples::{
    CesCondition, ConditionalEndorsementSeriesTriple, ConditionalSeriesRecord, ReferenceTriple,
};
use corim::validate::{
    apply_endorsement_series, apply_endorsement_series_with_profile, match_reference_values,
    match_reference_values_with_profile, EvidenceClaim,
};

// ---------------------------------------------------------------------------
// Test profiles
// ---------------------------------------------------------------------------

/// Profile that always defers to the crate's default matching logic.
struct PassthroughProfile {
    id: ProfileChoice,
}
impl Profile for PassthroughProfile {
    fn identifier(&self) -> &ProfileChoice {
        &self.id
    }
    // match_measurement uses the trait default (returns None)
}

/// Profile that always claims the pair matches.
struct AlwaysMatchProfile {
    id: ProfileChoice,
}
impl Profile for AlwaysMatchProfile {
    fn identifier(&self) -> &ProfileChoice {
        &self.id
    }
    fn match_measurement(
        &self,
        _reference: &MeasurementMap,
        _evidence: &MeasurementMap,
    ) -> Option<bool> {
        Some(true)
    }
}

/// Profile that always claims the pair does NOT match.
struct AlwaysRejectProfile {
    id: ProfileChoice,
}
impl Profile for AlwaysRejectProfile {
    fn identifier(&self) -> &ProfileChoice {
        &self.id
    }
    fn match_measurement(
        &self,
        _reference: &MeasurementMap,
        _evidence: &MeasurementMap,
    ) -> Option<bool> {
        Some(false)
    }
}

fn test_id() -> ProfileChoice {
    ProfileChoice::Uri("urn:example:test-profile".into())
}

// ---------------------------------------------------------------------------
// Fixture helpers
// ---------------------------------------------------------------------------

fn ref_with_digest(byte: u8) -> ReferenceTriple {
    ReferenceTriple::new(
        EnvironmentMap::for_class("ACME", "Widget"),
        vec![MeasurementMap {
            mkey: None,
            mval: MeasurementValuesMap {
                digests: Some(vec![Digest::new(7, vec![byte; 32])]),
                ..MeasurementValuesMap::default()
            },
            authorized_by: None,
        }],
    )
}

fn evidence_with_digest(byte: u8) -> EvidenceClaim {
    EvidenceClaim {
        environment: EnvironmentMap::for_class("ACME", "Widget"),
        measurements: vec![MeasurementMap {
            mkey: None,
            mval: MeasurementValuesMap {
                digests: Some(vec![Digest::new(7, vec![byte; 32])]),
                ..MeasurementValuesMap::default()
            },
            authorized_by: None,
        }],
    }
}

// ---------------------------------------------------------------------------
// match_reference_values_with_profile
// ---------------------------------------------------------------------------

#[test]
fn with_profile_none_matches_default_behavior_on_match() {
    let triples = vec![ref_with_digest(0xAA)];
    let evidence = vec![evidence_with_digest(0xAA)];

    let default = match_reference_values(&triples, &evidence);
    let with_none = match_reference_values_with_profile(&triples, &evidence, None);

    assert_eq!(default.len(), 1);
    assert_eq!(with_none.len(), default.len());
}

#[test]
fn with_profile_none_matches_default_behavior_on_mismatch() {
    let triples = vec![ref_with_digest(0xAA)];
    let evidence = vec![evidence_with_digest(0xBB)];

    let default = match_reference_values(&triples, &evidence);
    let with_none = match_reference_values_with_profile(&triples, &evidence, None);

    assert_eq!(default.len(), 0);
    assert_eq!(with_none.len(), 0);
}

#[test]
fn passthrough_profile_returns_none_so_defers_to_core() {
    let profile = PassthroughProfile { id: test_id() };
    let triples = vec![ref_with_digest(0xAA)];

    let evidence_match = vec![evidence_with_digest(0xAA)];
    let evidence_miss = vec![evidence_with_digest(0xBB)];

    let claims_match =
        match_reference_values_with_profile(&triples, &evidence_match, Some(&profile));
    let claims_miss = match_reference_values_with_profile(&triples, &evidence_miss, Some(&profile));

    assert_eq!(
        claims_match.len(),
        1,
        "passthrough should match when core matches"
    );
    assert_eq!(
        claims_miss.len(),
        0,
        "passthrough should miss when core misses"
    );
}

#[test]
fn always_match_profile_overrides_core_mismatch() {
    let profile = AlwaysMatchProfile { id: test_id() };
    let triples = vec![ref_with_digest(0xAA)];
    let evidence = vec![evidence_with_digest(0xBB)]; // differs from reference

    // Core says no match
    let core_claims = match_reference_values(&triples, &evidence);
    assert_eq!(core_claims.len(), 0);

    // Profile says yes
    let profile_claims = match_reference_values_with_profile(&triples, &evidence, Some(&profile));
    assert_eq!(profile_claims.len(), 1, "AlwaysMatch should force a match");
}

#[test]
fn always_reject_profile_blocks_core_match() {
    let profile = AlwaysRejectProfile { id: test_id() };
    let triples = vec![ref_with_digest(0xAA)];
    let evidence = vec![evidence_with_digest(0xAA)]; // would match

    // Core says match
    let core_claims = match_reference_values(&triples, &evidence);
    assert_eq!(core_claims.len(), 1);

    // Profile says no
    let profile_claims = match_reference_values_with_profile(&triples, &evidence, Some(&profile));
    assert_eq!(
        profile_claims.len(),
        0,
        "AlwaysReject should block the match"
    );
}

#[test]
fn empty_triples_with_profile_yields_empty() {
    let profile = AlwaysMatchProfile { id: test_id() };
    let evidence = vec![evidence_with_digest(0xAA)];

    let claims = match_reference_values_with_profile(&[], &evidence, Some(&profile));
    assert!(claims.is_empty());
}

#[test]
fn environment_mismatch_skipped_before_profile_consulted() {
    // Profile should never be asked about pairs whose environments don't match
    // (the core environment-match gate runs first).
    let profile = AlwaysMatchProfile { id: test_id() };
    let triples = vec![ReferenceTriple::new(
        EnvironmentMap::for_class("ACME", "Widget"),
        vec![MeasurementMap {
            mkey: None,
            mval: MeasurementValuesMap {
                digests: Some(vec![Digest::new(7, vec![0xAA; 32])]),
                ..MeasurementValuesMap::default()
            },
            authorized_by: None,
        }],
    )];
    let evidence = vec![EvidenceClaim {
        environment: EnvironmentMap::for_class("OTHER", "Thing"),
        measurements: vec![MeasurementMap {
            mkey: None,
            mval: MeasurementValuesMap {
                digests: Some(vec![Digest::new(7, vec![0xAA; 32])]),
                ..MeasurementValuesMap::default()
            },
            authorized_by: None,
        }],
    }];

    let claims = match_reference_values_with_profile(&triples, &evidence, Some(&profile));
    assert!(
        claims.is_empty(),
        "environment mismatch should still gate the match"
    );
}

// ---------------------------------------------------------------------------
// apply_endorsement_series_with_profile
// ---------------------------------------------------------------------------

fn build_series_triple(
    selection_byte: u8,
    addition_byte: u8,
) -> ConditionalEndorsementSeriesTriple {
    let condition = CesCondition {
        environment: EnvironmentMap::for_class("ACME", "Widget"),
        claims_list: Vec::new(),
        authorized_by: None,
    };
    let selection = vec![MeasurementMap {
        mkey: Some(MeasuredElement::Text("k".into())),
        mval: MeasurementValuesMap {
            digests: Some(vec![Digest::new(7, vec![selection_byte; 32])]),
            ..MeasurementValuesMap::default()
        },
        authorized_by: None,
    }];
    let addition = vec![MeasurementMap {
        mkey: Some(MeasuredElement::Text("k".into())),
        mval: MeasurementValuesMap {
            digests: Some(vec![Digest::new(7, vec![addition_byte; 32])]),
            ..MeasurementValuesMap::default()
        },
        authorized_by: None,
    }];
    let record = ConditionalSeriesRecord::new(selection, addition);
    ConditionalEndorsementSeriesTriple::new(condition, vec![record])
}

#[test]
fn endorsement_series_with_profile_none_matches_default() {
    let triples = vec![build_series_triple(0xAA, 0xCC)];
    let evidence = vec![EvidenceClaim {
        environment: EnvironmentMap::for_class("ACME", "Widget"),
        measurements: vec![MeasurementMap {
            mkey: Some(MeasuredElement::Text("k".into())),
            mval: MeasurementValuesMap {
                digests: Some(vec![Digest::new(7, vec![0xAA; 32])]),
                ..MeasurementValuesMap::default()
            },
            authorized_by: None,
        }],
    }];

    let default = apply_endorsement_series(&triples, &evidence).unwrap();
    let with_none = apply_endorsement_series_with_profile(&triples, &evidence, None).unwrap();

    assert_eq!(default.len(), 1);
    assert_eq!(with_none.len(), default.len());
}

#[test]
fn endorsement_series_always_match_profile_forces_endorsement() {
    let profile = AlwaysMatchProfile { id: test_id() };
    let triples = vec![build_series_triple(0xAA, 0xCC)];
    // Evidence digest differs from selection — core would not endorse.
    let evidence = vec![EvidenceClaim {
        environment: EnvironmentMap::for_class("ACME", "Widget"),
        measurements: vec![MeasurementMap {
            mkey: Some(MeasuredElement::Text("k".into())),
            mval: MeasurementValuesMap {
                digests: Some(vec![Digest::new(7, vec![0xBB; 32])]),
                ..MeasurementValuesMap::default()
            },
            authorized_by: None,
        }],
    }];

    let core = apply_endorsement_series(&triples, &evidence).unwrap();
    assert_eq!(core.len(), 0, "core should not endorse");

    let with_profile =
        apply_endorsement_series_with_profile(&triples, &evidence, Some(&profile)).unwrap();
    assert_eq!(with_profile.len(), 1, "profile should force endorsement");
}

#[test]
fn endorsement_series_always_reject_profile_blocks_endorsement() {
    let profile = AlwaysRejectProfile { id: test_id() };
    let triples = vec![build_series_triple(0xAA, 0xCC)];
    // Evidence matches selection — core would endorse.
    let evidence = vec![EvidenceClaim {
        environment: EnvironmentMap::for_class("ACME", "Widget"),
        measurements: vec![MeasurementMap {
            mkey: Some(MeasuredElement::Text("k".into())),
            mval: MeasurementValuesMap {
                digests: Some(vec![Digest::new(7, vec![0xAA; 32])]),
                ..MeasurementValuesMap::default()
            },
            authorized_by: None,
        }],
    }];

    let core = apply_endorsement_series(&triples, &evidence).unwrap();
    assert_eq!(core.len(), 1, "core should endorse");

    let with_profile =
        apply_endorsement_series_with_profile(&triples, &evidence, Some(&profile)).unwrap();
    assert_eq!(with_profile.len(), 0, "profile should block endorsement");
}
