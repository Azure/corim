// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Tests for the [`corim::profile`] registry and trait.
//!
//! Exercises only the framework mechanics: registration, lookup, default
//! method bodies, and `Send + Sync` shareability. Profile-specific
//! semantics are tested in their respective profile crates.

use corim::cbor::value::Value;
use corim::profile::{Profile, ProfileRegistry};
use corim::types::common::MeasuredElement;
use corim::types::corim::ProfileChoice;
use corim::types::measurement::{MeasurementMap, MeasurementValuesMap, SvnChoice};

/// Minimal `Profile` impl that overrides nothing beyond `identifier`.
struct NullProfile {
    id: ProfileChoice,
}

impl Profile for NullProfile {
    fn identifier(&self) -> &ProfileChoice {
        &self.id
    }
}

#[test]
fn registry_register_and_lookup() {
    let id = ProfileChoice::Uri("urn:example:test".into());
    let mut registry = ProfileRegistry::new();
    assert!(registry.is_empty());
    assert_eq!(registry.len(), 0);

    registry.register(Box::new(NullProfile { id: id.clone() }));
    assert_eq!(registry.len(), 1);
    assert!(!registry.is_empty());

    let looked_up = registry
        .get(&id)
        .expect("registered profile must be findable");
    assert_eq!(looked_up.identifier(), &id);

    // Unknown identifier returns None.
    let other = ProfileChoice::Uri("urn:example:other".into());
    assert!(registry.get(&other).is_none());
}

#[test]
fn registry_re_register_replaces() {
    let id = ProfileChoice::Oid(vec![0x60, 0x86, 0x48, 0x01]);
    let mut registry = ProfileRegistry::new();
    let prev = registry.register(Box::new(NullProfile { id: id.clone() }));
    assert!(prev.is_none(), "first registration returns None");

    let prev = registry.register(Box::new(NullProfile { id: id.clone() }));
    assert!(
        prev.is_some(),
        "re-registration returns the displaced profile"
    );
    assert_eq!(registry.len(), 1);
}

#[test]
fn default_match_measurement_returns_none() {
    let id = ProfileChoice::Uri("urn:example:default".into());
    let profile = NullProfile { id };
    let mval = MeasurementValuesMap {
        svn: Some(SvnChoice::ExactValue(1)),
        ..MeasurementValuesMap::default()
    };
    let meas = MeasurementMap {
        mkey: Some(MeasuredElement::Uint(0)),
        mval,
        authorized_by: None,
    };
    // Default impl defers to crate-level matching by returning None.
    assert_eq!(
        profile.match_measurement(&meas, &meas, &corim::profile::MatchContext::new()),
        None
    );
}

#[test]
fn default_diagnose_mval_entry_returns_none() {
    let id = ProfileChoice::Uri("urn:example:default".into());
    let profile = NullProfile { id };
    let value = Value::Integer(42);
    assert!(profile.diagnose_mval_entry(-83, &value).is_none());
}

#[test]
fn registry_iter_visits_all_profiles() {
    let mut registry = ProfileRegistry::new();
    registry.register(Box::new(NullProfile {
        id: ProfileChoice::Uri("urn:a".into()),
    }));
    registry.register(Box::new(NullProfile {
        id: ProfileChoice::Uri("urn:b".into()),
    }));

    let collected: Vec<_> = registry.iter().map(|(id, _)| id.clone()).collect();
    assert_eq!(collected.len(), 2);
    assert!(collected.contains(&ProfileChoice::Uri("urn:a".into())));
    assert!(collected.contains(&ProfileChoice::Uri("urn:b".into())));
}

/// Demonstrates a profile that overrides `match_measurement` with
/// custom semantics. Used here to verify the override mechanism, not to
/// claim any particular appraisal logic.
#[test]
fn custom_profile_can_override_match() {
    struct AlwaysMatchProfile {
        id: ProfileChoice,
    }
    impl Profile for AlwaysMatchProfile {
        fn identifier(&self) -> &ProfileChoice {
            &self.id
        }
        fn match_measurement(
            &self,
            _r: &MeasurementMap,
            _e: &MeasurementMap,
            _ctx: &corim::profile::MatchContext,
        ) -> Option<bool> {
            Some(true)
        }
    }

    let profile = AlwaysMatchProfile {
        id: ProfileChoice::Uri("urn:always".into()),
    };
    let meas = MeasurementMap {
        mkey: None,
        mval: MeasurementValuesMap {
            svn: Some(SvnChoice::ExactValue(1)),
            ..MeasurementValuesMap::default()
        },
        authorized_by: None,
    };
    let other = MeasurementMap {
        mkey: None,
        mval: MeasurementValuesMap {
            svn: Some(SvnChoice::ExactValue(99)),
            ..MeasurementValuesMap::default()
        },
        authorized_by: None,
    };
    assert_eq!(
        profile.match_measurement(&meas, &other, &corim::profile::MatchContext::new()),
        Some(true)
    );
}

/// The registry must be `Send + Sync` so callers can wrap it in an
/// `Arc` and share across threads. This test only needs to compile.
#[test]
fn registry_is_send_and_sync() {
    fn assert_send_sync<T: Send + Sync>() {}
    assert_send_sync::<ProfileRegistry>();
}
