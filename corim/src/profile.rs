// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Profile extension framework for CoRIM.
//!
//! CoRIM is intentionally extensible via the `corim-map.profile` field
//! (§4.1.4 of draft-ietf-rats-corim-10) — a URI or OID that names a
//! profile defining additional measurement-values keys, expression
//! tags, appraisal semantics, and media-type discriminators. Examples
//! include the in-progress Intel profile
//! (`draft-cds-rats-intel-corim-profile`, OID
//! `2.16.840.1.113741.1.16.1`).
//!
//! The `corim` core crate is profile-agnostic: it preserves
//! profile-defined keys verbatim via the
//! [`MeasurementValuesMap::extra_entries`][crate::types::measurement::MeasurementValuesMap::extra_entries]
//! field but does **not** interpret or appraise them. Profile-aware
//! semantics live in separate crates that implement the [`Profile`]
//! trait and register an instance with a [`ProfileRegistry`]. The
//! registry is then passed to the validate/diagnose entry points that
//! accept it.
//!
//! # Example
//!
//! A minimal no-op profile that recognizes its identifier but defers
//! all behavior to defaults:
//!
//! ```rust
//! use corim::profile::{Profile, ProfileRegistry};
//! use corim::types::corim::ProfileChoice;
//!
//! struct ExampleProfile {
//!     id: ProfileChoice,
//! }
//! impl Profile for ExampleProfile {
//!     fn identifier(&self) -> &ProfileChoice { &self.id }
//! }
//!
//! let profile = ExampleProfile {
//!     id: ProfileChoice::Uri("urn:example:profile".into()),
//! };
//! let mut registry = ProfileRegistry::new();
//! registry.register(Box::new(profile));
//! assert_eq!(registry.len(), 1);
//! ```

#[allow(unused_imports)]
use crate::nostd_prelude::*;

use crate::cbor::value::Value;
use crate::types::corim::ProfileChoice;
use crate::types::measurement::MeasurementMap;

/// Trait implemented by profile crates to teach `corim` about a CoRIM
/// profile's extension semantics.
///
/// All non-identifier methods carry default no-op implementations so
/// implementers only need to define the methods they actually want to
/// override. A profile that only wants to provide pretty-printing in
/// `--diagnose` output, for example, needs only to override
/// [`Profile::diagnose_mval_entry`].
///
/// Implementations are typically registered with a [`ProfileRegistry`]
/// and looked up at validate/diagnose time by matching the manifest's
/// `corim-map.profile` field against [`Profile::identifier`].
pub trait Profile {
    /// The profile identifier this implementation handles.
    ///
    /// Must be stable across calls (the registry uses it as a map key).
    fn identifier(&self) -> &ProfileChoice;

    /// Profile-aware measurement matching for appraisal.
    ///
    /// Called by [`crate::validate`] when the manifest's `profile` field
    /// matches this profile's [`Profile::identifier`]. Return `Some(true)`
    /// if the reference value matches the evidence under profile-defined
    /// semantics (e.g. operator-based comparison via tag `#6.60010`),
    /// `Some(false)` if it explicitly does not match, or `None` to defer
    /// to the crate's default exact-match logic.
    fn match_measurement(
        &self,
        _reference: &MeasurementMap,
        _evidence: &MeasurementMap,
    ) -> Option<bool> {
        None
    }

    /// Render an `extra_entries` key/value pair for `--diagnose` output.
    ///
    /// Called by the diagnose walker when it encounters a profile-defined
    /// integer key in [`MeasurementValuesMap::extra_entries`][crate::types::measurement::MeasurementValuesMap::extra_entries].
    /// Return a human-readable description (e.g. `"tee.mrtee = <digest>"`)
    /// or `None` to fall back to the generic `"extension key {n}"` rendering.
    fn diagnose_mval_entry(&self, _key: i64, _value: &Value) -> Option<String> {
        None
    }
}

/// Type alias for owned, thread-safe boxed profiles stored in a
/// [`ProfileRegistry`]. Requires implementations to be `Send + Sync`
/// so registries can be shared across threads via `Arc<ProfileRegistry>`.
pub type BoxedProfile = Box<dyn Profile + Send + Sync>;

/// Owns a set of [`Profile`] implementations keyed by [`ProfileChoice`].
///
/// Construct once at application startup, register every profile the
/// application needs to understand, and pass the registry by reference
/// to validate/diagnose entry points that accept it. A registry with
/// no entries is functionally equivalent to passing no registry at all.
#[derive(Default)]
pub struct ProfileRegistry {
    profiles: BTreeMap<ProfileChoice, BoxedProfile>,
}

impl ProfileRegistry {
    /// Create an empty registry.
    pub fn new() -> Self {
        Self::default()
    }

    /// Register a profile. If a profile with the same identifier was
    /// previously registered, it is replaced and the old value returned.
    pub fn register(&mut self, profile: BoxedProfile) -> Option<BoxedProfile> {
        let id = profile.identifier().clone();
        self.profiles.insert(id, profile)
    }

    /// Look up a profile by its identifier. Returns `None` if no profile
    /// with that identifier has been registered.
    pub fn get(&self, id: &ProfileChoice) -> Option<&(dyn Profile + Send + Sync)> {
        self.profiles.get(id).map(|b| b.as_ref())
    }

    /// Number of registered profiles.
    pub fn len(&self) -> usize {
        self.profiles.len()
    }

    /// Whether the registry has no registered profiles.
    pub fn is_empty(&self) -> bool {
        self.profiles.is_empty()
    }

    /// Iterate over registered `(identifier, profile)` pairs.
    pub fn iter(&self) -> impl Iterator<Item = (&ProfileChoice, &(dyn Profile + Send + Sync))> {
        self.profiles.iter().map(|(k, v)| (k, v.as_ref()))
    }
}

impl core::fmt::Debug for ProfileRegistry {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("ProfileRegistry")
            .field("profiles", &self.profiles.keys().collect::<Vec<_>>())
            .finish()
    }
}
