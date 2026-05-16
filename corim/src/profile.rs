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
use crate::types::common::CborTime;
use crate::types::corim::ProfileChoice;
use crate::types::measurement::MeasurementMap;

// ---------------------------------------------------------------------------
// MatchContext
// ---------------------------------------------------------------------------

/// Per-call context threaded through profile-aware matching.
///
/// Built once per appraisal call by the verifier and passed by reference
/// into [`Profile::match_measurement`] (and from there into the
/// profile-aware variants of the [`crate::validate`] entry points). The
/// caller is the source of truth for verifier-side state that the
/// profile may need but should not own — currently just
/// verifier-current-time for epoch-based reference values.
///
/// Construct with [`MatchContext::new`] (empty) or, with the `std`
/// feature, [`MatchContext::system_now`] (clock from
/// `std::time::SystemTime`). Chain [`MatchContext::with_now`] to set
/// the clock explicitly.
///
/// Designed to grow: future fields (nonce, evidence-source-class, etc.)
/// can be added without breaking the trait signature again — hence
/// `#[non_exhaustive]`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct MatchContext {
    /// Verifier-current-time, as CBOR epoch seconds. `None` means "no
    /// clock available"; profiles that need a clock should fall back to
    /// `Skip`-equivalent behaviour (return `None` from
    /// [`Profile::match_measurement`] for that key) when this is `None`.
    pub now: Option<CborTime>,
}

impl MatchContext {
    /// Empty context. `now` is `None`; epoch-based reference values
    /// will Skip.
    pub fn new() -> Self {
        Self { now: None }
    }

    /// Set the verifier-current-time. Chainable.
    #[must_use]
    pub fn with_now(mut self, now: CborTime) -> Self {
        self.now = Some(now);
        self
    }

    /// Build a context whose `now` is `SystemTime::now()` expressed as
    /// Unix epoch seconds. Saturates to `i64::MAX` past the year 2262.
    /// Returns an empty context (no clock) on the (impossible) case
    /// where `SystemTime::now()` is before the Unix epoch.
    #[cfg(feature = "std")]
    pub fn system_now() -> Self {
        use std::time::{SystemTime, UNIX_EPOCH};
        match SystemTime::now().duration_since(UNIX_EPOCH) {
            Ok(d) => {
                let secs = i64::try_from(d.as_secs()).unwrap_or(i64::MAX);
                Self {
                    now: Some(CborTime::new(secs)),
                }
            }
            Err(_) => Self::new(),
        }
    }
}

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
    ///
    /// `ctx` carries per-call verifier state (currently just
    /// `now: Option<CborTime>` for epoch-based reference values).
    /// Profiles that don't need any context can ignore the parameter.
    fn match_measurement(
        &self,
        _reference: &MeasurementMap,
        _evidence: &MeasurementMap,
        _ctx: &MatchContext,
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
