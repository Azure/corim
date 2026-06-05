// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Builder API for CoRIM and CoMID generation.
//!
//! Provides a fluent interface for constructing CoRIM and CoMID structures
//! per draft-ietf-rats-corim-10.
//!
//! # Cross-triple anchoring (opt-in)
//!
//! By default, [`ComidBuilder`] performs no cross-triple checks: any
//! `EnvironmentMap` may appear in any triple, even if no reference-triple
//! "characterises" it first. The wire format imposes no such constraint
//! and verifiers handle mismatches at appraisal time.
//!
//! Calling [`ComidBuilder::strict_links`] with `true` enables a builder-side
//! lint with two parts:
//!
//! 1. **Environment anchoring.** Every condition env in a
//!    conditional-endorsement-series, conditional-endorsement, or endorsed
//!    triple must structurally equal some reference-triple env in the same
//!    CoMID. Mismatch produces [`BuilderError::UnanchoredConditionEnv`].
//! 2. **Measurement anchoring.** Every selection-side measurement (a CES
//!    `claims_list`, a CES series-record `selection`, or a CE
//!    `stateful-environment-record` measurement) must structurally equal
//!    some measurement in a reference triple **for the same env**.
//!    Mismatch produces [`BuilderError::UnanchoredConditionMeasurement`].
//!    Endorsement and addition lists are not anchored — they add values,
//!    they do not select.
//!
//! Both checks use **exact structural equality** — no subsumption or
//! wildcard matching. They catch authoring mistakes like typos and
//! forgotten reference triples; they deliberately do not enforce the
//! richer matching rules used by verifiers (§6 of the draft). Identity,
//! attest-key, dependency, membership, and coswid triple envs are not
//! considered anchors and not checked.
//!
//! [`BuilderError::UnanchoredConditionEnv`]: crate::error::BuilderError::UnanchoredConditionEnv
//! [`BuilderError::UnanchoredConditionMeasurement`]: crate::error::BuilderError::UnanchoredConditionMeasurement
//!
//! # Environment catalog (opt-in)
//!
//! For CoMIDs where a single environment appears in multiple triples,
//! [`ComidBuilder::declare_env`] records an env in a per-builder catalog
//! and returns an [`EnvRef`] handle. Passing the handle to any
//! `add_*_for` method records the *intent* that two triples target the
//! same environment, which yields:
//!
//! - Better diagnostics under [`strict_links`](ComidBuilder::strict_links)
//!   — the lint reports the offending env by label, not by structural diff.
//! - A single point of truth for late edits — mutating an env in the
//!   catalog is not supported today, but a future API could.
//! - A documented call-site signal that two triples are linked (e.g.
//!   `&cpu` reads clearer than two independent `EnvironmentMap` values).
//!
//! `EnvRef`s never reach the wire format. At [`build`](ComidBuilder::build)
//! time each ref is resolved into an inline [`EnvironmentMap`]; the CBOR
//! output is identical to what the non-`_for` methods would produce.
//!
//! ## Scope of `add_*_for`
//!
//! The catalog API covers all nine triple kinds. The seven simple shapes
//! (reference, endorsed, identity, attest-key, dependency, membership,
//! coswid) have a single env slot or flat list of env slots and use the
//! straightforward `add_*_for(env, ...)` signature.
//!
//! The two conditional shapes
//! ([`ConditionalEndorsementSeriesTriple`] and
//! [`ConditionalEndorsementTriple`]) embed the env inside a nested record.
//! Their `_for` variants —
//! [`add_conditional_endorsement_series_for`](ComidBuilder::add_conditional_endorsement_series_for)
//! and
//! [`add_conditional_endorsement_for`](ComidBuilder::add_conditional_endorsement_for)
//! — accept the env(s) and the rest of the record's fields as separate
//! arguments and assemble the wire-type internally.
//!
//! ## When the catalog pays off
//!
//! The catalog is most useful when **one environment appears in three or
//! more triples**, or when you need a stable label for build-time
//! diagnostics. For the common one-reference + one-conditional pattern
//! (e.g. an Intel-profile CoMID with a reference triple and a paired CES
//! triple), declaring an env is also worthwhile because it eliminates the
//! risk of structural drift between the two copies of the env — the lint
//! that [`strict_links`](ComidBuilder::strict_links) provides becomes
//! redundant in the by-ref case.
//!
//! For one-shot CoMIDs with a single triple, the catalog adds boilerplate
//! without benefit; pass the [`EnvironmentMap`] directly.
//!
//! ## Builder scoping
//!
//! `EnvRef`s carry an opaque per-builder id. Passing a ref produced by
//! one [`ComidBuilder`] to a different builder's `add_*_for` method
//! fails at `build()` time with [`BuilderError::RefFromOtherBuilder`].
//! Sharing a single environment across multiple CoMIDs is not supported
//! by this API; clone the [`EnvironmentMap`] instead.
//!
//! ## Interaction with `strict_links`
//!
//! Refs are resolved *before* the [`strict_links`](ComidBuilder::strict_links)
//! lint runs. The lint operates on the resolved [`EnvironmentMap`] values
//! and its promise is unchanged: catalog membership alone does not anchor
//! an env — only a reference triple does. A ref used in an endorsed/CES/CET
//! triple still fails the lint unless the *same* env is also referenced
//! (by inline or ref form) from at least one reference triple.
//!
//! [`BuilderError::RefFromOtherBuilder`]: crate::error::BuilderError::RefFromOtherBuilder
//!
//! # Example
//!
//! ```rust
//! use corim::builder::{ComidBuilder, CorimBuilder};
//! use corim::types::common::{TagIdChoice, MeasuredElement};
//! use corim::types::corim::CorimId;
//! use corim::types::environment::{ClassMap, EnvironmentMap};
//! use corim::types::measurement::{Digest, MeasurementMap, MeasurementValuesMap};
//! use corim::types::triples::ReferenceTriple;
//!
//! let env = EnvironmentMap {
//!     class: Some(ClassMap {
//!         class_id: None,
//!         vendor: Some("ACME".into()),
//!         model: Some("Widget".into()),
//!         layer: None,
//!         index: None,
//!     }),
//!     instance: None,
//!     group: None,
//! };
//!
//! let meas = MeasurementMap {
//!     mkey: Some(MeasuredElement::Text("firmware".into())),
//!     mval: MeasurementValuesMap {
//!         digests: Some(vec![Digest::new(7, vec![0xAA; 48])]),
//!         ..MeasurementValuesMap::default()
//!     },
//!     authorized_by: None,
//! };
//!
//! let comid = ComidBuilder::new(TagIdChoice::Text("my-comid-tag".into()))
//!     .add_reference_triple(ReferenceTriple::new(env, vec![meas]))
//!     .build()
//!     .unwrap();
//!
//! let bytes = CorimBuilder::new(CorimId::Text("my-corim".into()))
//!     .add_comid_tag(comid).unwrap()
//!     .build_bytes()
//!     .unwrap();
//! ```

use crate::cbor;
use crate::error::BuilderError;
#[allow(unused_imports)]
use crate::nostd_prelude::*;
use crate::types::comid::ComidTag;
use crate::types::common::{
    CborTime, CryptoKey, EntityMap, LinkedTagMap, TagIdChoice, TagIdentity, ValidityMap,
};
use crate::types::corim::{
    ConciseTagChoice, ConciseTlTag, CorimId, CorimLocator, CorimMap, ProfileChoice,
};
use crate::types::coswid::ConciseSwidTag;
use crate::types::environment::EnvironmentMap;
use crate::types::measurement::MeasurementMap;
use crate::types::tags::TAG_CORIM;
use crate::types::triples::{
    AttestKeyTriple, CesCondition, ConditionalEndorsementSeriesTriple,
    ConditionalEndorsementTriple, ConditionalSeriesRecord, CoswidTriple, DomainDependencyTriple,
    DomainMembershipTriple, EndorsedTriple, IdentityTriple, KeyTripleConditions, ReferenceTriple,
    StatefulEnvironmentRecord, TriplesMap,
};
use crate::Validate;
use core::sync::atomic::{AtomicUsize, Ordering};

// ---------------------------------------------------------------------------
// Env catalog (build-time only — never appears on the wire)
// ---------------------------------------------------------------------------

static NEXT_BUILDER_ID: AtomicUsize = AtomicUsize::new(1);

/// Opaque, builder-scoped handle to an environment declared via
/// [`ComidBuilder::declare_env`].
///
/// `EnvRef`s record the *intent* that two triples target the same environment.
/// They never reach the wire format — `build()` resolves each ref into an
/// inline [`EnvironmentMap`] before encoding.
///
/// Refs are scoped to the builder that produced them; using a ref from
/// another builder is a build-time error.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EnvRef {
    builder_id: usize,
    label: String,
    uid: u32,
}

impl EnvRef {
    /// The label this ref was declared with.
    pub fn label(&self) -> &str {
        &self.label
    }
}

/// Either an inline environment or a reference to one in the builder's catalog.
///
/// Constructed via `From<EnvironmentMap>` or `From<EnvRef>` — the `add_*_for`
/// family of builder methods take `impl Into<EnvSpec>` so either form works
/// at the call site.
#[derive(Clone, Debug, PartialEq)]
#[non_exhaustive]
pub enum EnvSpec {
    /// An inline environment value.
    Inline(EnvironmentMap),
    /// A reference declared via [`ComidBuilder::declare_env`].
    Ref(EnvRef),
}

impl From<EnvironmentMap> for EnvSpec {
    fn from(env: EnvironmentMap) -> Self {
        Self::Inline(env)
    }
}

impl From<EnvRef> for EnvSpec {
    fn from(r: EnvRef) -> Self {
        Self::Ref(r)
    }
}

impl From<&EnvRef> for EnvSpec {
    fn from(r: &EnvRef) -> Self {
        Self::Ref(r.clone())
    }
}

// ---------------------------------------------------------------------------
// ComidBuilder
// ---------------------------------------------------------------------------

/// Builder for constructing a [`ComidTag`] (CoMID).
///
/// Accepts a caller-provided `tag-id` and allows adding any combination
/// of the nine triple types defined by the RFC. At least one triple must
/// be present for [`build`](ComidBuilder::build) to succeed.
#[must_use]
pub struct ComidBuilder {
    tag_id: TagIdChoice,
    tag_version: Option<u64>,
    language: Option<String>,
    entities: Option<Vec<EntityMap>>,
    linked_tags: Option<Vec<LinkedTagMap>>,
    reference_triples: Option<Vec<ReferenceTriple>>,
    endorsed_triples: Option<Vec<EndorsedTriple>>,
    identity_triples: Option<Vec<IdentityTriple>>,
    attest_key_triples: Option<Vec<AttestKeyTriple>>,
    dependency_triples: Option<Vec<DomainDependencyTriple>>,
    membership_triples: Option<Vec<DomainMembershipTriple>>,
    coswid_triples: Option<Vec<CoswidTriple>>,
    conditional_endorsement_series: Option<Vec<ConditionalEndorsementSeriesTriple>>,
    conditional_endorsement: Option<Vec<ConditionalEndorsementTriple>>,
    strict_links: bool,
    // Env catalog (build-time only). Maps label -> (uid, env).
    builder_id: usize,
    env_catalog: BTreeMap<String, (u32, EnvironmentMap)>,
    next_env_uid: u32,
    // Pending triples added via the `_for` family — resolved at build() time.
    pending_reference: Vec<(EnvSpec, Vec<MeasurementMap>)>,
    pending_endorsed: Vec<(EnvSpec, Vec<MeasurementMap>)>,
    pending_identity: Vec<(EnvSpec, Vec<CryptoKey>, Option<KeyTripleConditions>)>,
    pending_attest_key: Vec<(EnvSpec, Vec<CryptoKey>, Option<KeyTripleConditions>)>,
    pending_dependency: Vec<(EnvSpec, Vec<EnvSpec>)>,
    pending_membership: Vec<(EnvSpec, Vec<EnvSpec>)>,
    pending_coswid: Vec<(EnvSpec, Vec<TagIdChoice>)>,
    #[allow(clippy::type_complexity)]
    pending_ces: Vec<(
        EnvSpec,
        Vec<MeasurementMap>,
        Option<Vec<CryptoKey>>,
        Vec<ConditionalSeriesRecord>,
    )>,
    #[allow(clippy::type_complexity)]
    pending_ce: Vec<(Vec<(EnvSpec, Vec<MeasurementMap>)>, Vec<EndorsedTriple>)>,
}

impl ComidBuilder {
    /// Create a new builder with the given tag identifier.
    ///
    /// The tag identifier must be globally unique per §5.1.1.1.
    pub fn new(tag_id: TagIdChoice) -> Self {
        Self {
            tag_id,
            tag_version: None,
            language: None,
            entities: None,
            linked_tags: None,
            reference_triples: None,
            endorsed_triples: None,
            identity_triples: None,
            attest_key_triples: None,
            dependency_triples: None,
            membership_triples: None,
            coswid_triples: None,
            conditional_endorsement_series: None,
            conditional_endorsement: None,
            strict_links: false,
            builder_id: NEXT_BUILDER_ID.fetch_add(1, Ordering::Relaxed),
            env_catalog: BTreeMap::new(),
            next_env_uid: 0,
            pending_reference: Vec::new(),
            pending_endorsed: Vec::new(),
            pending_identity: Vec::new(),
            pending_attest_key: Vec::new(),
            pending_dependency: Vec::new(),
            pending_membership: Vec::new(),
            pending_coswid: Vec::new(),
            pending_ces: Vec::new(),
            pending_ce: Vec::new(),
        }
    }

    /// Enable cross-triple link checking at `build()` time.
    ///
    /// When enabled, two anchoring checks run:
    ///
    /// 1. Every condition environment in a conditional-endorsement-series,
    ///    conditional-endorsement, or endorsed triple must structurally
    ///    equal some reference-triple environment in the same CoMID;
    ///    otherwise `build()` returns [`BuilderError::UnanchoredConditionEnv`].
    /// 2. Every selection-side measurement (CES `claims_list`, CES series
    ///    `selection`, or CE `stateful-environment-record` measurement)
    ///    must structurally equal some measurement in a reference triple
    ///    for the *same* env; otherwise `build()` returns
    ///    [`BuilderError::UnanchoredConditionMeasurement`]. Endorsement
    ///    and addition lists are not anchored.
    ///
    /// The wire format does not encode either constraint — these are
    /// builder-side lints for catching authoring mistakes.
    pub fn strict_links(mut self, enable: bool) -> Self {
        self.strict_links = enable;
        self
    }

    /// Declare a named environment in this builder's catalog.
    ///
    /// Returns an [`EnvRef`] that can be passed to any `add_*_for` method on
    /// this same builder. The label is for diagnostics only; uniqueness is
    /// enforced — a second `declare_env` with the same label returns
    /// [`BuilderError::DuplicateEnvLabel`].
    ///
    /// `EnvRef`s never reach the wire format; `build()` resolves each ref into
    /// an inline [`EnvironmentMap`] before encoding.
    pub fn declare_env(
        &mut self,
        label: impl Into<String>,
        env: EnvironmentMap,
    ) -> Result<EnvRef, BuilderError> {
        let label = label.into();
        if self.env_catalog.contains_key(&label) {
            return Err(BuilderError::DuplicateEnvLabel { label });
        }
        let uid = self.next_env_uid;
        self.next_env_uid = self
            .next_env_uid
            .checked_add(1)
            .ok_or(BuilderError::Validation(
                "env-catalog uid counter overflow".into(),
            ))?;
        self.env_catalog.insert(label.clone(), (uid, env));
        Ok(EnvRef {
            builder_id: self.builder_id,
            label,
            uid,
        })
    }

    /// Add a reference values triple by env-spec.
    ///
    /// `env` may be an [`EnvironmentMap`] (inline) or an [`EnvRef`] obtained
    /// from [`declare_env`](Self::declare_env) on this same builder. Resolution
    /// happens at [`build`](Self::build) time.
    pub fn add_reference_triple_for(
        mut self,
        env: impl Into<EnvSpec>,
        measurements: Vec<MeasurementMap>,
    ) -> Self {
        self.pending_reference.push((env.into(), measurements));
        self
    }

    /// Add an endorsed values triple by env-spec. See [`add_reference_triple_for`](Self::add_reference_triple_for).
    pub fn add_endorsed_triple_for(
        mut self,
        env: impl Into<EnvSpec>,
        endorsement: Vec<MeasurementMap>,
    ) -> Self {
        self.pending_endorsed.push((env.into(), endorsement));
        self
    }

    /// Add an identity triple by env-spec. See [`add_reference_triple_for`](Self::add_reference_triple_for).
    pub fn add_identity_triple_for(
        mut self,
        env: impl Into<EnvSpec>,
        keys: Vec<CryptoKey>,
        conditions: Option<KeyTripleConditions>,
    ) -> Self {
        self.pending_identity.push((env.into(), keys, conditions));
        self
    }

    /// Add an attest-key triple by env-spec. See [`add_reference_triple_for`](Self::add_reference_triple_for).
    pub fn add_attest_key_triple_for(
        mut self,
        env: impl Into<EnvSpec>,
        keys: Vec<CryptoKey>,
        conditions: Option<KeyTripleConditions>,
    ) -> Self {
        self.pending_attest_key.push((env.into(), keys, conditions));
        self
    }

    /// Add a domain dependency triple by env-spec. Trustees are also env-specs;
    /// pass `vec![env_a.into(), env_b_ref.into()]` to mix inline envs and refs.
    pub fn add_dependency_triple_for(
        mut self,
        domain: impl Into<EnvSpec>,
        trustees: Vec<EnvSpec>,
    ) -> Self {
        self.pending_dependency.push((domain.into(), trustees));
        self
    }

    /// Add a domain membership triple by env-spec. See [`add_dependency_triple_for`](Self::add_dependency_triple_for).
    pub fn add_membership_triple_for(
        mut self,
        domain: impl Into<EnvSpec>,
        members: Vec<EnvSpec>,
    ) -> Self {
        self.pending_membership.push((domain.into(), members));
        self
    }

    /// Add a CoMID-CoSWID linking triple by env-spec.
    pub fn add_coswid_triple_for(
        mut self,
        env: impl Into<EnvSpec>,
        tag_ids: Vec<TagIdChoice>,
    ) -> Self {
        self.pending_coswid.push((env.into(), tag_ids));
        self
    }

    /// Add a conditional-endorsement-series triple by env-spec.
    ///
    /// The arguments correspond to the fields of [`CesCondition`] plus the
    /// `series` list. The condition env may be an [`EnvironmentMap`] or an
    /// [`EnvRef`]; refs are resolved at [`build`](Self::build) time exactly
    /// like the other `_for` methods.
    ///
    /// This is the preferred way to construct a CES triple whose condition
    /// env is shared with a reference triple — passing the same [`EnvRef`]
    /// to both [`add_reference_triple_for`](Self::add_reference_triple_for)
    /// and this method guarantees the two envs are byte-for-byte identical
    /// on the wire, with no caller-visible clone.
    pub fn add_conditional_endorsement_series_for(
        mut self,
        condition_env: impl Into<EnvSpec>,
        condition_claims_list: Vec<MeasurementMap>,
        condition_authorized_by: Option<Vec<CryptoKey>>,
        series: Vec<ConditionalSeriesRecord>,
    ) -> Self {
        self.pending_ces.push((
            condition_env.into(),
            condition_claims_list,
            condition_authorized_by,
            series,
        ));
        self
    }

    /// Add a conditional-endorsement triple by env-spec.
    ///
    /// `conditions` is the `[+ stateful-environment-record]` list — each
    /// entry pairs an env (inline or [`EnvRef`]) with its measurement list.
    /// `endorsements` is the `[+ endorsed-triple-record]` list; those inner
    /// envs are not covered by the catalog (use
    /// [`add_endorsed_triple_for`](Self::add_endorsed_triple_for) when the
    /// shared-env intent is across whole endorsed triples instead).
    pub fn add_conditional_endorsement_for(
        mut self,
        conditions: Vec<(EnvSpec, Vec<MeasurementMap>)>,
        endorsements: Vec<EndorsedTriple>,
    ) -> Self {
        self.pending_ce.push((conditions, endorsements));
        self
    }

    /// Resolve an [`EnvSpec`] to an owned [`EnvironmentMap`], validating
    /// builder-scoping for `Ref` variants.
    fn resolve(&self, spec: EnvSpec) -> Result<EnvironmentMap, BuilderError> {
        match spec {
            EnvSpec::Inline(env) => Ok(env),
            EnvSpec::Ref(r) => {
                if r.builder_id != self.builder_id {
                    return Err(BuilderError::RefFromOtherBuilder { label: r.label });
                }
                // Invariant: `EnvRef` is only constructed by `declare_env`,
                // which always inserts into `env_catalog` before returning
                // the ref. The catalog only grows, so a builder-scoped ref
                // is always present.
                let (_uid, env) = self
                    .env_catalog
                    .get(&r.label)
                    .expect("EnvRef invariant: catalog entry present");
                Ok(env.clone())
            }
        }
    }

    /// Set the tag version (§5.1.1.2). Defaults to 0 if not set.
    pub fn set_tag_version(mut self, version: u64) -> Self {
        self.tag_version = Some(version);
        self
    }

    /// Set the optional language tag (BCP 47).
    pub fn set_language(mut self, lang: impl Into<String>) -> Self {
        self.language = Some(lang.into());
        self
    }

    /// Add an entity (§5.1.2).
    pub fn add_entity(mut self, entity: EntityMap) -> Self {
        self.entities.get_or_insert_with(Vec::new).push(entity);
        self
    }

    /// Add a linked tag (§5.1.3).
    pub fn add_linked_tag(mut self, linked_tag: LinkedTagMap) -> Self {
        self.linked_tags
            .get_or_insert_with(Vec::new)
            .push(linked_tag);
        self
    }

    /// Add a reference values triple (§5.1.5).
    pub fn add_reference_triple(mut self, triple: ReferenceTriple) -> Self {
        self.reference_triples
            .get_or_insert_with(Vec::new)
            .push(triple);
        self
    }

    /// Add an endorsed values triple (§5.1.6).
    pub fn add_endorsed_triple(mut self, triple: EndorsedTriple) -> Self {
        self.endorsed_triples
            .get_or_insert_with(Vec::new)
            .push(triple);
        self
    }

    /// Add a device identity triple (§5.1.9).
    pub fn add_identity_triple(mut self, triple: IdentityTriple) -> Self {
        self.identity_triples
            .get_or_insert_with(Vec::new)
            .push(triple);
        self
    }

    /// Add an attest key triple (§5.1.10).
    pub fn add_attest_key_triple(mut self, triple: AttestKeyTriple) -> Self {
        self.attest_key_triples
            .get_or_insert_with(Vec::new)
            .push(triple);
        self
    }

    /// Add a domain dependency triple (§5.1.11.2).
    pub fn add_dependency_triple(mut self, triple: DomainDependencyTriple) -> Self {
        self.dependency_triples
            .get_or_insert_with(Vec::new)
            .push(triple);
        self
    }

    /// Add a domain membership triple (§5.1.11.1).
    pub fn add_membership_triple(mut self, triple: DomainMembershipTriple) -> Self {
        self.membership_triples
            .get_or_insert_with(Vec::new)
            .push(triple);
        self
    }

    /// Add a CoMID-CoSWID linking triple (§5.1.12).
    pub fn add_coswid_triple(mut self, triple: CoswidTriple) -> Self {
        self.coswid_triples
            .get_or_insert_with(Vec::new)
            .push(triple);
        self
    }

    /// Add a conditional endorsement series triple (§5.1.8).
    pub fn add_conditional_endorsement_series(
        mut self,
        triple: ConditionalEndorsementSeriesTriple,
    ) -> Self {
        self.conditional_endorsement_series
            .get_or_insert_with(Vec::new)
            .push(triple);
        self
    }

    /// Add a conditional endorsement triple (§5.1.7).
    pub fn add_conditional_endorsement(mut self, triple: ConditionalEndorsementTriple) -> Self {
        self.conditional_endorsement
            .get_or_insert_with(Vec::new)
            .push(triple);
        self
    }

    /// Build the [`ComidTag`].
    ///
    /// Returns an error if no triples have been added, or if any triple
    /// contains an empty list where the CDDL requires `[+ T]`.
    pub fn build(mut self) -> Result<ComidTag, BuilderError> {
        // Resolve any pending triples added via the `_for` family.
        // Each EnvSpec::Ref is checked against this builder's catalog and
        // converted into an inline EnvironmentMap before being merged into
        // the corresponding self.X_triples list.
        for (env_spec, measurements) in core::mem::take(&mut self.pending_reference) {
            let env = self.resolve(env_spec)?;
            self.reference_triples
                .get_or_insert_with(Vec::new)
                .push(ReferenceTriple::new(env, measurements));
        }
        for (env_spec, endorsement) in core::mem::take(&mut self.pending_endorsed) {
            let env = self.resolve(env_spec)?;
            self.endorsed_triples
                .get_or_insert_with(Vec::new)
                .push(EndorsedTriple::new(env, endorsement));
        }
        for (env_spec, keys, conditions) in core::mem::take(&mut self.pending_identity) {
            let env = self.resolve(env_spec)?;
            self.identity_triples
                .get_or_insert_with(Vec::new)
                .push(IdentityTriple::new(env, keys, conditions));
        }
        for (env_spec, keys, conditions) in core::mem::take(&mut self.pending_attest_key) {
            let env = self.resolve(env_spec)?;
            self.attest_key_triples
                .get_or_insert_with(Vec::new)
                .push(AttestKeyTriple::new(env, keys, conditions));
        }
        for (domain_spec, trustees_spec) in core::mem::take(&mut self.pending_dependency) {
            let domain = self.resolve(domain_spec)?;
            let mut trustees = Vec::with_capacity(trustees_spec.len());
            for t in trustees_spec {
                trustees.push(self.resolve(t)?);
            }
            self.dependency_triples
                .get_or_insert_with(Vec::new)
                .push(DomainDependencyTriple::new(domain, trustees));
        }
        for (domain_spec, members_spec) in core::mem::take(&mut self.pending_membership) {
            let domain = self.resolve(domain_spec)?;
            let mut members = Vec::with_capacity(members_spec.len());
            for m in members_spec {
                members.push(self.resolve(m)?);
            }
            self.membership_triples
                .get_or_insert_with(Vec::new)
                .push(DomainMembershipTriple::new(domain, members));
        }
        for (env_spec, tag_ids) in core::mem::take(&mut self.pending_coswid) {
            let env = self.resolve(env_spec)?;
            self.coswid_triples
                .get_or_insert_with(Vec::new)
                .push(CoswidTriple::new(env, tag_ids));
        }
        for (env_spec, claims_list, authorized_by, series) in core::mem::take(&mut self.pending_ces)
        {
            let environment = self.resolve(env_spec)?;
            self.conditional_endorsement_series
                .get_or_insert_with(Vec::new)
                .push(ConditionalEndorsementSeriesTriple::new(
                    CesCondition {
                        environment,
                        claims_list,
                        authorized_by,
                    },
                    series,
                ));
        }
        for (conditions_spec, endorsements) in core::mem::take(&mut self.pending_ce) {
            let mut conditions = Vec::with_capacity(conditions_spec.len());
            for (env_spec, measurements) in conditions_spec {
                let env = self.resolve(env_spec)?;
                conditions.push(StatefulEnvironmentRecord(env, measurements));
            }
            self.conditional_endorsement
                .get_or_insert_with(Vec::new)
                .push(ConditionalEndorsementTriple(conditions, endorsements));
        }

        let has_triples = self.reference_triples.is_some()
            || self.endorsed_triples.is_some()
            || self.identity_triples.is_some()
            || self.attest_key_triples.is_some()
            || self.dependency_triples.is_some()
            || self.membership_triples.is_some()
            || self.coswid_triples.is_some()
            || self.conditional_endorsement_series.is_some()
            || self.conditional_endorsement.is_some();

        if !has_triples {
            return Err(BuilderError::EmptyTriples);
        }

        // Validate [+ T] constraints inside triple records
        if let Some(ref triples) = self.reference_triples {
            for t in triples {
                if t.1.is_empty() {
                    return Err(BuilderError::EmptyList {
                        field: "ref-claims",
                    });
                }
            }
        }
        if let Some(ref triples) = self.endorsed_triples {
            for t in triples {
                if t.1.is_empty() {
                    return Err(BuilderError::EmptyList {
                        field: "endorsement",
                    });
                }
            }
        }
        if let Some(ref triples) = self.identity_triples {
            for t in triples {
                if t.1.is_empty() {
                    return Err(BuilderError::EmptyList { field: "key-list" });
                }
            }
        }
        if let Some(ref triples) = self.attest_key_triples {
            for t in triples {
                if t.1.is_empty() {
                    return Err(BuilderError::EmptyList { field: "key-list" });
                }
            }
        }
        if let Some(ref triples) = self.dependency_triples {
            for t in triples {
                if t.1.is_empty() {
                    return Err(BuilderError::EmptyList { field: "trustees" });
                }
            }
        }
        if let Some(ref triples) = self.membership_triples {
            for t in triples {
                if t.1.is_empty() {
                    return Err(BuilderError::EmptyList { field: "members" });
                }
            }
        }
        if let Some(ref triples) = self.coswid_triples {
            for t in triples {
                if t.1.is_empty() {
                    return Err(BuilderError::EmptyList { field: "tag-ids" });
                }
            }
        }

        // strict_links: every condition env must structurally match some
        // reference-triple env. Reference-triple envs are the only anchor set;
        // identity/attest-key/dependency/membership/coswid envs are not
        // considered anchors for this lint.
        //
        // The lint also extends to selection-side measurements: a CES
        // claims_list, a CES series-record selection, or a CE stateful-
        // environment-record measurement must structurally equal some
        // measurement in a reference triple for the *same* env (S2 pool).
        // Endorsement and addition lists are not anchored.
        if self.strict_links {
            let anchors: Vec<&EnvironmentMap> = self
                .reference_triples
                .as_deref()
                .unwrap_or(&[])
                .iter()
                .map(|t| &t.0)
                .collect();
            let is_anchored = |env: &EnvironmentMap| anchors.contains(&env);

            // Build the per-env measurement pool for S2 anchoring. The
            // closure returns the union of measurements across all reference
            // triples whose env structurally equals `env`.
            let ref_triples = self.reference_triples.as_deref().unwrap_or(&[]);
            let meas_anchors = |env: &EnvironmentMap| -> Vec<&MeasurementMap> {
                ref_triples
                    .iter()
                    .filter(|t| &t.0 == env)
                    .flat_map(|t| t.1.iter())
                    .collect()
            };
            let check_meas = |env: &EnvironmentMap,
                              to_anchor: &[MeasurementMap],
                              triple_kind: &'static str,
                              triple_index: usize|
             -> Result<(), BuilderError> {
                if to_anchor.is_empty() {
                    return Ok(());
                }
                let pool = meas_anchors(env);
                for (mi, m) in to_anchor.iter().enumerate() {
                    if !pool.contains(&m) {
                        return Err(BuilderError::UnanchoredConditionMeasurement {
                            triple_kind,
                            triple_index,
                            measurement_index: mi,
                        });
                    }
                }
                Ok(())
            };

            if let Some(ref triples) = self.conditional_endorsement_series {
                for (i, t) in triples.iter().enumerate() {
                    if !is_anchored(&t.0.environment) {
                        return Err(BuilderError::UnanchoredConditionEnv {
                            triple_kind: "conditional-endorsement-series",
                            index: i,
                        });
                    }
                    check_meas(
                        &t.0.environment,
                        &t.0.claims_list,
                        "conditional-endorsement-series",
                        i,
                    )?;
                    for series in &t.1 {
                        check_meas(
                            &t.0.environment,
                            &series.0,
                            "conditional-endorsement-series-selection",
                            i,
                        )?;
                    }
                }
            }
            if let Some(ref triples) = self.endorsed_triples {
                for (i, t) in triples.iter().enumerate() {
                    if !is_anchored(&t.0) {
                        return Err(BuilderError::UnanchoredConditionEnv {
                            triple_kind: "endorsed",
                            index: i,
                        });
                    }
                }
            }
            if let Some(ref triples) = self.conditional_endorsement {
                for (i, t) in triples.iter().enumerate() {
                    for stateful in &t.0 {
                        if !is_anchored(&stateful.0) {
                            return Err(BuilderError::UnanchoredConditionEnv {
                                triple_kind: "conditional-endorsement",
                                index: i,
                            });
                        }
                        check_meas(&stateful.0, &stateful.1, "conditional-endorsement", i)?;
                    }
                }
            }
        }

        let triples = TriplesMap {
            reference_triples: self.reference_triples,
            endorsed_triples: self.endorsed_triples,
            identity_triples: self.identity_triples,
            attest_key_triples: self.attest_key_triples,
            dependency_triples: self.dependency_triples,
            membership_triples: self.membership_triples,
            coswid_triples: self.coswid_triples,
            conditional_endorsement_series: self.conditional_endorsement_series,
            conditional_endorsement: self.conditional_endorsement,
        };

        Ok(ComidTag {
            language: self.language,
            tag_identity: TagIdentity {
                tag_id: self.tag_id,
                tag_version: self.tag_version,
            },
            entities: self.entities,
            linked_tags: self.linked_tags,
            triples,
        })
    }
}

// ---------------------------------------------------------------------------
// CotlBuilder
// ---------------------------------------------------------------------------

/// Builder for constructing a [`ConciseTlTag`] (CoTL) — §6.1.
///
/// A CoTL signals which CoMID/CoSWID tags the Verifier should consider
/// "active" at a given point in time.
#[must_use]
pub struct CotlBuilder {
    tag_id: TagIdChoice,
    tag_version: Option<u64>,
    tags_list: Vec<TagIdentity>,
    not_before: Option<i64>,
    not_after: i64,
}

impl CotlBuilder {
    /// Create a new CoTL builder with the given tag identifier and validity end.
    pub fn new(tag_id: TagIdChoice, not_after: i64) -> Self {
        Self {
            tag_id,
            tag_version: None,
            tags_list: Vec::new(),
            not_before: None,
            not_after,
        }
    }

    /// Set the tag version.
    pub fn set_tag_version(mut self, version: u64) -> Self {
        self.tag_version = Some(version);
        self
    }

    /// Set the optional not-before timestamp.
    pub fn set_not_before(mut self, not_before: i64) -> Self {
        self.not_before = Some(not_before);
        self
    }

    /// Add a tag identity to the activation list.
    pub fn add_tag(mut self, tag_identity: TagIdentity) -> Self {
        self.tags_list.push(tag_identity);
        self
    }

    /// Add a tag by ID (convenience — version defaults to None).
    pub fn add_tag_id(mut self, tag_id: TagIdChoice) -> Self {
        self.tags_list.push(TagIdentity {
            tag_id,
            tag_version: None,
        });
        self
    }

    /// Build the [`ConciseTlTag`].
    ///
    /// Returns an error if the tags list is empty (CDDL requires `[+ tag-identity-map]`).
    pub fn build(self) -> Result<ConciseTlTag, BuilderError> {
        if self.tags_list.is_empty() {
            return Err(BuilderError::EmptyList { field: "tags-list" });
        }
        if let Some(nb) = self.not_before {
            if nb > self.not_after {
                return Err(BuilderError::InvalidValidity);
            }
        }
        Ok(ConciseTlTag {
            tag_identity: TagIdentity {
                tag_id: self.tag_id,
                tag_version: self.tag_version,
            },
            tags_list: self.tags_list,
            tl_validity: ValidityMap {
                not_before: self.not_before.map(CborTime::new),
                not_after: CborTime::new(self.not_after),
            },
        })
    }
}

// ---------------------------------------------------------------------------
// CorimBuilder
// ---------------------------------------------------------------------------

/// Builder for constructing a [`CorimMap`] (top-level CoRIM).
///
/// At least one tag (CoMID, CoSWID, or CoTL) must be added for
/// [`build`](CorimBuilder::build) to succeed.
#[must_use]
pub struct CorimBuilder {
    id: CorimId,
    profile: Option<ProfileChoice>,
    rim_validity: Option<ValidityMap>,
    entities: Option<Vec<EntityMap>>,
    dependent_rims: Option<Vec<CorimLocator>>,
    tags: Vec<ConciseTagChoice>,
}

impl CorimBuilder {
    /// Create a new CoRIM builder with the given identifier (§4.1.1).
    pub fn new(id: CorimId) -> Self {
        Self {
            id,
            profile: None,
            rim_validity: None,
            entities: None,
            dependent_rims: None,
            tags: Vec::new(),
        }
    }

    /// Set the optional profile (§4.1.4).
    pub fn set_profile(mut self, profile: ProfileChoice) -> Self {
        self.profile = Some(profile);
        self
    }

    /// Set the optional validity window (§7.3).
    ///
    /// Returns an error if `not_before` is present and greater than `not_after`.
    pub fn set_validity(
        mut self,
        not_before: Option<i64>,
        not_after: i64,
    ) -> Result<Self, BuilderError> {
        if let Some(nb) = not_before {
            if nb > not_after {
                return Err(BuilderError::InvalidValidity);
            }
        }
        self.rim_validity = Some(ValidityMap {
            not_before: not_before.map(CborTime::new),
            not_after: CborTime::new(not_after),
        });
        Ok(self)
    }

    /// Add an entity (§4.1.5).
    pub fn add_entity(mut self, entity: EntityMap) -> Self {
        self.entities.get_or_insert_with(Vec::new).push(entity);
        self
    }

    /// Add a dependent RIM locator (§4.1.3).
    pub fn add_dependent_rim(mut self, locator: CorimLocator) -> Self {
        self.dependent_rims
            .get_or_insert_with(Vec::new)
            .push(locator);
        self
    }

    /// Add a pre-built [`ComidTag`], encoding it to CBOR and wrapping with tag 506.
    pub fn add_comid_tag(mut self, comid: ComidTag) -> Result<Self, BuilderError> {
        let comid_bytes = cbor::encode(&comid)?;
        self.tags.push(ConciseTagChoice::Comid(comid_bytes));
        Ok(self)
    }

    /// Add a CoSWID tag as opaque CBOR bytes (tag 505).
    pub fn add_coswid_tag(mut self, coswid_bytes: Vec<u8>) -> Self {
        self.tags.push(ConciseTagChoice::Coswid(coswid_bytes));
        self
    }

    /// Add a pre-built [`ConciseSwidTag`], encoding it to CBOR and wrapping with tag 505.
    pub fn add_coswid(mut self, coswid: ConciseSwidTag) -> Result<Self, BuilderError> {
        coswid
            .valid()
            .map_err(|e: String| BuilderError::Validation(e))?;
        let coswid_bytes = cbor::encode(&coswid)?;
        self.tags.push(ConciseTagChoice::Coswid(coswid_bytes));
        Ok(self)
    }

    /// Add a CoTL tag as opaque CBOR bytes (tag 508).
    pub fn add_cotl_tag(mut self, cotl_bytes: Vec<u8>) -> Self {
        self.tags.push(ConciseTagChoice::Cotl(cotl_bytes));
        self
    }

    /// Add a pre-built [`ConciseTlTag`], encoding it to CBOR and wrapping with tag 508.
    pub fn add_cotl(mut self, cotl: ConciseTlTag) -> Result<Self, BuilderError> {
        let cotl_bytes = cbor::encode(&cotl)?;
        self.tags.push(ConciseTagChoice::Cotl(cotl_bytes));
        Ok(self)
    }

    /// Add a raw [`ConciseTagChoice`] directly.
    pub fn add_tag(mut self, tag: ConciseTagChoice) -> Self {
        self.tags.push(tag);
        self
    }

    /// Build the [`CorimMap`].
    ///
    /// Returns an error if no tags have been added.
    pub fn build(self) -> Result<CorimMap, BuilderError> {
        if self.tags.is_empty() {
            return Err(BuilderError::NoTags);
        }

        Ok(CorimMap {
            id: self.id,
            tags: self.tags,
            dependent_rims: self.dependent_rims,
            profile: self.profile,
            rim_validity: self.rim_validity,
            entities: self.entities,
        })
    }

    /// Build and encode as deterministic CBOR bytes with tag 501 wrapper.
    ///
    /// This is equivalent to calling [`build`](CorimBuilder::build) followed
    /// by wrapping in `Tagged::new(501, corim)` and encoding.
    pub fn build_bytes(self) -> Result<Vec<u8>, BuilderError> {
        let corim = self.build()?;
        let tagged = cbor::value::Tagged::new(TAG_CORIM, corim);
        let bytes = cbor::encode(&tagged)?;
        Ok(bytes)
    }
}
