// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Builder API for CoRIM and CoMID generation.
//!
//! Provides a fluent interface for constructing CoRIM and CoMID structures
//! per draft-ietf-rats-corim-10.
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
use crate::types::comid::ComidTag;
use crate::types::common::{
    CborTime, EntityMap, LinkedTagMap, TagIdChoice, TagIdentity, ValidityMap,
};
use crate::types::corim::{
    ConciseTagChoice, ConciseTlTag, CorimId, CorimLocator, CorimMap, ProfileChoice,
};
use crate::types::coswid::ConciseSwidTag;
use crate::types::tags::TAG_CORIM;
use crate::types::triples::{
    AttestKeyTriple, ConditionalEndorsementSeriesTriple, ConditionalEndorsementTriple,
    CoswidTriple, DomainDependencyTriple, DomainMembershipTriple, EndorsedTriple, IdentityTriple,
    ReferenceTriple, TriplesMap,
};
use crate::Validate;

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
    pub fn build(self) -> Result<ComidTag, BuilderError> {
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
            .map_err(|e| BuilderError::Validation(e.to_string()))?;
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
