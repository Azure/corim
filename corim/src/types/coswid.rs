// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! CoSWID (Concise Software Identification) types per RFC 9393.
//!
//! This module models the core subset of `concise-swid-tag` needed for CoRIM
//! integration. The full RFC 9393 resource-collection model (file-entry,
//! directory-entry, process-entry) is deferred — payload and evidence are
//! stored as opaque [`crate::cbor::value::Value`] when present.
//!
//! # Modeled types
//!
//! | CDDL | Rust type |
//! |------|-----------|
//! | `concise-swid-tag` | [`ConciseSwidTag`] |
//! | `entity-entry` | [`SwidEntity`] |
//! | `link-entry` | [`SwidLink`] |
//! | `hash-entry` | reuses [`crate::types::measurement::Digest`] |

#[allow(unused_imports)]
use crate::nostd_prelude::*;
use corim_macros::{CborDeserialize, CborSerialize};

use super::common::TagIdChoice;
use super::measurement::Digest;
use crate::Validate;

// ---------------------------------------------------------------------------
// concise-swid-tag (RFC 9393 §2.3)
// ---------------------------------------------------------------------------

/// `concise-swid-tag` — top-level CoSWID tag.
///
/// Models the core fields of the `concise-swid-tag` map per RFC 9393 §2.3.
/// Payload and evidence are not modeled (opaque in CoRIM context).
///
/// CDDL (subset):
/// ```text
/// concise-swid-tag = {
///   tag-id: 0 => text / bstr .size 16,
///   software-name: 1 => text,
///   entity: 2 => entity-entry / [2* entity-entry],
///   ? link: 4 => link-entry / [2* link-entry],
///   ? corpus: 8 => bool,
///   ? patch: 9 => bool,
///   ? supplemental: 11 => bool,
///   tag-version: 12 => integer,
///   ? software-version: 13 => text,
///   ? version-scheme: 14 => int / text,
///   ? lang: 15 => text,
/// }
/// ```
#[derive(Clone, Debug, PartialEq, CborSerialize, CborDeserialize)]
pub struct ConciseSwidTag {
    /// `tag-id` (key 0): globally unique tag identifier (text or UUID).
    #[cbor(key = 0)]
    pub tag_id: TagIdChoice,

    /// `software-name` (key 1): human-readable software name.
    #[cbor(key = 1)]
    pub software_name: String,

    /// `entity` (key 2): one or more entities (tag creator, etc.).
    #[cbor(key = 2)]
    pub entities: Vec<SwidEntity>,

    /// `link` (key 4): optional relationship links.
    #[cbor(key = 4, optional)]
    pub links: Option<Vec<SwidLink>>,

    /// `corpus` (key 8): true if this is a corpus (pre-installation) tag.
    #[cbor(key = 8, optional)]
    pub corpus: Option<bool>,

    /// `patch` (key 9): true if this is a patch tag.
    #[cbor(key = 9, optional)]
    pub patch: Option<bool>,

    /// `supplemental` (key 11): true if this is a supplemental tag.
    #[cbor(key = 11, optional)]
    pub supplemental: Option<bool>,

    /// `tag-version` (key 12): revision number of the tag itself.
    #[cbor(key = 12)]
    pub tag_version: i64,

    /// `software-version` (key 13): version of the software component.
    #[cbor(key = 13, optional)]
    pub software_version: Option<String>,

    /// `version-scheme` (key 14): versioning scheme (e.g., semver=16384).
    #[cbor(key = 14, optional)]
    pub version_scheme: Option<i64>,

    /// `lang` (key 15): BCP 47 language tag.
    #[cbor(key = 15, optional)]
    pub lang: Option<String>,
}

impl Validate for ConciseSwidTag {
    fn valid(&self) -> Result<(), String> {
        // entities must be non-empty (CDDL: one-or-more<entity-entry>)
        if self.entities.is_empty() {
            return Err("at least one entity is required".into());
        }

        // At least one entity must have the tag-creator role
        let has_tag_creator = self
            .entities
            .iter()
            .any(|e| e.roles.contains(&super::tags::SWID_ROLE_TAG_CREATOR));
        if !has_tag_creator {
            return Err("at least one entity must have the tag-creator role".into());
        }

        // Validate entities
        for (i, e) in self.entities.iter().enumerate() {
            e.valid()
                .map_err(|err| format!("entity at index {i}: {err}"))?;
        }

        // Validate links if present
        if let Some(ref links) = self.links {
            for (i, l) in links.iter().enumerate() {
                l.valid()
                    .map_err(|err| format!("link at index {i}: {err}"))?;
            }
        }

        // Co-constraints (RFC 9393 §2.4):
        // patch and supplemental must not both be true
        if self.patch == Some(true) && self.supplemental == Some(true) {
            return Err("patch and supplemental must not both be true".into());
        }

        // If patch is true, must have at least one link with rel="patches"
        if self.patch == Some(true) {
            let has_patches_link = self
                .links
                .as_ref()
                .is_some_and(|links| links.iter().any(|l| l.rel == super::tags::SWID_REL_PATCHES));
            if !has_patches_link {
                return Err("patch tag must have at least one link with rel=\"patches\"".into());
            }
        }

        Ok(())
    }
}

impl ConciseSwidTag {
    /// Create a new CoSWID tag with the minimum required fields.
    pub fn new(
        tag_id: TagIdChoice,
        software_name: impl Into<String>,
        tag_version: i64,
        entities: Vec<SwidEntity>,
    ) -> Self {
        Self {
            tag_id,
            software_name: software_name.into(),
            entities,
            links: None,
            corpus: None,
            patch: None,
            supplemental: None,
            tag_version,
            software_version: None,
            version_scheme: None,
            lang: None,
        }
    }
}

// ---------------------------------------------------------------------------
// entity-entry (RFC 9393 §2.6)
// ---------------------------------------------------------------------------

/// `entity-entry` — an entity involved in a CoSWID tag.
///
/// CDDL:
/// ```text
/// entity-entry = {
///   entity-name: 31 => text,
///   ? reg-id: 32 => any-uri,
///   role: 33 => $role / [2* $role],
///   ? thumbprint: 34 => hash-entry,
/// }
/// ```
#[derive(Clone, Debug, PartialEq, CborSerialize, CborDeserialize)]
pub struct SwidEntity {
    /// `entity-name` (key 31): name of the entity.
    #[cbor(key = 31)]
    pub entity_name: String,

    /// `reg-id` (key 32): optional registration URI.
    #[cbor(key = 32, optional)]
    pub reg_id: Option<String>,

    /// `role` (key 33): one or more role values.
    #[cbor(key = 33)]
    pub roles: Vec<i64>,

    /// `thumbprint` (key 34): optional signing entity thumbprint.
    #[cbor(key = 34, optional)]
    pub thumbprint: Option<Digest>,
}

impl Validate for SwidEntity {
    fn valid(&self) -> Result<(), String> {
        if self.entity_name.is_empty() {
            return Err("entity-name must not be empty".into());
        }
        if self.roles.is_empty() {
            return Err("at least one role is required".into());
        }
        Ok(())
    }
}

impl SwidEntity {
    /// Create a new entity with the given name and roles.
    pub fn new(name: impl Into<String>, roles: Vec<i64>) -> Self {
        Self {
            entity_name: name.into(),
            reg_id: None,
            roles,
            thumbprint: None,
        }
    }

    /// Set the registration URI.
    pub fn with_reg_id(mut self, reg_id: impl Into<String>) -> Self {
        self.reg_id = Some(reg_id.into());
        self
    }
}

// ---------------------------------------------------------------------------
// link-entry (RFC 9393 §2.7)
// ---------------------------------------------------------------------------

/// `link-entry` — a relationship link in a CoSWID tag.
///
/// CDDL:
/// ```text
/// link-entry = {
///   ? artifact: 37 => text,
///   href: 38 => any-uri,
///   ? media: 10 => text,
///   ? ownership: 39 => $ownership,
///   rel: 40 => $rel,
///   ? media-type: 41 => text,
///   ? use: 42 => $use,
/// }
/// ```
#[derive(Clone, Debug, PartialEq, CborSerialize, CborDeserialize)]
pub struct SwidLink {
    /// `media` (key 10): optional media query hint.
    #[cbor(key = 10, optional)]
    pub media: Option<String>,

    /// `artifact` (key 37): optional artifact path.
    #[cbor(key = 37, optional)]
    pub artifact: Option<String>,

    /// `href` (key 38): URI reference.
    #[cbor(key = 38)]
    pub href: String,

    /// `ownership` (key 39): optional ownership type.
    #[cbor(key = 39, optional)]
    pub ownership: Option<i64>,

    /// `rel` (key 40): relationship type.
    #[cbor(key = 40)]
    pub rel: i64,

    /// `media-type` (key 41): optional media type hint.
    #[cbor(key = 41, optional)]
    pub media_type: Option<String>,

    /// `use` (key 42): optional use type.
    #[cbor(key = 42, optional)]
    pub use_: Option<i64>,
}

impl Validate for SwidLink {
    fn valid(&self) -> Result<(), String> {
        if self.href.is_empty() {
            return Err("href must not be empty".into());
        }
        Ok(())
    }
}

impl SwidLink {
    /// Create a new link with the given href and rel.
    pub fn new(href: impl Into<String>, rel: i64) -> Self {
        Self {
            media: None,
            artifact: None,
            href: href.into(),
            ownership: None,
            rel,
            media_type: None,
            use_: None,
        }
    }
}
