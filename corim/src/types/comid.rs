// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! `concise-mid-tag` (CoMID) type.

use corim_macros::{CborDeserialize, CborSerialize};

use super::common::{EntityMap, LinkedTagMap, TagIdentity};
use super::triples::TriplesMap;
use crate::Validate;

// ---------------------------------------------------------------------------
// concise-mid-tag  { language: 0, tag-identity: 1, entities: 2,
//                    linked-tags: 3, triples: 4 }
// ---------------------------------------------------------------------------

/// `concise-mid-tag` — a CoMID tag containing triples.
#[derive(Clone, Debug, PartialEq, CborSerialize, CborDeserialize)]
pub struct ComidTag {
    /// `language` (key 0): optional BCP 47 language tag.
    #[cbor(key = 0, optional)]
    pub language: Option<String>,

    /// `tag-identity` (key 1): identifies this CoMID.
    #[cbor(key = 1)]
    pub tag_identity: TagIdentity,

    /// `entities` (key 2): optional list of entities.
    #[cbor(key = 2, optional)]
    pub entities: Option<Vec<EntityMap>>,

    /// `linked-tags` (key 3): optional references to other tags.
    #[cbor(key = 3, optional)]
    pub linked_tags: Option<Vec<LinkedTagMap>>,

    /// `triples` (key 4): the measurement triples.
    #[cbor(key = 4)]
    pub triples: TriplesMap,
}

impl Validate for ComidTag {
    fn valid(&self) -> Result<(), String> {
        // Validate triples
        self.triples
            .valid()
            .map_err(|e| format!("triples validation failed: {e}"))?;

        // Validate entities if present
        if let Some(ref entities) = self.entities {
            if entities.is_empty() {
                return Err("entities list must not be empty".into());
            }
        }

        // Validate linked-tags if present
        if let Some(ref linked) = self.linked_tags {
            if linked.is_empty() {
                return Err("linked-tags list must not be empty".into());
            }
        }

        Ok(())
    }
}
