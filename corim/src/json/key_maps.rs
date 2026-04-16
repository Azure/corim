// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Integer → string key mapping tables for JSON serialization.
//!
//! Each table maps CBOR integer keys to JSON string keys matching
//! the CoRIM/CoMID/CoSWID JSON format and the CDDL key names.

#![allow(dead_code)]

#[allow(unused_imports)]
use crate::nostd_prelude::*;

/// Lookup a JSON string key for a given CBOR integer key.
///
/// Returns the string key if found in any registered map, or `None`.
pub(crate) fn int_to_string_key(key: i64) -> Option<&'static str> {
    // Search all tables; keys are globally unique across CoRIM/CoMID/CoSWID
    ALL_KEYS.iter().find(|(k, _)| *k == key).map(|(_, v)| *v)
}

/// Lookup a CBOR integer key for a given JSON string key.
pub(crate) fn string_to_int_key(key: &str) -> Option<i64> {
    ALL_KEYS.iter().find(|(_, v)| *v == key).map(|(k, _)| *k)
}

/// Combined key table — globally unique integer↔string mappings only.
///
/// Keys 0–30 are **not** included because they overlap across different
/// map types (corim-map, comid-tag, class-map, etc.). For those keys,
/// the value_conv module falls back to integer-as-string representation.
/// Keys 31+ are globally unique across CoRIM, CoMID, and CoSWID.
static ALL_KEYS: &[(i64, &str)] = &[
    // --- CoSWID entity-entry (RFC 9393 §2.6) — keys 31-34 ---
    (31, "entity-name"),
    (32, "reg-id"),
    (33, "role"),
    (34, "thumbprint"),
    // --- CoSWID link-entry (RFC 9393 §2.7) — keys 37-42 ---
    (37, "artifact"),
    (38, "href"),
    (39, "ownership"),
    (40, "rel"),
    (41, "media-type"),
    (42, "use"),
    // --- CoSWID software-meta-entry (RFC 9393 §2.8) — keys 43-57 ---
    (43, "activation-status"),
    (44, "channel-type"),
    (45, "colloquial-version"),
    (46, "description"),
    (47, "edition"),
    (48, "entitlement-data-required"),
    (49, "entitlement-key"),
    (50, "generator"),
    (51, "persistent-id"),
    (52, "product"),
    (53, "product-family"),
    (54, "revision"),
    (55, "summary"),
    (56, "unspsc-code"),
    (57, "unspsc-version"),
];

// ---- Context-aware key tables for overlapping key ranges ----

/// Key names for `corim-map`.
pub(crate) static CORIM_MAP_KEYS: &[(i64, &str)] = &[
    (0, "corim-id"),
    (1, "tags"),
    (2, "dependent-rims"),
    (3, "profile"),
    (4, "rim-validity"),
    (5, "entities"),
];

/// Key names for `concise-mid-tag` (CoMID).
pub(crate) static COMID_MAP_KEYS: &[(i64, &str)] = &[
    (0, "lang"),
    (1, "tag-identity"),
    (2, "entities"),
    (3, "linked-tags"),
    (4, "triples"),
];

/// Key names for `tag-identity-map`.
pub(crate) static TAG_IDENTITY_KEYS: &[(i64, &str)] = &[(0, "id"), (1, "version")];

/// Key names for `validity-map`.
pub(crate) static VALIDITY_MAP_KEYS: &[(i64, &str)] = &[(0, "not-before"), (1, "not-after")];

/// Key names for `entity-map` (CoRIM entity).
pub(crate) static ENTITY_MAP_KEYS: &[(i64, &str)] =
    &[(0, "entity-name"), (1, "reg-id"), (2, "role")];

/// Key names for `class-map`.
pub(crate) static CLASS_MAP_KEYS: &[(i64, &str)] = &[
    (0, "id"),
    (1, "vendor"),
    (2, "model"),
    (3, "layer"),
    (4, "index"),
];

/// Key names for `environment-map`.
pub(crate) static ENVIRONMENT_MAP_KEYS: &[(i64, &str)] =
    &[(0, "class"), (1, "instance"), (2, "group")];

/// Key names for `measurement-map`.
pub(crate) static MEASUREMENT_MAP_KEYS: &[(i64, &str)] =
    &[(0, "key"), (1, "value"), (2, "authorized-by")];

/// Key names for `measurement-values-map`.
pub(crate) static MVAL_MAP_KEYS: &[(i64, &str)] = &[
    (0, "version"),
    (1, "svn"),
    (2, "digests"),
    (3, "flags"),
    (4, "raw-value"),
    (6, "mac-addr"),
    (7, "ip-addr"),
    (8, "serial-number"),
    (9, "ueid"),
    (10, "uuid"),
    (11, "name"),
    (13, "cryptokeys"),
    (14, "integrity-registers"),
    (15, "int-range"),
];

/// Key names for `version-map`.
pub(crate) static VERSION_MAP_KEYS: &[(i64, &str)] = &[(0, "version"), (1, "version-scheme")];

/// Key names for `flags-map`.
pub(crate) static FLAGS_MAP_KEYS: &[(i64, &str)] = &[
    (0, "is-configured"),
    (1, "is-secure"),
    (2, "is-recovery"),
    (3, "is-debug"),
    (4, "is-replay-protected"),
    (5, "is-integrity-protected"),
    (6, "is-runtime-meas"),
    (7, "is-immutable"),
    (8, "is-tcb"),
    (9, "is-confidentiality-protected"),
];

/// Key names for `triples-map`.
pub(crate) static TRIPLES_MAP_KEYS: &[(i64, &str)] = &[
    (0, "reference-triples"),
    (1, "endorsed-triples"),
    (2, "identity-triples"),
    (3, "attest-key-triples"),
    (4, "dependency-triples"),
    (5, "membership-triples"),
    (6, "coswid-triples"),
    (8, "conditional-endorsement-series-triples"),
    (10, "conditional-endorsement-triples"),
];

/// Key names for `linked-tag-map`.
pub(crate) static LINKED_TAG_MAP_KEYS: &[(i64, &str)] = &[(0, "target"), (1, "rel")];

/// Key names for `corim-locator-map`.
pub(crate) static LOCATOR_MAP_KEYS: &[(i64, &str)] = &[(0, "href"), (1, "thumbprint")];

/// Key names for `corim-signer-map`.
pub(crate) static SIGNER_MAP_KEYS: &[(i64, &str)] = &[(0, "signer-name"), (1, "signer-uri")];

/// Key names for `corim-meta-map`.
pub(crate) static META_MAP_KEYS: &[(i64, &str)] = &[(0, "signer"), (1, "signature-validity")];

/// Key names for `concise-tl-tag` (CoTL).
pub(crate) static COTL_MAP_KEYS: &[(i64, &str)] =
    &[(0, "tag-identity"), (1, "tags-list"), (2, "tl-validity")];

/// Key names for `concise-swid-tag` (CoSWID).
pub(crate) static COSWID_MAP_KEYS: &[(i64, &str)] = &[
    (0, "tag-id"),
    (1, "software-name"),
    (2, "entity"),
    (4, "link"),
    (8, "corpus"),
    (9, "patch"),
    (11, "supplemental"),
    (12, "tag-version"),
    (13, "software-version"),
    (14, "version-scheme"),
    (15, "lang"),
];

/// Key names for CoSWID `entity-entry`.
pub(crate) static SWID_ENTITY_KEYS: &[(i64, &str)] = &[
    (31, "entity-name"),
    (32, "reg-id"),
    (33, "role"),
    (34, "thumbprint"),
];

/// Key names for CoSWID `link-entry`.
pub(crate) static SWID_LINK_KEYS: &[(i64, &str)] = &[
    (10, "media"),
    (37, "artifact"),
    (38, "href"),
    (39, "ownership"),
    (40, "rel"),
    (41, "media-type"),
    (42, "use"),
];

/// Key names for `conditions` map (identity/attest-key triple).
pub(crate) static KEY_TRIPLE_COND_KEYS: &[(i64, &str)] = &[(0, "mkey"), (1, "authorized-by")];
