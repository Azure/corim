// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Integer → string key mapping tables for JSON serialization.
//!
//! Each table maps CBOR integer keys to JSON string keys matching
//! the CoRIM/CoMID/CoSWID JSON format and the CDDL key names.

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
