// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Context-aware prose <-> integer-key rewriting for CoMID JSON templates.
//!
//! The core crate's `corim::json` layer maps CBOR integer map keys to
//! JSON string keys mechanically, without knowing *which* CDDL map it is
//! looking at. Because low keys (0..30) overlap across map types (e.g.
//! `"version"` is key 1 in `tag-identity-map` but key 0 in
//! `measurement-values-map`), that layer emits/accepts those keys as
//! numeric strings (`"1"`, `"4"`, ...).
//!
//! This module lets a human author a CoMID template with **named** keys
//! (`"tag-identity"`, `"triples"`, `"vendor"`, `"svn"`, ...) by walking
//! the CoMID tree with an explicit context state machine that knows, at
//! every node, which CDDL map or positional record it is looking at.
//!
//! It is deliberately scoped to `corim-cli`: the schema
//! below is a hand-maintained mirror of the CDDL key tables, kept out of
//! the core crate's public JSON API so that library JSON output is
//! unchanged.
//!
//! # Scope
//!
//! Only **map keys** are named. Triple records are positional CBOR
//! arrays in the wire format (`reference-triple = [environment,
//! [measurement]]`), and they stay positional arrays in the template —
//! but the converter recurses into them with the correct child context
//! so maps *nested inside* those arrays (environments, measurements,
//! mval) still get named keys.
//!
//! # Symmetry
//!
//! The walk is bidirectional: [`to_int_keys`] rewrites prose -> integer
//! (used by `generate`), and `to_prose_keys` rewrites integer -> prose.
//! Both share one schema, so a prose template round-trips through the
//! core crate's `to_json`/`from_json` exactly. Unknown keys (e.g.
//! profile-specific `measurement-values-map` extensions such as
//! `tcbstatus`) pass through untouched, so profile alias resolution can
//! run afterwards.

use serde_json::{Map, Value};

/// A child value's interpretation: its context, and whether the value is
/// a homogeneous array of that context (`list`) or a single node.
#[derive(Clone, Copy)]
struct Slot {
    list: bool,
    ctx: Ctx,
}

const fn one(ctx: Ctx) -> Slot {
    Slot { list: false, ctx }
}

const fn many(ctx: Ctx) -> Slot {
    Slot { list: true, ctx }
}

/// Every CDDL map or positional record the walker can be positioned at.
#[derive(Clone, Copy)]
enum Ctx {
    // --- maps ---
    Comid,
    TagIdentity,
    Triples,
    Environment,
    Class,
    Measurement,
    Mval,
    Version,
    Flags,
    Entity,
    LinkedTag,
    KeyTripleConditions,
    // --- positional records (arrays) ---
    ReferenceTriple,
    EndorsedTriple,
    IdentityTriple,
    AttestKeyTriple,
    DomainDependency,
    DomainMembership,
    CoswidTriple,
    CesTriple,
    CesCondition,
    CesRecord,
    CondEndorseTriple,
    StatefulEnvRecord,
    // --- pass-through (text/int/bytes/type-choice objects) ---
    Leaf,
}

/// How to interpret a node at a given context.
enum Shape {
    /// A CBOR map: `(integer key, prose name, child slot)` entries.
    /// Keys not listed pass through unchanged (recursed as `Leaf`).
    Map(&'static [(i64, &'static str, Slot)]),
    /// A positional array: element `i` uses `slots[i]`; elements beyond
    /// the listed slots pass through as `Leaf`.
    Tuple(&'static [Slot]),
    /// A leaf node: returned unchanged.
    Leaf,
}

/// Direction of the rewrite.
#[derive(Clone, Copy, PartialEq)]
enum Dir {
    /// prose name -> integer-string key.
    ToInt,
    /// integer-string key -> prose name. Only exercised by the symmetric
    /// round-trip tests; the `generate` path uses `ToInt`.
    #[cfg_attr(not(test), allow(dead_code))]
    ToProse,
}

/// Rewrite a CoMID JSON tree from prose keys to integer-string keys, so
/// it can be handed to `corim::json::from_json::<ComidTag>`.
pub fn to_int_keys(comid: &Value) -> Value {
    convert(comid, Ctx::Comid, Dir::ToInt)
}

/// Rewrite a CoMID JSON tree (as emitted by `corim::json::to_json`) from
/// integer-string keys to prose keys. Inverse of [`to_int_keys`].
#[cfg(test)]
pub fn to_prose_keys(comid: &Value) -> Value {
    convert(comid, Ctx::Comid, Dir::ToProse)
}

fn convert(v: &Value, ctx: Ctx, dir: Dir) -> Value {
    match shape(ctx) {
        Shape::Leaf => v.clone(),
        Shape::Map(entries) => {
            let obj = match v {
                Value::Object(o) => o,
                _ => return v.clone(),
            };
            let mut out = Map::new();
            for (k, val) in obj {
                match resolve(entries, k, dir) {
                    Some((new_key, slot)) => {
                        out.insert(new_key, convert_slot(val, slot, dir));
                    }
                    None => {
                        // Unknown key (e.g. profile mval alias); keep it
                        // and its value verbatim for later passes.
                        out.insert(k.clone(), val.clone());
                    }
                }
            }
            Value::Object(out)
        }
        Shape::Tuple(slots) => {
            let arr = match v {
                Value::Array(a) => a,
                _ => return v.clone(),
            };
            Value::Array(
                arr.iter()
                    .enumerate()
                    .map(|(i, e)| {
                        let slot = slots.get(i).copied().unwrap_or(one(Ctx::Leaf));
                        convert_slot(e, slot, dir)
                    })
                    .collect(),
            )
        }
    }
}

fn convert_slot(v: &Value, slot: Slot, dir: Dir) -> Value {
    if slot.list {
        if let Value::Array(items) = v {
            return Value::Array(items.iter().map(|e| convert(e, slot.ctx, dir)).collect());
        }
    }
    convert(v, slot.ctx, dir)
}

/// Resolve an incoming object key to its rewritten form and the child
/// slot to recurse with. Returns `None` when the key is not part of this
/// context's schema (the caller passes it through unchanged).
fn resolve(
    entries: &'static [(i64, &'static str, Slot)],
    key: &str,
    dir: Dir,
) -> Option<(String, Slot)> {
    match dir {
        Dir::ToInt => {
            if let Some((k, _, slot)) = entries.iter().find(|(_, name, _)| *name == key) {
                return Some((k.to_string(), *slot));
            }
            // Already an integer key: keep it, but recover the child slot
            // so nested prose still resolves.
            if let Ok(ki) = key.parse::<i64>() {
                let slot = entries
                    .iter()
                    .find(|(k, _, _)| *k == ki)
                    .map(|(_, _, s)| *s)
                    .unwrap_or(one(Ctx::Leaf));
                return Some((key.to_string(), slot));
            }
            None
        }
        Dir::ToProse => {
            if let Ok(ki) = key.parse::<i64>() {
                if let Some((_, name, slot)) = entries.iter().find(|(k, _, _)| *k == ki) {
                    return Some((name.to_string(), *slot));
                }
                // Unknown integer key: keep the integer string.
                return Some((key.to_string(), one(Ctx::Leaf)));
            }
            // Already a prose name.
            if let Some((_, name, slot)) = entries.iter().find(|(_, n, _)| *n == key) {
                return Some((name.to_string(), *slot));
            }
            None
        }
    }
}

/// The hand-maintained schema mirroring the CDDL key tables. Kept in one
/// place so the mapping is auditable against
/// `corim/src/json/key_maps.rs`.
fn shape(ctx: Ctx) -> Shape {
    match ctx {
        // -- concise-mid-tag --
        Ctx::Comid => Shape::Map(COMID),
        Ctx::TagIdentity => Shape::Map(TAG_IDENTITY),
        // -- triples-map --
        Ctx::Triples => Shape::Map(TRIPLES),
        // -- environment-map / class-map --
        Ctx::Environment => Shape::Map(ENVIRONMENT),
        Ctx::Class => Shape::Map(CLASS),
        // -- measurement-map / measurement-values-map --
        Ctx::Measurement => Shape::Map(MEASUREMENT),
        Ctx::Mval => Shape::Map(MVAL),
        Ctx::Version => Shape::Map(VERSION),
        Ctx::Flags => Shape::Map(FLAGS),
        Ctx::Entity => Shape::Map(ENTITY),
        Ctx::LinkedTag => Shape::Map(LINKED_TAG),
        Ctx::KeyTripleConditions => Shape::Map(KEY_TRIPLE_CONDITIONS),
        // -- positional triple records (arrays) --
        // reference / endorsed / stateful-env = [environment, [measurement]]
        Ctx::ReferenceTriple | Ctx::EndorsedTriple | Ctx::StatefulEnvRecord => {
            Shape::Tuple(ENV_AND_MEASUREMENTS)
        }
        // identity / attest-key = [environment, [crypto-key], ?conditions]
        Ctx::IdentityTriple | Ctx::AttestKeyTriple => Shape::Tuple(KEY_TRIPLE),
        // dependency / membership = [environment, [environment]]
        Ctx::DomainDependency | Ctx::DomainMembership => Shape::Tuple(ENV_AND_ENVS),
        // coswid = [environment, [tag-id]]
        Ctx::CoswidTriple => Shape::Tuple(ENV_AND_LEAVES),
        // ces = [condition, [record]]
        Ctx::CesTriple => Shape::Tuple(CES_TRIPLE),
        // ces-condition = [environment, [claim], ?authorized-by]
        Ctx::CesCondition => Shape::Tuple(CES_CONDITION),
        // ces-record = [[selection], [addition]]
        Ctx::CesRecord => Shape::Tuple(CES_RECORD),
        // conditional-endorsement = [[stateful-env], [endorsed-triple]]
        Ctx::CondEndorseTriple => Shape::Tuple(COND_ENDORSE),
        Ctx::Leaf => Shape::Leaf,
    }
}

// --- map schemas ---

const COMID: &[(i64, &str, Slot)] = &[
    (0, "lang", one(Ctx::Leaf)),
    (1, "tag-identity", one(Ctx::TagIdentity)),
    (2, "entities", many(Ctx::Entity)),
    (3, "linked-tags", many(Ctx::LinkedTag)),
    (4, "triples", one(Ctx::Triples)),
];

const TAG_IDENTITY: &[(i64, &str, Slot)] =
    &[(0, "id", one(Ctx::Leaf)), (1, "version", one(Ctx::Leaf))];

const TRIPLES: &[(i64, &str, Slot)] = &[
    (0, "reference-triples", many(Ctx::ReferenceTriple)),
    (1, "endorsed-triples", many(Ctx::EndorsedTriple)),
    (2, "identity-triples", many(Ctx::IdentityTriple)),
    (3, "attest-key-triples", many(Ctx::AttestKeyTriple)),
    (4, "dependency-triples", many(Ctx::DomainDependency)),
    (5, "membership-triples", many(Ctx::DomainMembership)),
    (6, "coswid-triples", many(Ctx::CoswidTriple)),
    (
        8,
        "conditional-endorsement-series-triples",
        many(Ctx::CesTriple),
    ),
    (
        10,
        "conditional-endorsement-triples",
        many(Ctx::CondEndorseTriple),
    ),
];

const ENVIRONMENT: &[(i64, &str, Slot)] = &[
    (0, "class", one(Ctx::Class)),
    (1, "instance", one(Ctx::Leaf)),
    (2, "group", one(Ctx::Leaf)),
];

const CLASS: &[(i64, &str, Slot)] = &[
    (0, "id", one(Ctx::Leaf)),
    (1, "vendor", one(Ctx::Leaf)),
    (2, "model", one(Ctx::Leaf)),
    (3, "layer", one(Ctx::Leaf)),
    (4, "index", one(Ctx::Leaf)),
];

const MEASUREMENT: &[(i64, &str, Slot)] = &[
    (0, "key", one(Ctx::Leaf)),
    (1, "value", one(Ctx::Mval)),
    (2, "authorized-by", many(Ctx::Leaf)),
];

const MVAL: &[(i64, &str, Slot)] = &[
    (0, "version", one(Ctx::Version)),
    (1, "svn", one(Ctx::Leaf)),
    (2, "digests", many(Ctx::Leaf)),
    (3, "flags", one(Ctx::Flags)),
    (4, "raw-value", one(Ctx::Leaf)),
    (6, "mac-addr", one(Ctx::Leaf)),
    (7, "ip-addr", one(Ctx::Leaf)),
    (8, "serial-number", one(Ctx::Leaf)),
    (9, "ueid", one(Ctx::Leaf)),
    (10, "uuid", one(Ctx::Leaf)),
    (11, "name", one(Ctx::Leaf)),
    (13, "cryptokeys", many(Ctx::Leaf)),
    (14, "integrity-registers", one(Ctx::Leaf)),
    (15, "int-range", one(Ctx::Leaf)),
];

const VERSION: &[(i64, &str, Slot)] = &[
    (0, "version", one(Ctx::Leaf)),
    (1, "version-scheme", one(Ctx::Leaf)),
];

const FLAGS: &[(i64, &str, Slot)] = &[
    (0, "is-configured", one(Ctx::Leaf)),
    (1, "is-secure", one(Ctx::Leaf)),
    (2, "is-recovery", one(Ctx::Leaf)),
    (3, "is-debug", one(Ctx::Leaf)),
    (4, "is-replay-protected", one(Ctx::Leaf)),
    (5, "is-integrity-protected", one(Ctx::Leaf)),
    (6, "is-runtime-meas", one(Ctx::Leaf)),
    (7, "is-immutable", one(Ctx::Leaf)),
    (8, "is-tcb", one(Ctx::Leaf)),
    (9, "is-confidentiality-protected", one(Ctx::Leaf)),
];

const ENTITY: &[(i64, &str, Slot)] = &[
    (0, "entity-name", one(Ctx::Leaf)),
    (1, "reg-id", one(Ctx::Leaf)),
    (2, "role", one(Ctx::Leaf)),
];

const LINKED_TAG: &[(i64, &str, Slot)] =
    &[(0, "target", one(Ctx::Leaf)), (1, "rel", one(Ctx::Leaf))];

const KEY_TRIPLE_CONDITIONS: &[(i64, &str, Slot)] = &[
    (0, "mkey", one(Ctx::Leaf)),
    (1, "authorized-by", many(Ctx::Leaf)),
];

// --- positional record schemas ---

const ENV_AND_MEASUREMENTS: &[Slot] = &[one(Ctx::Environment), many(Ctx::Measurement)];
const KEY_TRIPLE: &[Slot] = &[
    one(Ctx::Environment),
    many(Ctx::Leaf),
    one(Ctx::KeyTripleConditions),
];
const ENV_AND_ENVS: &[Slot] = &[one(Ctx::Environment), many(Ctx::Environment)];
const ENV_AND_LEAVES: &[Slot] = &[one(Ctx::Environment), many(Ctx::Leaf)];
const CES_TRIPLE: &[Slot] = &[one(Ctx::CesCondition), many(Ctx::CesRecord)];
const CES_CONDITION: &[Slot] = &[
    one(Ctx::Environment),
    many(Ctx::Measurement),
    many(Ctx::Leaf),
];
const CES_RECORD: &[Slot] = &[many(Ctx::Measurement), many(Ctx::Measurement)];
const COND_ENDORSE: &[Slot] = &[many(Ctx::StatefulEnvRecord), many(Ctx::EndorsedTriple)];

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    /// A prose CoMID with a CES triple round-trips to integer keys and
    /// back to the same prose.
    #[test]
    fn prose_int_prose_round_trip() {
        let prose = json!({
            "tag-identity": { "id": "example-ndpa" },
            "triples": {
                "conditional-endorsement-series-triples": [
                    [
                        [ { "class": { "vendor": "Microsoft" } }, [] ],
                        [
                            [
                                [ { "key": 20, "value": { "svn": { "type": "min-svn", "value": 1 } } } ],
                                [ { "value": { "-700": "UpToDate" } } ]
                            ]
                        ]
                    ]
                ]
            }
        });

        let ints = to_int_keys(&prose);
        // Structural keys became integer strings.
        assert!(ints.get("1").is_some(), "tag-identity -> 1");
        assert!(ints.get("4").is_some(), "triples -> 4");
        assert_eq!(ints["1"]["0"], "example-ndpa", "id -> 0");

        // Round-trip back to prose equals the original.
        let back = to_prose_keys(&ints);
        assert_eq!(back, prose, "prose -> int -> prose must be identity");
    }

    /// Unknown keys (profile mval aliases) pass through untouched so the
    /// profile alias pass can handle them.
    #[test]
    fn unknown_mval_key_passes_through() {
        let prose = json!({
            "tag-identity": { "id": "x" },
            "triples": {
                "reference-triples": [
                    [ { "class": { "vendor": "V" } }, [ { "value": { "tcbstatus": "UpToDate" } } ] ]
                ]
            }
        });
        let ints = to_int_keys(&prose);
        // mval is at [triples][0 ref-triple][1 measurements][0][1 value]
        let mval = &ints["4"]["0"][0][1][0]["1"];
        assert_eq!(
            mval["tcbstatus"], "UpToDate",
            "alias key preserved verbatim"
        );
    }

    /// The `version` collision is resolved by context: key 1 in
    /// tag-identity, key 0 in measurement-values-map.
    #[test]
    fn version_key_is_context_sensitive() {
        let ti = json!({ "tag-identity": { "id": "x", "version": "2" } });
        let ti_ints = to_int_keys(&ti);
        assert_eq!(ti_ints["1"]["1"], "2", "tag-identity.version -> 1");

        let mv = json!({
            "tag-identity": { "id": "x" },
            "triples": { "reference-triples": [
                [ { "class": { "vendor": "V" } },
                  [ { "value": { "version": { "version": "1.0", "version-scheme": 1 } } } ] ]
            ] }
        });
        let mv_ints = to_int_keys(&mv);
        // mval.version -> 0, and nested version-map.version -> 0 too.
        let vmap = &mv_ints["4"]["0"][0][1][0]["1"]["0"];
        assert_eq!(vmap["0"], "1.0", "version-map.version -> 0");
    }
}
