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
//! Two kinds of node get named:
//!
//! - **Map keys** — `measurement-values-map` etc. become
//!   `{ "svn": ... }` instead of `{ "1": ... }`.
//! - **Triple records** — positional CBOR arrays in the wire format
//!   (`reference-triple = [ref-env, ref-claims]`) are emitted as labeled
//!   objects (`{ "ref-env": ..., "ref-claims": ... }`) using the CDDL
//!   field names. On the `generate` (prose -> integer) path both the
//!   labeled-object form and the legacy positional-array form are
//!   accepted and lowered back to the positional array the wire format
//!   requires. Digest pairs (`[alg, val]`) stay positional.
//!
//! # Symmetry
//!
//! The walk is bidirectional: [`to_int_keys`] rewrites prose -> integer
//! (used by `generate`), and [`to_prose_keys`] rewrites integer -> prose
//! (used by `convert`). Both share one schema, so a template round-trips
//! through the core crate exactly — `convert` -> `generate` reproduces
//! the original bytes. Unknown keys (e.g. profile-specific
//! `measurement-values-map` extensions such as `tcbstatus`) pass through
//! untouched, so profile alias resolution can run afterwards.

use serde_json::{Map, Value};

use corim::cbor::value::Value as CborValue;

/// `oid` type-choice tag (RFC 8949 §3.4). Wraps a bare `bstr`.
const TAG_OID: u64 = 111;
/// `key-thumbprint` type-choice tag (RFC 9052 / CoRIM §D). Wraps a
/// digest `[alg, bstr]`.
const TAG_KEY_THUMBPRINT: u64 = 557;
/// `cose-key` type-choice tag. Wraps a bare `bstr` (encoded COSE_Key).
const TAG_COSE_KEY: u64 = 558;
/// `cert-thumbprint` type-choice tag. Wraps a digest `[alg, bstr]`.
const TAG_CERT_THUMBPRINT: u64 = 559;
/// `cert-path-thumbprint` type-choice tag. Wraps a digest `[alg, bstr]`.
const TAG_CERT_PATH_THUMBPRINT: u64 = 561;
/// `pkix-asn1der-cert` type-choice tag. Wraps a bare `bstr` (DER cert).
const TAG_PKIX_ASN1DER_CERT: u64 = 562;
/// `masked-raw-value` type-choice tag. Wraps `[value: bstr, mask: bstr]`.
const TAG_MASKED_RAW_VALUE: u64 = 563;

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

/// A named field in a positional record ([`Shape::Record`]). `optional`
/// marks a trailing element that may be absent (all optional fields in
/// the CoRIM CDDL records are trailing).
#[derive(Clone, Copy)]
struct Field {
    name: &'static str,
    slot: Slot,
    optional: bool,
}

const fn field(name: &'static str, slot: Slot) -> Field {
    Field {
        name,
        slot,
        optional: false,
    }
}

const fn opt_field(name: &'static str, slot: Slot) -> Field {
    Field {
        name,
        slot,
        optional: true,
    }
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
    Digest,
    // --- CoRIM-level and CoSWID/CoTL maps and records ---
    Validity,
    Locator,
    Coswid,
    SwidEntity,
    SwidLink,
    Cotl,
    // integrity-registers: `{ id => [digest+] }` (arbitrary id keys).
    IntegrityRegisters,
    // a locator thumbprint: a single digest `[alg, bstr]` or a list of
    // such digests (disambiguated at coerce time).
    DigestOrList,
    // --- a bare `bstr` leaf: base64 text on input, coerced to CBOR
    //     bytes by `coerce_bytes` (the core JSON layer cannot express
    //     bare byte strings, only base64 text).
    Bytes,
    // --- pass-through (text/int/type-choice objects) ---
    Leaf,
}

/// How to interpret a node at a given context.
enum Shape {
    /// A CBOR map: `(integer key, prose name, child slot)` entries.
    /// Keys not listed pass through unchanged (recursed as `Leaf`).
    Map(&'static [(i64, &'static str, Slot)]),
    /// A positional array with **named** fields (a CoRIM triple record).
    /// On the `convert` (integer -> prose) path it is emitted as a
    /// labeled object; on the `generate` (prose -> integer) path both the
    /// labeled-object form and the legacy positional-array form are
    /// accepted and lowered back to a positional array.
    Record(&'static [Field]),
    /// A positional array with unnamed elements (e.g. a digest
    /// `[alg, val]`). Element `i` uses `slots[i]`; elements beyond the
    /// listed slots pass through as `Leaf`. Stays positional in both
    /// directions.
    Tuple(&'static [Slot]),
    /// A map with arbitrary keys whose every value is a list of digests
    /// (`integrity-registers`). Keys pass through unchanged.
    DigestListMap,
    /// A bare `bstr` leaf: a base64 string that [`coerce_bytes`] turns
    /// into CBOR bytes. Treated as a plain leaf during key rewriting.
    Bytes,
    /// A leaf node: returned unchanged.
    Leaf,
}

/// Direction of the rewrite.
#[derive(Clone, Copy, PartialEq)]
enum Dir {
    /// prose name -> integer-string key.
    ToInt,
    /// integer-string key -> prose name.
    ToProse,
}

/// The top-level template value kind a prose walk starts from. Selects
/// which CDDL root context the converter/coercer begins in.
#[derive(Clone, Copy)]
pub enum Root {
    /// A decoded `concise-mid-tag` (CoMID).
    Comid,
    /// A CoRIM `entity-map`.
    Entity,
    /// A CoRIM `corim-locator-map` (dependent-rims entry).
    Locator,
    /// A `concise-swid-tag` (CoSWID).
    Coswid,
    /// A `concise-tl-tag` (CoTL).
    Cotl,
    /// A CoRIM `validity-map` (`rim-validity` / `tl-validity`).
    Validity,
    /// A scalar type-choice (e.g. `corim-id`, `profile`). No prose keys;
    /// only the universal tag-driven byte coercion applies.
    Scalar,
}

fn root_ctx(root: Root) -> Ctx {
    match root {
        Root::Comid => Ctx::Comid,
        Root::Entity => Ctx::Entity,
        Root::Locator => Ctx::Locator,
        Root::Coswid => Ctx::Coswid,
        Root::Cotl => Ctx::Cotl,
        Root::Validity => Ctx::Validity,
        Root::Scalar => Ctx::Leaf,
    }
}

/// Rewrite a JSON tree from prose keys to integer-string keys for the
/// given root kind, so it can be handed to the core JSON layer.
pub fn to_int_keys(value: &Value, root: Root) -> Value {
    convert(value, root_ctx(root), Dir::ToInt)
}

/// Coerce base64 text at bare-`bstr` positions of a decoded CBOR value
/// into byte strings, starting from the given root kind.
///
/// The core `corim::json` layer maps every JSON string to CBOR text, so
/// bare `bstr` fields (digest values, `ueid`, `uuid`, `mac-addr`,
/// `ip-addr`, integrity-register digests) arrive as `Value::Text(base64)`
/// and fail to deserialize. This walks the value tree with the same
/// context schema used for key rewriting and, at each `bstr` position,
/// base64-decodes the text into `Value::Bytes`. It also decodes the
/// inner bytes of type-choice tags the core layer leaves as text
/// (`oid`, `cose-key`, thumbprints, `masked-raw-value`, DER certs).
///
/// Call this on the CBOR value produced by `corim::json::json_to_value`
/// before `corim::cbor::value::from_value`.
pub fn coerce_bytes(value: &mut CborValue, root: Root) {
    coerce(value, root_ctx(root));
}

/// Rewrite a JSON tree (as emitted by `corim::json::value_to_json`) from
/// integer-string keys to prose keys for the given root kind. Inverse of
/// [`to_int_keys`]; used by the `convert` command to emit
/// generate-ready templates.
pub fn to_prose_keys(value: &Value, root: Root) -> Value {
    convert(value, root_ctx(root), Dir::ToProse)
}

fn convert(v: &Value, ctx: Ctx, dir: Dir) -> Value {
    match shape(ctx) {
        // `Bytes` leaves carry a base64 string through key rewriting
        // unchanged; the JSON->CBOR byte coercion happens later in
        // `coerce_bytes`, which operates on the CBOR value tree.
        // `DigestListMap` has arbitrary (register-id) keys and no prose
        // to rewrite, so it likewise passes through untouched here.
        Shape::Leaf | Shape::Bytes | Shape::DigestListMap => v.clone(),
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
        Shape::Record(fields) => match dir {
            // integer -> prose: emit a labeled object, one entry per
            // present array element (absent trailing optionals are
            // simply omitted).
            Dir::ToProse => {
                let arr = match v {
                    Value::Array(a) => a,
                    // Already a labeled object (idempotent) or unexpected.
                    _ => return v.clone(),
                };
                let mut out = Map::new();
                for (i, f) in fields.iter().enumerate() {
                    if let Some(e) = arr.get(i) {
                        out.insert(f.name.to_string(), convert_slot(e, f.slot, dir));
                    }
                }
                Value::Object(out)
            }
            // prose -> integer: accept either the labeled-object form or
            // the legacy positional-array form; lower both to an array.
            Dir::ToInt => match v {
                Value::Object(obj) => {
                    let mut arr = Vec::new();
                    for f in fields {
                        match obj.get(f.name) {
                            Some(e) => arr.push(convert_slot(e, f.slot, dir)),
                            // Trailing optional omitted: stop emitting.
                            None if f.optional => {}
                            // Required field missing: keep positions
                            // aligned with a null so the downstream
                            // decode reports a precise error.
                            None => arr.push(Value::Null),
                        }
                    }
                    Value::Array(arr)
                }
                Value::Array(a) => Value::Array(
                    a.iter()
                        .enumerate()
                        .map(|(i, e)| {
                            let slot = fields.get(i).map(|f| f.slot).unwrap_or(one(Ctx::Leaf));
                            convert_slot(e, slot, dir)
                        })
                        .collect(),
                ),
                _ => v.clone(),
            },
        },
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

/// Recursively coerce base64 text into bytes at `bstr` positions of a
/// decoded CoMID CBOR value. Mirrors [`convert`] but operates on the
/// CBOR value tree (integer keys) and only rewrites `Bytes` leaves.
fn coerce(v: &mut CborValue, ctx: Ctx) {
    // Universal tag-driven coercion. Several type-choice tags wrap byte
    // strings that the core JSON layer emits as base64 text (via the
    // `{ "type": ..., "value": ... }` form) but does not decode back to
    // bytes on input. Handle them here regardless of schema context, so
    // crypto keys, OIDs, COSE keys, DER certs and masked raw values work
    // wherever they appear.
    if let CborValue::Tag(t, inner) = v {
        match *t {
            // Digest-bearing thumbprints: inner is `[alg, bstr]`.
            TAG_KEY_THUMBPRINT | TAG_CERT_THUMBPRINT | TAG_CERT_PATH_THUMBPRINT => {
                coerce(inner, Ctx::Digest);
                return;
            }
            // Bare-`bstr`-bearing type-choices: inner is a base64 text.
            TAG_OID | TAG_COSE_KEY | TAG_PKIX_ASN1DER_CERT => {
                coerce(inner, Ctx::Bytes);
                return;
            }
            // masked-raw-value: inner is `[value: bstr, mask: bstr]`.
            TAG_MASKED_RAW_VALUE => {
                if let CborValue::Array(a) = inner.as_mut() {
                    for e in a.iter_mut() {
                        coerce(e, Ctx::Bytes);
                    }
                }
                return;
            }
            _ => {}
        }
    }
    match shape(ctx) {
        Shape::Leaf => {}
        Shape::Bytes => {
            if let CborValue::Text(s) = v {
                if let Some(bytes) = base64_decode(s) {
                    *v = CborValue::Bytes(bytes);
                }
            }
        }
        Shape::DigestListMap => {
            // `{ id => [digest+] }`: coerce every digest in every value.
            if let CborValue::Map(m) = v {
                for (_k, val) in m.iter_mut() {
                    if let CborValue::Array(ds) = val {
                        for d in ds.iter_mut() {
                            coerce(d, Ctx::Digest);
                        }
                    }
                }
            }
        }
        Shape::Map(entries) => {
            if let CborValue::Map(m) = v {
                for (k, val) in m.iter_mut() {
                    let CborValue::Integer(ki) = k else { continue };
                    let Ok(ki) = i64::try_from(*ki) else { continue };
                    if let Some(slot) = entries
                        .iter()
                        .find(|(ek, _, _)| *ek == ki)
                        .map(|(_, _, s)| *s)
                    {
                        coerce_slot(val, slot);
                    }
                }
            }
        }
        Shape::Tuple(slots) => {
            if let CborValue::Array(a) = v {
                for (i, e) in a.iter_mut().enumerate() {
                    let slot = slots.get(i).copied().unwrap_or(one(Ctx::Leaf));
                    coerce_slot(e, slot);
                }
            }
        }
        Shape::Record(fields) => {
            // By the time `coerce` runs, `to_int_keys` has already lowered
            // any labeled object to a positional array, so treat a record
            // like a tuple keyed by field position.
            if let CborValue::Array(a) = v {
                for (i, e) in a.iter_mut().enumerate() {
                    let slot = fields.get(i).map(|f| f.slot).unwrap_or(one(Ctx::Leaf));
                    coerce_slot(e, slot);
                }
            }
        }
    }
}

fn coerce_slot(v: &mut CborValue, slot: Slot) {
    // A `DigestOrList` slot is a single digest `[alg, bstr]` or a list of
    // such digests. Disambiguate: if the first element is an integer
    // (the alg), it is a single digest; otherwise a list.
    if let Ctx::DigestOrList = slot.ctx {
        if let CborValue::Array(a) = v {
            let single = matches!(a.first(), Some(CborValue::Integer(_)));
            if single {
                coerce(v, Ctx::Digest);
            } else {
                for e in a.iter_mut() {
                    coerce(e, Ctx::Digest);
                }
            }
        }
        return;
    }
    if slot.list {
        if let CborValue::Array(items) = v {
            for e in items.iter_mut() {
                coerce(e, slot.ctx);
            }
            return;
        }
    }
    coerce(v, slot.ctx);
}

/// Decode standard (padded) base64, matching the encoding emitted by
/// `corim::json::to_json` for byte strings. Returns `None` on malformed
/// input, in which case the caller leaves the value as text (and the
/// downstream decode reports a precise type error).
fn base64_decode(s: &str) -> Option<Vec<u8>> {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD.decode(s).ok()
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
        // -- positional triple records (named-field arrays) --
        // reference-triple = [ref-env, ref-claims]
        Ctx::ReferenceTriple => Shape::Record(REFERENCE_TRIPLE),
        // endorsed-triple = [condition, endorsement]
        Ctx::EndorsedTriple => Shape::Record(ENDORSED_TRIPLE),
        // stateful-environment = [environment, claims-list]
        Ctx::StatefulEnvRecord => Shape::Record(STATEFUL_ENV),
        // identity / attest-key = [environment, key-list, ?conditions]
        Ctx::IdentityTriple | Ctx::AttestKeyTriple => Shape::Record(KEY_TRIPLE),
        // dependency = [domain-id, trustees]
        Ctx::DomainDependency => Shape::Record(DOMAIN_DEPENDENCY),
        // membership = [domain-id, members]
        Ctx::DomainMembership => Shape::Record(DOMAIN_MEMBERSHIP),
        // coswid = [environment, tag-ids]
        Ctx::CoswidTriple => Shape::Record(COSWID_TRIPLE),
        // ces = [condition, series]
        Ctx::CesTriple => Shape::Record(CES_TRIPLE),
        // ces-condition = [environment, claims-list, ?authorized-by]
        Ctx::CesCondition => Shape::Record(CES_CONDITION),
        // ces-record = [selection, addition]
        Ctx::CesRecord => Shape::Record(CES_RECORD),
        // conditional-endorsement = [conditions, endorsements]
        Ctx::CondEndorseTriple => Shape::Record(COND_ENDORSE),
        // digest = [alg (int/text), bstr] — stays positional
        Ctx::Digest => Shape::Tuple(DIGEST),
        Ctx::Bytes => Shape::Bytes,
        // integrity-registers = { id => [digest+] }
        Ctx::IntegrityRegisters => Shape::DigestListMap,
        // a locator thumbprint: single digest or list of digests.
        Ctx::DigestOrList => Shape::Leaf,
        // -- CoRIM-level maps --
        Ctx::Validity => Shape::Map(VALIDITY),
        Ctx::Locator => Shape::Map(LOCATOR),
        // -- CoSWID / CoTL --
        Ctx::Coswid => Shape::Map(COSWID),
        Ctx::SwidEntity => Shape::Map(SWID_ENTITY),
        Ctx::SwidLink => Shape::Map(SWID_LINK),
        Ctx::Cotl => Shape::Map(COTL),
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
    (2, "digests", many(Ctx::Digest)),
    (3, "flags", one(Ctx::Flags)),
    (4, "raw-value", one(Ctx::Leaf)),
    (6, "mac-addr", one(Ctx::Bytes)),
    (7, "ip-addr", one(Ctx::Bytes)),
    (8, "serial-number", one(Ctx::Leaf)),
    (9, "ueid", one(Ctx::Bytes)),
    (10, "uuid", one(Ctx::Bytes)),
    (11, "name", one(Ctx::Leaf)),
    (13, "cryptokeys", many(Ctx::Leaf)),
    (14, "integrity-registers", one(Ctx::IntegrityRegisters)),
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

// --- positional record schemas (named fields, per CDDL) ---

const REFERENCE_TRIPLE: &[Field] = &[
    field("ref-env", one(Ctx::Environment)),
    field("ref-claims", many(Ctx::Measurement)),
];
const ENDORSED_TRIPLE: &[Field] = &[
    field("condition", one(Ctx::Environment)),
    field("endorsement", many(Ctx::Measurement)),
];
const STATEFUL_ENV: &[Field] = &[
    field("environment", one(Ctx::Environment)),
    field("claims-list", many(Ctx::Measurement)),
];
const KEY_TRIPLE: &[Field] = &[
    field("environment", one(Ctx::Environment)),
    field("key-list", many(Ctx::Leaf)),
    opt_field("conditions", one(Ctx::KeyTripleConditions)),
];
const DOMAIN_DEPENDENCY: &[Field] = &[
    field("domain-id", one(Ctx::Environment)),
    field("trustees", many(Ctx::Environment)),
];
const DOMAIN_MEMBERSHIP: &[Field] = &[
    field("domain-id", one(Ctx::Environment)),
    field("members", many(Ctx::Environment)),
];
const COSWID_TRIPLE: &[Field] = &[
    field("environment", one(Ctx::Environment)),
    field("tag-ids", many(Ctx::Leaf)),
];
const CES_TRIPLE: &[Field] = &[
    field("condition", one(Ctx::CesCondition)),
    field("series", many(Ctx::CesRecord)),
];
const CES_CONDITION: &[Field] = &[
    field("environment", one(Ctx::Environment)),
    field("claims-list", many(Ctx::Measurement)),
    opt_field("authorized-by", many(Ctx::Leaf)),
];
const CES_RECORD: &[Field] = &[
    field("selection", many(Ctx::Measurement)),
    field("addition", many(Ctx::Measurement)),
];
const COND_ENDORSE: &[Field] = &[
    field("conditions", many(Ctx::StatefulEnvRecord)),
    field("endorsements", many(Ctx::EndorsedTriple)),
];

// digest = [alg, val] — stays positional (unnamed).
const DIGEST: &[Slot] = &[one(Ctx::Leaf), one(Ctx::Bytes)];

// -- CoRIM-level and CoSWID/CoTL schemas --

const VALIDITY: &[(i64, &str, Slot)] = &[
    (0, "not-before", one(Ctx::Leaf)),
    (1, "not-after", one(Ctx::Leaf)),
];

const LOCATOR: &[(i64, &str, Slot)] = &[
    (0, "href", one(Ctx::Leaf)),
    (1, "thumbprint", one(Ctx::DigestOrList)),
];

const COSWID: &[(i64, &str, Slot)] = &[
    (0, "tag-id", one(Ctx::Leaf)),
    (1, "software-name", one(Ctx::Leaf)),
    (2, "entity", many(Ctx::SwidEntity)),
    (4, "link", many(Ctx::SwidLink)),
    (8, "corpus", one(Ctx::Leaf)),
    (9, "patch", one(Ctx::Leaf)),
    (11, "supplemental", one(Ctx::Leaf)),
    (12, "tag-version", one(Ctx::Leaf)),
    (13, "software-version", one(Ctx::Leaf)),
    (14, "version-scheme", one(Ctx::Leaf)),
    (15, "lang", one(Ctx::Leaf)),
];

const SWID_ENTITY: &[(i64, &str, Slot)] = &[
    (31, "entity-name", one(Ctx::Leaf)),
    (32, "reg-id", one(Ctx::Leaf)),
    (33, "role", one(Ctx::Leaf)),
    (34, "thumbprint", one(Ctx::Digest)),
];

const SWID_LINK: &[(i64, &str, Slot)] = &[
    (10, "media", one(Ctx::Leaf)),
    (37, "artifact", one(Ctx::Leaf)),
    (38, "href", one(Ctx::Leaf)),
    (39, "ownership", one(Ctx::Leaf)),
    (40, "rel", one(Ctx::Leaf)),
    (41, "media-type", one(Ctx::Leaf)),
    (42, "use", one(Ctx::Leaf)),
];

const COTL: &[(i64, &str, Slot)] = &[
    (0, "tag-identity", one(Ctx::TagIdentity)),
    (1, "tags-list", many(Ctx::TagIdentity)),
    (2, "tl-validity", one(Ctx::Validity)),
];

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    /// A prose CoMID with a CES triple round-trips to integer keys and
    /// back to the same prose. The canonical prose form uses **labeled**
    /// records (`condition`/`series`/`selection`/`addition`).
    #[test]
    fn prose_int_prose_round_trip() {
        let prose = json!({
            "tag-identity": { "id": "example-ndpa" },
            "triples": {
                "conditional-endorsement-series-triples": [
                    {
                        "condition": {
                            "environment": { "class": { "vendor": "Microsoft" } },
                            "claims-list": []
                        },
                        "series": [
                            {
                                "selection": [
                                    { "key": 20, "value": { "svn": { "type": "min-svn", "value": 1 } } }
                                ],
                                "addition": [ { "value": { "-700": "UpToDate" } } ]
                            }
                        ]
                    }
                ]
            }
        });

        let ints = to_int_keys(&prose, Root::Comid);
        // Structural keys became integer strings.
        assert!(ints.get("1").is_some(), "tag-identity -> 1");
        assert!(ints.get("4").is_some(), "triples -> 4");
        assert_eq!(ints["1"]["0"], "example-ndpa", "id -> 0");

        // Round-trip back to prose equals the original.
        let back = to_prose_keys(&ints, Root::Comid);
        assert_eq!(back, prose, "prose -> int -> prose must be identity");
    }

    /// The legacy positional-array record form is still accepted on the
    /// `to_int_keys` (generate) path and lowers to the same integer tree
    /// as the labeled form.
    #[test]
    fn legacy_positional_records_still_accepted() {
        let positional = json!({
            "tag-identity": { "id": "x" },
            "triples": {
                "conditional-endorsement-series-triples": [
                    [
                        [ { "class": { "vendor": "Microsoft" } }, [] ],
                        [ [ [ { "value": { "svn": { "type": "min-svn", "value": 1 } } } ],
                            [ { "value": { "-700": "UpToDate" } } ] ] ]
                    ]
                ]
            }
        });
        let labeled = json!({
            "tag-identity": { "id": "x" },
            "triples": {
                "conditional-endorsement-series-triples": [
                    {
                        "condition": {
                            "environment": { "class": { "vendor": "Microsoft" } },
                            "claims-list": []
                        },
                        "series": [
                            {
                                "selection": [ { "value": { "svn": { "type": "min-svn", "value": 1 } } } ],
                                "addition": [ { "value": { "-700": "UpToDate" } } ]
                            }
                        ]
                    }
                ]
            }
        });
        assert_eq!(
            to_int_keys(&positional, Root::Comid),
            to_int_keys(&labeled, Root::Comid),
            "positional and labeled forms must lower to the same integer tree"
        );
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
        let ints = to_int_keys(&prose, Root::Comid);
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
        let ti_ints = to_int_keys(&ti, Root::Comid);
        assert_eq!(ti_ints["1"]["1"], "2", "tag-identity.version -> 1");

        let mv = json!({
            "tag-identity": { "id": "x" },
            "triples": { "reference-triples": [
                [ { "class": { "vendor": "V" } },
                  [ { "value": { "version": { "version": "1.0", "version-scheme": 1 } } } ] ]
            ] }
        });
        let mv_ints = to_int_keys(&mv, Root::Comid);
        // mval.version -> 0, and nested version-map.version -> 0 too.
        let vmap = &mv_ints["4"]["0"][0][1][0]["1"]["0"];
        assert_eq!(vmap["0"], "1.0", "version-map.version -> 0");
    }

    /// `coerce_bytes` turns base64 text into CBOR bytes at bare-`bstr`
    /// positions (here a digest value) while leaving the alg integer and
    /// surrounding structure intact.
    #[test]
    fn coerce_bytes_decodes_digest_value() {
        // Build the int-keyed CoMID and convert to a CBOR value.
        let prose = json!({
            "tag-identity": { "id": "c1" },
            "triples": { "reference-triples": [
                [ { "class": { "vendor": "ACME" } },
                  [ { "value": { "digests": [ [ 7, "3q2+7w==" ] ] } } ] ]
            ] }
        });
        let ints = to_int_keys(&prose, Root::Comid);
        let mut cbor_val = corim::json::json_to_value(&ints);
        coerce_bytes(&mut cbor_val, Root::Comid);

        // Navigate: comid[4 triples][0 ref-triples][0][1 measurements][0]
        //           [1 value][2 digests][0][1 digest-val]
        let CborValue::Map(comid) = &cbor_val else {
            panic!("comid must be a map")
        };
        let triples = map_get(comid, 4).expect("triples");
        let ref_triples = arr_get(triples_key(triples, 0), 0);
        let measurements = arr_get(ref_triples, 1);
        let meas0 = arr_get(measurements, 0);
        let CborValue::Map(meas) = meas0 else {
            panic!("measurement must be a map")
        };
        let value = map_get(meas, 1).expect("mval");
        let CborValue::Map(mval) = value else {
            panic!("mval must be a map")
        };
        let digests = map_get(mval, 2).expect("digests");
        let digest0 = arr_get(digests, 0);
        let digest_val = arr_get(digest0, 1);
        assert_eq!(
            digest_val,
            &CborValue::Bytes(vec![0xde, 0xad, 0xbe, 0xef]),
            "digest val must be coerced to bytes"
        );
    }

    // -- small helpers for navigating a CBOR value in tests --
    fn map_get(m: &[(CborValue, CborValue)], key: i64) -> Option<&CborValue> {
        m.iter().find_map(|(k, v)| match k {
            CborValue::Integer(n) if *n == key as i128 => Some(v),
            _ => None,
        })
    }
    fn arr_get(v: &CborValue, i: usize) -> &CborValue {
        match v {
            CborValue::Array(a) => &a[i],
            _ => panic!("expected array"),
        }
    }
    fn triples_key(v: &CborValue, key: i64) -> &CborValue {
        match v {
            CborValue::Map(m) => map_get(m, key).expect("triple key"),
            _ => panic!("expected map"),
        }
    }
}
