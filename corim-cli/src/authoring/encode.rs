// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! `corim-cli generate` — build an unsigned CoRIM from a JSON template.
//!
//! The template is authored against the *decoded* CoMID type (not the
//! wire-format `corim-map`, whose CoMID tags are opaque bstr-wrapped
//! CBOR). Each entry in the template's `comids` array is:
//!
//! 1. Rewritten from **prose keys** (`"tag-identity"`, `"triples"`,
//!    `"vendor"`, `"svn"`, ...) to integer-string keys for the private
//!    semantic converter, using the context state machine in
//!    [`crate::prose`].
//! 2. Passed through profile mval alias resolution (`"tcbstatus"` ->
//!    `"-700"`).
//! 3. Converted to a CBOR value via the private semantic converter, then
//!    base64 text at bare-`bstr` positions (digest values, `ueid`,
//!    `uuid`, `mac-addr`, `ip-addr`) is coerced to CBOR bytes by
//!    [`crate::prose::coerce_bytes`] in schema-defined byte positions.
//! 4. Deserialized via `corim::cbor::value::from_value` into a
//!    `ComidTag` — giving the full triples tree for free — then encoded
//!    and wrapped by `CorimBuilder`.
//!
//! Keys may be written either as prose names or as their raw integer
//! index (the prose pass is idempotent on integer keys), so mixed and
//! legacy integer-keyed templates still work.
//!
//! # Profile-aware mval aliases
//!
//! `measurement-values-map` extension keys are integers (e.g. the Azure
//! profile's `tcbstatus` = -700). To let humans write
//! `"tcbstatus": "UpToDate"` instead of `"-700": "UpToDate"`, the
//! generator resolves aliases against the profile named by the
//! template's `profile` field (or `--profile`) using
//! `Profile::mval_json_alias`. These aliases are disjoint from the
//! structural prose keys and survive the prose pass untouched.
//!
//! # Template shape
//!
//! ```json
//! {
//!   "$comment": "Annotations are ordinary standard-JSON keys.",
//!   "corim-id": "1.3.6.1.4.1.311.102.5_NDPA_20260705",
//!   "profile": "tag:microsoft.com,2026:azure-profile#1.0.0",
//!   "rim-validity": { "not-before": 1700000000, "not-after": 1900000000 },
//!   "comids": [
//!     {
//!       "tag-identity": { "id": "..._NDPA" },
//!       "triples": {
//!         "reference-triples": [{
//!           "ref-env": { "class": { "vendor": "ACME" } },
//!           "ref-claims": [{ "value": { "svn": { "type": "svn", "value": 1 } } }]
//!         }]
//!       }
//!     }
//!   ]
//! }
//! ```
//!
//! `corim-id`, `profile`, `rim-validity`, `entities`, and
//! `dependent-rims` are optional except `corim-id`; at least one of
//! `comids` / `coswids` / `cotls` must be present. Triple records may be
//! authored as **labeled objects** (`{ "common-condition": ..., "series": ... }`,
//! using the CDDL field names) or as the legacy **positional arrays**;
//! both are accepted. See [`corim-cli/templates/azure_ndpa.json`] for a
//! worked example.
//!
//! # Comments
//!
//! Any object may carry a `$comment` (or `//`) key; these are stripped
//! before processing and never reach the CBOR output. The template stays
//! valid standard JSON, so any JSON tool accepts it. Comments can
//! annotate objects (the root, a CoMID, a triple record, an
//! environment, ...) but not bare array elements or scalars.
//!
//! [`corim-cli/templates/azure_ndpa.json`]: ../../templates/azure_ndpa.json

use corim::builder::CorimBuilder;
use corim::profile::Profile;
use corim::types::comid::ComidTag;
use corim::types::common::EntityMap;
use corim::types::corim::{ConciseTlTag, CorimId, CorimLocator, ProfileChoice};
use corim::types::coswid::ConciseSwidTag;

use crate::prose::Root;

/// Build tag-501 CoRIM bytes from a prose-or-integer JSON template.
///
/// This is the shared core of `generate` (also used by `validate
/// --baseline` to load a JSON baseline). `profile_override`, when set,
/// replaces the template's `profile` and drives mval-alias resolution.
pub(crate) fn encode_template(
    mut template: serde_json::Value,
    profile_override: Option<&str>,
) -> Result<Vec<u8>, String> {
    // Strip authoring comments before any structural processing so they
    // never reach the CBOR output (see `strip_comments`).
    super::check_json_budget(&template)?;
    strip_comments(&mut template);

    let obj = template
        .as_object()
        .ok_or_else(|| "template root must be a JSON object".to_string())?;
    for field in ["comids", "coswids", "cotls", "entities", "dependent-rims"] {
        if obj.get(field).is_some_and(|value| !value.is_array()) {
            return Err(format!("{field} must be an array"));
        }
    }

    // corim-id (required): a text string, or a `{ "type": "uuid", ... }`
    // type-choice for a UUID id.
    let corim_id_json = obj
        .get("corim-id")
        .ok_or_else(|| "template must have a \"corim-id\" field".to_string())?;
    let corim_id: CorimId = decode_scalar(corim_id_json).map_err(|e| format!("corim-id: {e}"))?;

    // profile: `--profile` (always a URI) overrides the template's
    // `profile`, which may be a text URI or a `{ "type": "oid", ... }`
    // type-choice.
    let profile_choice: Option<ProfileChoice> = match profile_override {
        Some(uri) => Some(ProfileChoice::Uri(uri.to_owned())),
        None => match obj.get("profile") {
            Some(p) => Some(decode_scalar(p).map_err(|e| format!("profile: {e}"))?),
            None => None,
        },
    };

    // Build the profile registry (all first-party profiles the CLI was
    // compiled with) and look up the profile named by the template so
    // its mval aliases resolve. Missing lookup is not fatal — the
    // template may use only core fields or raw integer keys.
    let registry = crate::profiles::build_registry();
    let profile: Option<&(dyn Profile + Send + Sync)> =
        profile_choice.as_ref().and_then(|pc| registry.get(pc));

    let mut builder = CorimBuilder::new(corim_id);
    if let Some(pc) = &profile_choice {
        builder = builder.set_profile(pc.clone());
    }

    // rim-validity (optional): { not-before?: <epoch>, not-after: <epoch> }.
    // Epoch seconds are plain integers; prose or integer keys accepted.
    if let Some(v) = obj.get("rim-validity") {
        crate::prose::try_to_int_keys(v, Root::Validity)?;
        let vo = v
            .as_object()
            .ok_or_else(|| "rim-validity must be an object".to_string())?;
        // Epoch seconds may be a bare integer or a `#6.1(int)` tag envelope
        // (`{"__cbor_tag": 1, "__cbor_value": <epoch>}`), the form emitted by
        // `convert`. Accept either.
        let as_epoch = |val: &serde_json::Value| -> Option<i64> {
            val.as_i64().or_else(|| {
                val.as_object()
                    .filter(|o| {
                        o.get("__cbor_tag").and_then(|t| t.as_u64())
                            == Some(corim::types::tags::TAG_EPOCH_TIME)
                    })
                    .and_then(|o| o.get("__cbor_value"))
                    .and_then(serde_json::Value::as_i64)
            })
        };
        let epoch = |names: &[&str]| -> Result<Option<i64>, String> {
            names
                .iter()
                .find_map(|name| vo.get(*name))
                .map(|value| {
                    as_epoch(value).ok_or_else(|| {
                        format!(
                            "rim-validity {} must be an epoch integer or a #6.1 tag envelope",
                            names[0]
                        )
                    })
                })
                .transpose()
        };
        let not_after = epoch(&["not-after", "1"])?.ok_or_else(|| {
            "rim-validity requires \"not-after\" as an epoch integer or a \
             #6.1 tag envelope ({\"__cbor_tag\": 1, \"__cbor_value\": <epoch>})"
                .to_string()
        })?;
        let not_before = epoch(&["not-before", "0"])?;
        builder = builder
            .set_validity(not_before, not_after)
            .map_err(|e| format!("rim-validity: {e}"))?;
    }

    // entities (optional): CoRIM entity-map list.
    if let Some(arr) = obj.get("entities").and_then(|v| v.as_array()) {
        for (i, e) in arr.iter().enumerate() {
            let em: EntityMap = decode_typed(e, Root::Entity, profile)
                .map_err(|err| format!("entities[{i}]: {err}"))?;
            builder = builder.add_entity(em);
        }
    }

    // dependent-rims (optional): corim-locator-map list.
    if let Some(arr) = obj.get("dependent-rims").and_then(|v| v.as_array()) {
        for (i, l) in arr.iter().enumerate() {
            let loc: CorimLocator = decode_typed(l, Root::Locator, profile)
                .map_err(|err| format!("dependent-rims[{i}]: {err}"))?;
            builder = builder.add_dependent_rim(loc);
        }
    }

    let mut tag_count = 0usize;

    // comids (optional): decoded CoMID tags (full triples tree).
    if let Some(arr) = obj.get("comids").and_then(|v| v.as_array()) {
        for (i, comid_json) in arr.iter().enumerate() {
            let comid: ComidTag = decode_typed(comid_json, Root::Comid, profile)
                .map_err(|err| format!("comids[{i}]: {err}"))?;
            builder = builder
                .add_comid_tag(comid)
                .map_err(|e| format!("comids[{i}]: add_comid_tag: {e}"))?;
            tag_count += 1;
        }
    }

    // coswids (optional): concise-swid-tag list.
    if let Some(arr) = obj.get("coswids").and_then(|v| v.as_array()) {
        for (i, s) in arr.iter().enumerate() {
            let sw: ConciseSwidTag = decode_typed(s, Root::Coswid, profile)
                .map_err(|err| format!("coswids[{i}]: {err}"))?;
            builder = builder
                .add_coswid(sw)
                .map_err(|e| format!("coswids[{i}]: {e}"))?;
            tag_count += 1;
        }
    }

    // cotls (optional): concise-tl-tag list.
    if let Some(arr) = obj.get("cotls").and_then(|v| v.as_array()) {
        for (i, t) in arr.iter().enumerate() {
            let tl: ConciseTlTag =
                decode_typed(t, Root::Cotl, profile).map_err(|err| format!("cotls[{i}]: {err}"))?;
            builder = builder
                .add_cotl(tl)
                .map_err(|e| format!("cotls[{i}]: {e}"))?;
            tag_count += 1;
        }
    }

    if tag_count == 0 {
        return Err("template must define at least one tag (comids, coswids, or cotls)".into());
    }

    let bytes = builder
        .build_bytes()
        .map_err(|e| format!("building CoRIM: {e}"))?;

    if bytes.len() > corim::cbor::DEFAULT_MAX_INPUT_BYTES {
        return Err("readable template CBOR exceeds the default 16 MiB document limit".into());
    }
    Ok(bytes)
}

/// Decode one prose-keyed template value of the given root kind into a
/// typed CoRIM structure.
///
/// Pipeline: prose keys -> integer keys, profile mval alias resolution,
/// semantic JSON -> CBOR value, base64 -> bytes coercion at bare-`bstr`
/// positions, then `from_value`. Mirrors the CoMID path for every typed
/// template node (entities, locators, CoSWID, CoTL).
fn decode_typed<T: serde::de::DeserializeOwned>(
    json: &serde_json::Value,
    root: Root,
    profile: Option<&(dyn Profile + Send + Sync)>,
) -> Result<T, String> {
    let mut resolved = crate::prose::try_to_int_keys(json, root)?;
    if let Some(p) = profile {
        resolve_mval_aliases(&mut resolved, p)?;
    }
    let mut cbor_val = super::value_conv::json_to_value(&resolved)?;
    crate::prose::coerce_bytes(&mut cbor_val, root);
    corim::cbor::value::from_value(&cbor_val)
}

/// Decode a scalar type-choice template value (`corim-id`, `profile`).
///
/// No prose keys apply, but the universal tag-driven byte coercion runs
/// so an OID `{ "type": "oid", "value": "<base64>" }` decodes to bytes.
fn decode_scalar<T: serde::de::DeserializeOwned>(json: &serde_json::Value) -> Result<T, String> {
    let mut cbor_val = super::value_conv::json_to_value(json)?;
    crate::prose::coerce_bytes(&mut cbor_val, Root::Scalar);
    corim::cbor::value::from_value(&cbor_val)
}

/// Object keys treated as authoring comments and stripped before the
/// template is processed. `$comment` follows the JSON Schema convention;
/// `//` mirrors the familiar line-comment sigil. Both carry arbitrary
/// values (string, array, object) so multi-line notes are possible.
const COMMENT_KEYS: [&str; 2] = ["$comment", "//"];

/// Recursively remove comment keys ([`COMMENT_KEYS`]) from every object
/// in the template.
///
/// Comments are kept as valid standard JSON (they are ordinary
/// string-valued keys), so the template still parses with any JSON tool.
/// Stripping them here — before prose rewriting, alias resolution, and
/// CBOR encoding — guarantees they never reach the output and the
/// `convert -> generate` round trip stays byte-identical (`convert`
/// never emits them).
///
/// Comments can annotate any JSON object (the root, a CoMID, a triple
/// record, an environment, an mval, ...). They cannot annotate bare
/// array elements or scalars, which have no place for a key.
fn strip_comments(value: &mut serde_json::Value) {
    match value {
        serde_json::Value::Object(map) => {
            for key in COMMENT_KEYS {
                map.remove(key);
            }
            for v in map.values_mut() {
                strip_comments(v);
            }
        }
        serde_json::Value::Array(items) => {
            for v in items.iter_mut() {
                strip_comments(v);
            }
        }
        _ => {}
    }
}

/// Recursively rewrite object keys that the profile recognises as
/// `measurement-values-map` aliases into their integer-string form
/// (e.g. `"tcbstatus"` -> `"-700"`), so the crate's JSON layer maps
/// them into `extra_entries` on deserialization.
///
/// The walk is global over the CoMID tree. Alias names are
/// profile-specific and do not collide with core CDDL key names, so a
/// targeted per-mval-map walk would add complexity without changing the
/// result for well-formed templates.
pub(super) fn resolve_mval_aliases(
    value: &mut serde_json::Value,
    profile: &(dyn Profile + Send + Sync),
) -> Result<(), String> {
    match value {
        serde_json::Value::Object(map) => {
            let renames: Vec<(String, i64)> = map
                .keys()
                .filter_map(|k| profile.mval_json_alias(k).map(|n| (k.clone(), n)))
                .collect();
            for (old_key, int_key) in renames {
                if map.contains_key(&int_key.to_string()) {
                    return Err(format!(
                        "conflicting profile alias {old_key} and key {int_key}"
                    ));
                }
                if let Some(v) = map.remove(&old_key) {
                    map.insert(int_key.to_string(), v);
                }
            }
            for v in map.values_mut() {
                resolve_mval_aliases(v, profile)?;
            }
        }
        serde_json::Value::Array(items) => {
            for v in items.iter_mut() {
                resolve_mval_aliases(v, profile)?;
            }
        }
        _ => {}
    }
    Ok(())
}
