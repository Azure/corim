// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! `corim-cli generate` — build an unsigned CoRIM from a JSON template.
//!
//! The template is authored against the *decoded* CoMID type (not the
//! wire-format `corim-map`, whose CoMID tags are opaque bstr-wrapped
//! CBOR). Each entry in the template's `comids` array is:
//!
//! 1. Rewritten from **prose keys** (`"tag-identity"`, `"triples"`,
//!    `"vendor"`, `"svn"`, ...) to the integer-string keys the core
//!    crate's JSON layer expects, using the context state machine in
//!    [`crate::prose`].
//! 2. Passed through profile mval alias resolution (`"tcbstatus"` ->
//!    `"-700"`).
//! 3. Converted to a CBOR value via `corim::json::json_to_value`, then
//!    base64 text at bare-`bstr` positions (digest values, `ueid`,
//!    `uuid`, `mac-addr`, `ip-addr`) is coerced to CBOR bytes by
//!    [`crate::prose::coerce_bytes`] — the core JSON layer maps every
//!    string to text and cannot express bare byte strings.
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
//! ```jsonc
//! {
//!   "corim-id": "1.3.6.1.4.1.311.102.5_NDPA_20260705",
//!   //          or { "type": "uuid", "value": "…" }
//!   "profile": "tag:microsoft.com,2026:azure-profile#1.0.0",
//!   //          or { "type": "oid", "value": "<base64>" }
//!   "rim-validity": { "not-before": 1700000000, "not-after": 1900000000 },
//!   "entities": [ { "entity-name": "ACME", "role": [1] } ],
//!   "dependent-rims": [ { "href": "https://…" } ],
//!   "comids": [
//!     {
//!       "tag-identity": { "id": "..._NDPA" },
//!       "triples": {
//!         "conditional-endorsement-series-triples": [ /* ... */ ]
//!       }
//!     }
//!   ],
//!   "coswids": [ /* concise-swid-tag */ ],
//!   "cotls":   [ /* concise-tl-tag */ ]
//! }
//! ```
//!
//! `corim-id`, `profile`, `rim-validity`, `entities`, and
//! `dependent-rims` are optional except `corim-id`; at least one of
//! `comids` / `coswids` / `cotls` must be present. Triple records may be
//! authored as **labeled objects** (`{ "condition": ..., "series": ... }`,
//! using the CDDL field names) or as the legacy **positional arrays**;
//! both are accepted. See [`corim-cli/templates/azure_ndpa.json`] for a
//! worked example.
//!
//! [`corim-cli/templates/azure_ndpa.json`]: ../../templates/azure_ndpa.json

use std::fs;
use std::path::PathBuf;
use std::process;

use clap::Parser;

use corim::builder::CorimBuilder;
use corim::profile::{Profile, ProfileRegistry};
use corim::types::comid::ComidTag;
use corim::types::common::EntityMap;
use corim::types::corim::{ConciseTlTag, CorimId, CorimLocator, ProfileChoice};
use corim::types::coswid::ConciseSwidTag;

use crate::prose::Root;

#[derive(Parser)]
pub struct GenerateArgs {
    /// Path to the JSON template describing the CoRIM.
    #[arg(value_name = "TEMPLATE")]
    template: String,

    /// Output path for the CBOR CoRIM. Defaults to the template path with
    /// a `.cbor` extension.
    #[arg(short, long, value_name = "FILE")]
    output: Option<String>,

    /// Override the profile URI declared in the template. Also used to
    /// resolve `measurement-values-map` aliases (e.g. `tcbstatus`).
    #[arg(long, value_name = "URI")]
    profile: Option<String>,
}

/// Entry point for the `generate` subcommand.
pub fn run(args: GenerateArgs) {
    match run_impl(args) {
        Ok(out) => {
            eprintln!("Wrote CoRIM: {}", out.display());
        }
        Err(e) => {
            eprintln!("Error: {e}");
            process::exit(1);
        }
    }
}

fn run_impl(args: GenerateArgs) -> Result<PathBuf, String> {
    let template_str = fs::read_to_string(&args.template)
        .map_err(|e| format!("reading template {}: {e}", args.template))?;
    let template: serde_json::Value =
        serde_json::from_str(&template_str).map_err(|e| format!("parsing template JSON: {e}"))?;

    let obj = template
        .as_object()
        .ok_or_else(|| "template root must be a JSON object".to_string())?;

    // corim-id (required): a text string, or a `{ "type": "uuid", ... }`
    // type-choice for a UUID id.
    let corim_id_json = obj
        .get("corim-id")
        .ok_or_else(|| "template must have a \"corim-id\" field".to_string())?;
    let corim_id: CorimId = decode_scalar(corim_id_json).map_err(|e| format!("corim-id: {e}"))?;

    // profile: `--profile` (always a URI) overrides the template's
    // `profile`, which may be a text URI or a `{ "type": "oid", ... }`
    // type-choice.
    let profile_choice: Option<ProfileChoice> = match args.profile.as_deref() {
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
    let registry = build_registry();
    let profile: Option<&(dyn Profile + Send + Sync)> =
        profile_choice.as_ref().and_then(|pc| registry.get(pc));

    let mut builder = CorimBuilder::new(corim_id);
    if let Some(pc) = &profile_choice {
        builder = builder.set_profile(pc.clone());
    }

    // rim-validity (optional): { not-before?: <epoch>, not-after: <epoch> }.
    // Epoch seconds are plain integers; prose or integer keys accepted.
    if let Some(v) = obj.get("rim-validity") {
        let vo = v
            .as_object()
            .ok_or_else(|| "rim-validity must be an object".to_string())?;
        let epoch = |names: &[&str]| -> Option<i64> {
            names
                .iter()
                .find_map(|n| vo.get(*n))
                .and_then(serde_json::Value::as_i64)
        };
        let not_after = epoch(&["not-after", "1"])
            .ok_or_else(|| "rim-validity requires integer \"not-after\"".to_string())?;
        let not_before = epoch(&["not-before", "0"]);
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
    let mut comid_count = 0usize;

    // comids (optional): decoded CoMID tags (full triples tree).
    if let Some(arr) = obj.get("comids").and_then(|v| v.as_array()) {
        for (i, comid_json) in arr.iter().enumerate() {
            let comid: ComidTag = decode_typed(comid_json, Root::Comid, profile)
                .map_err(|err| format!("comids[{i}]: {err}"))?;
            builder = builder
                .add_comid_tag(comid)
                .map_err(|e| format!("comids[{i}]: add_comid_tag: {e}"))?;
            tag_count += 1;
            comid_count += 1;
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

    // Sanity-check the freshly-built CoRIM before writing. The strict
    // validator requires at least one CoMID, so only run it when CoMIDs
    // are present; for CoSWID/CoTL-only CoRIMs, fall back to a structural
    // tag-501 decode.
    if comid_count > 0 {
        corim::validate::decode_and_validate(&bytes)
            .map_err(|e| format!("post-build validation failed: {e}"))?;
    } else {
        corim::cbor::decode::<corim::cbor::value::Tagged<corim::types::corim::CorimMap>>(&bytes)
            .map_err(|e| format!("post-build decode failed: {e}"))?;
    }

    let out_path = match args.output {
        Some(o) => PathBuf::from(o),
        None => PathBuf::from(&args.template).with_extension("cbor"),
    };
    fs::write(&out_path, &bytes).map_err(|e| format!("writing {}: {e}", out_path.display()))?;
    Ok(out_path)
}

/// Decode one prose-keyed template value of the given root kind into a
/// typed CoRIM structure.
///
/// Pipeline: prose keys -> integer keys, profile mval alias resolution,
/// JSON -> CBOR value, base64 -> bytes coercion at bare-`bstr`
/// positions, then `from_value`. Mirrors the CoMID path for every typed
/// template node (entities, locators, CoSWID, CoTL).
fn decode_typed<T: serde::de::DeserializeOwned>(
    json: &serde_json::Value,
    root: Root,
    profile: Option<&(dyn Profile + Send + Sync)>,
) -> Result<T, String> {
    let mut resolved = crate::prose::to_int_keys(json, root);
    if let Some(p) = profile {
        resolve_mval_aliases(&mut resolved, p);
    }
    let mut cbor_val = corim::json::json_to_value(&resolved);
    crate::prose::coerce_bytes(&mut cbor_val, root);
    corim::cbor::value::from_value(&cbor_val)
}

/// Decode a scalar type-choice template value (`corim-id`, `profile`).
///
/// No prose keys apply, but the universal tag-driven byte coercion runs
/// so an OID `{ "type": "oid", "value": "<base64>" }` decodes to bytes.
fn decode_scalar<T: serde::de::DeserializeOwned>(json: &serde_json::Value) -> Result<T, String> {
    let mut cbor_val = corim::json::json_to_value(json);
    crate::prose::coerce_bytes(&mut cbor_val, Root::Scalar);
    corim::cbor::value::from_value(&cbor_val)
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
fn resolve_mval_aliases(value: &mut serde_json::Value, profile: &(dyn Profile + Send + Sync)) {
    match value {
        serde_json::Value::Object(map) => {
            let renames: Vec<(String, i64)> = map
                .keys()
                .filter_map(|k| profile.mval_json_alias(k).map(|n| (k.clone(), n)))
                .collect();
            for (old_key, int_key) in renames {
                if let Some(v) = map.remove(&old_key) {
                    map.insert(int_key.to_string(), v);
                }
            }
            for v in map.values_mut() {
                resolve_mval_aliases(v, profile);
            }
        }
        serde_json::Value::Array(items) => {
            for v in items.iter_mut() {
                resolve_mval_aliases(v, profile);
            }
        }
        _ => {}
    }
}

/// Build a registry of every first-party profile the CLI was compiled
/// with, so `generate` can resolve profile-specific mval aliases.
fn build_registry() -> ProfileRegistry {
    #[allow(unused_mut)]
    let mut registry = ProfileRegistry::new();
    #[cfg(feature = "intel")]
    registry.register(Box::new(corim::profile::intel::IntelProfile::new()));
    #[cfg(feature = "azure")]
    registry.register(Box::new(corim::profile::azure::AzureProfile::new()));
    registry
}
