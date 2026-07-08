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
//!   "profile": "tag:microsoft.com,2026:azure-profile#1.0.0",
//!   "comids": [
//!     {
//!       "tag-identity": { "id": "..._NDPA" },
//!       "triples": {
//!         "conditional-endorsement-series-triples": [ /* ... */ ]
//!       }
//!     }
//!   ]
//! }
//! ```
//!
//! Triple records are positional CBOR arrays in the wire format, so they
//! stay positional arrays in the template; only map keys are named. See
//! [`corim-cli/templates/azure_ndpa.json`] for a worked example.
//!
//! [`corim-cli/templates/azure_ndpa.json`]: ../../templates/azure_ndpa.json

use std::fs;
use std::path::PathBuf;
use std::process;

use clap::Parser;

use corim::builder::CorimBuilder;
use corim::profile::{Profile, ProfileRegistry};
use corim::types::comid::ComidTag;
use corim::types::corim::{CorimId, ProfileChoice};

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

    // corim-id (required, text).
    let corim_id = obj
        .get("corim-id")
        .and_then(|v| v.as_str())
        .ok_or_else(|| "template must have a string \"corim-id\" field".to_string())?;

    // profile: --profile overrides the template's "profile" field.
    let profile_uri = args
        .profile
        .as_deref()
        .or_else(|| obj.get("profile").and_then(|v| v.as_str()))
        .map(str::to_owned);

    // Build the profile registry (all first-party profiles the CLI was
    // compiled with) and look up the profile named by the template so
    // its mval aliases resolve. Missing lookup is not fatal — the
    // template may use only core fields or raw integer keys.
    let registry = build_registry();
    let profile: Option<&(dyn Profile + Send + Sync)> = profile_uri
        .as_deref()
        .map(|u| ProfileChoice::Uri(u.to_owned()))
        .and_then(|pc| registry.get(&pc));

    // comids (required, non-empty array).
    let comids_json = obj
        .get("comids")
        .and_then(|v| v.as_array())
        .ok_or_else(|| "template must have a \"comids\" array".to_string())?;
    if comids_json.is_empty() {
        return Err("\"comids\" array must not be empty".into());
    }

    let mut builder = CorimBuilder::new(CorimId::Text(corim_id.to_owned()));
    if let Some(uri) = &profile_uri {
        builder = builder.set_profile(ProfileChoice::Uri(uri.clone()));
    }

    for (i, comid_json) in comids_json.iter().enumerate() {
        // 1. Rewrite prose keys ("tag-identity", "vendor", "svn", ...)
        //    to integer-string keys using the context state machine.
        // 2. Rewrite profile mval aliases ("tcbstatus") to their integer
        //    keys. These are disjoint from the structural keys, so order
        //    only matters in that aliases survive step 1 untouched.
        let mut resolved = crate::prose::to_int_keys(comid_json);
        if let Some(p) = profile {
            resolve_mval_aliases(&mut resolved, p);
        }
        // 3. Convert JSON -> CBOR value via the core layer, then coerce
        //    base64 text into bytes at bare-`bstr` positions (digest
        //    values, ueid, uuid, mac/ip-addr) — the core JSON layer maps
        //    every string to text and cannot express bare byte strings.
        // 4. Deserialize the decoded CoMID.
        let mut cbor_val = corim::json::json_to_value(&resolved);
        crate::prose::coerce_bytes(&mut cbor_val);
        let comid: ComidTag = corim::cbor::value::from_value(&cbor_val)
            .map_err(|e| format!("comids[{i}]: decode: {e}"))?;
        builder = builder
            .add_comid_tag(comid)
            .map_err(|e| format!("comids[{i}]: add_comid_tag: {e}"))?;
    }

    let bytes = builder
        .build_bytes()
        .map_err(|e| format!("building CoRIM: {e}"))?;

    // Validate the freshly-built CoRIM as a sanity check before writing.
    corim::validate::decode_and_validate(&bytes)
        .map_err(|e| format!("post-build validation failed: {e}"))?;

    let out_path = match args.output {
        Some(o) => PathBuf::from(o),
        None => PathBuf::from(&args.template).with_extension("cbor"),
    };
    fs::write(&out_path, &bytes).map_err(|e| format!("writing {}: {e}", out_path.display()))?;
    Ok(out_path)
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
