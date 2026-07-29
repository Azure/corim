// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! `corim-cli convert` — dump an unsigned CoRIM as a prose-keyed JSON
//! template.
//!
//! This is the inverse of `corim-cli generate`: it decodes a tag-501
//! unsigned CoRIM and emits a JSON template with **named** keys that
//! feeds straight back into `generate`, closing the
//! `convert -> edit -> generate` loop.
//!
//! # Pipeline
//!
//! For each typed node (CoRIM id/profile/validity/entities/locators and
//! every CoMID/CoSWID/CoTL tag) the value is:
//!
//! 1. Serialized to the core `cbor::value::Value` tree.
//! 2. Converted to `serde_json::Value` via `corim::json::value_to_json`
//!    (integer keys, base64 bytes, `{ "type": ..., "value": ... }`
//!    type-choices).
//! 3. Rewritten from integer keys to prose names by
//!    [`crate::prose::to_prose_keys`] for the node's root kind.
//!
//! The result is exactly the shape `generate` accepts, so a round trip
//! reproduces the original CBOR byte-for-byte.
//!
//! Signed CoRIMs (COSE_Sign1, tag 18) are out of scope — convert the
//! detached/embedded payload instead.

use std::fs;
use std::path::PathBuf;
use std::process;

use clap::Parser;
use serde::Serialize;
use serde_json::{Map, Value as JsonValue};

use corim::profile::{Profile, ProfileRegistry};
use corim::types::comid::ComidTag;
use corim::types::corim::{ConciseTagChoice, ConciseTlTag, CorimMap};
use corim::types::coswid::ConciseSwidTag;

use crate::prose::Root;

#[derive(Parser)]
pub struct ConvertArgs {
    /// Path to the unsigned CoRIM CBOR file. Use "-" or omit for stdin.
    #[arg(value_name = "FILE")]
    file: Option<String>,

    /// Output path for the JSON template. Defaults to stdout.
    #[arg(short, long, value_name = "FILE")]
    output: Option<String>,
}

/// Entry point for the `convert` subcommand.
pub fn run(args: ConvertArgs) {
    match run_impl(args) {
        Ok(()) => {}
        Err(e) => {
            eprintln!("Error: {e}");
            process::exit(1);
        }
    }
}

fn run_impl(args: ConvertArgs) -> Result<(), String> {
    let bytes = read_input(args.file.as_deref())?;

    // Peel legacy `#6.500` / `#6.502` outer wrappers (TCG / NVIDIA
    // producers) so the tag-501 decode below sees the inner map.
    let peeled = corim::compat::peel_tcg_wrappers(&bytes)
        .map_err(|e| format!("legacy-wrapper peel failed: {e}"))?;
    let inner = peeled.as_bytes();

    if inner.first() == Some(&0xD2) {
        return Err(
            "input is a signed CoRIM (COSE_Sign1, tag 18); convert its payload instead".into(),
        );
    }

    let tagged: corim::cbor::value::Tagged<CorimMap> =
        corim::cbor::decode(inner).map_err(|e| format!("not a tag-501 unsigned CoRIM: {e}"))?;
    if tagged.tag != corim::types::tags::TAG_CORIM {
        return Err(format!(
            "expected CBOR tag {} (unsigned CoRIM), found tag {}",
            corim::types::tags::TAG_CORIM,
            tagged.tag
        ));
    }
    let corim = tagged.value;
    let registry = build_registry();
    let profile: Option<&(dyn Profile + Send + Sync)> =
        corim.profile.as_ref().and_then(|pc| registry.get(pc));

    let mut template = build_template(&corim)?;
    if let Some(p) = profile {
        apply_mval_alias_names(&mut template, p);
    }
    let json = serde_json::to_string_pretty(&template)
        .map_err(|e| format!("serializing template: {e}"))?;

    match args.output {
        Some(path) => {
            fs::write(&path, format!("{json}\n")).map_err(|e| format!("writing {path}: {e}"))?;
            eprintln!("Wrote template: {}", PathBuf::from(&path).display());
        }
        None => println!("{json}"),
    }
    Ok(())
}

/// Assemble the prose-keyed template object from a decoded CoRIM.
fn build_template(corim: &CorimMap) -> Result<JsonValue, String> {
    let mut root = Map::new();

    // corim-id and profile are scalar type-choices: a plain string
    // (text id / URI) or a `{ "type": ..., "value": ... }` object.
    root.insert("corim-id".into(), typed_to_prose(&corim.id, Root::Scalar)?);
    if let Some(profile) = &corim.profile {
        root.insert("profile".into(), typed_to_prose(profile, Root::Scalar)?);
    }

    if let Some(validity) = &corim.rim_validity {
        root.insert(
            "rim-validity".into(),
            typed_to_prose(validity, Root::Validity)?,
        );
    }

    if let Some(entities) = &corim.entities {
        let arr = entities
            .iter()
            .map(|e| typed_to_prose(e, Root::Entity))
            .collect::<Result<Vec<_>, _>>()?;
        root.insert("entities".into(), JsonValue::Array(arr));
    }

    if let Some(locators) = &corim.dependent_rims {
        let arr = locators
            .iter()
            .map(|l| typed_to_prose(l, Root::Locator))
            .collect::<Result<Vec<_>, _>>()?;
        root.insert("dependent-rims".into(), JsonValue::Array(arr));
    }

    // Tags: sort each decoded tag into its typed array.
    let mut comids = Vec::new();
    let mut coswids = Vec::new();
    let mut cotls = Vec::new();

    for (i, tag) in corim.tags.iter().enumerate() {
        match tag {
            ConciseTagChoice::Comid(inner) => {
                let comid: ComidTag = corim::cbor::decode(inner)
                    .map_err(|e| format!("tags[{i}] (CoMID) decode: {e}"))?;
                comids.push(typed_to_prose(&comid, Root::Comid)?);
            }
            ConciseTagChoice::BareBstr(inner) => {
                let comid = corim::compat::decode_comid_from_tcg_bstr(inner)
                    .map_err(|e| format!("tags[{i}] (bare CoMID) decode: {e}"))?;
                comids.push(typed_to_prose(&comid, Root::Comid)?);
            }
            ConciseTagChoice::Coswid(inner) => {
                let sw: ConciseSwidTag = corim::cbor::decode(inner)
                    .map_err(|e| format!("tags[{i}] (CoSWID) decode: {e}"))?;
                coswids.push(typed_to_prose(&sw, Root::Coswid)?);
            }
            ConciseTagChoice::Cotl(inner) => {
                let tl: ConciseTlTag = corim::cbor::decode(inner)
                    .map_err(|e| format!("tags[{i}] (CoTL) decode: {e}"))?;
                cotls.push(typed_to_prose(&tl, Root::Cotl)?);
            }
            ConciseTagChoice::Unknown(tag_num, _) => {
                return Err(format!("tags[{i}]: unknown tag type {tag_num}"));
            }
            _ => return Err(format!("tags[{i}]: unrecognized tag variant")),
        }
    }

    if !comids.is_empty() {
        root.insert("comids".into(), JsonValue::Array(comids));
    }
    if !coswids.is_empty() {
        root.insert("coswids".into(), JsonValue::Array(coswids));
    }
    if !cotls.is_empty() {
        root.insert("cotls".into(), JsonValue::Array(cotls));
    }

    Ok(JsonValue::Object(root))
}

/// Serialize a typed value to prose-keyed JSON: `T -> cbor Value ->
/// serde_json Value (integer keys) -> prose keys`.
fn typed_to_prose<T: Serialize>(value: &T, root: Root) -> Result<JsonValue, String> {
    let cbor_val = corim::cbor::value::to_value(value)?;
    let json_val = corim::json::value_to_json(&cbor_val);
    Ok(crate::prose::to_prose_keys(&json_val, root))
}

/// Recursively rewrite profile-defined integer `measurement-values-map`
/// extension keys to their human-friendly JSON aliases during `convert`
/// output (e.g. `"-700"` -> `"tcbstatus"` for Azure).
fn apply_mval_alias_names(value: &mut JsonValue, profile: &(dyn Profile + Send + Sync)) {
    match value {
        JsonValue::Object(map) => {
            let renames: Vec<(String, &'static str)> = map
                .keys()
                .filter_map(|k| {
                    k.parse::<i64>()
                        .ok()
                        .and_then(|n| profile.mval_json_name(n).map(|name| (k.clone(), name)))
                })
                .collect();

            for (old_key, alias) in renames {
                if map.contains_key(alias) {
                    continue;
                }
                if let Some(v) = map.remove(&old_key) {
                    map.insert(alias.to_string(), v);
                }
            }

            for v in map.values_mut() {
                apply_mval_alias_names(v, profile);
            }
        }
        JsonValue::Array(items) => {
            for v in items.iter_mut() {
                apply_mval_alias_names(v, profile);
            }
        }
        _ => {}
    }
}

fn build_registry() -> ProfileRegistry {
    #[allow(unused_mut)]
    let mut registry = ProfileRegistry::new();
    #[cfg(feature = "intel")]
    registry.register(Box::new(corim::profile::intel::IntelProfile::new()));
    #[cfg(feature = "azure")]
    registry.register(Box::new(corim::profile::azure::AzureProfile::new()));
    #[cfg(feature = "psa")]
    registry.register(Box::new(corim::profile::psa::PsaProfile::new()));
    registry
}

/// Read input from a file path, or from stdin when the path is `None` or
/// `"-"`.
fn read_input(path: Option<&str>) -> Result<Vec<u8>, String> {
    use std::io::Read;
    match path {
        None | Some("-") => {
            let mut buf = Vec::new();
            std::io::stdin()
                .read_to_end(&mut buf)
                .map_err(|e| format!("reading stdin: {e}"))?;
            Ok(buf)
        }
        Some(p) => fs::read(p).map_err(|e| format!("reading {p}: {e}")),
    }
}
