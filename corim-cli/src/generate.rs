// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Generate CBOR from readable authoring templates or strict lossless JSON.
//! Format selection is structural, never a fallback after a parser fails.
//! Document validation runs before any output file is written.

use clap::Parser;
use corim::cbor::value::Value;
use corim::types::tags::{
    CORIM_KEY_PROFILE, TAG_CORIM, TAG_LEGACY_SIGNED, TAG_LEGACY_TOP, TAG_URI,
};
use std::{fs, path::PathBuf, process};

#[derive(Parser)]
pub struct GenerateArgs {
    /// Readable JSON template (with comment annotations) or lossless document.
    #[arg(value_name = "TEMPLATE")]
    template: String,
    /// Output path; defaults to the input path with a `.cbor` extension.
    #[arg(short, long, value_name = "FILE")]
    output: Option<String>,
    /// Replace the unsigned document's profile URI. Rejected for signed documents.
    #[arg(long, value_name = "URI")]
    profile: Option<String>,
}

/// Entry point for validated JSON generation.
pub fn run(args: GenerateArgs) {
    match run_impl(args) {
        Ok(path) => eprintln!("Wrote CoRIM: {}", path.display()),
        Err(error) => {
            eprintln!("Error: {error}");
            process::exit(match error {
                GenerationError::Partial => crate::validation::PARTIAL_EXIT_CODE,
                GenerationError::Invalid(_) => 1,
            });
        }
    }
}

#[derive(Debug)]
enum GenerationError {
    Invalid(String),
    Partial,
}

impl From<String> for GenerationError {
    fn from(error: String) -> Self {
        Self::Invalid(error)
    }
}

impl std::fmt::Display for GenerationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Invalid(error) => f.write_str(error),
            Self::Partial => f.write_str("PARTIAL validation coverage: refusing to generate a document with unexamined content"),
        }
    }
}

fn run_impl(args: GenerateArgs) -> Result<PathBuf, GenerationError> {
    let raw = crate::input::read_file(&args.template)
        .map_err(|e| format!("reading template {}: {e}", args.template))?;
    let text = std::str::from_utf8(&raw).map_err(|e| format!("template UTF-8: {e}"))?;
    let template =
        corim::json::parse_json(text).map_err(|e| format!("parsing template JSON: {e}"))?;
    let bytes = build_with_time(
        template,
        args.profile.as_deref(),
        Some(crate::validation::now()?),
        true,
    )?;
    let path = args
        .output
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(args.template).with_extension("cbor"));
    fs::write(&path, bytes).map_err(|e| format!("writing {}: {e}", path.display()))?;
    Ok(path)
}

/// Compatibility loader that encodes and validates once. Baseline callers
/// needing coverage use `encode_document` and the shared validation pipeline.
#[allow(dead_code)]
pub(crate) fn build_corim_from_template_with_time(
    template: serde_json::Value,
    profile_override: Option<&str>,
    now: Option<i64>,
) -> Result<Vec<u8>, String> {
    build_with_time(template, profile_override, now, false).map_err(|e| e.to_string())
}

fn build_with_time(
    template: serde_json::Value,
    profile_override: Option<&str>,
    now: Option<i64>,
    require_complete: bool,
) -> Result<Vec<u8>, GenerationError> {
    let bytes = encode_document(template, profile_override)?;
    validate_generated_document(&bytes, now, require_complete)?;
    Ok(bytes)
}

/// Encode either document format without validation. Baseline callers feed
/// these bytes to the shared validation pipeline exactly once.
pub(crate) fn encode_document(
    template: serde_json::Value,
    profile_override: Option<&str>,
) -> Result<Vec<u8>, String> {
    if is_authoring_template(&template)? {
        return crate::authoring::encode_template(template, profile_override);
    }
    let mut root =
        corim::json::json_to_value(&template).map_err(|e| format!("lossless JSON: {e}"))?;
    if let Some(uri) = profile_override {
        override_unsigned_profile(&mut root, uri)?;
    }
    corim::cbor::encode(&root).map_err(|e| format!("encoding CBOR: {e}"))
}

fn is_authoring_template(value: &serde_json::Value) -> Result<bool, String> {
    let Some(object) = value.as_object() else {
        return Ok(false);
    };
    let readable = [
        "corim-id",
        "comids",
        "coswids",
        "cotls",
        "profile",
        "rim-validity",
        "entities",
        "dependent-rims",
        "protected-header",
    ]
    .iter()
    .any(|key| object.contains_key(*key));
    let lossless = object.contains_key("type");
    if readable && lossless {
        return Err("ambiguous document JSON: readable template fields and a lossless wrapper cannot be mixed".into());
    }
    Ok(readable || !lossless && (object.contains_key("$comment") || object.contains_key("//")))
}

// Central gate for the shared CLI validation pipeline. Keep this before writes.
fn validate_generated_document(
    bytes: &[u8],
    now: Option<i64>,
    require_complete: bool,
) -> Result<(), GenerationError> {
    let registry = crate::profiles::build_registry();
    let outcome = crate::validation::document(bytes, now, &registry)
        .map_err(|e| format!("post-build validation failed: {e}"))?;
    if require_complete && !outcome.coverage.is_complete() {
        return Err(GenerationError::Partial);
    }
    Ok(())
}

fn override_unsigned_profile(root: &mut Value, uri: &str) -> Result<(), String> {
    let mut document = root;
    while let Value::Tag(TAG_LEGACY_TOP | TAG_LEGACY_SIGNED, inner) = document {
        document = inner;
    }
    let Value::Tag(TAG_CORIM, inner) = document else {
        return Err("--profile is supported only for unsigned tag-501 documents; signed protected and payload bytes must not be modified".into());
    };
    let Value::Map(entries) = inner.as_mut() else {
        return Err("unsigned CoRIM must contain a map".into());
    };
    let key = Value::Integer(i128::from(CORIM_KEY_PROFILE));
    let value = Value::Tag(TAG_URI, Box::new(Value::Text(uri.into())));
    let mut profiles = entries.iter_mut().filter(|(k, _)| *k == key);
    if let Some((_, existing)) = profiles.next() {
        if profiles.next().is_some() {
            return Err("cannot override duplicate profile entries".into());
        }
        *existing = value;
    } else {
        entries.push((key, value));
    }
    Ok(())
}
