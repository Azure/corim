// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Shared JSON rendering helpers.
//!
//! The COSE protected header is built once here as a `serde_json::Value` and
//! reused by `validate -f json`, `extract --header --json`, and `convert`, so
//! the three cannot drift apart.

use std::collections::HashSet;
use std::fmt::Write as _;

use base64::Engine;
use corim::cbor::value::Value;
use corim::types::signed::{ClaimKey, ProtectedCorimHeaderMap};
use serde_json::{json, Map, Value as JsonValue};

/// Template/report key under which the COSE protected header is emitted.
pub const PROTECTED_HEADER_KEY: &str = "protected-header";

/// Escape a string for a JSON string literal per RFC 8259 §7: the quote and
/// reverse solidus, plus every control character below U+0020.
///
/// Only needed by the hand-rolled parts of the `validate` report; anything
/// going through `serde_json` is escaped for us.
pub fn escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '\u{08}' => out.push_str("\\b"),
            '\u{0c}' => out.push_str("\\f"),
            c if (c as u32) < 0x20 => {
                let _ = write!(out, "\\u{:04x}", c as u32);
            }
            c => out.push(c),
        }
    }
    out
}

/// Convert a CBOR [`Value`] to JSON. Byte strings use base64, matching
/// `corim::json` and the `convert` / `generate` templates; tags use the
/// `{"__cbor_tag": N, "__cbor_value": …}` envelope so the value round-trips
/// rather than being flattened.
pub fn cbor_to_json(v: &Value) -> JsonValue {
    match v {
        Value::Null => JsonValue::Null,
        Value::Bool(b) => JsonValue::Bool(*b),
        Value::Text(t) => JsonValue::String(t.clone()),
        Value::Bytes(b) => JsonValue::String(base64::engine::general_purpose::STANDARD.encode(b)),
        // JSON numbers only cover i64/u64; fall back to a string outside that.
        Value::Integer(n) => match (i64::try_from(*n), u64::try_from(*n)) {
            (Ok(x), _) => json!(x),
            (_, Ok(x)) => json!(x),
            _ => JsonValue::String(n.to_string()),
        },
        Value::Float(f) => serde_json::Number::from_f64(*f)
            .map(JsonValue::Number)
            .unwrap_or(JsonValue::Null),
        Value::Array(a) => JsonValue::Array(a.iter().map(cbor_to_json).collect()),
        Value::Map(m) => {
            // JSON object keys are strings, so distinct CBOR keys can collide
            // (integer `1` and text `"1"`, say). Only use the object form when
            // every key stringifies uniquely; otherwise fall back to an array
            // of entries, which keeps each key's type and loses nothing.
            let keys: Vec<String> = m.iter().map(|(k, _)| map_key(k)).collect();
            let unique = keys.iter().collect::<HashSet<_>>().len() == keys.len();
            if unique {
                let mut obj = Map::new();
                for ((_, val), key) in m.iter().zip(keys) {
                    obj.insert(key, cbor_to_json(val));
                }
                JsonValue::Object(obj)
            } else {
                JsonValue::Array(
                    m.iter()
                        .map(|(k, val)| {
                            json!({ "key": cbor_to_json(k), "value": cbor_to_json(val) })
                        })
                        .collect(),
                )
            }
        }
        Value::Tag(t, inner) => json!({
            "__cbor_tag": t,
            "__cbor_value": cbor_to_json(inner),
        }),
    }
}

/// Stringify a CBOR map key for use as a JSON object key.
fn map_key(k: &Value) -> String {
    match k {
        Value::Text(t) => t.clone(),
        Value::Integer(n) => n.to_string(),
        // Unwrap string-valued keys: `to_string` on a JSON string would bake
        // the quotes into the object key.
        other => match cbor_to_json(other) {
            JsonValue::String(s) => s,
            v => v.to_string(),
        },
    }
}

/// Build the COSE protected header as a JSON object.
///
/// `size` is the length of the protected `bstr` as it appears in the
/// envelope (the bytes that go into `Sig_structure1`).
pub fn protected_header_value(p: &ProtectedCorimHeaderMap, size: usize) -> JsonValue {
    let mut o = Map::new();
    o.insert("size".into(), json!(size));
    o.insert("alg".into(), json!(p.alg.name()));
    o.insert("alg_id".into(), json!(p.alg.to_i64()));
    if let Some(ct) = p.content_type.as_ref() {
        o.insert("content_type".into(), json!(ct));
    }
    if let Some(alg) = p.payload_hash_alg {
        o.insert("payload_hash_alg".into(), json!(alg));
    }
    if let Some(ct) = p.payload_preimage_content_type.as_ref() {
        o.insert("payload_preimage_content_type".into(), json!(ct));
    }
    if let Some(loc) = p.payload_location.as_ref() {
        o.insert("payload_location".into(), json!(loc));
    }
    if let Some(claims) = p.cwt_claims.as_ref() {
        o.insert("issuer".into(), json!(claims.iss));
        if let Some(subject) = claims.sub.as_ref() {
            o.insert("subject".into(), json!(subject));
        }
        if let Some(exp) = claims.exp {
            o.insert("exp".into(), json!(exp));
        }
        if let Some(nbf) = claims.nbf {
            o.insert("nbf".into(), json!(nbf));
        }
        if let Some(extra) = claim_extras(&claims.extra) {
            o.insert("cwt_claims_extra".into(), extra);
        }
    }
    if let Some(meta) = p.corim_meta.as_ref() {
        o.insert("signer_name".into(), json!(meta.signer.signer_name));
        if let Some(uri) = meta.signer.signer_uri.as_ref() {
            o.insert("signer_uri".into(), json!(uri));
        }
    }
    o.insert("has_cwt_claims".into(), json!(p.cwt_claims.is_some()));
    o.insert("has_corim_meta".into(), json!(p.corim_meta.is_some()));
    o.insert("has_kid".into(), json!(p.kid.is_some()));
    o.insert(
        "x5chain_count".into(),
        json!(p.x5chain.as_ref().map(|x| x.certs().len()).unwrap_or(0)),
    );
    o.insert("has_x5t".into(), json!(p.x5t.is_some()));
    if !p.extra.is_empty() {
        let mut ext = Map::new();
        for (k, v) in &p.extra {
            ext.insert(k.to_string(), cbor_to_json(v));
        }
        o.insert("header_extra".into(), JsonValue::Object(ext));
    }
    JsonValue::Object(o)
}

/// Render the protected header as pretty JSON, with every line after the
/// first prefixed by `indent` so it can be embedded in a larger report.
pub fn protected_header(p: &ProtectedCorimHeaderMap, size: usize, indent: &str) -> String {
    let text = serde_json::to_string_pretty(&protected_header_value(p, size))
        .unwrap_or_else(|_| "{}".into());
    let mut out = String::with_capacity(text.len());
    for (i, line) in text.lines().enumerate() {
        if i > 0 {
            out.push('\n');
            out.push_str(indent);
        }
        out.push_str(line);
    }
    out
}

/// Extra CWT claims, namespaced by key type.
///
/// JSON object keys are strings, so integer and text claim keys are kept in
/// separate objects: `Int(6)` and `Text("6")` would otherwise collide and one
/// entry would be lost.
fn claim_extras(extra: &std::collections::BTreeMap<ClaimKey, Value>) -> Option<JsonValue> {
    if extra.is_empty() {
        return None;
    }
    let (mut ints, mut texts) = (Map::new(), Map::new());
    for (k, v) in extra {
        match k {
            ClaimKey::Int(n) => ints.insert(n.to_string(), cbor_to_json(v)),
            ClaimKey::Text(t) => texts.insert(t.clone(), cbor_to_json(v)),
            other => texts.insert(other.to_string(), cbor_to_json(v)),
        };
    }
    let mut o = Map::new();
    if !ints.is_empty() {
        o.insert("int".into(), JsonValue::Object(ints));
    }
    if !texts.is_empty() {
        o.insert("text".into(), JsonValue::Object(texts));
    }
    Some(JsonValue::Object(o))
}
