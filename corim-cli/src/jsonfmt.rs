// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Shared JSON rendering helpers.
//!
//! The CLI hand-rolls its JSON output. These helpers keep escaping, CBOR
//! value rendering, and the COSE protected-header object identical across
//! `validate -f json` and `extract --header --json`.

use std::fmt::Write as _;

use base64::Engine;
use corim::cbor::value::Value;
use corim::types::signed::{ClaimKey, ProtectedCorimHeaderMap};

/// Escape a string for a JSON string literal per RFC 8259 §7: the quote and
/// reverse solidus, plus every control character below U+0020.
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

/// Render a CBOR [`Value`] as a JSON fragment. Byte strings use base64,
/// matching `corim::json` and the `convert` / `generate` templates; tags use
/// the `{"__cbor_tag": N, "__cbor_value": …}` envelope so the value
/// round-trips rather than being flattened.
pub fn cbor_value(v: &Value) -> String {
    match v {
        Value::Null => "null".into(),
        Value::Bool(b) => b.to_string(),
        Value::Text(t) => format!("\"{}\"", escape(t)),
        Value::Bytes(b) => format!(
            "\"{}\"",
            base64::engine::general_purpose::STANDARD.encode(b)
        ),
        // JSON numbers only cover i64/u64; fall back to a string outside that.
        Value::Integer(n) => match (i64::try_from(*n), u64::try_from(*n)) {
            (Ok(x), _) => x.to_string(),
            (_, Ok(x)) => x.to_string(),
            _ => format!("\"{n}\""),
        },
        Value::Float(f) => {
            if f.is_finite() {
                f.to_string()
            } else {
                "null".into()
            }
        }
        Value::Array(a) => {
            let items: Vec<String> = a.iter().map(cbor_value).collect();
            format!("[{}]", items.join(", "))
        }
        Value::Map(m) => {
            let items: Vec<String> = m
                .iter()
                .map(|(k, val)| {
                    let key = match k {
                        Value::Text(t) => t.clone(),
                        Value::Integer(n) => n.to_string(),
                        other => cbor_value(other),
                    };
                    format!("\"{}\": {}", escape(&key), cbor_value(val))
                })
                .collect();
            format!("{{{}}}", items.join(", "))
        }
        Value::Tag(t, inner) => {
            format!(
                "{{\"__cbor_tag\": {t}, \"__cbor_value\": {}}}",
                cbor_value(inner)
            )
        }
    }
}

/// Render the COSE protected header as a JSON object.
///
/// Lines after the opening brace are prefixed with `indent`; the caller
/// supplies the leading context (e.g. `"protected": `) and any trailing comma.
pub fn protected_header(p: &ProtectedCorimHeaderMap, size: usize, indent: &str) -> String {
    let mut out = String::from("{\n");
    let mut fields: Vec<String> = Vec::new();

    fields.push(format!("\"size\": {size}"));
    fields.push(format!("\"alg\": \"{}\"", escape(p.alg.name())));
    fields.push(format!("\"alg_id\": {}", p.alg.to_i64()));
    if let Some(ct) = p.content_type.as_ref() {
        fields.push(format!("\"content_type\": \"{}\"", escape(ct)));
    }
    if let Some(loc) = p.payload_location.as_ref() {
        fields.push(format!("\"payload_location\": \"{}\"", escape(loc)));
    }
    if let Some(alg) = p.payload_hash_alg {
        fields.push(format!("\"payload_hash_alg\": {alg}"));
    }
    if let Some(ct) = p.payload_preimage_content_type.as_ref() {
        fields.push(format!(
            "\"payload_preimage_content_type\": \"{}\"",
            escape(ct)
        ));
    }
    if let Some(claims) = p.cwt_claims.as_ref() {
        fields.push(format!("\"issuer\": \"{}\"", escape(&claims.iss)));
        if let Some(subject) = claims.sub.as_ref() {
            fields.push(format!("\"subject\": \"{}\"", escape(subject)));
        }
        if let Some(exp) = claims.exp {
            fields.push(format!("\"exp\": {exp}"));
        }
        if let Some(nbf) = claims.nbf {
            fields.push(format!("\"nbf\": {nbf}"));
        }
        if let Some(extra) = claim_extras_json(&claims.extra) {
            fields.push(format!("\"cwt_claims_extra\": {extra}"));
        }
    }
    if let Some(meta) = p.corim_meta.as_ref() {
        fields.push(format!(
            "\"signer_name\": \"{}\"",
            escape(&meta.signer.signer_name)
        ));
        if let Some(uri) = meta.signer.signer_uri.as_ref() {
            fields.push(format!("\"signer_uri\": \"{}\"", escape(uri)));
        }
    }
    fields.push(format!("\"has_cwt_claims\": {}", p.cwt_claims.is_some()));
    fields.push(format!("\"has_corim_meta\": {}", p.corim_meta.is_some()));
    fields.push(format!("\"has_kid\": {}", p.kid.is_some()));
    fields.push(format!(
        "\"x5chain_count\": {}",
        p.x5chain.as_ref().map(|x| x.certs().len()).unwrap_or(0)
    ));
    fields.push(format!("\"has_x5t\": {}", p.x5t.is_some()));
    if !p.extra.is_empty() {
        let items: Vec<String> = p
            .extra
            .iter()
            .map(|(k, v)| format!("\"{k}\": {}", cbor_value(v)))
            .collect();
        fields.push(format!("\"header_extra\": {{ {} }}", items.join(", ")));
    }

    for (i, f) in fields.iter().enumerate() {
        let comma = if i + 1 < fields.len() { "," } else { "" };
        let _ = writeln!(out, "{indent}  {f}{comma}");
    }
    let _ = write!(out, "{indent}}}");
    out
}

/// Render the extra CWT claims, namespaced by key type.
///
/// JSON object keys are strings, so integer and text claim keys are kept in
/// separate objects: `Int(6)` and `Text("6")` would otherwise collide and one
/// entry would be lost.
fn claim_extras_json(extra: &std::collections::BTreeMap<ClaimKey, Value>) -> Option<String> {
    if extra.is_empty() {
        return None;
    }
    let mut ints: Vec<String> = Vec::new();
    let mut texts: Vec<String> = Vec::new();
    for (k, v) in extra {
        match k {
            ClaimKey::Int(n) => ints.push(format!("\"{n}\": {}", cbor_value(v))),
            ClaimKey::Text(t) => texts.push(format!("\"{}\": {}", escape(t), cbor_value(v))),
            other => texts.push(format!(
                "\"{}\": {}",
                escape(&other.to_string()),
                cbor_value(v)
            )),
        }
    }
    let mut parts = Vec::new();
    if !ints.is_empty() {
        parts.push(format!("\"int\": {{ {} }}", ints.join(", ")));
    }
    if !texts.is_empty() {
        parts.push(format!("\"text\": {{ {} }}", texts.join(", ")));
    }
    Some(format!("{{ {} }}", parts.join(", ")))
}
