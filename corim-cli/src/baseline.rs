// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! `validate --baseline`: structural conformance of the input CoRIM
//! against a known-good baseline.
//!
//! The baseline may be a CBOR CoRIM (tag 501), a signed CoRIM (tag 18,
//! attached payload), or a JSON template (same shape `generate` accepts).
//! It is decoded and validated, then compared with the input via
//! [`corim::baseline::compare`]. The library returns a structured report;
//! this module owns the text and JSON presentation and the exit-code
//! semantics.

use std::fs;

use corim::baseline::{
    compare, ConformanceReport, MismatchKind, StructuralMismatch, ValueDifference,
};
use corim::cbor::value::Value;
use corim::types::corim::CorimMap;

/// Compare `input` against the baseline at `path`. Returns `Ok(true)`
/// when the input is structurally conformant. Prints the report as text
/// or JSON (`format` is `"text"` or `"json"`).
pub fn run(input: &CorimMap, path: &str, format: &str) -> Result<bool, String> {
    let baseline = load_corim(path)?;
    let report = compare(input, &baseline);
    if format == "json" {
        println!("{}", render_json(&report));
    } else {
        render_text(&report);
    }
    Ok(report.is_conformant())
}

/// Load a CoRIM from a JSON template, a CBOR CoRIM, or a signed CoRIM,
/// then decode-and-validate it into a [`CorimMap`].
fn load_corim(path: &str) -> Result<CorimMap, String> {
    let raw = fs::read(path).map_err(|e| format!("reading baseline {path}: {e}"))?;
    if raw.is_empty() {
        return Err("baseline is empty".into());
    }

    let bytes = if is_json(&raw) {
        let json: serde_json::Value =
            serde_json::from_slice(&raw).map_err(|e| format!("parsing baseline JSON: {e}"))?;
        crate::generate::build_corim_from_template(json, None)
            .map_err(|e| format!("building baseline from JSON template: {e}"))?
    } else {
        // CBOR. Try decoding as a signed CoRIM first: `decode_signed_corim`
        // recognizes both the bare `#6.18` tag and the legacy
        // `#6.500`/`#6.502` wrappers. If it isn't a signed CoRIM, fall back
        // to treating the bytes as an unsigned CoRIM.
        match corim::types::signed::decode_signed_corim(&raw) {
            Ok(env) => env.payload.ok_or_else(|| {
                "baseline is a detached signed CoRIM (nil payload); supply the unsigned CoRIM"
                    .to_string()
            })?,
            Err(_) => raw,
        }
    };

    let (corim, _) = corim::validate::decode_and_validate(&bytes)
        .map_err(|e| format!("baseline is not a valid CoRIM: {e}"))?;
    Ok(corim)
}

/// A byte buffer is treated as a JSON template if its first non-whitespace
/// byte is `{`.
fn is_json(raw: &[u8]) -> bool {
    raw.iter()
        .position(|b| !b.is_ascii_whitespace())
        .map(|i| raw[i] == b'{')
        .unwrap_or(false)
}

// ---------------------------------------------------------------------------
// Rendering
// ---------------------------------------------------------------------------

fn result_str(report: &ConformanceReport) -> &'static str {
    if !report.structural_mismatches.is_empty() {
        "structural-mismatch"
    } else if !report.value_differences.is_empty() {
        "value-differences"
    } else {
        "match"
    }
}

fn render_text(report: &ConformanceReport) {
    println!("═══ Baseline conformance ═══");
    match result_str(report) {
        "match" => println!("✓ input is structurally conformant (identical values)"),
        "value-differences" => {
            println!(
                "✓ input is structurally conformant ({} value difference(s))",
                report.value_differences.len()
            );
        }
        _ => println!(
            "✗ input is NOT structurally conformant ({} structural mismatch(es))",
            report.structural_mismatches.len()
        ),
    }

    if !report.structural_mismatches.is_empty() {
        println!("\nStructural mismatches (conformance failures):");
        for m in &report.structural_mismatches {
            println!(
                "  {} — {} [{}]",
                corim::baseline::render_path(&m.path),
                m.detail,
                mismatch_kind_str(&m.kind)
            );
        }
    }
    if !report.value_differences.is_empty() {
        println!("\nValue differences (informational):");
        for v in &report.value_differences {
            println!(
                "  {} {}: {} → {}",
                corim::baseline::render_path(&v.path),
                v.field,
                render_value(&v.baseline),
                render_value(&v.input)
            );
        }
    }
}

fn render_json(report: &ConformanceReport) -> String {
    let structural: Vec<serde_json::Value> = report
        .structural_mismatches
        .iter()
        .map(structural_json)
        .collect();
    let values: Vec<serde_json::Value> = report
        .value_differences
        .iter()
        .map(value_diff_json)
        .collect();

    let out = serde_json::json!({
        "result": result_str(report),
        "conformant": report.is_conformant(),
        "summary": {
            "structural_mismatches": report.structural_mismatches.len(),
            "value_differences": report.value_differences.len(),
        },
        "structural_mismatches": structural,
        "value_differences": values,
    });
    serde_json::to_string_pretty(&out).unwrap_or_else(|_| "{}".into())
}

fn structural_json(m: &StructuralMismatch) -> serde_json::Value {
    let mut obj = serde_json::json!({
        "path": corim::baseline::render_path(&m.path),
        "kind": mismatch_kind_str(&m.kind),
        "detail": m.detail,
    });
    if let MismatchKind::TypeMismatch { baseline, input } = &m.kind {
        obj["baseline_type"] = serde_json::Value::String(baseline.clone());
        obj["input_type"] = serde_json::Value::String(input.clone());
    }
    obj
}

fn value_diff_json(v: &ValueDifference) -> serde_json::Value {
    serde_json::json!({
        "path": corim::baseline::render_path(&v.path),
        "field": v.field,
        "baseline": value_to_json(&v.baseline),
        "input": value_to_json(&v.input),
    })
}

fn mismatch_kind_str(k: &MismatchKind) -> &'static str {
    match k {
        MismatchKind::MissingInInput => "missing-in-input",
        MismatchKind::UnexpectedInInput => "unexpected-in-input",
        MismatchKind::TypeMismatch { .. } => "type-mismatch",
        _ => "structural-mismatch",
    }
}

/// Render a CBOR [`Value`] as a compact human string (bytes as hex).
fn render_value(v: &Value) -> String {
    match v {
        Value::Bytes(b) => hex(b),
        Value::Text(t) => t.clone(),
        Value::Integer(n) => n.to_string(),
        Value::Bool(b) => b.to_string(),
        Value::Null => "null".into(),
        other => format!("{other:?}"),
    }
}

/// Render a CBOR [`Value`] into a JSON value (bytes as a hex string).
fn value_to_json(v: &Value) -> serde_json::Value {
    match v {
        Value::Bytes(b) => serde_json::Value::String(hex(b)),
        Value::Text(t) => serde_json::Value::String(t.clone()),
        Value::Integer(n) => {
            // `Value::Integer` is an `i128`; `serde_json` numbers only cover
            // i64/u64, so fall back to a string for out-of-range values
            // rather than risking a serializer failure.
            if let Ok(x) = i64::try_from(*n) {
                serde_json::json!(x)
            } else if let Ok(x) = u64::try_from(*n) {
                serde_json::json!(x)
            } else {
                serde_json::Value::String(n.to_string())
            }
        }
        Value::Bool(b) => serde_json::Value::Bool(*b),
        Value::Null => serde_json::Value::Null,
        Value::Array(a) => serde_json::Value::Array(a.iter().map(value_to_json).collect()),
        other => serde_json::Value::String(format!("{other:?}")),
    }
}

fn hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}
