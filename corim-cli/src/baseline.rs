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

use std::fmt::Write as _;
use std::fs;

use corim::baseline::{
    compare, ConformanceReport, MismatchKind, StructuralMismatch, ValueDifference,
};
use corim::cbor::value::Value;
use corim::types::corim::CorimMap;
use corim::types::signed::ProtectedCorimHeaderMap;

/// Compare the input against the baseline at `path`. Returns `Ok(true)`
/// when the input is structurally conformant.
///
/// Protected headers are compared only when **both** the baseline and the
/// target are signed. Payloads are compared whenever both sides carry one
/// (a detached signed CoRIM has no payload). Prints the report as text or
/// JSON (`format` is `"text"` or `"json"`).
pub fn run(
    input_payload: Option<&CorimMap>,
    input_header: Option<&ProtectedCorimHeaderMap>,
    path: &str,
    format: &str,
) -> Result<bool, String> {
    let baseline = load_corim(path)?;

    let mut report = ConformanceReport::default();
    let mut compared_header = false;
    let mut compared_payload = false;

    // Header: only when both baseline and target are signed.
    if let (Some(ih), Some(bh)) = (input_header, baseline.header.as_ref()) {
        report.merge(corim::baseline::compare_headers(ih, bh));
        compared_header = true;
    }
    // Payload: whenever both sides carry one.
    if let (Some(ip), Some(bp)) = (input_payload, baseline.payload.as_ref()) {
        report.merge(compare(ip, bp));
        compared_payload = true;
    }

    let target = describe_side(
        input_header.is_some(),
        input_payload.is_some(),
        "unsigned CoRIM",
    );
    let baseline_desc = describe_side(
        baseline.header.is_some(),
        baseline.payload.is_some(),
        baseline.source_unsigned_desc,
    );

    if !compared_header && !compared_payload {
        return Err(format!(
            "nothing to compare (baseline: {baseline_desc}; target: {target}). \
             Header comparison needs both sides signed; payload comparison needs \
             both sides to carry a payload."
        ));
    }

    if format == "json" {
        println!(
            "{}",
            render_json(
                &report,
                &baseline_desc,
                &target,
                compared_header,
                compared_payload
            )
        );
    } else {
        println!("Baseline: {baseline_desc}");
        println!("Target:   {target}");
        println!(
            "Comparing: {}",
            compared_scope(compared_header, compared_payload)
        );
        render_text(&report);
    }
    Ok(report.is_conformant())
}

/// A decoded baseline: its optional payload and optional protected header.
struct LoadedBaseline {
    payload: Option<CorimMap>,
    header: Option<ProtectedCorimHeaderMap>,
    /// Description used when the baseline is unsigned (JSON vs CBOR source).
    source_unsigned_desc: &'static str,
}

/// Human-readable description of one side's format.
fn describe_side(signed: bool, has_payload: bool, unsigned_desc: &str) -> String {
    match (signed, has_payload) {
        (true, true) => "signed CoRIM (attached payload)".into(),
        (true, false) => "signed CoRIM (detached payload)".into(),
        (false, _) => unsigned_desc.to_string(),
    }
}

fn compared_scope(header: bool, payload: bool) -> &'static str {
    match (header, payload) {
        (true, true) => "protected header + payload",
        (true, false) => "protected header",
        (false, true) => "payload",
        (false, false) => "nothing",
    }
}

/// Load a CoRIM from a JSON template, a CBOR CoRIM, or a signed CoRIM,
/// retaining the protected header (if signed) and payload (if present).
fn load_corim(path: &str) -> Result<LoadedBaseline, String> {
    let raw = fs::read(path).map_err(|e| format!("reading baseline {path}: {e}"))?;
    if raw.is_empty() {
        return Err("baseline is empty".into());
    }

    if is_json(&raw) {
        let json: serde_json::Value =
            serde_json::from_slice(&raw).map_err(|e| format!("parsing baseline JSON: {e}"))?;
        let bytes = crate::generate::build_corim_from_template(json, None)
            .map_err(|e| format!("building baseline from JSON template: {e}"))?;
        let (corim, _) = corim::validate::decode_and_validate(&bytes)
            .map_err(|e| format!("baseline is not a valid CoRIM: {e}"))?;
        return Ok(LoadedBaseline {
            payload: Some(corim),
            header: None,
            source_unsigned_desc: "unsigned CoRIM (from JSON template)",
        });
    }

    // CBOR. Try decoding as a signed CoRIM first: `decode_signed_corim`
    // recognizes both the bare `#6.18` tag and the legacy `#6.500`/`#6.502`
    // wrappers. If it isn't signed, fall back to an unsigned CoRIM.
    match corim::types::signed::decode_signed_corim(&raw) {
        Ok(env) => {
            let payload = match env.payload {
                Some(p) => {
                    let (corim, _) = corim::validate::decode_and_validate(&p).map_err(|e| {
                        format!("baseline signed payload is not a valid CoRIM: {e}")
                    })?;
                    Some(corim)
                }
                None => None,
            };
            Ok(LoadedBaseline {
                payload,
                header: Some(env.protected),
                source_unsigned_desc: "unsigned CoRIM",
            })
        }
        Err(_) => {
            let (corim, _) = corim::validate::decode_and_validate(&raw)
                .map_err(|e| format!("baseline is not a valid CoRIM: {e}"))?;
            Ok(LoadedBaseline {
                payload: Some(corim),
                header: None,
                source_unsigned_desc: "unsigned CoRIM",
            })
        }
    }
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
                render_value_short(&v.baseline),
                render_value_short(&v.input)
            );
        }
    }
}

fn render_json(
    report: &ConformanceReport,
    baseline_desc: &str,
    target_desc: &str,
    compared_header: bool,
    compared_payload: bool,
) -> String {
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
        "baseline_format": baseline_desc,
        "target_format": target_desc,
        "compared": compared_scope(compared_header, compared_payload),
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

/// Maximum rendered length of a value in text output. Certificate chains and
/// other long byte strings are elided; `--format json` always carries the
/// full value.
const MAX_TEXT_VALUE_LEN: usize = 96;

/// Accumulates a rendering while writing at most `limit` chars, tracking the
/// full length so the caller can report how much was elided. Byte strings are
/// hex-encoded only up to the budget, so a large `x5chain` is never fully
/// materialized just to be thrown away.
struct Capped {
    out: String,
    written: usize,
    total: usize,
    limit: usize,
}

impl Capped {
    fn new(limit: usize) -> Self {
        Self {
            out: String::new(),
            written: 0,
            total: 0,
            limit,
        }
    }

    fn push(&mut self, s: &str) {
        let n = s.chars().count();
        self.total += n;
        if self.written >= self.limit {
            return;
        }
        let room = self.limit - self.written;
        if n <= room {
            self.out.push_str(s);
            self.written += n;
        } else {
            self.out.extend(s.chars().take(room));
            self.written = self.limit;
        }
    }

    fn push_hex(&mut self, bytes: &[u8]) {
        self.total += bytes.len() * 2;
        if self.written >= self.limit {
            return;
        }
        let room = self.limit - self.written;
        let take = room.div_ceil(2).min(bytes.len());
        for b in &bytes[..take] {
            let _ = write!(self.out, "{b:02x}");
        }
        if take * 2 > room {
            self.out.pop();
        }
        self.written = (self.written + take * 2).min(self.limit);
    }

    fn finish(self) -> String {
        if self.total > self.limit {
            format!("{}… ({} chars total)", self.out, self.total)
        } else {
            self.out
        }
    }
}

/// Text-mode rendering of a value, eliding anything overly long.
fn render_value_short(v: &Value) -> String {
    let mut c = Capped::new(MAX_TEXT_VALUE_LEN);
    render_capped(v, &mut c);
    c.finish()
}

fn render_capped(v: &Value, c: &mut Capped) {
    match v {
        Value::Bytes(b) => c.push_hex(b),
        Value::Text(t) => c.push(t),
        Value::Integer(n) => c.push(&n.to_string()),
        Value::Float(f) => c.push(&f.to_string()),
        Value::Bool(b) => c.push(if *b { "true" } else { "false" }),
        Value::Null => c.push("null"),
        Value::Tag(t, inner) => {
            c.push(&format!("#6.{t}("));
            render_capped(inner, c);
            c.push(")");
        }
        Value::Array(a) => {
            c.push("[");
            for (i, item) in a.iter().enumerate() {
                if i > 0 {
                    c.push(", ");
                }
                render_capped(item, c);
            }
            c.push("]");
        }
        Value::Map(m) => {
            c.push("{");
            for (i, (k, val)) in m.iter().enumerate() {
                if i > 0 {
                    c.push(", ");
                }
                render_capped(k, c);
                c.push(": ");
                render_capped(val, c);
            }
            c.push("}");
        }
    }
}

/// Render a CBOR [`Value`] as a compact human string (bytes as hex,
/// tags as `#6.N(inner)`).
fn render_value(v: &Value) -> String {
    match v {
        Value::Bytes(b) => hex(b),
        Value::Text(t) => t.clone(),
        Value::Integer(n) => n.to_string(),
        Value::Float(f) => f.to_string(),
        Value::Bool(b) => b.to_string(),
        Value::Null => "null".into(),
        Value::Tag(t, inner) => format!("#6.{t}({})", render_value(inner)),
        Value::Array(a) => {
            let items: Vec<String> = a.iter().map(render_value).collect();
            format!("[{}]", items.join(", "))
        }
        Value::Map(m) => {
            let items: Vec<String> = m
                .iter()
                .map(|(k, val)| format!("{}: {}", render_value(k), render_value(val)))
                .collect();
            format!("{{{}}}", items.join(", "))
        }
    }
}

/// Render a CBOR [`Value`] into a JSON value (bytes as hex; tags as the
/// `{"__cbor_tag": N, "__cbor_value": ...}` envelope).
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
        Value::Float(f) => serde_json::Number::from_f64(*f)
            .map(serde_json::Value::Number)
            .unwrap_or(serde_json::Value::Null),
        Value::Bool(b) => serde_json::Value::Bool(*b),
        Value::Null => serde_json::Value::Null,
        Value::Array(a) => serde_json::Value::Array(a.iter().map(value_to_json).collect()),
        Value::Tag(t, inner) => serde_json::json!({
            "__cbor_tag": t,
            "__cbor_value": value_to_json(inner),
        }),
        Value::Map(m) => {
            let mut obj = serde_json::Map::new();
            for (k, val) in m {
                obj.insert(render_value(k), value_to_json(val));
            }
            serde_json::Value::Object(obj)
        }
    }
}

fn hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn short_values_are_not_elided() {
        let v = Value::Text("hello".into());
        assert_eq!(render_value_short(&v), "hello");
    }

    #[test]
    fn value_exactly_at_the_limit_is_not_elided() {
        let v = Value::Text("x".repeat(MAX_TEXT_VALUE_LEN));
        let out = render_value_short(&v);
        assert!(!out.contains("chars total"), "{out}");
        assert_eq!(out.chars().count(), MAX_TEXT_VALUE_LEN);
    }

    #[test]
    fn long_bytes_are_elided_with_the_full_length() {
        // 1 KiB of bytes renders as 2048 hex chars.
        let v = Value::Bytes(vec![0xab; 1024]);
        let out = render_value_short(&v);
        assert!(out.ends_with("… (2048 chars total)"), "{out}");
        let head: String = out.chars().take(MAX_TEXT_VALUE_LEN).collect();
        assert_eq!(head, "ab".repeat(MAX_TEXT_VALUE_LEN / 2));
    }

    /// The hex prefix is encoded a whole byte at a time, so an odd remaining
    /// budget must still cut cleanly at the limit.
    #[test]
    fn odd_budget_cuts_hex_at_the_limit() {
        // "[" + hex ... : one char consumed before the byte string, leaving an
        // odd budget for the hex.
        let v = Value::Array(vec![Value::Bytes(vec![0xcd; 1024])]);
        let out = render_value_short(&v);
        let head: String = out.chars().take(MAX_TEXT_VALUE_LEN).collect();
        assert_eq!(head.chars().count(), MAX_TEXT_VALUE_LEN);
        assert!(head.starts_with("[cd"), "{head}");
        // 1 ("[") + 2048 (hex) + 1 ("]") = 2050
        assert!(out.ends_with("… (2050 chars total)"), "{out}");
    }

    #[test]
    fn elision_never_exceeds_the_limit_for_nested_values() {
        let v = Value::Map(vec![(
            Value::Text("k".into()),
            Value::Array(vec![
                Value::Bytes(vec![0x01; 512]),
                Value::Bytes(vec![0x02; 512]),
            ]),
        )]);
        let out = render_value_short(&v);
        let head: String = out.chars().take(MAX_TEXT_VALUE_LEN).collect();
        assert_eq!(head.chars().count(), MAX_TEXT_VALUE_LEN);
        assert!(out.contains("chars total"), "{out}");
    }
}
