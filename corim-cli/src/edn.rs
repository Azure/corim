// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! CBOR Extended Diagnostic Notation (EDN) renderer.
//!
//! Implements RFC 8949 §8 EDN with the `<<...>>` embedded-CBOR extension
//! (RFC 8610 §G.4) at well-known CoRIM positions:
//!
//! - `#6.505(bstr)` / `#6.506(bstr)` / `#6.508(bstr)` — the three CDDL-defined
//!   `concise-*-tag` types wrap an embedded CBOR map. Always unwrapped.
//! - `#6.18([h'...', {...}, h'...' / nil, h'...'])` — `COSE_Sign1`. The
//!   protected-header bstr (element 0) and the payload bstr (element 2,
//!   when present) are decoded and rendered as `<<...>>`.
//! - Inside a decoded COSE protected header, key `8` is the
//!   `corim-meta` bstr (`bstr .cbor corim-meta-map`); it is also unwrapped.

use corim::cbor::minimal::{decode_value, SliceReader};
use corim::cbor::value::Value;

/// Render a CBOR byte string as EDN. The decoder is the same one used by
/// the CoRIM library so anything that round-trips through the library
/// will render cleanly here.
pub fn render(bytes: &[u8]) -> Result<String, String> {
    let mut reader = SliceReader::new(bytes);
    let v = decode_value(&mut reader).map_err(|e| format!("CBOR decode failed: {}", e))?;
    let mut out = String::new();
    write_value(&v, 0, Ctx::Top, &mut out);
    out.push('\n');
    Ok(out)
}

/// Position context that controls schema-aware bstr unwrapping.
#[derive(Clone, Copy, PartialEq)]
enum Ctx {
    Top,
    /// Inside a `#6.18(array)` — elements 0 (protected) and 2 (payload)
    /// are bstr-wrapped CBOR; track the index so we can unwrap them.
    CoseSign1Array(usize),
    /// Inside a CBOR map that is itself the decoded COSE protected
    /// header (i.e. element 0 of a `#6.18` array). Key 8 (`corim-meta`)
    /// is bstr-wrapped CBOR.
    ProtectedHeaderMap,
}

const INDENT: &str = "  ";

fn indent(out: &mut String, depth: usize) {
    for _ in 0..depth {
        out.push_str(INDENT);
    }
}

fn write_value(v: &Value, depth: usize, ctx: Ctx, out: &mut String) {
    match v {
        Value::Integer(n) => out.push_str(&n.to_string()),
        Value::Text(s) => {
            out.push('"');
            for c in s.chars() {
                match c {
                    '"' => out.push_str("\\\""),
                    '\\' => out.push_str("\\\\"),
                    '\n' => out.push_str("\\n"),
                    '\r' => out.push_str("\\r"),
                    '\t' => out.push_str("\\t"),
                    c if (c as u32) < 0x20 => {
                        out.push_str(&format!("\\u{:04x}", c as u32));
                    }
                    c => out.push(c),
                }
            }
            out.push('"');
        }
        Value::Bytes(b) => {
            out.push_str("h'");
            for byte in b {
                out.push_str(&format!("{:02x}", byte));
            }
            out.push('\'');
        }
        Value::Bool(b) => out.push_str(if *b { "true" } else { "false" }),
        Value::Null => out.push_str("null"),
        Value::Float(f) => {
            if f.is_nan() {
                out.push_str("NaN");
            } else if f.is_infinite() {
                out.push_str(if *f > 0.0 { "Infinity" } else { "-Infinity" });
            } else {
                out.push_str(&format!("{}_3", f));
            }
        }
        Value::Array(items) => write_array(items, depth, ctx, out),
        Value::Map(entries) => write_map(entries, depth, ctx, out),
        Value::Tag(tag, inner) => write_tag(*tag, inner, depth, ctx, out),
    }
}

fn write_array(items: &[Value], depth: usize, ctx: Ctx, out: &mut String) {
    if items.is_empty() {
        out.push_str("[]");
        return;
    }
    out.push_str("[\n");
    for (i, item) in items.iter().enumerate() {
        indent(out, depth + 1);
        if matches!(ctx, Ctx::CoseSign1Array(_)) {
            // Render with bstr-unwrap for COSE_Sign1 elements 0 and 2.
            write_value_in_cose_elem(item, depth + 1, i, out);
        } else {
            write_value(item, depth + 1, Ctx::Top, out);
        }
        if i + 1 < items.len() {
            out.push(',');
        }
        out.push('\n');
    }
    indent(out, depth);
    out.push(']');
}

/// Render an element of a `#6.18(array)` body, with bstr-unwrap for
/// elements 0 (protected header) and 2 (payload). Element 1 is the
/// unprotected map (rendered as a normal map). Element 3 is the signature.
fn write_value_in_cose_elem(v: &Value, depth: usize, idx: usize, out: &mut String) {
    match (idx, v) {
        // protected header bstr
        (0, Value::Bytes(b)) => write_embedded_bstr(b, depth, Ctx::ProtectedHeaderMap, out),
        // payload bstr (could be #6.501(corim-map) or a hash digest)
        (2, Value::Bytes(b)) => write_embedded_bstr(b, depth, Ctx::Top, out),
        _ => write_value(v, depth, Ctx::Top, out),
    }
}

fn write_map(entries: &[(Value, Value)], depth: usize, ctx: Ctx, out: &mut String) {
    if entries.is_empty() {
        out.push_str("{}");
        return;
    }
    out.push_str("{\n");
    for (i, (k, v)) in entries.iter().enumerate() {
        indent(out, depth + 1);
        write_value(k, depth + 1, Ctx::Top, out);
        out.push_str(": ");
        // Inside a COSE protected-header map, key 8 is corim-meta bstr.
        if ctx == Ctx::ProtectedHeaderMap {
            if let (Value::Integer(8), Value::Bytes(b)) = (k, v) {
                write_embedded_bstr(b, depth + 1, Ctx::Top, out);
            } else {
                write_value(v, depth + 1, Ctx::Top, out);
            }
        } else {
            write_value(v, depth + 1, Ctx::Top, out);
        }
        if i + 1 < entries.len() {
            out.push(',');
        }
        out.push('\n');
    }
    indent(out, depth);
    out.push('}');
}

fn write_tag(tag: u64, inner: &Value, depth: usize, _ctx: Ctx, out: &mut String) {
    out.push_str(&format!("#6.{}(", tag));
    match (tag, inner) {
        // concise-mid / concise-swid / concise-tl tags wrap embedded CBOR
        (505 | 506 | 508, Value::Bytes(b)) => {
            write_embedded_bstr(b, depth, Ctx::Top, out);
        }
        // COSE_Sign1 — descend with the special array context
        (18, Value::Array(items)) => {
            write_array(items, depth, Ctx::CoseSign1Array(0), out);
        }
        _ => write_value(inner, depth, Ctx::Top, out),
    }
    out.push(')');
}

/// Try to decode `b` as CBOR and emit it as `<<...>>`. If decoding fails
/// fall back to the raw `h'...'` form so the renderer never lies.
fn write_embedded_bstr(b: &[u8], depth: usize, ctx: Ctx, out: &mut String) {
    let mut reader = SliceReader::new(b);
    match decode_value(&mut reader) {
        Ok(v) => {
            out.push_str("<<");
            write_value(&v, depth, ctx, out);
            out.push_str(">>");
        }
        Err(_) => {
            out.push_str("h'");
            for byte in b {
                out.push_str(&format!("{:02x}", byte));
            }
            out.push('\'');
        }
    }
}
