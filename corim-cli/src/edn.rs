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

use corim::cbor::value::Value;
use corim::cbor::{DecodeLimits, DecodeSession};
use corim::error::DecodeError;
use corim::types::signed::{COSE_HEADER_CORIM_META, COSE_HEADER_PAYLOAD_HASH_ALG};
use corim::types::tags::{TAG_COMID, TAG_COSWID, TAG_COTL, TAG_SIGNED_CORIM};

/// Render a CBOR byte string as EDN. The decoder is the same one used by
/// the CoRIM library so anything that round-trips through the library
/// will render cleanly here.
pub fn render(bytes: &[u8]) -> Result<String, String> {
    corim::validate::check_document_framing(bytes, &DecodeLimits::default())
        .map_err(|e| format!("CBOR decode failed: {e}"))?;
    let mut renderer = Renderer::new().map_err(|e| e.to_string())?;
    let v = renderer
        .decode(bytes, 0)
        .map_err(|e| format!("CBOR decode failed: {e}"))?;
    let mut out = String::new();
    renderer
        .write_value(&v, 0, 0, Ctx::Top, &mut out)
        .map_err(|e| format!("CBOR decode failed: {e}"))?;
    out.push('\n');
    Ok(out)
}

/// Position context that controls schema-aware bstr unwrapping.
#[derive(Clone, Copy, PartialEq)]
enum Ctx {
    Top,
    /// Inside a `#6.18(array)` — elements 0 (protected) and 2 (payload)
    /// are bstr-wrapped CBOR.
    CoseSign1Array,
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

/// One budget spans the outer value and every embedded decode, regardless of
/// schema position. `nesting` is separate from visual indentation: tags and
/// embedded byte strings consume depth even when they render on the same line.
struct Renderer {
    limits: DecodeLimits,
    session: DecodeSession,
}

impl Renderer {
    fn new() -> Result<Self, DecodeError> {
        let limits = DecodeLimits::default();
        Ok(Self {
            session: DecodeSession::new(&limits)?,
            limits,
        })
    }

    fn check_depth(&self, nesting: usize) -> Result<(), DecodeError> {
        if nesting > self.limits.max_depth {
            return Err(DecodeError::LimitExceeded {
                resource: "depth",
                limit: self.limits.max_depth,
            });
        }
        Ok(())
    }

    fn decode(&mut self, bytes: &[u8], nesting: usize) -> Result<Value, DecodeError> {
        self.session.decode_nested_exact(bytes, nesting)
    }

    fn write_value(
        &mut self,
        v: &Value,
        depth: usize,
        nesting: usize,
        ctx: Ctx,
        out: &mut String,
    ) -> Result<(), DecodeError> {
        self.check_depth(nesting)?;
        match v {
            Value::Integer(n) => out.push_str(&n.to_string()),
            Value::Text(s) => {
                out.push('"');
                out.push_str(&corim::cbor::value::escape_text(s));
                out.push('"');
            }
            Value::Bytes(b) => write_hex(b, out),
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
            Value::Array(items) => self.write_array(items, depth, nesting, ctx, out)?,
            Value::Map(entries) => self.write_map(entries, depth, nesting, ctx, out)?,
            Value::Tag(tag, inner) => self.write_tag(*tag, inner, depth, nesting, out)?,
        }
        Ok(())
    }

    fn write_array(
        &mut self,
        items: &[Value],
        depth: usize,
        nesting: usize,
        ctx: Ctx,
        out: &mut String,
    ) -> Result<(), DecodeError> {
        if items.is_empty() {
            out.push_str("[]");
            return Ok(());
        }
        out.push_str("[\n");
        let mut hash_payload = false;
        for (i, item) in items.iter().enumerate() {
            indent(out, depth + 1);
            match (ctx, i, item) {
                (Ctx::CoseSign1Array, 0, Value::Bytes(b)) => match self.decode(b, nesting + 2) {
                    Ok(header) => {
                        if let Value::Map(fields) = &header {
                            hash_payload = fields.iter().any(|(k, _)| {
                                k == &Value::Integer(i128::from(COSE_HEADER_PAYLOAD_HASH_ALG))
                            });
                        }
                        out.push_str("<<");
                        self.write_value(
                            &header,
                            depth + 1,
                            nesting + 2,
                            Ctx::ProtectedHeaderMap,
                            out,
                        )?;
                        out.push_str(">>");
                    }
                    Err(e @ DecodeError::LimitExceeded { .. })
                    | Err(e @ DecodeError::TrailingData { .. }) => return Err(e),
                    Err(_) => write_hex(b, out),
                },
                (Ctx::CoseSign1Array, 2, Value::Bytes(b)) if !hash_payload => {
                    self.write_embedded_bstr(b, depth + 1, nesting + 1, Ctx::Top, out)?;
                }
                _ => self.write_value(item, depth + 1, nesting + 1, Ctx::Top, out)?,
            }
            if i + 1 < items.len() {
                out.push(',');
            }
            out.push('\n');
        }
        indent(out, depth);
        out.push(']');
        Ok(())
    }

    fn write_map(
        &mut self,
        entries: &[(Value, Value)],
        depth: usize,
        nesting: usize,
        ctx: Ctx,
        out: &mut String,
    ) -> Result<(), DecodeError> {
        if entries.is_empty() {
            out.push_str("{}");
            return Ok(());
        }
        out.push_str("{\n");
        for (i, (k, v)) in entries.iter().enumerate() {
            indent(out, depth + 1);
            self.write_value(k, depth + 1, nesting + 1, Ctx::Top, out)?;
            out.push_str(": ");
            match (ctx, k, v) {
                (Ctx::ProtectedHeaderMap, Value::Integer(key), Value::Bytes(b))
                    if *key == i128::from(COSE_HEADER_CORIM_META) =>
                {
                    self.write_embedded_bstr(b, depth + 1, nesting + 1, Ctx::Top, out)?;
                }
                _ => self.write_value(v, depth + 1, nesting + 1, Ctx::Top, out)?,
            }
            if i + 1 < entries.len() {
                out.push(',');
            }
            out.push('\n');
        }
        indent(out, depth);
        out.push('}');
        Ok(())
    }

    fn write_tag(
        &mut self,
        tag: u64,
        inner: &Value,
        depth: usize,
        nesting: usize,
        out: &mut String,
    ) -> Result<(), DecodeError> {
        out.push_str(&format!("#6.{}(", tag));
        match (tag, inner) {
            (TAG_COSWID | TAG_COMID | TAG_COTL, Value::Bytes(b)) => {
                self.write_embedded_bstr(b, depth, nesting + 1, Ctx::Top, out)?;
            }
            (TAG_SIGNED_CORIM, Value::Array(_)) => {
                self.write_value(inner, depth, nesting + 1, Ctx::CoseSign1Array, out)?;
            }
            _ => self.write_value(inner, depth, nesting + 1, Ctx::Top, out)?,
        }
        out.push(')');
        Ok(())
    }

    /// Syntax failures retain the raw hex fallback; framing and resource failures are fatal.
    fn write_embedded_bstr(
        &mut self,
        b: &[u8],
        depth: usize,
        nesting: usize,
        ctx: Ctx,
        out: &mut String,
    ) -> Result<(), DecodeError> {
        match self.decode(b, nesting + 1) {
            Ok(v) => {
                out.push_str("<<");
                self.write_value(&v, depth, nesting + 1, ctx, out)?;
                out.push_str(">>");
            }
            Err(e @ DecodeError::LimitExceeded { .. })
            | Err(e @ DecodeError::TrailingData { .. }) => return Err(e),
            Err(_) => write_hex(b, out),
        }
        Ok(())
    }
}

fn write_hex(bytes: &[u8], out: &mut String) {
    out.push_str("h'");
    for byte in bytes {
        out.push_str(&format!("{byte:02x}"));
    }
    out.push('\'');
}
