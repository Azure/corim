// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Minimal in-house CBOR encoder/decoder.
//!
//! Implements the subset of CBOR needed by CoRIM:
//! - Major types 0–5 (unsigned int, negative int, byte string, text string, array, map)
//! - Major type 6 (semantic tags)
//! - Major type 7 (simple values: false, true, null, float64)
//! - Deterministic encoding per RFC 8949 §4.2.1
//!
//! Does **not** support:
//! - Indefinite-length encoding
//! - Half/single precision floats
//! - Simple values other than false/true/null

/// Maximum number of items allowed in a single CBOR array or map.
///
/// Prevents excessive memory allocation from maliciously crafted inputs
/// even within the 16 MiB payload limit. A single item is at minimum 1 byte,
/// so 2 million items × 1 byte = 2 MB — well within limits.
#[allow(unused_imports)]
use crate::nostd_prelude::*;
const MAX_COLLECTION_ITEMS: usize = 2_000_000;

// Import CBOR wire-format constants.
// In match arms we use fully-qualified `c::` prefix to avoid Rust interpreting
// UPPER_CASE identifiers as variable bindings.
use super::constants as c;

// ═══════════════════════════════════════════════════════════════════════════
// Encoder
// ═══════════════════════════════════════════════════════════════════════════

/// Encode a CBOR major type + argument in deterministic (shortest) form.
///
/// Per RFC 8949 §4.2.1, the argument is encoded in the shortest form that
/// can represent the value.
fn encode_head(w: &mut Vec<u8>, major: u8, val: u64) {
    let mt = major << 5;
    if val <= c::AI_MAX_INLINE as u64 {
        w.push(mt | val as u8);
    } else if val <= u8::MAX as u64 {
        w.extend_from_slice(&[mt | c::AI_ONE_BYTE, val as u8]);
    } else if val <= u16::MAX as u64 {
        let b = (val as u16).to_be_bytes();
        w.extend_from_slice(&[mt | c::AI_TWO_BYTES, b[0], b[1]]);
    } else if val <= u32::MAX as u64 {
        let b = (val as u32).to_be_bytes();
        w.extend_from_slice(&[mt | c::AI_FOUR_BYTES, b[0], b[1], b[2], b[3]]);
    } else {
        let b = val.to_be_bytes();
        let mut buf = [0u8; 9];
        buf[0] = mt | c::AI_EIGHT_BYTES;
        buf[1..9].copy_from_slice(&b);
        w.extend_from_slice(&buf);
    }
}

/// Encode a dynamic [`Value`](super::value::Value) to CBOR bytes.
///
/// Writes are infallible since the target is a `Vec<u8>`.
/// Returns `Err` only for values outside the CBOR representable range.
pub fn encode_value(w: &mut Vec<u8>, val: &super::value::Value) -> Result<(), EncodeError> {
    use super::value::Value;
    match val {
        Value::Integer(n) => {
            if *n >= 0 {
                let arg = u64::try_from(*n).map_err(|_| {
                    EncodeError("positive integer above 2^64-1 cannot be encoded in CBOR")
                })?;
                encode_head(w, c::MAJOR_UNSIGNED, arg);
            } else {
                let arg_i128 = -1_i128 - *n;
                let arg = u64::try_from(arg_i128).map_err(|_| {
                    EncodeError("negative integer below -(2^64) cannot be encoded in CBOR")
                })?;
                encode_head(w, c::MAJOR_NEGATIVE, arg);
            }
        }
        Value::Bytes(b) => {
            encode_head(w, c::MAJOR_BYTES, b.len() as u64);
            w.extend_from_slice(b);
        }
        Value::Text(t) => {
            encode_head(w, c::MAJOR_TEXT, t.len() as u64);
            w.extend_from_slice(t.as_bytes());
        }
        Value::Array(arr) => {
            encode_head(w, c::MAJOR_ARRAY, arr.len() as u64);
            for item in arr {
                encode_value(w, item)?;
            }
        }
        Value::Map(entries) => {
            let mut items: Vec<(Vec<u8>, &super::value::Value, &super::value::Value)> = entries
                .iter()
                .map(|(k, v)| {
                    let mut kb = Vec::new();
                    // Key encoding into a Vec is infallible for sortable keys.
                    encode_value(&mut kb, k).expect("key encoding cannot fail for canonical sort");
                    (kb, k, v)
                })
                .collect();
            items.sort_by(|(a, _, _), (b, _, _)| a.len().cmp(&b.len()).then_with(|| a.cmp(b)));

            encode_head(w, c::MAJOR_MAP, items.len() as u64);
            for (_, k, v) in &items {
                encode_value(w, k)?;
                encode_value(w, v)?;
            }
        }
        Value::Tag(tag, inner) => {
            encode_head(w, c::MAJOR_TAG, *tag);
            encode_value(w, inner)?;
        }
        Value::Bool(true) => w.push(c::BYTE_TRUE),
        Value::Bool(false) => w.push(c::BYTE_FALSE),
        Value::Null => w.push(c::BYTE_NULL),
        Value::Float(f) => {
            let b = f.to_bits().to_be_bytes();
            let mut buf = [0u8; 9];
            buf[0] = c::BYTE_FLOAT64;
            buf[1..9].copy_from_slice(&b);
            w.extend_from_slice(&buf);
        }
    }
    Ok(())
}

/// Encoder-only error (value outside CBOR representable range).
#[derive(Debug)]
pub struct EncodeError(pub &'static str);

impl core::fmt::Display for EncodeError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(self.0)
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// Decoder
// ═══════════════════════════════════════════════════════════════════════════

/// CBOR decode error.
#[derive(Debug)]
pub enum CborError {
    /// Unexpected end of input.
    Eof,
    /// Invalid CBOR encoding.
    Invalid(String),
}

impl core::fmt::Display for CborError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            CborError::Eof => write!(f, "unexpected end of CBOR input"),
            CborError::Invalid(s) => write!(f, "invalid CBOR: {}", s),
        }
    }
}

/// A minimal reader over a byte slice (replaces `std::io::Cursor` for `no_std`).
pub struct SliceReader<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> SliceReader<'a> {
    pub fn new(data: &'a [u8]) -> Self {
        Self { data, pos: 0 }
    }

    fn read_u8(&mut self) -> Result<u8, CborError> {
        if self.pos >= self.data.len() {
            return Err(CborError::Eof);
        }
        let b = self.data[self.pos];
        self.pos += 1;
        Ok(b)
    }

    fn read_exact(&mut self, len: usize) -> Result<&'a [u8], CborError> {
        if self.pos + len > self.data.len() {
            return Err(CborError::Eof);
        }
        let slice = &self.data[self.pos..self.pos + len];
        self.pos += len;
        Ok(slice)
    }
}

/// Decode the argument from a CBOR head byte.
fn decode_arg(r: &mut SliceReader<'_>, additional: u8) -> Result<u64, CborError> {
    match additional {
        0..=c::AI_MAX_INLINE => Ok(additional as u64),
        c::AI_ONE_BYTE => Ok(r.read_u8()? as u64),
        c::AI_TWO_BYTES => {
            let b = r.read_exact(2)?;
            Ok(u16::from_be_bytes([b[0], b[1]]) as u64)
        }
        c::AI_FOUR_BYTES => {
            let b = r.read_exact(4)?;
            Ok(u32::from_be_bytes([b[0], b[1], b[2], b[3]]) as u64)
        }
        c::AI_EIGHT_BYTES => {
            let b = r.read_exact(8)?;
            Ok(u64::from_be_bytes([
                b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7],
            ]))
        }
        _ => Err(CborError::Invalid(format!(
            "invalid additional info {}",
            additional
        ))),
    }
}

/// Decode a single CBOR [`Value`](super::value::Value) from a byte slice reader.
pub fn decode_value(r: &mut SliceReader<'_>) -> Result<super::value::Value, CborError> {
    use super::value::Value;

    let head = r.read_u8()?;
    let major = head >> 5;
    let additional = head & 0x1F;

    match major {
        c::MAJOR_UNSIGNED => {
            let val = decode_arg(r, additional)?;
            Ok(Value::Integer(val as i128))
        }
        c::MAJOR_NEGATIVE => {
            let val = decode_arg(r, additional)?;
            Ok(Value::Integer(-1 - i128::from(val)))
        }
        c::MAJOR_BYTES => {
            if additional == c::AI_INDEFINITE {
                return Err(CborError::Invalid(
                    "indefinite-length bytes not supported".into(),
                ));
            }
            let len = usize::try_from(decode_arg(r, additional)?).map_err(|_| {
                CborError::Invalid("byte string length exceeds platform capacity".into())
            })?;
            let data = r.read_exact(len)?;
            Ok(Value::Bytes(data.to_vec()))
        }
        c::MAJOR_TEXT => {
            if additional == c::AI_INDEFINITE {
                return Err(CborError::Invalid(
                    "indefinite-length text not supported".into(),
                ));
            }
            let len = usize::try_from(decode_arg(r, additional)?).map_err(|_| {
                CborError::Invalid("text string length exceeds platform capacity".into())
            })?;
            let data = r.read_exact(len)?;
            let text = String::from_utf8(data.to_vec())
                .map_err(|e| CborError::Invalid(format!("invalid UTF-8: {}", e)))?;
            Ok(Value::Text(text))
        }
        c::MAJOR_ARRAY => {
            if additional == c::AI_INDEFINITE {
                return Err(CborError::Invalid(
                    "indefinite-length array not supported".into(),
                ));
            }
            let count = usize::try_from(decode_arg(r, additional)?)
                .map_err(|_| CborError::Invalid("array length exceeds platform capacity".into()))?;
            if count > MAX_COLLECTION_ITEMS {
                return Err(CborError::Invalid(format!(
                    "array length {} exceeds maximum {}",
                    count, MAX_COLLECTION_ITEMS
                )));
            }
            let mut arr = Vec::with_capacity(count.min(1024));
            for _ in 0..count {
                arr.push(decode_value(r)?);
            }
            Ok(Value::Array(arr))
        }
        c::MAJOR_MAP => {
            if additional == c::AI_INDEFINITE {
                return Err(CborError::Invalid(
                    "indefinite-length map not supported".into(),
                ));
            }
            let count = usize::try_from(decode_arg(r, additional)?)
                .map_err(|_| CborError::Invalid("map length exceeds platform capacity".into()))?;
            if count > MAX_COLLECTION_ITEMS {
                return Err(CborError::Invalid(format!(
                    "map length {} exceeds maximum {}",
                    count, MAX_COLLECTION_ITEMS
                )));
            }
            let mut map = Vec::with_capacity(count.min(1024));
            for _ in 0..count {
                let k = decode_value(r)?;
                let v = decode_value(r)?;
                map.push((k, v));
            }
            Ok(Value::Map(map))
        }
        c::MAJOR_TAG => {
            let tag = decode_arg(r, additional)?;
            let inner = decode_value(r)?;
            Ok(Value::Tag(tag, Box::new(inner)))
        }
        c::MAJOR_SIMPLE => match additional {
            c::SIMPLE_FALSE => Ok(Value::Bool(false)),
            c::SIMPLE_TRUE => Ok(Value::Bool(true)),
            c::SIMPLE_NULL => Ok(Value::Null),
            c::FLOAT_HALF => {
                let b = r.read_exact(2)?;
                let half = u16::from_be_bytes([b[0], b[1]]);
                Ok(Value::Float(f16_to_f64(half)))
            }
            c::FLOAT_SINGLE => {
                let b = r.read_exact(4)?;
                let val = f32::from_be_bytes([b[0], b[1], b[2], b[3]]);
                Ok(Value::Float(val as f64))
            }
            c::FLOAT_DOUBLE => {
                let b = r.read_exact(8)?;
                let val = f64::from_be_bytes([b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7]]);
                Ok(Value::Float(val))
            }
            _ => Err(CborError::Invalid(format!(
                "unsupported simple value {}",
                additional
            ))),
        },
        _ => Err(CborError::Invalid(format!("unknown major type {}", major))),
    }
}

/// Convert IEEE 754 half-precision float to f64.
///
/// Uses bit manipulation instead of `f64::powi()` for `no_std` compatibility.
fn f16_to_f64(half: u16) -> f64 {
    let sign = ((half >> 15) & 1) as u64;
    let exp = ((half >> 10) & 0x1F) as u32;
    let mant = (half & 0x3FF) as u64;

    if exp == 0 {
        // Subnormal or zero: value = (-1)^sign * 2^(-14) * (mant / 1024)
        // = (-1)^sign * mant * 2^(-24)
        let val = f64::from_bits((mant as f64).to_bits()) * ldexp2(-24);
        if sign == 1 {
            -val
        } else {
            val
        }
    } else if exp == 31 {
        // Inf or NaN
        if mant == 0 {
            if sign == 1 {
                f64::NEG_INFINITY
            } else {
                f64::INFINITY
            }
        } else {
            f64::NAN
        }
    } else {
        // Normal: value = (-1)^sign * 2^(exp-15) * (1 + mant/1024)
        // = (-1)^sign * (1024 + mant) * 2^(exp-25)
        let significand = (1024 + mant) as f64;
        let val = significand * ldexp2(exp as i32 - 25);
        if sign == 1 {
            -val
        } else {
            val
        }
    }
}

/// Compute 2^exp using f64 bit manipulation (no_std compatible).
/// Only valid for exp in [-1074, 1023].
fn ldexp2(exp: i32) -> f64 {
    // For reasonable exponent range, construct the f64 directly.
    // f64 = sign(1) | biased_exp(11) | mantissa(52)
    // 2^exp = 0 | (exp+1023) | 0...0  when exp >= -1022
    if exp >= -1022 {
        let bits = ((exp + 1023) as u64) << 52;
        f64::from_bits(bits)
    } else {
        // Subnormal territory: 2^exp = 2^(-1022) * 2^(exp+1022)
        // For the half-float subnormal case, exp = -24 which is fine.
        let bits = 1u64 << (exp + 1074);
        f64::from_bits(bits)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cbor::value::Value;

    fn round_trip(val: &Value) -> Value {
        let mut buf = Vec::new();
        encode_value(&mut buf, val).unwrap();
        let mut reader = SliceReader::new(&buf);
        decode_value(&mut reader).unwrap()
    }

    #[test]
    fn integers() {
        assert_eq!(round_trip(&Value::Integer(0)), Value::Integer(0));
        assert_eq!(round_trip(&Value::Integer(23)), Value::Integer(23));
        assert_eq!(round_trip(&Value::Integer(24)), Value::Integer(24));
        assert_eq!(round_trip(&Value::Integer(255)), Value::Integer(255));
        assert_eq!(round_trip(&Value::Integer(256)), Value::Integer(256));
        assert_eq!(round_trip(&Value::Integer(65535)), Value::Integer(65535));
        assert_eq!(
            round_trip(&Value::Integer(1000000)),
            Value::Integer(1000000)
        );
        assert_eq!(round_trip(&Value::Integer(-1)), Value::Integer(-1));
        assert_eq!(round_trip(&Value::Integer(-100)), Value::Integer(-100));
        assert_eq!(round_trip(&Value::Integer(-1000)), Value::Integer(-1000));
    }

    #[test]
    fn bytes_and_text() {
        assert_eq!(round_trip(&Value::Bytes(vec![])), Value::Bytes(vec![]));
        assert_eq!(
            round_trip(&Value::Bytes(vec![1, 2, 3])),
            Value::Bytes(vec![1, 2, 3])
        );
        assert_eq!(round_trip(&Value::Text("".into())), Value::Text("".into()));
        assert_eq!(
            round_trip(&Value::Text("hello".into())),
            Value::Text("hello".into())
        );
    }

    #[test]
    fn arrays_and_maps() {
        let arr = Value::Array(vec![Value::Integer(1), Value::Text("two".into())]);
        assert_eq!(round_trip(&arr), arr);

        let map = Value::Map(vec![
            (Value::Integer(0), Value::Text("zero".into())),
            (Value::Integer(1), Value::Bool(true)),
        ]);
        assert_eq!(round_trip(&map), map);
    }

    #[test]
    fn tags() {
        let tagged = Value::Tag(
            501,
            Box::new(Value::Map(vec![(
                Value::Integer(0),
                Value::Text("id".into()),
            )])),
        );
        assert_eq!(round_trip(&tagged), tagged);
    }

    #[test]
    fn simple_values() {
        assert_eq!(round_trip(&Value::Bool(true)), Value::Bool(true));
        assert_eq!(round_trip(&Value::Bool(false)), Value::Bool(false));
        assert_eq!(round_trip(&Value::Null), Value::Null);
    }

    #[test]
    fn deterministic_integer_encoding() {
        // Verify shortest-form encoding per RFC 8949 §4.2.1
        let mut buf = Vec::new();
        encode_value(&mut buf, &Value::Integer(0)).unwrap();
        assert_eq!(buf, vec![0x00]); // single byte

        buf.clear();
        encode_value(&mut buf, &Value::Integer(23)).unwrap();
        assert_eq!(buf, vec![0x17]); // single byte

        buf.clear();
        encode_value(&mut buf, &Value::Integer(24)).unwrap();
        assert_eq!(buf, vec![0x18, 0x18]); // 2 bytes

        buf.clear();
        encode_value(&mut buf, &Value::Integer(255)).unwrap();
        assert_eq!(buf, vec![0x18, 0xFF]); // 2 bytes

        buf.clear();
        encode_value(&mut buf, &Value::Integer(256)).unwrap();
        assert_eq!(buf, vec![0x19, 0x01, 0x00]); // 3 bytes
    }

    #[test]
    fn eof_on_truncated() {
        let result = decode_value(&mut SliceReader::new(&[0x58])); // byte string claiming 1-byte length but no data
        assert!(result.is_err());
    }

    #[test]
    fn rejects_indefinite_length() {
        // 0x5F = indefinite-length byte string
        let result = decode_value(&mut SliceReader::new(&[0x5F]));
        assert!(result.is_err());
    }
}
