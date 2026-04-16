// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! CBOR wire-format constants from RFC 8949 (STD 94).
//!
//! All numeric values in this module come directly from
//! [RFC 8949](https://www.rfc-editor.org/rfc/rfc8949) — Concise Binary Object
//! Representation (CBOR). They describe the wire format structure: major types,
//! additional information encoding, and well-known simple values.

// ═══════════════════════════════════════════════════════════════════════════
// Major types (RFC 8949 §3.1, Table 1)
// ═══════════════════════════════════════════════════════════════════════════

/// Major type 0: unsigned integer.
pub const MAJOR_UNSIGNED: u8 = 0;
/// Major type 1: negative integer (value = -1 - argument).
pub const MAJOR_NEGATIVE: u8 = 1;
/// Major type 2: byte string.
pub const MAJOR_BYTES: u8 = 2;
/// Major type 3: UTF-8 text string.
pub const MAJOR_TEXT: u8 = 3;
/// Major type 4: array of data items.
pub const MAJOR_ARRAY: u8 = 4;
/// Major type 5: map of pairs of data items.
pub const MAJOR_MAP: u8 = 5;
/// Major type 6: semantic tag.
pub const MAJOR_TAG: u8 = 6;
/// Major type 7: simple values, floats, and break.
pub const MAJOR_SIMPLE: u8 = 7;

// ═══════════════════════════════════════════════════════════════════════════
// Additional information values (RFC 8949 §3)
// ═══════════════════════════════════════════════════════════════════════════

/// Maximum value encoded inline in the initial byte (0–23).
pub const AI_MAX_INLINE: u8 = 23;
/// Additional information: 1-byte argument follows.
pub const AI_ONE_BYTE: u8 = 24;
/// Additional information: 2-byte argument follows (network byte order).
pub const AI_TWO_BYTES: u8 = 25;
/// Additional information: 4-byte argument follows (network byte order).
pub const AI_FOUR_BYTES: u8 = 26;
/// Additional information: 8-byte argument follows (network byte order).
pub const AI_EIGHT_BYTES: u8 = 27;
/// Additional information: indefinite-length indicator (not supported by this crate).
pub const AI_INDEFINITE: u8 = 31;

// ═══════════════════════════════════════════════════════════════════════════
// Simple values — major type 7 (RFC 8949 §3.3, Table 4)
// ═══════════════════════════════════════════════════════════════════════════

/// Simple value `false` (major 7, additional 20).
pub const SIMPLE_FALSE: u8 = 20;
/// Simple value `true` (major 7, additional 21).
pub const SIMPLE_TRUE: u8 = 21;
/// Simple value `null` (major 7, additional 22).
pub const SIMPLE_NULL: u8 = 22;
/// Simple value `undefined` (major 7, additional 23) — not used by CoRIM.
pub const SIMPLE_UNDEFINED: u8 = 23;

// ═══════════════════════════════════════════════════════════════════════════
// Float sub-types — major type 7 (RFC 8949 §3.3)
// ═══════════════════════════════════════════════════════════════════════════

/// IEEE 754 half-precision float (16-bit), major 7, additional 25.
pub const FLOAT_HALF: u8 = 25;
/// IEEE 754 single-precision float (32-bit), major 7, additional 26.
pub const FLOAT_SINGLE: u8 = 26;
/// IEEE 754 double-precision float (64-bit), major 7, additional 27.
pub const FLOAT_DOUBLE: u8 = 27;

// ═══════════════════════════════════════════════════════════════════════════
// Pre-computed initial bytes for simple values and floats
// ═══════════════════════════════════════════════════════════════════════════

/// Initial byte for `false`: `0xF4` (major 7 << 5 | 20).
pub const BYTE_FALSE: u8 = (MAJOR_SIMPLE << 5) | SIMPLE_FALSE;
/// Initial byte for `true`: `0xF5` (major 7 << 5 | 21).
pub const BYTE_TRUE: u8 = (MAJOR_SIMPLE << 5) | SIMPLE_TRUE;
/// Initial byte for `null`: `0xF6` (major 7 << 5 | 22).
pub const BYTE_NULL: u8 = (MAJOR_SIMPLE << 5) | SIMPLE_NULL;
/// Initial byte for float64: `0xFB` (major 7 << 5 | 27).
pub const BYTE_FLOAT64: u8 = (MAJOR_SIMPLE << 5) | FLOAT_DOUBLE;
