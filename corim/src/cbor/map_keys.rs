// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Duplicate-label checks for schema maps (RFC 8949 §5.6).
//! Generic `Value` parsing deliberately retains every pair for inspection.

use super::value::Value;
use crate::error::DecodeError;
use crate::nostd_prelude::*;
use alloc::collections::BTreeSet;

/// Walk an already depth-bounded schema tree. Bytes remain opaque. Typed maps
/// use integer/text labels; other key types are left to schema validation.
pub(crate) fn check(value: &Value) -> Result<(), DecodeError> {
    match value {
        Value::Map(entries) => {
            let mut integers = BTreeSet::new();
            let mut texts = BTreeSet::new();
            for (key, value) in entries {
                match key {
                    Value::Integer(n) if !integers.insert(*n) => {
                        return Err(DecodeError::DuplicateKey { key: n.to_string() });
                    }
                    Value::Text(t) if !texts.insert(t.as_str()) => {
                        return Err(DecodeError::DuplicateKey {
                            key: format!("\"{}\"", super::value::escape_text(t)),
                        });
                    }
                    _ => {}
                }
                check(key)?;
                check(value)?;
            }
        }
        Value::Array(items) => {
            for item in items {
                check(item)?;
            }
        }
        Value::Tag(_, inner) => check(inner)?,
        _ => {}
    }
    Ok(())
}

/// Protected headers alone permit the documented, decode-only flat-CWT
/// exception. These duplicate-label wire maps are not standard CBOR maps.
pub(crate) fn check_header(value: &Value) -> Result<(), DecodeError> {
    use crate::types::signed::{COSE_HEADER_ALG, CWT_CLAIM_EXP, CWT_CLAIM_NBF, CWT_CLAIM_SUB};
    let Value::Map(entries) = value else {
        return Ok(());
    };
    let mut seen = BTreeMap::new();
    let mut texts = BTreeSet::new();
    for (key, value) in entries {
        match key {
            Value::Integer(n) => {
                let role = match (i64::try_from(*n).ok(), value) {
                    (Some(COSE_HEADER_ALG), Value::Integer(_))
                    | (Some(CWT_CLAIM_SUB), Value::Array(_))
                    | (Some(CWT_CLAIM_EXP | CWT_CLAIM_NBF), Value::Bytes(_)) => 1_u8,
                    (Some(COSE_HEADER_ALG | CWT_CLAIM_SUB), Value::Text(_))
                    | (Some(CWT_CLAIM_EXP | CWT_CLAIM_NBF), Value::Integer(_) | Value::Float(_)) => {
                        2_u8
                    }
                    _ => 0_u8,
                };
                if let Some(previous) = seen.get_mut(n) {
                    if !matches!((*previous, role), (1, 2) | (2, 1)) {
                        return Err(DecodeError::DuplicateKey { key: n.to_string() });
                    }
                    *previous = 0;
                } else {
                    seen.insert(*n, role);
                }
            }
            Value::Text(t) if !texts.insert(t.as_str()) => {
                return Err(DecodeError::DuplicateKey {
                    key: format!("\"{}\"", super::value::escape_text(t)),
                });
            }
            _ => {}
        }
        check(value)?;
    }
    Ok(())
}
