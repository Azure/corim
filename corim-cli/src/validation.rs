//! Shared non-cryptographic document validation for CLI inputs and baselines.

use corim::cbor::{self, value::Value, DecodeLimits};
use corim::profile::ProfileRegistry;
use corim::types::signed::{self, CoseSign1Corim};
use corim::types::tags::{TAG_LEGACY_SIGNED, TAG_LEGACY_TOP, TAG_SIGNED_CORIM};
use corim::validate::{self, ValidatedCorim};

pub(crate) struct Document {
    pub payload: ValidatedCorim,
    pub signed: Option<CoseSign1Corim>,
    pub legacy_wrappers: bool,
}

pub(crate) fn now() -> Result<i64, String> {
    let seconds = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|error| format!("system clock: {error}"))?
        .as_secs();
    i64::try_from(seconds).map_err(|_| "system clock exceeds i64 range".into())
}

pub(crate) fn document(
    bytes: &[u8],
    now: Option<i64>,
    registry: &ProfileRegistry,
) -> Result<Document, String> {
    validate::check_document_framing(bytes, &DecodeLimits::default())
        .map_err(|error| error.to_string())?;
    let mut root: Value = cbor::decode_exact(bytes).map_err(|error| error.to_string())?;
    let mut legacy_wrappers = false;
    while let Value::Tag(TAG_LEGACY_TOP | TAG_LEGACY_SIGNED, inner) = root {
        legacy_wrappers = true;
        root = *inner;
    }
    let is_signed = matches!(root, Value::Tag(TAG_SIGNED_CORIM, _));
    drop(root);
    let limits = DecodeLimits::default();
    let (signed, payload) = if is_signed {
        let (signed, payload) = match now {
            Some(now) => {
                signed::decode_and_validate_signed_corim_at_with_limits(bytes, None, now, &limits)
            }
            None => {
                signed::decode_and_validate_signed_corim_structure_with_limits(bytes, None, &limits)
            }
        }
        .map_err(|error| error.to_string())?;
        (Some(signed), payload)
    } else {
        let payload = match now {
            Some(now) => validate::decode_and_validate_document_at_with_limits(bytes, now, &limits),
            None => validate::decode_and_validate_structure_with_limits(bytes, &limits),
        }
        .map_err(|error| error.to_string())?;
        (None, payload)
    };
    if payload.coswid_opaque_count != 0 {
        return Err("cannot validate opaque CoSWID content".into());
    }
    validate::validate_corim_profile(&payload.corim, &payload.comids, registry)
        .map_err(|error| error.to_string())?;
    Ok(Document {
        payload,
        signed,
        legacy_wrappers,
    })
}
