// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Signed CoRIM (`#6.18(COSE-Sign1-corim)`) types per §4.2.
//!
//! Provides types for parsing and constructing signed CoRIM documents
//! without requiring any cryptographic dependencies. The caller performs
//! the actual signature creation/verification externally.
//!
//! # Wire format
//!
//! ```text
//! signed-corim = #6.18(COSE-Sign1-corim)
//!
//! COSE-Sign1-corim = [
//!   protected: bstr .cbor protected-corim-header-map,
//!   unprotected: unprotected-corim-header-map,
//!   payload: bstr .cbor tagged-unsigned-corim-map / nil,
//!   signature: bstr,
//! ]
//! ```
//!
//! # Module layout
//!
//! - [`algorithm`] — [`CoseAlgorithm`] (RFC 9864)
//! - [`x509`] — [`CoseX509`], [`CoseCertHash`], `kid`/`x5*` constants (RFC 9360)
//! - [`cwt`] — [`CwtClaims`] + `CWT_CLAIM_*` constants (RFC 8392 / RFC 9597)
//! - [`header`] — [`ProtectedCorimHeaderMap`] + builder + COSE header constants (§4.2.1)
//! - [`envelope`] — [`CoseSign1Corim`] + encode/decode/TBS helpers (§4.2)
//! - [`builder`] — [`SignedCorimBuilder`] for assembling signed CoRIMs

pub mod algorithm;
pub use algorithm::CoseAlgorithm;

pub mod x509;
pub use x509::{
    CoseCertHash, CoseX509, COSE_HEADER_KID, COSE_HEADER_X5BAG, COSE_HEADER_X5CHAIN,
    COSE_HEADER_X5T, COSE_HEADER_X5U,
};

pub mod cwt;
pub use cwt::{
    CwtClaims, CWT_CLAIM_EXP, CWT_CLAIM_IAT, CWT_CLAIM_ISS, CWT_CLAIM_NBF, CWT_CLAIM_SUB,
};

pub mod header;
pub use header::{
    ProtectedCorimHeaderMap, ProtectedCorimHeaderMapBuilder, CORIM_CONTENT_TYPE, COSE_HEADER_ALG,
    COSE_HEADER_CONTENT_TYPE, COSE_HEADER_CORIM_META, COSE_HEADER_CWT_CLAIMS,
    COSE_HEADER_PAYLOAD_HASH_ALG, COSE_HEADER_PAYLOAD_LOCATION, COSE_HEADER_PAYLOAD_PREIMAGE_CT,
};

pub mod envelope;
pub use envelope::{
    build_sig_structure1, decode_signed_corim, encode_signed_corim, validate_signed_corim_payload,
    validate_signed_corim_payload_detached, CoseSign1Corim,
};

pub mod builder;
pub use builder::SignedCorimBuilder;
