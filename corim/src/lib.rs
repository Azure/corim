// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! CoRIM (Concise Reference Integrity Manifest) — Rust library.
//!
//! This crate provides Rust types for the CoRIM/CoMID CDDL schema
//! ([draft-ietf-rats-corim-11](https://www.ietf.org/archive/id/draft-ietf-rats-corim-11.html)),
//! CBOR encoding/decoding (via a swappable backend), a builder API for
//! constructing CoRIM and CoMID structures, and validation per the spec.
//!
//! # Quick example
//!
//! ```rust
//! use corim::builder::{ComidBuilder, CorimBuilder};
//! use corim::types::common::{TagIdChoice, MeasuredElement};
//! use corim::types::corim::CorimId;
//! use corim::types::environment::{ClassMap, EnvironmentMap};
//! use corim::types::measurement::{Digest, MeasurementMap, MeasurementValuesMap};
//! use corim::types::triples::ReferenceTriple;
//!
//! let env = EnvironmentMap {
//!     class: Some(ClassMap {
//!         class_id: None, vendor: Some("ACME".into()),
//!         model: Some("Widget".into()), layer: None, index: None,
//!     }),
//!     instance: None, group: None,
//! };
//!
//! let meas = MeasurementMap {
//!     mkey: Some(MeasuredElement::Text("firmware".into())),
//!     mval: MeasurementValuesMap {
//!         digests: Some(vec![Digest::new(7, vec![0xAA; 48])]),
//!         ..MeasurementValuesMap::default()
//!     },
//!     authorized_by: None,
//! };
//!
//! let comid = ComidBuilder::new(TagIdChoice::Text("my-tag".into()))
//!     .add_reference_triple(ReferenceTriple::new(env, vec![meas]))
//!     .build().unwrap();
//!
//! let bytes = CorimBuilder::new(CorimId::Text("my-corim".into()))
//!     .add_comid_tag(comid).unwrap()
//!     .build_bytes().unwrap();
//!
//! let (_corim, _comids) = corim::validate::decode_and_validate(&bytes).unwrap();
//! ```
//!
//! # CBOR backend
//!
//! This crate includes an in-house minimal CBOR encoder/decoder that
//! guarantees RFC 8949 §4.2.1 deterministic encoding with zero external
//! CBOR dependencies. The [`cbor::CborCodec`] trait is designed so that
//! alternative backends (e.g., ciborium) can be added behind feature gates
//! in the future without changing any public APIs.
//!
//! ## CBOR implementation limitations
//!
//! The built-in CBOR codec covers the subset needed by CoRIM. Known
//! limitations (none of which affect CoRIM functionality):
//!
//! - **No indefinite-length encoding** — rejected on decode. CoRIM/CoMID
//!   CDDL uses definite-length only.
//! - **Float encoding is always float64** — half and single precision floats
//!   are decoded correctly, but encoding always uses 8-byte float64. CoRIM
//!   data rarely uses floats (only `cwt-claims` exp/nbf, which are `int`).
//! - **No CBOR simple values** beyond `false`, `true`, `null` — other simple
//!   values (0–19, 32–255) are rejected. Not used in CoRIM.
//! - **No CBOR sequences** — only single top-level items. CoRIM always has
//!   a single tagged wrapper.
//! - **Maximum nesting depth** is limited by the call stack (~100+ levels).
//!   CoRIM documents are typically 5–10 levels deep.
//!
//! # Compliance notes
//!
//! This crate implements CoRIM per draft-ietf-rats-corim-11.
//!
//! ## Tag coverage
//!
//! The RFC defines three tag types inside a CoRIM `tags` array:
//!
//! | Tag | CBOR | Status |
//! |-----|------|--------|
//! | **CoMID** (§5) | `#6.506` | ✅ Fully modeled — types, builder, validation, appraisal |
//! | **CoTL** (§6) | `#6.508` | ✅ Fully modeled — `ConciseTlTag`, `CotlBuilder`, validity checks |
//! | **CoSWID** (RFC 9393) | `#6.505` | ✅ Structured — `ConciseSwidTag`, `SwidEntity`, `SwidLink`; payload/evidence opaque |
//!
//! ## Signed CoRIM (`#6.18`)
//!
//! The crate supports **decoding, structural validation, and construction**
//! of signed CoRIM documents (`COSE_Sign1-corim`) per §4.2. Cryptographic
//! signature verification is intentionally **not** performed — the caller
//! is responsible for verifying signatures using their preferred crypto
//! library. The crate provides:
//!
//! - [`types::signed::decode_signed_corim`]: Parse `#6.18` COSE_Sign1 structures
//! - [`types::signed::validate_signed_corim_payload`]: Validate attached payloads
//! - [`types::signed::validate_signed_corim_payload_detached`]: Validate detached payloads
//! - [`types::signed::SignedCorimBuilder`]: Construct signed CoRIM with external signing
//!   (attached via `build_with_signature` or detached via `build_detached_with_signature`)
//! - [`types::signed::CoseSign1Corim::to_be_signed`]: Emit TBS for attached payloads
//! - [`types::signed::CoseSign1Corim::to_be_signed_detached`]: Emit TBS for detached payloads
//!
//! Additionally:
//! - **CoTS** (`draft-ietf-rats-concise-ta-stores`) is a separate draft, not modeled.
//! - **CDDL extension sockets** (`$$corim-map-extension`, etc.) are not
//!   modeled; unknown CBOR map keys are silently skipped for forward
//!   compatibility.
//! - **`raw-value-mask-DEPRECATED`** (key 5) is accepted on decode but not
//!   exposed as a struct field.
//!
//! ## `no_std` support
//!
//! The `corim` crate supports `#![no_std]` with the `alloc` crate.
//! Disable the default `std` feature:
//!
//! ```toml
//! corim = { version = "0.1", default-features = false }
//! ```
//!
//! The `std` feature (on by default) adds [`validate::decode_and_validate`]
//! and [`validate::decode_and_validate_full`] which use `SystemTime::now()`.
//! The `_at` variants that take an explicit timestamp work in `no_std`.
//! The `json` feature requires `std`.

#![cfg_attr(docsrs, feature(doc_cfg))]
#![cfg_attr(not(feature = "std"), no_std)]

// In no_std mode, alloc provides String, Vec, Box, format!, vec!, etc.
// The #[macro_use] brings format! and vec! macros into scope crate-wide.
#[cfg_attr(not(feature = "std"), macro_use)]
extern crate alloc;

// Re-export std when available so modules can `use std::time::SystemTime` etc.
// In no_std mode, modules must use core:: and alloc:: directly.
#[cfg(feature = "std")]
extern crate std;

/// Internal prelude for no_std compatibility.
///
/// All modules should `use crate::nostd_prelude::*;` to get String, Vec, Box
/// and other alloc types regardless of std/no_std mode.
#[allow(unused_imports)]
pub(crate) mod nostd_prelude {
    pub use alloc::borrow::ToOwned;
    pub use alloc::boxed::Box;
    pub use alloc::collections::BTreeMap;
    pub use alloc::string::{String, ToString};
    pub use alloc::vec;
    pub use alloc::vec::Vec;
}

pub mod cbor;
pub mod error;
pub mod types;

pub mod builder;
/// Decode-only interop helpers (legacy tag stripping, etc.). See module docs.
pub mod compat;
/// **Unstable** — debugging-only structural inspector. The shapes of the
/// types in this module may change between minor versions without a
/// deprecation cycle. Production code should use [`validate::decode_and_validate`].
pub mod diagnose;
/// Profile-extension registry and trait. See module docs for how
/// profile-aware crates plug into validation and diagnosis.
pub mod profile;
pub mod validate;

#[cfg(feature = "json")]
#[cfg_attr(docsrs, doc(cfg(feature = "json")))]
pub mod json;

pub use error::{BuilderError, DecodeError, EncodeError, ValidationError};

/// Trait for types that can self-validate per the CoRIM specification.
///
/// Each type validates its own constraints (non-empty maps,
/// size limits, structural invariants) without requiring an external validator.
///
/// # Example
///
/// ```rust
/// use corim::Validate;
/// use corim::types::environment::{ClassMap, EnvironmentMap};
///
/// let env = EnvironmentMap::for_class("ACME", "Widget");
/// assert!(env.valid().is_ok());
///
/// let empty_env = EnvironmentMap { class: None, instance: None, group: None };
/// assert!(empty_env.valid().is_err());
/// ```
pub trait Validate {
    /// Validate that this value satisfies its specification constraints.
    ///
    /// Returns `Ok(())` if valid, or a human-readable error message.
    fn valid(&self) -> Result<(), alloc::string::String>;
}
