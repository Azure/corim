// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Proc-macro derive crate for CBOR integer-keyed map serialization
//! and CBOR tag-choice enum serialization.
//!
//! Provides:
//!
//! - `CborSerialize` / `CborDeserialize` derives for **structs** that map to
//!   CDDL integer-keyed maps (e.g. `corim-map`, `concise-mid-tag`).
//! - `CborTagChoiceSerialize` / `CborTagChoiceDeserialize` derives for
//!   **enums** that model CDDL tag-choice productions (e.g.
//!   `$class-id-type-choice`, `$crypto-key-type-choice`).
//!
//! # Supported attributes
//!
//! ## Struct (CborSerialize / CborDeserialize)
//!
//! Struct-level:
//! - `#[cbor(tag = <u64>)]` — wrap the serialized form in a CBOR semantic tag
//! - `#[cbor(non_empty)]` — enforce at least one field is present
//!
//! Field-level:
//! - `#[cbor(key = <int>)]` — CBOR integer key for this field (required)
//! - `#[cbor(optional)]` — field is `Option<T>`; skip on `None`, tolerate absence
//! - `#[cbor(bytes)]` — `Vec<u8>` / `[u8; N]` field; emit as CBOR bstr
//!
//! ## Enum (CborTagChoice…)
//!
//! See the doc-comments on [`CborTagChoiceSerialize`] and
//! [`CborTagChoiceDeserialize`] below for the supported variant
//! attributes.

use proc_macro::TokenStream;
use syn::{parse_macro_input, DeriveInput};

mod attrs;
mod choice_attrs;
mod choice_de;
mod choice_ser;
mod de;
mod ser;

/// Derive `serde::Serialize` using integer-keyed CBOR map encoding.
///
/// Fields must be annotated with `#[cbor(key = <int>)]`.
/// Optional fields use `#[cbor(optional)]` and must be `Option<T>`.
#[proc_macro_derive(CborSerialize, attributes(cbor))]
pub fn derive_cbor_serialize(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as DeriveInput);
    match ser::expand_serialize(&input) {
        Ok(ts) => ts.into(),
        Err(e) => e.to_compile_error().into(),
    }
}

/// Derive `serde::Deserialize` using integer-keyed CBOR map decoding.
///
/// Fields must be annotated with `#[cbor(key = <int>)]`.
/// Optional fields use `#[cbor(optional)]` and must be `Option<T>`.
#[proc_macro_derive(CborDeserialize, attributes(cbor))]
pub fn derive_cbor_deserialize(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as DeriveInput);
    match de::expand_deserialize(&input) {
        Ok(ts) => ts.into(),
        Err(e) => e.to_compile_error().into(),
    }
}

/// Derive `serde::Serialize` for a CBOR tag-choice enum.
///
/// Each variant must be a single-field tuple variant carrying one of:
///
/// - `#[cbor(tag = N)]` — encoded as `#6.N(inner)`
/// - `#[cbor(tag = N, bytes)]` — same, but the inner field is `Vec<u8>` /
///   `[u8; M]` and must encode as a CBOR `bstr` (not a CBOR array).
///   Mirrors `#[cbor(bytes)]` on struct fields.
/// - `#[cbor(text)]` — inline `tstr` (no CBOR tag)
/// - `#[cbor(uint)]` — inline unsigned integer (no CBOR tag)
///
/// The `accept_bare = "uuid_16"` and `custom_validate = "fn"` attributes
/// affect deserialization only and are silently accepted here.
///
/// See [`CborTagChoiceDeserialize`](macro@CborTagChoiceDeserialize) for
/// the deserialize-only attributes.
#[proc_macro_derive(CborTagChoiceSerialize, attributes(cbor))]
pub fn derive_cbor_tag_choice_serialize(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as DeriveInput);
    match choice_ser::expand_tag_choice_serialize(&input) {
        Ok(ts) => ts.into(),
        Err(e) => e.to_compile_error().into(),
    }
}

/// Derive `serde::Deserialize` for a CBOR tag-choice enum.
///
/// See [`CborTagChoiceSerialize`](macro@CborTagChoiceSerialize) for the
/// shared attribute grammar. The Deserialize half additionally honors:
///
/// - `#[cbor(tag = N, accept_bare = "uuid_16")]` on a variant — accepts a
///   bare 16-byte CBOR `bstr` (no tag) on decode and routes it to that
///   variant. Used for the interop relaxation observed across CoRIM
///   producers that omit tag 37 on UUIDs.
/// - `#[cbor(tag = N, bytes, catch_bare_bytes)]` on at most one variant —
///   any bare bstr (no tag, any length not already routed by an
///   `accept_bare` rule) lands here. The variant's inner field must be
///   `Vec<u8>`.
/// - `#[cbor(custom_validate = "path::to::fn")]` on the enum — invokes
///   `fn(&value) -> Result<(), String>` after construction; an `Err(msg)`
///   becomes `serde::de::Error::custom(msg)`.
#[proc_macro_derive(CborTagChoiceDeserialize, attributes(cbor))]
pub fn derive_cbor_tag_choice_deserialize(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as DeriveInput);
    match choice_de::expand_tag_choice_deserialize(&input) {
        Ok(ts) => ts.into(),
        Err(e) => e.to_compile_error().into(),
    }
}
