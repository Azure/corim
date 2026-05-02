// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Proc-macro derive crate for CBOR integer-keyed map serialization.
//!
//! Provides `CborSerialize` and `CborDeserialize` derives that generate
//! `serde::Serialize` and `serde::Deserialize` implementations using
//! `serialize_map` / `MapAccess` visitors with integer keys — required for
//! CoRIM CDDL types where every map uses integer keys, not string field names.
//!
//! # Supported attributes
//!
//! ## Struct-level
//! - `#[cbor(tag = <u64>)]` — wrap the serialized form in a CBOR semantic tag
//! - `#[cbor(non_empty)]` — enforce at least one field is present
//!
//! ## Field-level
//! - `#[cbor(key = <int>)]` — CBOR integer key for this field (required)
//! - `#[cbor(optional)]` — field is `Option<T>`; skip on `None`, tolerate absence

use proc_macro::TokenStream;
use syn::{parse_macro_input, DeriveInput};

mod attrs;
// Codegen for `#[derive(CborTagChoice)]` lands in subsequent commits;
// the parser already lives here so the attribute grammar can be reviewed
// in isolation.
#[allow(dead_code)]
mod choice_attrs;
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
