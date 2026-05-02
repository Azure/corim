// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Codegen for `#[derive(CborTagChoiceSerialize)]`.
//!
//! Emits a `serde::Serialize` impl that dispatches on enum variant:
//!
//! - `#[cbor(tag = N)]`         → `value::serialize_tagged(N, &self.0, s)`
//! - `#[cbor(tag = N, bytes)]`  → `value::serialize_tagged_bytes(N, &self.0, s)`
//!   (the `_bytes` form wraps in `Value::Bytes` directly so `Vec<u8>` /
//!   `[u8; M]` survive as CBOR `bstr`, not as a CBOR array of integers)
//! - `#[cbor(text)]`            → `s.serialize_str(&self.0)`
//! - `#[cbor(uint)]`            → `s.serialize_u64(*self.0)` (after deref)
//!
//! The `accept_bare = "uuid_16"` rule and `custom_validate` hook are
//! decode-time only and have no effect on serialize codegen.

use proc_macro2::TokenStream;
use quote::quote;
use syn::{Data, DeriveInput};

use crate::choice_attrs::{parse_choice_variants, ChoiceVariantKind};

pub fn expand_tag_choice_serialize(input: &DeriveInput) -> syn::Result<TokenStream> {
    let name = &input.ident;
    let (impl_generics, ty_generics, where_clause) = input.generics.split_for_impl();

    let data = match &input.data {
        Data::Enum(e) => e,
        _ => {
            return Err(syn::Error::new_spanned(
                input,
                "CborTagChoiceSerialize only supports enums",
            ))
        }
    };

    let variants = parse_choice_variants(data)?;

    let arms: Vec<TokenStream> = variants
        .iter()
        .map(|v| {
            let vid = &v.ident;
            match &v.kind {
                ChoiceVariantKind::Tagged {
                    tag,
                    bytes,
                    text,
                    accept_bare_uuid: _,
                    catch_bare_bytes: _,
                } => {
                    if *bytes {
                        // `Vec<u8>` and `[u8; M]` both deref/borrow to `&[u8]`.
                        // The leading `&*` forces the deref-coercion path so
                        // both shapes work without per-variant type sniffing.
                        quote! {
                            #name::#vid(inner) => {
                                crate::cbor::value::serialize_tagged_bytes(#tag, &*inner, s)
                            }
                        }
                    } else if *text {
                        // Inner is `String` (or `&str`). Wrap as `Value::Text` so
                        // the tagged form encodes as `#6.N(tstr)` and on decode
                        // the strict-shape Deserialize requires Value::Text.
                        quote! {
                            #name::#vid(inner) => {
                                crate::cbor::value::serialize_tagged(
                                    #tag,
                                    &crate::cbor::value::Value::Text(inner.clone()),
                                    s,
                                )
                            }
                        }
                    } else {
                        quote! {
                            #name::#vid(inner) => {
                                crate::cbor::value::serialize_tagged(#tag, inner, s)
                            }
                        }
                    }
                }
                ChoiceVariantKind::InlineText => {
                    quote! {
                        #name::#vid(inner) => s.serialize_str(inner),
                    }
                }
                ChoiceVariantKind::InlineUint => {
                    quote! {
                        #name::#vid(inner) => s.serialize_u64(*inner),
                    }
                }
            }
        })
        .collect();

    Ok(quote! {
        impl #impl_generics serde::Serialize for #name #ty_generics #where_clause {
            fn serialize<__S>(&self, s: __S) -> ::core::result::Result<__S::Ok, __S::Error>
            where
                __S: serde::Serializer,
            {
                match self {
                    #(#arms)*
                }
            }
        }
    })
}
