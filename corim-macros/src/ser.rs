// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! `CborSerialize` expansion — generates `serde::Serialize` impls using
//! `serialize_map` with integer keys in ascending order for deterministic
//! CBOR encoding.

use proc_macro2::TokenStream;
use quote::quote;
use syn::{Data, DeriveInput};

use crate::attrs::{parse_fields, StructAttrs};

pub fn expand_serialize(input: &DeriveInput) -> syn::Result<TokenStream> {
    let name = &input.ident;
    let (impl_generics, ty_generics, where_clause) = input.generics.split_for_impl();

    let struct_attrs = StructAttrs::from_attrs(&input.attrs)?;

    let data = match &input.data {
        Data::Struct(s) => s,
        _ => {
            return Err(syn::Error::new_spanned(
                input,
                "CborSerialize only supports structs",
            ))
        }
    };

    let fields = parse_fields(data)?;

    // Build non_empty check if needed
    let non_empty_check = if struct_attrs.non_empty {
        let checks: Vec<_> = fields
            .iter()
            .filter(|f| f.attrs.optional)
            .map(|f| {
                let ident = &f.ident;
                quote! { self.#ident.is_none() }
            })
            .collect();

        if checks.is_empty() {
            quote! {}
        } else {
            quote! {
                if #(#checks)&&* {
                    return Err(serde::ser::Error::custom(
                        concat!("non-empty constraint violated: all optional fields are None in ", stringify!(#name))
                    ));
                }
            }
        }
    } else {
        quote! {}
    };

    // Count entries for the map. We compute the count at runtime since optional
    // fields may be absent.
    let count_exprs: Vec<_> = fields
        .iter()
        .map(|f| {
            let ident = &f.ident;
            if f.attrs.optional {
                quote! { if self.#ident.is_some() { 1usize } else { 0usize } }
            } else {
                quote! { 1usize }
            }
        })
        .collect();

    // Emit map entries in key-ascending order (caller must declare fields in order)
    let entry_stmts: Vec<_> = fields
        .iter()
        .map(|f| {
            let ident = &f.ident;
            let key = f.attrs.key;
            if f.attrs.optional {
                quote! {
                    if let Some(ref val) = self.#ident {
                        map.serialize_entry(&#key, val)?;
                    }
                }
            } else {
                quote! {
                    map.serialize_entry(&#key, &self.#ident)?;
                }
            }
        })
        .collect();

    let serialize_body = quote! {
        fn serialize<__S>(&self, serializer: __S) -> Result<__S::Ok, __S::Error>
        where
            __S: serde::Serializer,
        {
            use serde::ser::SerializeMap as _;

            #non_empty_check

            let count: usize = #(#count_exprs)+*;
            let mut map = serializer.serialize_map(Some(count))?;
            #(#entry_stmts)*
            serde::ser::SerializeMap::end(map)
        }
    };

    // If a tag is set, wrap with crate::cbor::value::Tagged
    let expanded = if let Some(tag) = struct_attrs.tag {
        quote! {
            impl #impl_generics serde::Serialize for #name #ty_generics #where_clause {
                fn serialize<__S>(&self, serializer: __S) -> Result<__S::Ok, __S::Error>
                where
                    __S: serde::Serializer,
                {
                    use serde::ser::Error as _;

                    let inner = __CborSerInner(self);
                    crate::cbor::value::Tagged::new(#tag, inner).serialize(serializer)
                }
            }

            // A helper newtype for the inner map serialization (without tag).
            // Uses a name unlikely to collide in user code.
            struct __CborSerInner<'a>(pub &'a #name);

            impl<'a> serde::Serialize for __CborSerInner<'a> {
                #serialize_body
            }
        }
    } else {
        quote! {
            impl #impl_generics serde::Serialize for #name #ty_generics #where_clause {
                #serialize_body
            }
        }
    };

    Ok(expanded)
}
