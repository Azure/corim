// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! `CborDeserialize` expansion — generates `serde::Deserialize` impls using
//! `MapAccess` visitor with integer keys.

use proc_macro2::TokenStream;
use quote::{format_ident, quote};
use syn::{Data, DeriveInput};

use crate::attrs::{parse_fields, StructAttrs};

pub fn expand_deserialize(input: &DeriveInput) -> syn::Result<TokenStream> {
    let name = &input.ident;
    let (_impl_generics, _ty_generics, _where_clause) = input.generics.split_for_impl();

    let struct_attrs = StructAttrs::from_attrs(&input.attrs)?;

    let data = match &input.data {
        Data::Struct(s) => s,
        _ => {
            return Err(syn::Error::new_spanned(
                input,
                "CborDeserialize only supports structs",
            ))
        }
    };

    let fields = parse_fields(data)?;
    let vis_name = format!("{}Visitor", name);
    let visitor_ident = format_ident!("__{}Visitor", name);

    // For each field, get its type from the original struct definition
    let field_types: Vec<_> = data
        .fields
        .iter()
        .filter_map(|f| {
            let ident = f.ident.as_ref()?;
            // Check if this field is in our parsed cbor fields
            fields.iter().find(|cf| cf.ident == *ident).map(|_| &f.ty)
        })
        .collect();

    // Temporaries: one Option<T> per field to accumulate during visitation
    let temp_decls: Vec<_> = fields
        .iter()
        .zip(field_types.iter())
        .map(|(f, _ty)| {
            let temp = format_ident!("__field_{}", f.ident);
            if f.attrs.optional && f.attrs.bytes {
                // For optional bytes fields: temp is Option<Vec<u8>> directly
                // (the field type is already Option<Vec<u8>>)
                quote! { let mut #temp: #_ty = None; }
            } else {
                quote! { let mut #temp: Option<#_ty> = None; }
            }
        })
        .collect();

    // Match arms: map integer key -> set the right temporary
    let match_arms: Vec<_> = fields
        .iter()
        .zip(field_types.iter())
        .map(|(f, _ty)| {
            let key = f.attrs.key;
            let temp = format_ident!("__field_{}", f.ident);
            if f.attrs.bytes {
                // For bytes fields, deserialize from Value::Bytes → Vec<u8>
                quote! {
                    #key => {
                        let val: crate::cbor::value::Value = map.next_value()?;
                        match val {
                            crate::cbor::value::Value::Bytes(b) => {
                                #temp = Some(b);
                            }
                            _ => {
                                return Err(serde::de::Error::custom(
                                    concat!("expected bytes for field ", stringify!(#temp))
                                ));
                            }
                        }
                    }
                }
            } else {
                quote! {
                    #key => {
                        #temp = Some(map.next_value()?);
                    }
                }
            }
        })
        .collect();

    // Post-visit: build the struct from temporaries
    let field_constructs: Vec<_> = fields
        .iter()
        .map(|f| {
            let ident = &f.ident;
            let temp = format_ident!("__field_{}", f.ident);
            if f.attrs.optional && f.attrs.bytes {
                // For optional bytes fields: temp is Option<Vec<u8>>, which IS the field type.
                quote! { #ident: #temp }
            } else if f.attrs.optional {
                // Optional non-bytes fields: temp is Option<Option<Inner>>, flatten to Option<Inner>.
                quote! { #ident: #temp.flatten() }
            } else {
                let err_msg = format!("missing required field with key {}", f.attrs.key);
                quote! {
                    #ident: #temp.ok_or_else(|| serde::de::Error::custom(#err_msg))?
                }
            }
        })
        .collect();

    // Non-empty check after constructing
    let non_empty_check = if struct_attrs.non_empty {
        let checks: Vec<_> = fields
            .iter()
            .filter(|f| f.attrs.optional)
            .map(|f| {
                let ident = &f.ident;
                quote! { result.#ident.is_none() }
            })
            .collect();

        if checks.is_empty() {
            quote! {}
        } else {
            // A map satisfies non-empty if ANY known field is populated,
            // OR if any entry at all was present (including extension keys
            // that were skipped by the unknown-key handler).
            quote! {
                if !__had_any_entry {
                    return Err(serde::de::Error::custom(
                        concat!("non-empty constraint violated: all optional fields are None in ", stringify!(#name))
                    ));
                }
            }
        }
    } else {
        quote! {}
    };

    // Extras-field plumbing: when `#[cbor(extras = "field")]` is set, unknown
    // integer keys are collected into a `BTreeMap<i64, Value>` field instead
    // of being silently dropped. Otherwise unknown keys are read-and-skipped
    // for forward compatibility (existing behavior).
    let (extras_decl, unknown_key_branch, extras_construct) =
        if let Some(ref extras_ident) = struct_attrs.extras {
            (
                quote! {
                    let mut __extras: alloc::collections::BTreeMap<i64, crate::cbor::value::Value>
                        = alloc::collections::BTreeMap::new();
                },
                quote! {
                    let val: crate::cbor::value::Value = map.next_value()?;
                    __extras.insert(key, val);
                },
                quote! { #extras_ident: __extras, },
            )
        } else {
            (
                quote! {},
                quote! {
                    // Skip unknown keys for forward compatibility
                    let _ = map.next_value::<serde::de::IgnoredAny>()?;
                },
                quote! {},
            )
        };

    let deserialize_body = quote! {
        fn deserialize<__D>(deserializer: __D) -> Result<Self, __D::Error>
        where
            __D: serde::Deserializer<'de>,
        {
            struct #visitor_ident;

            impl<'de> serde::de::Visitor<'de> for #visitor_ident {
                type Value = #name;

                fn expecting(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
                    f.write_str(#vis_name)
                }

                fn visit_map<__A>(self, mut map: __A) -> Result<Self::Value, __A::Error>
                where
                    __A: serde::de::MapAccess<'de>,
                {
                    #(#temp_decls)*
                    #extras_decl
                    let mut __had_any_entry = false;

                    while let Some(key) = map.next_key::<i64>()? {
                        __had_any_entry = true;
                        match key {
                            #(#match_arms)*
                            _ => {
                                #unknown_key_branch
                            }
                        }
                    }

                    let result = #name {
                        #(#field_constructs,)*
                        #extras_construct
                    };

                    #non_empty_check

                    Ok(result)
                }
            }

            deserializer.deserialize_map(#visitor_ident)
        }
    };

    // If a tag is set, unwrap the tag first
    let expanded = if let Some(tag) = struct_attrs.tag {
        quote! {
            impl<'de> serde::Deserialize<'de> for #name {
                fn deserialize<__D>(deserializer: __D) -> Result<Self, __D::Error>
                where
                    __D: serde::Deserializer<'de>,
                {
                    let tagged: crate::cbor::value::Tagged<__CborDeInner> =
                        crate::cbor::value::Tagged::deserialize(deserializer)?;
                    if tagged.tag != #tag {
                        return Err(serde::de::Error::custom(
                            format!("expected CBOR tag {}, found {}", #tag, tagged.tag)
                        ));
                    }
                    Ok(tagged.value.0)
                }
            }

            // Helper for inner map deserialization.
            // Uses a name unlikely to collide in user code.
            struct __CborDeInner(#name);

            impl<'de> serde::Deserialize<'de> for __CborDeInner {
                #deserialize_body
            }
        }
    } else {
        quote! {
            impl<'de> serde::Deserialize<'de> for #name {
                #deserialize_body
            }
        }
    };

    Ok(expanded)
}
