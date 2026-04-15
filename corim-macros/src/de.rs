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
            quote! { let mut #temp: Option<#_ty> = None; }
        })
        .collect();

    // Match arms: map integer key -> set the right temporary
    let match_arms: Vec<_> = fields
        .iter()
        .zip(field_types.iter())
        .map(|(f, _ty)| {
            let key = f.attrs.key;
            let temp = format_ident!("__field_{}", f.ident);
            if f.attrs.optional {
                // For optional fields the struct type is Option<Inner>.
                // We want to deserialize the inner type and wrap in Some.
                // But the map value is the inner type, not Option<inner>.
                // We can just deserialize as the full Option<Inner> type or
                // use the inner. Let's deserialize as the field type directly:
                // since the value exists in the map, we set Some(value).
                quote! {
                    #key => {
                        #temp = Some(map.next_value()?);
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
            if f.attrs.optional {
                // Optional fields: if the key wasn't in the map, it's None.
                // If it was, temp is Some(Option<T>) — but we deserialized as the field type.
                // Actually we need to be careful. The field type IS Option<Inner>.
                // When the key is present, we did `temp = Some(map.next_value::<FieldType>()?)`.
                // That means temp is Option<Option<Inner>>. We want to flatten.
                // Better approach: deserialize as the inner type directly.
                // Let's handle it differently. The temp holds Option<FieldType>.
                // If FieldType is Option<X>, then temp: Option<Option<X>>.
                // We flatten with .unwrap_or(None) → Option<X>.
                // Actually .flatten() is cleaner.
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
            quote! {
                if #(#checks)&&* {
                    return Err(serde::de::Error::custom(
                        concat!("non-empty constraint violated: all optional fields are None in ", stringify!(#name))
                    ));
                }
            }
        }
    } else {
        quote! {}
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

                    while let Some(key) = map.next_key::<i64>()? {
                        match key {
                            #(#match_arms)*
                            _ => {
                                // Skip unknown keys for forward compatibility
                                let _ = map.next_value::<serde::de::IgnoredAny>()?;
                            }
                        }
                    }

                    let result = #name {
                        #(#field_constructs,)*
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
