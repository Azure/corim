// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Codegen for `#[derive(CborTagChoiceDeserialize)]`.
//!
//! Emits a `serde::Deserialize` impl that decodes a `Value` and
//! dispatches on its CBOR shape:
//!
//! ```text
//! Value::Tag(N, inner)              -> tagged variant whose tag matches N
//! Value::Bytes(b) if b.len() == 16  -> any variant with `accept_bare = "uuid_16"`
//! Value::Bytes(b)                   -> the variant marked `catch_bare_bytes`,
//!                                      if any (else error)
//! Value::Text(t)                    -> the `#[cbor(text)]` variant, if any
//! Value::Integer(n)                 -> the `#[cbor(uint)]` variant, if any
//! _                                 -> error listing accepted shapes
//! ```
//!
//! After construction, the optional `#[cbor(custom_validate = "fn")]`
//! hook is invoked; an `Err(msg)` is converted to
//! `serde::de::Error::custom(msg)`.

use proc_macro2::TokenStream;
use quote::quote;
use syn::{Data, DeriveInput};

use crate::choice_attrs::{
    parse_choice_variants, ChoiceEnumAttrs, ChoiceVariant, ChoiceVariantKind,
};

pub fn expand_tag_choice_deserialize(input: &DeriveInput) -> syn::Result<TokenStream> {
    let name = &input.ident;
    let (impl_generics, ty_generics, where_clause) = input.generics.split_for_impl();

    let data = match &input.data {
        Data::Enum(e) => e,
        _ => {
            return Err(syn::Error::new_spanned(
                input,
                "CborTagChoiceDeserialize only supports enums",
            ))
        }
    };

    let enum_attrs = ChoiceEnumAttrs::from_attrs(&input.attrs)?;
    let variants = parse_choice_variants(data)?;

    // Tagged arms: one match arm per tagged variant, dispatched on tag number.
    let tagged_arms = build_tagged_arms(name, &variants);

    // Bare-bytes arms (16-byte UUID relaxation).
    let bare_uuid_arm = build_bare_uuid_arm(name, &variants);

    // Catch-all bare-bytes arm.
    let catch_bare_arm = build_catch_bare_arm(name, &variants);

    // Inline text/uint arms.
    let inline_text_arm = build_inline_text_arm(name, &variants);
    let inline_uint_arm = build_inline_uint_arm(name, &variants);

    // Error message lists accepted shapes so users see what the macro can take.
    let accepted_shapes = build_accepted_shapes_list(&variants);
    let fallback_arm = quote! {
        other => Err(serde::de::Error::custom(format!(
            concat!(
                "expected one of [", #accepted_shapes, "] for ",
                stringify!(#name),
                ", got CBOR value of variant {:?}"
            ),
            core::mem::discriminant(&other)
        ))),
    };

    // Optional post-decode validation hook.
    let validate_call = if let Some(path) = enum_attrs.custom_validate {
        quote! {
            #path(&value).map_err(serde::de::Error::custom)?;
        }
    } else {
        quote! {}
    };

    Ok(quote! {
        impl<'de> #impl_generics serde::Deserialize<'de> for #name #ty_generics #where_clause {
            fn deserialize<__D>(d: __D) -> ::core::result::Result<Self, __D::Error>
            where
                __D: serde::Deserializer<'de>,
            {
                let value = match crate::cbor::value::Value::deserialize(d)? {
                    #(#tagged_arms)*
                    #bare_uuid_arm
                    #catch_bare_arm
                    #inline_text_arm
                    #inline_uint_arm
                    #fallback_arm
                };
                let value = value?;
                #validate_call
                Ok(value)
            }
        }
    })
}

// ---------------------------------------------------------------------------
// Per-arm builders
//
// Each builder returns a `TokenStream` containing zero or more match arms.
// They each evaluate to `Result<Self, D::Error>` so the outer match can be
// followed by a single `?` to flatten the layered Result.
// ---------------------------------------------------------------------------

fn build_tagged_arms(name: &syn::Ident, variants: &[ChoiceVariant]) -> Vec<TokenStream> {
    variants
        .iter()
        .filter_map(|v| match &v.kind {
            ChoiceVariantKind::Tagged { tag, bytes, .. } => {
                let vid = &v.ident;
                let tag_lit = *tag;
                if *bytes {
                    // For byte-shaped variants, the inner value must be a bstr.
                    // The constructor differs between Vec<u8> (direct) and
                    // [u8; N] (TryInto). We branch on the field type here.
                    let bytes_to_inner = bytes_to_inner_expr(&v.field_ty, vid, name);
                    Some(quote! {
                        crate::cbor::value::Value::Tag(#tag_lit, inner) => {
                            match *inner {
                                crate::cbor::value::Value::Bytes(b) => {
                                    #bytes_to_inner
                                }
                                other => Err(serde::de::Error::custom(format!(
                                    concat!(
                                        "tag {} (",
                                        stringify!(#name), "::", stringify!(#vid),
                                        ") must wrap bstr, got {:?}"
                                    ),
                                    #tag_lit, core::mem::discriminant(&other)
                                ))),
                            }
                        }
                    })
                } else {
                    // Non-bytes tagged variant: reflow inner Value through serde
                    // by re-encoding then decoding into the inner type. Avoids
                    // teaching the macro about each possible inner type.
                    Some(quote! {
                        crate::cbor::value::Value::Tag(#tag_lit, inner) => {
                            crate::cbor::value::from_value::<_>(&*inner)
                                .map(#name::#vid)
                                .map_err(|e| serde::de::Error::custom(format!(
                                    concat!(
                                        "tag {} (",
                                        stringify!(#name), "::", stringify!(#vid),
                                        ") inner decode: {}"
                                    ),
                                    #tag_lit, e
                                )))
                        }
                    })
                }
            }
            _ => None,
        })
        .collect()
}

/// Given the variant's field type, return an expression that constructs
/// `Self::vid(value)` from a `b: Vec<u8>` in scope, returning
/// `Result<Self, D::Error>`.
///
/// Two shapes are supported:
///   - `Vec<u8>` — direct: `Ok(Name::vid(b))`
///   - `[u8; N]` — TryInto: `Ok(Name::vid(b.try_into()?))`
///
/// Anything else falls through to `Ok(Name::vid(b))` and lets the compiler
/// emit a type error if the field doesn't accept `Vec<u8>`.
fn bytes_to_inner_expr(field_ty: &syn::Type, vid: &syn::Ident, name: &syn::Ident) -> TokenStream {
    if let syn::Type::Array(_) = field_ty {
        // `[u8; N]` for any N — TryFrom<Vec<u8>>::Error is Vec<u8>, so include
        // the actual length in the error message for diagnosability.
        quote! {
            {
                let actual = b.len();
                let arr: #field_ty = b.try_into().map_err(|_| {
                    serde::de::Error::custom(format!(
                        concat!(
                            stringify!(#name), "::", stringify!(#vid),
                            " requires fixed-size byte array, got {} bytes"
                        ),
                        actual
                    ))
                })?;
                Ok(#name::#vid(arr))
            }
        }
    } else {
        // Assume Vec<u8>; if not, the compiler will catch it at expansion.
        quote! { Ok(#name::#vid(b)) }
    }
}

fn build_bare_uuid_arm(name: &syn::Ident, variants: &[ChoiceVariant]) -> TokenStream {
    let target = variants.iter().find_map(|v| match &v.kind {
        ChoiceVariantKind::Tagged {
            accept_bare_uuid: true,
            ..
        } => Some(&v.ident),
        _ => None,
    });
    match target {
        Some(vid) => quote! {
            crate::cbor::value::Value::Bytes(b) if b.len() == 16 => {
                let arr: [u8; 16] = b.try_into().map_err(|_| {
                    serde::de::Error::custom(concat!(
                        "bare 16-byte bstr for ",
                        stringify!(#name), "::", stringify!(#vid),
                        " failed array conversion"
                    ))
                })?;
                Ok(#name::#vid(arr))
            }
        },
        None => quote! {},
    }
}

fn build_catch_bare_arm(name: &syn::Ident, variants: &[ChoiceVariant]) -> TokenStream {
    let target = variants.iter().find_map(|v| match &v.kind {
        ChoiceVariantKind::Tagged {
            catch_bare_bytes: true,
            ..
        } => Some(&v.ident),
        _ => None,
    });
    match target {
        Some(vid) => quote! {
            crate::cbor::value::Value::Bytes(b) => Ok(#name::#vid(b)),
        },
        None => quote! {},
    }
}

fn build_inline_text_arm(name: &syn::Ident, variants: &[ChoiceVariant]) -> TokenStream {
    let target = variants.iter().find_map(|v| match &v.kind {
        ChoiceVariantKind::InlineText => Some(&v.ident),
        _ => None,
    });
    match target {
        Some(vid) => quote! {
            crate::cbor::value::Value::Text(t) => Ok(#name::#vid(t)),
        },
        None => quote! {},
    }
}

fn build_inline_uint_arm(name: &syn::Ident, variants: &[ChoiceVariant]) -> TokenStream {
    let target = variants.iter().find_map(|v| match &v.kind {
        ChoiceVariantKind::InlineUint => Some(&v.ident),
        _ => None,
    });
    match target {
        Some(vid) => quote! {
            crate::cbor::value::Value::Integer(n) => {
                let n: u64 = n.try_into().map_err(|_| {
                    serde::de::Error::custom(concat!(
                        stringify!(#name), "::", stringify!(#vid),
                        " requires unsigned integer"
                    ))
                })?;
                Ok(#name::#vid(n))
            }
        },
        None => quote! {},
    }
}

/// Build a runtime string literal listing the CBOR shapes the deserializer
/// accepts. Used in the fallback error message so users see exactly what
/// went wrong without having to read the macro source.
fn build_accepted_shapes_list(variants: &[ChoiceVariant]) -> String {
    let mut parts: Vec<String> = Vec::new();

    // Collect tagged variants (use a stable, declaration order for readability).
    let mut tags: Vec<u64> = Vec::new();
    let mut has_bare_uuid = false;
    let mut has_catch_bare = false;
    let mut has_inline_text = false;
    let mut has_inline_uint = false;
    for v in variants {
        match &v.kind {
            ChoiceVariantKind::Tagged {
                tag,
                accept_bare_uuid,
                catch_bare_bytes,
                ..
            } => {
                tags.push(*tag);
                if *accept_bare_uuid {
                    has_bare_uuid = true;
                }
                if *catch_bare_bytes {
                    has_catch_bare = true;
                }
            }
            ChoiceVariantKind::InlineText => has_inline_text = true,
            ChoiceVariantKind::InlineUint => has_inline_uint = true,
        }
    }
    if !tags.is_empty() {
        let tag_list = tags
            .iter()
            .map(|t| format!("#6.{}", t))
            .collect::<Vec<_>>()
            .join("|");
        parts.push(format!("tagged {}", tag_list));
    }
    if has_bare_uuid {
        parts.push("16-byte bstr (UUID)".to_string());
    }
    if has_catch_bare {
        parts.push("any bstr (catch-all)".to_string());
    }
    if has_inline_text {
        parts.push("tstr".to_string());
    }
    if has_inline_uint {
        parts.push("uint".to_string());
    }
    parts.join(", ")
}
