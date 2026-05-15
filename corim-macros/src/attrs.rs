// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Attribute parsing for `#[cbor(...)]`.

use syn::Attribute;

/// Struct-level attributes.
#[derive(Debug, Default)]
pub struct StructAttrs {
    /// If set, wrap the serialized form in this CBOR tag number.
    pub tag: Option<u64>,
    /// If true, at least one field must be present (CDDL `non-empty<M>`).
    pub non_empty: bool,
    /// If set, names a `BTreeMap<i64, cbor::value::Value>` field that
    /// receives unknown integer map keys on deserialize and emits them
    /// on serialize. Used to model CDDL extension sockets such as
    /// `$$measurement-values-map-extension` (e.g. profile-defined keys
    /// in the negative integer range). The extras field MUST NOT carry
    /// `#[cbor(key = ...)]` and MUST exist on the struct.
    pub extras: Option<syn::Ident>,
}

/// Field-level attributes.
#[derive(Debug)]
pub struct FieldAttrs {
    /// The CBOR integer key for this field.
    pub key: i64,
    /// Whether the field is optional (`Option<T>`).
    pub optional: bool,
    /// Whether to serialize the field as CBOR bstr (bytes) instead of array.
    /// Use for `Vec<u8>` fields that represent byte strings.
    pub bytes: bool,
}

impl StructAttrs {
    pub fn from_attrs(attrs: &[Attribute]) -> syn::Result<Self> {
        let mut result = Self::default();

        for attr in attrs {
            if !attr.path().is_ident("cbor") {
                continue;
            }

            attr.parse_nested_meta(|meta| {
                if meta.path.is_ident("tag") {
                    let _eq: syn::Token![=] = meta.input.parse()?;
                    let lit: syn::LitInt = meta.input.parse()?;
                    result.tag = Some(lit.base10_parse::<u64>()?);
                    Ok(())
                } else if meta.path.is_ident("non_empty") {
                    result.non_empty = true;
                    Ok(())
                } else if meta.path.is_ident("extras") {
                    let _eq: syn::Token![=] = meta.input.parse()?;
                    let lit: syn::LitStr = meta.input.parse()?;
                    let ident = syn::Ident::new(&lit.value(), lit.span());
                    result.extras = Some(ident);
                    Ok(())
                } else {
                    Err(meta.error("unknown cbor struct attribute"))
                }
            })?;
        }

        Ok(result)
    }
}

impl FieldAttrs {
    pub fn from_attrs(attrs: &[Attribute]) -> syn::Result<Option<Self>> {
        let mut key: Option<i64> = None;
        let mut optional = false;
        let mut bytes = false;

        for attr in attrs {
            if !attr.path().is_ident("cbor") {
                continue;
            }

            attr.parse_nested_meta(|meta| {
                if meta.path.is_ident("key") {
                    let _eq: syn::Token![=] = meta.input.parse()?;
                    let lit: syn::LitInt = meta.input.parse()?;
                    key = Some(lit.base10_parse::<i64>()?);
                    Ok(())
                } else if meta.path.is_ident("optional") {
                    optional = true;
                    Ok(())
                } else if meta.path.is_ident("bytes") {
                    bytes = true;
                    Ok(())
                } else {
                    Err(meta.error("unknown cbor field attribute"))
                }
            })?;
        }

        match key {
            Some(k) => Ok(Some(FieldAttrs {
                key: k,
                optional,
                bytes,
            })),
            None if optional => Err(syn::Error::new_spanned(
                &attrs[0],
                "#[cbor(optional)] requires #[cbor(key = ...)]",
            )),
            None => Ok(None),
        }
    }
}

/// Parsed field info for code generation.
pub struct CborField {
    pub ident: syn::Ident,
    pub attrs: FieldAttrs,
}

/// Extract all CBOR-annotated fields from a struct.
pub fn parse_fields(data: &syn::DataStruct) -> syn::Result<Vec<CborField>> {
    let mut fields = Vec::new();

    for field in &data.fields {
        let ident = field
            .ident
            .clone()
            .ok_or_else(|| syn::Error::new_spanned(field, "tuple structs not supported"))?;

        if let Some(attrs) = FieldAttrs::from_attrs(&field.attrs)? {
            fields.push(CborField { ident, attrs });
        }
    }

    if fields.is_empty() {
        return Err(syn::Error::new(
            proc_macro2::Span::call_site(),
            "at least one field must have #[cbor(key = ...)]",
        ));
    }

    // Validate keys are strictly ascending (required for deterministic CBOR
    // per RFC 8949 §4.2.1) and unique.
    let mut prev_key: Option<i64> = None;
    for f in &fields {
        if let Some(prev) = prev_key {
            if f.attrs.key == prev {
                return Err(syn::Error::new_spanned(
                    &f.ident,
                    format!(
                        "duplicate #[cbor(key = {})] — each field must have a unique key",
                        f.attrs.key
                    ),
                ));
            }
            if f.attrs.key < prev {
                return Err(syn::Error::new_spanned(
                    &f.ident,
                    format!(
                        "#[cbor(key = {})] follows key {} — keys must be in strictly ascending order for deterministic CBOR (RFC 8949 §4.2.1)",
                        f.attrs.key, prev
                    ),
                ));
            }
        }
        prev_key = Some(f.attrs.key);
    }

    Ok(fields)
}
