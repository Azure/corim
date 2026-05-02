// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Attribute parser for the `CborTagChoice` derive.
//!
//! Grammar (per-variant attributes, mutually exclusive between
//! `tag` / standalone `text` / standalone `uint`):
//!
//! ```text
//! #[cbor(tag = N)]                            tagged variant — emits #6.N(inner);
//!                                             inner reflowed via from_value
//!                                             (works for any Serialize/Deserialize
//!                                             type, e.g. Digest, custom newtypes)
//! #[cbor(tag = N, bytes)]                     tagged variant whose inner field is
//!                                             `Vec<u8>` or `[u8; M]`; emits
//!                                             #6.N(bstr) and decodes only from
//!                                             a CBOR bstr (rejects array, etc.).
//!                                             Mirrors `#[cbor(bytes)]` on struct
//!                                             fields.
//! #[cbor(tag = N, text)]                      tagged variant whose inner field is
//!                                             `String`; emits #6.N(tstr) and
//!                                             decodes only from a CBOR tstr.
//!                                             Symmetric with `bytes`. Without
//!                                             this hint, a tagged-String variant
//!                                             would accept any Value that serde
//!                                             can coerce to String — including
//!                                             a CBOR bstr — which is wrong for
//!                                             RFC types like PEM-encoded keys.
//! #[cbor(tag = N, accept_bare = "uuid_16")]   ditto, plus decode-time interop
//!                                             relaxation accepting a bare
//!                                             16-byte bstr as untagged UUID.
//!                                             May combine with `bytes`.
//! #[cbor(tag = N, bytes, catch_bare_bytes)]   on decode, accept any bare bstr
//!                                             (no tag, any length not already
//!                                             routed by an `accept_bare` rule)
//!                                             and route it to this variant.
//!                                             At most one variant per enum may
//!                                             carry this attribute. Requires
//!                                             `bytes`.
//! #[cbor(text)]                               inline text variant (no tag)
//! #[cbor(uint)]                               inline unsigned integer variant
//! ```
//!
//! Enum-level attribute (optional):
//!
//! ```text
//! #[cbor(custom_validate = "path::to::fn")]   post-deserialize hook; the macro
//!                                             calls fn(&value) -> Result<(), String>
//!                                             and converts Err into a serde error.
//!                                             The value is a path expression, so
//!                                             both bare names ("validate_x") and
//!                                             qualified paths ("module::validate_x")
//!                                             are accepted.
//! ```
//!
//! ## Variant shape constraints
//!
//! Tag-choice variants must be **single-field tuple variants**, e.g.
//! `Uuid([u8; 16])`. Unit variants (`Empty`), struct variants
//! (`Named { x: u32 }`), and multi-field tuple variants (`Pair(u32, u32)`)
//! are rejected at parse time so codegen can assume `self.0` works.
//!
//! The grammar deliberately reuses the existing `#[cbor(...)]` namespace
//! that struct fields already use, so contributors only need to learn one
//! attribute set.

use syn::Attribute;

/// Parsed enum-level attributes for `CborTagChoice`.
#[derive(Debug, Default)]
pub struct ChoiceEnumAttrs {
    /// Optional path to a free function with signature
    /// `fn(&Self) -> Result<(), String>` invoked at the end of `Deserialize`.
    /// On `Err(msg)` the deserializer returns `serde::de::Error::custom(msg)`.
    pub custom_validate: Option<syn::Path>,
}

/// Parsed per-variant attributes for `CborTagChoice`.
#[derive(Debug, Clone)]
pub enum ChoiceVariantKind {
    /// `#[cbor(tag = N)]` — variant is `#6.N(inner)`.
    Tagged {
        tag: u64,
        /// `true` if `#[cbor(bytes)]` is also present. The inner field is
        /// expected to be `Vec<u8>` or `[u8; M]`; codegen will route the
        /// value through a `Value::Bytes(…)` wrapper so it serializes as
        /// a CBOR `bstr`, not as a CBOR array of integers (the default
        /// serde behavior for `Vec<u8>`). Same purpose and semantics as
        /// the existing `#[cbor(key = N, bytes)]` on struct fields.
        ///
        /// Mutually exclusive with `text`.
        bytes: bool,
        /// `true` if `#[cbor(text)]` is also present *together with* `tag`.
        /// The inner field is expected to be `String`; codegen will
        /// serialize as `Value::Text(…)` and on decode will require the
        /// inner Value to be `Value::Text` (rejecting `Value::Bytes` etc).
        ///
        /// Without this hint, a tagged-String variant would silently
        /// accept any Value that serde can coerce to String, including
        /// a CBOR bstr — which is wrong for RFC types like the PEM
        /// PkixBase64Key (#6.554) where the inner must be tstr.
        ///
        /// Mutually exclusive with `bytes`.
        text: bool,
        /// `true` if `accept_bare = "uuid_16"` is also present. On decode,
        /// a bare 16-byte CBOR `bstr` (no tag) is accepted and routed to
        /// this variant. Used for the interop relaxation observed across
        /// CoRIM producers that omit tag 37 on UUIDs.
        ///
        /// The grammar form is a string ("uuid_16") rather than a flag so
        /// future relaxations (e.g., a 6-byte bstr → MAC) can extend the
        /// attribute syntactically without breaking existing call sites,
        /// but only one rule exists today and it collapses to a bool.
        accept_bare_uuid: bool,
        /// `true` if `#[cbor(catch_bare_bytes)]` is also present. On decode,
        /// any bare bstr (no tag) that wasn't already routed by another
        /// variant's `accept_bare` rule is routed to this variant. At most
        /// one variant per enum may carry this. Requires `bytes`.
        ///
        /// Used by `ClassIdChoice` / `GroupIdChoice` / `InstanceIdChoice`
        /// where the CDDL `bytes`-tagged variant doubles as the catch-all
        /// for non-conformant producers that emit untagged byte strings.
        catch_bare_bytes: bool,
    },
    /// `#[cbor(text)]` — inline CBOR `tstr`, no tag.
    InlineText,
    /// `#[cbor(uint)]` — inline CBOR unsigned integer, no tag.
    InlineUint,
}

/// Variant-level metadata after parsing.
#[derive(Debug, Clone)]
pub struct ChoiceVariant {
    pub ident: syn::Ident,
    pub kind: ChoiceVariantKind,
    /// Type of the variant's single tuple field (e.g. `String`, `Vec<u8>`,
    /// `[u8; 16]`, `Digest`). Codegen uses this to choose between
    /// `Vec<u8>`-direct vs `[u8; N]::try_from(Vec<u8>)` constructions for
    /// tagged-bytes variants. The parser already enforced single-field
    /// tuple shape, so this is always present and unique.
    pub field_ty: syn::Type,
}

impl ChoiceEnumAttrs {
    pub fn from_attrs(attrs: &[Attribute]) -> syn::Result<Self> {
        let mut result = Self::default();
        for attr in attrs {
            if !attr.path().is_ident("cbor") {
                continue;
            }
            attr.parse_nested_meta(|meta| {
                if meta.path.is_ident("custom_validate") {
                    let _eq: syn::Token![=] = meta.input.parse()?;
                    let lit: syn::LitStr = meta.input.parse()?;
                    let path: syn::Path = syn::parse_str(&lit.value())?;
                    result.custom_validate = Some(path);
                    Ok(())
                } else {
                    Err(meta.error(
                        "unknown cbor enum attribute (expected `custom_validate = \"path\"`)",
                    ))
                }
            })?;
        }
        Ok(result)
    }
}

/// Verify the variant has exactly one tuple field (so codegen can use
/// `self.0` / `Variant(inner) => ...` patterns).
fn require_single_field_tuple(variant: &syn::Variant) -> syn::Result<()> {
    match &variant.fields {
        syn::Fields::Unnamed(fields) if fields.unnamed.len() == 1 => Ok(()),
        syn::Fields::Unnamed(fields) => Err(syn::Error::new_spanned(
            variant,
            format!(
                "CborTagChoice variants must have exactly one tuple field, got {}",
                fields.unnamed.len()
            ),
        )),
        syn::Fields::Named(_) => Err(syn::Error::new_spanned(
            variant,
            "CborTagChoice variants must be tuple-style (e.g. `Uuid([u8; 16])`), not struct-style",
        )),
        syn::Fields::Unit => Err(syn::Error::new_spanned(
            variant,
            "CborTagChoice variants must have exactly one tuple field; unit variants are not supported",
        )),
    }
}

/// Parse the `#[cbor(...)]` attributes on a single enum variant.
///
/// Errors if the variant has no `#[cbor(...)]` attribute, has the wrong
/// shape (see [`require_single_field_tuple`]), or carries conflicting /
/// invalid attributes.
pub fn parse_variant(variant: &syn::Variant) -> syn::Result<ChoiceVariant> {
    require_single_field_tuple(variant)?;

    let mut tag: Option<u64> = None;
    let mut bytes = false;
    let mut accept_bare_uuid = false;
    let mut catch_bare_bytes = false;
    let mut inline_text = false;
    let mut inline_uint = false;
    let mut saw_attr = false;

    for attr in &variant.attrs {
        if !attr.path().is_ident("cbor") {
            continue;
        }
        saw_attr = true;
        attr.parse_nested_meta(|meta| {
            if meta.path.is_ident("tag") {
                let _eq: syn::Token![=] = meta.input.parse()?;
                let lit: syn::LitInt = meta.input.parse()?;
                tag = Some(lit.base10_parse::<u64>()?);
                Ok(())
            } else if meta.path.is_ident("bytes") {
                bytes = true;
                Ok(())
            } else if meta.path.is_ident("accept_bare") {
                let _eq: syn::Token![=] = meta.input.parse()?;
                let lit: syn::LitStr = meta.input.parse()?;
                match lit.value().as_str() {
                    "uuid_16" => accept_bare_uuid = true,
                    other => {
                        return Err(meta.error(format!(
                            "unknown accept_bare rule {:?} (expected \"uuid_16\")",
                            other
                        )));
                    }
                }
                Ok(())
            } else if meta.path.is_ident("catch_bare_bytes") {
                catch_bare_bytes = true;
                Ok(())
            } else if meta.path.is_ident("text") {
                inline_text = true;
                Ok(())
            } else if meta.path.is_ident("uint") {
                inline_uint = true;
                Ok(())
            } else {
                Err(meta.error(
                    "unknown cbor variant attribute (expected `tag = N`, `bytes`, `text`, or `uint`)",
                ))
            }
        })?;
    }

    if !saw_attr {
        return Err(syn::Error::new_spanned(
            variant,
            "every variant of a CborTagChoice enum must have a `#[cbor(...)]` attribute",
        ));
    }

    // The `text` and `bytes` attributes have a dual life:
    //   - alone (no `tag`): they are kind selectors for inline tstr/bstr-less
    //     variants — `text` means inline tstr, `bytes` would mean inline bstr
    //     (not currently implemented; see error message below).
    //   - with `tag`: they are shape qualifiers on the tagged variant.
    //
    // The mutually-exclusive rule below treats them differently in each context.
    let has_tag = tag.is_some();

    if has_tag {
        // Tagged context: text and bytes are mutually-exclusive shape qualifiers.
        if inline_text && bytes {
            return Err(syn::Error::new_spanned(
                variant,
                "variant attributes `text` and `bytes` are mutually exclusive on a tagged variant",
            ));
        }
        if inline_uint {
            return Err(syn::Error::new_spanned(
                variant,
                "`uint` is an inline-kind selector and cannot be combined with `tag = N`",
            ));
        }
    } else {
        // Inline context: exactly one of {text, uint}. `bytes` alone is not
        // currently a supported inline kind.
        if bytes {
            return Err(syn::Error::new_spanned(
                variant,
                "`bytes` requires `#[cbor(tag = N)]` (inline bytes variants are not supported)",
            ));
        }
        let inline_kinds = [inline_text, inline_uint];
        let count = inline_kinds.iter().filter(|b| **b).count();
        if count == 0 {
            return Err(syn::Error::new_spanned(
                variant,
                "variant must specify exactly one of `#[cbor(tag = N)]`, `#[cbor(text)]`, or `#[cbor(uint)]`",
            ));
        }
        if count > 1 {
            return Err(syn::Error::new_spanned(
                variant,
                "inline kinds `text` and `uint` are mutually exclusive",
            ));
        }
    }

    if accept_bare_uuid && !has_tag {
        return Err(syn::Error::new_spanned(
            variant,
            "`accept_bare` requires `#[cbor(tag = N)]`",
        ));
    }

    if catch_bare_bytes && (!has_tag || !bytes) {
        return Err(syn::Error::new_spanned(
            variant,
            "`catch_bare_bytes` requires `#[cbor(tag = N, bytes)]` so the catch-all variant has a byte-shaped inner field",
        ));
    }

    let kind = if let Some(tag) = tag {
        ChoiceVariantKind::Tagged {
            tag,
            bytes,
            text: inline_text,
            accept_bare_uuid,
            catch_bare_bytes,
        }
    } else if inline_text {
        ChoiceVariantKind::InlineText
    } else {
        ChoiceVariantKind::InlineUint
    };

    // Pull out the (single) tuple field type. require_single_field_tuple
    // already validated the shape; this destructure is infallible.
    let field_ty = match &variant.fields {
        syn::Fields::Unnamed(fields) => fields.unnamed.first().unwrap().ty.clone(),
        // Other shapes already errored out above.
        _ => unreachable!("require_single_field_tuple should have rejected this"),
    };

    Ok(ChoiceVariant {
        ident: variant.ident.clone(),
        kind,
        field_ty,
    })
}

/// Parse all variants of an enum and return the metadata needed by codegen.
///
/// Errors if:
/// - the enum has zero variants (the generated `Serialize` would have an
///   unreachable match and `Deserialize` would always fail; better to say so);
/// - any variant lacks a `#[cbor(...)]` attribute, has the wrong shape, or
///   carries invalid attributes (see [`parse_variant`]);
/// - any tagged variant duplicates a CBOR tag number, or two variants share
///   `#[cbor(text)]` / `#[cbor(uint)]` (the dispatch match would shadow).
pub fn parse_choice_variants(data: &syn::DataEnum) -> syn::Result<Vec<ChoiceVariant>> {
    if data.variants.is_empty() {
        return Err(syn::Error::new(
            proc_macro2::Span::call_site(),
            "CborTagChoice enum must have at least one variant",
        ));
    }

    let mut variants = Vec::with_capacity(data.variants.len());
    for v in &data.variants {
        variants.push(parse_variant(v)?);
    }

    // Reject duplicate tag numbers and duplicate inline kinds — the
    // deserialize match arm would shadow.
    //
    // We clone idents (cheap; `proc_macro2::Ident` is `Rc`-backed) so the
    // tracking state doesn't borrow `variants` and stay fragile to later
    // mutation in the loop.
    let mut seen_tags: Vec<(u64, syn::Ident)> = Vec::new();
    let mut seen_inline_text: Option<syn::Ident> = None;
    let mut seen_inline_uint: Option<syn::Ident> = None;
    let mut seen_catch_bare_bytes: Option<syn::Ident> = None;
    for v in &variants {
        match &v.kind {
            ChoiceVariantKind::Tagged {
                tag,
                catch_bare_bytes,
                ..
            } => {
                if let Some((_, prev)) = seen_tags.iter().find(|(t, _)| *t == *tag) {
                    return Err(syn::Error::new_spanned(
                        &v.ident,
                        format!(
                            "duplicate CBOR tag {} (also used by variant `{}`)",
                            tag, prev
                        ),
                    ));
                }
                seen_tags.push((*tag, v.ident.clone()));

                if *catch_bare_bytes {
                    if let Some(prev) = &seen_catch_bare_bytes {
                        return Err(syn::Error::new_spanned(
                            &v.ident,
                            format!(
                                "duplicate `#[cbor(catch_bare_bytes)]` (also on variant `{}`); at most one variant per enum may carry it",
                                prev
                            ),
                        ));
                    }
                    seen_catch_bare_bytes = Some(v.ident.clone());
                }
            }
            ChoiceVariantKind::InlineText => {
                if let Some(prev) = &seen_inline_text {
                    return Err(syn::Error::new_spanned(
                        &v.ident,
                        format!("duplicate `#[cbor(text)]` (also on variant `{}`)", prev),
                    ));
                }
                seen_inline_text = Some(v.ident.clone());
            }
            ChoiceVariantKind::InlineUint => {
                if let Some(prev) = &seen_inline_uint {
                    return Err(syn::Error::new_spanned(
                        &v.ident,
                        format!("duplicate `#[cbor(uint)]` (also on variant `{}`)", prev),
                    ));
                }
                seen_inline_uint = Some(v.ident.clone());
            }
        }
    }

    Ok(variants)
}

#[cfg(test)]
mod tests {
    use super::*;
    use syn::parse_quote;

    fn parse_enum(item: syn::ItemEnum) -> (Vec<ChoiceVariant>, ChoiceEnumAttrs) {
        let attrs = ChoiceEnumAttrs::from_attrs(&item.attrs).unwrap();
        let data = syn::DataEnum {
            enum_token: item.enum_token,
            brace_token: item.brace_token,
            variants: item.variants,
        };
        let variants = parse_choice_variants(&data).unwrap();
        (variants, attrs)
    }

    fn parse_enum_err(item: syn::ItemEnum) -> String {
        let data = syn::DataEnum {
            enum_token: item.enum_token,
            brace_token: item.brace_token,
            variants: item.variants,
        };
        match parse_choice_variants(&data) {
            Err(e) => e.to_string(),
            Ok(_) => panic!("expected parse error"),
        }
    }

    // --- success paths ---

    #[test]
    fn tagged_only_enum() {
        let (vs, attrs) = parse_enum(parse_quote! {
            enum E {
                #[cbor(tag = 111)] Oid(Vec<u8>),
                #[cbor(tag = 37)]  Uuid([u8; 16]),
                #[cbor(tag = 560)] Bytes(Vec<u8>),
            }
        });
        assert_eq!(vs.len(), 3);
        assert!(attrs.custom_validate.is_none());
        match &vs[0].kind {
            ChoiceVariantKind::Tagged {
                tag,
                bytes,
                text,
                accept_bare_uuid,
                catch_bare_bytes,
            } => {
                assert_eq!(*tag, 111);
                assert!(!bytes);
                assert!(!text);
                assert!(!accept_bare_uuid);
                assert!(!catch_bare_bytes);
            }
            _ => panic!("expected tagged"),
        }
    }

    #[test]
    fn accept_bare_uuid() {
        let (vs, _) = parse_enum(parse_quote! {
            enum E {
                #[cbor(tag = 37, accept_bare = "uuid_16")] Uuid([u8; 16]),
                #[cbor(tag = 560)] Bytes(Vec<u8>),
            }
        });
        match &vs[0].kind {
            ChoiceVariantKind::Tagged {
                tag: 37,
                bytes: false,
                text: false,
                accept_bare_uuid: true,
                catch_bare_bytes: false,
            } => {}
            other => panic!(
                "expected Tagged{{tag: 37, bytes: false, text: false, accept_bare_uuid: true, catch_bare_bytes: false}}, got {:?}",
                other
            ),
        }
    }

    #[test]
    fn inline_text_and_uint() {
        let (vs, _) = parse_enum(parse_quote! {
            enum E {
                #[cbor(text)] Text(String),
                #[cbor(uint)] Uint(u64),
                #[cbor(tag = 37)] Uuid([u8; 16]),
            }
        });
        assert!(matches!(vs[0].kind, ChoiceVariantKind::InlineText));
        assert!(matches!(vs[1].kind, ChoiceVariantKind::InlineUint));
    }

    #[test]
    fn custom_validate_simple_name() {
        let (_, attrs) = parse_enum(parse_quote! {
            #[cbor(custom_validate = "validate_ueid_size")]
            enum E {
                #[cbor(tag = 550)] Ueid(Vec<u8>),
            }
        });
        let path = attrs.custom_validate.expect("custom_validate not parsed");
        assert_eq!(
            quote::quote!(#path).to_string(),
            "validate_ueid_size".to_string()
        );
    }

    #[test]
    fn custom_validate_qualified_path() {
        let (_, attrs) = parse_enum(parse_quote! {
            #[cbor(custom_validate = "crate::common::validate_ueid")]
            enum E {
                #[cbor(tag = 550)] Ueid(Vec<u8>),
            }
        });
        let path = attrs.custom_validate.expect("custom_validate not parsed");
        // Qualified paths survive parsing.
        assert_eq!(
            quote::quote!(#path).to_string(),
            "crate :: common :: validate_ueid".to_string()
        );
    }

    // --- rejection paths: variant shape ---

    #[test]
    fn rejects_unit_variant() {
        let err = parse_enum_err(parse_quote! {
            enum E {
                #[cbor(text)] Empty,
            }
        });
        assert!(
            err.contains("unit variants are not supported"),
            "got: {err}"
        );
    }

    #[test]
    fn rejects_struct_variant() {
        let err = parse_enum_err(parse_quote! {
            enum E {
                #[cbor(tag = 1)] Named { x: u32 },
            }
        });
        assert!(err.contains("must be tuple-style"), "got: {err}");
    }

    #[test]
    fn rejects_multi_field_tuple_variant() {
        let err = parse_enum_err(parse_quote! {
            enum E {
                #[cbor(tag = 1)] Pair(u32, u32),
            }
        });
        assert!(err.contains("exactly one tuple field, got 2"), "got: {err}");
    }

    // --- rejection paths: attribute mistakes ---

    #[test]
    fn rejects_variant_without_attribute() {
        let err = parse_enum_err(parse_quote! {
            enum E {
                #[cbor(tag = 37)] Uuid([u8; 16]),
                Text(String), // missing #[cbor(...)]
            }
        });
        assert!(
            err.contains("must have a `#[cbor(...)]` attribute"),
            "got: {err}"
        );
    }

    #[test]
    fn rejects_duplicate_tag() {
        let err = parse_enum_err(parse_quote! {
            enum E {
                #[cbor(tag = 37)] A([u8; 16]),
                #[cbor(tag = 37)] B([u8; 16]),
            }
        });
        assert!(err.contains("duplicate CBOR tag 37"), "got: {err}");
    }

    #[test]
    fn rejects_duplicate_inline_text() {
        let err = parse_enum_err(parse_quote! {
            enum E {
                #[cbor(text)] A(String),
                #[cbor(text)] B(String),
            }
        });
        assert!(err.contains("duplicate `#[cbor(text)]`"), "got: {err}");
    }

    #[test]
    fn rejects_duplicate_inline_uint() {
        let err = parse_enum_err(parse_quote! {
            enum E {
                #[cbor(uint)] A(u64),
                #[cbor(uint)] B(u64),
            }
        });
        assert!(err.contains("duplicate `#[cbor(uint)]`"), "got: {err}");
    }

    #[test]
    fn rejects_inline_text_uint_combined() {
        // text and uint are both inline kinds; can't be combined.
        let err = parse_enum_err(parse_quote! {
            enum E {
                #[cbor(text, uint)] A(String),
            }
        });
        assert!(
            err.contains("inline kinds") && err.contains("mutually exclusive"),
            "got: {err}"
        );
    }

    #[test]
    fn rejects_tagged_text_and_bytes_combined() {
        // On a tagged variant, text and bytes are mutually exclusive shape qualifiers.
        let err = parse_enum_err(parse_quote! {
            enum E {
                #[cbor(tag = 37, text, bytes)] A(String),
            }
        });
        assert!(err.contains("mutually exclusive"), "got: {err}");
    }

    #[test]
    fn rejects_tag_with_uint() {
        // `uint` is an inline-kind selector, not a shape qualifier.
        let err = parse_enum_err(parse_quote! {
            enum E {
                #[cbor(tag = 100, uint)] A(u64),
            }
        });
        assert!(
            err.contains("uint") && err.contains("inline-kind"),
            "got: {err}"
        );
    }

    #[test]
    fn rejects_no_kind() {
        let err = parse_enum_err(parse_quote! {
            enum E {
                #[cbor()] A(String),
            }
        });
        assert!(
            err.contains("exactly one of") || err.contains("must specify"),
            "got: {err}"
        );
    }

    #[test]
    fn rejects_accept_bare_without_tag() {
        let err = parse_enum_err(parse_quote! {
            enum E {
                #[cbor(text, accept_bare = "uuid_16")] A(String),
            }
        });
        assert!(
            err.contains("accept_bare") && err.contains("requires"),
            "got: {err}"
        );
    }

    #[test]
    fn rejects_unknown_accept_bare_rule() {
        let err = parse_enum_err(parse_quote! {
            enum E {
                #[cbor(tag = 37, accept_bare = "wat")] A([u8; 16]),
            }
        });
        assert!(err.contains("unknown accept_bare rule"), "got: {err}");
    }

    // --- rejection paths: enum-level ---

    #[test]
    fn rejects_empty_enum() {
        let err = parse_enum_err(parse_quote! {
            enum E {}
        });
        assert!(err.contains("at least one variant"), "got: {err}");
    }

    // --- bytes attribute ---

    #[test]
    fn bytes_attribute_on_tagged_variant() {
        let (vs, _) = parse_enum(parse_quote! {
            enum E {
                #[cbor(tag = 37, bytes)] Uuid([u8; 16]),
                #[cbor(tag = 111, bytes)] Oid(Vec<u8>),
                #[cbor(tag = 554)] PkixKey(String),
            }
        });
        assert!(matches!(
            vs[0].kind,
            ChoiceVariantKind::Tagged {
                tag: 37,
                bytes: true,
                text: false,
                accept_bare_uuid: false,
                catch_bare_bytes: false,
            }
        ));
        assert!(matches!(
            vs[1].kind,
            ChoiceVariantKind::Tagged {
                tag: 111,
                bytes: true,
                text: false,
                accept_bare_uuid: false,
                catch_bare_bytes: false,
            }
        ));
        assert!(matches!(
            vs[2].kind,
            ChoiceVariantKind::Tagged {
                tag: 554,
                bytes: false,
                text: false,
                accept_bare_uuid: false,
                catch_bare_bytes: false,
            }
        ));
    }

    #[test]
    fn bytes_combines_with_accept_bare() {
        let (vs, _) = parse_enum(parse_quote! {
            enum E {
                #[cbor(tag = 37, bytes, accept_bare = "uuid_16")] Uuid([u8; 16]),
                #[cbor(tag = 560, bytes)] Bytes(Vec<u8>),
            }
        });
        assert!(matches!(
            vs[0].kind,
            ChoiceVariantKind::Tagged {
                tag: 37,
                bytes: true,
                text: false,
                accept_bare_uuid: true,
                catch_bare_bytes: false,
            }
        ));
    }

    #[test]
    fn rejects_bytes_without_tag() {
        let err = parse_enum_err(parse_quote! {
            enum E {
                #[cbor(text, bytes)] X(Vec<u8>),
            }
        });
        assert!(
            err.contains("`bytes` requires `#[cbor(tag = N)]`"),
            "got: {err}"
        );
    }

    // --- catch_bare_bytes attribute ---

    #[test]
    fn catch_bare_bytes_on_tagged_bytes_variant() {
        let (vs, _) = parse_enum(parse_quote! {
            enum E {
                #[cbor(tag = 37, bytes, accept_bare = "uuid_16")] Uuid([u8; 16]),
                #[cbor(tag = 560, bytes, catch_bare_bytes)] Bytes(Vec<u8>),
            }
        });
        assert!(matches!(
            vs[1].kind,
            ChoiceVariantKind::Tagged {
                tag: 560,
                bytes: true,
                text: false,
                accept_bare_uuid: false,
                catch_bare_bytes: true,
            }
        ));
    }

    #[test]
    fn rejects_catch_bare_bytes_without_tag() {
        let err = parse_enum_err(parse_quote! {
            enum E {
                #[cbor(text, catch_bare_bytes)] X(String),
            }
        });
        assert!(
            err.contains("`catch_bare_bytes` requires `#[cbor(tag = N, bytes)]`"),
            "got: {err}"
        );
    }

    #[test]
    fn rejects_catch_bare_bytes_without_bytes() {
        let err = parse_enum_err(parse_quote! {
            enum E {
                #[cbor(tag = 560, catch_bare_bytes)] X(String),
            }
        });
        assert!(
            err.contains("`catch_bare_bytes` requires `#[cbor(tag = N, bytes)]`"),
            "got: {err}"
        );
    }

    #[test]
    fn rejects_duplicate_catch_bare_bytes() {
        let err = parse_enum_err(parse_quote! {
            enum E {
                #[cbor(tag = 560, bytes, catch_bare_bytes)] A(Vec<u8>),
                #[cbor(tag = 561, bytes, catch_bare_bytes)] B(Vec<u8>),
            }
        });
        assert!(
            err.contains("duplicate `#[cbor(catch_bare_bytes)]`")
                && err.contains("at most one variant per enum"),
            "got: {err}"
        );
    }

    // --- text shape qualifier on tagged variants ---

    #[test]
    fn text_attribute_on_tagged_variant() {
        let (vs, _) = parse_enum(parse_quote! {
            enum E {
                #[cbor(tag = 554, text)] PkixKey(String),
                #[cbor(tag = 555, text)] PkixCert(String),
                #[cbor(tag = 100)]       Other(u64),
            }
        });
        assert!(matches!(
            vs[0].kind,
            ChoiceVariantKind::Tagged {
                tag: 554,
                bytes: false,
                text: true,
                accept_bare_uuid: false,
                catch_bare_bytes: false,
            }
        ));
        assert!(matches!(
            vs[1].kind,
            ChoiceVariantKind::Tagged {
                tag: 555,
                bytes: false,
                text: true,
                accept_bare_uuid: false,
                catch_bare_bytes: false,
            }
        ));
        // Tag without text/bytes still parses correctly.
        assert!(matches!(
            vs[2].kind,
            ChoiceVariantKind::Tagged {
                tag: 100,
                bytes: false,
                text: false,
                accept_bare_uuid: false,
                catch_bare_bytes: false,
            }
        ));
    }
}
