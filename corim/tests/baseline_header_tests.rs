// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Tests for `corim::baseline::compare_headers` — protected-header
//! structural conformance of signed CoRIMs.

use corim::baseline::{compare_headers, MismatchKind, PathSegment};
use corim::types::corim::{CorimMetaMap, CorimSignerMap};
use corim::types::signed::{
    CoseAlgorithm, CwtClaims, ProtectedCorimHeaderMap, ProtectedCorimHeaderMapBuilder,
};

fn header() -> ProtectedCorimHeaderMapBuilder {
    ProtectedCorimHeaderMapBuilder::new(CoseAlgorithm::Es256).content_type("application/rim+cbor")
}

fn meta(name: &str) -> CorimMetaMap {
    CorimMetaMap {
        signer: CorimSignerMap {
            signer_name: name.into(),
            signer_uri: None,
        },
        signature_validity: None,
    }
}

fn has_field(paths: &[Vec<PathSegment>], field: &'static str) -> bool {
    paths.iter().any(|p| p.contains(&PathSegment::Field(field)))
}

#[test]
fn identical_headers_conform() {
    let b = header().cwt_claims(CwtClaims::new("iss-1")).build();
    let i = header().cwt_claims(CwtClaims::new("iss-1")).build();
    let r = compare_headers(&i, &b);
    assert!(r.is_conformant());
    assert!(r.value_differences.is_empty());
}

#[test]
fn cwt_iss_difference_is_structural() {
    let b = header().cwt_claims(CwtClaims::new("iss-A")).build();
    let i = header().cwt_claims(CwtClaims::new("iss-B")).build();
    let r = compare_headers(&i, &b);
    assert!(!r.is_conformant(), "iss is structural");
    let paths: Vec<_> = r
        .structural_mismatches
        .iter()
        .map(|m| m.path.clone())
        .collect();
    assert!(has_field(&paths, "cwt-claims"));
    assert!(r
        .structural_mismatches
        .iter()
        .any(|m| matches!(m.kind, MismatchKind::TypeMismatch { .. })));
}

#[test]
fn cwt_subject_difference_is_value() {
    let b = header()
        .cwt_claims(CwtClaims::new("iss-1").with_sub("sub-A"))
        .build();
    let i = header()
        .cwt_claims(CwtClaims::new("iss-1").with_sub("sub-B"))
        .build();
    let r = compare_headers(&i, &b);
    assert!(r.is_conformant(), "subject may differ");
    assert_eq!(r.value_differences.len(), 1);
    assert_eq!(r.value_differences[0].field, "sub");
}

#[test]
fn corim_meta_signer_name_difference_is_value() {
    let b = header().corim_meta(meta("Authority A")).build();
    let i = header().corim_meta(meta("Authority B")).build();
    let r = compare_headers(&i, &b);
    assert!(r.is_conformant(), "signer name may differ");
    assert!(r.value_differences.iter().any(|v| v.field == "signer-name"));
}

#[test]
fn alg_difference_is_structural() {
    let b = ProtectedCorimHeaderMapBuilder::new(CoseAlgorithm::Es256).build();
    let i = ProtectedCorimHeaderMapBuilder::new(CoseAlgorithm::Es384).build();
    let r = compare_headers(&i, &b);
    assert!(!r.is_conformant(), "alg is structural");
    assert!(r
        .structural_mismatches
        .iter()
        .any(|m| m.path.contains(&PathSegment::Field("alg"))));
}

#[test]
fn kid_presence_difference_is_structural() {
    let b: ProtectedCorimHeaderMap = header().kid(vec![1, 2, 3]).build();
    let i: ProtectedCorimHeaderMap = header().build();
    let r = compare_headers(&i, &b);
    assert!(!r.is_conformant(), "kid presence is structural");
    assert!(r
        .structural_mismatches
        .iter()
        .any(|m| m.kind == MismatchKind::MissingInInput
            && m.path.contains(&PathSegment::Field("kid"))));
}

#[test]
fn kid_bytes_difference_is_value() {
    let b = header().kid(vec![1, 2, 3]).build();
    let i = header().kid(vec![4, 5, 6]).build();
    let r = compare_headers(&i, &b);
    assert!(r.is_conformant(), "kid bytes may differ");
    assert!(r.value_differences.iter().any(|v| v.field == "kid"));
}
