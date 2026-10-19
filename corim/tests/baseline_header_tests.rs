// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Tests for `corim::baseline::compare_headers` — protected-header
//! structural conformance of signed CoRIMs.

use corim::baseline::{render_path, MismatchKind, PathSegment};
use corim::cbor::value::Value;
use corim::types::corim::{CorimMetaMap, CorimSignerMap};
use corim::types::signed::{
    CoseAlgorithm, CwtClaims, ProtectedCorimHeaderMap, ProtectedCorimHeaderMapBuilder,
};

fn header() -> ProtectedCorimHeaderMapBuilder {
    ProtectedCorimHeaderMapBuilder::new(CoseAlgorithm::Es256).content_type("application/rim+cbor")
}

fn compare_headers(
    input: &ProtectedCorimHeaderMap,
    baseline: &ProtectedCorimHeaderMap,
) -> corim::baseline::ConformanceReport {
    corim::baseline::compare_headers(input, baseline).unwrap()
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
fn nested_map_keys_in_header_extensions_compare_without_reencoding_explosion() {
    use corim::cbor::{self, constants};
    let mut bytes = vec![(constants::MAJOR_MAP << 5) | 1; 40];
    bytes.extend(vec![constants::BYTE_NULL; 41]);
    let extension: Value = cbor::decode_exact(&bytes).unwrap();
    let baseline = header().extra(10001, extension).build();
    let report = compare_headers(&baseline, &baseline);
    assert!(report.is_conformant());
    assert!(report.value_differences.is_empty());
    assert_eq!(bytes.pop(), Some(constants::BYTE_NULL));
    bytes.push(constants::BYTE_TRUE);
    let changed = header()
        .extra(10001, cbor::decode_exact(&bytes).unwrap())
        .build();
    assert!(!compare_headers(&changed, &baseline).is_conformant());
}

#[test]
fn header_extensions_compare_shape_and_reject_invalid_cbor() {
    let baseline = header()
        .extra(10001, Value::Array(vec![Value::Integer(1)]))
        .build();
    let changed = header()
        .extra(10001, Value::Array(vec![Value::Text("1".into())]))
        .build();
    assert!(!compare_headers(&changed, &baseline).is_conformant());
    let invalid = header().extra(10001, Value::Integer(i128::MAX)).build();
    assert!(corim::baseline::compare_headers(&invalid, &invalid).is_err());
    assert!(corim::baseline::compare_headers(&invalid, &baseline).is_err());
    assert!(corim::baseline::compare_headers(&baseline, &invalid).is_err());
}

#[test]
fn large_extension_map_comparison_preserves_all_entries() {
    let entries: Vec<_> = (0..100_000)
        .map(|index| (Value::Integer(index), Value::Integer(index)))
        .collect();
    let mut reversed = entries.clone();
    reversed.reverse();
    let baseline = header().extra(10001, Value::Map(entries)).build();
    let input = header().extra(10001, Value::Map(reversed)).build();
    let report = compare_headers(&input, &baseline);
    assert!(report.is_conformant());
    assert!(report.value_differences.is_empty());
}

#[test]
fn indexed_extension_keys_preserve_recursive_identity_and_multiplicity() {
    let key = Value::Map(vec![
        (Value::Text("a".into()), Value::Integer(1)),
        (Value::Text("b".into()), Value::Integer(2)),
    ]);
    let Value::Map(mut reordered_key) = key.clone() else {
        panic!("map key");
    };
    reordered_key.reverse();
    let reordered_key = Value::Map(reordered_key);
    let baseline_entries = vec![
        (key.clone(), Value::Float(0.0)),
        (key.clone(), Value::Float(-0.0)),
    ];
    let baseline = header().extra(10001, Value::Map(baseline_entries)).build();
    let input = header()
        .extra(
            10001,
            Value::Map(vec![
                (reordered_key.clone(), Value::Float(-0.0)),
                (reordered_key.clone(), Value::Float(0.0)),
            ]),
        )
        .build();
    let report = compare_headers(&input, &baseline);
    assert!(report.is_conformant());
    assert!(report.value_differences.is_empty());
    let missing = header()
        .extra(
            10001,
            Value::Map(vec![(reordered_key.clone(), Value::Float(0.0))]),
        )
        .build();
    assert!(!compare_headers(&missing, &baseline).is_conformant());
    let changed = header()
        .extra(
            10001,
            Value::Map(vec![
                (key, Value::Float(1.0)),
                (reordered_key, Value::Float(0.0)),
            ]),
        )
        .build();
    let report = compare_headers(&changed, &baseline);
    assert!(report.is_conformant());
    assert_eq!(report.value_differences.len(), 1);
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

#[test]
fn value_diff_path_includes_leaf_field() {
    let b = header().corim_meta(meta("Authority A")).build();
    let i = header().corim_meta(meta("Authority B")).build();
    let r = compare_headers(&i, &b);
    let paths: Vec<String> = r
        .value_differences
        .iter()
        .map(|v| render_path(&v.path))
        .collect();
    assert!(
        paths
            .iter()
            .any(|p| p == "$.protected-header.corim-meta.signer-name"),
        "{paths:?}"
    );
}

#[test]
fn structural_mismatch_path_includes_leaf_field() {
    let b = ProtectedCorimHeaderMapBuilder::new(CoseAlgorithm::Es256)
        .content_type("application/rim+cbor")
        .build();
    let i = ProtectedCorimHeaderMapBuilder::new(CoseAlgorithm::Es256)
        .content_type("text/plain")
        .build();
    let r = compare_headers(&i, &b);
    assert!(r
        .structural_mismatches
        .iter()
        .any(|m| render_path(&m.path) == "$.protected-header.content-type"));
}

#[test]
fn extension_key_absent_in_input_is_reported_even_when_baseline_is_null() {
    let b = header().extra(9, Value::Null).build();
    let i = header().build();
    let r = compare_headers(&i, &b);
    assert!(
        r.structural_mismatches
            .iter()
            .any(|v| render_path(&v.path) == "$.protected-header.header-extension[9]"),
        "a baseline extension key (even a null one) missing from the input is a difference"
    );
}

/// A text-keyed claim containing a quote, backslash, or control character
/// must not produce an ambiguous or multi-line path.
#[test]
fn text_claim_key_path_is_escaped() {
    use corim::types::signed::ClaimKey;

    fn path_for(key: &str) -> String {
        let mut claims = CwtClaims::new("iss");
        claims
            .extra
            .insert(ClaimKey::Text(key.into()), Value::Integer(1));
        let b = header().cwt_claims(claims).build();
        let i = header().cwt_claims(CwtClaims::new("iss")).build();
        let r = compare_headers(&i, &b);
        r.structural_mismatches
            .iter()
            .map(|v| render_path(&v.path))
            .find(|p| p.contains("cwt-extension"))
            .expect("claim difference reported")
    }

    assert!(path_for(r#"a"b\c"#).ends_with(r#"["a\"b\\c"]"#));

    let nl = path_for("a\nb");
    assert!(!nl.contains('\n'), "path must stay on one line: {nl:?}");
    assert!(nl.ends_with(r#"["a\nb"]"#), "{nl:?}");

    let ctrl = path_for("a\u{1}b");
    assert!(ctrl.ends_with(r#"["a\u0001b"]"#), "{ctrl:?}");
}
