// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Structural conformance comparison of a CoRIM against a baseline.
//!
//! Compares an `input` CoRIM against a known-good `baseline` and reports
//! two classes of differences:
//!
//! - **Structural mismatches** — the two documents differ in *shape*: a
//!   CoMID / triple / measurement / measurement-values attribute present
//!   in one but not the other, or a type/algorithm discriminant that
//!   differs. These indicate the input does **not** conform to the
//!   baseline's structure.
//! - **Value differences** — the same structure carries a different
//!   concrete value (a digest's bytes, an svn number, a flag's boolean,
//!   …). These are expected to vary across builds and are reported for
//!   visibility only; they are **not** conformance failures.
//!
//! The structure/value boundary follows the draft-ietf-rats-corim-11
//! appraisal model (§8.2.4.4): the environment (§8.2.4.4.1), the
//! measured-element key (§8.2.4.4.4), attribute *presence*
//! (§8.2.4.4.5), the type/tag discriminant (§8.2.4.4.5.1), and a
//! digest's *algorithm* (§8.2.4.4.5.4) are identity/structure; the
//! concrete per-attribute payloads are values.
//!
//! This module performs the comparison and returns a structured
//! [`ConformanceReport`](crate::baseline::ConformanceReport). It does not
//! impose any serialization format — callers (e.g. `corim-cli`) render the
//! report to text or JSON.

use crate::cbor::value::{to_value, Value};
use crate::nostd_prelude::*;
use crate::types::comid::ComidTag;
use crate::types::corim::{ConciseTagChoice, CorimMap, CorimMetaMap};
use crate::types::measurement::{
    Digest, DigestAlg, FlagsMap, MeasurementMap, MeasurementValuesMap, RawValueChoice, SvnChoice,
};
use crate::types::signed::{CoseCertHash, CoseX509, CwtClaims, ProtectedCorimHeaderMap};

// ---------------------------------------------------------------------------
// Report types
// ---------------------------------------------------------------------------

/// A single step in a path locating a difference within the CoRIM tree.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum PathSegment {
    /// A CoMID selected by its `tag-identity` id (or `#<index>` if none).
    Comid(String),
    /// A triple list of the named kind (e.g. `reference`) at an index.
    Triple {
        /// The triple kind (`reference`, `endorsed`, …).
        kind: &'static str,
        /// Position within that kind's list (baseline order).
        index: usize,
    },
    /// A measurement selected by its `mkey` (or `#<index>` if unkeyed).
    Measurement(String),
    /// A named field / attribute (mval attribute, corim-level field, …).
    Field(&'static str),
    /// An array index within a field (e.g. a digest slot).
    Index(usize),
    /// A signed integer map key (e.g. an `mval-extension` key, which the
    /// CDDL allows to be any `int` including large or negative values).
    MapKey(i64),
}

/// The nature of a structural mismatch.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum MismatchKind {
    /// Present in the baseline but absent from the input.
    MissingInInput,
    /// Present in the input but absent from the baseline.
    UnexpectedInInput,
    /// Present in both but with a different type/shape discriminant
    /// (e.g. `svn` vs `min-svn`, `digests` vs `raw-value`, a differing
    /// digest algorithm).
    TypeMismatch {
        /// The baseline's discriminant/description.
        baseline: String,
        /// The input's discriminant/description.
        input: String,
    },
}

/// A structural mismatch — the input does not conform to the baseline.
#[derive(Clone, Debug, PartialEq)]
pub struct StructuralMismatch {
    /// Location of the mismatch within the CoRIM tree.
    pub path: Vec<PathSegment>,
    /// What kind of mismatch this is.
    pub kind: MismatchKind,
    /// Human-readable detail.
    pub detail: String,
}

/// A value difference — same structure, different concrete value.
/// Reported for visibility; never a conformance failure.
#[derive(Clone, Debug, PartialEq)]
pub struct ValueDifference {
    /// Location of the difference within the CoRIM tree.
    pub path: Vec<PathSegment>,
    /// The attribute whose value differs.
    pub field: &'static str,
    /// The baseline value, as a structured CBOR value.
    pub baseline: Value,
    /// The input value, as a structured CBOR value.
    pub input: Value,
}

/// The result of comparing an input CoRIM against a baseline.
#[derive(Clone, Debug, PartialEq, Default)]
#[non_exhaustive]
pub struct ConformanceReport {
    /// Structural mismatches (conformance failures).
    pub structural_mismatches: Vec<StructuralMismatch>,
    /// Value differences (informational).
    pub value_differences: Vec<ValueDifference>,
}

impl ConformanceReport {
    /// Returns `true` when there are no structural mismatches (the input
    /// conforms to the baseline's structure). Value differences do not
    /// affect conformance.
    pub fn is_conformant(&self) -> bool {
        self.structural_mismatches.is_empty()
    }

    /// Append another report's findings into this one (used to combine a
    /// payload comparison with a protected-header comparison).
    pub fn merge(&mut self, other: ConformanceReport) {
        self.structural_mismatches
            .extend(other.structural_mismatches);
        self.value_differences.extend(other.value_differences);
    }
}

/// Render a path as a dotted location string (presentation-neutral).
pub fn render_path(path: &[PathSegment]) -> String {
    let mut s = String::from("$");
    for seg in path {
        match seg {
            PathSegment::Comid(id) => s.push_str(&format!(".comid[{id}]")),
            PathSegment::Triple { kind, index } => s.push_str(&format!(".{kind}[{index}]")),
            PathSegment::Measurement(k) => s.push_str(&format!(".measurement[{k}]")),
            PathSegment::Field(f) => s.push_str(&format!(".{f}")),
            PathSegment::Index(i) => s.push_str(&format!("[{i}]")),
            PathSegment::MapKey(k) => s.push_str(&format!("[{k}]")),
        }
    }
    s
}

// ---------------------------------------------------------------------------
// Comparison entry point
// ---------------------------------------------------------------------------

/// Compare `input` against `baseline` for structural conformance.
///
/// Returns a [`ConformanceReport`]; the input conforms when
/// [`ConformanceReport::is_conformant`] is `true`.
pub fn compare(input: &CorimMap, baseline: &CorimMap) -> ConformanceReport {
    let mut r = ConformanceReport::default();

    // --- corim-level: profile is structural; id/validity/entities are values.
    compare_opt_value(
        &[PathSegment::Field("profile")],
        "profile",
        opt_val(&baseline.profile),
        opt_val(&input.profile),
        &mut r,
        /*structural=*/ true,
    );
    compare_opt_value(
        &[PathSegment::Field("corim-id")],
        "corim-id",
        Some(to_value_lossy(&baseline.id)),
        Some(to_value_lossy(&input.id)),
        &mut r,
        false,
    );

    // --- CoMIDs: decode and pair by tag-identity id.
    let base_comids = decode_comids(baseline);
    let input_comids = decode_comids(input);
    compare_comids(&base_comids, &input_comids, &mut r);

    r
}

// ---------------------------------------------------------------------------
// Protected-header comparison (signed CoRIMs)
// ---------------------------------------------------------------------------

/// Compare two COSE protected headers of signed CoRIMs.
///
/// Structural (must match): `alg`, `content-type`, hash-envelope mode
/// (`payload_hash_alg` / `payload_preimage_content_type`), the *presence*
/// of `corim-meta` / `CWT-Claims` / `kid` / `x5bag` / `x5chain` / `x5t` /
/// `x5u`, and the CWT `iss` (the signer identity). Everything else — signer
/// name/uri, signature-validity, CWT `sub`/`exp`/`nbf` and extra claims,
/// certificate/key bytes, `payload-location`, extra header labels — is
/// reported as a value difference only.
///
/// Findings are located under `$.protected-header`.
pub fn compare_headers(
    input: &ProtectedCorimHeaderMap,
    baseline: &ProtectedCorimHeaderMap,
) -> ConformanceReport {
    let mut r = ConformanceReport::default();
    let base = [PathSegment::Field("protected-header")];

    // alg — structural (the signing algorithm must match).
    if baseline.alg != input.alg {
        let mut p = base.to_vec();
        p.push(PathSegment::Field("alg"));
        r.structural_mismatches.push(StructuralMismatch {
            path: p,
            kind: MismatchKind::TypeMismatch {
                baseline: format!("{}", baseline.alg),
                input: format!("{}", input.alg),
            },
            detail: "protected-header alg differs".into(),
        });
    }
    // content-type / hash-envelope mode — structural.
    compare_opt_value(
        &base,
        "content-type",
        opt_val(&baseline.content_type),
        opt_val(&input.content_type),
        &mut r,
        true,
    );
    compare_opt_value(
        &base,
        "payload-hash-alg",
        opt_int(baseline.payload_hash_alg),
        opt_int(input.payload_hash_alg),
        &mut r,
        true,
    );
    compare_opt_value(
        &base,
        "payload-preimage-content-type",
        opt_val(&baseline.payload_preimage_content_type),
        opt_val(&input.payload_preimage_content_type),
        &mut r,
        true,
    );
    // payload-location — value.
    compare_opt_value(
        &base,
        "payload-location",
        opt_val(&baseline.payload_location),
        opt_val(&input.payload_location),
        &mut r,
        false,
    );

    // corim-meta — presence structural; contents are values.
    compare_presence(
        &base,
        "corim-meta",
        baseline.corim_meta.is_some(),
        input.corim_meta.is_some(),
        &mut r,
    );
    if let (Some(b), Some(i)) = (&baseline.corim_meta, &input.corim_meta) {
        compare_corim_meta(&base, b, i, &mut r);
    }

    // CWT-Claims — presence structural; `iss` structural; rest values.
    compare_presence(
        &base,
        "cwt-claims",
        baseline.cwt_claims.is_some(),
        input.cwt_claims.is_some(),
        &mut r,
    );
    if let (Some(b), Some(i)) = (&baseline.cwt_claims, &input.cwt_claims) {
        compare_cwt_claims(&base, b, i, &mut r);
    }

    // X.509 / kid — presence structural; the bytes/contents are values.
    compare_opt_with(&base, "kid", &baseline.kid, &input.kid, &mut r, |b| {
        Value::Bytes(b.clone())
    });
    compare_opt_with(
        &base,
        "x5bag",
        &baseline.x5bag,
        &input.x5bag,
        &mut r,
        cose_x509_value,
    );
    compare_opt_with(
        &base,
        "x5chain",
        &baseline.x5chain,
        &input.x5chain,
        &mut r,
        cose_x509_value,
    );
    compare_opt_with(
        &base,
        "x5t",
        &baseline.x5t,
        &input.x5t,
        &mut r,
        cose_cert_hash_value,
    );
    compare_opt_with(&base, "x5u", &baseline.x5u, &input.x5u, &mut r, |s| {
        Value::Text(s.clone())
    });

    // Extra header labels — reported as value differences.
    compare_extra_values(
        &base,
        "header-extension",
        &baseline.extra,
        &input.extra,
        &mut r,
    );

    r
}

/// A presence difference on a structural field.
fn compare_presence(
    base: &[PathSegment],
    field: &'static str,
    baseline_present: bool,
    input_present: bool,
    r: &mut ConformanceReport,
) {
    match (baseline_present, input_present) {
        (true, false) => push_missing_field(base, field, r),
        (false, true) => push_unexpected_field(base, field, r),
        _ => {}
    }
}

/// Presence is structural; when present on both, a content difference (as
/// produced by `to_val`) is a value difference.
fn compare_opt_with<T: PartialEq, F: Fn(&T) -> Value>(
    base: &[PathSegment],
    field: &'static str,
    baseline: &Option<T>,
    input: &Option<T>,
    r: &mut ConformanceReport,
    to_val: F,
) {
    match (baseline, input) {
        (Some(_), None) => push_missing_field(base, field, r),
        (None, Some(_)) => push_unexpected_field(base, field, r),
        (Some(b), Some(i)) if b != i => {
            let mut p = base.to_vec();
            p.push(PathSegment::Field(field));
            r.value_differences.push(ValueDifference {
                path: p,
                field,
                baseline: to_val(b),
                input: to_val(i),
            });
        }
        _ => {}
    }
}

fn cose_x509_value(x: &CoseX509) -> Value {
    match x {
        CoseX509::Single(c) => Value::Bytes(c.clone()),
        CoseX509::Chain(cs) => Value::Array(cs.iter().map(|c| Value::Bytes(c.clone())).collect()),
    }
}

fn cose_cert_hash_value(h: &CoseCertHash) -> Value {
    let alg = match &h.hash_alg {
        DigestAlg::Int(n) => Value::Integer(i128::from(*n)),
        DigestAlg::Text(t) => Value::Text(t.clone()),
    };
    Value::Array(alloc::vec![alg, Value::Bytes(h.hash_value.clone())])
}

fn compare_corim_meta(
    base: &[PathSegment],
    baseline: &CorimMetaMap,
    input: &CorimMetaMap,
    r: &mut ConformanceReport,
) {
    let mut p = base.to_vec();
    p.push(PathSegment::Field("corim-meta"));
    compare_opt_value(
        &p,
        "signer-name",
        Some(Value::Text(baseline.signer.signer_name.clone())),
        Some(Value::Text(input.signer.signer_name.clone())),
        r,
        false,
    );
    compare_opt_value(
        &p,
        "signer-uri",
        opt_val(&baseline.signer.signer_uri),
        opt_val(&input.signer.signer_uri),
        r,
        false,
    );
    compare_opt_value(
        &p,
        "signature-validity",
        opt_val(&baseline.signature_validity),
        opt_val(&input.signature_validity),
        r,
        false,
    );
}

fn compare_cwt_claims(
    base: &[PathSegment],
    baseline: &CwtClaims,
    input: &CwtClaims,
    r: &mut ConformanceReport,
) {
    let mut p = base.to_vec();
    p.push(PathSegment::Field("cwt-claims"));
    // `iss` (the signer identity) is structural.
    compare_opt_value(
        &p,
        "iss",
        Some(Value::Text(baseline.iss.clone())),
        Some(Value::Text(input.iss.clone())),
        r,
        true,
    );
    compare_opt_value(
        &p,
        "sub",
        opt_val(&baseline.sub),
        opt_val(&input.sub),
        r,
        false,
    );
    compare_opt_value(
        &p,
        "exp",
        opt_int(baseline.exp),
        opt_int(input.exp),
        r,
        false,
    );
    compare_opt_value(
        &p,
        "nbf",
        opt_int(baseline.nbf),
        opt_int(input.nbf),
        r,
        false,
    );
    compare_extra_values(&p, "cwt-extension", &baseline.extra, &input.extra, r);
}

/// Report presence and content differences of an integer-keyed extension
/// map as value differences (never structural).
fn compare_extra_values(
    base: &[PathSegment],
    field: &'static str,
    baseline: &BTreeMap<i64, Value>,
    input: &BTreeMap<i64, Value>,
    r: &mut ConformanceReport,
) {
    for (k, bv) in baseline {
        let iv = input.get(k).cloned().unwrap_or(Value::Null);
        if &iv != bv {
            let mut p = base.to_vec();
            p.push(PathSegment::Field(field));
            p.push(PathSegment::MapKey(*k));
            r.value_differences.push(ValueDifference {
                path: p,
                field,
                baseline: bv.clone(),
                input: iv,
            });
        }
    }
    for (k, iv) in input {
        if !baseline.contains_key(k) {
            let mut p = base.to_vec();
            p.push(PathSegment::Field(field));
            p.push(PathSegment::MapKey(*k));
            r.value_differences.push(ValueDifference {
                path: p,
                field,
                baseline: Value::Null,
                input: iv.clone(),
            });
        }
    }
}

fn opt_int(v: Option<i64>) -> Option<Value> {
    v.map(|n| Value::Integer(i128::from(n)))
}

/// Decode the CoMID tags of a CoRIM into `(tag-id, ComidTag)` pairs,
/// preserving order. Non-CoMID tags and undecodable entries are skipped
/// (the CLI validates both inputs before calling `compare`).
fn decode_comids(corim: &CorimMap) -> Vec<(String, ComidTag)> {
    let mut out = Vec::new();
    for (i, tag) in corim.tags.iter().enumerate() {
        if let ConciseTagChoice::Comid(bytes) = tag {
            if let Ok(comid) = crate::cbor::decode::<ComidTag>(bytes) {
                let id = tag_id_string(&comid, i);
                out.push((id, comid));
            }
        }
    }
    out
}

fn tag_id_string(comid: &ComidTag, index: usize) -> String {
    // `tag-identity.id` is a `$tag-id-type-choice` (text or UUID bytes).
    match to_value(&comid.tag_identity.tag_id) {
        Ok(Value::Text(t)) => t,
        Ok(Value::Bytes(b)) => hex(&b),
        _ => format!("#{index}"),
    }
}

fn compare_comids(
    baseline: &[(String, ComidTag)],
    input: &[(String, ComidTag)],
    r: &mut ConformanceReport,
) {
    for (id, b_comid) in baseline {
        match input.iter().find(|(iid, _)| iid == id) {
            Some((_, i_comid)) => {
                let path = [PathSegment::Comid(id.clone())];
                compare_triples(&path, &b_comid.triples, &i_comid.triples, r);
            }
            None => r.structural_mismatches.push(StructuralMismatch {
                path: alloc::vec![PathSegment::Comid(id.clone())],
                kind: MismatchKind::MissingInInput,
                detail: "CoMID present in baseline but missing in input".into(),
            }),
        }
    }
    for (id, _) in input {
        if !baseline.iter().any(|(bid, _)| bid == id) {
            r.structural_mismatches.push(StructuralMismatch {
                path: alloc::vec![PathSegment::Comid(id.clone())],
                kind: MismatchKind::UnexpectedInInput,
                detail: "CoMID present in input but not in baseline".into(),
            });
        }
    }
}

// ---------------------------------------------------------------------------
// Triples (commit 1: reference + endorsed; both are [env, [+ measurement]])
// ---------------------------------------------------------------------------

fn compare_triples(
    base_path: &[PathSegment],
    baseline: &crate::types::triples::TriplesMap,
    input: &crate::types::triples::TriplesMap,
    r: &mut ConformanceReport,
) {
    compare_measurement_triples(
        base_path,
        "reference",
        baseline.reference_triples.as_deref().map(refs_as_pairs),
        input.reference_triples.as_deref().map(refs_as_pairs),
        r,
    );
    compare_measurement_triples(
        base_path,
        "endorsed",
        baseline.endorsed_triples.as_deref().map(endorsed_as_pairs),
        input.endorsed_triples.as_deref().map(endorsed_as_pairs),
        r,
    );
    compare_ces(
        base_path,
        baseline.conditional_endorsement_series.as_deref(),
        input.conditional_endorsement_series.as_deref(),
        r,
    );
    compare_ce(
        base_path,
        baseline.conditional_endorsement.as_deref(),
        input.conditional_endorsement.as_deref(),
        r,
    );
    // Key/domain triples carry identity content (keys, domains, tag-ids)
    // that the spec compares binary (§8.2.4.4.2); any difference is
    // therefore structural. Paired by position.
    compare_opaque_triples(
        "identity",
        base_path,
        baseline.identity_triples.as_deref(),
        input.identity_triples.as_deref(),
        r,
    );
    compare_opaque_triples(
        "attest-key",
        base_path,
        baseline.attest_key_triples.as_deref(),
        input.attest_key_triples.as_deref(),
        r,
    );
    compare_opaque_triples(
        "dependency",
        base_path,
        baseline.dependency_triples.as_deref(),
        input.dependency_triples.as_deref(),
        r,
    );
    compare_opaque_triples(
        "membership",
        base_path,
        baseline.membership_triples.as_deref(),
        input.membership_triples.as_deref(),
        r,
    );
    compare_opaque_triples(
        "coswid",
        base_path,
        baseline.coswid_triples.as_deref(),
        input.coswid_triples.as_deref(),
        r,
    );
}

/// Compare conditional-endorsement-series triples, paired by their
/// common-condition environment. Claims-list and each series record's
/// condition/addition measurement lists are compared like measurements.
fn compare_ces(
    base_path: &[PathSegment],
    baseline: Option<&[crate::types::triples::ConditionalEndorsementSeriesTriple]>,
    input: Option<&[crate::types::triples::ConditionalEndorsementSeriesTriple]>,
    r: &mut ConformanceReport,
) {
    let b = baseline.unwrap_or(&[]);
    let i = input.unwrap_or(&[]);
    let kind = "conditional-endorsement-series";
    for (index, bt) in b.iter().enumerate() {
        let mut path = base_path.to_vec();
        path.push(PathSegment::Triple { kind, index });
        match i
            .iter()
            .find(|it| it.common_condition().environment == bt.common_condition().environment)
        {
            Some(it) => {
                meas_list(
                    &path,
                    "claims-list",
                    &bt.common_condition().claims_list,
                    &it.common_condition().claims_list,
                    r,
                );
                if bt.common_condition().authorized_by != it.common_condition().authorized_by {
                    push_authority_mismatch(&path, r);
                }
                compare_series(&path, bt.series(), it.series(), r);
            }
            None => r.structural_mismatches.push(StructuralMismatch {
                path,
                kind: MismatchKind::MissingInInput,
                detail:
                    "CES triple common-condition environment present in baseline but not in input"
                        .into(),
            }),
        }
    }
    for (in_index, it) in i.iter().enumerate() {
        if !b
            .iter()
            .any(|bt| bt.common_condition().environment == it.common_condition().environment)
        {
            let mut path = base_path.to_vec();
            path.push(PathSegment::Triple {
                kind,
                index: in_index,
            });
            r.structural_mismatches.push(StructuralMismatch {
                path,
                kind: MismatchKind::UnexpectedInInput,
                detail: "CES triple present in input but not in baseline".into(),
            });
        }
    }
}

/// Compare CES series records by position (order is significant — first
/// match wins, §8.2.4.3.2). A differing series length is structural.
fn compare_series(
    base_path: &[PathSegment],
    baseline: &[crate::types::triples::ConditionalSeriesRecord],
    input: &[crate::types::triples::ConditionalSeriesRecord],
    r: &mut ConformanceReport,
) {
    if baseline.len() != input.len() {
        let mut p = base_path.to_vec();
        p.push(PathSegment::Field("series"));
        r.structural_mismatches.push(StructuralMismatch {
            path: p,
            kind: MismatchKind::TypeMismatch {
                baseline: baseline.len().to_string(),
                input: input.len().to_string(),
            },
            detail: "CES series length differs".into(),
        });
    }
    for (idx, br) in baseline.iter().enumerate() {
        let mut p = base_path.to_vec();
        p.push(PathSegment::Field("series"));
        p.push(PathSegment::Index(idx));
        match input.get(idx) {
            Some(ir) => {
                meas_list(&p, "condition", br.condition(), ir.condition(), r);
                meas_list(&p, "addition", br.addition(), ir.addition(), r);
            }
            None => r.structural_mismatches.push(StructuralMismatch {
                path: p,
                kind: MismatchKind::MissingInInput,
                detail: "CES series record present in baseline but not in input".into(),
            }),
        }
    }
}

/// Compare conditional-endorsement triples by position: `conditions`
/// (stateful-environment-records, paired by environment) and
/// `endorsements` (endorsed-triple-records, paired by environment).
fn compare_ce(
    base_path: &[PathSegment],
    baseline: Option<&[crate::types::triples::ConditionalEndorsementTriple]>,
    input: Option<&[crate::types::triples::ConditionalEndorsementTriple]>,
    r: &mut ConformanceReport,
) {
    let b = baseline.unwrap_or(&[]);
    let i = input.unwrap_or(&[]);
    let kind = "conditional-endorsement";
    let n = b.len().max(i.len());
    for index in 0..n {
        let mut path = base_path.to_vec();
        path.push(PathSegment::Triple { kind, index });
        match (b.get(index), i.get(index)) {
            (Some(bt), Some(it)) => {
                // conditions: stateful-environment-records, env-keyed.
                let bc: EnvMeas = bt.0.iter().map(|s| (&s.0, s.1.as_slice())).collect();
                let ic: EnvMeas = it.0.iter().map(|s| (&s.0, s.1.as_slice())).collect();
                compare_env_meas(&path, "conditions", &bc, &ic, r);
                // endorsements: endorsed-triple-records, env-keyed.
                let be: EnvMeas = it_pairs(&bt.1);
                let ie: EnvMeas = it_pairs(&it.1);
                compare_env_meas(&path, "endorsements", &be, &ie, r);
            }
            (Some(_), None) => r.structural_mismatches.push(StructuralMismatch {
                path,
                kind: MismatchKind::MissingInInput,
                detail: "conditional-endorsement triple present in baseline but not in input"
                    .into(),
            }),
            (None, Some(_)) => r.structural_mismatches.push(StructuralMismatch {
                path,
                kind: MismatchKind::UnexpectedInInput,
                detail: "conditional-endorsement triple present in input but not in baseline"
                    .into(),
            }),
            (None, None) => {}
        }
    }
}

fn it_pairs(v: &[crate::types::triples::EndorsedTriple]) -> EnvMeas<'_> {
    v.iter().map(|t| (&t.0, t.1.as_slice())).collect()
}

/// Compare two env-keyed measurement groups nested under a named field.
fn compare_env_meas(
    base_path: &[PathSegment],
    field: &'static str,
    baseline: &EnvMeas<'_>,
    input: &EnvMeas<'_>,
    r: &mut ConformanceReport,
) {
    for (b_env, b_meas) in baseline {
        let mut path = base_path.to_vec();
        path.push(PathSegment::Field(field));
        match input.iter().find(|(ie, _)| *ie == *b_env) {
            Some((_, i_meas)) => compare_measurements(&path, b_meas, i_meas, r),
            None => r.structural_mismatches.push(StructuralMismatch {
                path,
                kind: MismatchKind::MissingInInput,
                detail: format!("{field} environment present in baseline but not in input"),
            }),
        }
    }
    for (i_env, _) in input {
        if !baseline.iter().any(|(be, _)| *be == *i_env) {
            let mut path = base_path.to_vec();
            path.push(PathSegment::Field(field));
            r.structural_mismatches.push(StructuralMismatch {
                path,
                kind: MismatchKind::UnexpectedInInput,
                detail: format!("{field} environment present in input but not in baseline"),
            });
        }
    }
}

/// Push a measurement-list comparison under a named field segment.
fn meas_list(
    base_path: &[PathSegment],
    field: &'static str,
    baseline: &[MeasurementMap],
    input: &[MeasurementMap],
    r: &mut ConformanceReport,
) {
    let mut p = base_path.to_vec();
    p.push(PathSegment::Field(field));
    compare_measurements(&p, baseline, input, r);
}

/// Structural comparison of identity/key/domain-bearing triples whose
/// content is binary-compared per the spec. Paired by position; any
/// difference is a structural mismatch.
fn compare_opaque_triples<T: PartialEq>(
    kind: &'static str,
    base_path: &[PathSegment],
    baseline: Option<&[T]>,
    input: Option<&[T]>,
    r: &mut ConformanceReport,
) {
    let b = baseline.unwrap_or(&[]);
    let i = input.unwrap_or(&[]);
    let n = b.len().max(i.len());
    for index in 0..n {
        let mut path = base_path.to_vec();
        path.push(PathSegment::Triple { kind, index });
        match (b.get(index), i.get(index)) {
            (Some(x), Some(y)) if x != y => r.structural_mismatches.push(StructuralMismatch {
                path,
                kind: MismatchKind::TypeMismatch {
                    baseline: "triple".into(),
                    input: "triple".into(),
                },
                detail: format!("{kind} triple content differs from baseline"),
            }),
            (Some(_), None) => r.structural_mismatches.push(StructuralMismatch {
                path,
                kind: MismatchKind::MissingInInput,
                detail: format!("{kind} triple present in baseline but not in input"),
            }),
            (None, Some(_)) => r.structural_mismatches.push(StructuralMismatch {
                path,
                kind: MismatchKind::UnexpectedInInput,
                detail: format!("{kind} triple present in input but not in baseline"),
            }),
            _ => {}
        }
    }
}

fn push_authority_mismatch(path: &[PathSegment], r: &mut ConformanceReport) {
    let mut p = path.to_vec();
    p.push(PathSegment::Field("authorized-by"));
    r.structural_mismatches.push(StructuralMismatch {
        path: p,
        kind: MismatchKind::TypeMismatch {
            baseline: "authority".into(),
            input: "authority".into(),
        },
        detail: "authorized-by keys differ (binary comparison, §8.2.4.4.2)".into(),
    });
}

type EnvMeas<'a> = Vec<(
    &'a crate::types::environment::EnvironmentMap,
    &'a [MeasurementMap],
)>;

fn refs_as_pairs(v: &[crate::types::triples::ReferenceTriple]) -> EnvMeas<'_> {
    v.iter().map(|t| (&t.0, t.1.as_slice())).collect()
}
fn endorsed_as_pairs(v: &[crate::types::triples::EndorsedTriple]) -> EnvMeas<'_> {
    v.iter().map(|t| (&t.0, t.1.as_slice())).collect()
}

/// Compare two lists of `[environment, measurements]` triples of one
/// kind, pairing triples by environment (binary equality, §8.2.4.4.1).
fn compare_measurement_triples(
    base_path: &[PathSegment],
    kind: &'static str,
    baseline: Option<EnvMeas<'_>>,
    input: Option<EnvMeas<'_>>,
    r: &mut ConformanceReport,
) {
    let baseline = baseline.unwrap_or_default();
    let input = input.unwrap_or_default();

    for (index, (b_env, b_meas)) in baseline.iter().enumerate() {
        let mut path = base_path.to_vec();
        path.push(PathSegment::Triple { kind, index });
        match input.iter().find(|(ie, _)| *ie == *b_env) {
            Some((_, i_meas)) => compare_measurements(&path, b_meas, i_meas, r),
            None => r.structural_mismatches.push(StructuralMismatch {
                path,
                kind: MismatchKind::MissingInInput,
                detail: format!("{kind} triple environment present in baseline but not in input"),
            }),
        }
    }
    for (in_index, (i_env, _)) in input.iter().enumerate() {
        if !baseline.iter().any(|(be, _)| *be == *i_env) {
            let mut path = base_path.to_vec();
            path.push(PathSegment::Triple {
                kind,
                index: in_index,
            });
            r.structural_mismatches.push(StructuralMismatch {
                path,
                kind: MismatchKind::UnexpectedInInput,
                detail: format!("{kind} triple environment present in input but not in baseline"),
            });
        }
    }
}

/// Pair measurements by `mkey` (unkeyed → by index); compare mval.
fn compare_measurements(
    base_path: &[PathSegment],
    baseline: &[MeasurementMap],
    input: &[MeasurementMap],
    r: &mut ConformanceReport,
) {
    for (idx, b) in baseline.iter().enumerate() {
        let key = mkey_string(b, idx);
        let mut path = base_path.to_vec();
        path.push(PathSegment::Measurement(key));
        // Match by mkey when keyed, else by position.
        let matched = if b.mkey.is_some() {
            input.iter().find(|i| i.mkey == b.mkey)
        } else {
            input.get(idx).filter(|i| i.mkey.is_none())
        };
        match matched {
            Some(i) => {
                // `authorized-by` (the measurement's authority keys) is part
                // of the structural identity (§8.2.4.4.2), not a value.
                if b.authorized_by != i.authorized_by {
                    push_authority_mismatch(&path, r);
                }
                compare_mval(&path, &b.mval, &i.mval, r);
            }
            None => r.structural_mismatches.push(StructuralMismatch {
                path,
                kind: MismatchKind::MissingInInput,
                detail: "measurement present in baseline but not in input".into(),
            }),
        }
    }
    for (idx, i) in input.iter().enumerate() {
        let present = if i.mkey.is_some() {
            baseline.iter().any(|b| b.mkey == i.mkey)
        } else {
            baseline.get(idx).is_some_and(|b| b.mkey.is_none())
        };
        if !present {
            let mut path = base_path.to_vec();
            path.push(PathSegment::Measurement(mkey_string(i, idx)));
            r.structural_mismatches.push(StructuralMismatch {
                path,
                kind: MismatchKind::UnexpectedInInput,
                detail: "measurement present in input but not in baseline".into(),
            });
        }
    }
}

fn mkey_string(m: &MeasurementMap, index: usize) -> String {
    match &m.mkey {
        Some(k) => match to_value(k) {
            Ok(Value::Text(t)) => t,
            Ok(Value::Integer(n)) => n.to_string(),
            Ok(Value::Bytes(b)) => hex(&b),
            _ => format!("#{index}"),
        },
        None => format!("#{index}"),
    }
}

// ---------------------------------------------------------------------------
// measurement-values-map comparison
// ---------------------------------------------------------------------------

fn compare_mval(
    path: &[PathSegment],
    b: &MeasurementValuesMap,
    i: &MeasurementValuesMap,
    r: &mut ConformanceReport,
) {
    // digests (structure = algorithms/count; value = bytes).
    compare_digests(path, b.digests.as_deref(), i.digests.as_deref(), r);
    // svn (structure = exact vs min; value = the number).
    compare_svn(path, b.svn.as_ref(), i.svn.as_ref(), r);
    // raw-value (structure = bytes vs masked; value = the bytes/mask).
    compare_raw_value(path, b.raw_value.as_ref(), i.raw_value.as_ref(), r);
    // flags (structure = which keys present; value = booleans).
    compare_flags(path, b.flags.as_ref(), i.flags.as_ref(), r);

    // Simple scalar attributes: presence = structure, payload = value.
    scalar(path, "version", opt_val(&b.version), opt_val(&i.version), r);
    scalar(
        path,
        "serial-number",
        opt_val(&b.serial_number),
        opt_val(&i.serial_number),
        r,
    );
    scalar(path, "name", opt_val(&b.name), opt_val(&i.name), r);
    scalar(
        path,
        "ueid",
        b.ueid.as_ref().map(|v| Value::Bytes(v.clone())),
        i.ueid.as_ref().map(|v| Value::Bytes(v.clone())),
        r,
    );
    scalar(
        path,
        "uuid",
        b.uuid.as_ref().map(|v| Value::Bytes(v.clone())),
        i.uuid.as_ref().map(|v| Value::Bytes(v.clone())),
        r,
    );
    scalar(
        path,
        "mac-addr",
        opt_val(&b.mac_addr),
        opt_val(&i.mac_addr),
        r,
    );
    scalar(path, "ip-addr", opt_val(&b.ip_addr), opt_val(&i.ip_addr), r);

    // Coarse (refined in a later commit): presence = structure, whole-field
    // inequality = value difference. Never a false structural failure.
    scalar(
        path,
        "cryptokeys",
        opt_val(&b.cryptokeys),
        opt_val(&i.cryptokeys),
        r,
    );
    scalar(
        path,
        "integrity-registers",
        opt_val(&b.integrity_registers),
        opt_val(&i.integrity_registers),
        r,
    );
    scalar(
        path,
        "int-range",
        opt_val(&b.int_range),
        opt_val(&i.int_range),
        r,
    );

    // Profile-defined extension attributes: key presence = structure,
    // value = value difference.
    compare_extra_entries(path, &b.extra_entries, &i.extra_entries, r);
}

fn compare_digests(
    path: &[PathSegment],
    baseline: Option<&[Digest]>,
    input: Option<&[Digest]>,
    r: &mut ConformanceReport,
) {
    match (baseline, input) {
        (None, None) => {}
        (Some(_), None) => push_missing_field(path, "digests", r),
        (None, Some(_)) => push_unexpected_field(path, "digests", r),
        (Some(b), Some(i)) => {
            // Pair by algorithm (§8.2.4.4.5.4).
            for (slot, bd) in b.iter().enumerate() {
                let mut p = path.to_vec();
                p.push(PathSegment::Field("digests"));
                p.push(PathSegment::Index(slot));
                match i.iter().find(|id| id.0 == bd.0) {
                    Some(id) if id.1 != bd.1 => r.value_differences.push(ValueDifference {
                        path: p,
                        field: "digest-value",
                        baseline: Value::Bytes(bd.1.clone()),
                        input: Value::Bytes(id.1.clone()),
                    }),
                    Some(_) => {}
                    None => r.structural_mismatches.push(StructuralMismatch {
                        path: p,
                        kind: MismatchKind::MissingInInput,
                        detail: format!(
                            "digest algorithm {:?} present in baseline but not in input",
                            bd.0
                        ),
                    }),
                }
            }
            for id in i {
                if !b.iter().any(|bd| bd.0 == id.0) {
                    let mut p = path.to_vec();
                    p.push(PathSegment::Field("digests"));
                    r.structural_mismatches.push(StructuralMismatch {
                        path: p,
                        kind: MismatchKind::UnexpectedInInput,
                        detail: format!(
                            "digest algorithm {:?} present in input but not in baseline",
                            id.0
                        ),
                    });
                }
            }
        }
    }
}

fn compare_svn(
    path: &[PathSegment],
    baseline: Option<&SvnChoice>,
    input: Option<&SvnChoice>,
    r: &mut ConformanceReport,
) {
    match (baseline, input) {
        (None, None) => {}
        (Some(_), None) => push_missing_field(path, "svn", r),
        (None, Some(_)) => push_unexpected_field(path, "svn", r),
        (Some(b), Some(i)) => {
            let mut p = path.to_vec();
            p.push(PathSegment::Field("svn"));
            match (b, i) {
                (SvnChoice::ExactValue(x), SvnChoice::ExactValue(y))
                | (SvnChoice::MinValue(x), SvnChoice::MinValue(y)) => {
                    if x != y {
                        r.value_differences.push(ValueDifference {
                            path: p,
                            field: "svn",
                            baseline: Value::Integer(i128::from(*x)),
                            input: Value::Integer(i128::from(*y)),
                        });
                    }
                }
                _ => r.structural_mismatches.push(StructuralMismatch {
                    path: p,
                    kind: MismatchKind::TypeMismatch {
                        baseline: svn_kind(b).into(),
                        input: svn_kind(i).into(),
                    },
                    detail: "svn type discriminant differs (exact vs minimum)".into(),
                }),
            }
        }
    }
}

fn svn_kind(s: &SvnChoice) -> &'static str {
    match s {
        SvnChoice::ExactValue(_) => "exact-svn",
        SvnChoice::MinValue(_) => "min-svn",
    }
}

fn compare_raw_value(
    path: &[PathSegment],
    baseline: Option<&RawValueChoice>,
    input: Option<&RawValueChoice>,
    r: &mut ConformanceReport,
) {
    match (baseline, input) {
        (None, None) => {}
        (Some(_), None) => push_missing_field(path, "raw-value", r),
        (None, Some(_)) => push_unexpected_field(path, "raw-value", r),
        (Some(b), Some(i)) => {
            let mut p = path.to_vec();
            p.push(PathSegment::Field("raw-value"));
            match (b, i) {
                (RawValueChoice::Bytes(x), RawValueChoice::Bytes(y)) => {
                    if x != y {
                        r.value_differences.push(ValueDifference {
                            path: p,
                            field: "raw-value",
                            baseline: Value::Bytes(x.clone()),
                            input: Value::Bytes(y.clone()),
                        });
                    }
                }
                (
                    RawValueChoice::Masked {
                        value: xv,
                        mask: xm,
                    },
                    RawValueChoice::Masked {
                        value: yv,
                        mask: ym,
                    },
                ) => {
                    if xv != yv || xm != ym {
                        r.value_differences.push(ValueDifference {
                            path: p,
                            field: "raw-value",
                            baseline: Value::Array(alloc::vec![
                                Value::Bytes(xv.clone()),
                                Value::Bytes(xm.clone())
                            ]),
                            input: Value::Array(alloc::vec![
                                Value::Bytes(yv.clone()),
                                Value::Bytes(ym.clone())
                            ]),
                        });
                    }
                }
                _ => r.structural_mismatches.push(StructuralMismatch {
                    path: p,
                    kind: MismatchKind::TypeMismatch {
                        baseline: "bytes-or-masked".into(),
                        input: "bytes-or-masked".into(),
                    },
                    detail: "raw-value type discriminant differs (bytes vs masked)".into(),
                }),
            }
        }
    }
}

fn compare_flags(
    path: &[PathSegment],
    baseline: Option<&FlagsMap>,
    input: Option<&FlagsMap>,
    r: &mut ConformanceReport,
) {
    match (baseline, input) {
        (None, None) => {}
        (Some(_), None) => push_missing_field(path, "flags", r),
        (None, Some(_)) => push_unexpected_field(path, "flags", r),
        (Some(b), Some(i)) => {
            let mut p = path.to_vec();
            p.push(PathSegment::Field("flags"));
            let each: [(&'static str, Option<bool>, Option<bool>); 11] = [
                ("is-configured", b.is_configured, i.is_configured),
                ("is-secure", b.is_secure, i.is_secure),
                ("is-recovery", b.is_recovery, i.is_recovery),
                ("is-debug", b.is_debug, i.is_debug),
                (
                    "is-replay-protected",
                    b.is_replay_protected,
                    i.is_replay_protected,
                ),
                (
                    "is-integrity-protected",
                    b.is_integrity_protected,
                    i.is_integrity_protected,
                ),
                ("is-runtime-meas", b.is_runtime_meas, i.is_runtime_meas),
                ("is-immutable", b.is_immutable, i.is_immutable),
                ("is-tcb", b.is_tcb, i.is_tcb),
                (
                    "is-confidentiality-protected",
                    b.is_confidentiality_protected,
                    i.is_confidentiality_protected,
                ),
                (
                    "is-runtime-updatable",
                    b.is_runtime_updatable,
                    i.is_runtime_updatable,
                ),
            ];
            for (name, bv, iv) in each {
                let mut fp = p.clone();
                fp.push(PathSegment::Field(name));
                match (bv, iv) {
                    (None, None) => {}
                    (Some(_), None) => r.structural_mismatches.push(StructuralMismatch {
                        path: fp,
                        kind: MismatchKind::MissingInInput,
                        detail: format!("flag {name} present in baseline but not in input"),
                    }),
                    (None, Some(_)) => r.structural_mismatches.push(StructuralMismatch {
                        path: fp,
                        kind: MismatchKind::UnexpectedInInput,
                        detail: format!("flag {name} present in input but not in baseline"),
                    }),
                    (Some(x), Some(y)) => {
                        if x != y {
                            r.value_differences.push(ValueDifference {
                                path: fp,
                                field: "flag",
                                baseline: Value::Bool(x),
                                input: Value::Bool(y),
                            });
                        }
                    }
                }
            }
        }
    }
}

fn compare_extra_entries(
    path: &[PathSegment],
    baseline: &BTreeMap<i64, Value>,
    input: &BTreeMap<i64, Value>,
    r: &mut ConformanceReport,
) {
    for (k, bv) in baseline {
        let mut p = path.to_vec();
        p.push(PathSegment::Field("mval-extension"));
        p.push(PathSegment::MapKey(*k));
        match input.get(k) {
            Some(iv) if iv != bv => r.value_differences.push(ValueDifference {
                path: p,
                field: "mval-extension",
                baseline: bv.clone(),
                input: iv.clone(),
            }),
            Some(_) => {}
            None => r.structural_mismatches.push(StructuralMismatch {
                path: p,
                kind: MismatchKind::MissingInInput,
                detail: format!("mval extension key {k} present in baseline but not in input"),
            }),
        }
    }
    for k in input.keys() {
        if !baseline.contains_key(k) {
            let mut p = path.to_vec();
            p.push(PathSegment::Field("mval-extension"));
            p.push(PathSegment::MapKey(*k));
            r.structural_mismatches.push(StructuralMismatch {
                path: p,
                kind: MismatchKind::UnexpectedInInput,
                detail: format!("mval extension key {k} present in input but not in baseline"),
            });
        }
    }
}

// ---------------------------------------------------------------------------
// small helpers
// ---------------------------------------------------------------------------

/// Compare an optional scalar attribute: presence is structural, payload
/// is a value difference.
fn scalar(
    path: &[PathSegment],
    field: &'static str,
    baseline: Option<Value>,
    input: Option<Value>,
    r: &mut ConformanceReport,
) {
    match (baseline, input) {
        (None, None) => {}
        (Some(_), None) => push_missing_field(path, field, r),
        (None, Some(_)) => push_unexpected_field(path, field, r),
        (Some(b), Some(i)) => {
            if b != i {
                let mut p = path.to_vec();
                p.push(PathSegment::Field(field));
                r.value_differences.push(ValueDifference {
                    path: p,
                    field,
                    baseline: b,
                    input: i,
                });
            }
        }
    }
}

/// corim-level presence/value helper: structural presence vs value.
fn compare_opt_value(
    path: &[PathSegment],
    field: &'static str,
    baseline: Option<Value>,
    input: Option<Value>,
    r: &mut ConformanceReport,
    structural: bool,
) {
    match (baseline, input) {
        (None, None) => {}
        (Some(_), None) if structural => push_missing_field_at(path, field, r),
        (None, Some(_)) if structural => push_unexpected_field_at(path, field, r),
        // A structural field present in both but with a different value
        // (e.g. `profile`) means the documents follow different structures;
        // report it as a structural mismatch, not an informational value diff.
        (Some(b), Some(i)) if structural && b != i => {
            r.structural_mismatches.push(StructuralMismatch {
                path: path.to_vec(),
                kind: MismatchKind::TypeMismatch {
                    baseline: describe_value(&b),
                    input: describe_value(&i),
                },
                detail: format!("{field} differs; the documents follow different structures"),
            })
        }
        (Some(b), Some(i)) if b != i => r.value_differences.push(ValueDifference {
            path: path.to_vec(),
            field,
            baseline: b,
            input: i,
        }),
        // Non-structural presence change (id/validity may be absent):
        // report as a value difference against Null.
        (b, i) if b != i => r.value_differences.push(ValueDifference {
            path: path.to_vec(),
            field,
            baseline: b.unwrap_or(Value::Null),
            input: i.unwrap_or(Value::Null),
        }),
        _ => {}
    }
}

fn push_missing_field(path: &[PathSegment], field: &'static str, r: &mut ConformanceReport) {
    let mut p = path.to_vec();
    p.push(PathSegment::Field(field));
    push_missing_field_at(&p, field, r);
}
fn push_unexpected_field(path: &[PathSegment], field: &'static str, r: &mut ConformanceReport) {
    let mut p = path.to_vec();
    p.push(PathSegment::Field(field));
    push_unexpected_field_at(&p, field, r);
}
fn push_missing_field_at(path: &[PathSegment], field: &str, r: &mut ConformanceReport) {
    r.structural_mismatches.push(StructuralMismatch {
        path: path.to_vec(),
        kind: MismatchKind::MissingInInput,
        detail: format!("{field} present in baseline but missing in input"),
    });
}
fn push_unexpected_field_at(path: &[PathSegment], field: &str, r: &mut ConformanceReport) {
    r.structural_mismatches.push(StructuralMismatch {
        path: path.to_vec(),
        kind: MismatchKind::UnexpectedInInput,
        detail: format!("{field} present in input but not in baseline"),
    });
}

fn opt_val<T: serde::Serialize>(v: &Option<T>) -> Option<Value> {
    v.as_ref().map(to_value_lossy)
}
fn to_value_lossy<T: serde::Serialize>(v: &T) -> Value {
    to_value(v).unwrap_or(Value::Null)
}

fn hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

/// A short, human-readable description of a CBOR value for mismatch detail
/// strings (not a canonical encoding).
fn describe_value(v: &Value) -> String {
    match v {
        Value::Text(t) => t.clone(),
        Value::Bytes(b) => hex(b),
        Value::Integer(n) => n.to_string(),
        Value::Tag(t, inner) => format!("#6.{t}({})", describe_value(inner)),
        other => format!("{other:?}"),
    }
}
