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
//! Typed identities pair one-to-one, reserving exact matches before pairing
//! remaining entries in encounter order. Unknown extensions compare recursive
//! CBOR shape: keys, types, tags and container structure are structural;
//! leaf contents are values. Maps are unordered and arrays positional.
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
use crate::types::signed::{ClaimKey, CoseCertHash, CoseX509, CwtClaims, ProtectedCorimHeaderMap};

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
    /// A text map key (e.g. a text-keyed CWT claim such as `"svn"`).
    TextKey(String),
    /// A CBOR map key outside the integer/text label namespaces.
    ValueKey(String),
    /// A semantic CBOR tag surrounding a nested value (RFC 8949 Section 3.4).
    Tag(u64),
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
            PathSegment::TextKey(k) => {
                s.push_str(&format!("[\"{}\"]", crate::cbor::value::escape_text(k)))
            }
            PathSegment::ValueKey(key) => {
                s.push_str(&format!("[cbor:{}]", crate::cbor::value::escape_text(key)))
            }
            PathSegment::Tag(tag) => s.push_str(&format!(".#6.{tag}")),
        }
    }
    s
}

// ---------------------------------------------------------------------------
// Comparison entry point
// ---------------------------------------------------------------------------

/// Compare two CoRIM maps, rejecting invalid or unsupported input.
///
/// Both inputs must be structurally valid CoMID-only documents, including
/// supported TCG bare-bstr forms (draft-ietf-rats-corim-11 Section 4.1).
/// Embedded tags use exact decoding and shared default per-document resource
/// limits (RFC 8949 Sections 3 and 10). Serialization, decoding and structural
/// failures return an error rather than an incomplete conformance report.
///
/// Entries are paired one-to-one using typed identities. Unknown extensions
/// use recursive CBOR shape comparison. This does not check the clock,
/// registered profiles, signatures or certificate trust.
/// Callers must apply those checks separately when required.
pub fn compare(
    input: &CorimMap,
    baseline: &CorimMap,
) -> Result<ConformanceReport, crate::ValidationError> {
    let input_comids = checked_comids(input)?;
    let base_comids = checked_comids(baseline)?;
    compare_decoded(input, baseline, &input_comids, &base_comids)
}

fn checked_comids(corim: &CorimMap) -> Result<Vec<(String, ComidTag)>, crate::ValidationError> {
    if corim.tags.iter().any(|tag| {
        !matches!(
            tag,
            ConciseTagChoice::Comid(_) | ConciseTagChoice::BareBstr(_)
        )
    }) {
        return Err(crate::ValidationError::Invalid(
            "unsupported payload for baseline comparison: only CoMID tags are supported".into(),
        ));
    }
    let bytes = crate::cbor::encode(corim)
        .map_err(|error| crate::ValidationError::Invalid(error.to_string()))?;
    let validated = crate::validate::decode_and_validate_structure_with_limits(
        &bytes,
        &crate::cbor::DecodeLimits::default(),
    )?;
    let mut comids = Vec::with_capacity(validated.comids.len());
    for (index, comid) in validated.comids.into_iter().enumerate() {
        comids.push((tag_id_string(&comid, index), comid));
    }
    Ok(comids)
}

fn compare_decoded(
    input: &CorimMap,
    baseline: &CorimMap,
    input_comids: &[(String, ComidTag)],
    base_comids: &[(String, ComidTag)],
) -> Result<ConformanceReport, crate::ValidationError> {
    let mut r = ConformanceReport::default();

    // --- corim-level: profile is structural; the rest are values.
    compare_leaf(
        &[],
        "profile",
        opt_val(&baseline.profile)?,
        opt_val(&input.profile)?,
        &mut r,
        /*structural=*/ true,
    );
    compare_leaf(
        &[],
        "corim-id",
        Some(checked_value(&baseline.id)?),
        Some(checked_value(&input.id)?),
        &mut r,
        false,
    );
    compare_leaf(
        &[],
        "rim-validity",
        opt_val(&baseline.rim_validity)?,
        opt_val(&input.rim_validity)?,
        &mut r,
        false,
    );
    compare_leaf(
        &[],
        "entities",
        opt_val(&baseline.entities)?,
        opt_val(&input.entities)?,
        &mut r,
        false,
    );
    compare_leaf(
        &[],
        "dependent-rims",
        opt_val(&baseline.dependent_rims)?,
        opt_val(&input.dependent_rims)?,
        &mut r,
        false,
    );

    compare_comids(base_comids, input_comids, &mut r)?;

    Ok(r)
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
/// name/uri, signature-validity, CWT `sub`/`exp`/`nbf`, certificate/key bytes,
/// and `payload-location` is reported as a value difference. Unknown header
/// and CWT extensions compare recursively by CBOR shape.
/// Encoding or conversion failures return an error; signatures are not verified.
///
/// Findings are located under `$.protected-header`.
pub fn compare_headers(
    input: &ProtectedCorimHeaderMap,
    baseline: &ProtectedCorimHeaderMap,
) -> Result<ConformanceReport, crate::ValidationError> {
    checked_value(input)?;
    checked_value(baseline)?;
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
    compare_leaf(
        &base,
        "content-type",
        opt_val(&baseline.content_type)?,
        opt_val(&input.content_type)?,
        &mut r,
        true,
    );
    compare_leaf(
        &base,
        "payload-hash-alg",
        opt_int(baseline.payload_hash_alg),
        opt_int(input.payload_hash_alg),
        &mut r,
        true,
    );
    compare_leaf(
        &base,
        "payload-preimage-content-type",
        opt_val(&baseline.payload_preimage_content_type)?,
        opt_val(&input.payload_preimage_content_type)?,
        &mut r,
        true,
    );
    // payload-location — value.
    compare_leaf(
        &base,
        "payload-location",
        opt_val(&baseline.payload_location)?,
        opt_val(&input.payload_location)?,
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
        compare_corim_meta(&base, b, i, &mut r)?;
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
        compare_cwt_claims(&base, b, i, &mut r)?;
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

    compare_extra_values(
        &base,
        "header-extension",
        &baseline.extra,
        &input.extra,
        &mut r,
        |k| PathSegment::MapKey(*k),
    );

    Ok(r)
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
) -> Result<(), crate::ValidationError> {
    let mut p = base.to_vec();
    p.push(PathSegment::Field("corim-meta"));
    compare_leaf(
        &p,
        "signer-name",
        Some(Value::Text(baseline.signer.signer_name.clone())),
        Some(Value::Text(input.signer.signer_name.clone())),
        r,
        false,
    );
    compare_leaf(
        &p,
        "signer-uri",
        opt_val(&baseline.signer.signer_uri)?,
        opt_val(&input.signer.signer_uri)?,
        r,
        false,
    );
    compare_leaf(
        &p,
        "signature-validity",
        opt_val(&baseline.signature_validity)?,
        opt_val(&input.signature_validity)?,
        r,
        false,
    );
    Ok(())
}

fn compare_cwt_claims(
    base: &[PathSegment],
    baseline: &CwtClaims,
    input: &CwtClaims,
    r: &mut ConformanceReport,
) -> Result<(), crate::ValidationError> {
    let mut p = base.to_vec();
    p.push(PathSegment::Field("cwt-claims"));
    // `iss` (the signer identity) is structural.
    compare_leaf(
        &p,
        "iss",
        Some(Value::Text(baseline.iss.clone())),
        Some(Value::Text(input.iss.clone())),
        r,
        true,
    );
    compare_leaf(
        &p,
        "sub",
        opt_val(&baseline.sub)?,
        opt_val(&input.sub)?,
        r,
        false,
    );
    compare_leaf(
        &p,
        "exp",
        opt_int(baseline.exp),
        opt_int(input.exp),
        r,
        false,
    );
    compare_leaf(
        &p,
        "nbf",
        opt_int(baseline.nbf),
        opt_int(input.nbf),
        r,
        false,
    );
    compare_extra_values(
        &p,
        "cwt-extension",
        &baseline.extra,
        &input.extra,
        r,
        |k| match k {
            ClaimKey::Int(n) => PathSegment::MapKey(*n),
            ClaimKey::Text(t) => PathSegment::TextKey(t.clone()),
        },
    );
    Ok(())
}

/// Compare extension presence and recursive CBOR shape; `seg` renders a key.
fn compare_extra_values<K: Ord>(
    base: &[PathSegment],
    field: &'static str,
    baseline: &BTreeMap<K, Value>,
    input: &BTreeMap<K, Value>,
    r: &mut ConformanceReport,
    seg: impl Fn(&K) -> PathSegment,
) {
    for (k, bv) in baseline {
        let mut p = base.to_vec();
        p.push(PathSegment::Field(field));
        p.push(seg(k));
        match input.get(k) {
            Some(value) => compare_value_shape(&p, field, bv, value, r),
            None => push_missing_field_at(&p, field, r),
        }
    }
    for k in input.keys() {
        if !baseline.contains_key(k) {
            let mut p = base.to_vec();
            p.push(PathSegment::Field(field));
            p.push(seg(k));
            push_unexpected_field_at(&p, field, r);
        }
    }
}

fn opt_int(v: Option<i64>) -> Option<Value> {
    v.map(|n| Value::Integer(i128::from(n)))
}

fn tag_id_string(comid: &ComidTag, _index: usize) -> String {
    match &comid.tag_identity.tag_id {
        crate::types::common::TagIdChoice::Text(text) => text.clone(),
        crate::types::common::TagIdChoice::Uuid(bytes) => format!("uuid:{}", hex(bytes)),
    }
}

fn pair_indices<T: PartialEq>(
    baseline: &[T],
    input: &[T],
    same_key: impl Fn(usize, usize) -> bool,
) -> Vec<Option<usize>> {
    let result: Result<_, core::convert::Infallible> =
        pair_indices_by(baseline, input, same_key, |base, candidate| {
            Ok(base == candidate)
        });
    match result {
        Ok(pairs) => pairs,
        Err(never) => match never {},
    }
}

fn pair_indices_by<T, Error>(
    baseline: &[T],
    input: &[T],
    same_key: impl Fn(usize, usize) -> bool,
    exact_equal: impl Fn(&T, &T) -> Result<bool, Error>,
) -> Result<Vec<Option<usize>>, Error> {
    let mut pairs = alloc::vec![None; baseline.len()];
    let mut used = alloc::vec![false; input.len()];
    for exact in [true, false] {
        for (base_index, baseline_entry) in baseline.iter().enumerate() {
            if pairs[base_index].is_some() {
                continue;
            }
            for (index, entry) in input.iter().enumerate() {
                if !used[index]
                    && same_key(base_index, index)
                    && (!exact || exact_equal(baseline_entry, entry)?)
                {
                    pairs[base_index] = Some(index);
                    used[index] = true;
                    break;
                }
            }
        }
    }
    Ok(pairs)
}

fn exact_comparison(
    compare: impl FnOnce(&mut ConformanceReport) -> Result<(), crate::ValidationError>,
) -> Result<bool, crate::ValidationError> {
    let mut report = ConformanceReport::default();
    compare(&mut report)?;
    Ok(report.structural_mismatches.is_empty() && report.value_differences.is_empty())
}

fn compare_comids(
    baseline: &[(String, ComidTag)],
    input: &[(String, ComidTag)],
    r: &mut ConformanceReport,
) -> Result<(), crate::ValidationError> {
    let pairs = pair_indices_by(
        baseline,
        input,
        |base_index, input_index| {
            baseline[base_index].1.tag_identity.tag_id == input[input_index].1.tag_identity.tag_id
        },
        |base, candidate| {
            exact_comparison(|report| {
                compare_comid_metadata(&[], &base.1, &candidate.1, report)?;
                compare_triples(&[], &base.1.triples, &candidate.1.triples, report)
            })
        },
    )?;
    for (base_index, (id, b_comid)) in baseline.iter().enumerate() {
        match pairs[base_index].map(|index| &input[index]) {
            Some((_, i_comid)) => {
                let path = [PathSegment::Comid(id.clone())];
                compare_comid_metadata(&path, b_comid, i_comid, r)?;
                compare_triples(&path, &b_comid.triples, &i_comid.triples, r)?;
            }
            None => r.structural_mismatches.push(StructuralMismatch {
                path: alloc::vec![PathSegment::Comid(id.clone())],
                kind: MismatchKind::MissingInInput,
                detail: "CoMID present in baseline but missing in input".into(),
            }),
        }
    }
    for (index, (id, _)) in input.iter().enumerate() {
        if !pairs.contains(&Some(index)) {
            r.structural_mismatches.push(StructuralMismatch {
                path: alloc::vec![PathSegment::Comid(id.clone())],
                kind: MismatchKind::UnexpectedInInput,
                detail: "CoMID present in input but not in baseline".into(),
            });
        }
    }
    Ok(())
}

/// Compare a CoMID's non-triple metadata. These fields legitimately change
/// when a document is re-issued (`tag-version` is bumped on every re-issue),
/// so they are reported as value differences, not structural mismatches.
fn compare_comid_metadata(
    path: &[PathSegment],
    baseline: &ComidTag,
    input: &ComidTag,
    r: &mut ConformanceReport,
) -> Result<(), crate::ValidationError> {
    compare_leaf(
        path,
        "tag-version",
        baseline.tag_identity.tag_version.map(u64_value),
        input.tag_identity.tag_version.map(u64_value),
        r,
        false,
    );
    compare_leaf(
        path,
        "language",
        opt_val(&baseline.language)?,
        opt_val(&input.language)?,
        r,
        false,
    );
    compare_leaf(
        path,
        "entities",
        opt_val(&baseline.entities)?,
        opt_val(&input.entities)?,
        r,
        false,
    );
    compare_leaf(
        path,
        "linked-tags",
        opt_val(&baseline.linked_tags)?,
        opt_val(&input.linked_tags)?,
        r,
        false,
    );
    Ok(())
}

fn u64_value(v: u64) -> Value {
    Value::Integer(i128::from(v))
}

// ---------------------------------------------------------------------------
// Triples (commit 1: reference + endorsed; both are [env, [+ measurement]])
// ---------------------------------------------------------------------------

fn compare_triples(
    base_path: &[PathSegment],
    baseline: &crate::types::triples::TriplesMap,
    input: &crate::types::triples::TriplesMap,
    r: &mut ConformanceReport,
) -> Result<(), crate::ValidationError> {
    compare_measurement_triples(
        base_path,
        "reference",
        baseline.reference_triples.as_deref().map(refs_as_pairs),
        input.reference_triples.as_deref().map(refs_as_pairs),
        r,
    )?;
    compare_measurement_triples(
        base_path,
        "endorsed",
        baseline.endorsed_triples.as_deref().map(endorsed_as_pairs),
        input.endorsed_triples.as_deref().map(endorsed_as_pairs),
        r,
    )?;
    compare_ces(
        base_path,
        baseline.conditional_endorsement_series.as_deref(),
        input.conditional_endorsement_series.as_deref(),
        r,
    )?;
    compare_ce(
        base_path,
        baseline.conditional_endorsement.as_deref(),
        input.conditional_endorsement.as_deref(),
        r,
    )?;
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
    Ok(())
}

/// Compare conditional-endorsement-series triples, paired by their
/// common-condition environment. Claims-list and each series record's
/// condition/addition measurement lists are compared like measurements.
fn compare_ces(
    base_path: &[PathSegment],
    baseline: Option<&[crate::types::triples::ConditionalEndorsementSeriesTriple]>,
    input: Option<&[crate::types::triples::ConditionalEndorsementSeriesTriple]>,
    r: &mut ConformanceReport,
) -> Result<(), crate::ValidationError> {
    let b = baseline.unwrap_or(&[]);
    let i = input.unwrap_or(&[]);
    let kind = "conditional-endorsement-series";
    let pairs = pair_indices_by(
        b,
        i,
        |base_index, input_index| {
            b[base_index].common_condition().environment
                == i[input_index].common_condition().environment
        },
        |base, candidate| {
            exact_comparison(|report| compare_ces_entry(&[], base, candidate, report))
        },
    )?;
    for (index, bt) in b.iter().enumerate() {
        let mut path = base_path.to_vec();
        path.push(PathSegment::Triple { kind, index });
        match pairs[index].map(|input_index| &i[input_index]) {
            Some(it) => {
                compare_ces_entry(&path, bt, it, r)?;
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
    for in_index in 0..i.len() {
        if !pairs.contains(&Some(in_index)) {
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
    Ok(())
}

fn compare_ces_entry(
    path: &[PathSegment],
    baseline: &crate::types::triples::ConditionalEndorsementSeriesTriple,
    input: &crate::types::triples::ConditionalEndorsementSeriesTriple,
    report: &mut ConformanceReport,
) -> Result<(), crate::ValidationError> {
    meas_list(
        path,
        "claims-list",
        &baseline.common_condition().claims_list,
        &input.common_condition().claims_list,
        report,
    )?;
    if baseline.common_condition().authorized_by != input.common_condition().authorized_by {
        push_authority_mismatch(path, report);
    }
    compare_series(path, baseline.series(), input.series(), report)
}

/// Compare CES series records by position (order is significant — first
/// match wins, §8.2.4.3.2). A differing series length is structural.
fn compare_series(
    base_path: &[PathSegment],
    baseline: &[crate::types::triples::ConditionalSeriesRecord],
    input: &[crate::types::triples::ConditionalSeriesRecord],
    r: &mut ConformanceReport,
) -> Result<(), crate::ValidationError> {
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
                meas_list(&p, "condition", br.condition(), ir.condition(), r)?;
                meas_list(&p, "addition", br.addition(), ir.addition(), r)?;
            }
            None => r.structural_mismatches.push(StructuralMismatch {
                path: p,
                kind: MismatchKind::MissingInInput,
                detail: "CES series record present in baseline but not in input".into(),
            }),
        }
    }
    Ok(())
}

/// Compare conditional-endorsement triples by position: `conditions`
/// (stateful-environment-records, paired by environment) and
/// `endorsements` (endorsed-triple-records, paired by environment).
fn compare_ce(
    base_path: &[PathSegment],
    baseline: Option<&[crate::types::triples::ConditionalEndorsementTriple]>,
    input: Option<&[crate::types::triples::ConditionalEndorsementTriple]>,
    r: &mut ConformanceReport,
) -> Result<(), crate::ValidationError> {
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
                compare_env_meas(&path, "conditions", &bc, &ic, r)?;
                // endorsements: endorsed-triple-records, env-keyed.
                let be: EnvMeas = it_pairs(&bt.1);
                let ie: EnvMeas = it_pairs(&it.1);
                compare_env_meas(&path, "endorsements", &be, &ie, r)?;
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
    Ok(())
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
) -> Result<(), crate::ValidationError> {
    let pairs = pair_indices_by(
        baseline,
        input,
        |base_index, input_index| baseline[base_index].0 == input[input_index].0,
        |base, candidate| {
            exact_comparison(|report| compare_measurements(&[], base.1, candidate.1, report))
        },
    )?;
    for (index, (_, b_meas)) in baseline.iter().enumerate() {
        let mut path = base_path.to_vec();
        path.push(PathSegment::Field(field));
        path.push(PathSegment::Index(index));
        match pairs[index].map(|input_index| &input[input_index]) {
            Some((_, i_meas)) => compare_measurements(&path, b_meas, i_meas, r)?,
            None => r.structural_mismatches.push(StructuralMismatch {
                path,
                kind: MismatchKind::MissingInInput,
                detail: format!("{field} environment present in baseline but not in input"),
            }),
        }
    }
    for index in 0..input.len() {
        if !pairs.contains(&Some(index)) {
            let mut path = base_path.to_vec();
            path.push(PathSegment::Field(field));
            path.push(PathSegment::Index(index));
            r.structural_mismatches.push(StructuralMismatch {
                path,
                kind: MismatchKind::UnexpectedInInput,
                detail: format!("{field} environment present in input but not in baseline"),
            });
        }
    }
    Ok(())
}

/// Push a measurement-list comparison under a named field segment.
fn meas_list(
    base_path: &[PathSegment],
    field: &'static str,
    baseline: &[MeasurementMap],
    input: &[MeasurementMap],
    r: &mut ConformanceReport,
) -> Result<(), crate::ValidationError> {
    let mut p = base_path.to_vec();
    p.push(PathSegment::Field(field));
    compare_measurements(&p, baseline, input, r)?;
    Ok(())
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
) -> Result<(), crate::ValidationError> {
    let baseline = baseline.unwrap_or_default();
    let input = input.unwrap_or_default();
    let pairs = pair_indices_by(
        &baseline,
        &input,
        |base_index, input_index| baseline[base_index].0 == input[input_index].0,
        |base, candidate| {
            exact_comparison(|report| compare_measurements(&[], base.1, candidate.1, report))
        },
    )?;
    for (index, (_, b_meas)) in baseline.iter().enumerate() {
        let mut path = base_path.to_vec();
        path.push(PathSegment::Triple { kind, index });
        match pairs[index].map(|input_index| &input[input_index]) {
            Some((_, i_meas)) => compare_measurements(&path, b_meas, i_meas, r)?,
            None => r.structural_mismatches.push(StructuralMismatch {
                path,
                kind: MismatchKind::MissingInInput,
                detail: format!("{kind} triple environment present in baseline but not in input"),
            }),
        }
    }
    for in_index in 0..input.len() {
        if !pairs.contains(&Some(in_index)) {
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
    Ok(())
}

/// Pair measurements by `mkey` (unkeyed → by index); compare mval.
fn compare_measurements(
    base_path: &[PathSegment],
    baseline: &[MeasurementMap],
    input: &[MeasurementMap],
    r: &mut ConformanceReport,
) -> Result<(), crate::ValidationError> {
    let pairs = pair_indices_by(
        baseline,
        input,
        |base_index, input_index| {
            baseline[base_index].mkey == input[input_index].mkey
                && (baseline[base_index].mkey.is_some() || base_index == input_index)
        },
        |base, candidate| {
            exact_comparison(|report| compare_measurement(&[], base, candidate, report))
        },
    )?;
    for (idx, b) in baseline.iter().enumerate() {
        let key = mkey_string(b, idx);
        let mut path = base_path.to_vec();
        path.push(PathSegment::Measurement(key));
        // Match by mkey when keyed, else by position.
        let matched = pairs[idx].map(|input_index| &input[input_index]);
        match matched {
            Some(i) => {
                compare_measurement(&path, b, i, r)?;
            }
            None => r.structural_mismatches.push(StructuralMismatch {
                path,
                kind: MismatchKind::MissingInInput,
                detail: "measurement present in baseline but not in input".into(),
            }),
        }
    }
    for (idx, i) in input.iter().enumerate() {
        let present = pairs.contains(&Some(idx));
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
    Ok(())
}

fn compare_measurement(
    path: &[PathSegment],
    baseline: &MeasurementMap,
    input: &MeasurementMap,
    report: &mut ConformanceReport,
) -> Result<(), crate::ValidationError> {
    if baseline.authorized_by != input.authorized_by {
        push_authority_mismatch(path, report);
    }
    compare_mval(path, &baseline.mval, &input.mval, report)
}

fn mkey_string(m: &MeasurementMap, index: usize) -> String {
    use crate::types::common::MeasuredElement;
    match &m.mkey {
        Some(MeasuredElement::Text(text)) => text.clone(),
        Some(MeasuredElement::Uint(number)) => format!("uint:{number}"),
        Some(MeasuredElement::Uuid(bytes)) => format!("uuid:{}", hex(bytes)),
        Some(MeasuredElement::Oid(bytes)) => format!("oid:{}", hex(bytes)),
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
) -> Result<(), crate::ValidationError> {
    // digests (structure = algorithms/count; value = bytes).
    compare_digests(path, b.digests.as_deref(), i.digests.as_deref(), r);
    // svn (structure = exact vs min; value = the number).
    compare_svn(path, b.svn.as_ref(), i.svn.as_ref(), r);
    // raw-value (structure = bytes vs masked; value = the bytes/mask).
    compare_raw_value(path, b.raw_value.as_ref(), i.raw_value.as_ref(), r);
    // flags (structure = which keys present; value = booleans).
    compare_flags(path, b.flags.as_ref(), i.flags.as_ref(), r);

    // Simple scalar attributes: presence = structure, payload = value.
    scalar(
        path,
        "version",
        opt_val(&b.version)?,
        opt_val(&i.version)?,
        r,
    );
    scalar(
        path,
        "serial-number",
        opt_val(&b.serial_number)?,
        opt_val(&i.serial_number)?,
        r,
    );
    scalar(path, "name", opt_val(&b.name)?, opt_val(&i.name)?, r);
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
        opt_val(&b.mac_addr)?,
        opt_val(&i.mac_addr)?,
        r,
    );
    scalar(
        path,
        "ip-addr",
        opt_val(&b.ip_addr)?,
        opt_val(&i.ip_addr)?,
        r,
    );

    compare_keys(path, b.cryptokeys.as_deref(), i.cryptokeys.as_deref(), r)?;
    compare_registers(
        path,
        b.integrity_registers.as_ref(),
        i.integrity_registers.as_ref(),
        r,
    )?;
    shape_field(
        path,
        "int-range",
        opt_val(&b.int_range)?,
        opt_val(&i.int_range)?,
        r,
    );

    scalar(path, "bool", opt_val(&b.r#bool)?, opt_val(&i.r#bool)?, r);
    shape_field(path, "number", opt_val(&b.number)?, opt_val(&i.number)?, r);
    shape_field(path, "text", opt_val(&b.text)?, opt_val(&i.text)?, r);
    shape_field(path, "bytes", opt_val(&b.bytes)?, opt_val(&i.bytes)?, r);

    compare_extra_entries(path, &b.extra_entries, &i.extra_entries, r);
    Ok(())
}

fn compare_keys(
    path: &[PathSegment],
    baseline: Option<&[crate::types::common::CryptoKey]>,
    input: Option<&[crate::types::common::CryptoKey]>,
    report: &mut ConformanceReport,
) -> Result<(), crate::ValidationError> {
    use crate::types::common::CryptoKey;
    compare_presence(
        path,
        "cryptokeys",
        baseline.is_some(),
        input.is_some(),
        report,
    );
    if let (Some(base), Some(candidate)) = (baseline, input) {
        let pairs = pair_indices(base, candidate, |base_index, input_index| {
            match (&base[base_index], &candidate[input_index]) {
                (CryptoKey::KeyThumbprint(base), CryptoKey::KeyThumbprint(candidate))
                | (CryptoKey::CertThumbprint(base), CryptoKey::CertThumbprint(candidate))
                | (CryptoKey::CertPathThumbprint(base), CryptoKey::CertPathThumbprint(candidate)) => {
                    base.0 == candidate.0
                }
                (base, candidate) => {
                    core::mem::discriminant(base) == core::mem::discriminant(candidate)
                }
            }
        });
        for (index, key) in base.iter().enumerate() {
            let mut nested = path.to_vec();
            nested.push(PathSegment::Field("cryptokeys"));
            nested.push(PathSegment::Index(index));
            match pairs[index] {
                Some(input_index) => compare_value_shape(
                    &nested,
                    "cryptokeys",
                    &checked_value(key)?,
                    &checked_value(&candidate[input_index])?,
                    report,
                ),
                None => push_missing_field_at(&nested, "key representation or algorithm", report),
            }
        }
        for index in 0..candidate.len() {
            if !pairs.contains(&Some(index)) {
                let mut nested = path.to_vec();
                nested.push(PathSegment::Field("cryptokeys"));
                nested.push(PathSegment::Index(index));
                push_unexpected_field_at(&nested, "key representation or algorithm", report);
            }
        }
    }
    Ok(())
}

fn compare_registers(
    path: &[PathSegment],
    baseline: Option<&crate::types::measurement::IntegrityRegisters>,
    input: Option<&crate::types::measurement::IntegrityRegisters>,
    report: &mut ConformanceReport,
) -> Result<(), crate::ValidationError> {
    compare_presence(
        path,
        "integrity-registers",
        baseline.is_some(),
        input.is_some(),
        report,
    );
    if let (Some(base), Some(candidate)) = (baseline, input) {
        for (key, digests) in &base.0 {
            let mut nested = path.to_vec();
            nested.push(PathSegment::Field("integrity-registers"));
            nested.push(value_key(&checked_value(key)?));
            match candidate.0.get(key) {
                Some(input_digests) => {
                    compare_digests(&nested, Some(digests), Some(input_digests), report)
                }
                None => push_missing_field_at(&nested, "register", report),
            }
        }
        for key in candidate.0.keys() {
            if !base.0.contains_key(key) {
                let mut nested = path.to_vec();
                nested.push(PathSegment::Field("integrity-registers"));
                nested.push(value_key(&checked_value(key)?));
                push_unexpected_field_at(&nested, "register", report);
            }
        }
    }
    Ok(())
}

fn shape_field(
    path: &[PathSegment],
    field: &'static str,
    baseline: Option<Value>,
    input: Option<Value>,
    report: &mut ConformanceReport,
) {
    match (baseline, input) {
        (Some(base), Some(candidate)) => {
            let mut nested = path.to_vec();
            nested.push(PathSegment::Field(field));
            if matches!(field, "number" | "text" | "bytes") {
                if let (Value::Tag(base_tag, base_values), Value::Tag(input_tag, input_values)) =
                    (&base, &candidate)
                {
                    if *base_tag == crate::types::tags::TAG_MATCHER_SET && base_tag == input_tag {
                        if let (Value::Array(base), Value::Array(candidate)) =
                            (base_values.as_ref(), input_values.as_ref())
                        {
                            let base_identities: Vec<_> = base
                                .iter()
                                .map(|value| (value_kind(value), ValueIdentity::from(value)))
                                .collect();
                            let input_identities: Vec<_> = candidate
                                .iter()
                                .map(|value| (value_kind(value), ValueIdentity::from(value)))
                                .collect();
                            let (pairs, used) = pair_indexed(&base_identities, &input_identities);
                            for (index, value) in base.iter().enumerate() {
                                let mut element = nested.clone();
                                element.push(PathSegment::Index(index));
                                match pairs[index] {
                                    Some(input_index) => compare_value_shape(
                                        &element,
                                        field,
                                        value,
                                        &candidate[input_index],
                                        report,
                                    ),
                                    None => push_missing_field_at(&element, field, report),
                                }
                            }
                            for (index, matched) in used.iter().enumerate() {
                                if !matched {
                                    let mut element = nested.clone();
                                    element.push(PathSegment::Index(index));
                                    push_unexpected_field_at(&element, field, report);
                                }
                            }
                            return;
                        }
                    }
                }
            }
            compare_value_shape(&nested, field, &base, &candidate, report);
        }
        (Some(_), None) => push_missing_field(path, field, report),
        (None, Some(_)) => push_unexpected_field(path, field, report),
        (None, None) => {}
    }
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
            let pairs = pair_indices(b, i, |base_index, input_index| {
                b[base_index].0 == i[input_index].0
            });
            for (slot, bd) in b.iter().enumerate() {
                let mut p = path.to_vec();
                p.push(PathSegment::Field("digests"));
                p.push(PathSegment::Index(slot));
                match pairs[slot].map(|index| &i[index]) {
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
            for (index, id) in i.iter().enumerate() {
                if !pairs.contains(&Some(index)) {
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
            Some(iv) => compare_value_shape(&p, "mval-extension", bv, iv, r),
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

fn value_key(key: &Value) -> PathSegment {
    match key {
        Value::Integer(number) => i64::try_from(*number)
            .map(PathSegment::MapKey)
            .unwrap_or_else(|_| PathSegment::ValueKey(format!("integer:{number}"))),
        Value::Text(text) => PathSegment::TextKey(text.clone()),
        other => PathSegment::ValueKey(format!("{other:?}")),
    }
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum ValueIdentity<'a> {
    Integer(i128),
    Float(u64),
    Bytes(&'a [u8]),
    Text(&'a str),
    Bool(bool),
    Null,
    Array(Vec<Self>),
    Map(Vec<(Self, Self)>),
    Tag(u64, Box<Self>),
}

impl<'a> From<&'a Value> for ValueIdentity<'a> {
    fn from(value: &'a Value) -> Self {
        match value {
            Value::Integer(number) => Self::Integer(*number),
            Value::Float(number) => Self::Float(number.to_bits()),
            Value::Bytes(bytes) => Self::Bytes(bytes),
            Value::Text(text) => Self::Text(text),
            Value::Bool(value) => Self::Bool(*value),
            Value::Null => Self::Null,
            Value::Array(values) => Self::Array(values.iter().map(Self::from).collect()),
            Value::Map(entries) => {
                let mut entries: Vec<_> = entries
                    .iter()
                    .map(|(key, value)| (Self::from(key), Self::from(value)))
                    .collect();
                entries.sort_unstable();
                Self::Map(entries)
            }
            Value::Tag(tag, inner) => Self::Tag(*tag, Box::new(Self::from(inner.as_ref()))),
        }
    }
}

fn values_equal(baseline: &Value, input: &Value) -> bool {
    ValueIdentity::from(baseline) == ValueIdentity::from(input)
}

fn pair_indexed<Key: Ord, Exact: Ord>(
    baseline: &[(Key, Exact)],
    input: &[(Key, Exact)],
) -> (Vec<Option<usize>>, Vec<bool>) {
    let mut by_key: BTreeMap<_, alloc::collections::VecDeque<usize>> = BTreeMap::new();
    let mut by_entry: BTreeMap<_, alloc::collections::VecDeque<usize>> = BTreeMap::new();
    for (index, (key, value)) in input.iter().enumerate() {
        by_key.entry(key).or_default().push_back(index);
        by_entry.entry((key, value)).or_default().push_back(index);
    }
    let mut pairs = alloc::vec![None; baseline.len()];
    let mut used = alloc::vec![false; input.len()];
    for (index, (key, value)) in baseline.iter().enumerate() {
        if let Some(candidates) = by_entry.get_mut(&(key, value)) {
            if let Some(candidate) = candidates.pop_front() {
                pairs[index] = Some(candidate);
                used[candidate] = true;
            }
        }
    }
    for (index, (key, _)) in baseline.iter().enumerate() {
        if pairs[index].is_some() {
            continue;
        }
        if let Some(candidates) = by_key.get_mut(key) {
            while let Some(candidate) = candidates.pop_front() {
                if !used[candidate] {
                    pairs[index] = Some(candidate);
                    used[candidate] = true;
                    break;
                }
            }
        }
    }
    (pairs, used)
}

fn value_kind(value: &Value) -> String {
    match value {
        Value::Integer(_) => "integer".into(),
        Value::Float(_) => "float".into(),
        Value::Bytes(_) => "bytes".into(),
        Value::Text(_) => "text".into(),
        Value::Bool(_) => "bool".into(),
        Value::Null => "null".into(),
        Value::Array(_) => "array".into(),
        Value::Map(_) => "map".into(),
        Value::Tag(tag, _) => format!("tag:{tag}"),
    }
}

fn compare_value_shape(
    path: &[PathSegment],
    field: &'static str,
    baseline: &Value,
    input: &Value,
    report: &mut ConformanceReport,
) {
    match (baseline, input) {
        (Value::Map(base), Value::Map(candidate)) => {
            let base_identities: Vec<_> = base
                .iter()
                .map(|(key, value)| (ValueIdentity::from(key), ValueIdentity::from(value)))
                .collect();
            let input_identities: Vec<_> = candidate
                .iter()
                .map(|(key, value)| (ValueIdentity::from(key), ValueIdentity::from(value)))
                .collect();
            let (pairs, used) = pair_indexed(&base_identities, &input_identities);
            for (index, (key, value)) in base.iter().enumerate() {
                let mut nested = path.to_vec();
                nested.push(value_key(key));
                match pairs[index] {
                    Some(input_index) => compare_value_shape(
                        &nested,
                        field,
                        value,
                        &candidate[input_index].1,
                        report,
                    ),
                    None => push_missing_field_at(&nested, field, report),
                }
            }
            for (index, (key, _)) in candidate.iter().enumerate() {
                if !used[index] {
                    let mut nested = path.to_vec();
                    nested.push(value_key(key));
                    push_unexpected_field_at(&nested, field, report);
                }
            }
        }
        (Value::Array(base), Value::Array(candidate)) => {
            for index in 0..base.len().max(candidate.len()) {
                let mut nested = path.to_vec();
                nested.push(PathSegment::Index(index));
                match (base.get(index), candidate.get(index)) {
                    (Some(base), Some(candidate)) => {
                        compare_value_shape(&nested, field, base, candidate, report)
                    }
                    (Some(_), None) => push_missing_field_at(&nested, field, report),
                    (None, Some(_)) => push_unexpected_field_at(&nested, field, report),
                    (None, None) => {}
                }
            }
        }
        (Value::Tag(base_tag, base), Value::Tag(input_tag, candidate)) if base_tag == input_tag => {
            let mut nested = path.to_vec();
            nested.push(PathSegment::Tag(*base_tag));
            compare_value_shape(&nested, field, base, candidate, report);
        }
        _ if value_kind(baseline) != value_kind(input) => {
            report.structural_mismatches.push(StructuralMismatch {
                path: path.to_vec(),
                kind: MismatchKind::TypeMismatch {
                    baseline: value_kind(baseline),
                    input: value_kind(input),
                },
                detail: format!("{field} CBOR type or tag differs"),
            })
        }
        _ if !values_equal(baseline, input) => report.value_differences.push(ValueDifference {
            path: path.to_vec(),
            field,
            baseline: baseline.clone(),
            input: input.clone(),
        }),
        _ => {}
    }
}

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
/// Compare a single leaf attribute located at `base + Field(field)`.
fn compare_leaf(
    base: &[PathSegment],
    field: &'static str,
    baseline: Option<Value>,
    input: Option<Value>,
    r: &mut ConformanceReport,
    structural: bool,
) {
    let mut p = base.to_vec();
    p.push(PathSegment::Field(field));
    compare_opt_value(&p, field, baseline, input, r, structural);
}

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

fn opt_val<T: serde::Serialize>(v: &Option<T>) -> Result<Option<Value>, crate::ValidationError> {
    v.as_ref().map(checked_value).transpose()
}
fn checked_value<T: serde::Serialize>(v: &T) -> Result<Value, crate::ValidationError> {
    to_value(v).map_err(crate::ValidationError::Invalid)
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
