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
//! After checked decoding, each document is interpreted once into a private
//! comparison projection. Exact-match reservation and difference reporting use
//! that same projection, including typed identities, unordered multisets,
//! positional records and optional-field presence. Prepared CBOR shape and
//! shared identity subtrees avoid reserializing candidates while pairing.
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
    Digest, DigestAlg, MeasurementMap, MeasurementValuesMap, RawValueChoice, SvnChoice,
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
    let input = ComparisonProjection::document(input, &input_comids)?;
    let baseline = ComparisonProjection::document(baseline, &base_comids)?;
    let mut report = ConformanceReport::default();
    baseline.compare(&input, &[], &mut report);
    Ok(report)
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
        |k| match k {
            ClaimKey::Int(number) => PathSegment::MapKey(*number),
            ClaimKey::Text(text) => PathSegment::TextKey(text.clone()),
        },
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
        opt_val(&baseline.exp)?,
        opt_val(&input.exp)?,
        r,
        false,
    );
    compare_leaf(
        &p,
        "nbf",
        opt_val(&baseline.nbf)?,
        opt_val(&input.nbf)?,
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

// A bounded, private interpretation of the fields baseline comparison understands.
// Preparation is the only place that selects fields and ordering semantics.
// Reservation keys and reporting both consume this interpretation; neither walks
// the source types again. Shared key subtrees keep parent indexing linear in the
// prepared document size instead of copying/encoding complete candidates.
type ProjectionKey = alloc::rc::Rc<ProjectionIdentity>;

#[derive(Debug, PartialEq, Eq, PartialOrd, Ord)]
enum ProjectionIdentity {
    Value(ExactKey),
    Absent,
    Ordered(Vec<ProjectionKey>),
    Keyed(Vec<(ProjectionKey, ProjectionKey)>),
    CborArray(Vec<ProjectionKey>),
    CborMap(Vec<(ProjectionKey, ProjectionKey)>),
    CborTag(u64, ProjectionKey),
}

fn projection_value(value: &Value) -> ProjectionKey {
    alloc::rc::Rc::new(ProjectionIdentity::Value(value.clone().into()))
}

fn projection_ordered(keys: impl Iterator<Item = ProjectionKey>) -> ProjectionKey {
    alloc::rc::Rc::new(ProjectionIdentity::Ordered(keys.collect()))
}

struct ComparisonProjection {
    exact: ProjectionKey,
    interpretation: ComparisonInterpretation,
}

enum ComparisonInterpretation {
    Fields(Vec<ComparisonProjection>),
    Attribute {
        field: &'static str,
        value: Option<Value>,
        meaning: AttributeMeaning,
    },
    Optional {
        field: &'static str,
        value: Option<Box<ComparisonProjection>>,
    },
    Entries {
        kind: ComparisonEntries,
        entries: Vec<ComparisonEntry>,
    },
    Shape {
        field: &'static str,
        value: PreparedShape,
    },
}

// These are report contracts, not an extensible schema or a wire-format model.
// In particular, optional fields, binary authorities, and ordered CES records
// deliberately remain distinct from recursively compared CBOR shapes.
enum AttributeMeaning {
    Metadata { structural: bool },
    Scalar,
    Authority,
    Digest,
    Svn(&'static str),
    Raw(bool),
    Flag,
    Opaque(&'static str),
}

enum ComparisonEntries {
    Comids,
    Measurements,
    Environments { kind: &'static str, nested: bool },
    Ces,
    Conditional,
    Series,
    Opaque(&'static str),
    Digests,
    CryptoKeys,
    Registers,
    Extensions,
}

struct ComparisonEntry {
    identity: ProjectionKey,
    segment: PathSegment,
    value: ComparisonProjection,
    description: String,
}

impl ComparisonEntries {
    fn ordered(&self) -> bool {
        matches!(self, Self::Conditional | Self::Series | Self::Opaque(_))
    }

    fn path(&self, path: &[PathSegment], entry: &ComparisonEntry) -> Vec<PathSegment> {
        let mut path = path.to_vec();
        path.push(entry.segment.clone());
        path
    }

    fn missing(
        &self,
        path: &[PathSegment],
        entry: &ComparisonEntry,
        unexpected: bool,
        report: &mut ConformanceReport,
    ) {
        let mut path = self.path(path, entry);
        // Historically an unexpected digest is located at the digest list,
        // while a missing digest uses the baseline digest index.
        if unexpected && matches!(self, Self::Digests) {
            path.pop();
        }
        let direction = if unexpected {
            "present in input but not in baseline"
        } else {
            "present in baseline but not in input"
        };
        let detail = match self {
            Self::Comids if !unexpected => "CoMID present in baseline but missing in input".into(),
            Self::Comids => "CoMID present in input but not in baseline".into(),
            Self::Measurements => {
                if unexpected {
                    "measurement present in input but not in baseline".into()
                } else {
                    "measurement present in baseline but not in input".into()
                }
            }
            Self::Environments { kind, nested } => format!(
                "{kind} {}environment {direction}",
                if *nested { "" } else { "triple " }
            ),
            Self::Ces if !unexpected => {
                "CES triple common-condition environment present in baseline but not in input"
                    .into()
            }
            Self::Ces => "CES triple present in input but not in baseline".into(),
            Self::Conditional => format!("conditional-endorsement triple {direction}"),
            Self::Series => format!("CES series record {direction}"),
            Self::Opaque(kind) => format!("{kind} triple {direction}"),
            Self::Digests => format!("digest algorithm {} {direction}", entry.description),
            Self::CryptoKeys | Self::Registers => {
                let field = if matches!(self, Self::CryptoKeys) {
                    "key representation or algorithm"
                } else {
                    "register"
                };
                if unexpected {
                    push_unexpected_field_at(&path, field, report);
                } else {
                    push_missing_field_at(&path, field, report);
                }
                return;
            }
            Self::Extensions => {
                format!("mval extension key {} {direction}", entry.description)
            }
        };
        report.structural_mismatches.push(StructuralMismatch {
            path,
            kind: if unexpected {
                MismatchKind::UnexpectedInInput
            } else {
                MismatchKind::MissingInInput
            },
            detail,
        });
    }
}

impl ComparisonProjection {
    fn fields(fields: Vec<Self>) -> Self {
        Self {
            exact: projection_ordered(fields.iter().map(|field| field.exact.clone())),
            interpretation: ComparisonInterpretation::Fields(fields),
        }
    }

    fn attribute(field: &'static str, value: Option<Value>, meaning: AttributeMeaning) -> Self {
        let value_key = value
            .as_ref()
            .map(projection_value)
            .unwrap_or_else(|| alloc::rc::Rc::new(ProjectionIdentity::Absent));
        // Variant discriminants that are structural must participate in exact
        // reservation even when their displayed payload is identical.
        let discriminant = match &meaning {
            AttributeMeaning::Svn(kind) => Some(Value::Text((*kind).into())),
            AttributeMeaning::Raw(masked) => Some(Value::Bool(*masked)),
            _ => None,
        };
        let exact = match discriminant {
            Some(kind) => projection_ordered([projection_value(&kind), value_key].into_iter()),
            None => value_key,
        };
        Self {
            exact,
            interpretation: ComparisonInterpretation::Attribute {
                field,
                value,
                meaning,
            },
        }
    }

    fn optional(field: &'static str, value: Option<Self>) -> Self {
        Self {
            exact: value
                .as_ref()
                .map(|value| value.exact.clone())
                .unwrap_or_else(|| alloc::rc::Rc::new(ProjectionIdentity::Absent)),
            interpretation: ComparisonInterpretation::Optional {
                field,
                value: value.map(Box::new),
            },
        }
    }

    fn entries(kind: ComparisonEntries, entries: Vec<ComparisonEntry>) -> Self {
        let exact = if kind.ordered() {
            projection_ordered(entries.iter().map(|entry| entry.value.exact.clone()))
        } else {
            let mut keys: Vec<_> = entries
                .iter()
                .map(|entry| (entry.identity.clone(), entry.value.exact.clone()))
                .collect();
            keys.sort_unstable();
            alloc::rc::Rc::new(ProjectionIdentity::Keyed(keys))
        };
        Self {
            exact,
            interpretation: ComparisonInterpretation::Entries { kind, entries },
        }
    }

    fn compare(&self, input: &Self, path: &[PathSegment], report: &mut ConformanceReport) {
        self.compare_inner(input, path, report, true);
    }

    fn compare_inner(
        &self,
        input: &Self,
        path: &[PathSegment],
        report: &mut ConformanceReport,
        prune: bool,
    ) {
        if prune && self.exact == input.exact {
            return;
        }
        match (&self.interpretation, &input.interpretation) {
            (ComparisonInterpretation::Fields(base), ComparisonInterpretation::Fields(input)) => {
                for (base, input) in base.iter().zip(input) {
                    base.compare_inner(input, path, report, prune);
                }
            }
            (
                ComparisonInterpretation::Optional { field, value: base },
                ComparisonInterpretation::Optional { value: input, .. },
            ) => match (base, input) {
                (Some(base), Some(input)) => {
                    let mut path = path.to_vec();
                    path.push(PathSegment::Field(field));
                    base.compare_inner(input, &path, report, prune);
                }
                (Some(_), None) => push_missing_field(path, field, report),
                (None, Some(_)) => push_unexpected_field(path, field, report),
                (None, None) => {}
            },
            (
                ComparisonInterpretation::Attribute {
                    field,
                    value: base,
                    meaning,
                },
                ComparisonInterpretation::Attribute {
                    value: input,
                    meaning: input_meaning,
                    ..
                },
            ) => compare_projected_attribute(
                path,
                field,
                base,
                input,
                meaning,
                input_meaning,
                report,
            ),
            (
                ComparisonInterpretation::Entries {
                    kind,
                    entries: base,
                },
                ComparisonInterpretation::Entries { entries: input, .. },
            ) => {
                if matches!(kind, ComparisonEntries::Series) && base.len() != input.len() {
                    report.structural_mismatches.push(StructuralMismatch {
                        path: path.to_vec(),
                        kind: MismatchKind::TypeMismatch {
                            baseline: base.len().to_string(),
                            input: input.len().to_string(),
                        },
                        detail: "CES series length differs".into(),
                    });
                }
                let (pairs, used) = if kind.ordered() {
                    (
                        (0..base.len())
                            .map(|index| (index < input.len()).then_some(index))
                            .collect(),
                        (0..input.len()).map(|index| index < base.len()).collect(),
                    )
                } else {
                    fn keys(entries: &[ComparisonEntry]) -> Vec<(&ProjectionKey, &ProjectionKey)> {
                        entries
                            .iter()
                            .map(|entry| (&entry.identity, &entry.value.exact))
                            .collect::<Vec<_>>()
                    }
                    pair_indexed(&keys(base), &keys(input))
                };
                for (index, entry) in base.iter().enumerate() {
                    if let Some(input_index) = pairs[index] {
                        entry.value.compare_inner(
                            &input[input_index].value,
                            &kind.path(path, entry),
                            report,
                            prune,
                        );
                    } else {
                        kind.missing(path, entry, false, report);
                    }
                }
                if !matches!(kind, ComparisonEntries::Series) {
                    for (index, entry) in input.iter().enumerate() {
                        if !used[index] {
                            kind.missing(path, entry, true, report);
                        }
                    }
                }
            }
            (
                ComparisonInterpretation::Shape { field, value: base },
                ComparisonInterpretation::Shape { value: input, .. },
            ) => base.compare(input, path, field, report, prune),
            // The private constructors always produce the same interpretation
            // at a given field. A mismatch is not silently accepted.
            _ => report.structural_mismatches.push(StructuralMismatch {
                path: path.to_vec(),
                kind: MismatchKind::TypeMismatch {
                    baseline: "comparison field".into(),
                    input: "comparison field".into(),
                },
                detail: "comparison field interpretation differs".into(),
            }),
        }
    }

    fn document(
        corim: &CorimMap,
        comids: &[(String, ComidTag)],
    ) -> Result<Self, crate::ValidationError> {
        let mut fields = alloc::vec![
            Self::attribute(
                "profile",
                opt_val(&corim.profile)?,
                AttributeMeaning::Metadata { structural: true }
            ),
            Self::attribute(
                "corim-id",
                Some(checked_value(&corim.id)?),
                AttributeMeaning::Metadata { structural: false }
            ),
            Self::attribute(
                "rim-validity",
                opt_val(&corim.rim_validity)?,
                AttributeMeaning::Metadata { structural: false }
            ),
            Self::attribute(
                "entities",
                opt_val(&corim.entities)?,
                AttributeMeaning::Metadata { structural: false }
            ),
            Self::attribute(
                "dependent-rims",
                opt_val(&corim.dependent_rims)?,
                AttributeMeaning::Metadata { structural: false }
            ),
        ];
        let entries = comids
            .iter()
            .map(|(id, comid)| {
                Ok(ComparisonEntry {
                    identity: projection_value(&checked_value(&comid.tag_identity.tag_id)?),
                    segment: PathSegment::Comid(id.clone()),
                    value: Self::comid(comid)?,
                    description: String::new(),
                })
            })
            .collect::<Result<_, crate::ValidationError>>()?;
        fields.push(Self::entries(ComparisonEntries::Comids, entries));
        Ok(Self::fields(fields))
    }

    fn comid(comid: &ComidTag) -> Result<Self, crate::ValidationError> {
        let triples = &comid.triples;
        let mut fields = alloc::vec![
            Self::attribute(
                "tag-version",
                comid.tag_identity.tag_version.map(u64_value),
                AttributeMeaning::Metadata { structural: false }
            ),
            Self::attribute(
                "language",
                opt_val(&comid.language)?,
                AttributeMeaning::Metadata { structural: false }
            ),
            Self::attribute(
                "entities",
                opt_val(&comid.entities)?,
                AttributeMeaning::Metadata { structural: false }
            ),
            Self::attribute(
                "linked-tags",
                opt_val(&comid.linked_tags)?,
                AttributeMeaning::Metadata { structural: false }
            ),
            Self::environments(
                "reference",
                false,
                refs_as_pairs(triples.reference_triples.as_deref().unwrap_or_default())
            )?,
            Self::environments(
                "endorsed",
                false,
                endorsed_as_pairs(triples.endorsed_triples.as_deref().unwrap_or_default())
            )?,
        ];
        let ces = triples
            .conditional_endorsement_series
            .as_deref()
            .unwrap_or_default();
        let entries = ces
            .iter()
            .enumerate()
            .map(|(index, ces)| {
                let common = ces.common_condition();
                let mut fields = alloc::vec![
                    Self::optional(
                        "claims-list",
                        Some(Self::measurements(&common.claims_list)?)
                    ),
                    Self::attribute(
                        "authorized-by",
                        opt_val(&common.authorized_by)?,
                        AttributeMeaning::Authority
                    ),
                ];
                let series = ces
                    .series()
                    .iter()
                    .enumerate()
                    .map(|(index, record)| {
                        Ok(ComparisonEntry {
                            identity: projection_value(&Value::Null),
                            segment: PathSegment::Index(index),
                            value: Self::fields(alloc::vec![
                                Self::optional(
                                    "condition",
                                    Some(Self::measurements(record.condition())?)
                                ),
                                Self::optional(
                                    "addition",
                                    Some(Self::measurements(record.addition())?)
                                ),
                            ]),
                            description: String::new(),
                        })
                    })
                    .collect::<Result<_, crate::ValidationError>>()?;
                fields.push(Self::optional(
                    "series",
                    Some(Self::entries(ComparisonEntries::Series, series)),
                ));
                Ok(ComparisonEntry {
                    identity: projection_value(&checked_value(&common.environment)?),
                    segment: PathSegment::Triple {
                        kind: "conditional-endorsement-series",
                        index,
                    },
                    value: Self::fields(fields),
                    description: String::new(),
                })
            })
            .collect::<Result<_, crate::ValidationError>>()?;
        fields.push(Self::entries(ComparisonEntries::Ces, entries));
        let conditional = triples
            .conditional_endorsement
            .as_deref()
            .unwrap_or_default();
        let entries = conditional
            .iter()
            .enumerate()
            .map(|(index, record)| {
                Ok(ComparisonEntry {
                    identity: projection_value(&Value::Null),
                    segment: PathSegment::Triple {
                        kind: "conditional-endorsement",
                        index,
                    },
                    value: Self::fields(alloc::vec![
                        Self::optional(
                            "conditions",
                            Some(Self::environments(
                                "conditions",
                                true,
                                record
                                    .0
                                    .iter()
                                    .map(|group| (&group.0, group.1.as_slice()))
                                    .collect()
                            )?)
                        ),
                        Self::optional(
                            "endorsements",
                            Some(Self::environments(
                                "endorsements",
                                true,
                                endorsed_as_pairs(&record.1)
                            )?)
                        ),
                    ]),
                    description: String::new(),
                })
            })
            .collect::<Result<_, crate::ValidationError>>()?;
        fields.push(Self::entries(ComparisonEntries::Conditional, entries));
        fn opaque<T: serde::Serialize>(
            kind: &'static str,
            triples: Option<&[T]>,
        ) -> Result<ComparisonProjection, crate::ValidationError> {
            let entries = triples
                .unwrap_or_default()
                .iter()
                .enumerate()
                .map(|(index, triple)| {
                    Ok(ComparisonEntry {
                        identity: projection_value(&Value::Null),
                        segment: PathSegment::Triple { kind, index },
                        value: ComparisonProjection::attribute(
                            kind,
                            Some(checked_value(triple)?),
                            AttributeMeaning::Opaque(kind),
                        ),
                        description: String::new(),
                    })
                })
                .collect::<Result<_, crate::ValidationError>>()?;
            Ok(ComparisonProjection::entries(
                ComparisonEntries::Opaque(kind),
                entries,
            ))
        }
        fields.extend([
            opaque("identity", triples.identity_triples.as_deref())?,
            opaque("attest-key", triples.attest_key_triples.as_deref())?,
            opaque("dependency", triples.dependency_triples.as_deref())?,
            opaque("membership", triples.membership_triples.as_deref())?,
            opaque("coswid", triples.coswid_triples.as_deref())?,
        ]);
        Ok(Self::fields(fields))
    }

    fn environments(
        kind: &'static str,
        nested: bool,
        groups: EnvMeas<'_>,
    ) -> Result<Self, crate::ValidationError> {
        let entries = groups
            .iter()
            .enumerate()
            .map(|(index, (environment, measurements))| {
                Ok(ComparisonEntry {
                    identity: projection_value(&checked_value(environment)?),
                    segment: if nested {
                        PathSegment::Index(index)
                    } else {
                        PathSegment::Triple { kind, index }
                    },
                    value: Self::measurements(measurements)?,
                    description: String::new(),
                })
            })
            .collect::<Result<_, crate::ValidationError>>()?;
        Ok(Self::entries(
            ComparisonEntries::Environments { kind, nested },
            entries,
        ))
    }

    fn measurements(measurements: &[MeasurementMap]) -> Result<Self, crate::ValidationError> {
        let entries = measurements
            .iter()
            .enumerate()
            .map(|(index, measurement)| {
                // Distinguish a typed key from an unkeyed positional slot, including
                // at parent reservation levels. Display strings are never identities.
                let identity = match &measurement.mkey {
                    Some(key) => projection_ordered(
                        [
                            projection_value(&Value::Bool(true)),
                            projection_value(&checked_value(key)?),
                        ]
                        .into_iter(),
                    ),
                    None => projection_ordered(
                        [
                            projection_value(&Value::Bool(false)),
                            projection_value(&Value::Integer(i128::try_from(index).map_err(
                                |_| {
                                    crate::ValidationError::Invalid(
                                        "measurement index out of range".into(),
                                    )
                                },
                            )?)),
                        ]
                        .into_iter(),
                    ),
                };
                let mut fields = alloc::vec![Self::attribute(
                    "authorized-by",
                    opt_val(&measurement.authorized_by)?,
                    AttributeMeaning::Authority
                )];
                fields.extend(Self::mval(&measurement.mval)?);
                Ok(ComparisonEntry {
                    identity,
                    segment: PathSegment::Measurement(mkey_string(measurement, index)),
                    value: Self::fields(fields),
                    description: String::new(),
                })
            })
            .collect::<Result<_, crate::ValidationError>>()?;
        Ok(Self::entries(ComparisonEntries::Measurements, entries))
    }

    fn digests(digests: &[Digest]) -> Self {
        Self::entries(
            ComparisonEntries::Digests,
            digests
                .iter()
                .enumerate()
                .map(|(index, digest)| {
                    let algorithm = match &digest.0 {
                        DigestAlg::Int(number) => Value::Integer(i128::from(*number)),
                        DigestAlg::Text(text) => Value::Text(text.clone()),
                    };
                    ComparisonEntry {
                        identity: projection_value(&algorithm),
                        segment: PathSegment::Index(index),
                        value: Self::attribute(
                            "digest-value",
                            Some(Value::Bytes(digest.1.clone())),
                            AttributeMeaning::Digest,
                        ),
                        description: format!("{:?}", digest.0),
                    }
                })
                .collect(),
        )
    }

    fn shape_value(field: &'static str, value: Value, matcher: bool) -> Self {
        let value = PreparedShape::new(value, matcher);
        Self {
            exact: value.exact.clone(),
            interpretation: ComparisonInterpretation::Shape { field, value },
        }
    }

    fn shape(field: &'static str, value: Option<Value>) -> Self {
        Self::optional(
            field,
            value.map(|value| {
                Self::shape_value(field, value, matches!(field, "number" | "text" | "bytes"))
            }),
        )
    }

    fn mval(values: &MeasurementValuesMap) -> Result<Vec<Self>, crate::ValidationError> {
        let mut fields = alloc::vec![
            Self::optional("digests", values.digests.as_deref().map(Self::digests)),
            Self::optional(
                "svn",
                values.svn.as_ref().map(|svn| Self::attribute(
                    "svn",
                    Some(Value::Integer(i128::from(match svn {
                        SvnChoice::ExactValue(n) | SvnChoice::MinValue(n) => *n,
                    }))),
                    AttributeMeaning::Svn(svn_kind(svn))
                ))
            ),
            Self::optional(
                "raw-value",
                values.raw_value.as_ref().map(|raw| {
                    let (value, masked) = match raw {
                        RawValueChoice::Bytes(bytes) => (Value::Bytes(bytes.clone()), false),
                        RawValueChoice::Masked { value, mask } => (
                            Value::Array(alloc::vec![
                                Value::Bytes(value.clone()),
                                Value::Bytes(mask.clone())
                            ]),
                            true,
                        ),
                    };
                    Self::attribute("raw-value", Some(value), AttributeMeaning::Raw(masked))
                })
            ),
        ];
        let flags = values
            .flags
            .as_ref()
            .map(|flags| {
                use crate::types::tags::*;
                // Preserve serialization failures for decoded extension-only
                // flags maps, whose unknown fields the typed decoder discards.
                let Value::Map(flags) = checked_value(flags)? else {
                    return Err(crate::ValidationError::Invalid(
                        "flags must be a CBOR map".into(),
                    ));
                };
                Ok::<_, crate::ValidationError>(Self::fields(
                    alloc::vec![
                        ("is-configured", FLAG_KEY_IS_CONFIGURED),
                        ("is-secure", FLAG_KEY_IS_SECURE),
                        ("is-recovery", FLAG_KEY_IS_RECOVERY),
                        ("is-debug", FLAG_KEY_IS_DEBUG),
                        ("is-replay-protected", FLAG_KEY_IS_REPLAY_PROTECTED),
                        ("is-integrity-protected", FLAG_KEY_IS_INTEGRITY_PROTECTED),
                        ("is-runtime-meas", FLAG_KEY_IS_RUNTIME_MEAS),
                        ("is-immutable", FLAG_KEY_IS_IMMUTABLE),
                        ("is-tcb", FLAG_KEY_IS_TCB),
                        (
                            "is-confidentiality-protected",
                            FLAG_KEY_IS_CONFIDENTIALITY_PROTECTED
                        ),
                        ("is-runtime-updatable", FLAG_KEY_IS_RUNTIME_UPDATABLE),
                    ]
                    .into_iter()
                    .map(|(field, label)| {
                        let value = flags.iter().find_map(|(key, value)| {
                            (*key == Value::Integer(i128::from(label))).then(|| value.clone())
                        });
                        Self::attribute(field, value, AttributeMeaning::Flag)
                    })
                    .collect(),
                ))
            })
            .transpose()?;
        fields.push(Self::optional("flags", flags));
        for (field, value) in [
            ("version", opt_val(&values.version)?),
            ("serial-number", opt_val(&values.serial_number)?),
            ("name", opt_val(&values.name)?),
            (
                "ueid",
                values.ueid.as_ref().map(|v| Value::Bytes(v.clone())),
            ),
            (
                "uuid",
                values.uuid.as_ref().map(|v| Value::Bytes(v.clone())),
            ),
            ("mac-addr", opt_val(&values.mac_addr)?),
            ("ip-addr", opt_val(&values.ip_addr)?),
        ] {
            fields.push(Self::attribute(field, value, AttributeMeaning::Scalar));
        }
        let keys = values
            .cryptokeys
            .as_ref()
            .map(|keys| {
                let entries = keys
                    .iter()
                    .enumerate()
                    .map(|(index, key)| {
                        let value = checked_value(key)?;
                        let Value::Tag(tag, _) = &value else {
                            return Err(crate::ValidationError::Invalid(
                                "crypto-key must have a representation tag".into(),
                            ));
                        };
                        use crate::types::common::CryptoKey;
                        let algorithm = match key {
                            CryptoKey::KeyThumbprint(digest)
                            | CryptoKey::CertThumbprint(digest)
                            | CryptoKey::CertPathThumbprint(digest) => match &digest.0 {
                                DigestAlg::Int(number) => Value::Integer(i128::from(*number)),
                                DigestAlg::Text(text) => Value::Text(text.clone()),
                            },
                            _ => Value::Null,
                        };
                        Ok(ComparisonEntry {
                            identity: projection_ordered(
                                [
                                    projection_value(&Value::Integer(i128::from(*tag))),
                                    projection_value(&algorithm),
                                ]
                                .into_iter(),
                            ),
                            segment: PathSegment::Index(index),
                            value: Self::shape_value("cryptokeys", value, false),
                            description: String::new(),
                        })
                    })
                    .collect::<Result<_, crate::ValidationError>>()?;
                Ok::<_, crate::ValidationError>(Self::entries(
                    ComparisonEntries::CryptoKeys,
                    entries,
                ))
            })
            .transpose()?;
        fields.push(Self::optional("cryptokeys", keys));
        let registers = values
            .integrity_registers
            .as_ref()
            .map(|registers| {
                let entries = registers
                    .0
                    .iter()
                    .map(|(key, digests)| {
                        let key = checked_value(key)?;
                        Ok(ComparisonEntry {
                            identity: projection_value(&key),
                            segment: value_key(&key),
                            value: Self::optional("digests", Some(Self::digests(digests))),
                            description: String::new(),
                        })
                    })
                    .collect::<Result<_, crate::ValidationError>>()?;
                Ok::<_, crate::ValidationError>(Self::entries(
                    ComparisonEntries::Registers,
                    entries,
                ))
            })
            .transpose()?;
        fields.push(Self::optional("integrity-registers", registers));
        fields.push(Self::shape("int-range", opt_val(&values.int_range)?));
        fields.push(Self::attribute(
            "bool",
            opt_val(&values.r#bool)?,
            AttributeMeaning::Scalar,
        ));
        fields.push(Self::shape("number", opt_val(&values.number)?));
        fields.push(Self::shape("text", opt_val(&values.text)?));
        fields.push(Self::shape("bytes", opt_val(&values.bytes)?));
        let extensions = values
            .extra_entries
            .iter()
            .map(|(key, value)| ComparisonEntry {
                identity: projection_value(&Value::Integer(i128::from(*key))),
                segment: PathSegment::MapKey(*key),
                value: Self::shape_value("mval-extension", value.clone(), false),
                description: key.to_string(),
            })
            .collect();
        fields.push(Self::optional(
            "mval-extension",
            Some(Self::entries(ComparisonEntries::Extensions, extensions)),
        ));
        Ok(fields)
    }
}

// CBOR shape is prepared recursively too: maps keep encounter order for paths
// and sorted typed identities for reservation; arrays retain position. Only a
// typed matcher's outer set is unordered, never an arbitrary extension array.
struct PreparedShape {
    exact: ProjectionKey,
    interpretation: ShapeInterpretation,
}

enum ShapeInterpretation {
    Atom(Value),
    Array(Vec<PreparedShape>),
    Map(Vec<(Value, ProjectionKey, PreparedShape)>),
    Tag(u64, Box<PreparedShape>),
    MatcherSet(Vec<(ProjectionKey, PreparedShape)>),
}

impl PreparedShape {
    fn new(value: Value, matcher: bool) -> Self {
        let interpretation = match value {
            Value::Map(entries) => ShapeInterpretation::Map(
                entries
                    .into_iter()
                    .map(|(key, value)| {
                        let identity = projection_value(&key);
                        (key, identity, Self::new(value, false))
                    })
                    .collect(),
            ),
            Value::Array(values) => ShapeInterpretation::Array(
                values
                    .into_iter()
                    .map(|value| Self::new(value, false))
                    .collect(),
            ),
            Value::Tag(tag, inner) if matcher && tag == crate::types::tags::TAG_MATCHER_SET => {
                match *inner {
                    Value::Array(values) => ShapeInterpretation::MatcherSet(
                        values
                            .into_iter()
                            .map(|value| {
                                (
                                    projection_value(&Value::Text(value_kind(&value))),
                                    Self::new(value, false),
                                )
                            })
                            .collect(),
                    ),
                    other => ShapeInterpretation::Tag(tag, Box::new(Self::new(other, false))),
                }
            }
            Value::Tag(tag, inner) => {
                ShapeInterpretation::Tag(tag, Box::new(Self::new(*inner, false)))
            }
            value => ShapeInterpretation::Atom(value),
        };
        let exact = match &interpretation {
            ShapeInterpretation::Atom(value) => projection_value(value),
            ShapeInterpretation::Array(values) => {
                alloc::rc::Rc::new(ProjectionIdentity::CborArray(
                    values.iter().map(|value| value.exact.clone()).collect(),
                ))
            }
            ShapeInterpretation::Map(entries) => {
                let mut keys: Vec<_> = entries
                    .iter()
                    .map(|(_, key, value)| (key.clone(), value.exact.clone()))
                    .collect();
                keys.sort_unstable();
                alloc::rc::Rc::new(ProjectionIdentity::CborMap(keys))
            }
            ShapeInterpretation::Tag(tag, inner) => {
                alloc::rc::Rc::new(ProjectionIdentity::CborTag(*tag, inner.exact.clone()))
            }
            ShapeInterpretation::MatcherSet(values) => {
                let mut keys: Vec<_> = values
                    .iter()
                    .map(|(kind, value)| (kind.clone(), value.exact.clone()))
                    .collect();
                keys.sort_unstable();
                alloc::rc::Rc::new(ProjectionIdentity::CborTag(
                    crate::types::tags::TAG_MATCHER_SET,
                    alloc::rc::Rc::new(ProjectionIdentity::Keyed(keys)),
                ))
            }
        };
        Self {
            exact,
            interpretation,
        }
    }

    fn kind(&self) -> String {
        match &self.interpretation {
            ShapeInterpretation::Atom(value) => value_kind(value),
            ShapeInterpretation::Array(_) => "array".into(),
            ShapeInterpretation::Map(_) => "map".into(),
            ShapeInterpretation::Tag(tag, _) => format!("tag:{tag}"),
            ShapeInterpretation::MatcherSet(_) => {
                format!("tag:{}", crate::types::tags::TAG_MATCHER_SET)
            }
        }
    }

    fn compare(
        &self,
        input: &Self,
        path: &[PathSegment],
        field: &'static str,
        report: &mut ConformanceReport,
        prune: bool,
    ) {
        if prune && self.exact == input.exact {
            return;
        }
        match (&self.interpretation, &input.interpretation) {
            (ShapeInterpretation::Map(base), ShapeInterpretation::Map(input)) => {
                let base_keys: Vec<_> = base
                    .iter()
                    .map(|(_, key, value)| (key, &value.exact))
                    .collect();
                let input_keys: Vec<_> = input
                    .iter()
                    .map(|(_, key, value)| (key, &value.exact))
                    .collect();
                let (pairs, used) = pair_indexed(&base_keys, &input_keys);
                for (index, (key, _, value)) in base.iter().enumerate() {
                    let mut nested = path.to_vec();
                    nested.push(value_key(key));
                    if let Some(input_index) = pairs[index] {
                        value.compare(&input[input_index].2, &nested, field, report, prune);
                    } else {
                        push_missing_field_at(&nested, field, report);
                    }
                }
                for (index, (key, _, _)) in input.iter().enumerate() {
                    if !used[index] {
                        let mut nested = path.to_vec();
                        nested.push(value_key(key));
                        push_unexpected_field_at(&nested, field, report);
                    }
                }
            }
            (ShapeInterpretation::Array(base), ShapeInterpretation::Array(input)) => {
                for index in 0..base.len().max(input.len()) {
                    let mut nested = path.to_vec();
                    nested.push(PathSegment::Index(index));
                    match (base.get(index), input.get(index)) {
                        (Some(base), Some(input)) => {
                            base.compare(input, &nested, field, report, prune)
                        }
                        (Some(_), None) => push_missing_field_at(&nested, field, report),
                        (None, Some(_)) => push_unexpected_field_at(&nested, field, report),
                        (None, None) => {}
                    }
                }
            }
            (
                ShapeInterpretation::Tag(base_tag, base),
                ShapeInterpretation::Tag(input_tag, input),
            ) if base_tag == input_tag => {
                let mut nested = path.to_vec();
                nested.push(PathSegment::Tag(*base_tag));
                base.compare(input, &nested, field, report, prune);
            }
            (ShapeInterpretation::MatcherSet(base), ShapeInterpretation::MatcherSet(input)) => {
                let base_keys: Vec<_> = base
                    .iter()
                    .map(|(key, value)| (key, &value.exact))
                    .collect();
                let input_keys: Vec<_> = input
                    .iter()
                    .map(|(key, value)| (key, &value.exact))
                    .collect();
                let (pairs, used) = pair_indexed(&base_keys, &input_keys);
                for (index, (_, value)) in base.iter().enumerate() {
                    let mut nested = path.to_vec();
                    nested.push(PathSegment::Index(index));
                    if let Some(input_index) = pairs[index] {
                        value.compare(&input[input_index].1, &nested, field, report, prune);
                    } else {
                        push_missing_field_at(&nested, field, report);
                    }
                }
                for (index, matched) in used.iter().enumerate() {
                    if !matched {
                        let mut nested = path.to_vec();
                        nested.push(PathSegment::Index(index));
                        push_unexpected_field_at(&nested, field, report);
                    }
                }
            }
            (ShapeInterpretation::Atom(base), ShapeInterpretation::Atom(input))
                if value_kind(base) == value_kind(input) =>
            {
                if !values_equal(base, input) {
                    report.value_differences.push(ValueDifference {
                        path: path.to_vec(),
                        field,
                        baseline: base.clone(),
                        input: input.clone(),
                    });
                }
            }
            _ => report.structural_mismatches.push(StructuralMismatch {
                path: path.to_vec(),
                kind: MismatchKind::TypeMismatch {
                    baseline: self.kind(),
                    input: input.kind(),
                },
                detail: format!("{field} CBOR type or tag differs"),
            }),
        }
    }
}

fn compare_projected_attribute(
    path: &[PathSegment],
    field: &'static str,
    baseline: &Option<Value>,
    input: &Option<Value>,
    meaning: &AttributeMeaning,
    input_meaning: &AttributeMeaning,
    report: &mut ConformanceReport,
) {
    let same_discriminant = match (meaning, input_meaning) {
        (AttributeMeaning::Svn(base), AttributeMeaning::Svn(input)) => base == input,
        (AttributeMeaning::Raw(base), AttributeMeaning::Raw(input)) => base == input,
        _ => true,
    };
    if same_discriminant
        && baseline.as_ref().map(ValueIdentity::from) == input.as_ref().map(ValueIdentity::from)
    {
        return;
    }
    let mut nested = path.to_vec();
    match meaning {
        AttributeMeaning::Metadata { structural } => {
            nested.push(PathSegment::Field(field));
            match (baseline, input) {
                (Some(base), Some(input)) if *structural => {
                    report.structural_mismatches.push(StructuralMismatch {
                        path: nested,
                        kind: MismatchKind::TypeMismatch {
                            baseline: describe_value(base),
                            input: describe_value(input),
                        },
                        detail: format!(
                            "{field} differs; the documents follow different structures"
                        ),
                    });
                }
                (Some(_), None) if *structural => push_missing_field_at(&nested, field, report),
                (None, Some(_)) if *structural => push_unexpected_field_at(&nested, field, report),
                _ => report.value_differences.push(ValueDifference {
                    path: nested,
                    field,
                    baseline: baseline.clone().unwrap_or(Value::Null),
                    input: input.clone().unwrap_or(Value::Null),
                }),
            }
        }
        AttributeMeaning::Authority => push_authority_mismatch(path, report),
        AttributeMeaning::Scalar => match (baseline, input) {
            (Some(base), Some(input)) => {
                nested.push(PathSegment::Field(field));
                report.value_differences.push(ValueDifference {
                    path: nested,
                    field,
                    baseline: base.clone(),
                    input: input.clone(),
                });
            }
            (Some(_), None) => push_missing_field(path, field, report),
            (None, Some(_)) => push_unexpected_field(path, field, report),
            (None, None) => {}
        },
        AttributeMeaning::Svn(base_kind) => {
            if let AttributeMeaning::Svn(input_kind) = input_meaning {
                if base_kind != input_kind {
                    report.structural_mismatches.push(StructuralMismatch {
                        path: path.to_vec(),
                        kind: MismatchKind::TypeMismatch {
                            baseline: (*base_kind).into(),
                            input: (*input_kind).into(),
                        },
                        detail: "svn type discriminant differs (exact vs minimum)".into(),
                    });
                    return;
                }
            }
            if let (Some(base), Some(input)) = (baseline, input) {
                report.value_differences.push(ValueDifference {
                    path: path.to_vec(),
                    field,
                    baseline: base.clone(),
                    input: input.clone(),
                });
            }
        }
        AttributeMeaning::Raw(base_masked) => {
            if let AttributeMeaning::Raw(input_masked) = input_meaning {
                if base_masked != input_masked {
                    report.structural_mismatches.push(StructuralMismatch {
                        path: path.to_vec(),
                        kind: MismatchKind::TypeMismatch {
                            baseline: "bytes-or-masked".into(),
                            input: "bytes-or-masked".into(),
                        },
                        detail: "raw-value type discriminant differs (bytes vs masked)".into(),
                    });
                    return;
                }
            }
            if let (Some(base), Some(input)) = (baseline, input) {
                report.value_differences.push(ValueDifference {
                    path: path.to_vec(),
                    field,
                    baseline: base.clone(),
                    input: input.clone(),
                });
            }
        }
        AttributeMeaning::Digest => {
            if let (Some(base), Some(input)) = (baseline, input) {
                report.value_differences.push(ValueDifference {
                    path: path.to_vec(),
                    field,
                    baseline: base.clone(),
                    input: input.clone(),
                });
            }
        }
        AttributeMeaning::Flag => {
            nested.push(PathSegment::Field(field));
            match (baseline, input) {
                (Some(base), Some(input)) => report.value_differences.push(ValueDifference {
                    path: nested,
                    field: "flag",
                    baseline: base.clone(),
                    input: input.clone(),
                }),
                (base, _) => report.structural_mismatches.push(StructuralMismatch {
                    path: nested,
                    kind: if base.is_some() {
                        MismatchKind::MissingInInput
                    } else {
                        MismatchKind::UnexpectedInInput
                    },
                    detail: format!(
                        "flag {field} present in {} but not in {}",
                        if base.is_some() { "baseline" } else { "input" },
                        if base.is_some() { "input" } else { "baseline" }
                    ),
                }),
            }
        }
        AttributeMeaning::Opaque(kind) => report.structural_mismatches.push(StructuralMismatch {
            path: path.to_vec(),
            kind: MismatchKind::TypeMismatch {
                baseline: "triple".into(),
                input: "triple".into(),
            },
            detail: format!("{kind} triple content differs from baseline"),
        }),
    }
}

fn tag_id_string(comid: &ComidTag, _index: usize) -> String {
    match &comid.tag_identity.tag_id {
        crate::types::common::TagIdChoice::Text(text) => text.clone(),
        crate::types::common::TagIdChoice::Uuid(bytes) => format!("uuid:{}", hex(bytes)),
    }
}

type ExactKey = ValueIdentity<'static>;

fn u64_value(v: u64) -> Value {
    Value::Integer(i128::from(v))
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

fn svn_kind(s: &SvnChoice) -> &'static str {
    match s {
        SvnChoice::ExactValue(_) => "exact-svn",
        SvnChoice::MinValue(_) => "min-svn",
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
    Bytes(alloc::borrow::Cow<'a, [u8]>),
    Text(alloc::borrow::Cow<'a, str>),
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
            Value::Bytes(bytes) => Self::Bytes(alloc::borrow::Cow::Borrowed(bytes)),
            Value::Text(text) => Self::Text(alloc::borrow::Cow::Borrowed(text)),
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

impl From<Value> for ValueIdentity<'static> {
    fn from(value: Value) -> Self {
        match value {
            Value::Integer(number) => Self::Integer(number),
            Value::Float(number) => Self::Float(number.to_bits()),
            Value::Bytes(bytes) => Self::Bytes(alloc::borrow::Cow::Owned(bytes)),
            Value::Text(text) => Self::Text(alloc::borrow::Cow::Owned(text)),
            Value::Bool(value) => Self::Bool(value),
            Value::Null => Self::Null,
            Value::Array(values) => Self::Array(values.into_iter().map(Self::from).collect()),
            Value::Map(entries) => {
                let mut entries: Vec<_> = entries
                    .into_iter()
                    .map(|(key, value)| (Self::from(key), Self::from(value)))
                    .collect();
                entries.sort_unstable();
                Self::Map(entries)
            }
            Value::Tag(tag, inner) => Self::Tag(tag, Box::new(Self::from(*inner))),
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

#[cfg(test)]
#[allow(clippy::field_reassign_with_default)]
mod projection_invariants {
    use super::*;
    use crate::types::common::{CryptoKey, MeasuredElement, TagIdChoice};
    use crate::types::environment::EnvironmentMap;
    use crate::types::matcher::{Number, NumberMatcher, TextMatcher};
    use crate::types::measurement::{FlagsMap, IntegrityRegisterId, IntegrityRegisters};
    use crate::types::triples::{
        CesCommonCondition, ConditionalEndorsementSeriesTriple, ConditionalEndorsementTriple,
        ConditionalSeriesRecord, EndorsedTriple, IdentityTriple, ReferenceTriple,
        StatefulEnvironmentRecord,
    };

    fn assert_equivalence(projections: &[ComparisonProjection]) {
        for (base_index, baseline) in projections.iter().enumerate() {
            for (input_index, input) in projections.iter().enumerate() {
                let mut report = ConformanceReport::default();
                // Disable every equality shortcut, including descendants. This
                // exercises reporting independently of the key under test.
                baseline.compare_inner(input, &[], &mut report, false);
                assert_eq!(
                    baseline.exact == input.exact,
                    report.structural_mismatches.is_empty() && report.value_differences.is_empty(),
                    "baseline {base_index}, input {input_index}: {report:?}"
                );
            }
        }
    }

    #[test]
    fn prepared_shape_keys_iff_unpruned_comparison_is_empty() {
        let nan = f64::NAN.to_bits();
        let mut values = alloc::vec![
            Value::Null,
            Value::Bool(false),
            Value::Bool(true),
            Value::Integer(1),
            Value::Text("1".into()),
            Value::Bytes(alloc::vec![1]),
            Value::Float(0.0),
            Value::Float(-0.0),
            Value::Float(f64::from_bits(nan)),
            Value::Float(f64::from_bits(nan ^ 1)),
            Value::Array(alloc::vec![]),
            Value::Map(alloc::vec![]),
        ];
        let maps = [
            alloc::vec![
                (Value::Integer(1), Value::Bool(false)),
                (Value::Text("1".into()), Value::Bool(true))
            ],
            alloc::vec![
                (Value::Text("1".into()), Value::Bool(true)),
                (Value::Integer(1), Value::Bool(false))
            ],
            // Repeated CBOR identities exercise the same multiset law even
            // though checked_comids rejects duplicate wire map keys.
            alloc::vec![
                (Value::Integer(1), Value::Float(0.0)),
                (Value::Integer(1), Value::Float(-0.0))
            ],
            alloc::vec![
                (Value::Integer(1), Value::Float(-0.0)),
                (Value::Integer(1), Value::Float(0.0))
            ],
        ];
        values.extend(maps.into_iter().map(Value::Map));
        for entries in [
            alloc::vec![],
            alloc::vec![Value::Integer(1)],
            alloc::vec![Value::Integer(1), Value::Text("1".into())],
            alloc::vec![Value::Text("1".into()), Value::Integer(1)],
            alloc::vec![Value::Integer(1), Value::Integer(1)],
            alloc::vec![Value::Float(0.0), Value::Float(-0.0)],
            alloc::vec![Value::Float(-0.0), Value::Float(0.0)],
        ] {
            values.push(Value::Array(entries.clone()));
            values.push(Value::Tag(
                crate::types::tags::TAG_MATCHER_SET,
                Box::new(Value::Array(entries)),
            ));
        }
        for matcher in [false, true] {
            let projections: Vec<_> = values
                .iter()
                .map(|value| {
                    ComparisonProjection::shape_value("test-shape", value.clone(), matcher)
                })
                .collect();
            assert_equivalence(&projections);
        }
    }

    fn measurement() -> MeasurementMap {
        let mut mval = MeasurementValuesMap::default();
        mval.digests = Some(alloc::vec![
            Digest::new(7, alloc::vec![1]),
            Digest::new(7, alloc::vec![2])
        ]);
        mval.text = Some(TextMatcher::Set(alloc::vec![
            "a".into(),
            "b".into(),
            "a".into()
        ]));
        mval.cryptokeys = Some(alloc::vec![
            CryptoKey::KeyThumbprint(Digest::new(7, alloc::vec![1])),
            CryptoKey::KeyThumbprint(Digest::new(7, alloc::vec![2])),
        ]);
        mval.integrity_registers = Some(IntegrityRegisters(
            [
                (IntegrityRegisterId::Uint(1), mval.digests.clone().unwrap()),
                (
                    IntegrityRegisterId::Text("1".into()),
                    mval.digests.clone().unwrap(),
                ),
            ]
            .into(),
        ));
        MeasurementMap {
            mkey: Some(MeasuredElement::Text("same".into())),
            mval,
            authorized_by: None,
        }
    }

    fn flags(is_secure: Option<bool>) -> FlagsMap {
        FlagsMap {
            is_configured: None,
            is_secure,
            is_recovery: None,
            is_debug: None,
            is_replay_protected: None,
            is_integrity_protected: None,
            is_runtime_meas: None,
            is_immutable: None,
            is_tcb: None,
            is_confidentiality_protected: None,
            is_runtime_updatable: None,
        }
    }

    #[test]
    fn measurement_reservation_keys_iff_unpruned_comparison_is_empty() {
        let original = measurement();
        let mut measurements = alloc::vec![original.clone()];
        let mut reordered = original.clone();
        reordered.mval.digests.as_mut().unwrap().reverse();
        reordered.mval.cryptokeys.as_mut().unwrap().reverse();
        for digests in reordered
            .mval
            .integrity_registers
            .as_mut()
            .unwrap()
            .0
            .values_mut()
        {
            digests.reverse();
        }
        reordered.mval.text = Some(TextMatcher::Set(alloc::vec![
            "b".into(),
            "a".into(),
            "a".into()
        ]));
        measurements.push(reordered);
        for edit in [
            |m: &mut MeasurementMap| m.mkey = None,
            |m: &mut MeasurementMap| m.mkey = Some(MeasuredElement::Uint(1)),
            |m: &mut MeasurementMap| m.mkey = Some(MeasuredElement::Text("uint:1".into())),
            |m: &mut MeasurementMap| m.authorized_by = Some(alloc::vec![]),
            |m: &mut MeasurementMap| {
                m.authorized_by = Some(alloc::vec![CryptoKey::Bytes(alloc::vec![1])])
            },
            |m: &mut MeasurementMap| m.mval.digests = None,
            |m: &mut MeasurementMap| m.mval.digests = Some(alloc::vec![]),
            |m: &mut MeasurementMap| m.mval.digests.as_mut().unwrap().pop().map(|_| ()).unwrap(),
            |m: &mut MeasurementMap| m.mval.cryptokeys = None,
            |m: &mut MeasurementMap| m.mval.cryptokeys.as_mut().unwrap().reverse(),
            |m: &mut MeasurementMap| m.mval.integrity_registers = None,
            |m: &mut MeasurementMap| {
                m.mval.integrity_registers = Some(IntegrityRegisters(BTreeMap::new()))
            },
            |m: &mut MeasurementMap| m.mval.svn = Some(SvnChoice::ExactValue(1)),
            |m: &mut MeasurementMap| m.mval.svn = Some(SvnChoice::MinValue(1)),
            |m: &mut MeasurementMap| m.mval.raw_value = Some(RawValueChoice::Bytes(alloc::vec![1])),
            |m: &mut MeasurementMap| {
                m.mval.raw_value = Some(RawValueChoice::Masked {
                    value: alloc::vec![1],
                    mask: alloc::vec![1],
                })
            },
            |m: &mut MeasurementMap| m.mval.flags = Some(flags(Some(true))),
            |m: &mut MeasurementMap| m.mval.flags = Some(flags(Some(false))),
            |m: &mut MeasurementMap| {
                m.mval.text = Some(TextMatcher::Set(alloc::vec!["a".into(), "b".into()]))
            },
            |m: &mut MeasurementMap| m.mval.text = Some(TextMatcher::Exact("a".into())),
            |m: &mut MeasurementMap| m.mval.serial_number = Some("1".into()),
            |m: &mut MeasurementMap| m.mval.name = Some("1".into()),
            |m: &mut MeasurementMap| {
                m.mval.extra_entries.insert(10001, Value::Null);
            },
        ] {
            let mut changed = original.clone();
            edit(&mut changed);
            measurements.push(changed);
        }
        for bits in [
            0.0f64.to_bits(),
            (-0.0f64).to_bits(),
            f64::NAN.to_bits(),
            f64::NAN.to_bits() ^ 1,
        ] {
            let mut changed = original.clone();
            changed.mval.number = Some(NumberMatcher::Set(alloc::vec![
                Number::Float(f64::from_bits(bits)),
                Number::Int(1)
            ]));
            measurements.push(changed);
        }
        let mut lists: Vec<_> = measurements
            .iter()
            .map(|measurement| alloc::vec![measurement.clone()])
            .collect();
        lists.extend([
            alloc::vec![measurements[0].clone(), measurements[1].clone()],
            alloc::vec![measurements[1].clone(), measurements[0].clone()],
            alloc::vec![measurements[0].clone(), measurements[2].clone()],
            alloc::vec![measurements[2].clone(), measurements[0].clone()],
        ]);
        let projections: Vec<_> = lists
            .iter()
            .map(|measurements| ComparisonProjection::measurements(measurements).unwrap())
            .collect();
        assert_equivalence(&projections);
    }

    #[test]
    fn parent_keys_preserve_ordered_series_and_nested_identity_rules() {
        let environment = EnvironmentMap::for_class("vendor", "model");
        let original = crate::builder::ComidBuilder::new(TagIdChoice::Text("same".into()))
            .add_reference_triple(ReferenceTriple::new(
                environment.clone(),
                alloc::vec![measurement()],
            ))
            .build()
            .unwrap();
        let mut comids = alloc::vec![original.clone()];
        let mut changed_measurement = measurement();
        changed_measurement.mval.name = Some("changed".into());
        let record =
            |measurements| ConditionalSeriesRecord::new(measurements, alloc::vec![measurement()]);
        let ces = ConditionalEndorsementSeriesTriple::new(
            CesCommonCondition {
                environment: environment.clone(),
                claims_list: alloc::vec![measurement()],
                authorized_by: None,
            },
            alloc::vec![
                record(alloc::vec![measurement()]),
                record(alloc::vec![changed_measurement.clone()])
            ],
        );
        for reverse in [false, true] {
            let mut changed = original.clone();
            let records = if reverse {
                alloc::vec![ces.series()[1].clone(), ces.series()[0].clone()]
            } else {
                ces.series().to_vec()
            };
            changed.triples.conditional_endorsement_series =
                Some(alloc::vec![ConditionalEndorsementSeriesTriple::new(
                    ces.common_condition().clone(),
                    records
                )]);
            comids.push(changed);
        }
        let mut shortened = comids[1].clone();
        shortened.triples.conditional_endorsement_series =
            Some(alloc::vec![ConditionalEndorsementSeriesTriple::new(
                ces.common_condition().clone(),
                alloc::vec![ces.series()[0].clone()]
            )]);
        comids.push(shortened);
        let mut conditional = original.clone();
        conditional.triples.conditional_endorsement =
            Some(alloc::vec![ConditionalEndorsementTriple(
                alloc::vec![StatefulEnvironmentRecord(
                    environment.clone(),
                    alloc::vec![measurement()]
                )],
                alloc::vec![EndorsedTriple(
                    environment.clone(),
                    alloc::vec![changed_measurement]
                )],
            )]);
        comids.push(conditional);
        for keys in [
            alloc::vec![CryptoKey::Bytes(alloc::vec![1])],
            alloc::vec![CryptoKey::Bytes(alloc::vec![2])],
        ] {
            let mut opaque = original.clone();
            opaque.triples.identity_triples =
                Some(alloc::vec![IdentityTriple(environment.clone(), keys, None)]);
            comids.push(opaque);
        }
        let projections: Vec<_> = comids
            .iter()
            .map(|comid| ComparisonProjection::comid(comid).unwrap())
            .collect();
        assert_equivalence(&projections);
    }
}
