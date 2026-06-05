// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Per-key operator evaluator for the Intel CoRIM profile.
//!
//! Given a reference value and an evidence value both keyed by an
//! Intel-defined `measurement-values-map` extension key (see
//! [`crate::profile::intel::intel_mval_name`]), this module decides
//! whether the evidence satisfies the reference under v07 §8.2 / §9
//! semantics.
//!
//! ## Per-key verdicts
//!
//! The reference may be a bare CBOR value or one of the five operator-
//! shaped tags decoded by [`Expression`]:
//!
//! | Reference shape                        | Verdict semantics                              |
//! |----------------------------------------|------------------------------------------------|
//! | bare value                             | exact CBOR equality with evidence (§9)         |
//! | numeric (`eq`/`gt`/`ge`/`lt`/`le`)     | promote both sides to `f64`, compare           |
//! | set-of-tstr (`mem`/`nmem`)             | string equality membership (§9.2.1)            |
//! | set-of-digests (`mem`/`nmem`)          | digest equality membership (§9.2.2)            |
//! | `tagged-int-range`                     | `min <= ev <= max` (open bounds skip the side) |
//! | `tagged-min-svn`                       | `ev >= min`                                    |
//! | `tagged-masked-raw-value`              | `(ev & mask) == (value & mask)` (bytewise)     |
//!
//! ## Failure policy
//!
//! Cases that the evaluator cannot complete return [`Verdict::Fail`]:
//! malformed expression bodies, operand-type mismatches, evidence that
//! cannot be coerced to the comparison domain. The conservative
//! interpretation of "couldn't decode" as Fail follows the RATS
//! verifier guidance that an unrecognised reference value MUST NOT be
//! silently dropped.

use crate::cbor::value::Value;
#[allow(unused_imports)]
use crate::nostd_prelude::*;
use crate::profile::MatchContext;
use crate::types::tags::{TAG_BYTES, TAG_INT_RANGE, TAG_MASKED_RAW_VALUE, TAG_MIN_SVN};

use super::expression::{
    Expression, Numeric, NumericOp, SetOp, TAG_INTEL_EXPRESSION, TAG_INTEL_SET_DIGEST_EXPRESSION,
    TAG_INTEL_SET_TSTR_EXPRESSION,
};

/// Outcome of evaluating one (reference, evidence) pair for a single
/// Intel `extra_entries` key.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Verdict {
    /// Evidence satisfies the reference.
    Pass,
    /// Evidence violates the reference (or the reference is
    /// unintelligible — see module docs for the fail-closed rationale).
    Fail,
}

/// Evaluate one Intel-keyed `(reference, evidence)` pair.
///
/// `key` is the Intel `measurement-values-map` extension code point
/// (e.g. `MVAL_TEE_TCBDATE = -72`); per-key normalization passes
/// (currently only tcbdate) inspect it to route to specialised
/// comparators.
pub(super) fn evaluate_one_key(
    key: i64,
    reference: &Value,
    evidence: &Value,
    _ctx: &MatchContext,
) -> Verdict {
    // tee.tcbdate (§8.3.4) has five equivalent point-in-time encodings
    // plus a period form; normalize both sides before comparing.
    if key == super::MVAL_TEE_TCBDATE {
        return super::tcbdate::match_tcbdate(reference, evidence);
    }

    // Operator-shaped reference (any of the five recognised tags).
    if let Value::Tag(t, _) = reference {
        if matches!(
            *t,
            TAG_INTEL_EXPRESSION
                | TAG_INTEL_SET_DIGEST_EXPRESSION
                | TAG_INTEL_SET_TSTR_EXPRESSION
                | TAG_INT_RANGE
                | TAG_MIN_SVN
                | TAG_MASKED_RAW_VALUE
        ) {
            return match Expression::from_tag(reference) {
                Ok(expr) => evaluate_expression(&expr, evidence),
                Err(_) => Verdict::Fail,
            };
        }
    }
    // Bare value — exact CBOR equality (§9 baseline matching).
    if reference == evidence {
        Verdict::Pass
    } else {
        Verdict::Fail
    }
}

fn evaluate_expression(e: &Expression, ev: &Value) -> Verdict {
    match e {
        Expression::Numeric { op, value } => match numeric_evidence(ev) {
            Some(ev_num) => cmp_numeric(*op, ev_num, value),
            None => Verdict::Fail,
        },
        Expression::SetOfTstr { op, members } => {
            let ev_text = match ev {
                Value::Text(t) => t.as_str(),
                _ => return Verdict::Fail,
            };
            let present = members.iter().any(|m| m == ev_text);
            match op {
                SetOp::Member => bool_verdict(present),
                SetOp::NotMember => bool_verdict(!present),
            }
        }
        Expression::SetOfDigests { op, members } => {
            let present = members.iter().any(|m| m == ev);
            match op {
                SetOp::Member => bool_verdict(present),
                SetOp::NotMember => bool_verdict(!present),
            }
        }
        Expression::IntRange { min, max } => match integer_evidence(ev) {
            Some(ev_n) => {
                let lo_ok = min.map(|lo| ev_n >= lo).unwrap_or(true);
                let hi_ok = max.map(|hi| ev_n <= hi).unwrap_or(true);
                bool_verdict(lo_ok && hi_ok)
            }
            None => Verdict::Fail,
        },
        Expression::MinSvn(min) => match integer_evidence(ev) {
            Some(ev_n) if ev_n >= 0 => {
                let ev_u = match u64::try_from(ev_n) {
                    Ok(v) => v,
                    Err(_) => return Verdict::Fail,
                };
                bool_verdict(ev_u >= *min)
            }
            _ => Verdict::Fail,
        },
        Expression::MaskedRawValue { value, mask } => match bytes_evidence(ev) {
            Some(ev_bytes) => masked_eq(ev_bytes, value, mask),
            None => Verdict::Fail,
        },
    }
}

/// Promote a CBOR evidence value to `f64` for numeric comparison.
/// Accepts `Integer`, `Float`, and `#6.1(integer/float)` (the RFC 8949
/// epoch-time tag, which the spec permits as a numeric operand).
fn numeric_evidence(v: &Value) -> Option<f64> {
    match v {
        Value::Integer(n) => Some(*n as f64),
        Value::Float(f) => Some(*f),
        Value::Tag(1, inner) => numeric_evidence(inner.as_ref()),
        _ => None,
    }
}

/// Extract an integer evidence value (for int-range / min-svn). Accepts
/// `Integer` (signed or unsigned within `i128`). Excludes float and
/// other types — int-range / min-svn are integer-domain operators.
fn integer_evidence(v: &Value) -> Option<i128> {
    match v {
        Value::Integer(n) => Some(*n),
        // tagged-svn = #6.552(svn) — accept the tag wrapper as well, so
        // an evidence-side SVN encoded as `#6.552(uint)` compares
        // correctly against a `tagged-min-svn` or `tagged-int-range`
        // reference. Other tag wrappers are not unwrapped here; they
        // are out of scope for integer comparison.
        Value::Tag(crate::types::tags::TAG_SVN, inner) => match inner.as_ref() {
            Value::Integer(n) => Some(*n),
            _ => None,
        },
        _ => None,
    }
}

fn numeric_ref_as_f64(n: &Numeric) -> f64 {
    match n {
        Numeric::Int(i) => *i as f64,
        Numeric::Float(f) => *f,
    }
}
fn cmp_numeric(op: NumericOp, ev: f64, refv: &Numeric) -> Verdict {
    let r = numeric_ref_as_f64(refv);
    if ev.is_nan() || r.is_nan() {
        // NaN compares false under every operator — fail-closed.
        return Verdict::Fail;
    }
    let outcome = match op {
        NumericOp::Eq => ev == r,
        NumericOp::Gt => ev > r,
        NumericOp::Ge => ev >= r,
        NumericOp::Lt => ev < r,
        NumericOp::Le => ev <= r,
    };
    bool_verdict(outcome)
}

/// Extract a byte-string evidence value. Accepts bare `bstr` (the
/// `~tagged-bytes` form) and `#6.560(bstr)` (`tagged-bytes` from base
/// CoRIM). Both are valid encodings of `$masked-value-type` on the
/// evidence side.
fn bytes_evidence(v: &Value) -> Option<&[u8]> {
    match v {
        Value::Bytes(b) => Some(b.as_slice()),
        Value::Tag(TAG_BYTES, inner) => match inner.as_ref() {
            Value::Bytes(b) => Some(b.as_slice()),
            _ => None,
        },
        _ => None,
    }
}

/// Mask-aware byte comparison: `(ev & mask) == (value & mask)`.
/// All three slices must have the same length (the `tagged-masked-raw-value`
/// CDDL does not specify a length-coercion rule, so we fail-closed
/// rather than zero-padding).
fn masked_eq(evidence: &[u8], value: &[u8], mask: &[u8]) -> Verdict {
    if evidence.len() != mask.len() || value.len() != mask.len() {
        return Verdict::Fail;
    }
    let matches = evidence
        .iter()
        .zip(value.iter())
        .zip(mask.iter())
        .all(|((e, v), m)| (e & m) == (v & m));
    bool_verdict(matches)
}

fn bool_verdict(b: bool) -> Verdict {
    if b {
        Verdict::Pass
    } else {
        Verdict::Fail
    }
}

/// Combine per-key verdicts into the overall Profile verdict.
///
/// Returns:
/// - `Some(true)`  — at least one key produced Pass and none Failed.
/// - `Some(false)` — at least one key Failed.
/// - `None`        — no keys were evaluated (caller defers to core).
pub(super) fn combine(verdicts: &[Verdict]) -> Option<bool> {
    let mut had_pass = false;
    for v in verdicts {
        match v {
            Verdict::Fail => return Some(false),
            Verdict::Pass => had_pass = true,
        }
    }
    if had_pass {
        Some(true)
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::profile::intel::expression::{NumericOp, SetOp};

    fn eval_pair(reference: &Value, evidence: &Value) -> Verdict {
        // Use a non-tcbdate key so the generic decoder path runs.
        evaluate_one_key(
            super::super::MVAL_TEE_ISVSVN,
            reference,
            evidence,
            &MatchContext::new(),
        )
    }

    fn numeric_expr(items: Vec<Value>) -> Value {
        Value::Tag(TAG_INTEL_EXPRESSION, Box::new(Value::Array(items)))
    }
    fn set_tstr_expr(items: Vec<Value>) -> Value {
        Value::Tag(TAG_INTEL_SET_TSTR_EXPRESSION, Box::new(Value::Array(items)))
    }
    fn set_digest_expr(items: Vec<Value>) -> Value {
        Value::Tag(
            TAG_INTEL_SET_DIGEST_EXPRESSION,
            Box::new(Value::Array(items)),
        )
    }
    fn int_range_expr(min: Value, max: Value) -> Value {
        Value::Tag(TAG_INT_RANGE, Box::new(Value::Array(vec![min, max])))
    }
    fn min_svn_expr(v: u64) -> Value {
        Value::Tag(TAG_MIN_SVN, Box::new(Value::Integer(v as i128)))
    }

    // -- evaluate_one_key: bare values -------------------------------------

    #[test]
    fn bare_text_equal_passes() {
        assert_eq!(
            eval_pair(&Value::Text("Intel".into()), &Value::Text("Intel".into())),
            Verdict::Pass
        );
    }

    #[test]
    fn bare_text_unequal_fails() {
        assert_eq!(
            eval_pair(&Value::Text("Intel".into()), &Value::Text("AMD".into())),
            Verdict::Fail
        );
    }

    #[test]
    fn bare_bytes_equal_passes() {
        let v = Value::Bytes(vec![1, 2, 3]);
        assert_eq!(eval_pair(&v, &v), Verdict::Pass);
    }

    // -- numeric ------------------------------------------------------------

    #[test]
    fn numeric_ge_passes_on_equal_and_greater() {
        let r = numeric_expr(vec![Value::Integer(2), Value::Integer(5)]); // ge 5
        assert_eq!(eval_pair(&r, &Value::Integer(5)), Verdict::Pass);
        assert_eq!(eval_pair(&r, &Value::Integer(9)), Verdict::Pass);
    }

    #[test]
    fn numeric_ge_fails_on_lesser() {
        let r = numeric_expr(vec![Value::Integer(2), Value::Integer(5)]);
        assert_eq!(eval_pair(&r, &Value::Integer(4)), Verdict::Fail);
    }

    #[test]
    fn numeric_eq_strict() {
        let r = numeric_expr(vec![Value::Integer(0), Value::Integer(7)]); // eq 7
        assert_eq!(eval_pair(&r, &Value::Integer(7)), Verdict::Pass);
        assert_eq!(eval_pair(&r, &Value::Integer(8)), Verdict::Fail);
    }

    #[test]
    fn numeric_gt_strict() {
        let r = numeric_expr(vec![Value::Integer(1), Value::Integer(5)]); // gt 5
        assert_eq!(eval_pair(&r, &Value::Integer(5)), Verdict::Fail);
        assert_eq!(eval_pair(&r, &Value::Integer(6)), Verdict::Pass);
    }

    #[test]
    fn numeric_lt_le() {
        let lt = numeric_expr(vec![Value::Integer(3), Value::Integer(10)]); // lt 10
        let le = numeric_expr(vec![Value::Integer(4), Value::Integer(10)]); // le 10
        assert_eq!(eval_pair(&lt, &Value::Integer(9)), Verdict::Pass);
        assert_eq!(eval_pair(&lt, &Value::Integer(10)), Verdict::Fail);
        assert_eq!(eval_pair(&le, &Value::Integer(10)), Verdict::Pass);
        assert_eq!(eval_pair(&le, &Value::Integer(11)), Verdict::Fail);
    }

    #[test]
    fn numeric_float_compare() {
        let r = numeric_expr(vec![Value::Integer(2), Value::Float(1.5)]); // ge 1.5
        assert_eq!(eval_pair(&r, &Value::Float(2.0)), Verdict::Pass);
        assert_eq!(eval_pair(&r, &Value::Float(1.0)), Verdict::Fail);
        assert_eq!(eval_pair(&r, &Value::Integer(2)), Verdict::Pass);
    }

    #[test]
    fn numeric_fails_on_non_numeric_evidence() {
        let r = numeric_expr(vec![Value::Integer(2), Value::Integer(0)]);
        assert_eq!(eval_pair(&r, &Value::Text("oops".into())), Verdict::Fail);
    }

    #[test]
    fn numeric_nan_fails() {
        let r = numeric_expr(vec![Value::Integer(2), Value::Float(0.0)]);
        assert_eq!(eval_pair(&r, &Value::Float(f64::NAN)), Verdict::Fail);
    }

    // -- set-of-tstr --------------------------------------------------------

    #[test]
    fn set_tstr_member_pass_and_fail() {
        let r = set_tstr_expr(vec![
            Value::Integer(6),
            Value::Array(vec![
                Value::Text("a".into()),
                Value::Text("b".into()),
                Value::Text("c".into()),
            ]),
        ]);
        assert_eq!(eval_pair(&r, &Value::Text("b".into())), Verdict::Pass);
        assert_eq!(eval_pair(&r, &Value::Text("z".into())), Verdict::Fail);
    }

    #[test]
    fn set_tstr_not_member_pass_and_fail() {
        let r = set_tstr_expr(vec![
            Value::Integer(7),
            Value::Array(vec![
                Value::Text("CVE-A".into()),
                Value::Text("CVE-B".into()),
            ]),
        ]);
        assert_eq!(eval_pair(&r, &Value::Text("CVE-C".into())), Verdict::Pass);
        assert_eq!(eval_pair(&r, &Value::Text("CVE-A".into())), Verdict::Fail);
    }

    #[test]
    fn set_tstr_non_text_evidence_fails() {
        let r = set_tstr_expr(vec![
            Value::Integer(6),
            Value::Array(vec![Value::Text("x".into())]),
        ]);
        assert_eq!(eval_pair(&r, &Value::Integer(1)), Verdict::Fail);
    }

    // -- set-of-digests -----------------------------------------------------

    #[test]
    fn set_digest_member_pass_and_fail() {
        let d1 = Value::Array(vec![Value::Integer(1), Value::Bytes(vec![0u8; 32])]);
        let d2 = Value::Array(vec![Value::Integer(1), Value::Bytes(vec![1u8; 32])]);
        let r = set_digest_expr(vec![
            Value::Integer(6),
            Value::Array(vec![d1.clone(), d2.clone()]),
        ]);
        assert_eq!(eval_pair(&r, &d1), Verdict::Pass);
        let other = Value::Array(vec![Value::Integer(1), Value::Bytes(vec![2u8; 32])]);
        assert_eq!(eval_pair(&r, &other), Verdict::Fail);
    }

    #[test]
    fn set_digest_not_member_excludes_known_bad() {
        let bad = Value::Array(vec![Value::Integer(1), Value::Bytes(vec![0xBAu8; 32])]);
        let r = set_digest_expr(vec![Value::Integer(7), Value::Array(vec![bad.clone()])]);
        let good = Value::Array(vec![Value::Integer(1), Value::Bytes(vec![0xCCu8; 32])]);
        assert_eq!(eval_pair(&r, &good), Verdict::Pass);
        assert_eq!(eval_pair(&r, &bad), Verdict::Fail);
    }

    // -- int-range ----------------------------------------------------------

    #[test]
    fn int_range_closed_inclusive() {
        let r = int_range_expr(Value::Integer(0), Value::Integer(15));
        assert_eq!(eval_pair(&r, &Value::Integer(0)), Verdict::Pass);
        assert_eq!(eval_pair(&r, &Value::Integer(15)), Verdict::Pass);
        assert_eq!(eval_pair(&r, &Value::Integer(7)), Verdict::Pass);
        assert_eq!(eval_pair(&r, &Value::Integer(-1)), Verdict::Fail);
        assert_eq!(eval_pair(&r, &Value::Integer(16)), Verdict::Fail);
    }

    #[test]
    fn int_range_open_min() {
        let r = int_range_expr(Value::Null, Value::Integer(10));
        assert_eq!(eval_pair(&r, &Value::Integer(-1_000_000)), Verdict::Pass);
        assert_eq!(eval_pair(&r, &Value::Integer(10)), Verdict::Pass);
        assert_eq!(eval_pair(&r, &Value::Integer(11)), Verdict::Fail);
    }

    #[test]
    fn int_range_open_max() {
        let r = int_range_expr(Value::Integer(5), Value::Null);
        assert_eq!(eval_pair(&r, &Value::Integer(4)), Verdict::Fail);
        assert_eq!(eval_pair(&r, &Value::Integer(5)), Verdict::Pass);
        assert_eq!(eval_pair(&r, &Value::Integer(1_000_000)), Verdict::Pass);
    }

    #[test]
    fn int_range_rejects_non_int_evidence() {
        let r = int_range_expr(Value::Integer(0), Value::Integer(10));
        assert_eq!(eval_pair(&r, &Value::Float(5.0)), Verdict::Fail);
        assert_eq!(eval_pair(&r, &Value::Text("5".into())), Verdict::Fail);
    }

    #[test]
    fn int_range_accepts_tagged_svn_evidence() {
        let r = int_range_expr(Value::Integer(0), Value::Integer(10));
        let ev = Value::Tag(crate::types::tags::TAG_SVN, Box::new(Value::Integer(5)));
        assert_eq!(eval_pair(&r, &ev), Verdict::Pass);
    }

    // -- min-svn ------------------------------------------------------------

    #[test]
    fn min_svn_pass_when_at_or_above() {
        let r = min_svn_expr(5);
        assert_eq!(eval_pair(&r, &Value::Integer(5)), Verdict::Pass);
        assert_eq!(eval_pair(&r, &Value::Integer(99)), Verdict::Pass);
    }

    #[test]
    fn min_svn_fail_when_below_or_negative() {
        let r = min_svn_expr(5);
        assert_eq!(eval_pair(&r, &Value::Integer(4)), Verdict::Fail);
        assert_eq!(eval_pair(&r, &Value::Integer(-1)), Verdict::Fail);
    }

    #[test]
    fn min_svn_accepts_tagged_svn_evidence() {
        let r = min_svn_expr(3);
        let ev = Value::Tag(crate::types::tags::TAG_SVN, Box::new(Value::Integer(7)));
        assert_eq!(eval_pair(&r, &ev), Verdict::Pass);
    }

    // -- masked-raw-value ---------------------------------------------------

    fn masked_expr(value: Vec<u8>, mask: Vec<u8>) -> Value {
        Value::Tag(
            TAG_MASKED_RAW_VALUE,
            Box::new(Value::Array(vec![Value::Bytes(value), Value::Bytes(mask)])),
        )
    }

    #[test]
    fn masked_raw_value_pass_under_mask() {
        // reference value=0xF0, mask=0xF0  →  upper nibble must be 0xF.
        let r = masked_expr(vec![0xF0], vec![0xF0]);
        assert_eq!(eval_pair(&r, &Value::Bytes(vec![0xFA])), Verdict::Pass);
        assert_eq!(eval_pair(&r, &Value::Bytes(vec![0xF7])), Verdict::Pass);
    }

    #[test]
    fn masked_raw_value_fail_outside_mask() {
        let r = masked_expr(vec![0xF0], vec![0xF0]);
        assert_eq!(eval_pair(&r, &Value::Bytes(vec![0x10])), Verdict::Fail);
    }

    #[test]
    fn masked_raw_value_length_mismatch_fails() {
        let r = masked_expr(vec![0xFF, 0xFF], vec![0xFF, 0xFF]);
        assert_eq!(eval_pair(&r, &Value::Bytes(vec![0xFF])), Verdict::Fail);
    }

    #[test]
    fn masked_raw_value_accepts_tag_560_evidence() {
        // Evidence wrapped as #6.560(bstr) (`tagged-bytes`).
        let r = masked_expr(vec![0xF0], vec![0xF0]);
        let ev = Value::Tag(
            crate::types::tags::TAG_BYTES,
            Box::new(Value::Bytes(vec![0xFA])),
        );
        assert_eq!(eval_pair(&r, &ev), Verdict::Pass);
    }

    #[test]
    fn masked_raw_value_non_bytes_evidence_fails() {
        let r = masked_expr(vec![0x00], vec![0xFF]);
        assert_eq!(eval_pair(&r, &Value::Integer(0)), Verdict::Fail);
    }

    // -- malformed expression fails-closed ---------------------------------

    #[test]
    fn malformed_expression_body_fails() {
        // Tag 60010 wrapping a non-array body → decode error → Fail.
        let r = Value::Tag(TAG_INTEL_EXPRESSION, Box::new(Value::Integer(5)));
        assert_eq!(eval_pair(&r, &Value::Integer(5)), Verdict::Fail);
    }

    #[test]
    fn unknown_operator_fails() {
        let r = numeric_expr(vec![Value::Integer(99), Value::Integer(0)]);
        assert_eq!(eval_pair(&r, &Value::Integer(0)), Verdict::Fail);
    }

    #[test]
    fn unrelated_tag_falls_back_to_equality() {
        // A non-Intel tag is treated as a bare CBOR value: equality
        // works if reference == evidence verbatim.
        let r = Value::Tag(42, Box::new(Value::Integer(5)));
        assert_eq!(eval_pair(&r, &r), Verdict::Pass);
        assert_eq!(eval_pair(&r, &Value::Integer(5)), Verdict::Fail);
    }

    // -- combine ------------------------------------------------------------

    #[test]
    fn combine_all_pass_is_some_true() {
        assert_eq!(combine(&[Verdict::Pass, Verdict::Pass]), Some(true));
    }

    #[test]
    fn combine_any_fail_is_some_false() {
        assert_eq!(combine(&[Verdict::Pass, Verdict::Fail]), Some(false));
    }

    #[test]
    fn combine_empty_is_none() {
        assert_eq!(combine(&[]), None);
    }

    // -- silence dead-code warnings ----------------------------------------

    #[test]
    fn evaluate_one_key_uses_enum_imports() {
        let _ = SetOp::Member;
        let _ = NumericOp::Ge;
    }
}
