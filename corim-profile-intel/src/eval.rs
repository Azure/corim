// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Per-key operator evaluator for the Intel CoRIM profile.
//!
//! Given a reference value and an evidence value both keyed by an
//! Intel-defined `measurement-values-map` extension key (see
//! [`crate::intel_mval_name`]), this module decides whether the
//! evidence satisfies the reference under the operator semantics of
//! `draft-cds-rats-intel-corim-profile-03` §8.1.
//!
//! ## Per-key verdicts
//!
//! The reference may be a bare CBOR value or a `#6.60010(...)`
//! expression. Each of the six classes is handled as follows:
//!
//! | Reference shape                       | Verdict semantics                           |
//! |---------------------------------------|---------------------------------------------|
//! | bare value                            | exact CBOR equality with evidence (§9.1)    |
//! | numeric (`gt`/`ge`/`lt`/`le`)         | promote both sides to `f64`, compare        |
//! | mask-eq (3-element)                   | `(evidence & mask) == (value & mask)`       |
//! | set member / not-member               | CBOR equality membership test               |
//! | set-of-set (subset/superset/disjoint) | [`Verdict::Skip`] — no Intel §8.2 key uses it |
//! | tdate / epoch                         | [`Verdict::Skip`] — time-semantics TBD      |
//!
//! ## Failure policy
//!
//! Cases that the evaluator cannot complete are split into two:
//!
//! - **Skip** ([`Verdict::Skip`]) — the reference uses an
//!   expression class that is structurally valid but for which this
//!   crate intentionally has no semantics yet (tdate, epoch,
//!   set-of-set). The caller treats Skip as "no information from this
//!   key" and combines it with the verdicts of other keys.
//! - **Fail** ([`Verdict::Fail`]) — the reference expression decodes
//!   but the evidence doesn't satisfy it, OR the expression doesn't
//!   even decode, OR the operand types disagree (e.g. numeric op vs
//!   text evidence). The verifier MUST reject in this case.
//!
//! The conservative interpretation of "couldn't decode" as Fail
//! follows the RATS verifier guidance that an unrecognised reference
//! value MUST NOT be silently dropped.

extern crate alloc;

use corim::cbor::value::Value;

use crate::expression::{Expression, Numeric, NumericOp, SetOp, TAG_INTEL_EXPRESSION};

/// Outcome of evaluating one (reference, evidence) pair for a single
/// Intel `extra_entries` key.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Verdict {
    /// Evidence satisfies the reference.
    Pass,
    /// Evidence violates the reference (or the reference is
    /// unintelligible — see module docs for the fail-closed rationale).
    Fail,
    /// The reference uses an expression class this crate does not yet
    /// evaluate (tdate, epoch, set-of-set). The caller folds Skip into
    /// the overall verdict as "no information".
    Skip,
}

/// Evaluate one Intel-keyed `(reference, evidence)` pair.
pub(crate) fn evaluate_one_key(reference: &Value, evidence: &Value) -> Verdict {
    // Tagged expression form.
    if matches!(reference, Value::Tag(t, _) if *t == TAG_INTEL_EXPRESSION) {
        return match Expression::from_tag(reference) {
            Ok(expr) => evaluate_expression(&expr, evidence),
            Err(_) => Verdict::Fail,
        };
    }
    // Bare value — exact CBOR equality (§9.1 baseline matching).
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
        Expression::Mask {
            value: ref_value,
            mask,
        } => match ev {
            Value::Bytes(ev_bytes) => mask_eq(ev_bytes, ref_value, mask),
            _ => Verdict::Fail,
        },
        Expression::Set { op, members } => match op {
            SetOp::Member => bool_verdict(members.iter().any(|m| m == ev)),
            SetOp::NotMember => bool_verdict(!members.iter().any(|m| m == ev)),
        },
        // No Intel §8.2 measurement-values-map key uses set-of-set
        // operators, so we don't bother implementing them yet.
        Expression::SetOfSet { .. } => Verdict::Skip,
        // TODO: time-semantics design — these need an injected clock
        // or per-call "now" parameter that the Profile trait doesn't
        // currently provide. Treated as Skip so the surrounding
        // structural check still happens via core_fields_match.
        Expression::Tdate { .. } | Expression::Epoch { .. } => Verdict::Skip,
    }
}

/// Promote a CBOR evidence value to `f64` for numeric comparison.
/// Accepts `Integer`, `Float`, and `#6.1(integer/float)` (the RFC 8949
/// epoch-time tag, which the spec permits as a numeric operand
/// per §8.1.4.1).
fn numeric_evidence(v: &Value) -> Option<f64> {
    match v {
        Value::Integer(n) => Some(*n as f64),
        Value::Float(f) => Some(*f),
        Value::Tag(1, inner) => numeric_evidence(inner.as_ref()),
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
        NumericOp::Gt => ev > r,
        NumericOp::Ge => ev >= r,
        NumericOp::Lt => ev < r,
        NumericOp::Le => ev <= r,
    };
    bool_verdict(outcome)
}

/// `mask-eq` per §8.1.5: `(evidence & mask) == (reference & mask)`.
/// The two byte strings (evidence and reference) must have the same
/// length as the mask; otherwise the comparison cannot be performed
/// and we fail-closed.
fn mask_eq(evidence: &[u8], reference: &[u8], mask: &[u8]) -> Verdict {
    if evidence.len() != mask.len() || reference.len() != mask.len() {
        return Verdict::Fail;
    }
    let matches = evidence
        .iter()
        .zip(reference.iter())
        .zip(mask.iter())
        .all(|((e, r), m)| (e & m) == (r & m));
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
/// - `Some(true)`  — at least one key produced Pass and none Failed
///   (Skips are tolerated alongside Passes).
/// - `Some(false)` — at least one key Failed.
/// - `None`        — every key produced Skip (caller defers to core).
pub(crate) fn combine(verdicts: &[Verdict]) -> Option<bool> {
    let mut had_pass = false;
    for v in verdicts {
        match v {
            Verdict::Fail => return Some(false),
            Verdict::Pass => had_pass = true,
            Verdict::Skip => {}
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
    use crate::expression::{NumericOp, SetOp};
    use alloc::vec;

    // -- evaluate_one_key: bare values -------------------------------------

    #[test]
    fn bare_text_equal_passes() {
        assert_eq!(
            evaluate_one_key(&Value::Text("Intel".into()), &Value::Text("Intel".into())),
            Verdict::Pass
        );
    }

    #[test]
    fn bare_text_unequal_fails() {
        assert_eq!(
            evaluate_one_key(&Value::Text("Intel".into()), &Value::Text("AMD".into())),
            Verdict::Fail
        );
    }

    #[test]
    fn bare_bytes_equal_passes() {
        let v = Value::Bytes(vec![1, 2, 3]);
        assert_eq!(evaluate_one_key(&v, &v), Verdict::Pass);
    }

    // -- numeric ------------------------------------------------------------

    fn make_expr_tag(body: Value) -> Value {
        Value::Tag(TAG_INTEL_EXPRESSION, alloc::boxed::Box::new(body))
    }

    #[test]
    fn numeric_ge_passes_on_equal() {
        let r = make_expr_tag(Value::Array(vec![Value::Integer(2), Value::Integer(5)])); // ge 5
        assert_eq!(evaluate_one_key(&r, &Value::Integer(5)), Verdict::Pass);
    }

    #[test]
    fn numeric_ge_passes_on_greater() {
        let r = make_expr_tag(Value::Array(vec![Value::Integer(2), Value::Integer(5)]));
        assert_eq!(evaluate_one_key(&r, &Value::Integer(9)), Verdict::Pass);
    }

    #[test]
    fn numeric_ge_fails_on_lesser() {
        let r = make_expr_tag(Value::Array(vec![Value::Integer(2), Value::Integer(5)]));
        assert_eq!(evaluate_one_key(&r, &Value::Integer(4)), Verdict::Fail);
    }

    #[test]
    fn numeric_gt_strict() {
        let r = make_expr_tag(Value::Array(vec![Value::Integer(1), Value::Integer(5)])); // gt 5
        assert_eq!(evaluate_one_key(&r, &Value::Integer(5)), Verdict::Fail);
        assert_eq!(evaluate_one_key(&r, &Value::Integer(6)), Verdict::Pass);
    }

    #[test]
    fn numeric_lt_le() {
        let lt = make_expr_tag(Value::Array(vec![Value::Integer(3), Value::Integer(10)])); // lt 10
        let le = make_expr_tag(Value::Array(vec![Value::Integer(4), Value::Integer(10)])); // le 10
        assert_eq!(evaluate_one_key(&lt, &Value::Integer(9)), Verdict::Pass);
        assert_eq!(evaluate_one_key(&lt, &Value::Integer(10)), Verdict::Fail);
        assert_eq!(evaluate_one_key(&le, &Value::Integer(10)), Verdict::Pass);
        assert_eq!(evaluate_one_key(&le, &Value::Integer(11)), Verdict::Fail);
    }

    #[test]
    fn numeric_float_compare() {
        let r = make_expr_tag(Value::Array(vec![Value::Integer(2), Value::Float(1.5)])); // ge 1.5
        assert_eq!(evaluate_one_key(&r, &Value::Float(2.0)), Verdict::Pass);
        assert_eq!(evaluate_one_key(&r, &Value::Float(1.0)), Verdict::Fail);
        // Integer evidence promoted.
        assert_eq!(evaluate_one_key(&r, &Value::Integer(2)), Verdict::Pass);
    }

    #[test]
    fn numeric_fails_on_non_numeric_evidence() {
        let r = make_expr_tag(Value::Array(vec![Value::Integer(2), Value::Integer(0)]));
        assert_eq!(
            evaluate_one_key(&r, &Value::Text("oops".into())),
            Verdict::Fail
        );
    }

    #[test]
    fn numeric_nan_fails() {
        let r = make_expr_tag(Value::Array(vec![Value::Integer(2), Value::Float(0.0)]));
        assert_eq!(evaluate_one_key(&r, &Value::Float(f64::NAN)), Verdict::Fail);
    }

    // -- mask-eq ------------------------------------------------------------

    fn mask_expr(value: Vec<u8>, mask: Vec<u8>) -> Value {
        make_expr_tag(Value::Array(vec![
            Value::Integer(1), // op=1 with 3 operands = mask-eq
            Value::Bytes(value),
            Value::Bytes(mask),
        ]))
    }

    #[test]
    fn mask_eq_passes_under_mask() {
        // reference = 0xF0, mask = 0xF0  → upper nibble must match 0xF
        let r = mask_expr(vec![0xF0], vec![0xF0]);
        assert_eq!(
            evaluate_one_key(&r, &Value::Bytes(vec![0xFA])),
            Verdict::Pass
        );
        assert_eq!(
            evaluate_one_key(&r, &Value::Bytes(vec![0xF7])),
            Verdict::Pass
        );
    }

    #[test]
    fn mask_eq_fails_outside_mask() {
        let r = mask_expr(vec![0xF0], vec![0xF0]);
        assert_eq!(
            evaluate_one_key(&r, &Value::Bytes(vec![0x10])),
            Verdict::Fail
        );
    }

    #[test]
    fn mask_eq_length_mismatch_fails() {
        let r = mask_expr(vec![0xFF, 0xFF], vec![0xFF, 0xFF]);
        assert_eq!(
            evaluate_one_key(&r, &Value::Bytes(vec![0xFF])),
            Verdict::Fail
        );
    }

    #[test]
    fn mask_eq_non_bytes_evidence_fails() {
        let r = mask_expr(vec![0x00], vec![0xFF]);
        assert_eq!(evaluate_one_key(&r, &Value::Integer(0)), Verdict::Fail);
    }

    // -- set ----------------------------------------------------------------

    fn set_expr(op_code: i64, members: Vec<Value>) -> Value {
        make_expr_tag(Value::Array(vec![
            Value::Integer(op_code as i128),
            Value::Array(members),
        ]))
    }

    #[test]
    fn set_member_pass_and_fail() {
        // op=6 (member), set = {"a","b","c"}
        let r = set_expr(
            6,
            vec![
                Value::Text("a".into()),
                Value::Text("b".into()),
                Value::Text("c".into()),
            ],
        );
        assert_eq!(
            evaluate_one_key(&r, &Value::Text("b".into())),
            Verdict::Pass
        );
        assert_eq!(
            evaluate_one_key(&r, &Value::Text("z".into())),
            Verdict::Fail
        );
    }

    #[test]
    fn set_not_member_pass_and_fail() {
        // op=7 (not-member), set = {1, 2}
        let r = set_expr(7, vec![Value::Integer(1), Value::Integer(2)]);
        assert_eq!(evaluate_one_key(&r, &Value::Integer(3)), Verdict::Pass);
        assert_eq!(evaluate_one_key(&r, &Value::Integer(1)), Verdict::Fail);
    }

    // -- deferred shapes ----------------------------------------------------

    #[test]
    fn tdate_is_skip() {
        let r = make_expr_tag(Value::Array(vec![
            Value::Integer(2), // ge
            Value::Text("2025-01-01T00:00:00Z".into()),
        ]));
        // Per module-level policy: any tdate reference is skipped so
        // the surrounding structural comparison still happens.
        assert_eq!(
            evaluate_one_key(&r, &Value::Text("2026-01-01T00:00:00Z".into())),
            Verdict::Skip
        );
    }

    #[test]
    fn epoch_is_skip() {
        // [op, grace_period, epoch_id] — 3-element epoch form.
        let r = make_expr_tag(Value::Array(vec![
            Value::Integer(2),
            Value::Integer(60),
            Value::Null,
        ]));
        assert_eq!(evaluate_one_key(&r, &Value::Integer(0)), Verdict::Skip);
    }

    // -- malformed expression fails-closed ----------------------------------

    #[test]
    fn malformed_expression_body_fails() {
        // Tag 60010 wrapping a non-array body → decode error → Fail.
        let r = Value::Tag(
            TAG_INTEL_EXPRESSION,
            alloc::boxed::Box::new(Value::Integer(5)),
        );
        assert_eq!(evaluate_one_key(&r, &Value::Integer(5)), Verdict::Fail);
    }

    #[test]
    fn unknown_operator_fails() {
        let r = make_expr_tag(Value::Array(vec![Value::Integer(99), Value::Integer(0)]));
        assert_eq!(evaluate_one_key(&r, &Value::Integer(0)), Verdict::Fail);
    }

    // -- combine ------------------------------------------------------------

    #[test]
    fn combine_all_pass_is_some_true() {
        assert_eq!(combine(&[Verdict::Pass, Verdict::Pass]), Some(true));
    }

    #[test]
    fn combine_any_fail_is_some_false() {
        assert_eq!(
            combine(&[Verdict::Pass, Verdict::Fail, Verdict::Skip]),
            Some(false)
        );
    }

    #[test]
    fn combine_all_skip_is_none() {
        assert_eq!(combine(&[Verdict::Skip, Verdict::Skip]), None);
    }

    #[test]
    fn combine_mixed_pass_skip_is_some_true() {
        assert_eq!(combine(&[Verdict::Skip, Verdict::Pass]), Some(true));
    }

    #[test]
    fn combine_empty_is_none() {
        assert_eq!(combine(&[]), None);
    }

    // -- silence dead-code warnings for the unused enum variant matching ---

    #[test]
    fn evaluate_one_key_uses_set_op_enum() {
        // ensures SetOp import isn't dead.
        let _ = SetOp::Member;
        let _ = NumericOp::Ge;
    }
}
