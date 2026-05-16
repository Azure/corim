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
//! | tdate (`gt`/`ge`/`lt`/`le`)           | parse both sides as RFC 3339, compare epoch |
//! | set-of-set (subset/superset/disjoint) | [`Verdict::Skip`] — no Intel §8.2 key uses it |
//! | epoch (default verifier-current-time) | uses `ctx.now`; Skip when ctx has no clock   |
//! | epoch with alternate `epoch-id`       | [`Verdict::Skip`] — no Intel §8.2 key uses it |
//!
//! ## Failure policy
//!
//! Cases that the evaluator cannot complete are split into two:
//!
//! - **Skip** ([`Verdict::Skip`]) — the reference uses an
//!   expression class that is structurally valid but for which this
//!   crate intentionally has no semantics yet (epoch, set-of-set).
//!   The caller treats Skip as "no information from this
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
use corim::profile::MatchContext;

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
pub(crate) fn evaluate_one_key(reference: &Value, evidence: &Value, ctx: &MatchContext) -> Verdict {
    // Tagged expression form.
    if matches!(reference, Value::Tag(t, _) if *t == TAG_INTEL_EXPRESSION) {
        return match Expression::from_tag(reference) {
            Ok(expr) => evaluate_expression(&expr, evidence, ctx),
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

fn evaluate_expression(e: &Expression, ev: &Value, ctx: &MatchContext) -> Verdict {
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
        // Tdate: compare two RFC 3339 strings as epoch-seconds. The
        // evidence side must be a text string (`tstr` or `#6.0(text)`);
        // anything else fails closed. Sub-second precision is dropped
        // — see `rfc3339_to_epoch_seconds`.
        Expression::Tdate { op, date } => match tdate_evidence(ev) {
            Some(ev_text) => match (
                rfc3339_to_epoch_seconds(date),
                rfc3339_to_epoch_seconds(ev_text),
            ) {
                (Some(ref_secs), Some(ev_secs)) => {
                    cmp_numeric(*op, ev_secs as f64, &Numeric::Int(ref_secs as i128))
                }
                _ => Verdict::Fail,
            },
            None => Verdict::Fail,
        },
        // Epoch (§8.1.4.2): with the default epoch (verifier-current-
        // time), the reference asserts `ev <op> (now - grace_period)`.
        // The decoder always emits the 3-element form for Epoch and
        // sets `epoch_id` to `Some(...)`; the convention `Some(Null)`
        // (or absent) means "default epoch". Any other `epoch_id`
        // value selects an alternate epoch scheme; no Intel §8.2 key
        // uses one, so we Skip rather than guess.
        Expression::Epoch {
            op,
            grace_period,
            epoch_id,
        } => {
            let is_default = matches!(epoch_id, None | Some(Value::Null));
            if !is_default {
                return Verdict::Skip;
            }
            match ctx.now {
                Some(now) => match epoch_evidence(ev) {
                    Some(ev_secs) => {
                        let threshold = now.epoch_secs().saturating_sub(*grace_period);
                        cmp_numeric(*op, ev_secs as f64, &Numeric::Int(threshold as i128))
                    }
                    None => Verdict::Fail,
                },
                None => Verdict::Skip,
            }
        }
    }
}

/// Unwrap epoch evidence to seconds-since-Unix-epoch.
///
/// Accepts (per §8.1.4.2): bare integer, `#6.1(int|float)` (epoch
/// time per RFC 8949 §3.4.2), bare float, or RFC 3339 text (`tstr`
/// or `#6.0(text)`). Floats are truncated; out-of-range or non-
/// finite floats return `None` per the no-`as`-narrowing rule.
fn epoch_evidence(v: &Value) -> Option<i64> {
    match v {
        Value::Integer(n) => i64::try_from(*n).ok(),
        Value::Float(f) => float_to_i64(*f),
        Value::Tag(1, inner) => match inner.as_ref() {
            Value::Integer(n) => i64::try_from(*n).ok(),
            Value::Float(f) => float_to_i64(*f),
            _ => None,
        },
        Value::Text(t) => rfc3339_to_epoch_seconds(t),
        Value::Tag(0, inner) => match inner.as_ref() {
            Value::Text(t) => rfc3339_to_epoch_seconds(t),
            _ => None,
        },
        _ => None,
    }
}

fn float_to_i64(f: f64) -> Option<i64> {
    if f.is_nan() || f.is_infinite() || f < (i64::MIN as f64) || f > (i64::MAX as f64) {
        None
    } else {
        Some(f as i64)
    }
}

/// Unwrap `tdate` evidence to an RFC 3339 `&str`. Accepts bare text
/// (the CDDL allows `tdate / text` in some operand positions) and
/// `#6.0(text)` per RFC 8949 §3.4.1.
fn tdate_evidence(v: &Value) -> Option<&str> {
    match v {
        Value::Text(t) => Some(t.as_str()),
        Value::Tag(0, inner) => match inner.as_ref() {
            Value::Text(t) => Some(t.as_str()),
            _ => None,
        },
        _ => None,
    }
}

/// Parse an RFC 3339 `date-time` string to integer seconds since the
/// Unix epoch.
///
/// Accepts the grammar `YYYY-MM-DDTHH:MM:SS[.frac](Z|[+-]HH:MM)` with
/// `T` permitted in either case (per RFC 3339 §5.6 "NOTE"). Fractional
/// seconds are syntactically accepted but truncated — the spec
/// (§8.1.4.1) does not specify a precision floor for `tdate`
/// operators, and Intel TCB dates are always emitted at second
/// resolution. Returns `None` on any parse failure (out-of-range
/// fields, malformed punctuation, missing offset, etc.).
///
/// Uses the Howard-Hinnant `days_from_civil` algorithm. Valid for
/// the full proleptic Gregorian range; calendar arithmetic is exact.
fn rfc3339_to_epoch_seconds(s: &str) -> Option<i64> {
    let b = s.as_bytes();
    // Minimum is "YYYY-MM-DDTHH:MM:SSZ" = 20 bytes.
    if b.len() < 20 {
        return None;
    }
    let year = parse_n_digits(&b[0..4])?;
    if b[4] != b'-' {
        return None;
    }
    let month = parse_n_digits(&b[5..7])?;
    if b[7] != b'-' {
        return None;
    }
    let day = parse_n_digits(&b[8..10])?;
    if b[10] != b'T' && b[10] != b't' {
        return None;
    }
    let hour = parse_n_digits(&b[11..13])?;
    if b[13] != b':' {
        return None;
    }
    let minute = parse_n_digits(&b[14..16])?;
    if b[16] != b':' {
        return None;
    }
    let second = parse_n_digits(&b[17..19])?;

    // Validate field ranges. Leap seconds (second == 60) are accepted
    // per RFC 3339 §5.6 but coerced down to 59 for epoch arithmetic.
    if !(1..=12).contains(&month)
        || !(1..=31).contains(&day)
        || hour > 23
        || minute > 59
        || second > 60
    {
        return None;
    }
    let second = if second == 60 { 59 } else { second };

    // Skip the optional fractional-seconds run.
    let mut i = 19usize;
    if i < b.len() && b[i] == b'.' {
        i += 1;
        let start = i;
        while i < b.len() && b[i].is_ascii_digit() {
            i += 1;
        }
        if i == start {
            return None; // "." with no digits
        }
    }

    // Time offset: 'Z'/'z' or [+-]HH:MM.
    let offset_secs: i64 = if i < b.len() && (b[i] == b'Z' || b[i] == b'z') {
        if i + 1 != b.len() {
            return None;
        }
        0
    } else if i + 6 == b.len() && (b[i] == b'+' || b[i] == b'-') {
        let sign: i64 = if b[i] == b'+' { 1 } else { -1 };
        let oh = parse_n_digits(&b[i + 1..i + 3])?;
        if b[i + 3] != b':' {
            return None;
        }
        let om = parse_n_digits(&b[i + 4..i + 6])?;
        if oh > 23 || om > 59 {
            return None;
        }
        sign * (oh * 3600 + om * 60)
    } else {
        return None;
    };

    // Howard-Hinnant civil-to-days (proleptic Gregorian, day 0 = 1970-01-01).
    // Treat Jan/Feb as months 13/14 of the previous year so leap day
    // falls at end-of-year.
    let (y, m) = if month <= 2 {
        (year - 1, month + 12)
    } else {
        (year, month)
    };
    let era = if y >= 0 { y / 400 } else { (y - 399) / 400 };
    let yoe = y - era * 400; // [0, 399]
    let doy = (153 * (m - 3) + 2) / 5 + day - 1; // [0, 365]
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy; // [0, 146096]
    let days_since_epoch = era * 146097 + doe - 719468;

    let total = days_since_epoch * 86400 + hour * 3600 + minute * 60 + second - offset_secs;
    Some(total)
}

/// Parse a fixed-width ASCII decimal slice into an `i64`. Returns
/// `None` if any byte is non-digit.
fn parse_n_digits(b: &[u8]) -> Option<i64> {
    let mut n: i64 = 0;
    for &byte in b {
        if !byte.is_ascii_digit() {
            return None;
        }
        n = n * 10 + i64::from(byte - b'0');
    }
    Some(n)
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

    /// Default-context wrapper so existing tests stay 2-arg.
    /// The `MatchContext::new()` default has `now = None`, which
    /// makes Epoch expressions Skip without affecting any other op.
    fn eval_pair(reference: &Value, evidence: &Value) -> Verdict {
        evaluate_one_key(reference, evidence, &MatchContext::new())
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

    fn make_expr_tag(body: Value) -> Value {
        Value::Tag(TAG_INTEL_EXPRESSION, alloc::boxed::Box::new(body))
    }

    #[test]
    fn numeric_ge_passes_on_equal() {
        let r = make_expr_tag(Value::Array(vec![Value::Integer(2), Value::Integer(5)])); // ge 5
        assert_eq!(eval_pair(&r, &Value::Integer(5)), Verdict::Pass);
    }

    #[test]
    fn numeric_ge_passes_on_greater() {
        let r = make_expr_tag(Value::Array(vec![Value::Integer(2), Value::Integer(5)]));
        assert_eq!(eval_pair(&r, &Value::Integer(9)), Verdict::Pass);
    }

    #[test]
    fn numeric_ge_fails_on_lesser() {
        let r = make_expr_tag(Value::Array(vec![Value::Integer(2), Value::Integer(5)]));
        assert_eq!(eval_pair(&r, &Value::Integer(4)), Verdict::Fail);
    }

    #[test]
    fn numeric_gt_strict() {
        let r = make_expr_tag(Value::Array(vec![Value::Integer(1), Value::Integer(5)])); // gt 5
        assert_eq!(eval_pair(&r, &Value::Integer(5)), Verdict::Fail);
        assert_eq!(eval_pair(&r, &Value::Integer(6)), Verdict::Pass);
    }

    #[test]
    fn numeric_lt_le() {
        let lt = make_expr_tag(Value::Array(vec![Value::Integer(3), Value::Integer(10)])); // lt 10
        let le = make_expr_tag(Value::Array(vec![Value::Integer(4), Value::Integer(10)])); // le 10
        assert_eq!(eval_pair(&lt, &Value::Integer(9)), Verdict::Pass);
        assert_eq!(eval_pair(&lt, &Value::Integer(10)), Verdict::Fail);
        assert_eq!(eval_pair(&le, &Value::Integer(10)), Verdict::Pass);
        assert_eq!(eval_pair(&le, &Value::Integer(11)), Verdict::Fail);
    }

    #[test]
    fn numeric_float_compare() {
        let r = make_expr_tag(Value::Array(vec![Value::Integer(2), Value::Float(1.5)])); // ge 1.5
        assert_eq!(eval_pair(&r, &Value::Float(2.0)), Verdict::Pass);
        assert_eq!(eval_pair(&r, &Value::Float(1.0)), Verdict::Fail);
        // Integer evidence promoted.
        assert_eq!(eval_pair(&r, &Value::Integer(2)), Verdict::Pass);
    }

    #[test]
    fn numeric_fails_on_non_numeric_evidence() {
        let r = make_expr_tag(Value::Array(vec![Value::Integer(2), Value::Integer(0)]));
        assert_eq!(eval_pair(&r, &Value::Text("oops".into())), Verdict::Fail);
    }

    #[test]
    fn numeric_nan_fails() {
        let r = make_expr_tag(Value::Array(vec![Value::Integer(2), Value::Float(0.0)]));
        assert_eq!(eval_pair(&r, &Value::Float(f64::NAN)), Verdict::Fail);
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
        assert_eq!(eval_pair(&r, &Value::Bytes(vec![0xFA])), Verdict::Pass);
        assert_eq!(eval_pair(&r, &Value::Bytes(vec![0xF7])), Verdict::Pass);
    }

    #[test]
    fn mask_eq_fails_outside_mask() {
        let r = mask_expr(vec![0xF0], vec![0xF0]);
        assert_eq!(eval_pair(&r, &Value::Bytes(vec![0x10])), Verdict::Fail);
    }

    #[test]
    fn mask_eq_length_mismatch_fails() {
        let r = mask_expr(vec![0xFF, 0xFF], vec![0xFF, 0xFF]);
        assert_eq!(eval_pair(&r, &Value::Bytes(vec![0xFF])), Verdict::Fail);
    }

    #[test]
    fn mask_eq_non_bytes_evidence_fails() {
        let r = mask_expr(vec![0x00], vec![0xFF]);
        assert_eq!(eval_pair(&r, &Value::Integer(0)), Verdict::Fail);
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
        assert_eq!(eval_pair(&r, &Value::Text("b".into())), Verdict::Pass);
        assert_eq!(eval_pair(&r, &Value::Text("z".into())), Verdict::Fail);
    }

    #[test]
    fn set_not_member_pass_and_fail() {
        // op=7 (not-member), set = {1, 2}
        let r = set_expr(7, vec![Value::Integer(1), Value::Integer(2)]);
        assert_eq!(eval_pair(&r, &Value::Integer(3)), Verdict::Pass);
        assert_eq!(eval_pair(&r, &Value::Integer(1)), Verdict::Fail);
    }

    // -- epoch --------------------------------------------------------------

    fn epoch_expr_default(op_code: i64, grace: i64) -> Value {
        // The decoder only emits Epoch from the 3-element form. Use
        // `Value::Null` for the epoch-id slot to signal "default
        // epoch" (verifier-current-time).
        make_expr_tag(Value::Array(vec![
            Value::Integer(op_code as i128),
            Value::Integer(grace as i128),
            Value::Null,
        ]))
    }

    fn ctx_at(epoch_secs: i64) -> MatchContext {
        MatchContext::new().with_now(corim::types::common::CborTime::new(epoch_secs))
    }

    #[test]
    fn epoch_with_explicit_alternate_epoch_id_is_skip() {
        // Non-Null, non-default epoch-id selects an alternate scheme.
        // No Intel §8.2 measurement key uses this; we Skip rather
        // than guess at semantics.
        let r = make_expr_tag(Value::Array(vec![
            Value::Integer(2),
            Value::Integer(60),
            Value::Text("alt".into()),
        ]));
        assert_eq!(
            evaluate_one_key(&r, &Value::Integer(0), &ctx_at(1_000_000_000)),
            Verdict::Skip
        );
    }

    #[test]
    fn epoch_default_without_clock_is_skip() {
        // Verifier didn't supply a clock → Skip (rather than guess).
        let r = epoch_expr_default(2, 60);
        assert_eq!(eval_pair(&r, &Value::Integer(0)), Verdict::Skip);
    }

    #[test]
    fn epoch_default_ge_pass_when_evidence_within_grace() {
        // now=1_000_000_000, grace=60 → threshold=999_999_940;
        // ev=999_999_950 ≥ threshold → Pass.
        let r = epoch_expr_default(2, 60); // op=ge
        let ev = Value::Integer(999_999_950);
        assert_eq!(
            evaluate_one_key(&r, &ev, &ctx_at(1_000_000_000)),
            Verdict::Pass
        );
    }

    #[test]
    fn epoch_default_ge_fail_when_evidence_too_old() {
        // ev=999_999_900 < threshold=999_999_940 → Fail.
        let r = epoch_expr_default(2, 60);
        let ev = Value::Integer(999_999_900);
        assert_eq!(
            evaluate_one_key(&r, &ev, &ctx_at(1_000_000_000)),
            Verdict::Fail
        );
    }

    #[test]
    fn epoch_evidence_accepts_tag_1_int() {
        // RFC 8949 §3.4.2 epoch-time tag wrapping an integer.
        let r = epoch_expr_default(2, 60);
        let ev = Value::Tag(1, alloc::boxed::Box::new(Value::Integer(999_999_950)));
        assert_eq!(
            evaluate_one_key(&r, &ev, &ctx_at(1_000_000_000)),
            Verdict::Pass
        );
    }

    #[test]
    fn epoch_evidence_accepts_rfc3339_text() {
        // 2025-01-01T00:00:00Z = 1735689600 epoch seconds; with
        // grace=60 and now=1735689700 the threshold is 1735689640
        // and evidence (1735689600) is 40s too old → Fail.
        let r = epoch_expr_default(2, 60);
        let ev = Value::Text("2025-01-01T00:00:00Z".into());
        assert_eq!(
            evaluate_one_key(&r, &ev, &ctx_at(1735689700)),
            Verdict::Fail
        );
        // …but with now exactly equal the evidence is in-window.
        assert_eq!(
            evaluate_one_key(&r, &ev, &ctx_at(1735689600)),
            Verdict::Pass
        );
    }

    #[test]
    fn epoch_evidence_accepts_tag_0_text() {
        let r = epoch_expr_default(2, 60);
        let ev = Value::Tag(
            0,
            alloc::boxed::Box::new(Value::Text("2025-01-01T00:00:00Z".into())),
        );
        assert_eq!(
            evaluate_one_key(&r, &ev, &ctx_at(1735689600)),
            Verdict::Pass
        );
    }

    #[test]
    fn epoch_garbage_evidence_fails() {
        let r = epoch_expr_default(2, 60);
        assert_eq!(
            evaluate_one_key(&r, &Value::Bytes(vec![1, 2, 3]), &ctx_at(1_000_000_000)),
            Verdict::Fail
        );
    }

    #[test]
    fn epoch_grace_saturates_at_min() {
        // i64::MAX grace_period would underflow `now - grace`; the
        // saturating_sub keeps the threshold at i64::MIN, which any
        // realistic evidence beats.
        let r = epoch_expr_default(2, i64::MAX);
        assert_eq!(
            evaluate_one_key(&r, &Value::Integer(0), &ctx_at(1_000)),
            Verdict::Pass
        );
    }

    // -- tdate --------------------------------------------------------------

    fn tdate_expr(op_code: i64, date: &str) -> Value {
        make_expr_tag(Value::Array(vec![
            Value::Integer(op_code as i128),
            Value::Text(date.into()),
        ]))
    }

    #[test]
    fn tdate_ge_passes_on_equal_and_later() {
        let r = tdate_expr(2, "2025-01-01T00:00:00Z"); // ge
        assert_eq!(
            eval_pair(&r, &Value::Text("2025-01-01T00:00:00Z".into())),
            Verdict::Pass
        );
        assert_eq!(
            eval_pair(&r, &Value::Text("2026-01-01T00:00:00Z".into())),
            Verdict::Pass
        );
    }

    #[test]
    fn tdate_ge_fails_on_earlier() {
        let r = tdate_expr(2, "2025-01-01T00:00:00Z");
        assert_eq!(
            eval_pair(&r, &Value::Text("2024-12-31T23:59:59Z".into())),
            Verdict::Fail
        );
    }

    #[test]
    fn tdate_gt_strict() {
        let r = tdate_expr(1, "2025-01-01T00:00:00Z"); // gt
        assert_eq!(
            eval_pair(&r, &Value::Text("2025-01-01T00:00:00Z".into())),
            Verdict::Fail
        );
        assert_eq!(
            eval_pair(&r, &Value::Text("2025-01-01T00:00:01Z".into())),
            Verdict::Pass
        );
    }

    #[test]
    fn tdate_lt_le() {
        let lt = tdate_expr(3, "2030-01-01T00:00:00Z");
        let le = tdate_expr(4, "2030-01-01T00:00:00Z");
        assert_eq!(
            eval_pair(&lt, &Value::Text("2029-12-31T23:59:59Z".into())),
            Verdict::Pass
        );
        assert_eq!(
            eval_pair(&lt, &Value::Text("2030-01-01T00:00:00Z".into())),
            Verdict::Fail
        );
        assert_eq!(
            eval_pair(&le, &Value::Text("2030-01-01T00:00:00Z".into())),
            Verdict::Pass
        );
    }

    #[test]
    fn tdate_evidence_accepts_tag_0_wrap() {
        // Evidence wrapped as #6.0(text) per RFC 8949 §3.4.1.
        let r = tdate_expr(2, "2025-01-01T00:00:00Z");
        let ev = Value::Tag(
            0,
            alloc::boxed::Box::new(Value::Text("2026-01-01T00:00:00Z".into())),
        );
        assert_eq!(eval_pair(&r, &ev), Verdict::Pass);
    }

    #[test]
    fn tdate_handles_positive_offset() {
        // "2025-01-01T05:00:00+05:00" == "2025-01-01T00:00:00Z"
        let r = tdate_expr(2, "2025-01-01T05:00:00+05:00");
        assert_eq!(
            eval_pair(&r, &Value::Text("2025-01-01T00:00:00Z".into())),
            Verdict::Pass
        );
    }

    #[test]
    fn tdate_handles_negative_offset() {
        // "2025-01-01T00:00:00-05:00" == "2025-01-01T05:00:00Z"
        let r = tdate_expr(2, "2025-01-01T00:00:00-05:00");
        assert_eq!(
            eval_pair(&r, &Value::Text("2025-01-01T05:00:00Z".into())),
            Verdict::Pass
        );
        assert_eq!(
            eval_pair(&r, &Value::Text("2025-01-01T04:59:59Z".into())),
            Verdict::Fail
        );
    }

    #[test]
    fn tdate_truncates_fractional_seconds() {
        let r = tdate_expr(2, "2025-01-01T00:00:00.500Z");
        // Both ref and ev are truncated to second resolution; equality holds.
        assert_eq!(
            eval_pair(&r, &Value::Text("2025-01-01T00:00:00.999Z".into())),
            Verdict::Pass
        );
    }

    #[test]
    fn tdate_non_text_evidence_fails() {
        let r = tdate_expr(2, "2025-01-01T00:00:00Z");
        assert_eq!(eval_pair(&r, &Value::Integer(1735689600)), Verdict::Fail);
    }

    #[test]
    fn tdate_malformed_evidence_fails() {
        let r = tdate_expr(2, "2025-01-01T00:00:00Z");
        assert_eq!(
            eval_pair(&r, &Value::Text("not a date".into())),
            Verdict::Fail
        );
    }

    #[test]
    fn tdate_malformed_reference_fails() {
        let r = tdate_expr(2, "garbage");
        assert_eq!(
            eval_pair(&r, &Value::Text("2025-01-01T00:00:00Z".into())),
            Verdict::Fail
        );
    }

    // -- rfc3339 parser -----------------------------------------------------

    #[test]
    fn parses_unix_epoch_origin() {
        assert_eq!(rfc3339_to_epoch_seconds("1970-01-01T00:00:00Z"), Some(0));
    }

    #[test]
    fn parses_year_2000() {
        // 2000-01-01T00:00:00Z = 946684800
        assert_eq!(
            rfc3339_to_epoch_seconds("2000-01-01T00:00:00Z"),
            Some(946684800)
        );
    }

    #[test]
    fn parses_leap_day() {
        // 2024-02-29 is valid; 2024-03-01 is one day later.
        let leap = rfc3339_to_epoch_seconds("2024-02-29T00:00:00Z").unwrap();
        let next = rfc3339_to_epoch_seconds("2024-03-01T00:00:00Z").unwrap();
        assert_eq!(next - leap, 86400);
    }

    #[test]
    fn parses_lowercase_t() {
        // RFC 3339 §5.6 NOTE permits lowercase t.
        assert_eq!(
            rfc3339_to_epoch_seconds("2025-01-01t00:00:00Z"),
            rfc3339_to_epoch_seconds("2025-01-01T00:00:00Z"),
        );
    }

    #[test]
    fn parses_lowercase_z() {
        assert_eq!(
            rfc3339_to_epoch_seconds("2025-01-01T00:00:00z"),
            rfc3339_to_epoch_seconds("2025-01-01T00:00:00Z"),
        );
    }

    #[test]
    fn rejects_short_string() {
        assert_eq!(rfc3339_to_epoch_seconds("2025"), None);
    }

    #[test]
    fn rejects_missing_offset() {
        assert_eq!(rfc3339_to_epoch_seconds("2025-01-01T00:00:00"), None);
    }

    #[test]
    fn rejects_bad_punctuation() {
        assert_eq!(rfc3339_to_epoch_seconds("2025/01/01T00:00:00Z"), None);
    }

    #[test]
    fn rejects_out_of_range_month() {
        assert_eq!(rfc3339_to_epoch_seconds("2025-13-01T00:00:00Z"), None);
    }

    #[test]
    fn rejects_dot_with_no_fraction() {
        assert_eq!(rfc3339_to_epoch_seconds("2025-01-01T00:00:00.Z"), None);
    }

    #[test]
    fn accepts_leap_second_60() {
        // Leap second is parsed; coerced to :59 for epoch arithmetic.
        let s60 = rfc3339_to_epoch_seconds("2016-12-31T23:59:60Z").unwrap();
        let s59 = rfc3339_to_epoch_seconds("2016-12-31T23:59:59Z").unwrap();
        assert_eq!(s60, s59);
    }

    // -- malformed expression fails-closed ----------------------------------

    #[test]
    fn malformed_expression_body_fails() {
        // Tag 60010 wrapping a non-array body → decode error → Fail.
        let r = Value::Tag(
            TAG_INTEL_EXPRESSION,
            alloc::boxed::Box::new(Value::Integer(5)),
        );
        assert_eq!(eval_pair(&r, &Value::Integer(5)), Verdict::Fail);
    }

    #[test]
    fn unknown_operator_fails() {
        let r = make_expr_tag(Value::Array(vec![Value::Integer(99), Value::Integer(0)]));
        assert_eq!(eval_pair(&r, &Value::Integer(0)), Verdict::Fail);
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
