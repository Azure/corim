// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Normalization-aware comparison for `tee.tcbdate` (v07 §8.3.4).
//!
//! `$tee-date-type` admits five wire encodings of the same instant
//! plus one interval form:
//!
//! | Form                       | CBOR shape                                |
//! |----------------------------|-------------------------------------------|
//! | bare `tdate`               | `text` (RFC 3339)                         |
//! | tagged `tdate`             | `#6.0(text)`                              |
//! | bare `time`                | `int` / `float` (epoch seconds)           |
//! | tagged `time`              | `#6.1(int/float)`                         |
//! | RFC 9581 `etime`           | `#6.1001({1 => ~time, *(int/tstr) => any})` |
//! | RFC 9581 `period`          | `#6.1003([start, end, ?duration])`        |
//!
//! Per §8.3.4 tcbdate is an exact-match measurement: the spec defines
//! no operator for it. This module normalizes both sides of the
//! comparison to either a single epoch-second value or a half-open
//! `[lo, hi]` interval before comparing, so that producers and
//! verifiers that picked different equivalent encodings still match.
//!
//! The matching matrix:
//!
//! - instant vs instant → epoch-second equality
//! - period vs instant  → instant ∈ `[lo, hi]` (the natural
//!   interpretation of an interval-typed Reference Value)
//! - period vs period   → structural equality on the normalized bounds
//! - non-normalizable   → fall through to bare CBOR equality
//!
//! The RFC 3339 parser supports the subset that real-world Intel
//! tooling actually emits: `YYYY-MM-DDTHH:MM:SS[.frac](Z|[+-]HH:MM)`
//! with optional fractional seconds (truncated to second precision)
//! and case-insensitive `T` / `Z`. Sub-second precision is dropped —
//! Intel TCB dates are always second-resolution, and §8.3.4 does not
//! specify a precision floor for tdate equivalence.

use crate::cbor::value::Value;
#[allow(unused_imports)]
use crate::nostd_prelude::*;

use super::eval::Verdict;

/// Normalize a tcbdate Reference Value and Evidence value, comparing
/// them for the exact-match contract of v07 §8.3.4.
///
/// Returns `Verdict::Pass` if the two encodings represent the same
/// instant (or, when the reference is a period, an instant within
/// the period). Returns `Verdict::Fail` otherwise. If either side
/// uses an encoding outside the recognised set, falls back to bare
/// CBOR equality.
pub(super) fn match_tcbdate(reference: &Value, evidence: &Value) -> Verdict {
    let ref_norm = normalize(reference);
    let ev_norm = normalize(evidence);

    match (ref_norm, ev_norm) {
        (Some(Tcbdate::Instant(r)), Some(Tcbdate::Instant(e))) => bool_verdict(r == e),
        (Some(Tcbdate::Period { lo, hi }), Some(Tcbdate::Instant(e))) => {
            let lo_ok = lo.map(|l| e >= l).unwrap_or(true);
            let hi_ok = hi.map(|h| e <= h).unwrap_or(true);
            bool_verdict(lo_ok && hi_ok)
        }
        (
            Some(Tcbdate::Period { lo: rlo, hi: rhi }),
            Some(Tcbdate::Period { lo: elo, hi: ehi }),
        ) => bool_verdict(rlo == elo && rhi == ehi),
        // Reference is an instant but evidence is a period — under
        // exact-match semantics an interval cannot equal a point;
        // fail closed. (Falling through to CBOR equality would also
        // fail; the explicit Verdict::Fail just makes the intent
        // clearer in diagnostics.)
        (Some(Tcbdate::Instant(_)), Some(Tcbdate::Period { .. })) => Verdict::Fail,
        // One or both sides not normalizable — defer to verbatim
        // CBOR equality so that future encodings or producer-defined
        // values still have a path to Pass.
        _ => bool_verdict(reference == evidence),
    }
}

/// Normalized representation of a tcbdate value.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Tcbdate {
    /// A single instant, epoch seconds.
    Instant(i64),
    /// A half-open period, both bounds in epoch seconds. `None`
    /// signals an open bound (i.e. negative or positive infinity).
    Period { lo: Option<i64>, hi: Option<i64> },
}

fn normalize(v: &Value) -> Option<Tcbdate> {
    // Period must be detected before "instant" because #6.1003 is
    // itself a tag (not an integer/text/etc).
    if let Some(p) = normalize_period(v) {
        return Some(p);
    }
    normalize_instant(v).map(Tcbdate::Instant)
}

fn normalize_instant(v: &Value) -> Option<i64> {
    match v {
        // Bare epoch-seconds.
        Value::Integer(n) => i64::try_from(*n).ok(),
        Value::Float(f) => float_to_i64(*f),
        // `#6.1(number)` — RFC 8949 §3.4.2 epoch time.
        Value::Tag(1, inner) => match inner.as_ref() {
            Value::Integer(n) => i64::try_from(*n).ok(),
            Value::Float(f) => float_to_i64(*f),
            _ => None,
        },
        // Bare RFC 3339 tdate text.
        Value::Text(s) => rfc3339_to_epoch_seconds(s),
        // `#6.0(text)` — RFC 8949 §3.4.1 tdate.
        Value::Tag(0, inner) => match inner.as_ref() {
            Value::Text(s) => rfc3339_to_epoch_seconds(s),
            _ => None,
        },
        // `#6.1001({...})` — RFC 9581 etime; extract key 1 as `~time`.
        Value::Tag(1001, inner) => etime_basetime(inner.as_ref()),
        _ => None,
    }
}

/// Extract the base time from an RFC 9581 etime body.
/// `$$ETIME-BASETIME //= (1: ~time)` — key 1 is the base time as an
/// untagged number (integer or float in epoch seconds). Other base-
/// time variants (`(4: ~decfrac)`, `(5: ~bigfloat)`) and supplementary
/// keys are ignored here; if key 1 is absent or the wrong type, we
/// return None so the caller falls back to CBOR equality.
fn etime_basetime(body: &Value) -> Option<i64> {
    let entries = match body {
        Value::Map(m) => m,
        _ => return None,
    };
    for (k, v) in entries {
        let key = match k {
            Value::Integer(n) => *n,
            _ => continue,
        };
        if key == 1 {
            return match v {
                Value::Integer(n) => i64::try_from(*n).ok(),
                Value::Float(f) => float_to_i64(*f),
                _ => None,
            };
        }
    }
    None
}

/// Normalize a `#6.1003` period to `Tcbdate::Period`. Returns `None`
/// for any non-period value (caller then tries `normalize_instant`).
fn normalize_period(v: &Value) -> Option<Tcbdate> {
    let body = match v {
        Value::Tag(1003, inner) => inner.as_ref(),
        _ => return None,
    };
    let items = match body {
        Value::Array(a) => a,
        _ => return None,
    };
    // Per v07 / RFC 9581: period body has 2 or 3 elements
    // `[start, end, ?duration]`; either start or end may be `null`.
    if items.len() < 2 || items.len() > 3 {
        return None;
    }
    let start = bound(&items[0])?;
    let end = bound(&items[1])?;
    let duration = if items.len() == 3 {
        match &items[2] {
            // `~duration` is the untagged seconds count; `#6.1002`
            // wraps it. We accept both forms here.
            Value::Integer(n) => Some(i64::try_from(*n).ok()?),
            Value::Float(f) => Some(float_to_i64(*f)?),
            Value::Tag(1002, inner) => match inner.as_ref() {
                Value::Integer(n) => Some(i64::try_from(*n).ok()?),
                Value::Float(f) => Some(float_to_i64(*f)?),
                // Duration encoded as a map (RFC 9581 detailed form)
                // is not normalized; treat as missing.
                _ => None,
            },
            Value::Null => None,
            _ => return None,
        }
    } else {
        None
    };

    // If `end` is null but a duration is supplied, derive `hi` as
    // `lo + duration` (per the half-open Period rule that requires
    // duration when end is null).
    let lo = start;
    let hi = match (end, start, duration) {
        (Some(_), _, _) => end,
        (None, Some(l), Some(d)) => Some(l.saturating_add(d)),
        _ => None,
    };
    Some(Tcbdate::Period { lo, hi })
}

fn bound(v: &Value) -> Option<Option<i64>> {
    if matches!(v, Value::Null) {
        return Some(None);
    }
    normalize_instant(v).map(Some)
}

fn float_to_i64(f: f64) -> Option<i64> {
    if f.is_nan() || f.is_infinite() || f < (i64::MIN as f64) || f > (i64::MAX as f64) {
        None
    } else {
        Some(f as i64)
    }
}

fn bool_verdict(b: bool) -> Verdict {
    if b {
        Verdict::Pass
    } else {
        Verdict::Fail
    }
}

/// Parse an RFC 3339 `date-time` string to integer seconds since the
/// Unix epoch.
///
/// Accepts the grammar `YYYY-MM-DDTHH:MM:SS[.frac](Z|[+-]HH:MM)` with
/// `T` and `Z` permitted in either case (per RFC 3339 §5.6 NOTE).
/// Fractional seconds are syntactically accepted but truncated.
/// Returns `None` on any parse failure.
///
/// Uses the Howard-Hinnant `days_from_civil` algorithm — exact across
/// the full proleptic Gregorian range.
fn rfc3339_to_epoch_seconds(s: &str) -> Option<i64> {
    let b = s.as_bytes();
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

    if !(1..=12).contains(&month)
        || !(1..=31).contains(&day)
        || hour > 23
        || minute > 59
        || second > 60
    {
        return None;
    }
    // RFC 3339 §5.6 permits leap-second `:60`; coerce to `:59` for
    // epoch arithmetic.
    let second = if second == 60 { 59 } else { second };

    let mut i = 19usize;
    if i < b.len() && b[i] == b'.' {
        i += 1;
        let start = i;
        while i < b.len() && b[i].is_ascii_digit() {
            i += 1;
        }
        if i == start {
            return None;
        }
    }

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

    let (y, m) = if month <= 2 {
        (year - 1, month + 12)
    } else {
        (year, month)
    };
    let era = if y >= 0 { y / 400 } else { (y - 399) / 400 };
    let yoe = y - era * 400;
    let doy = (153 * (m - 3) + 2) / 5 + day - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    let days_since_epoch = era * 146097 + doe - 719468;

    let total = days_since_epoch * 86400 + hour * 3600 + minute * 60 + second - offset_secs;
    Some(total)
}

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

#[cfg(test)]
mod tests {
    use super::*;

    // -- rfc3339 -----------------------------------------------------------

    #[test]
    fn parses_unix_epoch_origin() {
        assert_eq!(rfc3339_to_epoch_seconds("1970-01-01T00:00:00Z"), Some(0));
    }

    #[test]
    fn parses_year_2025() {
        // 2025-01-01T00:00:00Z = 1735689600.
        assert_eq!(
            rfc3339_to_epoch_seconds("2025-01-01T00:00:00Z"),
            Some(1735689600)
        );
    }

    #[test]
    fn parses_leap_day_advances_one_day() {
        let leap = rfc3339_to_epoch_seconds("2024-02-29T00:00:00Z").unwrap();
        let next = rfc3339_to_epoch_seconds("2024-03-01T00:00:00Z").unwrap();
        assert_eq!(next - leap, 86400);
    }

    #[test]
    fn parses_positive_offset() {
        assert_eq!(
            rfc3339_to_epoch_seconds("2025-01-01T05:00:00+05:00"),
            rfc3339_to_epoch_seconds("2025-01-01T00:00:00Z")
        );
    }

    #[test]
    fn parses_lowercase_t_and_z() {
        assert_eq!(
            rfc3339_to_epoch_seconds("2025-01-01t00:00:00z"),
            rfc3339_to_epoch_seconds("2025-01-01T00:00:00Z")
        );
    }

    #[test]
    fn parses_fractional_seconds_truncated() {
        assert_eq!(
            rfc3339_to_epoch_seconds("2025-01-01T00:00:00.999Z"),
            rfc3339_to_epoch_seconds("2025-01-01T00:00:00Z")
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
    fn rejects_out_of_range_month() {
        assert_eq!(rfc3339_to_epoch_seconds("2025-13-01T00:00:00Z"), None);
    }

    // -- normalize ---------------------------------------------------------

    #[test]
    fn normalize_bare_int_is_instant() {
        assert_eq!(
            normalize(&Value::Integer(1735689600)),
            Some(Tcbdate::Instant(1735689600))
        );
    }

    #[test]
    fn normalize_bare_text_is_instant() {
        assert_eq!(
            normalize(&Value::Text("2025-01-01T00:00:00Z".into())),
            Some(Tcbdate::Instant(1735689600))
        );
    }

    #[test]
    fn normalize_tag_0_text_is_instant() {
        let v = Value::Tag(0, Box::new(Value::Text("2025-01-01T00:00:00Z".into())));
        assert_eq!(normalize(&v), Some(Tcbdate::Instant(1735689600)));
    }

    #[test]
    fn normalize_tag_1_int_is_instant() {
        let v = Value::Tag(1, Box::new(Value::Integer(1735689600)));
        assert_eq!(normalize(&v), Some(Tcbdate::Instant(1735689600)));
    }

    #[test]
    fn normalize_etime_with_key_1_is_instant() {
        // #6.1001({1: 1735689600})
        let body = Value::Map(vec![(Value::Integer(1), Value::Integer(1735689600))]);
        let v = Value::Tag(1001, Box::new(body));
        assert_eq!(normalize(&v), Some(Tcbdate::Instant(1735689600)));
    }

    #[test]
    fn normalize_etime_without_key_1_is_none() {
        let body = Value::Map(vec![(Value::Integer(2), Value::Integer(0))]);
        let v = Value::Tag(1001, Box::new(body));
        assert_eq!(normalize(&v), None);
    }

    #[test]
    fn normalize_period_with_explicit_bounds() {
        // #6.1003([2024-01-01, 2025-01-01]).
        let body = Value::Array(vec![Value::Integer(1704067200), Value::Integer(1735689600)]);
        let v = Value::Tag(1003, Box::new(body));
        assert_eq!(
            normalize(&v),
            Some(Tcbdate::Period {
                lo: Some(1704067200),
                hi: Some(1735689600),
            })
        );
    }

    #[test]
    fn normalize_period_with_open_start() {
        let body = Value::Array(vec![Value::Null, Value::Integer(1735689600)]);
        let v = Value::Tag(1003, Box::new(body));
        assert_eq!(
            normalize(&v),
            Some(Tcbdate::Period {
                lo: None,
                hi: Some(1735689600),
            })
        );
    }

    #[test]
    fn normalize_period_with_duration_derives_end() {
        // [start=1000, end=null, duration=500] → hi = 1500.
        let body = Value::Array(vec![Value::Integer(1000), Value::Null, Value::Integer(500)]);
        let v = Value::Tag(1003, Box::new(body));
        assert_eq!(
            normalize(&v),
            Some(Tcbdate::Period {
                lo: Some(1000),
                hi: Some(1500),
            })
        );
    }

    #[test]
    fn normalize_period_with_text_bounds() {
        // Real-world Endorsers may emit RFC 3339 strings inside the
        // period array.
        let body = Value::Array(vec![
            Value::Text("2024-01-01T00:00:00Z".into()),
            Value::Text("2025-01-01T00:00:00Z".into()),
        ]);
        let v = Value::Tag(1003, Box::new(body));
        assert_eq!(
            normalize(&v),
            Some(Tcbdate::Period {
                lo: Some(1704067200),
                hi: Some(1735689600),
            })
        );
    }

    // -- match_tcbdate -----------------------------------------------------

    #[test]
    fn instant_text_equals_instant_int() {
        let r = Value::Text("2025-01-01T00:00:00Z".into());
        let e = Value::Integer(1735689600);
        assert_eq!(match_tcbdate(&r, &e), Verdict::Pass);
    }

    #[test]
    fn instant_etime_equals_instant_tag_0() {
        let r = Value::Tag(
            1001,
            Box::new(Value::Map(vec![(
                Value::Integer(1),
                Value::Integer(1735689600),
            )])),
        );
        let e = Value::Tag(0, Box::new(Value::Text("2025-01-01T00:00:00Z".into())));
        assert_eq!(match_tcbdate(&r, &e), Verdict::Pass);
    }

    #[test]
    fn instant_inequality_fails() {
        let r = Value::Text("2025-01-01T00:00:00Z".into());
        let e = Value::Integer(1735689601);
        assert_eq!(match_tcbdate(&r, &e), Verdict::Fail);
    }

    #[test]
    fn period_contains_instant_passes() {
        let r = Value::Tag(
            1003,
            Box::new(Value::Array(vec![
                Value::Integer(1704067200), // 2024-01-01
                Value::Integer(1735689600), // 2025-01-01
            ])),
        );
        // Evidence in the middle of the window.
        let e = Value::Text("2024-06-01T00:00:00Z".into());
        assert_eq!(match_tcbdate(&r, &e), Verdict::Pass);
    }

    #[test]
    fn period_excludes_instant_fails() {
        let r = Value::Tag(
            1003,
            Box::new(Value::Array(vec![
                Value::Integer(1704067200),
                Value::Integer(1735689600),
            ])),
        );
        let e = Value::Text("2026-01-01T00:00:00Z".into());
        assert_eq!(match_tcbdate(&r, &e), Verdict::Fail);
    }

    #[test]
    fn period_open_bounds_treat_as_infinity() {
        let r = Value::Tag(
            1003,
            Box::new(Value::Array(vec![Value::Null, Value::Integer(1735689600)])),
        );
        assert_eq!(
            match_tcbdate(&r, &Value::Integer(-1_000_000)),
            Verdict::Pass
        );
        assert_eq!(
            match_tcbdate(&r, &Value::Integer(1735689601)),
            Verdict::Fail
        );
    }

    #[test]
    fn period_equals_period_passes() {
        let r = Value::Tag(
            1003,
            Box::new(Value::Array(vec![Value::Integer(0), Value::Integer(100)])),
        );
        let e = r.clone();
        assert_eq!(match_tcbdate(&r, &e), Verdict::Pass);
    }

    #[test]
    fn period_differs_from_period_fails() {
        let r = Value::Tag(
            1003,
            Box::new(Value::Array(vec![Value::Integer(0), Value::Integer(100)])),
        );
        let e = Value::Tag(
            1003,
            Box::new(Value::Array(vec![Value::Integer(0), Value::Integer(200)])),
        );
        assert_eq!(match_tcbdate(&r, &e), Verdict::Fail);
    }

    #[test]
    fn instant_vs_period_fails_explicit() {
        let r = Value::Integer(0);
        let e = Value::Tag(
            1003,
            Box::new(Value::Array(vec![Value::Integer(0), Value::Integer(100)])),
        );
        assert_eq!(match_tcbdate(&r, &e), Verdict::Fail);
    }

    #[test]
    fn unrecognised_falls_back_to_cbor_equality() {
        // Two unrelated tag wrappers — not tcbdate forms; CBOR
        // equality still passes when they're verbatim equal.
        let r = Value::Tag(9999, Box::new(Value::Integer(7)));
        let e = r.clone();
        assert_eq!(match_tcbdate(&r, &e), Verdict::Pass);
    }
}
