// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Operator-shaped reference-value decoder for the Intel CoRIM profile,
//! per `draft-cds-rats-intel-corim-profile-07` §8.1 / §8.2 and the base
//! CoRIM definitions for `tagged-int-range` and `tagged-min-svn`.
//!
//! Reference Values in the Intel profile may carry one of several CBOR-
//! tagged shapes that instruct the Verifier how to compare Evidence
//! against the Reference (e.g. "greater than", "member of set",
//! "between min and max"). Six tags carry such shapes:
//!
//! | Tag       | CDDL name                                  | Shape       | §             |
//! |-----------|--------------------------------------------|-------------|---------------|
//! | `#6.60010`| `tagged-numeric-{gt,ge,lt,le}`             | numeric     | v07 §8.2.2    |
//! | `#6.60020`| `tagged-exp-digest-{member,not-member}`    | set-digests | v07 §8.2.3    |
//! | `#6.60021`| `tagged-exp-tstr-{member,not-member}`      | set-tstr    | v07 §8.2.3    |
//! | `#6.563`  | `tagged-masked-raw-value` (base CoRIM)     | masked-bstr | base CoRIM    |
//! | `#6.564`  | `tagged-int-range` (base CoRIM)            | int-range   | base CoRIM    |
//! | `#6.553`  | `tagged-min-svn` (base CoRIM)              | min-svn     | base CoRIM    |
//!
//! v07 §8.2.1 fixes the operator codes:
//! `op.eq=0`, `op.gt=1`, `op.ge=2`, `op.lt=3`, `op.le=4`,
//! `op.mem=6`, `op.nmem=7`. The v03 codes `op.subset=8` /
//! `op.superset=9` / `op.disjoint=10` and the overloaded `mask-eq=1`
//! 3-element shape were removed in v07 PR-equivalent edits; this
//! decoder no longer accepts them.

use crate::cbor::value::Value;
use crate::nostd_prelude::*;
use crate::types::tags::{TAG_INT_RANGE, TAG_MASKED_RAW_VALUE, TAG_MIN_SVN};

/// CBOR tag for Intel numeric expressions (v07 §8.2.2).
pub const TAG_INTEL_EXPRESSION: u64 = 60010;
/// CBOR tag for Intel set-of-digests expressions (v07 §8.2.3).
pub const TAG_INTEL_SET_DIGEST_EXPRESSION: u64 = 60020;
/// CBOR tag for Intel set-of-tstr expressions (v07 §8.2.3).
pub const TAG_INTEL_SET_TSTR_EXPRESSION: u64 = 60021;

// -- Operator wire codes (v07 §8.2.1). --------------------------------------

/// Equivalence operator. The CDDL never emits a tagged expression with
/// this code (exact-match is the default), but the integer is reserved
/// and accepted on decode for forward compatibility.
const OP_EQ: i64 = 0;
/// Numeric operator: greater-than.
const OP_GT: i64 = 1;
/// Numeric operator: greater-than-or-equal.
const OP_GE: i64 = 2;
/// Numeric operator: less-than.
const OP_LT: i64 = 3;
/// Numeric operator: less-than-or-equal.
const OP_LE: i64 = 4;
/// Set-membership operator: `op.mem`.
const OP_MEMBER: i64 = 6;
/// Set-membership operator: `op.nmem` (not member).
const OP_NOT_MEMBER: i64 = 7;

// -- Operator enums. --------------------------------------------------------

/// Numeric comparison operator (v07 §8.2.2).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum NumericOp {
    /// `op.eq` — equality. Reserved by the spec; not emitted by any
    /// `tagged-numeric-*` CDDL rule but accepted on decode.
    Eq,
    /// `op.gt` — greater-than.
    Gt,
    /// `op.ge` — greater-than-or-equal.
    Ge,
    /// `op.lt` — less-than.
    Lt,
    /// `op.le` — less-than-or-equal.
    Le,
}

impl NumericOp {
    fn from_code(code: i64) -> Option<Self> {
        Some(match code {
            OP_EQ => Self::Eq,
            OP_GT => Self::Gt,
            OP_GE => Self::Ge,
            OP_LT => Self::Lt,
            OP_LE => Self::Le,
            _ => return None,
        })
    }

    /// Short text mnemonic suitable for diagnostic output: `"eq"`,
    /// `"gt"`, `"ge"`, `"lt"`, or `"le"`.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Eq => "eq",
            Self::Gt => "gt",
            Self::Ge => "ge",
            Self::Lt => "lt",
            Self::Le => "le",
        }
    }
}

/// Set-membership operator (v07 §8.2.3).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum SetOp {
    /// `op.mem` — operand_1 must be a member of operand_2 (a set).
    Member,
    /// `op.nmem` — operand_1 must NOT be a member of operand_2.
    NotMember,
}

impl SetOp {
    fn from_code(code: i64) -> Option<Self> {
        Some(match code {
            OP_MEMBER => Self::Member,
            OP_NOT_MEMBER => Self::NotMember,
            _ => return None,
        })
    }

    /// Short text mnemonic: `"member"` or `"not-member"`.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Member => "member",
            Self::NotMember => "not-member",
        }
    }
}

// -- Numeric operand. -------------------------------------------------------

/// Operand of a [`Expression::Numeric`] — an integer or float per the
/// `numeric-type = integer / unsigned / float` rule in v07 §8.2.2.
///
/// CBOR has no distinct representation for unsigned vs signed; the
/// `unsigned` case is covered by a non-negative `Int`.
#[derive(Clone, Debug, PartialEq)]
#[non_exhaustive]
pub enum Numeric {
    /// Integer (signed or unsigned).
    Int(i128),
    /// IEEE 754 double-precision float.
    Float(f64),
}

// -- Expression enum. -------------------------------------------------------

/// Decoded representation of an operator-shaped Intel reference value.
///
/// Constructed via [`Expression::from_tag`] (which expects the outer
/// `Value::Tag(_, _)` and dispatches on the tag number) or via the
/// per-shape `from_body` constructors when the tag has already been
/// stripped.
///
/// The five variants correspond to the five tag shapes listed at the
/// top of the module.
#[derive(Clone, Debug, PartialEq)]
#[non_exhaustive]
pub enum Expression {
    /// `#6.60010([ op∈{eq,gt,ge,lt,le}, int / float ])` —
    /// numeric comparison (v07 §8.2.2).
    Numeric {
        /// Comparison operator.
        op: NumericOp,
        /// Reference numeric value.
        value: Numeric,
    },
    /// `#6.60020([ op∈{mem,nmem}, [* digest] ])` — set-of-digests
    /// membership (v07 §8.2.3). Each digest is preserved verbatim
    /// as a CBOR value so the per-digest CDDL shape
    /// (`[alg: int / text, val: bytes]`) is not coupled to this enum.
    SetOfDigests {
        /// Membership operator.
        op: SetOp,
        /// Reference digests (each typically `[int, bstr]`).
        members: Vec<Value>,
    },
    /// `#6.60021([ op∈{mem,nmem}, [* tstr] ])` — set-of-text-strings
    /// membership (v07 §8.2.3).
    SetOfTstr {
        /// Membership operator.
        op: SetOp,
        /// Reference strings.
        members: Vec<String>,
    },
    /// `#6.564([ min: int / null, max: int / null ])` — closed
    /// integer interval (`tagged-int-range`, base CoRIM). `None`
    /// signals `negative-inf` (for `min`) or `positive-inf` (for
    /// `max`).
    IntRange {
        /// Inclusive lower bound, or `None` for `-∞`.
        min: Option<i128>,
        /// Inclusive upper bound, or `None` for `+∞`.
        max: Option<i128>,
    },
    /// `#6.553(uint)` — minimum SVN (`tagged-min-svn`, base CoRIM).
    /// Evidence SVN must be `>=` this value.
    MinSvn(u64),
    /// `#6.563([value: bstr, mask: bstr])` — mask-aware raw value
    /// (`tagged-masked-raw-value`, base CoRIM). Evidence bytes `ev`
    /// match iff `(ev & mask) == (value & mask)`, with `value`,
    /// `mask`, and `ev` all the same length.
    MaskedRawValue {
        /// Reference value bytes.
        value: Vec<u8>,
        /// Bit-mask selecting which bits to compare.
        mask: Vec<u8>,
    },
}

impl Expression {
    /// Decode an expression from a CBOR value that is expected to be
    /// one of the six operator-shaped tags
    /// (`60010`/`60020`/`60021`/`563`/`564`/`553`).
    ///
    /// Returns [`ExpressionDecodeError::NotTagged`] if the input is
    /// not a tag, [`ExpressionDecodeError::WrongTag`] if the tag
    /// number is not one of the six, or a shape-specific error from
    /// the per-tag decoder.
    pub fn from_tag(value: &Value) -> Result<Self, ExpressionDecodeError> {
        match value {
            Value::Tag(t, inner) if *t == TAG_INTEL_EXPRESSION => {
                Self::numeric_from_body(inner.as_ref())
            }
            Value::Tag(t, inner) if *t == TAG_INTEL_SET_DIGEST_EXPRESSION => {
                Self::set_digest_from_body(inner.as_ref())
            }
            Value::Tag(t, inner) if *t == TAG_INTEL_SET_TSTR_EXPRESSION => {
                Self::set_tstr_from_body(inner.as_ref())
            }
            Value::Tag(t, inner) if *t == TAG_INT_RANGE => {
                Self::int_range_from_body(inner.as_ref())
            }
            Value::Tag(t, inner) if *t == TAG_MIN_SVN => Self::min_svn_from_body(inner.as_ref()),
            Value::Tag(t, inner) if *t == TAG_MASKED_RAW_VALUE => {
                Self::masked_raw_value_from_body(inner.as_ref())
            }
            Value::Tag(t, _) => Err(ExpressionDecodeError::WrongTag(*t)),
            _ => Err(ExpressionDecodeError::NotTagged),
        }
    }

    /// Returns `true` if `tag` is one of the six tags this decoder
    /// recognises (`60010`/`60020`/`60021`/`563`/`564`/`553`).
    pub fn is_intel_expression_tag(tag: u64) -> bool {
        matches!(
            tag,
            TAG_INTEL_EXPRESSION
                | TAG_INTEL_SET_DIGEST_EXPRESSION
                | TAG_INTEL_SET_TSTR_EXPRESSION
                | TAG_INT_RANGE
                | TAG_MIN_SVN
                | TAG_MASKED_RAW_VALUE
        )
    }

    fn numeric_from_body(body: &Value) -> Result<Self, ExpressionDecodeError> {
        let items = expect_array_n(body, 2)?;
        let op = numeric_op(&items[0])?;
        let value = numeric_value(&items[1])?;
        Ok(Self::Numeric { op, value })
    }

    fn set_digest_from_body(body: &Value) -> Result<Self, ExpressionDecodeError> {
        let items = expect_array_n(body, 2)?;
        let op = set_op(&items[0])?;
        let members = match &items[1] {
            Value::Array(a) => a.clone(),
            _ => return Err(ExpressionDecodeError::SetOperandNotArray),
        };
        Ok(Self::SetOfDigests { op, members })
    }

    fn set_tstr_from_body(body: &Value) -> Result<Self, ExpressionDecodeError> {
        let items = expect_array_n(body, 2)?;
        let op = set_op(&items[0])?;
        let members = match &items[1] {
            Value::Array(a) => {
                let mut out = Vec::with_capacity(a.len());
                for v in a {
                    match v {
                        Value::Text(s) => out.push(s.clone()),
                        _ => return Err(ExpressionDecodeError::SetTstrMemberNotText),
                    }
                }
                out
            }
            _ => return Err(ExpressionDecodeError::SetOperandNotArray),
        };
        Ok(Self::SetOfTstr { op, members })
    }

    fn int_range_from_body(body: &Value) -> Result<Self, ExpressionDecodeError> {
        let items = expect_array_n(body, 2)?;
        let min = match &items[0] {
            Value::Null => None,
            Value::Integer(n) => Some(*n),
            _ => return Err(ExpressionDecodeError::IntRangeBoundType),
        };
        let max = match &items[1] {
            Value::Null => None,
            Value::Integer(n) => Some(*n),
            _ => return Err(ExpressionDecodeError::IntRangeBoundType),
        };
        if let (Some(lo), Some(hi)) = (min, max) {
            if lo > hi {
                return Err(ExpressionDecodeError::IntRangeReversed);
            }
        }
        Ok(Self::IntRange { min, max })
    }

    fn min_svn_from_body(body: &Value) -> Result<Self, ExpressionDecodeError> {
        match body {
            Value::Integer(n) if *n >= 0 => {
                let v = u64::try_from(*n).map_err(|_| ExpressionDecodeError::MinSvnOutOfRange)?;
                Ok(Self::MinSvn(v))
            }
            Value::Integer(_) => Err(ExpressionDecodeError::MinSvnOutOfRange),
            _ => Err(ExpressionDecodeError::MinSvnNotUint),
        }
    }

    fn masked_raw_value_from_body(body: &Value) -> Result<Self, ExpressionDecodeError> {
        let items = expect_array_n(body, 2)?;
        let value = match &items[0] {
            Value::Bytes(b) => b.clone(),
            _ => return Err(ExpressionDecodeError::MaskedRawValueNotBytes),
        };
        let mask = match &items[1] {
            Value::Bytes(b) => b.clone(),
            _ => return Err(ExpressionDecodeError::MaskedRawValueNotBytes),
        };
        Ok(Self::MaskedRawValue { value, mask })
    }
}

fn expect_array(body: &Value) -> Result<&Vec<Value>, ExpressionDecodeError> {
    match body {
        Value::Array(a) => Ok(a),
        _ => Err(ExpressionDecodeError::NotArray),
    }
}

/// Like [`expect_array`], but also enforces an exact element count,
/// returning [`ExpressionDecodeError::WrongArity`] on mismatch.
fn expect_array_n(body: &Value, n: usize) -> Result<&Vec<Value>, ExpressionDecodeError> {
    let items = expect_array(body)?;
    if items.len() != n {
        return Err(ExpressionDecodeError::WrongArity(items.len()));
    }
    Ok(items)
}

fn numeric_op(v: &Value) -> Result<NumericOp, ExpressionDecodeError> {
    let code = op_code(v)?;
    NumericOp::from_code(code).ok_or(ExpressionDecodeError::UnknownOperator(code))
}

fn set_op(v: &Value) -> Result<SetOp, ExpressionDecodeError> {
    let code = op_code(v)?;
    SetOp::from_code(code).ok_or(ExpressionDecodeError::UnknownOperator(code))
}

fn op_code(v: &Value) -> Result<i64, ExpressionDecodeError> {
    match v {
        Value::Integer(n) => {
            i64::try_from(*n).map_err(|_| ExpressionDecodeError::OperatorOutOfRange(*n))
        }
        _ => Err(ExpressionDecodeError::OperatorNotInteger),
    }
}

fn numeric_value(v: &Value) -> Result<Numeric, ExpressionDecodeError> {
    match v {
        Value::Integer(n) => Ok(Numeric::Int(*n)),
        Value::Float(f) => Ok(Numeric::Float(*f)),
        // `#6.1(number)` — RFC 8949 §3.4.2 epoch-based time.
        Value::Tag(1, inner) => match inner.as_ref() {
            Value::Integer(n) => Ok(Numeric::Int(*n)),
            Value::Float(f) => Ok(Numeric::Float(*f)),
            _ => Err(ExpressionDecodeError::NumericOperandWrongType),
        },
        _ => Err(ExpressionDecodeError::NumericOperandWrongType),
    }
}

// -- Error type. ------------------------------------------------------------

/// Error returned by [`Expression::from_tag`] when a CBOR value does
/// not match any operator-shaped reference value defined by v07
/// §8.2 or the base CoRIM `tagged-int-range` / `tagged-min-svn`.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum ExpressionDecodeError {
    /// Input was not a CBOR tag.
    NotTagged,
    /// Input was a CBOR tag but the number was not one of
    /// `{60010, 60020, 60021, 564, 553}`.
    WrongTag(u64),
    /// The tag body was not a CBOR array (where one was required).
    NotArray,
    /// The body array had the wrong number of elements for the tag.
    WrongArity(usize),
    /// The operator slot was not an integer.
    OperatorNotInteger,
    /// The operator slot was an integer that did not fit in `i64`.
    OperatorOutOfRange(i128),
    /// The operator code did not match the operator set permitted by
    /// the tag (e.g. a set tag carried a numeric operator code).
    UnknownOperator(i64),
    /// A set expression's operand was not an array.
    SetOperandNotArray,
    /// A `set-tstr-type` member was not a text string.
    SetTstrMemberNotText,
    /// A numeric operand had a type other than integer or float
    /// (bare or `#6.1`-wrapped).
    NumericOperandWrongType,
    /// An `int-range` bound was neither `null` nor an integer.
    IntRangeBoundType,
    /// An `int-range` had `min > max`.
    IntRangeReversed,
    /// A `tagged-min-svn` body did not fit in `u64`.
    MinSvnOutOfRange,
    /// A `tagged-min-svn` body was not an unsigned integer.
    MinSvnNotUint,
    /// A `tagged-masked-raw-value` element was not a byte string.
    MaskedRawValueNotBytes,
}

impl core::fmt::Display for ExpressionDecodeError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::NotTagged => write!(f, "expected an Intel expression CBOR tag"),
            Self::WrongTag(n) => write!(
                f,
                "expected tag 60010 / 60020 / 60021 / 564 / 553, got tag {}",
                n
            ),
            Self::NotArray => write!(f, "expression tag body must be a CBOR array"),
            Self::WrongArity(n) => write!(f, "expression array has wrong arity: {}", n),
            Self::OperatorNotInteger => write!(f, "expression operator must be an integer"),
            Self::OperatorOutOfRange(n) => write!(f, "operator code {} does not fit in i64", n),
            Self::UnknownOperator(n) => write!(f, "operator code {} not permitted by this tag", n),
            Self::SetOperandNotArray => write!(f, "set operand must be an array"),
            Self::SetTstrMemberNotText => write!(f, "set-tstr member must be a text string"),
            Self::NumericOperandWrongType => {
                write!(f, "numeric operand must be an integer or float")
            }
            Self::IntRangeBoundType => write!(f, "int-range bound must be int or null"),
            Self::IntRangeReversed => write!(f, "int-range has min > max"),
            Self::MinSvnOutOfRange => write!(f, "tagged-min-svn value does not fit in u64"),
            Self::MinSvnNotUint => write!(f, "tagged-min-svn body must be an unsigned integer"),
            Self::MaskedRawValueNotBytes => {
                write!(f, "tagged-masked-raw-value element must be a byte string")
            }
        }
    }
}

impl core::error::Error for ExpressionDecodeError {}

// -- Display helper for diagnose output. ------------------------------------

/// Render an [`Expression`] as a short single-line string suitable for
/// `--diagnose` output. Examples:
///
/// - `Numeric { op: Ge, value: Int(5) }` → `"ge 5"`
/// - `SetOfDigests { op: Member, members: [3 items] }` → `"member (3 digests)"`
/// - `SetOfTstr { op: NotMember, members: ["CVE-1"] }` → `"not-member (1 string)"`
/// - `IntRange { min: Some(0), max: Some(15) }` → `"range [0..15]"`
/// - `MinSvn(5)` → `"min-svn 5"`
/// - `MaskedRawValue { value: <8 bytes>, mask: <8 bytes> }` → `"masked-bstr <8-byte value, 8-byte mask>"`
pub fn display_expression(e: &Expression) -> String {
    match e {
        Expression::Numeric { op, value } => format!("{} {}", op.as_str(), display_numeric(value)),
        Expression::SetOfDigests { op, members } => {
            format!(
                "{} ({} digest{})",
                op.as_str(),
                members.len(),
                s_plural(members.len())
            )
        }
        Expression::SetOfTstr { op, members } => {
            format!(
                "{} ({} string{})",
                op.as_str(),
                members.len(),
                s_plural(members.len())
            )
        }
        Expression::IntRange { min, max } => {
            let lo = min
                .map(|n| n.to_string())
                .unwrap_or_else(|| "-∞".to_string());
            let hi = max
                .map(|n| n.to_string())
                .unwrap_or_else(|| "+∞".to_string());
            format!("range [{}..{}]", lo, hi)
        }
        Expression::MinSvn(v) => format!("min-svn {}", v),
        Expression::MaskedRawValue { value, mask } => format!(
            "masked-bstr <{}-byte value, {}-byte mask>",
            value.len(),
            mask.len()
        ),
    }
}

fn display_numeric(n: &Numeric) -> String {
    match n {
        Numeric::Int(i) => format!("{}", i),
        Numeric::Float(f) => format!("{}", f),
    }
}

fn s_plural(n: usize) -> &'static str {
    if n == 1 {
        ""
    } else {
        "s"
    }
}

// -- Tests. -----------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn numeric_expr(items: Vec<Value>) -> Value {
        Value::Tag(TAG_INTEL_EXPRESSION, Box::new(Value::Array(items)))
    }
    fn set_digest_expr(items: Vec<Value>) -> Value {
        Value::Tag(
            TAG_INTEL_SET_DIGEST_EXPRESSION,
            Box::new(Value::Array(items)),
        )
    }
    fn set_tstr_expr(items: Vec<Value>) -> Value {
        Value::Tag(TAG_INTEL_SET_TSTR_EXPRESSION, Box::new(Value::Array(items)))
    }

    // -- numeric -------------------------------------------------------------

    #[test]
    fn decodes_numeric_ge_int() {
        let v = numeric_expr(vec![Value::Integer(OP_GE as i128), Value::Integer(5)]);
        let e = Expression::from_tag(&v).unwrap();
        assert_eq!(
            e,
            Expression::Numeric {
                op: NumericOp::Ge,
                value: Numeric::Int(5),
            }
        );
        assert_eq!(display_expression(&e), "ge 5");
    }

    #[test]
    fn decodes_numeric_eq() {
        let v = numeric_expr(vec![Value::Integer(OP_EQ as i128), Value::Integer(7)]);
        let e = Expression::from_tag(&v).unwrap();
        assert_eq!(
            e,
            Expression::Numeric {
                op: NumericOp::Eq,
                value: Numeric::Int(7),
            }
        );
    }

    #[test]
    fn decodes_numeric_lt_float() {
        let v = numeric_expr(vec![Value::Integer(OP_LT as i128), Value::Float(1.5)]);
        let e = Expression::from_tag(&v).unwrap();
        assert_eq!(
            e,
            Expression::Numeric {
                op: NumericOp::Lt,
                value: Numeric::Float(1.5),
            }
        );
    }

    #[test]
    fn unwraps_tagged_time_61() {
        let inner = Value::Tag(1, Box::new(Value::Integer(1700000000)));
        let v = numeric_expr(vec![Value::Integer(OP_GE as i128), inner]);
        let e = Expression::from_tag(&v).unwrap();
        assert_eq!(
            e,
            Expression::Numeric {
                op: NumericOp::Ge,
                value: Numeric::Int(1700000000),
            }
        );
    }

    // -- set-of-tstr ---------------------------------------------------------

    #[test]
    fn decodes_set_tstr_member() {
        let v = set_tstr_expr(vec![
            Value::Integer(OP_MEMBER as i128),
            Value::Array(vec![
                Value::Text("UpToDate".into()),
                Value::Text("OutOfDate".into()),
            ]),
        ]);
        let e = Expression::from_tag(&v).unwrap();
        match &e {
            Expression::SetOfTstr { op, members } => {
                assert_eq!(*op, SetOp::Member);
                assert_eq!(members.len(), 2);
            }
            other => panic!("expected SetOfTstr, got {:?}", other),
        }
        assert_eq!(display_expression(&e), "member (2 strings)");
    }

    #[test]
    fn decodes_set_tstr_not_member_singleton_uses_singular() {
        let v = set_tstr_expr(vec![
            Value::Integer(OP_NOT_MEMBER as i128),
            Value::Array(vec![Value::Text("CVE-1".into())]),
        ]);
        let e = Expression::from_tag(&v).unwrap();
        assert_eq!(display_expression(&e), "not-member (1 string)");
    }

    #[test]
    fn set_tstr_rejects_non_text_member() {
        let v = set_tstr_expr(vec![
            Value::Integer(OP_MEMBER as i128),
            Value::Array(vec![Value::Integer(1)]),
        ]);
        assert_eq!(
            Expression::from_tag(&v).unwrap_err(),
            ExpressionDecodeError::SetTstrMemberNotText
        );
    }

    // -- set-of-digests ------------------------------------------------------

    #[test]
    fn decodes_set_digest_member() {
        let digest = Value::Array(vec![Value::Integer(1), Value::Bytes(vec![0u8; 32])]);
        let v = set_digest_expr(vec![
            Value::Integer(OP_MEMBER as i128),
            Value::Array(vec![digest]),
        ]);
        let e = Expression::from_tag(&v).unwrap();
        match &e {
            Expression::SetOfDigests { op, members } => {
                assert_eq!(*op, SetOp::Member);
                assert_eq!(members.len(), 1);
            }
            other => panic!("expected SetOfDigests, got {:?}", other),
        }
        assert_eq!(display_expression(&e), "member (1 digest)");
    }

    // -- int-range -----------------------------------------------------------

    #[test]
    fn decodes_int_range_closed() {
        let v = Value::Tag(
            TAG_INT_RANGE,
            Box::new(Value::Array(vec![Value::Integer(0), Value::Integer(15)])),
        );
        let e = Expression::from_tag(&v).unwrap();
        assert_eq!(
            e,
            Expression::IntRange {
                min: Some(0),
                max: Some(15),
            }
        );
        assert_eq!(display_expression(&e), "range [0..15]");
    }

    #[test]
    fn decodes_int_range_half_open_min() {
        let v = Value::Tag(
            TAG_INT_RANGE,
            Box::new(Value::Array(vec![Value::Null, Value::Integer(10)])),
        );
        let e = Expression::from_tag(&v).unwrap();
        assert_eq!(
            e,
            Expression::IntRange {
                min: None,
                max: Some(10),
            }
        );
        assert_eq!(display_expression(&e), "range [-∞..10]");
    }

    #[test]
    fn decodes_int_range_half_open_max() {
        let v = Value::Tag(
            TAG_INT_RANGE,
            Box::new(Value::Array(vec![Value::Integer(5), Value::Null])),
        );
        let e = Expression::from_tag(&v).unwrap();
        assert_eq!(display_expression(&e), "range [5..+∞]");
    }

    #[test]
    fn int_range_rejects_reversed() {
        let v = Value::Tag(
            TAG_INT_RANGE,
            Box::new(Value::Array(vec![Value::Integer(10), Value::Integer(0)])),
        );
        assert_eq!(
            Expression::from_tag(&v).unwrap_err(),
            ExpressionDecodeError::IntRangeReversed
        );
    }

    #[test]
    fn int_range_rejects_non_int_non_null_bound() {
        let v = Value::Tag(
            TAG_INT_RANGE,
            Box::new(Value::Array(vec![
                Value::Text("0".into()),
                Value::Integer(10),
            ])),
        );
        assert_eq!(
            Expression::from_tag(&v).unwrap_err(),
            ExpressionDecodeError::IntRangeBoundType
        );
    }

    // -- min-svn -------------------------------------------------------------

    #[test]
    fn decodes_min_svn() {
        let v = Value::Tag(TAG_MIN_SVN, Box::new(Value::Integer(5)));
        let e = Expression::from_tag(&v).unwrap();
        assert_eq!(e, Expression::MinSvn(5));
        assert_eq!(display_expression(&e), "min-svn 5");
    }

    #[test]
    fn min_svn_rejects_negative() {
        let v = Value::Tag(TAG_MIN_SVN, Box::new(Value::Integer(-1)));
        assert_eq!(
            Expression::from_tag(&v).unwrap_err(),
            ExpressionDecodeError::MinSvnOutOfRange
        );
    }

    #[test]
    fn min_svn_rejects_non_int() {
        let v = Value::Tag(TAG_MIN_SVN, Box::new(Value::Text("5".into())));
        assert_eq!(
            Expression::from_tag(&v).unwrap_err(),
            ExpressionDecodeError::MinSvnNotUint
        );
    }

    // -- masked-raw-value ---------------------------------------------------

    #[test]
    fn decodes_masked_raw_value() {
        let v = Value::Tag(
            TAG_MASKED_RAW_VALUE,
            Box::new(Value::Array(vec![
                Value::Bytes(vec![0xAA, 0xBB]),
                Value::Bytes(vec![0xFF, 0x00]),
            ])),
        );
        let e = Expression::from_tag(&v).unwrap();
        assert_eq!(
            e,
            Expression::MaskedRawValue {
                value: vec![0xAA, 0xBB],
                mask: vec![0xFF, 0x00],
            }
        );
        assert_eq!(
            display_expression(&e),
            "masked-bstr <2-byte value, 2-byte mask>"
        );
    }

    #[test]
    fn masked_raw_value_rejects_wrong_arity() {
        let v = Value::Tag(
            TAG_MASKED_RAW_VALUE,
            Box::new(Value::Array(vec![Value::Bytes(vec![0])])),
        );
        assert_eq!(
            Expression::from_tag(&v).unwrap_err(),
            ExpressionDecodeError::WrongArity(1)
        );
    }

    #[test]
    fn masked_raw_value_rejects_non_bytes() {
        let v = Value::Tag(
            TAG_MASKED_RAW_VALUE,
            Box::new(Value::Array(vec![
                Value::Text("oops".into()),
                Value::Bytes(vec![0xFF]),
            ])),
        );
        assert_eq!(
            Expression::from_tag(&v).unwrap_err(),
            ExpressionDecodeError::MaskedRawValueNotBytes
        );
    }

    // -- error cases ---------------------------------------------------------

    #[test]
    fn rejects_non_tag() {
        assert_eq!(
            Expression::from_tag(&Value::Integer(1)).unwrap_err(),
            ExpressionDecodeError::NotTagged,
        );
    }

    #[test]
    fn rejects_wrong_tag() {
        let v = Value::Tag(999, Box::new(Value::Array(vec![])));
        assert_eq!(
            Expression::from_tag(&v).unwrap_err(),
            ExpressionDecodeError::WrongTag(999),
        );
    }

    #[test]
    fn numeric_rejects_wrong_arity() {
        let v = numeric_expr(vec![Value::Integer(OP_GE as i128)]);
        assert_eq!(
            Expression::from_tag(&v).unwrap_err(),
            ExpressionDecodeError::WrongArity(1),
        );
        let v = numeric_expr(vec![
            Value::Integer(OP_GE as i128),
            Value::Integer(0),
            Value::Integer(0),
        ]);
        assert_eq!(
            Expression::from_tag(&v).unwrap_err(),
            ExpressionDecodeError::WrongArity(3),
        );
    }

    #[test]
    fn numeric_rejects_set_operator() {
        let v = numeric_expr(vec![Value::Integer(OP_MEMBER as i128), Value::Integer(0)]);
        assert_eq!(
            Expression::from_tag(&v).unwrap_err(),
            ExpressionDecodeError::UnknownOperator(OP_MEMBER),
        );
    }

    #[test]
    fn set_rejects_numeric_operator() {
        let v = set_tstr_expr(vec![Value::Integer(OP_GE as i128), Value::Array(vec![])]);
        assert_eq!(
            Expression::from_tag(&v).unwrap_err(),
            ExpressionDecodeError::UnknownOperator(OP_GE),
        );
    }

    #[test]
    fn rejects_non_integer_operator() {
        let v = numeric_expr(vec![Value::Text("ge".into()), Value::Integer(0)]);
        assert_eq!(
            Expression::from_tag(&v).unwrap_err(),
            ExpressionDecodeError::OperatorNotInteger,
        );
    }

    #[test]
    fn rejects_unknown_operator_code() {
        let v = numeric_expr(vec![Value::Integer(99), Value::Integer(0)]);
        assert_eq!(
            Expression::from_tag(&v).unwrap_err(),
            ExpressionDecodeError::UnknownOperator(99),
        );
    }

    #[test]
    fn set_rejects_non_array_operand() {
        let v = set_tstr_expr(vec![Value::Integer(OP_MEMBER as i128), Value::Integer(1)]);
        assert_eq!(
            Expression::from_tag(&v).unwrap_err(),
            ExpressionDecodeError::SetOperandNotArray,
        );
    }

    #[test]
    fn is_intel_expression_tag_check() {
        assert!(Expression::is_intel_expression_tag(60010));
        assert!(Expression::is_intel_expression_tag(60020));
        assert!(Expression::is_intel_expression_tag(60021));
        assert!(Expression::is_intel_expression_tag(563));
        assert!(Expression::is_intel_expression_tag(564));
        assert!(Expression::is_intel_expression_tag(553));
        assert!(!Expression::is_intel_expression_tag(0));
        assert!(!Expression::is_intel_expression_tag(60011));
    }
}
