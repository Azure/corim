// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! CBOR `#6.60010` expression decoder, per §8.1 of
//! `draft-cds-rats-intel-corim-profile-03`.
//!
//! Reference Values in the Intel profile may carry an operator-and-operand
//! expression in place of a bare value. The expression instructs the Verifier
//! how Evidence should be compared against the Reference Value (e.g. "greater
//! than", "member of set", "subset of"). All such expressions share the same
//! CBOR shape:
//!
//! ```text
//! #6.60010( [ operator, operand_2, operand_3? ] )
//! ```
//!
//! The `operator` is a small integer; the remaining elements depend on the
//! expression kind. Seven shapes are defined:
//!
//! | Shape         | Operators                       | §        |
//! |---------------|---------------------------------|----------|
//! | numeric       | `gt`(1) `ge`(2) `lt`(3) `le`(4) | §8.1.2   |
//! | mask          | `mask-eq`(1) (3-element form)   | §8.1.5   |
//! | set           | `member`(6) `not-member`(7)     | §8.1.3   |
//! | set-of-set    | `subset`(8) `superset`(9) `disjoint`(10) | §8.1.3 |
//! | tdate         | `gt`/`ge`/`lt`/`le` on `tdate`  | §8.1.4.1 |
//! | epoch         | `gt`/`ge`/`lt`/`le` + grace s   | §8.1.4.2 |
//! | (time)        | folded into `numeric`           | §8.1.4.1 |
//!
//! The `mask-eq` operator code (`1`) collides with `gt`; arity (3 vs 2) and
//! operand types (bstr+bstr vs numeric) disambiguate. Per RFC 8949 §3.4.1
//! and §3.4.2, `tdate` operands may appear as either bare `text` or
//! `#6.0(text)`, and numeric times may appear as either bare integer/float
//! or `#6.1(number)`; both forms are accepted on decode.

use crate::cbor::value::Value;
use crate::nostd_prelude::*;

/// CBOR tag number used by every Intel comparison expression (§8.1).
pub const TAG_INTEL_EXPRESSION: u64 = 60010;

// -- Operator wire codes (§8.1.1). ------------------------------------------

/// Numeric operator: greater-than.
const OP_GT: i64 = 1;
/// Numeric operator: greater-than-or-equal.
const OP_GE: i64 = 2;
/// Numeric operator: less-than.
const OP_LT: i64 = 3;
/// Numeric operator: less-than-or-equal.
const OP_LE: i64 = 4;
/// Mask-equivalence operator. Shares the wire code `1` with `gt`; the
/// arity (3) and operand types (bstr + bstr) disambiguate.
const OP_MASK_EQ: i64 = 1;
/// Object-in-set operator: member.
const OP_MEMBER: i64 = 6;
/// Object-in-set operator: not-member.
const OP_NOT_MEMBER: i64 = 7;
/// Set-of-set operator: every member of the evidence set maps to a
/// member of the reference set.
const OP_SUBSET: i64 = 8;
/// Set-of-set operator: every member of the reference set maps to a
/// member of the evidence set.
const OP_SUPERSET: i64 = 9;
/// Set-of-set operator: no member of the evidence set maps to any
/// member of the reference set.
const OP_DISJOINT: i64 = 10;

// -- Operator enums. --------------------------------------------------------

/// Numeric (and time / tdate / epoch) comparison operator (§8.1.2, §8.1.4).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum NumericOp {
    /// `gt` — greater-than.
    Gt,
    /// `ge` — greater-than-or-equal.
    Ge,
    /// `lt` — less-than.
    Lt,
    /// `le` — less-than-or-equal.
    Le,
}

impl NumericOp {
    fn from_code(code: i64) -> Option<Self> {
        Some(match code {
            OP_GT => Self::Gt,
            OP_GE => Self::Ge,
            OP_LT => Self::Lt,
            OP_LE => Self::Le,
            _ => return None,
        })
    }

    /// Short text mnemonic suitable for diagnostic output: `"gt"`,
    /// `"ge"`, `"lt"`, or `"le"`.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Gt => "gt",
            Self::Ge => "ge",
            Self::Lt => "lt",
            Self::Le => "le",
        }
    }
}

/// Object-in-set operator (§8.1.3 first form).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum SetOp {
    /// `member` — operand_1 must be a member of operand_2 (a set).
    Member,
    /// `not-member` — operand_1 must NOT be a member of operand_2.
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

/// Set-of-set operator (§8.1.3 second form).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum SetOfSetOp {
    /// `subset` — every member of evidence set S1 maps to a member of S2.
    Subset,
    /// `superset` — every member of reference set S2 maps to a member of S1.
    Superset,
    /// `disjoint` — no member of S1 maps to any member of S2.
    Disjoint,
}

impl SetOfSetOp {
    fn from_code(code: i64) -> Option<Self> {
        Some(match code {
            OP_SUBSET => Self::Subset,
            OP_SUPERSET => Self::Superset,
            OP_DISJOINT => Self::Disjoint,
            _ => return None,
        })
    }

    /// Short text mnemonic: `"subset"`, `"superset"`, or `"disjoint"`.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Subset => "subset",
            Self::Superset => "superset",
            Self::Disjoint => "disjoint",
        }
    }
}

// -- Numeric operand. -------------------------------------------------------

/// Operand of a [`Expression::Numeric`] — an integer or float per the
/// `numeric-type = integer / unsigned / float` rule in §8.1.2.
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

/// Decoded representation of a CBOR `#6.60010(...)` expression.
///
/// Decoded via [`Expression::from_tag`] (which expects the surrounding
/// `Value::Tag(60010, _)`) or [`Expression::from_body`] (which expects
/// the inner array directly).
///
/// The seven variants correspond to the seven shapes listed at the
/// top of the module. Disambiguation among shapes whose operator
/// codes overlap (`mask-eq` shares `1` with `gt`; numeric, time, tdate,
/// and epoch all share operators `1..=4`) is performed by arity and
/// operand type, so the decode is unambiguous for any well-formed
/// expression.
#[derive(Clone, Debug, PartialEq)]
#[non_exhaustive]
pub enum Expression {
    /// `[ op∈{gt,ge,lt,le}, int / float ]` — numeric or time
    /// comparison (§8.1.2, §8.1.4.1). Time values wrapped in `#6.1`
    /// are accepted on decode and stored unwrapped.
    Numeric {
        /// Comparison operator.
        op: NumericOp,
        /// Reference numeric value.
        value: Numeric,
    },
    /// `[ mask-eq, value: bstr, mask: bstr ]` — mask equivalence (§8.1.5).
    Mask {
        /// Reference value bytes.
        value: Vec<u8>,
        /// Bit-mask selecting which bits to compare.
        mask: Vec<u8>,
    },
    /// `[ op∈{member,not-member}, [* any] ]` — object-in-set (§8.1.3).
    Set {
        /// Membership operator.
        op: SetOp,
        /// Reference set members.
        members: Vec<Value>,
    },
    /// `[ op∈{subset,superset,disjoint}, [* [+ any]] ]` — set-of-set (§8.1.3).
    SetOfSet {
        /// Set-relation operator.
        op: SetOfSetOp,
        /// Reference sets (each an array of arbitrary CBOR items).
        sets: Vec<Vec<Value>>,
    },
    /// `[ op∈{gt,ge,lt,le}, tdate ]` — date-time string comparison
    /// (§8.1.4.1). Values wrapped in `#6.0` are accepted on decode and
    /// stored unwrapped.
    Tdate {
        /// Comparison operator.
        op: NumericOp,
        /// Reference date-time as an RFC 3339 string.
        date: String,
    },
    /// `[ op∈{gt,ge,lt,le}, grace-period: int, ?epoch-id ]` — epoch
    /// comparison (§8.1.4.2). The optional epoch-id selects an
    /// alternate epoch scheme; the default is verifier-current-time.
    Epoch {
        /// Comparison operator applied to the grace window.
        op: NumericOp,
        /// Grace period in seconds, relative to the epoch.
        grace_period: i64,
        /// Optional epoch identifier (`$tagged-epoch-id`); `None`
        /// means "verifier current time".
        epoch_id: Option<Value>,
    },
}

impl Expression {
    /// Decode an expression from a CBOR value that is expected to be a
    /// `Value::Tag(60010, ...)`.
    ///
    /// Returns [`ExpressionDecodeError::NotTagged`] if the input is
    /// not a tag, [`ExpressionDecodeError::WrongTag`] if the tag
    /// number differs from `60010`, or any of the body errors from
    /// [`Expression::from_body`].
    pub fn from_tag(value: &Value) -> Result<Self, ExpressionDecodeError> {
        match value {
            Value::Tag(t, inner) if *t == TAG_INTEL_EXPRESSION => Self::from_body(inner.as_ref()),
            Value::Tag(t, _) => Err(ExpressionDecodeError::WrongTag(*t)),
            _ => Err(ExpressionDecodeError::NotTagged),
        }
    }

    /// Decode an expression from its CBOR array body (i.e. the value
    /// inside the `#6.60010(...)` tag).
    ///
    /// Useful when the caller has already unwrapped the tag.
    pub fn from_body(body: &Value) -> Result<Self, ExpressionDecodeError> {
        let items = match body {
            Value::Array(a) => a,
            _ => return Err(ExpressionDecodeError::NotArray),
        };
        if items.len() < 2 || items.len() > 3 {
            return Err(ExpressionDecodeError::WrongArity(items.len()));
        }
        let op_code = match &items[0] {
            Value::Integer(n) => {
                i64::try_from(*n).map_err(|_| ExpressionDecodeError::OperatorOutOfRange(*n))?
            }
            _ => return Err(ExpressionDecodeError::OperatorNotInteger),
        };

        // Set and set-of-set have unambiguous operator codes (6..=10).
        if let Some(op) = SetOp::from_code(op_code) {
            if items.len() != 2 {
                return Err(ExpressionDecodeError::WrongArity(items.len()));
            }
            let members = match &items[1] {
                Value::Array(a) => a.clone(),
                _ => return Err(ExpressionDecodeError::SetOperandNotArray),
            };
            return Ok(Self::Set { op, members });
        }
        if let Some(op) = SetOfSetOp::from_code(op_code) {
            if items.len() != 2 {
                return Err(ExpressionDecodeError::WrongArity(items.len()));
            }
            let outer = match &items[1] {
                Value::Array(a) => a,
                _ => return Err(ExpressionDecodeError::SetOperandNotArray),
            };
            let mut sets: Vec<Vec<Value>> = Vec::with_capacity(outer.len());
            for inner in outer {
                match inner {
                    Value::Array(a) => sets.push(a.clone()),
                    _ => return Err(ExpressionDecodeError::SetOfSetMemberNotArray),
                }
            }
            return Ok(Self::SetOfSet { op, sets });
        }

        // Remaining operators (1..=4) cover numeric, mask, tdate, and epoch.
        let nop =
            NumericOp::from_code(op_code).ok_or(ExpressionDecodeError::UnknownOperator(op_code))?;

        if items.len() == 3 {
            // mask-eq (op==1, two bstr operands) or epoch (op + int + epoch-id).
            if op_code == OP_MASK_EQ {
                if let (Value::Bytes(value), Value::Bytes(mask)) = (&items[1], &items[2]) {
                    return Ok(Self::Mask {
                        value: value.clone(),
                        mask: mask.clone(),
                    });
                }
            }
            if let Value::Integer(n) = &items[1] {
                let grace_period = i64::try_from(*n)
                    .map_err(|_| ExpressionDecodeError::EpochGraceOutOfRange(*n))?;
                return Ok(Self::Epoch {
                    op: nop,
                    grace_period,
                    epoch_id: Some(items[2].clone()),
                });
            }
            return Err(ExpressionDecodeError::UnrecognizedShape);
        }

        // len == 2: numeric, tdate (text), or 2-element epoch.
        // Numeric is preferred when ambiguous with 2-element epoch.
        match &items[1] {
            Value::Text(t) => Ok(Self::Tdate {
                op: nop,
                date: t.clone(),
            }),
            // `#6.0(text)` — RFC 8949 §3.4.1 tdate.
            Value::Tag(0, inner) => match inner.as_ref() {
                Value::Text(t) => Ok(Self::Tdate {
                    op: nop,
                    date: t.clone(),
                }),
                _ => Err(ExpressionDecodeError::TdateNotText),
            },
            // `#6.1(number)` — RFC 8949 §3.4.2 epoch-based time.
            Value::Tag(1, inner) => match inner.as_ref() {
                Value::Integer(n) => Ok(Self::Numeric {
                    op: nop,
                    value: Numeric::Int(*n),
                }),
                Value::Float(f) => Ok(Self::Numeric {
                    op: nop,
                    value: Numeric::Float(*f),
                }),
                _ => Err(ExpressionDecodeError::NumericOperandWrongType),
            },
            Value::Integer(n) => Ok(Self::Numeric {
                op: nop,
                value: Numeric::Int(*n),
            }),
            Value::Float(f) => Ok(Self::Numeric {
                op: nop,
                value: Numeric::Float(*f),
            }),
            _ => Err(ExpressionDecodeError::UnrecognizedShape),
        }
    }
}

// -- Error type. ------------------------------------------------------------

/// Error returned by [`Expression::from_tag`] / [`Expression::from_body`]
/// when a CBOR value does not match any §8.1 expression shape.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum ExpressionDecodeError {
    /// Input was not a CBOR tag (expected `#6.60010(...)`).
    NotTagged,
    /// Input was a CBOR tag but the number was not `60010`.
    WrongTag(u64),
    /// The tag body was not a CBOR array.
    NotArray,
    /// The array had fewer than 2 or more than 3 elements; no §8.1
    /// expression has any other arity.
    WrongArity(usize),
    /// The first element of the array was not an integer.
    OperatorNotInteger,
    /// The first element was an integer but did not fit in `i64`.
    OperatorOutOfRange(i128),
    /// The operator code was not one of `{1, 2, 3, 4, 6, 7, 8, 9, 10}`.
    UnknownOperator(i64),
    /// A set / set-of-set expression's operand was not an array.
    SetOperandNotArray,
    /// A member of a set-of-set's outer array was not itself an array.
    SetOfSetMemberNotArray,
    /// A `tdate` operand was not `text` (bare or `#6.0(text)`).
    TdateNotText,
    /// A numeric operand had a type other than integer or float
    /// (bare or `#6.1`-wrapped).
    NumericOperandWrongType,
    /// An epoch `grace-period` integer did not fit in `i64`.
    EpochGraceOutOfRange(i128),
    /// Operand types did not match any §8.1 expression shape.
    UnrecognizedShape,
}

impl core::fmt::Display for ExpressionDecodeError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::NotTagged => write!(f, "expected `#6.60010(...)` CBOR tag"),
            Self::WrongTag(n) => write!(f, "expected CBOR tag 60010, got tag {}", n),
            Self::NotArray => write!(f, "expression tag body must be a CBOR array"),
            Self::WrongArity(n) => {
                write!(f, "expression array must have 2 or 3 elements, got {}", n)
            }
            Self::OperatorNotInteger => write!(f, "expression operator must be an integer"),
            Self::OperatorOutOfRange(n) => write!(f, "operator code {} does not fit in i64", n),
            Self::UnknownOperator(n) => write!(f, "unknown operator code {}", n),
            Self::SetOperandNotArray => write!(f, "set / set-of-set operand must be an array"),
            Self::SetOfSetMemberNotArray => write!(f, "set-of-set member must itself be an array"),
            Self::TdateNotText => write!(f, "tdate operand must be a text string"),
            Self::NumericOperandWrongType => {
                write!(f, "numeric operand must be an integer or float")
            }
            Self::EpochGraceOutOfRange(n) => {
                write!(f, "epoch grace-period {} does not fit in i64", n)
            }
            Self::UnrecognizedShape => {
                write!(f, "operand shape does not match any §8.1 expression")
            }
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for ExpressionDecodeError {}

// -- Display helper for diagnose output. ------------------------------------

/// Render an [`Expression`] as a short single-line string suitable for
/// `--diagnose` output. Examples:
///
/// - `Numeric { op: Ge, value: Int(5) }` → `"ge 5"`
/// - `Mask { value: <8 bytes>, mask: <8 bytes> }` → `"mask-eq <8-byte value, 8-byte mask>"`
/// - `Set { op: Member, members: [3 items] }` → `"member (3 items)"`
/// - `Tdate { op: Ge, date: "2024-01-01" }` → `"ge \"2024-01-01\""`
pub fn display_expression(e: &Expression) -> String {
    match e {
        Expression::Numeric { op, value } => format!("{} {}", op.as_str(), display_numeric(value)),
        Expression::Mask { value, mask } => format!(
            "mask-eq <{}-byte value, {}-byte mask>",
            value.len(),
            mask.len()
        ),
        Expression::Set { op, members } => {
            format!(
                "{} ({} item{})",
                op.as_str(),
                members.len(),
                s_plural(members.len())
            )
        }
        Expression::SetOfSet { op, sets } => {
            format!(
                "{} ({} set{})",
                op.as_str(),
                sets.len(),
                s_plural(sets.len())
            )
        }
        Expression::Tdate { op, date } => format!("{} \"{}\"", op.as_str(), date),
        Expression::Epoch {
            op,
            grace_period,
            epoch_id,
        } => match epoch_id {
            Some(_) => format!("{} grace={}s +epoch-id", op.as_str(), grace_period),
            None => format!("{} grace={}s", op.as_str(), grace_period),
        },
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

    fn expr(items: Vec<Value>) -> Value {
        Value::Tag(TAG_INTEL_EXPRESSION, Box::new(Value::Array(items)))
    }

    // -- numeric ---

    #[test]
    fn decodes_numeric_ge_int() {
        let v = expr(vec![Value::Integer(2), Value::Integer(5)]);
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
    fn decodes_numeric_lt_float() {
        let v = expr(vec![Value::Integer(3), Value::Float(1.5)]);
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
        let v = expr(vec![Value::Integer(2), inner]);
        let e = Expression::from_tag(&v).unwrap();
        assert_eq!(
            e,
            Expression::Numeric {
                op: NumericOp::Ge,
                value: Numeric::Int(1700000000),
            }
        );
    }

    // -- mask ---

    #[test]
    fn decodes_mask_eq() {
        let v = expr(vec![
            Value::Integer(1),
            Value::Bytes(vec![0xAA, 0xBB]),
            Value::Bytes(vec![0xFF, 0x00]),
        ]);
        let e = Expression::from_tag(&v).unwrap();
        assert_eq!(
            e,
            Expression::Mask {
                value: vec![0xAA, 0xBB],
                mask: vec![0xFF, 0x00],
            }
        );
        assert_eq!(
            display_expression(&e),
            "mask-eq <2-byte value, 2-byte mask>"
        );
    }

    // -- set ---

    #[test]
    fn decodes_set_member() {
        let v = expr(vec![
            Value::Integer(6),
            Value::Array(vec![
                Value::Integer(1),
                Value::Integer(2),
                Value::Integer(3),
            ]),
        ]);
        let e = Expression::from_tag(&v).unwrap();
        match e {
            Expression::Set { op, ref members } => {
                assert_eq!(op, SetOp::Member);
                assert_eq!(members.len(), 3);
            }
            other => panic!("expected Set, got {:?}", other),
        }
        assert_eq!(
            display_expression(&Expression::from_tag(&v).unwrap()),
            "member (3 items)"
        );
    }

    #[test]
    fn decodes_set_not_member_singleton_uses_singular() {
        let v = expr(vec![
            Value::Integer(7),
            Value::Array(vec![Value::Text("CVE-1".into())]),
        ]);
        let e = Expression::from_tag(&v).unwrap();
        assert_eq!(display_expression(&e), "not-member (1 item)");
    }

    // -- set-of-set ---

    #[test]
    fn decodes_set_of_set_subset() {
        let v = expr(vec![
            Value::Integer(8),
            Value::Array(vec![
                Value::Array(vec![Value::Integer(1)]),
                Value::Array(vec![Value::Integer(2), Value::Integer(3)]),
            ]),
        ]);
        let e = Expression::from_tag(&v).unwrap();
        match e {
            Expression::SetOfSet { op, ref sets } => {
                assert_eq!(op, SetOfSetOp::Subset);
                assert_eq!(sets.len(), 2);
                assert_eq!(sets[1].len(), 2);
            }
            other => panic!("expected SetOfSet, got {:?}", other),
        }
    }

    #[test]
    fn set_of_set_rejects_non_array_member() {
        let v = expr(vec![
            Value::Integer(9),
            Value::Array(vec![Value::Integer(42)]),
        ]);
        assert_eq!(
            Expression::from_tag(&v).unwrap_err(),
            ExpressionDecodeError::SetOfSetMemberNotArray,
        );
    }

    // -- tdate ---

    #[test]
    fn decodes_tdate_bare_text() {
        let v = expr(vec![
            Value::Integer(2),
            Value::Text("2024-01-01T00:00:00Z".into()),
        ]);
        let e = Expression::from_tag(&v).unwrap();
        assert_eq!(
            e,
            Expression::Tdate {
                op: NumericOp::Ge,
                date: "2024-01-01T00:00:00Z".into(),
            }
        );
    }

    #[test]
    fn decodes_tdate_with_tag_0() {
        let inner = Value::Tag(0, Box::new(Value::Text("2024-06-01T00:00:00Z".into())));
        let v = expr(vec![Value::Integer(2), inner]);
        let e = Expression::from_tag(&v).unwrap();
        assert!(matches!(
            e,
            Expression::Tdate {
                op: NumericOp::Ge,
                ..
            }
        ));
    }

    // -- epoch ---

    #[test]
    fn decodes_epoch_with_id() {
        let v = expr(vec![
            Value::Integer(1),
            Value::Integer(60),
            Value::Text("custom-epoch".into()),
        ]);
        let e = Expression::from_tag(&v).unwrap();
        match e {
            Expression::Epoch {
                op,
                grace_period,
                epoch_id,
            } => {
                assert_eq!(op, NumericOp::Gt);
                assert_eq!(grace_period, 60);
                assert!(epoch_id.is_some());
            }
            other => panic!("expected Epoch, got {:?}", other),
        }
    }

    // -- error cases ---

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
    fn rejects_wrong_arity() {
        let v = expr(vec![Value::Integer(2)]);
        assert_eq!(
            Expression::from_tag(&v).unwrap_err(),
            ExpressionDecodeError::WrongArity(1),
        );
        let v = expr(vec![
            Value::Integer(2),
            Value::Integer(0),
            Value::Integer(0),
            Value::Integer(0),
        ]);
        assert_eq!(
            Expression::from_tag(&v).unwrap_err(),
            ExpressionDecodeError::WrongArity(4),
        );
    }

    #[test]
    fn rejects_unknown_operator() {
        let v = expr(vec![Value::Integer(99), Value::Integer(0)]);
        assert_eq!(
            Expression::from_tag(&v).unwrap_err(),
            ExpressionDecodeError::UnknownOperator(99),
        );
    }

    #[test]
    fn rejects_non_integer_operator() {
        let v = expr(vec![Value::Text("gt".into()), Value::Integer(0)]);
        assert_eq!(
            Expression::from_tag(&v).unwrap_err(),
            ExpressionDecodeError::OperatorNotInteger,
        );
    }

    #[test]
    fn rejects_set_with_non_array_operand() {
        let v = expr(vec![Value::Integer(6), Value::Integer(1)]);
        assert_eq!(
            Expression::from_tag(&v).unwrap_err(),
            ExpressionDecodeError::SetOperandNotArray,
        );
    }

    #[test]
    fn rejects_unrecognized_2elem_shape() {
        // numeric op + non-int/non-text/non-float -> can't classify
        let v = expr(vec![Value::Integer(2), Value::Bool(true)]);
        assert_eq!(
            Expression::from_tag(&v).unwrap_err(),
            ExpressionDecodeError::UnrecognizedShape,
        );
    }

    #[test]
    fn from_body_skips_tag_unwrap() {
        let body = Value::Array(vec![Value::Integer(2), Value::Integer(5)]);
        let e = Expression::from_body(&body).unwrap();
        assert_eq!(
            e,
            Expression::Numeric {
                op: NumericOp::Ge,
                value: Numeric::Int(5),
            }
        );
    }
}
