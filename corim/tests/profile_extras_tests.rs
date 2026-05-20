// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Round-trip tests for the profile-extension preservation mechanism on
//! `MeasurementValuesMap` (and any future map that opts into the
//! `#[cbor(extras = "...")]` derive-macro attribute).
//!
//! These tests exercise the `extra_entries: BTreeMap<i64, Value>` field
//! that captures CBOR map keys not matched by the static fields. The
//! Intel CoRIM profile (`draft-cds-rats-intel-corim-profile`) uses the
//! negative integer range (-70..=-125) for its `tee.*` measurement
//! extensions; this crate preserves them verbatim without interpreting
//! them, leaving semantics to a profile-aware consumer crate.

use corim::cbor;
use corim::cbor::value::Value;
use corim::types::measurement::{MeasurementValuesMap, SvnChoice};
use corim::Validate;
use std::collections::BTreeMap;

/// A `MeasurementValuesMap` containing only profile-extension entries
/// (no standard fields) round-trips losslessly and is `Validate`-valid:
/// extension entries satisfy the `non_empty` CDDL constraint.
#[test]
fn extras_only_mval_round_trips() {
    let mut extras = BTreeMap::new();
    // Mimic Intel profile `tee.mrtee = -83` carrying a single digest array.
    extras.insert(
        -83,
        Value::Array(vec![Value::Integer(7), Value::Bytes(vec![0xAA; 48])]),
    );
    let mval = MeasurementValuesMap {
        extra_entries: extras,
        ..MeasurementValuesMap::default()
    };

    // Validate: extras-only map satisfies non-empty.
    mval.valid().expect("extras-only mval should be valid");

    let bytes = cbor::encode(&mval).expect("encode failed");
    let decoded: MeasurementValuesMap = cbor::decode(&bytes).expect("decode failed");
    assert_eq!(mval, decoded);
    assert_eq!(decoded.extra_entries.len(), 1);
    assert!(decoded.extra_entries.contains_key(&-83));
}

/// Mixed standard + extension fields round-trip and the standard
/// fields land in their typed slots while the negative keys land
/// in `extra_entries`.
#[test]
fn mixed_standard_and_extras_round_trip() {
    let mut extras = BTreeMap::new();
    // Intel `tee.isvprodid = -85` as uint.
    extras.insert(-85, Value::Integer(42));
    // Intel `tee.advisory-ids = -89` as a set (CBOR array) of text strings.
    extras.insert(
        -89,
        Value::Array(vec![
            Value::Text("INTEL-SA-00001".into()),
            Value::Text("INTEL-SA-00002".into()),
        ]),
    );
    let mval = MeasurementValuesMap {
        svn: Some(SvnChoice::ExactValue(7)),
        name: Some("intel-tdx-module".into()),
        extra_entries: extras,
        ..MeasurementValuesMap::default()
    };

    let bytes = cbor::encode(&mval).expect("encode failed");
    let decoded: MeasurementValuesMap = cbor::decode(&bytes).expect("decode failed");
    assert_eq!(mval, decoded);
    assert_eq!(decoded.svn, Some(SvnChoice::ExactValue(7)));
    assert_eq!(decoded.name.as_deref(), Some("intel-tdx-module"));
    assert_eq!(decoded.extra_entries.len(), 2);
    assert_eq!(decoded.extra_entries.get(&-85), Some(&Value::Integer(42)));
}

/// An empty `MeasurementValuesMap` (no standard fields, no extras) still
/// fails the `non_empty` CDDL constraint at encode time.
#[test]
fn empty_mval_rejected_by_non_empty() {
    let mval = MeasurementValuesMap::default();
    assert!(mval.valid().is_err());
    let result = cbor::encode(&mval);
    assert!(
        result.is_err(),
        "encoding an empty mval must fail the non-empty constraint"
    );
}

/// Wire-format check: a hand-built CBOR map with negative integer keys
/// decodes into `extra_entries` (not silently dropped, as was the prior
/// forward-compat behavior).
#[test]
fn negative_keys_in_wire_bytes_decode_into_extras() {
    // CBOR map with two entries:
    //   key  -70 (tee.vendor)    -> "Intel"
    //   key  -71 (tee.model)     -> "TDX"
    // Encoded by hand to ensure we test wire-level acceptance.
    let entries = vec![
        (Value::Integer(-70), Value::Text("Intel".into())),
        (Value::Integer(-71), Value::Text("TDX".into())),
    ];
    let map_value = Value::Map(entries);
    let bytes = cbor::encode(&map_value).expect("encode raw map failed");

    let decoded: MeasurementValuesMap =
        cbor::decode(&bytes).expect("decode of negative-keyed map failed");

    // Standard fields stay None; both negative keys land in extras.
    assert!(decoded.svn.is_none());
    assert!(decoded.name.is_none());
    assert_eq!(decoded.extra_entries.len(), 2);
    assert_eq!(
        decoded.extra_entries.get(&-70),
        Some(&Value::Text("Intel".into()))
    );
    assert_eq!(
        decoded.extra_entries.get(&-71),
        Some(&Value::Text("TDX".into()))
    );
}

/// Profile keys can carry arbitrarily nested CBOR (e.g., the Intel
/// profile's `#6.60010(...)` expression tags inside extension values).
/// The opaque `Value` round-trip preserves tag nesting.
#[test]
fn extras_preserve_nested_tagged_values() {
    // Mimic Intel `tagged-numeric-ge`: #6.60010([2, 14])
    const TAG_INTEL_EXPRESSION: u64 = 60010;
    let inner = Value::Array(vec![Value::Integer(2), Value::Integer(14)]);
    let expression = Value::Tag(TAG_INTEL_EXPRESSION, Box::new(inner));

    let mut extras = BTreeMap::new();
    // Intel `tee.isvsvn = -73` carrying a tagged-numeric-ge expression.
    extras.insert(-73, expression.clone());
    let mval = MeasurementValuesMap {
        extra_entries: extras,
        ..MeasurementValuesMap::default()
    };

    let bytes = cbor::encode(&mval).expect("encode failed");
    let decoded: MeasurementValuesMap = cbor::decode(&bytes).expect("decode failed");
    assert_eq!(decoded.extra_entries.get(&-73), Some(&expression));
}
