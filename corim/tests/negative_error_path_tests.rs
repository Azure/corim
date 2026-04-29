// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Additional negative tests targeting the remaining ~13% reachable missed error paths.

use corim::cbor;
use corim::cbor::value::Value;
use corim::types::common::*;
use corim::types::corim::*;
use corim::types::environment::*;
use corim::types::measurement::*;
use corim::types::tags::*;
use corim::types::triples::*;
use corim::Validate;

/// Encode a Value to CBOR, then try to decode as T. Returns the error string.
fn decode_err<T: serde::de::DeserializeOwned + std::fmt::Debug>(val: &Value) -> String {
    let bytes = cbor::encode(val).unwrap();
    cbor::decode::<T>(&bytes).unwrap_err().to_string()
}

// ===================================================================
// measurement.rs — SVN inner-type errors
// ===================================================================

#[test]
fn svn_tag552_wrapping_non_int() {
    let v = Value::Tag(TAG_SVN, Box::new(Value::Text("not-int".into())));
    let err = decode_err::<SvnChoice>(&v);
    assert!(err.contains("uint") || err.contains("wrap"), "got: {err}");
}

#[test]
fn svn_tag553_wrapping_non_int() {
    let v = Value::Tag(TAG_MIN_SVN, Box::new(Value::Text("not-int".into())));
    let err = decode_err::<SvnChoice>(&v);
    assert!(err.contains("uint") || err.contains("wrap"), "got: {err}");
}

#[test]
fn svn_tag552_negative_value() {
    let v = Value::Tag(TAG_SVN, Box::new(Value::Integer(-5)));
    let err = decode_err::<SvnChoice>(&v);
    assert!(err.contains("unsigned"), "got: {err}");
}

#[test]
fn svn_tag553_negative_value() {
    let v = Value::Tag(TAG_MIN_SVN, Box::new(Value::Integer(-5)));
    let err = decode_err::<SvnChoice>(&v);
    assert!(err.contains("unsigned"), "got: {err}");
}

#[test]
fn svn_untagged_negative() {
    let v = Value::Integer(-10);
    let err = decode_err::<SvnChoice>(&v);
    assert!(err.contains("unsigned"), "got: {err}");
}

// ===================================================================
// measurement.rs — IntRange inner-type errors
// ===================================================================

#[test]
fn int_range_min_non_int_non_null() {
    let v = Value::Tag(
        TAG_INT_RANGE,
        Box::new(Value::Array(vec![
            Value::Text("bad".into()),
            Value::Integer(100),
        ])),
    );
    let err = decode_err::<IntRangeChoice>(&v);
    assert!(err.contains("int or null"), "got: {err}");
}

#[test]
fn int_range_max_non_int_non_null() {
    let v = Value::Tag(
        TAG_INT_RANGE,
        Box::new(Value::Array(vec![
            Value::Integer(0),
            Value::Text("bad".into()),
        ])),
    );
    let err = decode_err::<IntRangeChoice>(&v);
    assert!(err.contains("int or null"), "got: {err}");
}

// ===================================================================
// measurement.rs — masked raw-value inner errors
// ===================================================================

#[test]
fn masked_raw_value_mask_non_bytes() {
    let v = Value::Tag(
        TAG_MASKED_RAW_VALUE,
        Box::new(Value::Array(vec![
            Value::Bytes(vec![1, 2, 3]),
            Value::Text("not-bytes".into()), // mask must be bytes
        ])),
    );
    let err = decode_err::<RawValueChoice>(&v);
    assert!(err.contains("mask") || err.contains("bytes"), "got: {err}");
}

#[test]
fn masked_raw_value_value_non_bytes() {
    let v = Value::Tag(
        TAG_MASKED_RAW_VALUE,
        Box::new(Value::Array(vec![
            Value::Text("not-bytes".into()), // value must be bytes
            Value::Bytes(vec![0xFF; 4]),
        ])),
    );
    let err = decode_err::<RawValueChoice>(&v);
    assert!(err.contains("value") || err.contains("bytes"), "got: {err}");
}

// ===================================================================
// measurement.rs — IntegrityRegisterId negative int
// ===================================================================

#[test]
fn integrity_register_id_negative() {
    let v = Value::Map(vec![(
        Value::Integer(-1),
        Value::Array(vec![Value::Array(vec![
            Value::Integer(7),
            Value::Bytes(vec![0; 32]),
        ])]),
    )]);
    let err = decode_err::<IntegrityRegisters>(&v);
    assert!(err.contains("unsigned"), "got: {err}");
}

// ===================================================================
// corim.rs — CorimLocatorThumbprint multi-digest error paths
// ===================================================================

#[test]
fn locator_thumbprint_multi_digest_bad_item() {
    // Array of digests where one item is not a pair
    let v = Value::Map(vec![
        (Value::Integer(0), Value::Text("https://example.com".into())),
        (
            Value::Integer(1),
            Value::Array(vec![
                Value::Array(vec![Value::Integer(7), Value::Bytes(vec![0; 32])]),
                Value::Text("not-a-pair".into()), // bad digest item
            ]),
        ),
    ]);
    let err = decode_err::<CorimLocator>(&v);
    assert!(
        err.contains("digest") || err.contains("[alg, val]"),
        "got: {err}"
    );
}

#[test]
fn locator_thumbprint_multi_digest_text_alg_accepted() {
    // CDDL: alg = int / text. Text alg accepted, stored as -1.
    let v = Value::Map(vec![
        (Value::Integer(0), Value::Text("https://example.com".into())),
        (
            Value::Integer(1),
            Value::Array(vec![Value::Array(vec![
                Value::Text("sha-256".into()),
                Value::Bytes(vec![0; 32]),
            ])]),
        ),
    ]);
    let bytes = cbor::encode(&v).unwrap();
    let loc: CorimLocator = cbor::decode(&bytes).unwrap();
    match loc.thumbprint {
        Some(CorimLocatorThumbprint::Multiple(ds)) => {
            assert!(matches!(ds[0].alg(), DigestAlg::Text(_)))
        }
        other => panic!("expected Multiple, got {:?}", other),
    }
}

#[test]
fn locator_thumbprint_multi_digest_val_non_bytes() {
    let v = Value::Map(vec![
        (Value::Integer(0), Value::Text("https://example.com".into())),
        (
            Value::Integer(1),
            Value::Array(vec![Value::Array(vec![
                Value::Integer(7),
                Value::Text("not-bytes".into()),
            ])]),
        ),
    ]);
    let err = decode_err::<CorimLocator>(&v);
    assert!(err.contains("val") || err.contains("bytes"), "got: {err}");
}

#[test]
fn locator_thumbprint_single_digest_wrong_length() {
    // Single digest [alg, val, extra] — 3 elements
    let v = Value::Map(vec![
        (Value::Integer(0), Value::Text("https://example.com".into())),
        (
            Value::Integer(1),
            Value::Array(vec![
                Value::Integer(7),
                Value::Bytes(vec![0; 32]),
                Value::Integer(0), // extra element
            ]),
        ),
    ]);
    let err = decode_err::<CorimLocator>(&v);
    assert!(
        err.contains("[alg, val]") || err.contains("digest"),
        "got: {err}"
    );
}

#[test]
fn locator_thumbprint_single_digest_text_alg_accepted() {
    // CDDL: alg = int / text. Text alg accepted, stored as -1.
    let v = Value::Map(vec![
        (Value::Integer(0), Value::Text("https://example.com".into())),
        (
            Value::Integer(1),
            Value::Array(vec![
                Value::Text("sha-256".into()),
                Value::Bytes(vec![0; 32]),
            ]),
        ),
    ]);
    let bytes = cbor::encode(&v).unwrap();
    let loc: CorimLocator = cbor::decode(&bytes).unwrap();
    match loc.thumbprint {
        Some(CorimLocatorThumbprint::Single(d)) => assert!(matches!(d.alg(), DigestAlg::Text(_))),
        other => panic!("expected Single, got {:?}", other),
    }
}

#[test]
fn locator_thumbprint_single_digest_val_non_bytes() {
    let v = Value::Map(vec![
        (Value::Integer(0), Value::Text("https://example.com".into())),
        (
            Value::Integer(1),
            Value::Array(vec![Value::Integer(7), Value::Text("not-bytes".into())]),
        ),
    ]);
    let err = decode_err::<CorimLocator>(&v);
    assert!(err.contains("val") || err.contains("bytes"), "got: {err}");
}

#[test]
fn locator_thumbprint_non_array() {
    let v = Value::Map(vec![
        (Value::Integer(0), Value::Text("https://example.com".into())),
        (Value::Integer(1), Value::Text("not-array".into())),
    ]);
    let err = decode_err::<CorimLocator>(&v);
    assert!(
        err.contains("array") || err.contains("thumbprint"),
        "got: {err}"
    );
}

// ===================================================================
// validate.rs — class_matches individual field mismatches
// ===================================================================

#[test]
fn env_match_instance_mismatch() {
    let ref_triple = corim::types::triples::ReferenceTriple::new(
        EnvironmentMap {
            class: None,
            instance: Some(InstanceIdChoice::Uuid([0xAA; 16])),
            group: None,
        },
        vec![MeasurementMap {
            mkey: None,
            mval: MeasurementValuesMap {
                name: Some("x".into()),
                ..Default::default()
            },
            authorized_by: None,
        }],
    );
    let evidence = vec![corim::validate::EvidenceClaim {
        environment: EnvironmentMap {
            class: None,
            instance: Some(InstanceIdChoice::Uuid([0xBB; 16])), // different
            group: None,
        },
        measurements: vec![MeasurementMap {
            mkey: None,
            mval: MeasurementValuesMap {
                name: Some("x".into()),
                ..Default::default()
            },
            authorized_by: None,
        }],
    }];
    let result = corim::validate::match_reference_values(&[ref_triple], &evidence);
    assert!(result.is_empty());
}

#[test]
fn env_match_group_mismatch() {
    let ref_triple = corim::types::triples::ReferenceTriple::new(
        EnvironmentMap {
            class: None,
            instance: None,
            group: Some(GroupIdChoice::Uuid([0xAA; 16])),
        },
        vec![MeasurementMap {
            mkey: None,
            mval: MeasurementValuesMap {
                name: Some("x".into()),
                ..Default::default()
            },
            authorized_by: None,
        }],
    );
    let evidence = vec![corim::validate::EvidenceClaim {
        environment: EnvironmentMap {
            class: None,
            instance: None,
            group: Some(GroupIdChoice::Uuid([0xBB; 16])), // different
        },
        measurements: vec![MeasurementMap {
            mkey: None,
            mval: MeasurementValuesMap {
                name: Some("x".into()),
                ..Default::default()
            },
            authorized_by: None,
        }],
    }];
    let result = corim::validate::match_reference_values(&[ref_triple], &evidence);
    assert!(result.is_empty());
}

#[test]
fn class_match_class_id_mismatch() {
    let ref_triple = corim::types::triples::ReferenceTriple::new(
        EnvironmentMap {
            class: Some(ClassMap {
                class_id: Some(ClassIdChoice::Uuid([0xAA; 16])),
                vendor: None,
                model: None,
                layer: None,
                index: None,
            }),
            instance: None,
            group: None,
        },
        vec![MeasurementMap {
            mkey: None,
            mval: MeasurementValuesMap {
                name: Some("x".into()),
                ..Default::default()
            },
            authorized_by: None,
        }],
    );
    let evidence = vec![corim::validate::EvidenceClaim {
        environment: EnvironmentMap {
            class: Some(ClassMap {
                class_id: Some(ClassIdChoice::Uuid([0xBB; 16])), // different
                vendor: None,
                model: None,
                layer: None,
                index: None,
            }),
            instance: None,
            group: None,
        },
        measurements: vec![MeasurementMap {
            mkey: None,
            mval: MeasurementValuesMap {
                name: Some("x".into()),
                ..Default::default()
            },
            authorized_by: None,
        }],
    }];
    let result = corim::validate::match_reference_values(&[ref_triple], &evidence);
    assert!(result.is_empty());
}

#[test]
fn class_match_layer_mismatch() {
    let ref_triple = corim::types::triples::ReferenceTriple::new(
        EnvironmentMap {
            class: Some(ClassMap {
                class_id: None,
                vendor: Some("V".into()),
                model: None,
                layer: Some(1),
                index: None,
            }),
            instance: None,
            group: None,
        },
        vec![MeasurementMap {
            mkey: None,
            mval: MeasurementValuesMap {
                name: Some("x".into()),
                ..Default::default()
            },
            authorized_by: None,
        }],
    );
    let evidence = vec![corim::validate::EvidenceClaim {
        environment: EnvironmentMap {
            class: Some(ClassMap {
                class_id: None,
                vendor: Some("V".into()),
                model: None,
                layer: Some(2), // different
                index: None,
            }),
            instance: None,
            group: None,
        },
        measurements: vec![MeasurementMap {
            mkey: None,
            mval: MeasurementValuesMap {
                name: Some("x".into()),
                ..Default::default()
            },
            authorized_by: None,
        }],
    }];
    let result = corim::validate::match_reference_values(&[ref_triple], &evidence);
    assert!(result.is_empty());
}

#[test]
fn class_match_index_mismatch() {
    let ref_triple = corim::types::triples::ReferenceTriple::new(
        EnvironmentMap {
            class: Some(ClassMap {
                class_id: None,
                vendor: Some("V".into()),
                model: None,
                layer: None,
                index: Some(0),
            }),
            instance: None,
            group: None,
        },
        vec![MeasurementMap {
            mkey: None,
            mval: MeasurementValuesMap {
                name: Some("x".into()),
                ..Default::default()
            },
            authorized_by: None,
        }],
    );
    let evidence = vec![corim::validate::EvidenceClaim {
        environment: EnvironmentMap {
            class: Some(ClassMap {
                class_id: None,
                vendor: Some("V".into()),
                model: None,
                layer: None,
                index: Some(1), // different
            }),
            instance: None,
            group: None,
        },
        measurements: vec![MeasurementMap {
            mkey: None,
            mval: MeasurementValuesMap {
                name: Some("x".into()),
                ..Default::default()
            },
            authorized_by: None,
        }],
    }];
    let result = corim::validate::match_reference_values(&[ref_triple], &evidence);
    assert!(result.is_empty());
}

#[test]
fn class_match_target_missing_class() {
    let ref_triple = corim::types::triples::ReferenceTriple::new(
        EnvironmentMap {
            class: Some(ClassMap::new("V", "M")),
            instance: None,
            group: None,
        },
        vec![MeasurementMap {
            mkey: None,
            mval: MeasurementValuesMap {
                name: Some("x".into()),
                ..Default::default()
            },
            authorized_by: None,
        }],
    );
    let evidence = vec![corim::validate::EvidenceClaim {
        environment: EnvironmentMap {
            class: None, // target has no class
            instance: None,
            group: None,
        },
        measurements: vec![MeasurementMap {
            mkey: None,
            mval: MeasurementValuesMap {
                name: Some("x".into()),
                ..Default::default()
            },
            authorized_by: None,
        }],
    }];
    let result = corim::validate::match_reference_values(&[ref_triple], &evidence);
    assert!(result.is_empty());
}

// ===================================================================
// validate.rs — not-yet-valid CoRIM
// ===================================================================

#[test]
fn validate_corim_not_yet_valid() {
    let comid = corim::builder::ComidBuilder::new(TagIdChoice::Text("t".into()))
        .add_reference_triple(corim::types::triples::ReferenceTriple::new(
            EnvironmentMap::for_class("V", "M"),
            vec![MeasurementMap {
                mkey: None,
                mval: MeasurementValuesMap {
                    svn: Some(SvnChoice::ExactValue(1)),
                    ..Default::default()
                },
                authorized_by: None,
            }],
        ))
        .build()
        .unwrap();
    let bytes = corim::builder::CorimBuilder::new(CorimId::Text("c".into()))
        .set_validity(Some(i64::MAX - 1), i64::MAX)
        .unwrap()
        .add_comid_tag(comid)
        .unwrap()
        .build_bytes()
        .unwrap();
    let result = corim::validate::decode_and_validate(&bytes);
    assert!(result.is_err());
    let err_str = format!("{}", result.unwrap_err());
    assert!(err_str.contains("not yet valid"), "got: {err_str}");
}

// ===================================================================
// common.rs — CborTime with out-of-range value
// ===================================================================

#[test]
fn cbor_time_non_time_value() {
    let v = Value::Text("not-a-time".into());
    let err = decode_err::<CborTime>(&v);
    assert!(
        err.contains("time") || err.contains("integer"),
        "got: {err}"
    );
}

// ===================================================================
// common.rs — MeasuredElement tag inner type errors
// ===================================================================

#[test]
fn measured_element_oid_non_bytes() {
    let v = Value::Tag(TAG_OID, Box::new(Value::Text("not-bytes".into())));
    let err = decode_err::<MeasuredElement>(&v);
    assert!(err.contains("bytes"), "got: {err}");
}

#[test]
fn measured_element_uuid_non_bytes() {
    let v = Value::Tag(TAG_UUID, Box::new(Value::Text("not-bytes".into())));
    let err = decode_err::<MeasuredElement>(&v);
    assert!(err.contains("bytes"), "got: {err}");
}

#[test]
fn measured_element_uuid_wrong_size() {
    let v = Value::Tag(TAG_UUID, Box::new(Value::Bytes(vec![0; 8])));
    let err = decode_err::<MeasuredElement>(&v);
    assert!(
        err.contains("16 bytes") || err.contains("UUID"),
        "got: {err}"
    );
}

// ===================================================================
// common.rs — InstanceIdChoice UUID wrong size
// ===================================================================

#[test]
fn instance_id_uuid_wrong_size() {
    let v = Value::Tag(TAG_UUID, Box::new(Value::Bytes(vec![0; 8])));
    let err = decode_err::<InstanceIdChoice>(&v);
    assert!(err.contains("16 bytes"), "got: {err}");
}

// ===================================================================
// triples.rs — CoswidTriple with invalid env
// ===================================================================

#[test]
fn coswid_triple_invalid_env() {
    let t = CoswidTriple::new(
        EnvironmentMap {
            class: None,
            instance: None,
            group: None,
        },
        vec![TagIdChoice::Text("t".into())],
    );
    let err = t.valid().unwrap_err();
    assert!(err.contains("environment"), "got: {err}");
}

// ===================================================================
// triples.rs — ConditionalEndorsementSeriesTriple with invalid env
// ===================================================================

#[test]
fn ces_triple_invalid_condition_env() {
    let ces = ConditionalEndorsementSeriesTriple::new(
        CesCondition {
            environment: EnvironmentMap {
                class: None,
                instance: None,
                group: None,
            },
            claims_list: vec![],
            authorized_by: None,
        },
        vec![ConditionalSeriesRecord::new(
            vec![MeasurementMap {
                mkey: None,
                mval: MeasurementValuesMap {
                    name: Some("x".into()),
                    ..Default::default()
                },
                authorized_by: None,
            }],
            vec![MeasurementMap {
                mkey: None,
                mval: MeasurementValuesMap {
                    name: Some("y".into()),
                    ..Default::default()
                },
                authorized_by: None,
            }],
        )],
    );
    let err = ces.valid().unwrap_err();
    assert!(err.contains("environment"), "got: {err}");
}

// ===================================================================
// minimal_value_serde.rs — Value::Integer u128 boundary
// ===================================================================

#[test]
fn value_integer_large_positive_u128() {
    // Value > u64::MAX — cannot be encoded in CBOR, should return error
    let v = Value::Integer((u64::MAX as i128) + 100);
    assert!(cbor::encode(&v).is_err());
}

#[test]
fn value_integer_large_negative_i128() {
    // Value < -(2^64) — cannot be encoded in CBOR, should return error
    let v = Value::Integer(-(u64::MAX as i128) - 2);
    assert!(cbor::encode(&v).is_err());
}

#[test]
fn value_integer_negative_i64_min_encodes() {
    // i64::MIN is within CBOR range — should succeed
    let v = Value::Integer(i64::MIN as i128);
    let bytes = cbor::encode(&v).unwrap();
    assert!(!bytes.is_empty());
}

// ===================================================================
// validate.rs — CoSWID decode failure falls back to opaque
// ===================================================================

#[test]
fn validate_coswid_decode_failure_opaque() {
    let comid = corim::builder::ComidBuilder::new(TagIdChoice::Text("t".into()))
        .add_reference_triple(corim::types::triples::ReferenceTriple::new(
            EnvironmentMap::for_class("V", "M"),
            vec![MeasurementMap {
                mkey: None,
                mval: MeasurementValuesMap {
                    svn: Some(SvnChoice::ExactValue(1)),
                    ..Default::default()
                },
                authorized_by: None,
            }],
        ))
        .build()
        .unwrap();
    // Add garbage bytes as a CoSWID — should fall back to opaque count
    let bytes = corim::builder::CorimBuilder::new(CorimId::Text("c".into()))
        .add_comid_tag(comid)
        .unwrap()
        .add_coswid_tag(vec![0xA0]) // minimal CBOR map but not valid ConciseSwidTag
        .build_bytes()
        .unwrap();
    let full = corim::validate::decode_and_validate_full(&bytes).unwrap();
    assert_eq!(full.comids.len(), 1);
    assert_eq!(full.coswid_opaque_count, 1);
    assert_eq!(full.coswids.len(), 0);
}

// ===================================================================
// validate.rs — inconsistent mkeys in CES
// ===================================================================

#[test]
fn validate_series_inconsistent_mkeys() {
    let env = EnvironmentMap::for_class("V", "M");
    let ces = ConditionalEndorsementSeriesTriple::new(
        CesCondition {
            environment: env.clone(),
            claims_list: vec![],
            authorized_by: None,
        },
        vec![
            ConditionalSeriesRecord::new(
                vec![MeasurementMap {
                    mkey: Some(MeasuredElement::Uint(1)),
                    mval: MeasurementValuesMap {
                        svn: Some(SvnChoice::ExactValue(1)),
                        ..Default::default()
                    },
                    authorized_by: None,
                }],
                vec![MeasurementMap {
                    mkey: None,
                    mval: MeasurementValuesMap {
                        name: Some("a".into()),
                        ..Default::default()
                    },
                    authorized_by: None,
                }],
            ),
            ConditionalSeriesRecord::new(
                vec![MeasurementMap {
                    mkey: Some(MeasuredElement::Uint(99)), // different mkey
                    mval: MeasurementValuesMap {
                        svn: Some(SvnChoice::ExactValue(2)),
                        ..Default::default()
                    },
                    authorized_by: None,
                }],
                vec![MeasurementMap {
                    mkey: None,
                    mval: MeasurementValuesMap {
                        name: Some("b".into()),
                        ..Default::default()
                    },
                    authorized_by: None,
                }],
            ),
        ],
    );
    let evidence = vec![corim::validate::EvidenceClaim {
        environment: env,
        measurements: vec![MeasurementMap {
            mkey: Some(MeasuredElement::Uint(1)),
            mval: MeasurementValuesMap {
                svn: Some(SvnChoice::ExactValue(1)),
                ..Default::default()
            },
            authorized_by: None,
        }],
    }];
    let result = corim::validate::apply_endorsement_series(&[ces], &evidence);
    assert!(result.is_err());
    let err_str = format!("{}", result.unwrap_err());
    assert!(
        err_str.contains("inconsistent") || err_str.contains("mkey"),
        "got: {err_str}"
    );
}

// ===================================================================
// builder.rs — remaining empty-list builder errors
// ===================================================================

#[test]
fn builder_comid_identity_triple_empty_keys_via_builder() {
    let result = corim::builder::ComidBuilder::new(TagIdChoice::Text("t".into()))
        .add_identity_triple(IdentityTriple::new(
            EnvironmentMap::for_class("V", "M"),
            vec![], // empty keys
            None,
        ))
        .build();
    assert!(result.is_err());
}

#[test]
fn builder_comid_attest_key_triple_empty_keys_via_builder() {
    let result = corim::builder::ComidBuilder::new(TagIdChoice::Text("t".into()))
        .add_attest_key_triple(AttestKeyTriple::new(
            EnvironmentMap::for_class("V", "M"),
            vec![], // empty keys
            None,
        ))
        .build();
    assert!(result.is_err());
}

#[test]
fn builder_comid_dependency_triple_empty_trustees_via_builder() {
    let result = corim::builder::ComidBuilder::new(TagIdChoice::Text("t".into()))
        .add_dependency_triple(DomainDependencyTriple::new(
            EnvironmentMap::for_class("V", "M"),
            vec![], // empty trustees
        ))
        .build();
    assert!(result.is_err());
}

#[test]
fn builder_comid_membership_triple_empty_members_via_builder() {
    let result = corim::builder::ComidBuilder::new(TagIdChoice::Text("t".into()))
        .add_membership_triple(DomainMembershipTriple::new(
            EnvironmentMap::for_class("V", "M"),
            vec![], // empty members
        ))
        .build();
    assert!(result.is_err());
}

#[test]
fn builder_comid_coswid_triple_empty_tags_via_builder() {
    let result = corim::builder::ComidBuilder::new(TagIdChoice::Text("t".into()))
        .add_coswid_triple(CoswidTriple::new(
            EnvironmentMap::for_class("V", "M"),
            vec![], // empty tag IDs
        ))
        .build();
    assert!(result.is_err());
}

// ===================================================================
// corim.rs — CorimId from Profile OID tag inner
// ===================================================================

#[test]
fn profile_oid_non_bytes() {
    let v = Value::Tag(TAG_OID, Box::new(Value::Text("not-bytes".into())));
    let err = decode_err::<ProfileChoice>(&v);
    assert!(err.contains("bytes"), "got: {err}");
}
