// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Coverage ceiling tests — targeting ~88% practical limit.
//!
//! Covers:
//! 🟢 Low-hanging fruit: builder remaining methods, validate no-match paths, json edges
//! 🟡 Negative decode: malformed CBOR for type-choice enums (common, measurement, corim, triples)
//! 🟠 Serde infra: value_de error paths, Tagged<T> decode errors, i128 boundaries

use corim::cbor;
use corim::cbor::value::Value;
use corim::types::common::*;
use corim::types::corim::*;
use corim::types::coswid::*;
use corim::types::environment::*;
use corim::types::measurement::*;
use corim::types::tags::*;
use corim::types::triples::*;

// ===================================================================
// 🟢 builder.rs — remaining uncovered methods
// ===================================================================

#[test]
fn builder_cotl_set_tag_version() {
    let cotl = corim::builder::CotlBuilder::new(TagIdChoice::Text("v".into()), i64::MAX)
        .set_tag_version(3)
        .add_tag_id(TagIdChoice::Text("x".into()))
        .build()
        .unwrap();
    assert_eq!(cotl.tag_identity.tag_version, Some(3));
}

#[test]
fn builder_corim_add_entity() {
    let entity = EntityMap {
        entity_name: "ACME".into(),
        reg_id: Some("https://acme.example".into()),
        role: vec![1],
    };
    let comid = corim::builder::ComidBuilder::new(TagIdChoice::Text("t".into()))
        .add_reference_triple(ReferenceTriple::new(
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
    let corim = corim::builder::CorimBuilder::new(CorimId::Text("c".into()))
        .add_entity(entity)
        .add_comid_tag(comid)
        .unwrap()
        .build()
        .unwrap();
    assert!(corim.entities.is_some());
    assert_eq!(corim.entities.unwrap().len(), 1);
}

#[test]
fn builder_corim_add_dependent_rim() {
    let locator = CorimLocator {
        href: CorimLocatorHref::Single("https://example.com/dep.corim".into()),
        thumbprint: None,
    };
    let comid = corim::builder::ComidBuilder::new(TagIdChoice::Text("t".into()))
        .add_reference_triple(ReferenceTriple::new(
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
    let corim = corim::builder::CorimBuilder::new(CorimId::Text("c".into()))
        .add_dependent_rim(locator)
        .add_comid_tag(comid)
        .unwrap()
        .build()
        .unwrap();
    assert!(corim.dependent_rims.is_some());
}

#[test]
fn builder_corim_add_tag_directly() {
    let corim = corim::builder::CorimBuilder::new(CorimId::Text("c".into()))
        .add_tag(ConciseTagChoice::Comid(vec![0xA0]))
        .build()
        .unwrap();
    assert_eq!(corim.tags.len(), 1);
}

#[test]
fn builder_corim_set_profile() {
    let comid = corim::builder::ComidBuilder::new(TagIdChoice::Text("t".into()))
        .add_reference_triple(ReferenceTriple::new(
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
    let corim = corim::builder::CorimBuilder::new(CorimId::Text("c".into()))
        .set_profile(ProfileChoice::Uri("https://example.com/profile".into()))
        .add_comid_tag(comid)
        .unwrap()
        .build()
        .unwrap();
    assert!(corim.profile.is_some());
}

#[test]
fn builder_comid_conditional_endorsement_empty_fails() {
    let result = corim::builder::ComidBuilder::new(TagIdChoice::Text("t".into()))
        .add_conditional_endorsement(ConditionalEndorsementTriple(
            vec![StatefulEnvironmentRecord(
                EnvironmentMap::for_class("V", "M"),
                vec![MeasurementMap {
                    mkey: None,
                    mval: MeasurementValuesMap {
                        svn: Some(SvnChoice::ExactValue(1)),
                        ..Default::default()
                    },
                    authorized_by: None,
                }],
            )],
            vec![], // empty endorsements — but builder doesn't check inner validity, just [+T]
        ))
        .build();
    // The builder should succeed (it doesn't validate inner structure, just that triple types exist)
    assert!(result.is_ok());
}

#[test]
fn builder_comid_conditional_endorsement_series() {
    let env = EnvironmentMap::for_class("V", "M");
    let meas = vec![MeasurementMap {
        mkey: Some(MeasuredElement::Uint(1)),
        mval: MeasurementValuesMap {
            svn: Some(SvnChoice::ExactValue(1)),
            ..Default::default()
        },
        authorized_by: None,
    }];
    let ces = ConditionalEndorsementSeriesTriple::new(
        CesCondition {
            environment: env.clone(),
            claims_list: vec![],
            authorized_by: None,
        },
        vec![ConditionalSeriesRecord::new(meas.clone(), meas)],
    );
    let comid = corim::builder::ComidBuilder::new(TagIdChoice::Text("t".into()))
        .add_conditional_endorsement_series(ces)
        .build()
        .unwrap();
    assert!(comid.triples.conditional_endorsement_series.is_some());
}

#[test]
fn builder_comid_set_language_and_entities() {
    let comid = corim::builder::ComidBuilder::new(TagIdChoice::Text("t".into()))
        .set_language("en-US")
        .set_tag_version(2)
        .add_entity(EntityMap {
            entity_name: "Test".into(),
            reg_id: None,
            role: vec![0],
        })
        .add_linked_tag(LinkedTagMap {
            linked_tag_id: TagIdChoice::Text("other".into()),
            tag_rel: 0,
        })
        .add_reference_triple(ReferenceTriple::new(
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
    assert_eq!(comid.language.as_deref(), Some("en-US"));
    assert_eq!(comid.tag_identity.tag_version, Some(2));
    assert!(comid.entities.is_some());
    assert!(comid.linked_tags.is_some());
}

#[test]
fn builder_corim_add_coswid_invalid_fails() {
    let bad_coswid = ConciseSwidTag::new(
        TagIdChoice::Text("x".into()),
        "Test",
        0,
        vec![], // no entities
    );
    let result =
        corim::builder::CorimBuilder::new(CorimId::Text("c".into())).add_coswid(bad_coswid);
    assert!(result.is_err());
}

// ===================================================================
// 🟢 validate.rs — no-match paths, endorsement, digests_match
// ===================================================================

#[test]
fn match_reference_values_no_env_match() {
    let ref_triple = ReferenceTriple::new(
        EnvironmentMap::for_class("ACME", "Widget"),
        vec![MeasurementMap {
            mkey: None,
            mval: MeasurementValuesMap {
                svn: Some(SvnChoice::ExactValue(1)),
                ..Default::default()
            },
            authorized_by: None,
        }],
    );
    let evidence = vec![corim::validate::EvidenceClaim {
        environment: EnvironmentMap::for_class("OTHER", "Thing"),
        measurements: vec![MeasurementMap {
            mkey: None,
            mval: MeasurementValuesMap {
                svn: Some(SvnChoice::ExactValue(1)),
                ..Default::default()
            },
            authorized_by: None,
        }],
    }];
    let result = corim::validate::match_reference_values(&[ref_triple], &evidence);
    assert!(result.is_empty());
}

#[test]
fn match_reference_values_no_measurement_match() {
    let env = EnvironmentMap::for_class("ACME", "Widget");
    let ref_triple = ReferenceTriple::new(
        env.clone(),
        vec![MeasurementMap {
            mkey: Some(MeasuredElement::Uint(99)),
            mval: MeasurementValuesMap {
                svn: Some(SvnChoice::ExactValue(1)),
                ..Default::default()
            },
            authorized_by: None,
        }],
    );
    let evidence = vec![corim::validate::EvidenceClaim {
        environment: env,
        measurements: vec![MeasurementMap {
            mkey: Some(MeasuredElement::Uint(1)), // different mkey
            mval: MeasurementValuesMap {
                svn: Some(SvnChoice::ExactValue(1)),
                ..Default::default()
            },
            authorized_by: None,
        }],
    }];
    let result = corim::validate::match_reference_values(&[ref_triple], &evidence);
    assert!(result.is_empty());
}

#[test]
fn match_reference_values_digest_mismatch_same_alg() {
    let env = EnvironmentMap::for_class("V", "M");
    let ref_triple = ReferenceTriple::new(
        env.clone(),
        vec![MeasurementMap {
            mkey: None,
            mval: MeasurementValuesMap {
                digests: Some(vec![Digest::new(7, vec![0xAA; 32])]),
                ..Default::default()
            },
            authorized_by: None,
        }],
    );
    let evidence = vec![corim::validate::EvidenceClaim {
        environment: env,
        measurements: vec![MeasurementMap {
            mkey: None,
            mval: MeasurementValuesMap {
                digests: Some(vec![Digest::new(7, vec![0xBB; 32])]), // different value
                ..Default::default()
            },
            authorized_by: None,
        }],
    }];
    let result = corim::validate::match_reference_values(&[ref_triple], &evidence);
    assert!(result.is_empty());
}

#[test]
fn match_reference_evidence_lacks_digests() {
    let env = EnvironmentMap::for_class("V", "M");
    let ref_triple = ReferenceTriple::new(
        env.clone(),
        vec![MeasurementMap {
            mkey: None,
            mval: MeasurementValuesMap {
                digests: Some(vec![Digest::new(7, vec![0xAA; 32])]),
                ..Default::default()
            },
            authorized_by: None,
        }],
    );
    let evidence = vec![corim::validate::EvidenceClaim {
        environment: env,
        measurements: vec![MeasurementMap {
            mkey: None,
            mval: MeasurementValuesMap {
                svn: Some(SvnChoice::ExactValue(1)),
                ..Default::default()
            },
            authorized_by: None,
        }],
    }];
    let result = corim::validate::match_reference_values(&[ref_triple], &evidence);
    assert!(result.is_empty());
}

#[test]
fn match_reference_evidence_lacks_svn() {
    let env = EnvironmentMap::for_class("V", "M");
    let ref_triple = ReferenceTriple::new(
        env.clone(),
        vec![MeasurementMap {
            mkey: None,
            mval: MeasurementValuesMap {
                svn: Some(SvnChoice::ExactValue(5)),
                ..Default::default()
            },
            authorized_by: None,
        }],
    );
    let evidence = vec![corim::validate::EvidenceClaim {
        environment: env,
        measurements: vec![MeasurementMap {
            mkey: None,
            mval: MeasurementValuesMap {
                digests: Some(vec![Digest::new(7, vec![0xAA; 32])]),
                ..Default::default()
            },
            authorized_by: None,
        }],
    }];
    let result = corim::validate::match_reference_values(&[ref_triple], &evidence);
    assert!(result.is_empty());
}

#[test]
fn apply_endorsement_series_no_env_match() {
    let ces = ConditionalEndorsementSeriesTriple::new(
        CesCondition {
            environment: EnvironmentMap::for_class("ACME", "Widget"),
            claims_list: vec![],
            authorized_by: None,
        },
        vec![ConditionalSeriesRecord::new(
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
                    name: Some("endorsed".into()),
                    ..Default::default()
                },
                authorized_by: None,
            }],
        )],
    );
    let evidence = vec![corim::validate::EvidenceClaim {
        environment: EnvironmentMap::for_class("OTHER", "Thing"),
        measurements: vec![],
    }];
    let result = corim::validate::apply_endorsement_series(&[ces], &evidence).unwrap();
    assert!(result.is_empty());
}

#[test]
fn apply_endorsement_series_no_selection_match() {
    let env = EnvironmentMap::for_class("V", "M");
    let ces = ConditionalEndorsementSeriesTriple::new(
        CesCondition {
            environment: env.clone(),
            claims_list: vec![],
            authorized_by: None,
        },
        vec![ConditionalSeriesRecord::new(
            vec![MeasurementMap {
                mkey: Some(MeasuredElement::Uint(99)),
                mval: MeasurementValuesMap {
                    svn: Some(SvnChoice::ExactValue(100)),
                    ..Default::default()
                },
                authorized_by: None,
            }],
            vec![MeasurementMap {
                mkey: None,
                mval: MeasurementValuesMap {
                    name: Some("e".into()),
                    ..Default::default()
                },
                authorized_by: None,
            }],
        )],
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
    let result = corim::validate::apply_endorsement_series(&[ces], &evidence).unwrap();
    assert!(result.is_empty());
}

#[test]
fn appraisal_context_endorsement_phase() {
    let env = EnvironmentMap::for_class("V", "M");
    let meas_sel = vec![MeasurementMap {
        mkey: Some(MeasuredElement::Uint(1)),
        mval: MeasurementValuesMap {
            svn: Some(SvnChoice::ExactValue(1)),
            ..Default::default()
        },
        authorized_by: None,
    }];
    let meas_add = vec![MeasurementMap {
        mkey: None,
        mval: MeasurementValuesMap {
            name: Some("endorsed-value".into()),
            ..Default::default()
        },
        authorized_by: None,
    }];
    let ces = ConditionalEndorsementSeriesTriple::new(
        CesCondition {
            environment: env.clone(),
            claims_list: vec![],
            authorized_by: None,
        },
        vec![ConditionalSeriesRecord::new(meas_sel.clone(), meas_add)],
    );
    let mut ctx = corim::validate::AppraisalContext::new();
    ctx.add_evidence(vec![corim::validate::EvidenceClaim {
        environment: env,
        measurements: meas_sel,
    }]);
    let endorsed = ctx.apply_conditional_endorsements(&[ces]).unwrap();
    assert_eq!(endorsed.len(), 1);
    assert!(ctx
        .entries
        .iter()
        .any(|e| e.claim_type == corim::validate::ClaimType::Endorsement));
}

// ===================================================================
// 🟡 Negative decode: types/common.rs — wrong tag inner types
// ===================================================================

/// Helper: encode a Value to CBOR, then try to decode as T. Returns the error string.
fn decode_err<T: serde::de::DeserializeOwned + std::fmt::Debug>(val: &Value) -> String {
    let bytes = cbor::encode(val).unwrap();
    cbor::decode::<T>(&bytes).unwrap_err().to_string()
}

#[test]
fn tag_id_bad_uuid_inner() {
    // Tag 37 wrapping text instead of bytes
    let v = Value::Tag(TAG_UUID, Box::new(Value::Text("not-bytes".into())));
    let err = decode_err::<TagIdChoice>(&v);
    assert!(err.contains("bytes"), "got: {err}");
}

#[test]
fn tag_id_unexpected_type() {
    let v = Value::Integer(42);
    let err = decode_err::<TagIdChoice>(&v);
    assert!(err.contains("expected"), "got: {err}");
}

#[test]
fn class_id_oid_non_bytes() {
    let v = Value::Tag(TAG_OID, Box::new(Value::Text("not-bytes".into())));
    let err = decode_err::<ClassIdChoice>(&v);
    assert!(err.contains("bytes"), "got: {err}");
}

#[test]
fn class_id_uuid_wrong_size() {
    let v = Value::Tag(TAG_UUID, Box::new(Value::Bytes(vec![0; 8])));
    let err = decode_err::<ClassIdChoice>(&v);
    assert!(err.contains("16 bytes"), "got: {err}");
}

#[test]
fn class_id_uuid_non_bytes() {
    let v = Value::Tag(TAG_UUID, Box::new(Value::Text("x".into())));
    let err = decode_err::<ClassIdChoice>(&v);
    assert!(err.contains("bytes"), "got: {err}");
}

#[test]
fn class_id_bytes_non_bytes() {
    let v = Value::Tag(TAG_BYTES, Box::new(Value::Integer(1)));
    let err = decode_err::<ClassIdChoice>(&v);
    assert!(err.contains("bytes"), "got: {err}");
}

#[test]
fn class_id_unknown_tag() {
    let v = Value::Tag(999, Box::new(Value::Bytes(vec![1])));
    let err = decode_err::<ClassIdChoice>(&v);
    assert!(err.contains("expected"), "got: {err}");
}

#[test]
fn instance_id_ueid_non_bytes() {
    let v = Value::Tag(TAG_UEID, Box::new(Value::Text("x".into())));
    let err = decode_err::<InstanceIdChoice>(&v);
    assert!(err.contains("bytes"), "got: {err}");
}

#[test]
fn instance_id_ueid_wrong_size() {
    let v = Value::Tag(TAG_UEID, Box::new(Value::Bytes(vec![0; 3])));
    let err = decode_err::<InstanceIdChoice>(&v);
    assert!(err.contains("7-33"), "got: {err}");
}

#[test]
fn instance_id_pkix_key_non_text() {
    let v = Value::Tag(TAG_PKIX_BASE64_KEY, Box::new(Value::Bytes(vec![1])));
    let err = decode_err::<InstanceIdChoice>(&v);
    assert!(err.contains("text"), "got: {err}");
}

#[test]
fn instance_id_pkix_cert_non_text() {
    let v = Value::Tag(TAG_PKIX_BASE64_CERT, Box::new(Value::Bytes(vec![1])));
    let err = decode_err::<InstanceIdChoice>(&v);
    assert!(err.contains("text"), "got: {err}");
}

#[test]
fn instance_id_cose_key_non_bytes() {
    let v = Value::Tag(TAG_COSE_KEY, Box::new(Value::Text("x".into())));
    let err = decode_err::<InstanceIdChoice>(&v);
    assert!(err.contains("bytes"), "got: {err}");
}

#[test]
fn instance_id_key_thumbprint_non_array() {
    let v = Value::Tag(TAG_KEY_THUMBPRINT, Box::new(Value::Text("x".into())));
    let err = decode_err::<InstanceIdChoice>(&v);
    assert!(err.contains("array"), "got: {err}");
}

#[test]
fn instance_id_cert_thumbprint_non_array() {
    let v = Value::Tag(TAG_CERT_THUMBPRINT, Box::new(Value::Text("x".into())));
    let err = decode_err::<InstanceIdChoice>(&v);
    assert!(err.contains("array"), "got: {err}");
}

#[test]
fn instance_id_asn1_cert_non_bytes() {
    let v = Value::Tag(TAG_PKIX_ASN1DER_CERT, Box::new(Value::Text("x".into())));
    let err = decode_err::<InstanceIdChoice>(&v);
    assert!(err.contains("bytes"), "got: {err}");
}

#[test]
fn instance_id_bytes_non_bytes() {
    let v = Value::Tag(TAG_BYTES, Box::new(Value::Integer(1)));
    let err = decode_err::<InstanceIdChoice>(&v);
    assert!(err.contains("bytes"), "got: {err}");
}

#[test]
fn instance_id_unknown_tag() {
    let v = Value::Integer(42);
    let err = decode_err::<InstanceIdChoice>(&v);
    assert!(err.contains("expected"), "got: {err}");
}

#[test]
fn group_id_uuid_non_bytes() {
    let v = Value::Tag(TAG_UUID, Box::new(Value::Text("x".into())));
    let err = decode_err::<GroupIdChoice>(&v);
    assert!(err.contains("bytes"), "got: {err}");
}

#[test]
fn group_id_uuid_wrong_size() {
    let v = Value::Tag(TAG_UUID, Box::new(Value::Bytes(vec![0; 8])));
    let err = decode_err::<GroupIdChoice>(&v);
    assert!(err.contains("16 bytes"), "got: {err}");
}

#[test]
fn group_id_bytes_non_bytes() {
    let v = Value::Tag(TAG_BYTES, Box::new(Value::Integer(1)));
    let err = decode_err::<GroupIdChoice>(&v);
    assert!(err.contains("bytes"), "got: {err}");
}

#[test]
fn group_id_unknown() {
    let v = Value::Text("nope".into());
    let err = decode_err::<GroupIdChoice>(&v);
    assert!(err.contains("expected"), "got: {err}");
}

#[test]
fn measured_element_negative_int() {
    let v = Value::Integer(-1);
    let err = decode_err::<MeasuredElement>(&v);
    assert!(err.contains("unsigned"), "got: {err}");
}

#[test]
fn measured_element_unknown() {
    let v = Value::Bool(true);
    let err = decode_err::<MeasuredElement>(&v);
    assert!(err.contains("expected"), "got: {err}");
}

#[test]
fn crypto_key_pkix_key_non_text() {
    let v = Value::Tag(TAG_PKIX_BASE64_KEY, Box::new(Value::Bytes(vec![1])));
    let err = decode_err::<CryptoKey>(&v);
    assert!(err.contains("text"), "got: {err}");
}

#[test]
fn crypto_key_pkix_cert_non_text() {
    let v = Value::Tag(TAG_PKIX_BASE64_CERT, Box::new(Value::Bytes(vec![1])));
    let err = decode_err::<CryptoKey>(&v);
    assert!(err.contains("text"), "got: {err}");
}

#[test]
fn crypto_key_pkix_cert_path_non_text() {
    let v = Value::Tag(TAG_PKIX_BASE64_CERT_PATH, Box::new(Value::Bytes(vec![1])));
    let err = decode_err::<CryptoKey>(&v);
    assert!(err.contains("text"), "got: {err}");
}

#[test]
fn crypto_key_cose_key_non_bytes() {
    let v = Value::Tag(TAG_COSE_KEY, Box::new(Value::Text("x".into())));
    let err = decode_err::<CryptoKey>(&v);
    assert!(err.contains("bytes"), "got: {err}");
}

#[test]
fn crypto_key_asn1_cert_non_bytes() {
    let v = Value::Tag(TAG_PKIX_ASN1DER_CERT, Box::new(Value::Text("x".into())));
    let err = decode_err::<CryptoKey>(&v);
    assert!(err.contains("bytes"), "got: {err}");
}

#[test]
fn crypto_key_bytes_non_bytes() {
    let v = Value::Tag(TAG_BYTES, Box::new(Value::Integer(1)));
    let err = decode_err::<CryptoKey>(&v);
    assert!(err.contains("bytes"), "got: {err}");
}

#[test]
fn crypto_key_unknown_tag() {
    let v = Value::Integer(42);
    let err = decode_err::<CryptoKey>(&v);
    assert!(err.contains("expected"), "got: {err}");
}

#[test]
fn crypto_key_key_thumbprint_non_array() {
    let v = Value::Tag(TAG_KEY_THUMBPRINT, Box::new(Value::Text("x".into())));
    let err = decode_err::<CryptoKey>(&v);
    assert!(err.contains("array"), "got: {err}");
}

#[test]
fn crypto_key_cert_thumbprint_non_array() {
    let v = Value::Tag(TAG_CERT_THUMBPRINT, Box::new(Value::Text("x".into())));
    let err = decode_err::<CryptoKey>(&v);
    assert!(err.contains("array"), "got: {err}");
}

#[test]
fn crypto_key_cert_path_thumbprint_non_array() {
    let v = Value::Tag(TAG_CERT_PATH_THUMBPRINT, Box::new(Value::Text("x".into())));
    let err = decode_err::<CryptoKey>(&v);
    assert!(err.contains("array"), "got: {err}");
}

// ===================================================================
// 🟡 Negative decode: types/measurement.rs
// ===================================================================

#[test]
fn svn_unknown_type() {
    let v = Value::Text("not-a-svn".into());
    let err = decode_err::<SvnChoice>(&v);
    assert!(err.contains("expected"), "got: {err}");
}

#[test]
fn mac_addr_wrong_length() {
    let v = Value::Bytes(vec![0; 4]); // not 6 or 8
    let err = decode_err::<MacAddr>(&v);
    assert!(err.contains("6 or 8"), "got: {err}");
}

#[test]
fn mac_addr_non_bytes() {
    let v = Value::Text("not-bytes".into());
    let err = decode_err::<MacAddr>(&v);
    assert!(err.contains("bytes"), "got: {err}");
}

#[test]
fn ip_addr_wrong_length() {
    let v = Value::Bytes(vec![0; 8]); // not 4 or 16
    let err = decode_err::<IpAddr>(&v);
    assert!(err.contains("4 or 16"), "got: {err}");
}

#[test]
fn ip_addr_non_bytes() {
    let v = Value::Text("not-bytes".into());
    let err = decode_err::<IpAddr>(&v);
    assert!(err.contains("bytes"), "got: {err}");
}

#[test]
fn int_range_bad_tag_inner() {
    let v = Value::Tag(TAG_INT_RANGE, Box::new(Value::Text("x".into())));
    let err = decode_err::<IntRangeChoice>(&v);
    assert!(err.contains("[min, max]"), "got: {err}");
}

#[test]
fn int_range_unknown_type() {
    let v = Value::Text("nope".into());
    let err = decode_err::<IntRangeChoice>(&v);
    assert!(err.contains("expected"), "got: {err}");
}

#[test]
fn raw_value_bad_tag_560_inner() {
    let v = Value::Tag(TAG_BYTES, Box::new(Value::Integer(1)));
    let err = decode_err::<RawValueChoice>(&v);
    assert!(err.contains("bytes"), "got: {err}");
}

#[test]
fn raw_value_bad_tag_563_inner() {
    let v = Value::Tag(TAG_MASKED_RAW_VALUE, Box::new(Value::Text("x".into())));
    let err = decode_err::<RawValueChoice>(&v);
    assert!(err.contains("[value, mask]"), "got: {err}");
}

#[test]
fn raw_value_unknown_tag() {
    let v = Value::Integer(42);
    let err = decode_err::<RawValueChoice>(&v);
    assert!(err.contains("expected"), "got: {err}");
}

#[test]
fn integrity_register_id_unknown_type() {
    // Map with a bool key (invalid for register id)
    let v = Value::Map(vec![(
        Value::Bool(true),
        Value::Array(vec![Value::Array(vec![
            Value::Integer(7),
            Value::Bytes(vec![0xAA; 32]),
        ])]),
    )]);
    let err = decode_err::<IntegrityRegisters>(&v);
    assert!(err.contains("uint or text"), "got: {err}");
}

#[test]
fn integrity_registers_non_map() {
    let v = Value::Array(vec![]);
    let err = decode_err::<IntegrityRegisters>(&v);
    assert!(err.contains("map"), "got: {err}");
}

#[test]
fn integrity_registers_non_array_digests() {
    let v = Value::Map(vec![(Value::Integer(0), Value::Text("not-array".into()))]);
    let err = decode_err::<IntegrityRegisters>(&v);
    assert!(err.contains("array"), "got: {err}");
}

#[test]
fn integrity_registers_bad_digest_format() {
    let v = Value::Map(vec![(
        Value::Integer(0),
        Value::Array(vec![Value::Text("not-a-pair".into())]),
    )]);
    let err = decode_err::<IntegrityRegisters>(&v);
    assert!(err.contains("digest"), "got: {err}");
}

#[test]
fn integrity_registers_bad_digest_alg() {
    let v = Value::Map(vec![(
        Value::Integer(0),
        Value::Array(vec![Value::Array(vec![
            Value::Text("not-int".into()),
            Value::Bytes(vec![0]),
        ])]),
    )]);
    let err = decode_err::<IntegrityRegisters>(&v);
    assert!(err.contains("alg"), "got: {err}");
}

#[test]
fn integrity_registers_bad_digest_val() {
    let v = Value::Map(vec![(
        Value::Integer(0),
        Value::Array(vec![Value::Array(vec![
            Value::Integer(7),
            Value::Text("not-bytes".into()),
        ])]),
    )]);
    let err = decode_err::<IntegrityRegisters>(&v);
    assert!(err.contains("val"), "got: {err}");
}

// ===================================================================
// 🟡 Negative decode: types/corim.rs
// ===================================================================

#[test]
fn corim_locator_href_non_text_array_items() {
    let v = Value::Map(vec![(
        Value::Integer(0),
        Value::Array(vec![Value::Integer(42)]),
    )]);
    let err = decode_err::<CorimLocator>(&v);
    // Behavior contract: non-text/non-#6.32(text) array items must be rejected.
    // Error wording changed when the deserializer started accepting #6.32-tagged
    // URIs (real-world producers like NVIDIA emit them).
    assert!(
        err.contains("text") || err.contains("URI") || err.contains("string"),
        "got: {err}"
    );
}

#[test]
fn corim_locator_href_wrong_type() {
    let v = Value::Map(vec![(Value::Integer(0), Value::Integer(42))]);
    let err = decode_err::<CorimLocator>(&v);
    assert!(
        err.contains("expected") || err.contains("href"),
        "got: {err}"
    );
}

#[test]
fn concise_tag_choice_non_tagged() {
    let v = Value::Text("not-tagged".into());
    let err = decode_err::<ConciseTagChoice>(&v);
    assert!(
        err.contains("tagged") || err.contains("expected"),
        "got: {err}"
    );
}

#[test]
fn concise_tag_choice_comid_non_bytes() {
    let v = Value::Tag(TAG_COMID, Box::new(Value::Text("x".into())));
    let err = decode_err::<ConciseTagChoice>(&v);
    assert!(err.contains("bytes"), "got: {err}");
}

#[test]
fn concise_tag_choice_coswid_non_bytes() {
    let v = Value::Tag(TAG_COSWID, Box::new(Value::Text("x".into())));
    let err = decode_err::<ConciseTagChoice>(&v);
    assert!(err.contains("bytes"), "got: {err}");
}

#[test]
fn concise_tag_choice_cotl_non_bytes() {
    let v = Value::Tag(TAG_COTL, Box::new(Value::Text("x".into())));
    let err = decode_err::<ConciseTagChoice>(&v);
    assert!(err.contains("bytes"), "got: {err}");
}

#[test]
fn profile_choice_unknown() {
    let v = Value::Integer(42);
    let err = decode_err::<ProfileChoice>(&v);
    assert!(err.contains("expected"), "got: {err}");
}

#[test]
fn corim_id_unknown() {
    let v = Value::Bool(true);
    let err = decode_err::<CorimId>(&v);
    assert!(err.contains("expected"), "got: {err}");
}

// ===================================================================
// 🟡 Negative decode: types/triples.rs — CesCondition
// ===================================================================

#[test]
fn ces_condition_round_trip_with_auth() {
    let cond = CesCondition {
        environment: EnvironmentMap::for_class("V", "M"),
        claims_list: vec![MeasurementMap {
            mkey: None,
            mval: MeasurementValuesMap {
                svn: Some(SvnChoice::ExactValue(1)),
                ..Default::default()
            },
            authorized_by: None,
        }],
        authorized_by: Some(vec![CryptoKey::PkixBase64Key("key".into())]),
    };
    let bytes = cbor::encode(&cond).unwrap();
    let decoded: CesCondition = cbor::decode(&bytes).unwrap();
    assert!(decoded.authorized_by.is_some());
    assert_eq!(decoded.claims_list.len(), 1);
}

#[test]
fn ces_condition_round_trip_without_auth() {
    let cond = CesCondition {
        environment: EnvironmentMap::for_class("V", "M"),
        claims_list: vec![],
        authorized_by: None,
    };
    let bytes = cbor::encode(&cond).unwrap();
    let decoded: CesCondition = cbor::decode(&bytes).unwrap();
    assert!(decoded.authorized_by.is_none());
}

#[test]
fn ces_triple_accessor_methods() {
    let env = EnvironmentMap::for_class("V", "M");
    let meas = vec![MeasurementMap {
        mkey: Some(MeasuredElement::Uint(1)),
        mval: MeasurementValuesMap {
            svn: Some(SvnChoice::ExactValue(1)),
            ..Default::default()
        },
        authorized_by: None,
    }];
    let record = ConditionalSeriesRecord::new(meas.clone(), meas.clone());
    assert_eq!(record.selection().len(), 1);
    assert_eq!(record.addition().len(), 1);

    let cond = CesCondition {
        environment: env.clone(),
        claims_list: vec![],
        authorized_by: None,
    };
    let ces = ConditionalEndorsementSeriesTriple::new(cond, vec![record]);
    assert_eq!(ces.condition().environment, env);
    assert_eq!(ces.series().len(), 1);
}

#[test]
fn endorsed_triple_accessors() {
    let env = EnvironmentMap::for_class("V", "M");
    let meas = vec![MeasurementMap {
        mkey: None,
        mval: MeasurementValuesMap {
            svn: Some(SvnChoice::ExactValue(1)),
            ..Default::default()
        },
        authorized_by: None,
    }];
    let t = EndorsedTriple::new(env.clone(), meas);
    assert_eq!(*t.condition(), env);
    assert_eq!(t.endorsement().len(), 1);
}

#[test]
fn reference_triple_accessors() {
    let env = EnvironmentMap::for_class("V", "M");
    let meas = vec![MeasurementMap {
        mkey: None,
        mval: MeasurementValuesMap {
            svn: Some(SvnChoice::ExactValue(1)),
            ..Default::default()
        },
        authorized_by: None,
    }];
    let t = ReferenceTriple::new(env.clone(), meas);
    assert_eq!(*t.environment(), env);
    assert_eq!(t.measurements().len(), 1);
}

#[test]
fn coswid_triple_accessors() {
    let t = CoswidTriple::new(
        EnvironmentMap::for_class("V", "M"),
        vec![TagIdChoice::Text("t".into())],
    );
    assert_eq!(
        t.environment().class.as_ref().unwrap().vendor.as_deref(),
        Some("V")
    );
    assert_eq!(t.tag_ids().len(), 1);
}

#[test]
fn identity_triple_accessors() {
    let t = IdentityTriple::new(
        EnvironmentMap::for_class("V", "M"),
        vec![CryptoKey::PkixBase64Key("k".into())],
        Some(KeyTripleConditions {
            mkey: Some(MeasuredElement::Uint(1)),
            authorized_by: None,
        }),
    );
    assert!(t.conditions().is_some());
    assert_eq!(t.keys().len(), 1);
    assert_eq!(*t.environment(), EnvironmentMap::for_class("V", "M"));
}

#[test]
fn attest_key_triple_accessors() {
    let t = AttestKeyTriple::new(
        EnvironmentMap::for_class("V", "M"),
        vec![CryptoKey::PkixBase64Key("k".into())],
        None,
    );
    assert!(t.conditions().is_none());
    assert_eq!(t.keys().len(), 1);
}

#[test]
fn domain_dependency_accessors() {
    let t = DomainDependencyTriple::new(
        EnvironmentMap::for_class("V", "M"),
        vec![EnvironmentMap::for_class("A", "B")],
    );
    assert_eq!(*t.domain_id(), EnvironmentMap::for_class("V", "M"));
    assert_eq!(t.trustees().len(), 1);
}

#[test]
fn domain_membership_accessors() {
    let t = DomainMembershipTriple::new(
        EnvironmentMap::for_class("V", "M"),
        vec![EnvironmentMap::for_class("A", "B")],
    );
    assert_eq!(*t.domain_id(), EnvironmentMap::for_class("V", "M"));
    assert_eq!(t.members().len(), 1);
}

// ===================================================================
// 🟠 Serde infra: value_de.rs error paths
// ===================================================================

#[test]
fn value_de_deserialize_seq_non_array() {
    // Try to decode an integer as a Vec
    let v = Value::Integer(42);
    let bytes = cbor::encode(&v).unwrap();
    let result = cbor::decode::<Vec<u32>>(&bytes);
    assert!(result.is_err());
}

#[test]
fn value_de_deserialize_map_non_map() {
    // Try to decode an integer as a map (via a struct)
    let v = Value::Integer(42);
    let bytes = cbor::encode(&v).unwrap();
    let result = cbor::decode::<std::collections::HashMap<String, u32>>(&bytes);
    assert!(result.is_err());
}

// ===================================================================
// 🟠 Serde infra: Tagged<T> decode errors
// ===================================================================

#[test]
fn tagged_wrong_tag_number() {
    // Encode with tag 999, try to decode as Tagged with expected tag
    let v = Value::Tag(999, Box::new(Value::Text("hello".into())));
    let bytes = cbor::encode(&v).unwrap();
    let decoded: corim::cbor::value::Tagged<String> = cbor::decode(&bytes).unwrap();
    // Tagged doesn't enforce the tag number itself — it just captures it
    assert_eq!(decoded.tag, 999);
}

#[test]
fn tagged_non_tag_value() {
    // Try to decode a bare integer as Tagged<T>
    let v = Value::Integer(42);
    let bytes = cbor::encode(&v).unwrap();
    let result = cbor::decode::<corim::cbor::value::Tagged<String>>(&bytes);
    assert!(result.is_err());
}

// ===================================================================
// 🟠 i128 boundary values through Value
// ===================================================================

#[test]
fn value_i128_large_positive() {
    // Values above u64::MAX cannot be represented in CBOR — should error, not panic
    let v = Value::Integer((u64::MAX as i128) + 1);
    let result = cbor::encode(&v);
    assert!(result.is_err(), "encoding i128 > u64::MAX should fail");
}

#[test]
fn value_i128_large_negative() {
    // Values below -(2^64) cannot be represented in CBOR — should error, not panic
    let v = Value::Integer(-(u64::MAX as i128) - 2);
    let result = cbor::encode(&v);
    assert!(result.is_err(), "encoding i128 < -(2^64) should fail");
}

#[test]
fn value_i128_min() {
    let v = Value::Integer(i64::MIN as i128);
    let bytes = cbor::encode(&v).unwrap();
    let decoded: Value = cbor::decode(&bytes).unwrap();
    assert_eq!(decoded, Value::Integer(i64::MIN as i128));
}

// ===================================================================
// 🟡 digest_from_value_array error paths (common.rs helper)
// ===================================================================

#[test]
fn digest_wrong_array_length() {
    // Encode a CryptoKey::KeyThumbprint with a 3-element array inside tag 557
    let v = Value::Tag(
        TAG_KEY_THUMBPRINT,
        Box::new(Value::Array(vec![
            Value::Integer(7),
            Value::Bytes(vec![0xAA; 32]),
            Value::Integer(0), // extra element
        ])),
    );
    let err = decode_err::<CryptoKey>(&v);
    assert!(
        err.contains("digest") || err.contains("[alg, val]"),
        "got: {err}"
    );
}

#[test]
fn digest_text_alg_accepted() {
    // CDDL: eatmc.digest = [alg: int / text, val: bytes]
    // Text alg IDs are accepted and stored as alg=-1.
    let v = Value::Tag(
        TAG_KEY_THUMBPRINT,
        Box::new(Value::Array(vec![
            Value::Text("sha-256".into()),
            Value::Bytes(vec![0]),
        ])),
    );
    let bytes = cbor::encode(&v).unwrap();
    let key: CryptoKey = cbor::decode(&bytes).unwrap();
    match key {
        CryptoKey::KeyThumbprint(d) => assert!(matches!(d.alg(), DigestAlg::Text(_))),
        other => panic!("expected KeyThumbprint, got {:?}", other),
    }
}

#[test]
fn digest_non_bytes_val() {
    let v = Value::Tag(
        TAG_KEY_THUMBPRINT,
        Box::new(Value::Array(vec![
            Value::Integer(7),
            Value::Text("not-bytes".into()),
        ])),
    );
    let err = decode_err::<CryptoKey>(&v);
    assert!(err.contains("val"), "got: {err}");
}

// ===================================================================
// CorimLocatorThumbprint edge cases
// ===================================================================

#[test]
fn locator_thumbprint_empty_array() {
    let v = Value::Map(vec![
        (Value::Integer(0), Value::Text("https://x.com".into())),
        (Value::Integer(1), Value::Array(vec![])),
    ]);
    let err = decode_err::<CorimLocator>(&v);
    assert!(
        err.contains("array") || err.contains("thumbprint"),
        "got: {err}"
    );
}

// ===================================================================
// CborTime from/into i64
// ===================================================================

#[test]
fn cbor_time_conversions() {
    let t: CborTime = 12345i64.into();
    let val: i64 = t.into();
    assert_eq!(val, 12345);
}
