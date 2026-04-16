// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Tests for the corim crate.
//!
//! Covers derive macro round-trips, builder API, CBOR encoding,
//! and validation.

#[cfg(test)]
mod derive_tests {
    use corim::cbor;
    use corim::types::environment::{ClassMap, EnvironmentMap};

    #[test]
    fn class_map_round_trip() {
        let class = ClassMap {
            class_id: None,
            vendor: Some("AMD".into()),
            model: Some("SEV-SNP".into()),
            layer: None,
            index: None,
        };

        let bytes = cbor::encode(&class).unwrap();
        let decoded: ClassMap = cbor::decode(&bytes).unwrap();
        assert_eq!(class, decoded);
    }

    #[test]
    fn class_map_integer_keys() {
        let class = ClassMap {
            class_id: None,
            vendor: Some("AMD".into()),
            model: Some("SEV-SNP".into()),
            layer: None,
            index: None,
        };

        let bytes = cbor::encode(&class).unwrap();
        let val: corim::cbor::value::Value = corim::cbor::decode(&bytes).unwrap();
        if let corim::cbor::value::Value::Map(entries) = val {
            for (key, _) in &entries {
                match key {
                    corim::cbor::value::Value::Integer(_) => {}
                    other => panic!("Expected integer key, got {:?}", other),
                }
            }
            assert_eq!(entries.len(), 2);
        } else {
            panic!("Expected CBOR map, got {:?}", val);
        }
    }

    #[test]
    fn environment_map_non_empty_enforced() {
        let env = EnvironmentMap {
            class: None,
            instance: None,
            group: None,
        };

        let result = cbor::encode(&env);
        assert!(result.is_err(), "should fail non-empty check");
    }

    #[test]
    fn class_map_non_empty_enforced() {
        let class = ClassMap {
            class_id: None,
            vendor: None,
            model: None,
            layer: None,
            index: None,
        };

        let result = cbor::encode(&class);
        assert!(result.is_err(), "should fail non-empty check");
    }

    #[test]
    fn environment_map_round_trip() {
        let env = EnvironmentMap {
            class: Some(ClassMap {
                class_id: None,
                vendor: Some("Intel".into()),
                model: Some("TDX".into()),
                layer: None,
                index: None,
            }),
            instance: None,
            group: None,
        };

        let bytes = cbor::encode(&env).unwrap();
        let decoded: EnvironmentMap = cbor::decode(&bytes).unwrap();
        assert_eq!(env, decoded);
    }
}

#[cfg(test)]
mod measurement_tests {
    use corim::cbor;
    use corim::types::measurement::{Digest, MeasurementMap, MeasurementValuesMap, SvnChoice};

    #[test]
    fn digest_round_trip() {
        let digest = Digest::new(7, vec![0xAA; 48]);

        let bytes = cbor::encode(&digest).unwrap();
        let decoded: Digest = cbor::decode(&bytes).unwrap();
        assert_eq!(digest, decoded);
    }

    #[test]
    fn svn_exact_round_trip() {
        let svn = SvnChoice::ExactValue(42);

        let bytes = cbor::encode(&svn).unwrap();
        let decoded: SvnChoice = cbor::decode(&bytes).unwrap();
        assert_eq!(decoded, SvnChoice::ExactValue(42));
    }

    #[test]
    fn svn_min_round_trip() {
        let svn = SvnChoice::MinValue(10);

        let bytes = cbor::encode(&svn).unwrap();
        let decoded: SvnChoice = cbor::decode(&bytes).unwrap();
        assert_eq!(decoded, SvnChoice::MinValue(10));
    }

    #[test]
    fn measurement_values_map_with_digests() {
        let mval = MeasurementValuesMap {
            svn: Some(SvnChoice::ExactValue(1)),
            digests: Some(vec![Digest::new(7, vec![0xBB; 48])]),
            ..MeasurementValuesMap::default()
        };

        let bytes = cbor::encode(&mval).unwrap();
        let decoded: MeasurementValuesMap = cbor::decode(&bytes).unwrap();
        assert_eq!(mval, decoded);
    }

    #[test]
    fn measurement_map_round_trip() {
        let meas = MeasurementMap {
            mkey: Some(corim::types::common::MeasuredElement::Text(
                "MEASUREMENT".into(),
            )),
            mval: MeasurementValuesMap {
                digests: Some(vec![Digest::new(7, vec![0xCC; 48])]),
                ..MeasurementValuesMap::default()
            },
            authorized_by: None,
        };

        let bytes = cbor::encode(&meas).unwrap();
        let decoded: MeasurementMap = cbor::decode(&bytes).unwrap();
        assert_eq!(meas, decoded);
    }
}

#[cfg(test)]
mod builder_tests {
    use corim::builder::{ComidBuilder, CorimBuilder};
    use corim::cbor;
    use corim::types::common::{MeasuredElement, TagIdChoice};
    use corim::types::corim::CorimId;
    use corim::types::environment::{ClassMap, EnvironmentMap};
    use corim::types::measurement::{Digest, MeasurementMap, MeasurementValuesMap, SvnChoice};
    use corim::types::triples::{
        CesCondition, ConditionalEndorsementSeriesTriple, ConditionalSeriesRecord, ReferenceTriple,
    };

    fn make_env() -> EnvironmentMap {
        EnvironmentMap {
            class: Some(ClassMap {
                class_id: None,
                vendor: Some("ACME".into()),
                model: Some("Widget".into()),
                layer: None,
                index: None,
            }),
            instance: None,
            group: None,
        }
    }

    fn make_ref_measurement(mkey: &str, digest: Vec<u8>) -> MeasurementMap {
        MeasurementMap {
            mkey: Some(MeasuredElement::Text(mkey.into())),
            mval: MeasurementValuesMap {
                digests: Some(vec![Digest::new(7, digest)]),
                ..MeasurementValuesMap::default()
            },
            authorized_by: None,
        }
    }

    #[test]
    fn comid_builder_with_reference_triple() {
        let env = make_env();
        let meas = make_ref_measurement("firmware", vec![0xAA; 48]);

        let comid = ComidBuilder::new(TagIdChoice::Text("test-tag-001".into()))
            .add_reference_triple(ReferenceTriple::new(env, vec![meas]))
            .build()
            .unwrap();

        assert_eq!(
            comid.tag_identity.tag_id,
            TagIdChoice::Text("test-tag-001".into())
        );
        assert!(comid.triples.reference_triples.is_some());
    }

    #[test]
    fn comid_builder_with_uuid_tag_id() {
        let env = make_env();
        let meas = make_ref_measurement("firmware", vec![0xAA; 48]);
        let uuid_bytes = [0x01u8; 16];

        let comid = ComidBuilder::new(TagIdChoice::Uuid(uuid_bytes))
            .add_reference_triple(ReferenceTriple::new(env, vec![meas]))
            .build()
            .unwrap();

        assert_eq!(comid.tag_identity.tag_id, TagIdChoice::Uuid(uuid_bytes));
    }

    #[test]
    fn comid_builder_with_ces() {
        let env = make_env();
        let meas = make_ref_measurement("firmware", vec![0xAA; 48]);

        let ces_triple = ConditionalEndorsementSeriesTriple::new(
            CesCondition {
                environment: env.clone(),
                claims_list: Vec::new(),
                authorized_by: None,
            },
            vec![ConditionalSeriesRecord::new(
                vec![make_ref_measurement("firmware", vec![0xAA; 48])],
                vec![MeasurementMap {
                    mkey: None,
                    mval: MeasurementValuesMap {
                        svn: Some(SvnChoice::ExactValue(1)),
                        ..MeasurementValuesMap::default()
                    },
                    authorized_by: None,
                }],
            )],
        );

        let comid = ComidBuilder::new(TagIdChoice::Text("test-tag-002".into()))
            .add_reference_triple(ReferenceTriple::new(env, vec![meas]))
            .add_conditional_endorsement_series(ces_triple)
            .build()
            .unwrap();

        assert!(comid.triples.reference_triples.is_some());
        assert!(comid.triples.conditional_endorsement_series.is_some());
    }

    #[test]
    fn comid_builder_empty_triples_fails() {
        let result = ComidBuilder::new(TagIdChoice::Text("empty".into())).build();
        assert!(result.is_err());
    }

    #[test]
    fn corim_builder_round_trip() {
        let env = make_env();
        let meas = make_ref_measurement("firmware", vec![0xAA; 48]);

        let comid = ComidBuilder::new(TagIdChoice::Text("test-tag-003".into()))
            .add_reference_triple(ReferenceTriple::new(env, vec![meas]))
            .build()
            .unwrap();

        let bytes = CorimBuilder::new(CorimId::Text("test-corim-001".into()))
            .add_comid_tag(comid)
            .unwrap()
            .build_bytes()
            .unwrap();

        let tagged: corim::cbor::value::Tagged<corim::types::corim::CorimMap> =
            cbor::decode(&bytes).unwrap();
        let corim = tagged.value;

        assert_eq!(corim.id, CorimId::Text("test-corim-001".into()));
        assert_eq!(corim.tags.len(), 1);
    }

    #[test]
    fn corim_builder_no_tags_fails() {
        let result = CorimBuilder::new(CorimId::Text("empty".into())).build();
        assert!(result.is_err());
    }

    #[test]
    fn corim_builder_with_coswid_tag() {
        let coswid_bytes = vec![0xA0]; // minimal empty CBOR map for testing
        let corim = CorimBuilder::new(CorimId::Text("coswid-test".into()))
            .add_coswid_tag(coswid_bytes)
            .build()
            .unwrap();

        assert_eq!(corim.tags.len(), 1);
        match &corim.tags[0] {
            corim::types::corim::ConciseTagChoice::Coswid(_) => {}
            other => panic!("Expected Coswid tag, got {:?}", other),
        }
    }
}

#[cfg(test)]
mod validation_tests {
    use corim::builder::{ComidBuilder, CorimBuilder};
    use corim::types::common::{MeasuredElement, TagIdChoice};
    use corim::types::corim::CorimId;
    use corim::types::environment::{ClassMap, EnvironmentMap};
    use corim::types::measurement::{Digest, MeasurementMap, MeasurementValuesMap, SvnChoice};
    use corim::types::triples::{
        CesCondition, ConditionalEndorsementSeriesTriple, ConditionalSeriesRecord, ReferenceTriple,
    };
    use corim::validate::{
        apply_endorsement_series, match_reference_values, svn_matches, AppraisalContext,
        EvidenceClaim,
    };

    fn make_env() -> EnvironmentMap {
        EnvironmentMap {
            class: Some(ClassMap {
                class_id: None,
                vendor: Some("ACME".into()),
                model: Some("Widget".into()),
                layer: None,
                index: None,
            }),
            instance: None,
            group: None,
        }
    }

    fn make_measurement(mkey: &str, digest: Vec<u8>) -> MeasurementMap {
        MeasurementMap {
            mkey: Some(MeasuredElement::Text(mkey.into())),
            mval: MeasurementValuesMap {
                digests: Some(vec![Digest::new(7, digest)]),
                ..MeasurementValuesMap::default()
            },
            authorized_by: None,
        }
    }

    fn make_test_comid() -> corim::types::comid::ComidTag {
        let env = make_env();
        let ces_triple = ConditionalEndorsementSeriesTriple::new(
            CesCondition {
                environment: env.clone(),
                claims_list: Vec::new(),
                authorized_by: None,
            },
            vec![ConditionalSeriesRecord::new(
                vec![make_measurement("firmware", vec![0xAA; 48])],
                vec![MeasurementMap {
                    mkey: None,
                    mval: MeasurementValuesMap {
                        svn: Some(SvnChoice::ExactValue(1)),
                        ..MeasurementValuesMap::default()
                    },
                    authorized_by: None,
                }],
            )],
        );

        ComidBuilder::new(TagIdChoice::Text("validation-comid".into()))
            .add_reference_triple(ReferenceTriple::new(
                env,
                vec![make_measurement("firmware", vec![0xAA; 48])],
            ))
            .add_conditional_endorsement_series(ces_triple)
            .build()
            .unwrap()
    }

    fn make_test_corim_bytes() -> Vec<u8> {
        CorimBuilder::new(CorimId::Text("test-validation".into()))
            .set_validity(None, i64::MAX)
            .unwrap()
            .add_comid_tag(make_test_comid())
            .unwrap()
            .build_bytes()
            .unwrap()
    }

    #[test]
    fn decode_and_validate_happy_path() {
        let bytes = make_test_corim_bytes();
        let (corim, comids) = corim::validate::decode_and_validate(&bytes).unwrap();
        assert_eq!(corim.tags.len(), 1);
        assert_eq!(comids.len(), 1);
    }

    #[test]
    fn decode_and_validate_expired() {
        let comid = make_test_comid();

        let bytes = CorimBuilder::new(CorimId::Text("expired".into()))
            .set_validity(None, 0)
            .unwrap() // epoch = expired
            .add_comid_tag(comid)
            .unwrap()
            .build_bytes()
            .unwrap();

        let result = corim::validate::decode_and_validate(&bytes);
        assert!(result.is_err());
        let err_msg = format!("{}", result.unwrap_err());
        assert!(err_msg.contains("expired"), "error: {}", err_msg);
    }

    #[test]
    fn reference_value_matching() {
        let env = make_env();

        let ref_triples = vec![ReferenceTriple::new(
            env.clone(),
            vec![make_measurement("firmware", vec![0xAA; 48])],
        )];

        let evidence = vec![EvidenceClaim {
            environment: env.clone(),
            measurements: vec![make_measurement("firmware", vec![0xAA; 48])],
        }];

        let result = match_reference_values(&ref_triples, &evidence);
        assert_eq!(result.len(), 1);
    }

    #[test]
    fn reference_value_digest_mismatch() {
        let env = make_env();

        let ref_triples = vec![ReferenceTriple::new(
            env.clone(),
            vec![make_measurement("firmware", vec![0xAA; 48])],
        )];

        let evidence = vec![EvidenceClaim {
            environment: env.clone(),
            measurements: vec![make_measurement("firmware", vec![0xBB; 48])],
        }];

        let result = match_reference_values(&ref_triples, &evidence);
        assert!(result.is_empty());
    }

    #[test]
    fn reference_value_no_common_algorithms() {
        let env = make_env();

        let ref_triples = vec![ReferenceTriple::new(
            env.clone(),
            vec![make_measurement("firmware", vec![0xAA; 48])],
        )];

        let evidence = vec![EvidenceClaim {
            environment: env.clone(),
            measurements: vec![MeasurementMap {
                mkey: Some(MeasuredElement::Text("firmware".into())),
                mval: MeasurementValuesMap {
                    digests: Some(vec![Digest::new(1, vec![0xAA; 32])]), // SHA-256 (different alg)
                    ..MeasurementValuesMap::default()
                },
                authorized_by: None,
            }],
        }];

        let result = match_reference_values(&ref_triples, &evidence);
        assert!(result.is_empty(), "no common alg should mean no match");
    }

    #[test]
    fn svn_exact_match() {
        assert!(svn_matches(&SvnChoice::ExactValue(5), 5));
        assert!(!svn_matches(&SvnChoice::ExactValue(5), 6));
        assert!(!svn_matches(&SvnChoice::ExactValue(5), 4));
    }

    #[test]
    fn svn_min_match() {
        assert!(svn_matches(&SvnChoice::MinValue(5), 5));
        assert!(svn_matches(&SvnChoice::MinValue(5), 10));
        assert!(!svn_matches(&SvnChoice::MinValue(5), 4));
    }

    #[test]
    fn conditional_endorsement_series_application() {
        let env = make_env();

        let ces = vec![ConditionalEndorsementSeriesTriple::new(
            CesCondition {
                environment: env.clone(),
                claims_list: Vec::new(),
                authorized_by: None,
            },
            vec![
                ConditionalSeriesRecord::new(
                    vec![make_measurement("firmware", vec![0xAA; 48])],
                    vec![MeasurementMap {
                        mkey: None,
                        mval: MeasurementValuesMap {
                            svn: Some(SvnChoice::ExactValue(1)),
                            ..MeasurementValuesMap::default()
                        },
                        authorized_by: None,
                    }],
                ),
                ConditionalSeriesRecord::new(
                    vec![make_measurement("firmware", vec![0xBB; 48])],
                    vec![MeasurementMap {
                        mkey: None,
                        mval: MeasurementValuesMap {
                            svn: Some(SvnChoice::ExactValue(2)),
                            ..MeasurementValuesMap::default()
                        },
                        authorized_by: None,
                    }],
                ),
            ],
        )];

        let evidence = vec![EvidenceClaim {
            environment: env.clone(),
            measurements: vec![make_measurement("firmware", vec![0xAA; 48])],
        }];

        let endorsed = apply_endorsement_series(&ces, &evidence).unwrap();
        assert_eq!(endorsed.len(), 1);
        let svn = &endorsed[0].endorsements[0].mval.svn;
        assert_eq!(*svn, Some(SvnChoice::ExactValue(1)));
    }

    #[test]
    fn appraisal_context_full_flow() {
        let env = make_env();

        let ref_triples = vec![ReferenceTriple::new(
            env.clone(),
            vec![make_measurement("firmware", vec![0xAA; 48])],
        )];

        let ces = vec![ConditionalEndorsementSeriesTriple::new(
            CesCondition {
                environment: env.clone(),
                claims_list: Vec::new(),
                authorized_by: None,
            },
            vec![ConditionalSeriesRecord::new(
                vec![make_measurement("firmware", vec![0xAA; 48])],
                vec![MeasurementMap {
                    mkey: None,
                    mval: MeasurementValuesMap {
                        svn: Some(SvnChoice::ExactValue(1)),
                        ..MeasurementValuesMap::default()
                    },
                    authorized_by: None,
                }],
            )],
        )];

        let mut acs = AppraisalContext::new();

        // Phase 2: Add evidence
        acs.add_evidence(vec![EvidenceClaim {
            environment: env.clone(),
            measurements: vec![make_measurement("firmware", vec![0xAA; 48])],
        }]);

        // Phase 3: Reference values
        let corroborated = acs.apply_reference_values(&ref_triples);
        assert_eq!(corroborated.len(), 1);

        // Phase 4: Conditional endorsements
        let endorsed = acs.apply_conditional_endorsements(&ces).unwrap();
        assert_eq!(endorsed.len(), 2);

        // ACS should have entries from all phases
        assert!(acs.entries.len() >= 4);
    }
}

#[cfg(test)]
mod typed_triple_tests {
    use corim::cbor;
    use corim::types::common::{CryptoKey, TagIdChoice};
    use corim::types::environment::{ClassMap, EnvironmentMap};
    use corim::types::measurement::{Digest, MeasurementMap, MeasurementValuesMap};
    use corim::types::triples::*;

    fn make_env() -> EnvironmentMap {
        EnvironmentMap {
            class: Some(ClassMap {
                class_id: None,
                vendor: Some("TestVendor".into()),
                model: Some("TestModel".into()),
                layer: None,
                index: None,
            }),
            instance: None,
            group: None,
        }
    }

    #[test]
    fn identity_triple_round_trip() {
        let triple = IdentityTriple::new(
            make_env(),
            vec![CryptoKey::PkixBase64Key("test-key".into())],
            None,
        );

        let bytes = cbor::encode(&triple).unwrap();
        let decoded: IdentityTriple = cbor::decode(&bytes).unwrap();
        assert_eq!(decoded.0, triple.0);
        assert_eq!(decoded.1.len(), 1);
    }

    #[test]
    fn attest_key_triple_round_trip() {
        let triple = AttestKeyTriple::new(
            make_env(),
            vec![CryptoKey::Bytes(vec![0x01, 0x02, 0x03])],
            None,
        );

        let bytes = cbor::encode(&triple).unwrap();
        let decoded: AttestKeyTriple = cbor::decode(&bytes).unwrap();
        assert_eq!(decoded.0, triple.0);
    }

    #[test]
    fn domain_dependency_triple_round_trip() {
        let triple = DomainDependencyTriple::new(make_env(), vec![make_env()]);

        let bytes = cbor::encode(&triple).unwrap();
        let decoded: DomainDependencyTriple = cbor::decode(&bytes).unwrap();
        assert_eq!(decoded.0, triple.0);
        assert_eq!(decoded.1.len(), 1);
    }

    #[test]
    fn domain_membership_triple_round_trip() {
        let triple = DomainMembershipTriple::new(make_env(), vec![make_env()]);

        let bytes = cbor::encode(&triple).unwrap();
        let decoded: DomainMembershipTriple = cbor::decode(&bytes).unwrap();
        assert_eq!(decoded.0, triple.0);
    }

    #[test]
    fn coswid_triple_round_trip() {
        let triple = CoswidTriple::new(make_env(), vec![TagIdChoice::Text("test-tag-id".into())]);

        let bytes = cbor::encode(&triple).unwrap();
        let decoded: CoswidTriple = cbor::decode(&bytes).unwrap();
        assert_eq!(decoded.0, triple.0);
        assert_eq!(decoded.1.len(), 1);
    }

    #[test]
    fn triples_map_with_all_triple_types() {
        let env = make_env();
        let meas = MeasurementMap {
            mkey: None,
            mval: MeasurementValuesMap {
                digests: Some(vec![Digest::new(7, vec![0xAA; 48])]),
                ..MeasurementValuesMap::default()
            },
            authorized_by: None,
        };

        let triples = TriplesMap {
            reference_triples: Some(vec![ReferenceTriple::new(env.clone(), vec![meas.clone()])]),
            endorsed_triples: Some(vec![EndorsedTriple::new(env.clone(), vec![meas.clone()])]),
            identity_triples: Some(vec![IdentityTriple::new(
                env.clone(),
                vec![CryptoKey::PkixBase64Key("key".into())],
                None,
            )]),
            attest_key_triples: Some(vec![AttestKeyTriple::new(
                env.clone(),
                vec![CryptoKey::Bytes(vec![1, 2, 3])],
                None,
            )]),
            dependency_triples: Some(vec![DomainDependencyTriple::new(
                env.clone(),
                vec![env.clone()],
            )]),
            membership_triples: Some(vec![DomainMembershipTriple::new(
                env.clone(),
                vec![env.clone()],
            )]),
            coswid_triples: Some(vec![CoswidTriple::new(
                env.clone(),
                vec![TagIdChoice::Text("tag-1".into())],
            )]),
            conditional_endorsement_series: None,
            conditional_endorsement: None,
        };

        let bytes = cbor::encode(&triples).unwrap();
        let decoded: TriplesMap = cbor::decode(&bytes).unwrap();
        assert!(decoded.reference_triples.is_some());
        assert!(decoded.endorsed_triples.is_some());
        assert!(decoded.identity_triples.is_some());
        assert!(decoded.attest_key_triples.is_some());
        assert!(decoded.dependency_triples.is_some());
        assert!(decoded.membership_triples.is_some());
        assert!(decoded.coswid_triples.is_some());
    }
}

#[cfg(test)]
mod corim_type_tests {
    use corim::cbor;
    use corim::types::common::{CborTime, TagIdChoice, TagIdentity, ValidityMap};
    use corim::types::corim::*;

    #[test]
    fn corim_signer_map_round_trip() {
        let signer = CorimSignerMap {
            signer_name: "ACME Corp".into(),
            signer_uri: Some("https://acme.example.com".into()),
        };

        let bytes = cbor::encode(&signer).unwrap();
        let decoded: CorimSignerMap = cbor::decode(&bytes).unwrap();
        assert_eq!(signer, decoded);
    }

    #[test]
    fn corim_meta_map_round_trip() {
        let meta = CorimMetaMap {
            signer: CorimSignerMap {
                signer_name: "ACME Corp".into(),
                signer_uri: None,
            },
            signature_validity: Some(ValidityMap {
                not_before: Some(CborTime(1000)),
                not_after: CborTime(2000),
            }),
        };

        let bytes = cbor::encode(&meta).unwrap();
        let decoded: CorimMetaMap = cbor::decode(&bytes).unwrap();
        assert_eq!(meta, decoded);
    }

    #[test]
    fn concise_tl_tag_round_trip() {
        let cotl = ConciseTlTag {
            tag_identity: TagIdentity {
                tag_id: TagIdChoice::Text("cotl-1".into()),
                tag_version: Some(0),
            },
            tags_list: vec![TagIdentity {
                tag_id: TagIdChoice::Text("comid-1".into()),
                tag_version: None,
            }],
            tl_validity: ValidityMap {
                not_before: None,
                not_after: CborTime(9999999999),
            },
        };

        let bytes = cbor::encode(&cotl).unwrap();
        let decoded: ConciseTlTag = cbor::decode(&bytes).unwrap();
        assert_eq!(cotl, decoded);
    }

    #[test]
    fn corim_locator_round_trip() {
        let locator = CorimLocator {
            href: CorimLocatorHref::Single("https://example.com/rim.corim".into()),
            thumbprint: None,
        };

        let bytes = cbor::encode(&locator).unwrap();
        let decoded: CorimLocator = cbor::decode(&bytes).unwrap();
        assert_eq!(locator, decoded);
    }
}

#[cfg(test)]
mod measurement_extension_tests {
    use corim::cbor;
    use corim::types::measurement::*;

    #[test]
    fn mac_addr_eui48_round_trip() {
        let mval = MeasurementValuesMap {
            mac_addr: Some(MacAddr::Eui48([0x00, 0x11, 0x22, 0x33, 0x44, 0x55])),
            ..MeasurementValuesMap::default()
        };

        let bytes = cbor::encode(&mval).unwrap();
        let decoded: MeasurementValuesMap = cbor::decode(&bytes).unwrap();
        assert_eq!(mval.mac_addr, decoded.mac_addr);
    }

    #[test]
    fn ip_addr_v4_round_trip() {
        let mval = MeasurementValuesMap {
            ip_addr: Some(IpAddr::V4([192, 168, 1, 1])),
            ..MeasurementValuesMap::default()
        };

        let bytes = cbor::encode(&mval).unwrap();
        let decoded: MeasurementValuesMap = cbor::decode(&bytes).unwrap();
        assert_eq!(mval.ip_addr, decoded.ip_addr);
    }

    #[test]
    fn int_range_round_trip() {
        let mval = MeasurementValuesMap {
            int_range: Some(IntRangeChoice::Range {
                min: Some(0),
                max: Some(100),
            }),
            ..MeasurementValuesMap::default()
        };

        let bytes = cbor::encode(&mval).unwrap();
        let decoded: MeasurementValuesMap = cbor::decode(&bytes).unwrap();
        assert_eq!(mval.int_range, decoded.int_range);
    }

    #[test]
    fn int_range_unbounded_round_trip() {
        let mval = MeasurementValuesMap {
            int_range: Some(IntRangeChoice::Range {
                min: None,
                max: Some(50),
            }),
            ..MeasurementValuesMap::default()
        };

        let bytes = cbor::encode(&mval).unwrap();
        let decoded: MeasurementValuesMap = cbor::decode(&bytes).unwrap();
        assert_eq!(mval.int_range, decoded.int_range);
    }
}
