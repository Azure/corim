// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Example: build a sample unsigned CoRIM with the builder API.
//!
//! Writes the CBOR to the path given as the first argument, or to stdout
//! when none is given. Run with:
//! `cargo run -p corim-cli --example gen_sample > sample.corim`.

fn main() {
    use corim::builder::{ComidBuilder, CorimBuilder};
    use corim::types::common::{EntityMap, MeasuredElement, TagIdChoice};
    use corim::types::corim::CorimId;
    use corim::types::environment::{ClassMap, EnvironmentMap};
    use corim::types::measurement::{Digest, MeasurementMap, MeasurementValuesMap, SvnChoice};
    use corim::types::triples::{
        CesCondition, ConditionalEndorsementSeriesTriple, ConditionalSeriesRecord, EndorsedTriple,
        ReferenceTriple,
    };

    let env = EnvironmentMap {
        class: Some(ClassMap {
            class_id: None,
            vendor: Some("ACME Corp".into()),
            model: Some("Turbo Encabulator".into()),
            layer: Some(0),
            index: None,
        }),
        instance: None,
        group: None,
    };

    let ref_meas = MeasurementMap {
        mkey: Some(MeasuredElement::Text("firmware".into())),
        mval: MeasurementValuesMap {
            digests: Some(vec![
                Digest::new(7, vec![0xAA; 48]), // SHA-384
                Digest::new(2, vec![0xBB; 32]), // SHA-256
            ]),
            ..MeasurementValuesMap::default()
        },
        authorized_by: None,
    };

    let endorsed_meas = MeasurementMap {
        mkey: None,
        mval: MeasurementValuesMap {
            svn: Some(SvnChoice::MinValue(3)),
            ..MeasurementValuesMap::default()
        },
        authorized_by: None,
    };

    let ces_triple = ConditionalEndorsementSeriesTriple::new(
        CesCondition {
            environment: env.clone(),
            claims_list: Vec::new(),
            authorized_by: None,
        },
        vec![
            ConditionalSeriesRecord::new(
                vec![MeasurementMap {
                    mkey: Some(MeasuredElement::Text("firmware".into())),
                    mval: MeasurementValuesMap {
                        digests: Some(vec![Digest::new(7, vec![0xAA; 48])]),
                        ..MeasurementValuesMap::default()
                    },
                    authorized_by: None,
                }],
                vec![MeasurementMap {
                    mkey: None,
                    mval: MeasurementValuesMap {
                        svn: Some(SvnChoice::ExactValue(5)),
                        ..MeasurementValuesMap::default()
                    },
                    authorized_by: None,
                }],
            ),
            ConditionalSeriesRecord::new(
                vec![MeasurementMap {
                    mkey: Some(MeasuredElement::Text("firmware".into())),
                    mval: MeasurementValuesMap {
                        digests: Some(vec![Digest::new(7, vec![0xCC; 48])]),
                        ..MeasurementValuesMap::default()
                    },
                    authorized_by: None,
                }],
                vec![MeasurementMap {
                    mkey: None,
                    mval: MeasurementValuesMap {
                        svn: Some(SvnChoice::ExactValue(4)),
                        ..MeasurementValuesMap::default()
                    },
                    authorized_by: None,
                }],
            ),
        ],
    );

    let comid = ComidBuilder::new(TagIdChoice::Text(
        "example.com/acme/turbo-encabulator/1.0".into(),
    ))
    .set_tag_version(0)
    .set_language("en")
    .add_entity(EntityMap {
        entity_name: "ACME Corp".into(),
        reg_id: Some("https://acme.example.com".into()),
        role: vec![0, 1], // tag-creator + creator
    })
    .add_reference_triple(ReferenceTriple::new(env.clone(), vec![ref_meas]))
    .add_endorsed_triple(EndorsedTriple::new(env.clone(), vec![endorsed_meas]))
    .add_conditional_endorsement_series(ces_triple)
    .build()
    .unwrap();

    let bytes = CorimBuilder::new(CorimId::Text("example.com/acme/corim/1.0".into()))
        .set_profile(corim::types::corim::ProfileChoice::Uri(
            "https://example.com/acme-profile/v1".into(),
        ))
        .set_validity(Some(1700000000), 1900000000)
        .unwrap()
        .add_entity(EntityMap {
            entity_name: "ACME Corp".into(),
            reg_id: Some("https://acme.example.com".into()),
            role: vec![1], // manifest-creator
        })
        .add_comid_tag(comid)
        .unwrap()
        .build_bytes()
        .unwrap();

    use std::io::Write;
    let args: Vec<String> = std::env::args().collect();
    if args.len() > 1 {
        std::fs::write(&args[1], &bytes).unwrap();
        eprintln!("Wrote {} bytes to {}", bytes.len(), args[1]);
    } else {
        std::io::stdout().write_all(&bytes).unwrap();
    }
}
