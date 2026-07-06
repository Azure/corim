// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Example: build and validate a SOCMANA CoRIM using Azure profile `tcbstatus`.

#[cfg(feature = "profile-azure")]
const OUTPUT_FILE: &str = "build_corim_ovl3_tdisp_socmana.cbor";

#[cfg(feature = "profile-azure")]
fn make_env() -> corim::types::environment::EnvironmentMap {
    use corim::types::environment::{ClassMap, EnvironmentMap};

    EnvironmentMap {
        class: Some(ClassMap {
            class_id: None,
            vendor: Some("Microsoft".into()),
            model: None,
            layer: None,
            index: None,
        }),
        instance: None,
        group: None,
    }
}

#[cfg(feature = "profile-azure")]
fn make_addition_uptodate() -> corim::types::measurement::MeasurementMap {
    use corim::cbor::value::Value;
    use corim::profile::azure::MVAL_TCBSTATUS;
    use corim::types::measurement::{MeasurementMap, MeasurementValuesMap};

    let mut mval = MeasurementValuesMap::default();
    mval.extra_entries
        .insert(MVAL_TCBSTATUS, Value::Text("UpToDate".into()));

    MeasurementMap {
        mkey: None,
        mval,
        authorized_by: None,
    }
}

#[cfg(feature = "profile-azure")]
fn uint_svn_selection(key: u64, min_svn: u64) -> corim::types::measurement::MeasurementMap {
    use corim::types::common::MeasuredElement;
    use corim::types::measurement::{MeasurementMap, MeasurementValuesMap, SvnChoice};

    MeasurementMap {
        mkey: Some(MeasuredElement::Uint(key)),
        mval: MeasurementValuesMap {
            svn: Some(SvnChoice::MinValue(min_svn)),
            ..MeasurementValuesMap::default()
        },
        authorized_by: None,
    }
}

#[cfg(feature = "profile-azure")]
fn write_cbor_file(bytes: &[u8]) -> std::path::PathBuf {
    let out = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("examples")
        .join(OUTPUT_FILE);
    std::fs::write(&out, bytes).expect("failed to write CoRIM CBOR file");
    out
}

#[cfg(feature = "profile-azure")]
fn main() {
    use corim::builder::{ComidBuilder, CorimBuilder};
    use corim::profile::azure::{AzureProfile, AZURE_PROFILE_URI};
    use corim::profile::MatchContext;
    use corim::types::common::TagIdChoice;
    use corim::types::corim::{CorimId, ProfileChoice};
    use corim::types::measurement::{MeasurementMap, MeasurementValuesMap, SvnChoice};
    use corim::types::triples::{
        CesCondition, ConditionalEndorsementSeriesTriple, ConditionalSeriesRecord,
    };
    use corim::validate::{
        apply_endorsement_series_with_profile, decode_and_validate_at, EvidenceClaim,
    };

    let ces = ConditionalEndorsementSeriesTriple::new(
        CesCondition {
            environment: make_env(),
            claims_list: vec![],
            authorized_by: None,
        },
        vec![ConditionalSeriesRecord::new(
            vec![uint_svn_selection(19, 1)],
            vec![make_addition_uptodate()],
        )],
    );

    let comid = ComidBuilder::new(TagIdChoice::Text(
        "1.3.6.1.4.1.311.102.5_SOCMANA".into(),
    ))
    .add_conditional_endorsement_series(ces)
    .build()
    .expect("failed to build CoMID");

    let bytes = CorimBuilder::new(CorimId::Text(
        "1.3.6.1.4.1.311.102.5_SOCMANA_20260705".into(),
    ))
    .set_profile(ProfileChoice::Uri(AZURE_PROFILE_URI.into()))
    .add_comid_tag(comid)
    .expect("failed to encode CoMID")
    .build_bytes()
    .expect("failed to build CoRIM");

    let (_corim, comids) =
        decode_and_validate_at(&bytes, 1_800_000_000).expect("decode_and_validate_at failed");
    let decoded = &comids[0];

    let profile = AzureProfile::new();
    let evidence = vec![EvidenceClaim {
        environment: decoded.triples.conditional_endorsement_series.as_ref().unwrap()[0]
            .condition()
            .environment
            .clone(),
        measurements: vec![MeasurementMap {
            mkey: Some(corim::types::common::MeasuredElement::Uint(19)),
            mval: MeasurementValuesMap {
                svn: Some(SvnChoice::ExactValue(1)),
                ..MeasurementValuesMap::default()
            },
            authorized_by: None,
        }],
    }];

    let ces_endorsed = apply_endorsement_series_with_profile(
        decoded.triples.conditional_endorsement_series.as_deref().unwrap(),
        &evidence,
        Some(&profile),
        &MatchContext::new(),
    )
    .expect("apply_endorsement_series_with_profile failed");
    let out = write_cbor_file(&bytes);
    println!("CES endorsed claims: {}", ces_endorsed.len());
    println!("Saved CBOR: {}", out.display());

    println!("Encoded CoRIM: {} bytes", bytes.len());
    println!(
        "Hex: {}",
        bytes
            .iter()
            .map(|b| format!("{:02x}", b))
            .collect::<String>()
    );
}

#[cfg(not(feature = "profile-azure"))]
fn main() {
    eprintln!(
        "This example requires the `profile-azure` feature.\n\
         Run with:\n\
         cargo run -p corim --example build_corim_ovl3_tdisp_socmana --features profile-azure"
    );
}