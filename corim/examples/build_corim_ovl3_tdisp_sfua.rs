// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Example: build and validate a CoRIM using Azure profile `tcbstatus`.

#[cfg(feature = "profile-azure")]
const SPDM_CERTIFICATES: &[u8] = b"SPDM Certificates";

#[cfg(feature = "profile-azure")]
const SPDM_MEASUREMENTS: &[u8] = b"SPDM Measurements";

#[cfg(feature = "profile-azure")]
const OUTPUT_FILE: &str = "build_corim_ovl3_tdisp_sfua.cbor";

#[cfg(not(feature = "profile-azure"))]
fn main() {
    eprintln!(
        "This example requires the `profile-azure` feature.\n\
         Run with:\n\
         cargo run -p corim --example build_corim_ovl3_tdisp_sfua --features profile-azure"
    );
}

#[cfg(feature = "profile-azure")]
fn make_env(
    layer: Option<u64>,
    instance: Option<&[u8]>,
) -> corim::types::environment::EnvironmentMap {
    use corim::types::common::InstanceIdChoice;
    use corim::types::environment::{ClassMap, EnvironmentMap};

    EnvironmentMap {
        class: Some(ClassMap {
            class_id: None,
            vendor: Some("Microsoft".into()),
            model: None,
            layer,
            index: None,
        }),
        instance: instance.map(|bytes| InstanceIdChoice::Bytes(bytes.to_vec())),
        group: None,
    }
}

#[cfg(feature = "profile-azure")]
fn make_selection_svn(min_svn: u64) -> corim::types::measurement::MeasurementMap {
    use corim::types::measurement::{MeasurementMap, MeasurementValuesMap, SvnChoice};

    MeasurementMap {
        mkey: None,
        mval: MeasurementValuesMap {
            svn: Some(SvnChoice::MinValue(min_svn)),
            ..MeasurementValuesMap::default()
        },
        authorized_by: None,
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
fn make_ces(
    env: corim::types::environment::EnvironmentMap,
    selection: Vec<corim::types::measurement::MeasurementMap>,
    addition: corim::types::measurement::MeasurementMap,
) -> corim::types::triples::ConditionalEndorsementSeriesTriple {
    use corim::types::triples::{
        CesCondition, ConditionalEndorsementSeriesTriple, ConditionalSeriesRecord,
    };

    ConditionalEndorsementSeriesTriple::new(
        CesCondition {
            environment: env,
            claims_list: vec![],
            authorized_by: None,
        },
        vec![ConditionalSeriesRecord::new(selection, vec![addition])],
    )
}

#[cfg(feature = "profile-azure")]
fn sha384_digest(bytes: Vec<u8>) -> corim::types::measurement::Digest {
    use corim::types::measurement::{Digest, DigestAlg};
    Digest(DigestAlg::Int(7), bytes)
}

#[cfg(feature = "profile-azure")]
fn sha256_digest(bytes: Vec<u8>) -> corim::types::measurement::Digest {
    use corim::types::measurement::{Digest, DigestAlg};
    Digest(DigestAlg::Int(1), bytes)
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
fn uint_digest_selection(
    key: u64,
    digest: corim::types::measurement::Digest,
) -> corim::types::measurement::MeasurementMap {
    use corim::types::common::MeasuredElement;
    use corim::types::measurement::{MeasurementMap, MeasurementValuesMap};

    MeasurementMap {
        mkey: Some(MeasuredElement::Uint(key)),
        mval: MeasurementValuesMap {
            digests: Some(vec![digest]),
            ..MeasurementValuesMap::default()
        },
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
fn uint_raw_value_selection(key: u64, raw: Vec<u8>) -> corim::types::measurement::MeasurementMap {
    use corim::types::common::MeasuredElement;
    use corim::types::measurement::{MeasurementMap, MeasurementValuesMap, RawValueChoice};

    MeasurementMap {
        mkey: Some(MeasuredElement::Uint(key)),
        mval: MeasurementValuesMap {
            raw_value: Some(RawValueChoice::Bytes(raw)),
            ..MeasurementValuesMap::default()
        },
        authorized_by: None,
    }
}

#[cfg(feature = "profile-azure")]
fn main() {
    use corim::builder::{ComidBuilder, CorimBuilder};
    use corim::profile::azure::{AzureProfile, AZURE_PROFILE_URI};
    use corim::profile::MatchContext;
    use corim::types::common::{CryptoKey, TagIdChoice};
    use corim::types::corim::{CorimId, ProfileChoice};
    use corim::types::measurement::{MeasurementMap, MeasurementValuesMap, SvnChoice};
    use corim::types::triples::IdentityTriple;
    use corim::validate::{
        apply_endorsement_series_with_profile, decode_and_validate_at, EvidenceClaim,
    };

    let selection = make_selection_svn(0);
    let addition = make_addition_uptodate();

    let ces = make_ces(
        make_env(Some(0), Some(SPDM_CERTIFICATES)),
        vec![selection.clone()],
        addition.clone(),
    );

    let ces2 = make_ces(
        make_env(Some(1), Some(SPDM_CERTIFICATES)),
        vec![selection],
        addition.clone(),
    );

    let digest_384 = sha384_digest(vec![
        0x4b, 0x56, 0xcf, 0xa0, 0x7f, 0xae, 0xb2, 0xab, 0x57, 0xde, 0x92, 0x1e, 0x4a, 0x97, 0xd6,
        0x55, 0x14, 0x4b, 0x54, 0x64, 0x70, 0xeb, 0xaa, 0xab, 0x6f, 0x71, 0xc0, 0xdb, 0x51, 0x8d,
        0xdf, 0x5b, 0x4a, 0x5f, 0xb2, 0x8f, 0xb2, 0xad, 0x1b, 0x49, 0x34, 0x26, 0x44, 0x24, 0xeb,
        0x1e, 0x5a, 0x86,
    ]);

    let ces3_selection = vec![
        uint_digest_selection(1, digest_384.clone()),
        uint_digest_selection(8, digest_384),
        uint_svn_selection(15, 1),
        uint_svn_selection(16, 1),
        uint_svn_selection(17, 1),
        uint_svn_selection(18, 1),
        uint_raw_value_selection(
            254,
            vec![
                0x72, 0x61, 0x77, 0x76, 0x61, 0x6c, 0x75, 0x65, 0x0a, 0x72, 0x61, 0x77, 0x76, 0x61,
                0x6c, 0x75, 0x65, 0x0a,
            ],
        ),
    ];

    let ces3 = make_ces(
        make_env(None, Some(SPDM_MEASUREMENTS)),
        ces3_selection,
        addition.clone(),
    );

    let thumbprint_bytes: [u8; 32] = [
        0x44, 0xaa, 0x33, 0x6a, 0xf4, 0xcb, 0x14, 0xa8, 0x79, 0x43, 0x2e, 0x53, 0xdd, 0x65, 0x71,
        0xc7, 0xfa, 0x9b, 0xcc, 0xaf, 0xb7, 0x5f, 0x48, 0x82, 0x59, 0x26, 0x2d, 0x6e, 0xa3, 0xa4,
        0xd9, 0x1b,
    ];
    let thumbprint = sha256_digest(thumbprint_bytes.to_vec());
    let id_keys = vec![
        CryptoKey::CertThumbprint(thumbprint.clone()),
        CryptoKey::CertThumbprint(thumbprint),
    ];

    let comid = ComidBuilder::new(TagIdChoice::Text("1.3.6.1.4.1.311.102.5_SFUA".into()))
        .set_tag_version(1)
        .add_identity_triple(IdentityTriple::new(make_env(None, None), id_keys, None))
        .add_conditional_endorsement_series(ces)
        .add_conditional_endorsement_series(ces2)
        .add_conditional_endorsement_series(ces3)
        .build()
        .expect("failed to build CoMID");

    let bytes = CorimBuilder::new(CorimId::Text("1.3.6.1.4.1.311.102.5_SFUA_20260705".into()))
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
        environment: decoded
            .triples
            .conditional_endorsement_series
            .as_ref()
            .unwrap()[0]
            .condition()
            .environment
            .clone(),
        measurements: vec![MeasurementMap {
            mkey: None,
            mval: MeasurementValuesMap {
                svn: Some(SvnChoice::ExactValue(0)),
                ..MeasurementValuesMap::default()
            },
            authorized_by: None,
        }],
    }];

    let ces_endorsed = apply_endorsement_series_with_profile(
        decoded
            .triples
            .conditional_endorsement_series
            .as_deref()
            .unwrap(),
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
