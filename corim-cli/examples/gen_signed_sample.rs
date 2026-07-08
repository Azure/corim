// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Example: build a sample signed CoRIM (COSE_Sign1) with the builder
//! API and a placeholder signature.
//!
//! Writes the CBOR to stdout. Run with:
//! `cargo run -p corim-cli --example gen_signed_sample > signed.corim`.

use corim::builder::{ComidBuilder, CorimBuilder};
use corim::types::common::{MeasuredElement, TagIdChoice};
use corim::types::corim::{CorimId, CorimMetaMap, CorimSignerMap};
use corim::types::environment::{ClassMap, EnvironmentMap};
use corim::types::measurement::{Digest, MeasurementMap, MeasurementValuesMap};
use corim::types::signed::{CwtClaims, SignedCorimBuilder};
use corim::types::triples::ReferenceTriple;

fn main() {
    // Build the inner unsigned CoRIM
    let env = EnvironmentMap {
        class: Some(ClassMap {
            class_id: None,
            vendor: Some("ACME Corp".into()),
            model: Some("Widget v2".into()),
            layer: None,
            index: None,
        }),
        instance: None,
        group: None,
    };

    let meas = MeasurementMap {
        mkey: Some(MeasuredElement::Text("firmware".into())),
        mval: MeasurementValuesMap {
            digests: Some(vec![Digest::new(7, vec![0xAA; 48])]),
            ..MeasurementValuesMap::default()
        },
        authorized_by: None,
    };

    let comid = ComidBuilder::new(TagIdChoice::Text("sample-signed-comid".into()))
        .add_reference_triple(ReferenceTriple::new(env, vec![meas]))
        .build()
        .unwrap();

    let corim_bytes = CorimBuilder::new(CorimId::Text("sample-signed-corim".into()))
        .add_comid_tag(comid)
        .unwrap()
        .build_bytes()
        .unwrap();

    // Build the signed CoRIM
    let mut builder = SignedCorimBuilder::new(-7, corim_bytes)
        .set_corim_meta(CorimMetaMap {
            signer: CorimSignerMap {
                signer_name: "ACME Corp".into(),
                signer_uri: Some("https://acme.example.com".into()),
            },
            signature_validity: None,
        })
        .set_cwt_claims(
            CwtClaims::new("ACME Corp")
                .with_sub("sample-signed-corim")
                .with_nbf(1700000000)
                .with_exp(2000000000),
        );

    // Get TBS and "sign" with a fake signature
    let _tbs = builder.to_be_signed(&[]).unwrap();
    let fake_signature = vec![0xAB; 64]; // 64-byte fake ES256 signature

    let signed_bytes = builder.build_with_signature(fake_signature).unwrap();

    // Write to stdout
    use std::io::Write;
    std::io::stdout().write_all(&signed_bytes).unwrap();
}
