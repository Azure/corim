// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Example: build a CoRIM with reference values and encode to CBOR.

use corim::builder::{ComidBuilder, CorimBuilder};
use corim::types::common::{EntityMap, MeasuredElement, TagIdChoice};
use corim::types::corim::{CorimId, ProfileChoice};
use corim::types::environment::{ClassMap, EnvironmentMap};
use corim::types::measurement::{Digest, MeasurementMap, MeasurementValuesMap};
use corim::types::tags::COMID_ROLE_TAG_CREATOR;
use corim::types::triples::ReferenceTriple;

fn main() {
    // Define the target environment
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

    // Create a measurement with a SHA-384 digest
    let measurement = MeasurementMap {
        mkey: Some(MeasuredElement::Text("firmware".into())),
        mval: MeasurementValuesMap {
            digests: Some(vec![Digest::new(7, vec![0xAA; 48])]),
            ..MeasurementValuesMap::default()
        },
        authorized_by: None,
    };

    // Build a CoMID
    let comid = ComidBuilder::new(TagIdChoice::Text(
        "example.com/acme/turbo-encabulator".into(),
    ))
    .set_tag_version(0)
    .add_entity(EntityMap {
        entity_name: "ACME Corp".into(),
        reg_id: Some("https://acme.example.com".into()),
        role: vec![COMID_ROLE_TAG_CREATOR],
    })
    .add_reference_triple(ReferenceTriple::new(env, vec![measurement]))
    .build()
    .expect("failed to build CoMID");

    // Wrap in a CoRIM and encode
    let bytes = CorimBuilder::new(CorimId::Text("acme/corim/v1".into()))
        .set_profile(ProfileChoice::Uri(
            "https://example.com/acme-profile".into(),
        ))
        .set_validity(Some(1700000000), 1900000000)
        .unwrap()
        .add_comid_tag(comid)
        .expect("failed to encode CoMID")
        .build_bytes()
        .expect("failed to build CoRIM");

    println!("Encoded CoRIM: {} bytes", bytes.len());
    println!(
        "Hex: {}",
        bytes
            .iter()
            .map(|b| format!("{:02x}", b))
            .collect::<String>()
    );
}
