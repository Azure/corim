// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Integration tests for the TCG-style decode-only relaxations.
//!
//! Coverage:
//!
//! 1. Outer `#6.500` / `#6.502` legacy tag peeling (`peel_tcg_wrappers`).
//! 2. Bare `corim-map` payload (no `#6.501` wrap) → synthesized via
//!    `wrap_bare_corim_map`.
//! 3. Bare `bstr` `tags[]` entries (no `#6.506` wrap) → surfaced as
//!    [`corim::types::corim::ConciseTagChoice::BareBstr`] and routed through
//!    `decode_comid_from_tcg_bstr`, which also tolerates NVIDIA's swapped
//!    `bstr → #6.506 → map` nesting.
//!
//! Plus end-to-end tests using the real-world NVIDIA ConnectX-7 fixture
//! ([`fixtures/nvidia_cx7_tcg_wrapped.cbor`]) and a builder-side guard
//! that the encode path never emits `#6.500` / `#6.502`.
//!
//! See [`corim::compat`] and the README "Decode interop relaxations" section
//! for the full provenance and the cocli@v0.0.1-compat reference oracle.
//! Fixture provenance lives in [`fixtures/README.md`](fixtures/README.md).

use corim::compat::{peel_tcg_wrappers, wrap_bare_corim_map};
use corim::diagnose::{inspect, EnvelopeKind, Severity};
use corim::profile::ProfileRegistry;
use corim::types::signed::decode_signed_corim;

/// Real-world fixture: NVIDIA ConnectX-7 NIC firmware CoRIM, observed 2026-04.
/// Wrapped as `#6.500(#6.502(#6.18([...])))` per the TCG Endorsement spec.
const NVIDIA_CX7_BYTES: &[u8] = include_bytes!("fixtures/nvidia_cx7_tcg_wrapped.cbor");

#[test]
fn nvidia_cx7_peels_to_cose_sign1() {
    let peeled = peel_tcg_wrappers(NVIDIA_CX7_BYTES).expect("peel must succeed");
    assert!(peeled.was_peeled(), "NVIDIA fixture has legacy wrappers");
    // Inner must start with `0xD2` (CBOR tag 18, COSE_Sign1).
    assert_eq!(peeled.as_bytes()[0], 0xD2, "inner should be tag 18");
}

#[test]
fn nvidia_cx7_decode_signed_corim_succeeds() {
    // The strict decoder must accept the legacy-wrapped fixture because the
    // wrappers are peeled internally before tag-18 dispatch.
    let parsed = decode_signed_corim(NVIDIA_CX7_BYTES)
        .expect("decode_signed_corim must accept legacy-wrapped input");
    // Check we parsed the protected header sensibly.
    let signer = parsed
        .protected
        .corim_meta
        .as_ref()
        .map(|m| m.signer.signer_name.as_str());
    assert_eq!(signer, Some("NVIDIA"));
}

#[test]
fn nvidia_cx7_diagnose_warns_about_legacy_tag() {
    let report = inspect(NVIDIA_CX7_BYTES, &ProfileRegistry::new());
    assert_eq!(report.envelope(), EnvelopeKind::Signed);
    let warned = report
        .issues()
        .iter()
        .find(|i| i.severity() == Severity::Warning && i.message().contains("legacy"))
        .expect("expected a legacy-tag warning");
    assert!(
        warned.message().contains("500"),
        "warning should mention tag 500, got: {}",
        warned.message()
    );
}

#[test]
fn builder_never_emits_legacy_tags() {
    // Mitigation: encode side must always use draft-10 tags (#6.501 for
    // unsigned, #6.18 for signed). This guards against accidentally
    // emitting #6.500 / #6.502.
    use corim::builder::{ComidBuilder, CorimBuilder};
    use corim::types::common::{MeasuredElement, TagIdChoice};
    use corim::types::corim::CorimId;
    use corim::types::environment::{ClassMap, EnvironmentMap};
    use corim::types::measurement::{Digest, MeasurementMap, MeasurementValuesMap};
    use corim::types::triples::ReferenceTriple;

    let env = EnvironmentMap {
        class: Some(ClassMap {
            class_id: None,
            vendor: Some("TestVendor".into()),
            model: Some("Model".into()),
            layer: None,
            index: None,
        }),
        instance: None,
        group: None,
    };
    let meas = MeasurementMap {
        mkey: Some(MeasuredElement::Text("fw".into())),
        mval: MeasurementValuesMap {
            digests: Some(vec![Digest::new(7, vec![0xAA; 48])]),
            ..MeasurementValuesMap::default()
        },
        authorized_by: None,
    };
    let comid = ComidBuilder::new(TagIdChoice::Text("t".into()))
        .add_reference_triple(ReferenceTriple::new(env, vec![meas]))
        .build()
        .unwrap();
    let bytes = CorimBuilder::new(CorimId::Text("c".into()))
        .add_comid_tag(comid)
        .unwrap()
        .build_bytes()
        .unwrap();
    // First three bytes of #6.501(...) are 0xD9 0x01 0xF5.
    assert_eq!(
        &bytes[..3],
        &[0xD9, 0x01, 0xF5],
        "builder must emit #6.501 (draft-10), not #6.500 / #6.502"
    );
    // Sanity: not 500 (0xD9 0x01 0xF4) and not 502 (0xD9 0x01 0xF6).
    assert_ne!(&bytes[..3], &[0xD9, 0x01, 0xF4]);
    assert_ne!(&bytes[..3], &[0xD9, 0x01, 0xF6]);
}

#[test]
fn nvidia_cx7_payload_is_bare_corim_map() {
    // The COSE_Sign1 payload bstr in the NVIDIA fixture starts with a
    // CBOR map header (0xA*/0xB*), not the #6.501 tag header (0xD9 0x01 0xF5).
    // This is the second TCG-style divergence we accept on decode.
    let peeled = peel_tcg_wrappers(NVIDIA_CX7_BYTES).unwrap();
    let signed = decode_signed_corim(peeled.as_bytes()).unwrap();
    let payload = signed.payload.as_ref().expect("attached payload");
    let first = payload[0];
    assert!(
        (0xA0..=0xBB).contains(&first),
        "expected definite-length CBOR map header, got 0x{:02X}",
        first
    );
    // wrap_bare_corim_map must recognize this as needing the synthetic
    // #6.501 prefix.
    let wrapped = wrap_bare_corim_map(payload);
    assert!(
        wrapped.was_wrapped(),
        "wrap_bare_corim_map should prefix #6.501 onto a bare corim-map"
    );
}

#[test]
fn nvidia_cx7_end_to_end_decode_yields_expected_comid() {
    // End-to-end: validate_signed_corim_payload must succeed on the NVIDIA
    // fixture after all three TCG-style relaxations are in place:
    //   1. Outer #6.500/#6.502 tags are peeled (`peel_tcg_wrappers`).
    //   2. Bare `corim-map` payload (no #6.501) is wrapped (`wrap_bare_corim_map`).
    //   3. Bare-bstr `tags[]` entries are surfaced as `ConciseTagChoice::BareBstr`,
    //      and `validate.rs` routes them through `decode_comid_from_tcg_bstr`,
    //      which tolerates the swapped `bstr → #6.506 → map` nesting.
    //
    // Then assert the inner CoMID has the expected tag-id, vendor, and
    // measurement layout — this is the single regression guard that the
    // relaxations together produce a usable, fully-typed CoMID.
    let peeled = peel_tcg_wrappers(NVIDIA_CX7_BYTES).unwrap();
    let signed = decode_signed_corim(peeled.as_bytes()).unwrap();
    let now = 1_777_000_000_i64;
    let validated = corim::types::signed::validate_signed_corim_payload(&signed, now)
        .expect("validation should accept the NVIDIA fixture after relaxations");

    // Inner CoMID assertions: tag-id, vendor, and the 7-measurement layout.
    assert_eq!(validated.comids.len(), 1, "expected exactly one CoMID");
    let comid = &validated.comids[0];
    match &comid.tag_identity.tag_id {
        corim::types::common::TagIdChoice::Text(s) => {
            assert_eq!(s, "15b3102115b3002300-28.48.1000")
        }
        other => panic!("expected text tag-id, got {:?}", other),
    }
    let class = comid.triples.reference_triples.as_ref().unwrap()[0]
        .0
        .class
        .as_ref()
        .unwrap();
    assert_eq!(class.vendor.as_deref(), Some("NVIDIA"));

    // Measurements: NVIDIA CX-7 emits 7 measurements with uint mkeys 2..=8.
    let measurements = &comid.triples.reference_triples.as_ref().unwrap()[0].1;
    assert_eq!(
        measurements.len(),
        7,
        "expected 7 measurements (mkey 2..=8), got {}",
        measurements.len()
    );
    for (i, m) in measurements.iter().enumerate() {
        let expected_key = (i as u64) + 2;
        match m.mkey.as_ref().expect("mkey must be present") {
            corim::types::common::MeasuredElement::Uint(n) => assert_eq!(
                *n, expected_key,
                "measurement[{}].mkey expected uint {}, got uint {}",
                i, expected_key, n
            ),
            other => panic!("measurement[{}].mkey expected uint, got {:?}", i, other),
        }
    }
}

#[test]
fn as_comid_handles_both_tagged_and_bare_bstr() {
    // Both shapes from the NVIDIA fixture: when validation extracts the
    // CoMID it goes through the BareBstr path. We assert that the same
    // bytes, retrieved via the unsigned CorimMap inside the COSE payload,
    // can be unwrapped via `ConciseTagChoice::as_comid()` regardless of
    // which on-the-wire shape they carry.
    use corim::types::corim::{ConciseTagChoice, CorimMap};

    let peeled = peel_tcg_wrappers(NVIDIA_CX7_BYTES).unwrap();
    let signed = decode_signed_corim(peeled.as_bytes()).unwrap();
    let payload = signed.payload.as_ref().expect("attached payload");
    // Wrap-or-pass the bare corim-map.
    let wrapped = wrap_bare_corim_map(payload);
    // Strip the #6.501 tag to get to the CorimMap.
    use corim::cbor;
    let tagged: corim::cbor::value::Tagged<CorimMap> = cbor::decode(wrapped.as_bytes()).unwrap();
    let corim_map = tagged.value;

    // NVIDIA fixture: tags[] entries are BareBstr.
    let tag = &corim_map.tags[0];
    assert!(matches!(tag, ConciseTagChoice::BareBstr(_)));
    let comid = tag.as_comid().expect("as_comid must accept BareBstr");
    match &comid.tag_identity.tag_id {
        corim::types::common::TagIdChoice::Text(s) => {
            assert_eq!(s, "15b3102115b3002300-28.48.1000")
        }
        other => panic!("unexpected tag-id: {:?}", other),
    }

    // Synthetic spec-compliant case: a Comid(bstr .cbor concise-mid-tag).
    // Re-encode the parsed ComidTag and stuff into ConciseTagChoice::Comid.
    let inner_bytes = cbor::encode(&comid).unwrap();
    let spec_tag = ConciseTagChoice::Comid(inner_bytes);
    let comid2 = spec_tag
        .as_comid()
        .expect("as_comid must accept Comid variant");
    assert_eq!(comid.tag_identity.tag_id, comid2.tag_identity.tag_id);

    // Negative: CoSWID variant should error.
    let coswid_tag = ConciseTagChoice::Coswid(vec![0xA0]);
    assert!(coswid_tag.as_comid().is_err());
}
