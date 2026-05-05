// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Tests for `Display` impls and `From` conversions on the
//! type-choice enums and ID types defined in `types/common.rs`
//! and `types/corim.rs`.

use corim::types::common::*;
use corim::types::corim::*;
use corim::types::measurement::*;

// ===========================================================================
// Display impls — types/common.rs
// ===========================================================================

#[test]
fn display_tag_id_choice() {
    let text = TagIdChoice::Text("my-tag".into());
    assert_eq!(format!("{}", text), "my-tag");

    let uuid = TagIdChoice::Uuid([
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
        0x10,
    ]);
    let s = format!("{}", uuid);
    assert!(s.contains("01020304"));
    assert!(s.contains("-"));
}

#[test]
fn display_class_id_choice() {
    let oid = ClassIdChoice::Oid(vec![0x06, 0x03, 0x55, 0x04, 0x03]);
    assert!(format!("{}", oid).starts_with("oid:"));

    let uuid = ClassIdChoice::Uuid([0xAA; 16]);
    assert!(format!("{}", uuid).contains("aaaaaaaa"));

    let bytes = ClassIdChoice::Bytes(vec![1, 2, 3]);
    assert!(format!("{}", bytes).starts_with("bytes:"));
}

#[test]
fn display_instance_id_choice() {
    let ueid = InstanceIdChoice::Ueid(vec![0x02; 10]);
    assert!(format!("{}", ueid).starts_with("ueid:"));

    let uuid = InstanceIdChoice::Uuid([0xBB; 16]);
    assert!(format!("{}", uuid).contains("bbbbbbbb"));

    let bytes_id = InstanceIdChoice::Bytes(vec![0xFF; 4]);
    assert!(format!("{}", bytes_id).starts_with("bytes:"));

    let pkix_key = InstanceIdChoice::PkixBase64Key("MIIBIjANBg...".into());
    assert!(format!("{}", pkix_key).starts_with("pkix-key:"));

    let pkix_cert = InstanceIdChoice::PkixBase64Cert("MIIC...".into());
    assert!(format!("{}", pkix_cert).starts_with("pkix-cert:"));

    let cose_key = InstanceIdChoice::CoseKey(vec![0xA0, 0x01]);
    assert!(format!("{}", cose_key).contains("cose-key:"));

    let kt = InstanceIdChoice::KeyThumbprint(Digest::new(7, vec![0xCC; 32]));
    assert!(format!("{}", kt).starts_with("key-tp:"));

    let ct = InstanceIdChoice::CertThumbprint(Digest::new(7, vec![0xDD; 32]));
    assert!(format!("{}", ct).starts_with("cert-tp:"));

    let asn1 = InstanceIdChoice::PkixAsn1DerCert(vec![0x30; 100]);
    assert!(format!("{}", asn1).starts_with("asn1-cert:"));
}

#[test]
fn display_instance_long_bytes_truncated() {
    let inst = InstanceIdChoice::Bytes(vec![0xFF; 32]);
    let s = format!("{}", inst);
    assert!(s.contains("..") && s.contains("32 bytes"), "got: {s}");
}

#[test]
fn display_group_id_choice() {
    let uuid = GroupIdChoice::Uuid([0xCC; 16]);
    assert!(format!("{}", uuid).contains("cccccccc"));

    let bytes = GroupIdChoice::Bytes(vec![1, 2, 3, 4]);
    assert!(format!("{}", bytes).starts_with("bytes:"));
}

#[test]
fn display_measured_element() {
    let oid = MeasuredElement::Oid(vec![0x06, 0x01]);
    assert!(format!("{}", oid).starts_with("oid:"));

    let uuid = MeasuredElement::Uuid([0xDD; 16]);
    assert!(format!("{}", uuid).contains("dddddddd"));

    let uint = MeasuredElement::Uint(42);
    assert_eq!(format!("{}", uint), "42");

    let text = MeasuredElement::Text("firmware".into());
    assert_eq!(format!("{}", text), "firmware");
}

#[test]
fn display_crypto_key_all_variants() {
    assert!(format!("{}", CryptoKey::PkixBase64Key("key...".into())).starts_with("pkix-key:"));
    assert!(format!("{}", CryptoKey::PkixBase64Cert("cert...".into())).starts_with("pkix-cert:"));
    assert!(
        format!("{}", CryptoKey::PkixBase64CertPath("path...".into()))
            .starts_with("pkix-cert-path:")
    );
    assert!(
        format!("{}", CryptoKey::KeyThumbprint(Digest::new(1, vec![0; 32]))).starts_with("key-tp:")
    );
    assert!(format!("{}", CryptoKey::CoseKey(vec![0xA1])).starts_with("cose-key:"));
    assert!(
        format!("{}", CryptoKey::CertThumbprint(Digest::new(1, vec![0; 32])))
            .starts_with("cert-tp:")
    );
    assert!(format!(
        "{}",
        CryptoKey::CertPathThumbprint(Digest::new(1, vec![0; 32]))
    )
    .starts_with("cert-path-tp:"));
    assert!(format!("{}", CryptoKey::PkixAsn1DerCert(vec![0x30; 50])).starts_with("asn1-cert:"));
    assert!(format!("{}", CryptoKey::Bytes(vec![1, 2, 3])).starts_with("bytes:"));
}

#[test]
fn display_crypto_key_long_thumbprint_truncated() {
    let key = CryptoKey::KeyThumbprint(Digest::new(7, vec![0xCC; 48]));
    let s = format!("{}", key);
    assert!(s.contains(".."), "got: {s}");
}

// ===========================================================================
// Display impls — types/corim.rs
// ===========================================================================

#[test]
fn display_corim_id() {
    let text = CorimId::Text("my-corim".into());
    assert_eq!(format!("{}", text), "my-corim");

    let uuid = CorimId::Uuid([0xAA; 16]);
    assert!(format!("{}", uuid).contains("aaaaaaaa"));
}

#[test]
fn display_profile_choice() {
    let uri = ProfileChoice::Uri("https://example.com".into());
    assert_eq!(format!("{}", uri), "https://example.com");

    let oid = ProfileChoice::Oid(vec![0x06, 0x03]);
    assert!(format!("{}", oid).starts_with("oid:"));
}

#[test]
fn display_cbor_time() {
    let t = CborTime::new(1234567890);
    assert_eq!(format!("{}", t), "2009-02-13T23:31:30Z");
    // Negative epoch falls back to raw format
    let t2 = CborTime::new(-100);
    assert_eq!(format!("{}", t2), "-100(epoch)");
}

// ===========================================================================
// From conversions
// ===========================================================================

#[test]
fn from_conversions_into_id_types() {
    let _: TagIdChoice = "hello".into();
    let _: TagIdChoice = String::from("hello").into();
    let _: TagIdChoice = [0u8; 16].into();

    let _: CorimId = "test".into();
    let _: CorimId = String::from("test").into();
    let _: CorimId = [0u8; 16].into();

    let _: MeasuredElement = "firmware".into();
    let _: MeasuredElement = String::from("firmware").into();
    let _: MeasuredElement = 42u64.into();
}

#[test]
fn cbor_time_i64_conversions() {
    let t: CborTime = 12345i64.into();
    let val: i64 = t.into();
    assert_eq!(val, 12345);
}
