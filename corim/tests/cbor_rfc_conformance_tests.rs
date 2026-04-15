// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! CBOR RFC 8949 conformance tests for the in-house minimal encoder/decoder.
//!
//! Tests are organized by RFC section. Test vectors come from RFC 8949
//! Appendix A and the CBOR diagnostic notation examples in the spec.

use corim::cbor::minimal::{decode_value, encode_value};
use corim::cbor::value::Value;

// ═══════════════════════════════════════════════════════════════════════════
// Helpers
// ═══════════════════════════════════════════════════════════════════════════

fn enc(val: &Value) -> Vec<u8> {
    let mut buf = Vec::new();
    encode_value(&mut buf, val).unwrap();
    buf
}

fn dec(bytes: &[u8]) -> Value {
    decode_value(&mut &bytes[..]).unwrap()
}

fn rt(val: &Value) -> Value {
    dec(&enc(val))
}

// ═══════════════════════════════════════════════════════════════════════════
// RFC 8949 Appendix A — Diagnostic notation examples
// ═══════════════════════════════════════════════════════════════════════════

// §A: unsigned integers
#[test]
fn rfc_a_0() {
    assert_eq!(enc(&Value::Integer(0)), vec![0x00]);
}
#[test]
fn rfc_a_1() {
    assert_eq!(enc(&Value::Integer(1)), vec![0x01]);
}
#[test]
fn rfc_a_10() {
    assert_eq!(enc(&Value::Integer(10)), vec![0x0a]);
}
#[test]
fn rfc_a_23() {
    assert_eq!(enc(&Value::Integer(23)), vec![0x17]);
}
#[test]
fn rfc_a_24() {
    assert_eq!(enc(&Value::Integer(24)), vec![0x18, 0x18]);
}
#[test]
fn rfc_a_25() {
    assert_eq!(enc(&Value::Integer(25)), vec![0x18, 0x19]);
}
#[test]
fn rfc_a_100() {
    assert_eq!(enc(&Value::Integer(100)), vec![0x18, 0x64]);
}
#[test]
fn rfc_a_1000() {
    assert_eq!(enc(&Value::Integer(1000)), vec![0x19, 0x03, 0xe8]);
}
#[test]
fn rfc_a_1000000() {
    assert_eq!(
        enc(&Value::Integer(1000000)),
        vec![0x1a, 0x00, 0x0f, 0x42, 0x40]
    );
}
#[test]
fn rfc_a_1000000000000() {
    assert_eq!(
        enc(&Value::Integer(1000000000000)),
        vec![0x1b, 0x00, 0x00, 0x00, 0xe8, 0xd4, 0xa5, 0x10, 0x00]
    );
}

// §A: negative integers
#[test]
fn rfc_a_neg1() {
    assert_eq!(enc(&Value::Integer(-1)), vec![0x20]);
}
#[test]
fn rfc_a_neg10() {
    assert_eq!(enc(&Value::Integer(-10)), vec![0x29]);
}
#[test]
fn rfc_a_neg100() {
    assert_eq!(enc(&Value::Integer(-100)), vec![0x38, 0x63]);
}
#[test]
fn rfc_a_neg1000() {
    assert_eq!(enc(&Value::Integer(-1000)), vec![0x39, 0x03, 0xe7]);
}

// §A: byte strings
#[test]
fn rfc_a_empty_bytes() {
    assert_eq!(enc(&Value::Bytes(vec![])), vec![0x40]);
}
#[test]
fn rfc_a_bytes_01020304() {
    assert_eq!(
        enc(&Value::Bytes(vec![0x01, 0x02, 0x03, 0x04])),
        vec![0x44, 0x01, 0x02, 0x03, 0x04]
    );
}

// §A: text strings
#[test]
fn rfc_a_empty_text() {
    assert_eq!(enc(&Value::Text("".into())), vec![0x60]);
}
#[test]
fn rfc_a_text_a() {
    assert_eq!(enc(&Value::Text("a".into())), vec![0x61, 0x61]);
}
#[test]
fn rfc_a_text_ietf() {
    assert_eq!(
        enc(&Value::Text("IETF".into())),
        vec![0x64, 0x49, 0x45, 0x54, 0x46]
    );
}
#[test]
fn rfc_a_text_quote_backslash() {
    assert_eq!(enc(&Value::Text("\"\\".into())), vec![0x62, 0x22, 0x5c]);
}
#[test]
fn rfc_a_text_unicode_u00fc() {
    assert_eq!(enc(&Value::Text("\u{00fc}".into())), vec![0x62, 0xc3, 0xbc]);
}
#[test]
fn rfc_a_text_unicode_u6c34() {
    assert_eq!(
        enc(&Value::Text("\u{6c34}".into())),
        vec![0x63, 0xe6, 0xb0, 0xb4]
    );
}

// §A: arrays
#[test]
fn rfc_a_empty_array() {
    assert_eq!(enc(&Value::Array(vec![])), vec![0x80]);
}
#[test]
fn rfc_a_array_123() {
    let v = Value::Array(vec![
        Value::Integer(1),
        Value::Integer(2),
        Value::Integer(3),
    ]);
    assert_eq!(enc(&v), vec![0x83, 0x01, 0x02, 0x03]);
}
#[test]
fn rfc_a_nested_array() {
    // [1, [2, 3], [4, 5]]
    let v = Value::Array(vec![
        Value::Integer(1),
        Value::Array(vec![Value::Integer(2), Value::Integer(3)]),
        Value::Array(vec![Value::Integer(4), Value::Integer(5)]),
    ]);
    assert_eq!(
        enc(&v),
        vec![0x83, 0x01, 0x82, 0x02, 0x03, 0x82, 0x04, 0x05]
    );
}
#[test]
fn rfc_a_25_element_array() {
    // [1, 2, ... 25]
    let v = Value::Array((1..=25).map(Value::Integer).collect());
    let bytes = enc(&v);
    assert_eq!(bytes[0], 0x98); // array with 1-byte length
    assert_eq!(bytes[1], 25);
    // 23 elements fit in 1 byte each (1..=23), 2 elements need 2 bytes (24,25)
    assert_eq!(bytes.len(), 2 + 23 + 2 * 2);
}

// §A: maps
#[test]
fn rfc_a_empty_map() {
    assert_eq!(enc(&Value::Map(vec![])), vec![0xa0]);
}
#[test]
fn rfc_a_map_12_34() {
    // {1: 2, 3: 4}
    let v = Value::Map(vec![
        (Value::Integer(1), Value::Integer(2)),
        (Value::Integer(3), Value::Integer(4)),
    ]);
    assert_eq!(enc(&v), vec![0xa2, 0x01, 0x02, 0x03, 0x04]);
}
#[test]
fn rfc_a_map_text_keys() {
    // {"a": 1, "b": [2, 3]}
    let v = Value::Map(vec![
        (Value::Text("a".into()), Value::Integer(1)),
        (
            Value::Text("b".into()),
            Value::Array(vec![Value::Integer(2), Value::Integer(3)]),
        ),
    ]);
    assert_eq!(
        enc(&v),
        vec![0xa2, 0x61, 0x61, 0x01, 0x61, 0x62, 0x82, 0x02, 0x03]
    );
}

// §A: simple values
#[test]
fn rfc_a_false() {
    assert_eq!(enc(&Value::Bool(false)), vec![0xf4]);
}
#[test]
fn rfc_a_true() {
    assert_eq!(enc(&Value::Bool(true)), vec![0xf5]);
}
#[test]
fn rfc_a_null() {
    assert_eq!(enc(&Value::Null), vec![0xf6]);
}

// §A: tags
#[test]
fn rfc_a_tag_0_text() {
    // 0("2013-03-21T20:04:00Z") — tag 0 wrapping text
    let v = Value::Tag(0, Box::new(Value::Text("2013-03-21T20:04:00Z".into())));
    let bytes = enc(&v);
    assert_eq!(bytes[0], 0xc0); // tag 0
    assert_eq!(bytes[1], 0x74); // text(20)
}
#[test]
fn rfc_a_tag_1_int() {
    // 1(1363896240) — epoch time
    let v = Value::Tag(1, Box::new(Value::Integer(1363896240)));
    let bytes = enc(&v);
    assert_eq!(bytes[0], 0xc1); // tag 1
    assert_eq!(bytes[1], 0x1a); // uint32
}

// ═══════════════════════════════════════════════════════════════════════════
// §4.2.1 — Deterministic encoding (Core Deterministic Encoding Requirements)
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn deterministic_preferred_integer_encoding() {
    // "Integers MUST be encoded as per Section 3.4.5.2."
    // → preferred serialization = shortest form
    assert_eq!(enc(&Value::Integer(0)).len(), 1);
    assert_eq!(enc(&Value::Integer(23)).len(), 1);
    assert_eq!(enc(&Value::Integer(24)).len(), 2);
    assert_eq!(enc(&Value::Integer(255)).len(), 2);
    assert_eq!(enc(&Value::Integer(256)).len(), 3);
    assert_eq!(enc(&Value::Integer(65535)).len(), 3);
    assert_eq!(enc(&Value::Integer(65536)).len(), 5);
    assert_eq!(enc(&Value::Integer(4294967295)).len(), 5);
    assert_eq!(enc(&Value::Integer(4294967296)).len(), 9);
}

#[test]
fn deterministic_negative_shortest() {
    assert_eq!(enc(&Value::Integer(-1)).len(), 1);
    assert_eq!(enc(&Value::Integer(-24)).len(), 1);
    assert_eq!(enc(&Value::Integer(-25)).len(), 2);
    assert_eq!(enc(&Value::Integer(-256)).len(), 2);
    assert_eq!(enc(&Value::Integer(-257)).len(), 3);
}

#[test]
fn deterministic_length_encoding() {
    // String/bytes/array/map length MUST use shortest form
    let bytes_23 = Value::Bytes(vec![0u8; 23]);
    assert_eq!(enc(&bytes_23)[0], 0x57); // major 2, inline 23

    let bytes_24 = Value::Bytes(vec![0u8; 24]);
    assert_eq!(enc(&bytes_24)[0], 0x58); // major 2, 1-byte length
    assert_eq!(enc(&bytes_24)[1], 24);

    let bytes_255 = Value::Bytes(vec![0u8; 255]);
    assert_eq!(enc(&bytes_255)[0], 0x58);
    assert_eq!(enc(&bytes_255)[1], 255);

    let bytes_256 = Value::Bytes(vec![0u8; 256]);
    assert_eq!(enc(&bytes_256)[0], 0x59); // major 2, 2-byte length
}

#[test]
fn deterministic_map_key_order_preserved() {
    // Our encoder preserves insertion order. The derive macro emits keys
    // in ascending order. Verify the bytes match the insertion order.
    let map = Value::Map(vec![
        (Value::Integer(0), Value::Text("a".into())),
        (Value::Integer(1), Value::Text("b".into())),
        (Value::Integer(2), Value::Text("c".into())),
    ]);
    let bytes = enc(&map);
    // Keys should appear as 0, 1, 2
    assert_eq!(
        bytes,
        vec![
            0xa3, // map(3)
            0x00, 0x61, 0x61, // 0 => "a"
            0x01, 0x61, 0x62, // 1 => "b"
            0x02, 0x61, 0x63, // 2 => "c"
        ]
    );
}

// ═══════════════════════════════════════════════════════════════════════════
// §3.1 — Major type decoding
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn decode_unsigned_inline() {
    assert_eq!(dec(&[0x00]), Value::Integer(0));
}
#[test]
fn decode_unsigned_1byte() {
    assert_eq!(dec(&[0x18, 0x64]), Value::Integer(100));
}
#[test]
fn decode_unsigned_2byte() {
    assert_eq!(dec(&[0x19, 0x03, 0xe8]), Value::Integer(1000));
}
#[test]
fn decode_unsigned_4byte() {
    assert_eq!(
        dec(&[0x1a, 0x00, 0x0f, 0x42, 0x40]),
        Value::Integer(1000000)
    );
}
#[test]
fn decode_unsigned_8byte() {
    assert_eq!(
        dec(&[0x1b, 0x00, 0x00, 0x00, 0xe8, 0xd4, 0xa5, 0x10, 0x00]),
        Value::Integer(1000000000000)
    );
}
#[test]
fn decode_negative_inline() {
    assert_eq!(dec(&[0x20]), Value::Integer(-1));
}
#[test]
fn decode_negative_1byte() {
    assert_eq!(dec(&[0x38, 0x63]), Value::Integer(-100));
}
#[test]
fn decode_negative_2byte() {
    assert_eq!(dec(&[0x39, 0x03, 0xe7]), Value::Integer(-1000));
}

// ═══════════════════════════════════════════════════════════════════════════
// §3.3 — Simple values and floats
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn decode_false() {
    assert_eq!(dec(&[0xf4]), Value::Bool(false));
}
#[test]
fn decode_true() {
    assert_eq!(dec(&[0xf5]), Value::Bool(true));
}
#[test]
fn decode_null() {
    assert_eq!(dec(&[0xf6]), Value::Null);
}

#[test]
fn decode_float16_zero() {
    assert_eq!(dec(&[0xf9, 0x00, 0x00]), Value::Float(0.0));
}
#[test]
fn decode_float16_one() {
    let v = dec(&[0xf9, 0x3c, 0x00]);
    if let Value::Float(f) = v {
        assert!((f - 1.0).abs() < 1e-10);
    } else {
        panic!();
    }
}
#[test]
fn decode_float16_inf() {
    assert_eq!(dec(&[0xf9, 0x7c, 0x00]), Value::Float(f64::INFINITY));
}
#[test]
fn decode_float16_neg_inf() {
    assert_eq!(dec(&[0xf9, 0xfc, 0x00]), Value::Float(f64::NEG_INFINITY));
}
#[test]
fn decode_float16_nan() {
    if let Value::Float(f) = dec(&[0xf9, 0x7e, 0x00]) {
        assert!(f.is_nan());
    } else {
        panic!();
    }
}

#[test]
fn decode_float32() {
    let v = dec(&[0xfa, 0x47, 0xc3, 0x50, 0x00]); // 100000.0f
    if let Value::Float(f) = v {
        assert!((f - 100000.0).abs() < 0.1);
    } else {
        panic!();
    }
}

#[test]
fn decode_float64() {
    // 1.1 as float64: 0xFB 3F F1 99 99 99 99 99 9A
    let v = dec(&[0xfb, 0x3f, 0xf1, 0x99, 0x99, 0x99, 0x99, 0x99, 0x9a]);
    if let Value::Float(f) = v {
        assert!((f - 1.1).abs() < 1e-15);
    } else {
        panic!();
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// §3.4.3 — Semantic tags
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn tag_round_trip_small() {
    let v = Value::Tag(1, Box::new(Value::Integer(1363896240)));
    assert_eq!(rt(&v), v);
}
#[test]
fn tag_round_trip_large_tag_number() {
    let v = Value::Tag(55799, Box::new(Value::Null)); // self-described CBOR
    assert_eq!(rt(&v), v);
}
#[test]
fn tag_nested() {
    let v = Value::Tag(
        1,
        Box::new(Value::Tag(37, Box::new(Value::Bytes(vec![0xAA; 16])))),
    );
    assert_eq!(rt(&v), v);
}
#[test]
fn tag_501_corim() {
    // Tag 501 wrapping a map — the CoRIM pattern
    let v = Value::Tag(
        501,
        Box::new(Value::Map(vec![
            (Value::Integer(0), Value::Text("id".into())),
            (Value::Integer(1), Value::Array(vec![])),
        ])),
    );
    assert_eq!(rt(&v), v);
}

// ═══════════════════════════════════════════════════════════════════════════
// §3.2.2 — Byte and text strings
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn bytes_empty_round_trip() {
    assert_eq!(rt(&Value::Bytes(vec![])), Value::Bytes(vec![]));
}
#[test]
fn bytes_large_round_trip() {
    let big = vec![0xAB; 1000];
    assert_eq!(rt(&Value::Bytes(big.clone())), Value::Bytes(big));
}
#[test]
fn text_empty_round_trip() {
    assert_eq!(rt(&Value::Text("".into())), Value::Text("".into()));
}
#[test]
fn text_utf8_round_trip() {
    let s = "こんにちは世界 🌍";
    assert_eq!(rt(&Value::Text(s.into())), Value::Text(s.into()));
}

// ═══════════════════════════════════════════════════════════════════════════
// Error paths — invalid CBOR
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn error_empty_input() {
    assert!(decode_value(&mut &[][..]).is_err());
}
#[test]
fn error_truncated_uint() {
    assert!(decode_value(&mut &[0x18][..]).is_err());
} // expects 1 byte arg
#[test]
fn error_truncated_bytes() {
    assert!(decode_value(&mut &[0x43, 0x01][..]).is_err());
} // claims 3 bytes, only 1
#[test]
fn error_truncated_text() {
    assert!(decode_value(&mut &[0x64, 0x41][..]).is_err());
} // claims 4 bytes, only 1
#[test]
fn error_truncated_float64() {
    assert!(decode_value(&mut &[0xfb, 0x00, 0x00][..]).is_err());
}
#[test]
fn error_truncated_tag() {
    assert!(decode_value(&mut &[0xd9, 0x01][..]).is_err());
} // tag with 2-byte arg, only 1

// §3.2.3 — indefinite-length rejection
#[test]
fn error_indefinite_bytes() {
    assert!(decode_value(&mut &[0x5f][..]).is_err());
}
#[test]
fn error_indefinite_text() {
    assert!(decode_value(&mut &[0x7f][..]).is_err());
}
#[test]
fn error_indefinite_array() {
    assert!(decode_value(&mut &[0x9f][..]).is_err());
}
#[test]
fn error_indefinite_map() {
    assert!(decode_value(&mut &[0xbf][..]).is_err());
}

// §3.3 — unsupported simple values
#[test]
fn error_simple_undefined() {
    assert!(decode_value(&mut &[0xf7][..]).is_err());
} // undefined
#[test]
fn error_simple_reserved() {
    assert!(decode_value(&mut &[0xf8, 0x20][..]).is_err());
} // simple(32)

// Invalid additional info (28-30 are reserved)
#[test]
fn error_reserved_ai_28() {
    assert!(decode_value(&mut &[0x1c][..]).is_err());
}
#[test]
fn error_reserved_ai_29() {
    assert!(decode_value(&mut &[0x1d][..]).is_err());
}
#[test]
fn error_reserved_ai_30() {
    assert!(decode_value(&mut &[0x1e][..]).is_err());
}

// Invalid UTF-8 in text string
#[test]
fn error_invalid_utf8() {
    // text(2) followed by invalid UTF-8 sequence
    assert!(decode_value(&mut &[0x62, 0xff, 0xfe][..]).is_err());
}

// ═══════════════════════════════════════════════════════════════════════════
// Round-trip fidelity — encode then decode preserves value
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn rt_u64_max() {
    assert_eq!(
        rt(&Value::Integer(u64::MAX as i128)),
        Value::Integer(u64::MAX as i128)
    );
}
#[test]
fn rt_i64_min() {
    assert_eq!(
        rt(&Value::Integer(i64::MIN as i128)),
        Value::Integer(i64::MIN as i128)
    );
}
#[test]
fn rt_float_pi() {
    assert_eq!(
        rt(&Value::Float(std::f64::consts::PI)),
        Value::Float(std::f64::consts::PI)
    );
}
#[test]
fn rt_float_neg_zero() {
    assert_eq!(enc(&Value::Float(-0.0))[1], 0x80);
} // sign bit set

#[test]
fn rt_deeply_nested() {
    // 10 levels of nesting
    let mut val = Value::Integer(42);
    for _ in 0..10 {
        val = Value::Array(vec![val]);
    }
    assert_eq!(rt(&val), val);
}

#[test]
fn rt_map_with_various_key_types() {
    // Input order: int, text, bytes
    let map = Value::Map(vec![
        (Value::Integer(0), Value::Text("int-key".into())),
        (Value::Text("key".into()), Value::Integer(1)),
        (Value::Bytes(vec![0xFF]), Value::Bool(true)),
    ]);
    // After canonical sort: int (1 byte) < bytes (2 bytes) < text (4 bytes)
    let expected = Value::Map(vec![
        (Value::Integer(0), Value::Text("int-key".into())),
        (Value::Bytes(vec![0xFF]), Value::Bool(true)),
        (Value::Text("key".into()), Value::Integer(1)),
    ]);
    assert_eq!(rt(&map), expected);
}

#[test]
fn canonical_map_different_insertion_order_same_bytes() {
    // Two maps with same logical entries in different insertion order
    // must produce identical CBOR bytes (canonical ordering).
    let map_a = Value::Map(vec![
        (Value::Integer(2), Value::Text("c".into())),
        (Value::Integer(0), Value::Text("a".into())),
        (Value::Integer(1), Value::Text("b".into())),
    ]);
    let map_b = Value::Map(vec![
        (Value::Integer(1), Value::Text("b".into())),
        (Value::Integer(0), Value::Text("a".into())),
        (Value::Integer(2), Value::Text("c".into())),
    ]);
    assert_eq!(
        enc(&map_a),
        enc(&map_b),
        "same map in different order must encode identically"
    );
}

// ═══════════════════════════════════════════════════════════════════════════
// Full-stack round-trip through MinimalCodec (encode + decode = identity)
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn codec_round_trip_integer() {
    let v = 42i64;
    let bytes = corim::cbor::encode(&v).unwrap();
    let decoded: i64 = corim::cbor::decode(&bytes).unwrap();
    assert_eq!(v, decoded);
}

#[test]
fn codec_round_trip_string() {
    let v = "hello CBOR";
    let bytes = corim::cbor::encode(&v).unwrap();
    let decoded: String = corim::cbor::decode(&bytes).unwrap();
    assert_eq!(v, decoded);
}

#[test]
fn codec_round_trip_bytes() {
    // Bytes go through Value directly
    let v = Value::Bytes(vec![0xDE, 0xAD, 0xBE, 0xEF]);
    let bytes = corim::cbor::encode(&v).unwrap();
    let decoded: Value = corim::cbor::decode(&bytes).unwrap();
    assert_eq!(v, decoded);
}

#[test]
fn codec_round_trip_bool() {
    let bytes_t = corim::cbor::encode(&true).unwrap();
    let bytes_f = corim::cbor::encode(&false).unwrap();
    assert_eq!(bytes_t, vec![0xf5]);
    assert_eq!(bytes_f, vec![0xf4]);
    assert!(corim::cbor::decode::<bool>(&bytes_t).unwrap());
    assert!(!corim::cbor::decode::<bool>(&bytes_f).unwrap());
}

#[test]
fn codec_round_trip_option_some() {
    let v: Option<u32> = Some(42);
    let bytes = corim::cbor::encode(&v).unwrap();
    let decoded: Option<u32> = corim::cbor::decode(&bytes).unwrap();
    assert_eq!(v, decoded);
}

#[test]
fn codec_round_trip_option_none() {
    let v: Option<u32> = None;
    let bytes = corim::cbor::encode(&v).unwrap();
    assert_eq!(bytes, vec![0xf6]); // null
}

#[test]
fn codec_round_trip_vec() {
    let v = vec![1u32, 2, 3, 4, 5];
    let bytes = corim::cbor::encode(&v).unwrap();
    let decoded: Vec<u32> = corim::cbor::decode(&bytes).unwrap();
    assert_eq!(v, decoded);
}
