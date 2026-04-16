# corim

**Concise Reference Integrity Manifest (CoRIM)** — Rust implementation of
[draft-ietf-rats-corim-10](https://www.ietf.org/archive/id/draft-ietf-rats-corim-10.html).

CBOR-native Rust types for the CoRIM / CoMID CDDL schema, a builder API,
validation/appraisal logic, and signed CoRIM (COSE_Sign1) support for
Remote Attestation (RATS) Endorsements and Reference Values.

## Features

- **Full CDDL coverage** — `corim-map`, CoMID, CoTL, all 9 triple types,
  `measurement-values-map` with all fields
- **Signed CoRIM (`#6.18`)** — decode, validate, construct (attached + detached);
  no crypto dependency
- **Zero-dependency CBOR** — built-in encoder/decoder, deterministic per RFC 8949 §4.2.1
- **`no_std` support** — `#![no_std]` + `alloc`; `std` feature (default) adds
  `SystemTime`-based validation
- **Builder API** — `ComidBuilder`, `CotlBuilder`, `CorimBuilder`, `SignedCorimBuilder`
- **Validation & Appraisal** — reference value matching (§9.3), conditional
  endorsement series (§9.3.4)
- **CoSWID** — structured types per RFC 9393 with co-constraint validation
- **Optional JSON** — `json` feature gate for `Value ↔ serde_json::Value` conversion

## Quick start

```rust
use corim::builder::{ComidBuilder, CorimBuilder};
use corim::types::common::{TagIdChoice, MeasuredElement};
use corim::types::corim::CorimId;
use corim::types::environment::{ClassMap, EnvironmentMap};
use corim::types::measurement::{Digest, MeasurementMap, MeasurementValuesMap};
use corim::types::triples::ReferenceTriple;

let env = EnvironmentMap {
    class: Some(ClassMap {
        class_id: None,
        vendor: Some("ACME".into()),
        model: Some("Widget".into()),
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

let comid = ComidBuilder::new(TagIdChoice::Text("my-comid-tag".into()))
    .add_reference_triple(ReferenceTriple::new(env, vec![meas]))
    .build()
    .unwrap();

let bytes = CorimBuilder::new(CorimId::Text("my-corim".into()))
    .add_comid_tag(comid).unwrap()
    .build_bytes().unwrap();

let (_corim, _comids) = corim::validate::decode_and_validate(&bytes).unwrap();
```

## Feature flags

| Feature | Default | Description |
|---------|---------|-------------|
| `std` | ✅ | Enables `SystemTime`-based validation, `std::error::Error` impls |
| `json` | | Adds JSON serialization (implies `std`) |

For `no_std`, disable default features:

```toml
[dependencies]
corim = { version = "0.1", default-features = false }
```

## Compliance

| Feature | Status |
|---------|--------|
| **CoMID** (§5) — `#6.506` | ✅ Fully modeled |
| **CoTL** (§6) — `#6.508` | ✅ Fully modeled |
| **CoSWID** (RFC 9393) — `#6.505` | ✅ Structured core subset |
| **Signed CoRIM** (§4.2) — `#6.18` | ✅ Decode, validate, construct |
| `no_std` + `alloc` | ✅ Library compiles without `std` |

## License

[MIT](https://github.com/Azure/corim/blob/main/LICENSE)
