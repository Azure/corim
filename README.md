# corim

**Concise Reference Integrity Manifest (CoRIM)** — Rust implementation of
[draft-ietf-rats-corim-10](https://www.ietf.org/archive/id/draft-ietf-rats-corim-10.html).

This crate provides CBOR-native Rust types for the CoRIM / CoMID CDDL schema,
a builder API, validation/appraisal logic, and signed CoRIM (COSE_Sign1)
support for Remote Attestation (RATS) Endorsements and Reference Values.

## Features

- **Full CDDL coverage** — types for `corim-map`, `concise-mid-tag` (CoMID),
  `concise-tl-tag` (CoTL), all 9 triple types (reference, endorsed, identity,
  attest-key, domain dependency/membership, CoSWID, conditional endorsement,
  conditional endorsement series), `measurement-values-map` with all fields
  (digests, SVN, flags, raw-value, MAC/IP addresses, integrity registers,
  int-range, crypto keys, etc.).

- **Signed CoRIM (`#6.18`)** — decode, validate, and construct COSE_Sign1-corim
  structures per §4.2. Supports both attached and detached payload modes.
  No cryptographic dependencies — the caller signs/verifies externally using
  the emitted `Sig_structure1` TBS blob. Protected header extraction includes
  `corim-meta`, `CWT-Claims`, and hash-envelope fields.

- **Zero-dependency CBOR** — built-in CBOR encoder/decoder with deterministic
  encoding per RFC 8949 §4.2.1. No external CBOR library required. The
  `CborCodec` trait allows plugging in alternative backends in the future.

- **`no_std` support** — the `corim` library crate compiles with
  `#![no_std]` + `alloc`. The `std` feature (default) adds `SystemTime`-based
  validation. The `json` feature requires `std`.

- **Integer-keyed CBOR maps** — derive macros (`CborSerialize` /
  `CborDeserialize`) emit deterministic CBOR with integer keys per RFC 8949
  §4.2.1.

- **Builder API** — fluent `ComidBuilder`, `CotlBuilder`, `CorimBuilder`, and
  `SignedCorimBuilder` for constructing tagged CoRIM payloads. `ComidBuilder`
  has an opt-in environment catalog (`declare_env` / `EnvRef` /
  `add_*_for(…)`) for sharing one `EnvironmentMap` across multiple triples,
  plus a `strict_links` lint that flags conditional/endorsed triples whose
  condition env is not anchored by any reference triple in the same CoMID.

- **Validation & Appraisal** — reference value matching (Phase 3) and
  conditional endorsement series application (Phase 4) per §9 of the spec.

- **Profile framework** — [`corim::profile`](corim/src/profile.rs) defines a
  `Profile` trait, a `ProfileRegistry`, and a `MatchContext` (epoch-aware)
  so downstream crates can plug in CoRIM profiles that introduce extra
  measurement-values-map fields or non-core CBOR tags. The first-party
  Intel profile (`draft-cds-rats-intel-corim-profile`) ships under the
  `profile-intel` Cargo feature with an `IntelProfile`, the `#6.60010`
  expression decoder, and `tdate`-aware match semantics.

- **CoSWID** — structured `ConciseSwidTag`, `SwidEntity`, `SwidLink` types
  per RFC 9393 with co-constraint validation (patch/supplemental, tag-creator
  role, patches link).

- **Optional JSON** — `json` feature gate adds `Value ↔ serde_json::Value`
  conversion with integer-to-string key remapping and type-choice JSON format.

- **TCG / NVIDIA decode interop** — accepts the legacy `#6.500` / `#6.502`
  outer wrappers, bare `corim-map` payloads, and TCG-style `#6.506(map)`
  CoMID nesting seen in real-world signed CoRIMs (notably NVIDIA NIC
  firmware). Decode-only; encoders always emit draft-10 wire format.
  See [`corim::compat`](corim/src/compat.rs) for the full list.

## MSRV

Rust 1.85.

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

// Build a CoMID with reference values
let comid = ComidBuilder::new(TagIdChoice::Text("my-comid-tag".into()))
    .add_reference_triple(ReferenceTriple::new(env, vec![meas]))
    .build()
    .unwrap();

// Wrap in a CoRIM and encode to tag-501-wrapped CBOR
let bytes = CorimBuilder::new(CorimId::Text("my-corim".into()))
    .add_comid_tag(comid).unwrap()
    .build_bytes().unwrap();

// Decode and validate
let (_corim, _comids) = corim::validate::decode_and_validate(&bytes).unwrap();
```

## Compliance notes

This crate implements CoRIM per draft-ietf-rats-corim-10.

| Feature | Status |
|---------|--------|
| **CoMID** (§5) — `#6.506` | ✅ Fully modeled — types, builder, validation, appraisal |
| **CoTL** (§6) — `#6.508` | ✅ Fully modeled — `ConciseTlTag`, `CotlBuilder`, validity checks |
| **CoSWID** (RFC 9393) — `#6.505` | ✅ Structured — `ConciseSwidTag`, `SwidEntity`, `SwidLink`; payload/evidence opaque |
| **Signed CoRIM** (§4.2) — `#6.18` | ✅ Decode, validate, construct (attached + detached); no crypto dependency |
| CDDL extension sockets | ❌ Not modeled; unknown keys silently skipped for forward compatibility |
| CoTS (concise-ta-stores) | ❌ Separate draft, not modeled |
| `no_std` + `alloc` | ✅ Library crate compiles without `std`; `std` feature is default-on |

## Signed CoRIM

The crate supports creating and parsing signed CoRIM documents (`#6.18` /
`COSE_Sign1-corim`) without any cryptographic dependencies. The caller
performs signature operations externally.

```rust,no_run
use corim::types::signed::{SignedCorimBuilder, CwtClaims};

// 1. Build unsigned CoRIM payload bytes (tag-501-wrapped)
let corim_bytes: Vec<u8> = /* CorimBuilder::build_bytes() */ vec![];

// 2. Create a signed CoRIM builder
let mut builder = SignedCorimBuilder::new(-7, corim_bytes) // ES256
    .set_cwt_claims(CwtClaims::new("ACME Corp"));

// 3. Get the Sig_structure1 TBS blob
let tbs = builder.to_be_signed(&[]).unwrap();

// 4. Sign with your crypto library (ring, openssl, etc.)
let signature = vec![0u8; 64]; // placeholder

// 5. Produce the final signed CoRIM
let signed_bytes = builder.build_with_signature(signature).unwrap();
```

For detached payloads, use `build_detached_with_signature()` and
`to_be_signed_detached()` on the decoded envelope. See the
[`types::signed`](corim/src/types/signed/mod.rs) module documentation for
the full API.

## Crate structure

| Crate | Description |
|-------|-------------|
| `corim` | Main library — types, builder, validation, signed CoRIM, CBOR engine |
| `corim-macros` | Proc-macro derives for integer-keyed CBOR map serde |
| `corim-cli` | CLI tool for validating and inspecting CoRIM documents |

## CBOR implementation

This crate includes a built-in minimal CBOR encoder/decoder. No external CBOR
library is needed.

**What's supported** — the CBOR subset used by CoRIM:
- All CBOR major types (unsigned/negative int, byte/text strings, arrays, maps, tags)
- Deterministic encoding per RFC 8949 §4.2.1 (canonical map key sorting)
- Semantic tags (essential for CoRIM type-choice dispatching)
- Half/single/double precision float decoding

**Limitations** (none affect CoRIM functionality):
- No indefinite-length encoding (rejected on decode; CoRIM uses definite only)
- Float encoding always uses float64 (CoRIM rarely uses floats)
- No CBOR simple values beyond false/true/null (not used in CoRIM)
- Nesting depth limited by call stack (~100+ levels; CoRIM is typically 5–10)

## CLI tool

The `corim-cli` binary validates, inspects, and generates both unsigned
(tag 501) and signed (tag 18) CoRIM documents. It is organized into
subcommands:

```sh
# Validate an unsigned CoRIM
corim-cli validate --skip-expiry myfile.corim

# Validate a signed CoRIM (auto-detected)
corim-cli validate --skip-expiry signed.corim

# JSON output
corim-cli validate -f json myfile.corim

# Non-aborting structural diagnose pass — prints issues without rejecting
corim-cli validate --diagnose myfile.corim

# Generate an unsigned CoRIM from a JSON template
corim-cli generate template.json -o out.cbor
```

### `generate` — build a CoRIM from a JSON template

`generate` builds an **unsigned** CoRIM from a hand-authored JSON
template. Each entry in the template's `comids` array is deserialized
into a decoded CoMID (full triples tree), then encoded and wrapped by
the builder.

Map keys may be written as **prose names** (`"tag-identity"`,
`"triples"`, `"vendor"`, `"svn"`, …); the CLI rewrites them to the CBOR
integer keys the core `json` layer expects using a context-aware state
machine (it knows, e.g., that `"version"` is key 1 in `tag-identity` but
key 0 in `measurement-values-map`). Raw integer-string keys (`"1"`,
`"4"`, …) are still accepted, and the rewrite is idempotent — so
prose, integer, and mixed templates all produce identical output.
Triple records are positional CBOR arrays and stay positional arrays in
the template (only map keys are named).

Profile-defined `measurement-values-map` extension keys can be written
by alias (e.g. `"tcbstatus": "UpToDate"` instead of `"-700": ...`) when
the template's `profile` field names a profile the CLI was compiled with.
See [`corim-cli/templates/azure_ndpa.json`](corim-cli/templates/azure_ndpa.json)
for a worked example (equivalent to the `build_corim_ovl3_tdisp_ndpa`
example). Signed CoRIM generation is out of scope — sign the output
separately via `SignedCorimBuilder`.

Two helper binaries also ship with `corim-cli` for generating fixtures and
worked examples:

```sh
corim-gen-sample            # write a minimal unsigned CoRIM fixture
corim-gen-signed-sample     # write a minimal signed CoRIM fixture
```

`corim-cli` is a local development tool and is not published to crates.io.

## Contributing

This project welcomes contributions and suggestions. Most contributions require you to agree to a
Contributor License Agreement (CLA) declaring that you have the right to, and actually do, grant us
the rights to use your contribution. For details, visit [Contributor License Agreements](https://cla.opensource.microsoft.com).

When you submit a pull request, a CLA bot will automatically determine whether you need to provide
a CLA and decorate the PR appropriately (e.g., status check, comment). Simply follow the instructions
provided by the bot. You will only need to do this once across all repos using our CLA.

This project has adopted the [Microsoft Open Source Code of Conduct](https://opensource.microsoft.com/codeofconduct/).
For more information see the [Code of Conduct FAQ](https://opensource.microsoft.com/codeofconduct/faq/) or
contact [opencode@microsoft.com](mailto:opencode@microsoft.com) with any additional questions or comments.

See [CONTRIBUTING.md](CONTRIBUTING.md) for detailed guidelines.

## Trademarks

This project may contain trademarks or logos for projects, products, or services. Authorized use of Microsoft
trademarks or logos is subject to and must follow
[Microsoft's Trademark & Brand Guidelines](https://www.microsoft.com/en-us/legal/intellectualproperty/trademarks/usage/general).
Use of Microsoft trademarks or logos in modified versions of this project must not cause confusion or imply Microsoft sponsorship.
Any use of third-party trademarks or logos are subject to those third-party's policies.

## License

[MIT](LICENSE)
