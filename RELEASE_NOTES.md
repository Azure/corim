# Release Notes — v0.1.0

**Published:** April 17, 2026  
**Crates:** [`corim`](https://crates.io/crates/corim) v0.1.0, [`corim-macros`](https://crates.io/crates/corim-macros) v0.1.0  
**Spec:** [draft-ietf-rats-corim-10](https://www.ietf.org/archive/id/draft-ietf-rats-corim-10.html)

---

## Overview

Initial release of the CoRIM (Concise Reference Integrity Manifest) Rust crate — a CBOR-native implementation of draft-ietf-rats-corim-10 for Remote Attestation (RATS) Endorsements and Reference Values.

## Highlights

### Full CDDL Coverage
- `corim-map`, `concise-mid-tag` (CoMID), `concise-tl-tag` (CoTL)
- All 9 triple types: reference, endorsed, identity, attest-key, domain dependency/membership, CoSWID, conditional endorsement, conditional endorsement series
- `measurement-values-map` with all fields (digests, SVN, flags, raw-value, MAC/IP addresses, integrity registers, int-range, crypto keys)
- CoSWID structured types per RFC 9393 with co-constraint validation

### Signed CoRIM (`#6.18`)
- Decode, validate, and construct `COSE_Sign1-corim` structures per §4.2
- Attached and detached payload modes
- No cryptographic dependency — emits RFC 9052 `Sig_structure1` TBS blob for external signing
- Protected header extraction: `corim-meta`, `CWT-Claims` (RFC 8392/9597), hash-envelope fields
- X.509 certificate chain parsing per RFC 9360 (`x5chain`, `x5t`, `x5bag`, `x5u`, `kid`)
- `CoseAlgorithm` enum with RFC 9864 fully-specified identifiers (ESP256, Ed25519, etc.) and deprecated polymorphic variants (ES256, EdDSA) marked accordingly

### Zero-Dependency CBOR
- Built-in minimal CBOR encoder/decoder
- Deterministic encoding per RFC 8949 §4.2.1 (canonical map key sorting)
- No external CBOR library required
- `CborCodec` trait for future backend extensibility

### Builder API
- `ComidBuilder`, `CotlBuilder`, `CorimBuilder`, `SignedCorimBuilder`
- Fluent interface with compile-time and runtime constraint validation
- `#[must_use]` on all builders

### Validation & Appraisal
- Reference value matching (§9.3)
- Conditional endorsement series application (§9.3.4)
- Environment/measurement/SVN/digest comparison per §9.4

### `no_std` Support
- `#![no_std]` + `alloc` when `std` feature is disabled
- `std` feature (default-on) adds `SystemTime`-based validation
- `json` feature adds `serde_json` support (implies `std`)

### Interop Relaxations (Decode-Only)
- Bare (untagged) 16-byte `bstr` accepted as UUID in all type-choices
- Text digest algorithm identifiers accepted per CDDL (`alg: int / text`)
- Flat CWT claims in protected header (keys 1/2/4/5 at top level)
- Tolerant `corim-meta` decode (malformed inner CBOR stored as raw bytes)
- Tolerant COSE_Sign1 elements for non-standard envelopes
- `non-empty<M>` correctly accepts maps with only extension keys

### Derive Macros (`corim-macros`)
- `CborSerialize` / `CborDeserialize` for integer-keyed CBOR maps
- Compile-time key ordering and duplicate validation (RFC 8949 §4.2.1)
- `#[cbor(key, optional, tag, non_empty)]` attributes
- Unknown keys silently skipped for forward compatibility

### CLI Tool (`corim-cli`)
- Validates and inspects unsigned (tag 501) and signed (tag 18) CoRIM documents
- Auto-detects format
- Text and JSON output modes
- Displays COSE header info (algorithm, signer, X.509 chain, signature size)

## Stats

| Metric | Value |
|--------|-------|
| Tests | 631 |
| Library source lines | ~8,900 |
| Test source lines | ~8,900 |
| Source files | 25 |
| Clippy warnings | 0 |
| `unsafe` blocks | 0 |
| Dependencies (no features) | 3 (serde, thiserror, corim-macros) |
| Dependencies (+json) | 4 (+serde_json) |

## Compliance

| Feature | Status |
|---------|--------|
| CoMID (§5) `#6.506` | ✅ |
| CoTL (§6) `#6.508` | ✅ |
| CoSWID (RFC 9393) `#6.505` | ✅ (core subset) |
| Signed CoRIM (§4.2) `#6.18` | ✅ |
| X.509 headers (RFC 9360) | ✅ |
| COSE algorithms (RFC 9864) | ✅ |
| `no_std` + `alloc` | ✅ |
| CDDL extension sockets | ❌ (unknown keys skipped) |

## Known Limitations

- CDDL extension sockets (`$$*-extension`) are not modeled; unknown keys are silently skipped for forward compatibility
- `Digest` stores text algorithm IDs as `alg = -1`; full text-alg support deferred to struct redesign
- Float encoding always uses float64 (CoRIM rarely uses floats)
- No indefinite-length CBOR encoding (rejected on decode; CoRIM uses definite only)
- Cryptographic signature verification is not performed — the caller must verify externally

## Release Pattern

- **Tag:** `v0.1.0`
- **Branch:** `release/v0.1.0` — frozen snapshot of published code
- **Future releases:** Bump version in both `Cargo.toml` files, tag `vX.Y.Z`, create `release/vX.Y.Z` branch

## Links

- [crates.io/crates/corim](https://crates.io/crates/corim)
- [crates.io/crates/corim-macros](https://crates.io/crates/corim-macros)
- [docs.rs/corim](https://docs.rs/corim)
- [GitHub: Azure/corim](https://github.com/Azure/corim)
