# Changelog

All notable changes to the `corim` and `corim-macros` crates are documented
in this file. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [SemVer](https://semver.org/spec/v2.0.0.html)
with the caveat that pre-1.0 releases may include breaking changes in minor
versions.

## [Unreleased]

### Changed (breaking, profile-intel feature)

- **Intel CoRIM profile aligned with draft -07** (was -03). v07 reworks
  the CBOR wire format for operator-shaped reference values:
  - New CBOR tags `#6.60020` (`tagged-exp-digest-{member,not-member}`)
    and `#6.60021` (`tagged-exp-tstr-{member,not-member}`); v03
    overloaded tag `#6.60010` for these shapes.
  - `op.eq=0` is now an explicit operator code.
  - Removed: `op.subset=8`, `op.superset=9`, `op.disjoint=10`, and the
    overloaded `mask-eq` 3-element form on tag `#6.60010`.
  - Removed measurement key `tee.instance-id` (-77); use the new
    `tee.platform-instance-id` (-101) per v07 §8.3.6.
  - Removed measurement key `tee.epoch` (-90).
  - SVN-typed extension keys (`tee.isvsvn`, `tee.tcb-eval-num`,
    `tee.tcb-comp-svn`) now also accept base-CoRIM `tagged-int-range`
    (`#6.564`) and `tagged-min-svn` (`#6.553`).
  - `tee.tcbdate` (-72) now accepts RFC 9581 `etime` (`#6.1001`),
    `duration` (`#6.1002`), and `period` (`#6.1003`).

  Affected public API in [`corim::profile::intel`](corim/src/profile/intel/mod.rs):
  - Added: `TAG_INTEL_SET_DIGEST_EXPRESSION`,
    `TAG_INTEL_SET_TSTR_EXPRESSION`, `MVAL_TEE_PLATFORM_INSTANCE_ID`,
    `Expression::SetOfDigests`, `Expression::SetOfTstr`,
    `Expression::IntRange`, `Expression::MinSvn`, `NumericOp::Eq`,
    `Expression::is_intel_expression_tag`.
  - Removed: `MVAL_TEE_INSTANCE_ID`, `MVAL_TEE_EPOCH`, `SetOfSetOp`,
    `Expression::Mask`, `Expression::SetOfSet`, `Expression::Tdate`,
    `Expression::Epoch`, and the corresponding
    `ExpressionDecodeError::{EpochGraceOutOfRange, SetOfSetMemberNotArray,
    TdateNotText}` variants.

## [0.1.2] — 2026-06-01

**Crates:** [`corim`](https://crates.io/crates/corim) v0.1.2, [`corim-macros`](https://crates.io/crates/corim-macros) v0.1.2
**MSRV:** Rust 1.85

### Added

- **Profile framework** ([`corim::profile`](corim/src/profile.rs)) —
  pluggable extension points for CoRIM profiles that introduce
  non-core CBOR tags, profile-specific match semantics, or extra
  measurement-value fields:
  - New [`Profile`](corim/src/profile.rs) trait with
    `match_measurement`, `diagnose_extra_mvm_field`, and
    `match_context` hooks.
  - [`ProfileRegistry`](corim/src/profile.rs) dispatches by
    `ProfileChoice` (URI or OID).
  - [`MatchContext`](corim/src/profile.rs) carries appraisal-time
    facts such as the current epoch for time-based expressions.
  - [`validate::match_reference_values_with_profile`](corim/src/validate.rs)
    and the other `_with_profile` APIs are generic over
    `P: ?Sized + Profile` so trait objects work out of the box.
  - [`validate::core_fields_match`](corim/src/validate.rs) is now
    public so profile implementations can compose core matching
    with their own extra-field logic.
  - The `diagnose` walker descends into `measurement-values-map`
    and consults the registered `Profile` for unknown keys.
- **Intel CoRIM profile** under the new `profile-intel` feature —
  was previously a separate `corim-profile-intel` crate; folded
  back into `corim` so that profile plug-ins ship without extra
  workspace setup. Adds:
  - [`profile::intel::IntelProfile`](corim/src/profile/intel/mod.rs)
    (OID `2.16.840.1.113741.1.16.1`).
  - Operator-based [`match_measurement`](corim/src/profile/intel/mod.rs)
    with the Intel-defined comparators.
  - [`profile::intel::expression`](corim/src/profile/intel/expression.rs)
    decoder for the `#6.60010` tagged expression form, including
    `tdate` (epoch-based) expressions evaluated against
    `MatchContext`.
- **Environment catalog on `ComidBuilder`** — opt-in build-time mechanism
  for sharing one `EnvironmentMap` across multiple triples in a CoMID:
  - `ComidBuilder::declare_env(label, env) -> Result<EnvRef, _>` registers
    an env under a unique label and returns an opaque, builder-scoped handle.
  - Nine new `add_*_for(impl Into<EnvSpec>, ...)` methods covering all
    triple kinds — reference, endorsed, identity, attest-key, dependency,
    membership, coswid, conditional-endorsement-series, and
    conditional-endorsement. Each accepts either an inline
    `EnvironmentMap` or an `EnvRef`. Refs are resolved to inline envs at
    `build()` time; wire format is unchanged.
  - `add_conditional_endorsement_series_for(condition_env, claims_list, authorized_by, series)`
    and `add_conditional_endorsement_for(conditions, endorsements)` take
    env-specs for the nested condition env(s) and assemble the wire-type
    internally, so the by-ref equivalence guarantee extends to
    conditional triples — the most common case where one env must be
    structurally shared with a reference triple.
  - New `BuilderError` variants: `DuplicateEnvLabel` and
    `RefFromOtherBuilder`. Refs from one builder used on another fail
    deterministically rather than silently aliasing.
- **`ComidBuilder::strict_links(bool)`** — opt-in builder-side lint that
  rejects conditional-endorsement-series, endorsed, and
  conditional-endorsement triples whose condition `EnvironmentMap` does
  not structurally equal any reference-triple env in the same CoMID.
  Surfaces as the new
  [`BuilderError::UnanchoredConditionEnv`](corim/src/error.rs) variant.
  Default is unchanged (no cross-triple checks); wire format is
  unaffected.
- **`#[cbor(extras = "field")]` derive attribute** in
  [`corim-macros`](corim-macros) — declarative CDDL extension-socket
  support. Unknown integer-keyed map entries are collected into the
  named `BTreeMap<i64, Value>` field on deserialize and re-emitted
  on serialize, preserving forward-compatibility for
  `$$*-extension` group sockets.
- **Exported `CWT_CLAIM_*` constants** — `CWT_CLAIM_ISS`,
  `CWT_CLAIM_SUB`, `CWT_CLAIM_EXP`, `CWT_CLAIM_NBF`, `CWT_CLAIM_IAT`
  are now `pub` and re-exported from
  [`corim::types::signed`](corim/src/types/signed/mod.rs), matching
  the existing `COSE_HEADER_*` exports. Lets external signer /
  verifier tooling use the named keys instead of hard-coding the
  integer claim numbers.

### Changed

- The standalone `corim-profile-intel` crate was removed; its
  contents now live in `corim` behind the `profile-intel` feature.
  Downstream users should switch from
  `corim-profile-intel = "..."` to
  `corim = { version = "0.1.2", features = ["profile-intel"] }`.

### Internal

- Pre-commit hook gained a rustdoc gate
  (`RUSTDOCFLAGS=-D warnings cargo doc --no-deps`), matching the CI
  Documentation job. Documented in [`CONTRIBUTING.md`](CONTRIBUTING.md).
- Test files reorganized by topic (`display_tests.rs`,
  `builder_tests.rs`, `cbor_value_tests.rs`,
  `json_value_conv_tests.rs`, `cbor_tag_choice_de_tests.rs`,
  `signed_corim_tests.rs`, `validate_tests.rs`); the legacy
  `coverage_*_tests.rs` files were removed once their cases moved
  to behavior-named files.

### Notes

- `corim-cli` is bumped to 0.1.2 in lockstep but is **not
  published** to crates.io (`publish = false`).
- No breaking changes to existing public APIs. The `profile-intel`
  feature is additive; the env catalog and `strict_links` lint are
  opt-in.

## [0.1.1] — 2026-05-04

**Crates:** [`corim`](https://crates.io/crates/corim) v0.1.1, [`corim-macros`](https://crates.io/crates/corim-macros) v0.1.1
**MSRV:** Rust 1.85

### Added

- **TCG / NVIDIA decode interop** ([`corim::compat`](corim/src/compat.rs)) — decode-only relaxations
  that allow parsing real-world signed CoRIMs produced against the pre-PR-#337
  IETF draft and the TCG Endorsement spec, notably NVIDIA NIC firmware
  CoRIMs:
  - `peel_tcg_wrappers` strips legacy outer `#6.500` / `#6.502` tags.
  - `wrap_bare_corim_map` synthesizes a `#6.501` header for bare
    `corim-map` payloads.
  - `decode_comid_from_tcg_bstr` accepts both the spec-correct
    `#6.506(bstr .cbor map)` shape and the TCG-style
    `#6.506(map)` / bare-map shapes.
  - New `ConciseTagChoice::BareBstr` variant carries unwrapped `bstr`
    `tags[]` entries seen in the wild. Encoders always emit `#6.506(bstr)`.
- **Diagnose pass** (`corim::diagnose`, CLI `--diagnose`) — non-aborting
  structural inspector that reports issues without rejecting the document.
  Surfaces TCG wrapper warnings inline at the relevant CBOR paths.
- **`as_comid()`** on `ConciseTagChoice` — convenience accessor for
  extracting the inner CoMID tag.
- **`CborTagChoice` derive** in `corim-macros` — declarative codegen for
  type-choice enums (`int / text / #6.N(...)`), replacing five blocks of
  hand-written serde. Supports `#[cbor(tag = N)]`, `#[cbor(tag = N, text)]`
  for tagged-text variants, and `#[cbor(catch_bare_bytes)]` for the
  TCG bare-bstr fallback. Migrated: `ClassIdChoice`, `TagIdChoice`,
  `GroupIdChoice`, `MeasuredElement`, `CryptoKey`, `InstanceIdChoice`.
- **Better fixed-size byte error messages** — derive macro now reports the
  expected size on length mismatch.
- **`deny.toml`** — workspace policy enforcing the zero-CBOR-deps invariant
  and a tight allowlist of licenses.
- **MSRV** — `rust-version = "1.85"` is now declared on `corim` and
  `corim-macros`.

### Changed

- **Internal refactor:** `types::signed.rs` (~1.6k lines) split into
  `types::signed/{algorithm, x509, cwt, header, envelope, builder, mod}.rs`.
  No public API surface change — all re-exports under `types::signed::*`
  are preserved.
- **CLI signed-CoRIM display** structured by COSE_Sign1 sections;
  `--show-raw` flag fixed.
- **`CoseAlgorithm`** doc-text corrected: deprecated variants are
  intentionally **not** annotated with `#[deprecated]` so that downstream
  code parsing real-world ES256/EdDSA-signed CoRIMs does not emit
  warnings. Use `is_deprecated()` to check at runtime.

### Fixed

- Coverage-test bug where `signed_corim_coverage_tests` did not exercise
  the path it claimed to cover.

### Notes

- `corim-cli` is bumped to 0.1.1 in lockstep but is **not published** to
  crates.io (`publish = false`). It remains a local development tool.
- No breaking API changes. The `signed` module split and the
  `CborTagChoice` migration preserve all previously-exported symbols.

---

## [0.1.0] — 2026-04-17

**Crates:** [`corim`](https://crates.io/crates/corim) v0.1.0, [`corim-macros`](https://crates.io/crates/corim-macros) v0.1.0
**Spec:** [draft-ietf-rats-corim-10](https://www.ietf.org/archive/id/draft-ietf-rats-corim-10.html)

### Overview

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
