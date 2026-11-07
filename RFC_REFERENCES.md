# RFC Reference Tracking

This document tracks all RFCs and Internet-Drafts referenced by the `corim` crate implementation. It serves as a compliance checklist and must be updated when:

- A referenced draft advances to a new revision or becomes an RFC
- The implementation adds support for a new specification
- An RFC errata affects our implementation

**Last reviewed**: November 6, 2026

---

## Primary Specification

### draft-ietf-rats-corim-12 — Concise Reference Integrity Manifests (CoRIM)

| | |
|-|-|
| **Status** | Internet-Draft (not yet RFC) |
| **Version implemented** | **-12** (wire model and selected appraisal operations) |
| **URL** | https://www.ietf.org/archive/id/draft-ietf-rats-corim-12.html |
| **Datatracker** | https://datatracker.ietf.org/doc/draft-ietf-rats-corim/ |
| **CDDL source** | `cddl/corim.cddl` (draft-12 base with existing profile extensions) |

#### Sections Implemented

| Section | Topic | Status | Rust Module |
|---------|-------|--------|-------------|
| §4 | `corim-map` (unsigned CoRIM) | ✅ Full | `types/corim.rs` → `CorimMap` |
| §4.1.1 | `corim-id` | ✅ Full | `types/corim.rs` → `CorimId` |
| §4.1.3 | `corim-locator-map` | ✅ Full | `types/corim.rs` → `CorimLocator` |
| §4.1.4 | `profile` (wire format) | ✅ Full | `types/corim.rs` → `ProfileChoice` |
| §4.1.4 | Profile extension framework | ✅ Full | `profile.rs` → `Profile`, `ProfileRegistry`, `MatchContext` |
| §4.1.5 | `entity-map` (CoRIM) | ✅ Full | `types/common.rs` → `EntityMap` |
| §4.2.1 | Single-signature CoRIM (`#6.18`) | ✅ No crypto | `types/signed/envelope.rs`, `builder.rs` |
| §4.2.3 | Multi-signature CoRIM (`#6.98`) | ✅ No crypto | `types/signed/multi.rs` → `CoseSignCorim`, `MultiSignedCorimBuilder` |
| §5.1.4.9 | Primitive matchers (keys 16–20) | ✅ Integer/float domains separate; condition-only ranges/sets | `types/matcher.rs`, `types/measurement.rs` |
| §5 | `concise-mid-tag` (CoMID) | ✅ Full | `types/comid.rs` → `ComidTag` |
| §5.1.1 | `tag-identity-map` | ✅ Full | `types/common.rs` → `TagIdentity` |
| §5.1.2 | CoMID entities | ✅ Full | `types/common.rs` → `EntityMap` |
| §5.1.3 | `linked-tag-map` | ✅ Full | `types/common.rs` → `LinkedTagMap` |
| §5.1.4.1 | `environment-map` | ✅ Full | `types/environment.rs` → `EnvironmentMap` |
| §5.1.4.2 | `class-map` | ✅ Full | `types/environment.rs` → `ClassMap` |
| §5.1.4.5 | `measurement-map` | ✅ Full | `types/measurement.rs` → `MeasurementMap` |
| §5.1.4.5.3 | `version-map` | ✅ Full | `types/common.rs` → `VersionMap` |
| §5.1.5 | Reference triples | ✅ Full | `types/triples.rs` → `ReferenceTriple` |
| §5.1.6 | Endorsed triples | ✅ Full | `types/triples.rs` → `EndorsedTriple` |
| §5.1.7 | Conditional endorsement triples | ✅ Full | `types/triples.rs` → `ConditionalEndorsementTriple` |
| §5.1.8 | Conditional endorsement series | ✅ Full | `types/triples.rs` → `ConditionalEndorsementSeriesTriple` |
| §5.1.9 | Identity triples | ✅ Full | `types/triples.rs` → `IdentityTriple` |
| §5.1.10 | Attest-key triples | ✅ Full | `types/triples.rs` → `AttestKeyTriple` |
| §5.1.11.1 | Domain membership triples | ✅ Full | `types/triples.rs` → `DomainMembershipTriple` |
| §5.1.11.2 | Trust dependency triples | ✅ Full | `types/triples.rs` → `TrustDependencyTriple` |
| §5.1.12 | CoSWID triples | ✅ Full | `types/triples.rs` → `CoswidTriple` |
| §6 | `concise-tl-tag` (CoTL) | ✅ Full | `types/corim.rs` → `ConciseTlTag` |
| §6.1 | CoTL validity checks | ✅ Full | `validate.rs` → `validate_cotl` |
| §7 | Type-choice definitions | ✅ Full | `types/common.rs`, `types/measurement.rs` |
| §7.3 | `validity-map` | ✅ Full | `types/common.rs` → `ValidityMap` |
| §7.4 | UUID size constraints | ✅ Full | `types/tags.rs` → `UUID_SIZE` |
| §7.5 | UEID size constraints (7–33 bytes) | ✅ Full | `types/common.rs` → `InstanceIdChoice::Ueid` |
| §8.3 | Appraisal / Validation | ✅ Partial; not a full ACS/graph engine | `validate.rs` |
| §8.3.3 | Input validation | ✅ Structural/temporal; no crypto or remote fetch | `document.rs`, `validate.rs` |
| §8.3.3 | Profile-aware input validation | ✅ Registered profile checks | `validate.rs` → `decode_and_validate_with_registry` |
| §8.3.4.2 | Reference value matching | ✅ Full | `validate.rs` → `match_reference_values` |
| §8.3.4.2 | Profile-aware reference value matching | ✅ Full | `validate.rs` → `match_reference_values_with_profile` |
| §8.3.4.3.2 | CES application | ✅ Partial, existing direct-evidence API | `validate.rs` → `apply_endorsement_series` |
| §8.3.4.3.2 | Profile-aware CES application | ✅ Partial, existing direct-evidence API | `validate.rs` → `apply_endorsement_series_with_profile` |
| §8.3.4.4.1 | Environment matching | ✅ Full | `validate.rs` → `environment_matches` |
| §8.3.4.4.5 | Measurement matching | ✅ Attribute containment | `validate.rs` → `measurement_matches` |
| §8.3.4.4.5.3 | SVN comparison | ✅ Full | `validate.rs` → `svn_matches` |
| §8.3.4.4.5.4 | Digest comparison | ✅ Full | `validate.rs` → `digests_match` |
| §8.3.4.4.5.11–12 | Integer/float matcher comparison | ✅ Strict domain and bound validation | `types/matcher.rs` |
| §11 | IANA registries / constants | ✅ Full | `types/tags.rs` (all constants) |

#### Sections Not Implemented

| Section | Topic | Reason |
|---------|-------|--------|
| CDDL `$$*-extension` sockets | Extension points | Unknown keys are preserved in `extra_entries`; registered profiles can validate and appraise them (see `profile.rs`). |
| §4.3.1 | CMW collection transport | No collection envelope API; individual CoRIM documents remain supported. |
| §8.3 | Complete reference-verifier ACS/DMG/TDG engine | Existing matching/CES operations are not a complete graph-processing implementation. |
| §8.3.3 | Signature authentication, signer authority, remote locator retrieval | Caller-owned crypto/trust/retrieval policy. Authenticate at least the creator before accepting a multi-signature CoRIM; check fetched locator thumbprints before using content. |

#### Draft-12 migration decisions

- Generic document results use `SignedEnvelope::{Sign1, Sign}`; Sign1-specific
  APIs remain unchanged.
- COSE_Sign follows the complete-map CDDL, without inherited missing headers.
  The first signature agrees with the body's creator identity and algorithm.
- Mixed editor-draft numeric codepoint 17 is replaced by integer 17 / float 20.
  Invalid legacy forms reject instead of silently changing their signed bytes.
- `tag-version` has no protocol default. The explicitly named legacy
  `tag_version_or_default()` convenience remains available to callers, but
  parsing and comparisons retain absent-versus-zero identity.
- `FlagsMap` stores typed `Flag` labels and retained integer/text extension
  values. Known keys remain booleans; unrecognized condition paths fail closed.
  First-party profile comparators certify all required attributes, not only
  their recognized extensions. Empty CES conditions/additions are rejected.
  Multi-signature diagnostics share the strict cross-header relationship rules.

#### ⚠️ Draft Tracking Notes

This is an **Internet-Draft**, not a finalized RFC. Changes to watch for:

- **CDDL changes**: Any new keys, renamed fields, or restructured maps. Our `cddl/corim.cddl` tracks -12 with existing profile extensions. Diff against new revisions.
- **IANA registry updates**: New tag numbers, role values, or version scheme values may be added. Check `types/tags.rs` constants.
- **Appraisal algorithm changes**: §8.2 may be refined. Our `validate.rs`
  implements selected -12 semantics; full reference-verifier processing is not claimed.
- **Signed CoRIM changes**: §4.2 COSE structure may evolve. Our signed types
  implement the -12 semantics without cryptographic verification.

**How to check for updates**: Visit the [datatracker page](https://datatracker.ietf.org/doc/draft-ietf-rats-corim/) and compare the latest revision number against `-12`.

---

## Profile Specifications

CoRIM profiles are identified by URI or OID via the `corim-map.profile`
field (§4.1.4) and define additional measurement-values keys, expression
tags, validation, and appraisal semantics. Profile-aware behavior is opt-in
via Cargo features and registered with a
`corim::profile::ProfileRegistry`.

### draft-cds-rats-intel-corim-profile-07 — Intel CoRIM Profile

| | |
|-|-|
| **Status** | Internet-Draft |
| **Version implemented** | **-07** |
| **URL** | https://www.ietf.org/archive/id/draft-cds-rats-intel-corim-profile-07.html |
| **Profile OID** | `2.16.840.1.113741.1.16.1` |
| **Feature gate** | `corim/profile-intel` (opt-in) |
| **Rust module** | `corim::profile::intel` |

#### Sections Implemented

| Section | Topic | Status | Rust Item |
|---------|-------|--------|-----------|
| §4.1 | Profile identifier (OID) | ✅ Full | `intel::INTEL_PROFILE_OID_DER`, `IntelProfile::identifier` |
| §8.2.1 | Operator codes (`eq`/`gt`/`ge`/`lt`/`le`/`mem`/`nmem`) | ✅ Full | `NumericOp`, `SetOp` |
| §8.2.2 | `tagged-numeric-{eq,gt,ge,lt,le}` (`#6.60010`) | ✅ Full | `Expression::Numeric` |
| §8.2.3 | `tagged-exp-digest-{member,not-member}` (`#6.60020`) | ✅ Full | `Expression::SetOfDigests` |
| §8.2.3 | `tagged-exp-tstr-{member,not-member}` (`#6.60021`) | ✅ Full | `Expression::SetOfTstr` |
| base CoRIM | `tagged-int-range` (`#6.564`) | ✅ Full | `Expression::IntRange` |
| base CoRIM | `tagged-min-svn` (`#6.553`) | ✅ Full | `Expression::MinSvn` |
| base CoRIM | `tagged-masked-raw-value` (`#6.563`) | ✅ Full — mask-aware comparison | `Expression::MaskedRawValue` |
| §8.3 | All 16 `measurement-values-map` extension keys | ✅ Labelled + matched | `intel::MVAL_TEE_*` constants, `IntelProfile::match_measurement` |
| §8.3.4 | `tee.tcbdate` normalization across `tdate` / `time` / `etime` (RFC 9581) / `period` (RFC 9581) | ✅ Full | `profile::intel::tcbdate` |
| §9.1–9.2 | Bare-value equality, set comparison algorithm | ✅ Full | `intel::eval` |

#### Not Implemented

| Item | Reason |
|------|--------|
| Profile-typed accessors on `MeasurementValuesMap` | Out of scope; values stay in `extra_entries`. |

#### ⚠️ Draft Tracking Notes

This is an **Internet-Draft**, not a finalized RFC. When a new revision
is published, diff §8.2 (operator codes and tag dispatch), §8.3 (key
assignments), and the profile OID against the constants in
`corim/src/profile/intel/{mod,expression}.rs`. Pay special attention
to code points listed in the Removed / Renamed columns above; v07
already dropped `tee.instance-id` (-77), `tee.epoch` (-90), the
`mask-eq` operator, and the set-of-set operators.

### draft-ietf-rats-corim-11 — Arm PSA Profile (`psa-cert-num`)

| | |
|-|-|
| **Status** | Internet-Draft |
| **Profile URI** | `tag:arm.com,2025:psa#1.0.0` |
| **Feature gate** | `corim/profile-psa` (opt-in) |
| **Rust module** | `corim::profile::psa` |

The base CoRIM CDDL (draft-11 Appendix A) defines a single PSA
`measurement-values-map` extension. The full PSA endorsements profile is
specified separately in `I-D.fdb-rats-psa-endorsements` and reuses base
CoRIM features (string measured-element identifiers), adding no further
wire elements beyond `psa-cert-num`.

| Section | Topic | Status | Rust Item |
|---------|-------|--------|-----------|
| App. A | `psa-cert-num` (key 100) + `psa-cert-num-type` regexp | ✅ Full | `psa::MVAL_PSA_CERT_NUM`, `psa::is_valid_cert_num` |
| §8.2.6 | Profile identifier URI | ✅ Full | `psa::PSA_PROFILE_URI`, `PsaProfile::identifier` |
| §8.2.6 | Diagnose labelling / JSON alias / exact-match appraisal | ✅ Full | `PsaProfile::{diagnose_mval_entry, mval_json_alias, match_measurement}` |

### draft-ydb-rats-cca-endorsements-04 — Arm CCA Endorsements

| | |
|-|-|
| **Status** | Internet-Draft |
| **URL** | https://www.ietf.org/archive/id/draft-ydb-rats-cca-endorsements-04.html |
| **Platform profile URI** | `tag:arm.com,2025:endorsements/cca_platform#1.0.0` |
| **Realm profile URI** | `tag:arm.com,2025:endorsements/cca_realm#1.0.0` |
| **Feature gate** | `corim/profile-cca` (opt-in) |
| **Rust module** | `corim::profile::cca` |

| Section | Topic | Status | Rust Item |
|---------|-------|--------|-----------|
| §3.1.2 | Platform Implementation ID and Instance ID environments | ✅ Full | `CcaPlatformProfile` validation hooks |
| §3.1.3 | Platform software, configuration, ROTPK, and manufacturing reference values | ✅ Full | `CcaPlatformProfile::validate_reference_triple` |
| §3.1.4 | CPAK attestation verification key | ✅ Full | `CcaPlatformProfile::validate_attest_key_triple` |
| §3.2.2–3.2.3 | Realm environment, RIM, REMs, and RPV | ✅ Full | `CcaRealmProfile` validation and matching |
| §3.1.5 / §3.2.4 | CCA token evidence transformations | ❌ Not implemented | Callers provide normalized `EvidenceClaim` values |

---

## CBOR Encoding

### RFC 8949 — Concise Binary Object Representation (CBOR)

| | |
|-|-|
| **Status** | Standards Track (STD 94) — **Stable** |
| **URL** | https://www.rfc-editor.org/rfc/rfc8949.html |
| **Replaces** | RFC 7049 |

#### Sections Implemented

| Section | Topic | Status | Rust Module |
|---------|-------|--------|-------------|
| §3.1 | Major types 0–7 | ✅ Types 0–6 + simple values from type 7 | `cbor/minimal.rs` |
| §3.3 | Floating-point | ✅ Decode f16/f32/f64; encode always f64 | `cbor/minimal.rs` |
| §3.4.2 | Epoch-based date/time (`#6.1`) | ✅ Full | `types/common.rs` → `CborTime` |
| §3.4.5.3 | URI (`#6.32(tstr)`, as used by RFC 8610 Appendix D) | ✅ Encode tagged; decode tagged and legacy bare text | `types/uri.rs` |
| §4.2.1 | Core Deterministic Encoding | ✅ Full — shortest integer form + canonical map key ordering | `cbor/minimal.rs` → `encode_head`, `encode_value` |

#### Documented Limitations

| Feature | Status | Impact |
|---------|--------|--------|
| Indefinite-length encoding | ❌ Rejected on decode | CoRIM CDDL uses definite-length only |
| Float encode precision | Always f64 | CWT NumericDates and draft-12 float matchers retain their numeric domain |
| Simple values >23 (except false/true/null) | ❌ Rejected | Not used in CoRIM |
| CBOR sequences | ❌ Not supported | CoRIM always has single tagged wrapper |
| Maximum nesting depth | Bounded at 64 | Shared byte, collection and aggregate-value budgets also apply |

---

## CoSWID

### RFC 9393 — Concise Software Identification Tags

| | |
|-|-|
| **Status** | Standards Track — **Stable** |
| **URL** | https://www.rfc-editor.org/rfc/rfc9393.html |

#### Sections Implemented

| Section | Topic | Status | Rust Module |
|---------|-------|--------|-------------|
| §2.3 | `concise-swid-tag` map | ✅ Core subset | `types/coswid.rs` → `ConciseSwidTag` |
| §2.4 | Co-constraints (patch+supplemental, tag-creator) | ✅ Full | `types/coswid.rs` → `Validate` impl |
| §2.6 | `entity-entry` | ✅ Full | `types/coswid.rs` → `SwidEntity` |
| §2.7 | `link-entry` | ✅ Full | `types/coswid.rs` → `SwidLink` |
| §2.8 | `software-meta-entry` | ☐ Not modeled | Rarely used in CoRIM context |
| §2.9 | Resource collection (payload/evidence) | ☐ Opaque `Value` | Full filesystem model deferred |
| §4.1 | Version scheme values | ✅ Constants | `types/tags.rs` |
| §4.2 | Entity role values | ✅ Constants | `types/tags.rs` |
| §4.4 | Link rel values | ✅ Constants | `types/tags.rs` |

#### Not Implemented (out of scope for CoRIM use cases)

- `software-meta-entry` fields (§2.8) — activation-status, channel-type, etc.
- `file-entry`, `directory-entry`, `process-entry`, `resource-entry` (§2.9.2) — filesystem inventory
- `payload-entry` / `evidence-entry` (§2.9.3–4) — stored as opaque `Value`
- XML serialization — out of scope
- CBOR tag `#6.1398229316` wrapping — CoSWID inside CoRIM uses tag 505

---

## Supporting RFCs

### RFC 4648 — Base Encodings (Base64)

| | |
|-|-|
| **Status** | Standards Track — **Stable** |
| **URL** | https://www.rfc-editor.org/rfc/rfc4648.html |
| **Used in** | `json/value_conv.rs` — base64 encode/decode for bytes↔JSON string |
| **Implementation** | In-house standard alphabet (no URL-safe variant) |

### RFC 4122 — UUID Format

| | |
|-|-|
| **Status** | Standards Track — **Stable** |
| **URL** | https://www.rfc-editor.org/rfc/rfc4122.html |
| **Used in** | `types/common.rs` — `TagIdChoice::Uuid`, `ClassIdChoice::Uuid`, etc. (CBOR tag 37, 16-byte binary) |
| **Note** | RFC 9562 updates UUID with v6/v7/v8 — our code accepts any 16-byte value under tag 37 |

### RFC 9334 — RATS Architecture

| | |
|-|-|
| **Status** | Informational — **Stable** |
| **URL** | https://www.rfc-editor.org/rfc/rfc9334.html |
| **Used in** | Conceptual reference — Endorser/Verifier/Attester roles. Our `validate.rs` implements the Verifier's appraisal logic. |

### IANA Registries Referenced

| Registry | URL | Used in |
|----------|-----|---------|
| CBOR Tags | https://www.iana.org/assignments/cbor-tags | `types/tags.rs` — tags 1, 18, 37, 111, 501, 505, 506, 508, 550–564 |
| COSE Algorithms | https://www.iana.org/assignments/cose/cose.xhtml#algorithms | `types/signed.rs` → `CoseAlgorithm` enum (RFC 9864 fully-specified identifiers) |
| COSE Header Parameters | https://www.iana.org/assignments/cose/cose.xhtml#header-parameters | `types/signed.rs` → X.509 fields (RFC 9360) |
| Named Information Hash Algorithm | https://www.iana.org/assignments/named-information | `types/measurement.rs` — `Digest` algorithm IDs |
| CoSWID Items | https://www.iana.org/assignments/coswid | `types/tags.rs` — CoSWID key indices 0–57 |

---

### RFC 9864 — Fully-Specified Algorithms for JOSE and COSE

| | |
|-|-|
| **Status** | Standards Track — **Stable** (October 2025) |
| **URL** | https://www.rfc-editor.org/rfc/rfc9864.html |
| **Updates** | RFC 7518, RFC 8037, RFC 9053 |
| **Used in** | `types/signed.rs` → `CoseAlgorithm` enum |

#### Impact on this crate

RFC 9864 deprecates polymorphic COSE algorithm identifiers and defines
fully-specified replacements:

| Deprecated | Value | Replacement | Value | Status in our enum |
|-----------|-------|-------------|-------|--------------------|
| ES256 | -7 | ESP256 | -9 | Both modeled; ES256 marked deprecated |
| ES384 | -35 | ESP384 | -51 | Both modeled; ES384 marked deprecated |
| ES512 | -36 | ESP512 | -52 | Both modeled; ES512 marked deprecated |
| EdDSA | -8 | Ed25519 / Ed448 | -19 / -53 | Both modeled; EdDSA marked deprecated |

PS256/PS384/PS512 are NOT deprecated by RFC 9864 (§6.1).

The deprecated variants are retained in `CoseAlgorithm` for decode interop
with existing signed CoRIM documents. `CoseAlgorithm::is_deprecated()`
returns `true` for the old polymorphic identifiers.

---

### RFC 9360 — COSE Header Parameters for X.509 Certificates

| | |
|-|-|
| **Status** | Standards Track — **Stable** (February 2023) |
| **URL** | https://www.rfc-editor.org/rfc/rfc9360.html |
| **Used in** | `types/signed.rs` → `CoseX509`, `CoseCertHash` types |

#### Header parameters implemented

| Label | Key | CDDL Type | Status | Rust Type |
|-------|-----|-----------|--------|-----------|
| `kid` | 4 | `bstr` | ✅ | `Option<Vec<u8>>` |
| `x5bag` | 32 | `COSE_X509` | ✅ | `Option<CoseX509>` |
| `x5chain` | 33 | `COSE_X509` | ✅ | `Option<CoseX509>` |
| `x5t` | 34 | `COSE_CertHash` | ✅ | `Option<CoseCertHash>` |
| `x5u` | 35 | `uri` | ✅ | `Option<String>` |

The `CoseX509` type handles both single cert (`bstr`) and cert chain
(`[ 2*certs: bstr ]`) per the RFC 9360 CDDL. Certificates are stored
as raw DER-encoded bytes — no X.509 parsing is performed.

---

## How to Update This Document

When a new revision of `draft-ietf-rats-corim` is published:

1. **Check the datatracker**: https://datatracker.ietf.org/doc/draft-ietf-rats-corim/
2. **Diff the CDDL**: Download the new CDDL and diff against `cddl/corim.cddl`
3. **Check for new keys**: Look for new map keys in `corim-map`, `concise-mid-tag`, `triples-map`, `measurement-values-map`
4. **Check IANA registries**: New tag numbers, role values, version schemes
5. **Update this file**: Change the version number, URL, and mark any new sections
6. **Update `types/tags.rs`**: Add any new constants
7. **Update `cddl/corim.cddl`**: Replace with new snapshot
8. **Run tests**: `cargo test --features json` — look for decode failures from changed wire format
