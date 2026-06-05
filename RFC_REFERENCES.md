# RFC Reference Tracking

This document tracks all RFCs and Internet-Drafts referenced by the `corim` crate implementation. It serves as a compliance checklist and must be updated when:

- A referenced draft advances to a new revision or becomes an RFC
- The implementation adds support for a new specification
- An RFC errata affects our implementation

**Last reviewed**: May 18, 2026

---

## Primary Specification

### draft-ietf-rats-corim-10 — Concise Reference Integrity Manifests (CoRIM)

| | |
|-|-|
| **Status** | Internet-Draft (not yet RFC) |
| **Version implemented** | **-10** (December 2024) |
| **URL** | https://www.ietf.org/archive/id/draft-ietf-rats-corim-10.html |
| **Datatracker** | https://datatracker.ietf.org/doc/draft-ietf-rats-corim/ |
| **CDDL source** | `cddl/corim.cddl` (local copy from -10) |

#### Sections Implemented

| Section | Topic | Status | Rust Module |
|---------|-------|--------|-------------|
| §4 | `corim-map` (unsigned CoRIM) | ✅ Full | `types/corim.rs` → `CorimMap` |
| §4.1.1 | `corim-id` | ✅ Full | `types/corim.rs` → `CorimId` |
| §4.1.3 | `corim-locator-map` | ✅ Full | `types/corim.rs` → `CorimLocator` |
| §4.1.4 | `profile` (wire format) | ✅ Full | `types/corim.rs` → `ProfileChoice` |
| §4.1.4 | Profile extension framework | ✅ Full | `profile.rs` → `Profile`, `ProfileRegistry`, `MatchContext` |
| §4.1.5 | `entity-map` (CoRIM) | ✅ Full | `types/common.rs` → `EntityMap` |
| §4.2 | Signed CoRIM (`#6.18`) | ✅ Full (no crypto) | `types/signed.rs` → `CoseSign1Corim`, `SignedCorimBuilder` |
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
| §5.1.11.2 | Domain dependency triples | ✅ Full | `types/triples.rs` → `DomainDependencyTriple` |
| §5.1.12 | CoSWID triples | ✅ Full | `types/triples.rs` → `CoswidTriple` |
| §6 | `concise-tl-tag` (CoTL) | ✅ Full | `types/corim.rs` → `ConciseTlTag` |
| §6.1 | CoTL validity checks | ✅ Full | `validate.rs` → `validate_cotl` |
| §7 | Type-choice definitions | ✅ Full | `types/common.rs`, `types/measurement.rs` |
| §7.3 | `validity-map` | ✅ Full | `types/common.rs` → `ValidityMap` |
| §7.4 | UUID size constraints | ✅ Full | `types/tags.rs` → `UUID_SIZE` |
| §7.5 | UEID size constraints (7–33 bytes) | ✅ Full | `types/common.rs` → `InstanceIdChoice::Ueid` |
| §9 | Appraisal / Validation | ✅ Partial | `validate.rs` |
| §9.2 | Input validation | ✅ Full | `validate.rs` → `decode_and_validate` |
| §9.3.3 | Reference value matching | ✅ Full | `validate.rs` → `match_reference_values` |
| §9.3.3 | Profile-aware reference value matching | ✅ Full | `validate.rs` → `match_reference_values_with_profile` |
| §9.3.4.3 | CES application | ✅ Full | `validate.rs` → `apply_endorsement_series` |
| §9.3.4.3 | Profile-aware CES application | ✅ Full | `validate.rs` → `apply_endorsement_series_with_profile` |
| §9.4.2 | Environment matching | ✅ Full | `validate.rs` → `environment_matches` |
| §9.4.6 | Measurement matching | ✅ Full | `validate.rs` → `measurement_matches` |
| §9.4.6.1.2 | SVN comparison | ✅ Full | `validate.rs` → `svn_matches` |
| §9.4.6.1.3 | Digest comparison | ✅ Full | `validate.rs` → `digests_match` |
| §12 | IANA registries / constants | ✅ Full | `types/tags.rs` (all constants) |

#### Sections Not Implemented

| Section | Topic | Reason |
|---------|-------|--------|
| CDDL `$$*-extension` sockets | Extension points | Profile-agnostic core skips unknown keys for forward-compat; profile-aware appraisal interprets them via the registered profile's `match_measurement` (see `profile.rs`). |

#### ⚠️ Draft Tracking Notes

This is an **Internet-Draft**, not a finalized RFC. Changes to watch for:

- **CDDL changes**: Any new keys, renamed fields, or restructured maps. Our `cddl/corim.cddl` is a snapshot from -10. Diff against new revisions.
- **IANA registry updates**: New tag numbers, role values, or version scheme values may be added. Check `types/tags.rs` constants.
- **Appraisal algorithm changes**: §9 may be refined. Our `validate.rs` implements the -10 semantics.
- **Signed CoRIM changes**: §4.2 COSE structure may evolve. Our `types/signed.rs` implements the -10 semantics.

**How to check for updates**: Visit the [datatracker page](https://datatracker.ietf.org/doc/draft-ietf-rats-corim/) and compare the latest revision number against `-10`.

---

## Profile Specifications

CoRIM profiles are identified by URI or OID via the `corim-map.profile`
field (§4.1.4) and define additional measurement-values keys, expression
tags, and appraisal semantics. Profile-aware behavior is opt-in via
Cargo features and registered with a `corim::profile::ProfileRegistry`.

### draft-cds-rats-intel-corim-profile-03 — Intel CoRIM Profile

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
| §4.2.1 | Core Deterministic Encoding | ✅ Full — shortest integer form + canonical map key ordering | `cbor/minimal.rs` → `encode_head`, `encode_value` |

#### Documented Limitations

| Feature | Status | Impact |
|---------|--------|--------|
| Indefinite-length encoding | ❌ Rejected on decode | CoRIM CDDL uses definite-length only |
| Float encode precision | Always f64 | CoRIM rarely uses floats (only CWT claims) |
| Simple values >23 (except false/true/null) | ❌ Rejected | Not used in CoRIM |
| CBOR sequences | ❌ Not supported | CoRIM always has single tagged wrapper |
| Maximum nesting depth | Stack-limited (~100) | CoRIM is typically 5–10 levels |

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
