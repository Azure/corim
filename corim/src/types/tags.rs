// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! RFC-defined constants for CoRIM / CoMID / CoTL.
//!
//! All numeric values in this module come directly from
//! [draft-ietf-rats-corim-11](https://www.ietf.org/archive/id/draft-ietf-rats-corim-11.html)
//! and its referenced specifications. They are organized by category to match
//! the IANA registries defined in §11 of the draft.
//!
//! Using named constants instead of inline literals makes the code easier to
//! audit against the specification and reduces the risk of transcription errors.

// ===========================================================================
// CBOR tags (§11.2 — "CBOR Tags" registry)
// ===========================================================================

/// CBOR epoch-based date/time tag (RFC 8949 §3.4.2).
///
/// Used by `validity-map` fields (`not-before`, `not-after`).
#[allow(unused_imports)]
use crate::nostd_prelude::*;
pub const TAG_EPOCH_TIME: u64 = 1;

/// `signed-corim` = `#6.18(COSE-Sign1-corim)`.
pub const TAG_SIGNED_CORIM: u64 = 18;

/// `tagged-uuid-type` = `#6.37(bytes .size 16)`.
pub const TAG_UUID: u64 = 37;

/// `tagged-oid-type` = `#6.111(bytes)`.
pub const TAG_OID: u64 = 111;

/// `tagged-unsigned-corim-map` = `#6.501(unsigned-corim-map)`.
pub const TAG_CORIM: u64 = 501;

// ---------------------------------------------------------------------------
// Legacy / TCG-compatibility tags
// ---------------------------------------------------------------------------
//
// Tags 500 and 502 were defined in early drafts of CoRIM and are still used
// by the TCG Endorsement specification (see DICE errata) and by some
// real-world producers (e.g. NVIDIA NIC firmware CoRIMs, observed 2026).
// They were dropped from the IETF draft in PR #337 (issue #333), merged
// 2025-01-22.
//
// We accept them on **decode only** by transparently peeling them in
// `crate::compat::peel_tcg_wrappers`. Encoding always uses the draft-10
// shape (tag 18 for signed, tag 501 for unsigned).

/// `#6.500(...)` — legacy outer wrapper from early CoRIM drafts and the
/// TCG Endorsement spec. Not part of draft-ietf-rats-corim-10.
pub const TAG_LEGACY_TOP: u64 = 500;

/// `#6.502(signed-corim)` — legacy wrapper around `#6.18(COSE_Sign1)` from
/// early CoRIM drafts and the TCG Endorsement spec. Not part of
/// draft-ietf-rats-corim-10.
pub const TAG_LEGACY_SIGNED: u64 = 502;

/// `tagged-concise-swid-tag` = `#6.505(bytes .cbor concise-swid-tag)`.
pub const TAG_COSWID: u64 = 505;

/// `tagged-concise-mid-tag` = `#6.506(bytes .cbor concise-mid-tag)`.
pub const TAG_COMID: u64 = 506;

/// `tagged-concise-tl-tag` = `#6.508(bytes .cbor concise-tl-tag)`.
pub const TAG_COTL: u64 = 508;

/// `tagged-ueid-type` = `#6.550(bytes .size (7..33))`.
pub const TAG_UEID: u64 = 550;

/// `tagged-svn` = `#6.552(uint)` — exact SVN.
pub const TAG_SVN: u64 = 552;

/// `tagged-min-svn` = `#6.553(uint)` — minimum SVN.
pub const TAG_MIN_SVN: u64 = 553;

/// `tagged-pkix-base64-key-type` = `#6.554(tstr)`.
pub const TAG_PKIX_BASE64_KEY: u64 = 554;

/// `tagged-pkix-base64-cert-type` = `#6.555(tstr)`.
pub const TAG_PKIX_BASE64_CERT: u64 = 555;

/// `tagged-pkix-base64-cert-path-type` = `#6.556(tstr)`.
pub const TAG_PKIX_BASE64_CERT_PATH: u64 = 556;

/// `tagged-key-thumbprint-type` = `#6.557(eatmc.digest)`.
pub const TAG_KEY_THUMBPRINT: u64 = 557;

/// `tagged-cose-key-type` = `#6.558(COSE_Key)`.
pub const TAG_COSE_KEY: u64 = 558;

/// `tagged-cert-thumbprint-type` = `#6.559(eatmc.digest)`.
pub const TAG_CERT_THUMBPRINT: u64 = 559;

/// `tagged-bytes` = `#6.560(bytes)`.
pub const TAG_BYTES: u64 = 560;

/// `tagged-cert-path-thumbprint-type` = `#6.561(eatmc.digest)`.
pub const TAG_CERT_PATH_THUMBPRINT: u64 = 561;

/// `tagged-pkix-asn1der-cert-type` = `#6.562(bstr)`.
pub const TAG_PKIX_ASN1DER_CERT: u64 = 562;

/// `tagged-masked-raw-value` = `#6.563([value, mask])`.
pub const TAG_MASKED_RAW_VALUE: u64 = 563;

/// `tagged-int-range` = `#6.564(int-range)`.
pub const TAG_INT_RANGE: u64 = 564;

// ===========================================================================
// CoRIM Map keys (§11.3 — "CoRIM Map" registry)
// ===========================================================================

/// `corim-map` key: `id` (index 0).
pub const CORIM_KEY_ID: i64 = 0;
/// `corim-map` key: `tags` (index 1).
pub const CORIM_KEY_TAGS: i64 = 1;
/// `corim-map` key: `dependent-rims` (index 2).
pub const CORIM_KEY_DEPENDENT_RIMS: i64 = 2;
/// `corim-map` key: `profile` (index 3).
pub const CORIM_KEY_PROFILE: i64 = 3;
/// `corim-map` key: `rim-validity` (index 4).
pub const CORIM_KEY_RIM_VALIDITY: i64 = 4;
/// `corim-map` key: `entities` (index 5).
pub const CORIM_KEY_ENTITIES: i64 = 5;

// ===========================================================================
// CoRIM Entity / Signer Map keys (§11.4, §11.5)
// ===========================================================================

/// `entity-map` key: `entity-name` (index 0).
pub const ENTITY_KEY_NAME: i64 = 0;
/// `entity-map` key: `reg-id` (index 1).
pub const ENTITY_KEY_REG_ID: i64 = 1;
/// `entity-map` key: `role` (index 2).
pub const ENTITY_KEY_ROLE: i64 = 2;

/// `corim-signer-map` key: `signer-name` (index 0).
pub const SIGNER_KEY_NAME: i64 = 0;
/// `corim-signer-map` key: `signer-uri` (index 1).
pub const SIGNER_KEY_URI: i64 = 1;

/// `corim-meta-map` key: `signer` (index 0).
pub const META_KEY_SIGNER: i64 = 0;
/// `corim-meta-map` key: `signature-validity` (index 1).
pub const META_KEY_SIGNATURE_VALIDITY: i64 = 1;

// ===========================================================================
// CoRIM role values (§11.4)
// ===========================================================================

/// `$corim-role-type-choice`: `manifest-creator` (1).
pub const CORIM_ROLE_MANIFEST_CREATOR: i64 = 1;
/// `$corim-role-type-choice`: `manifest-signer` (2).
pub const CORIM_ROLE_MANIFEST_SIGNER: i64 = 2;

// ===========================================================================
// CoMID Map keys (§11.6 — "CoMID Map" registry)
// ===========================================================================

/// `concise-mid-tag` key: `language` (index 0).
pub const COMID_KEY_LANGUAGE: i64 = 0;
/// `concise-mid-tag` key: `tag-identity` (index 1).
pub const COMID_KEY_TAG_IDENTITY: i64 = 1;
/// `concise-mid-tag` key: `entities` (index 2).
pub const COMID_KEY_ENTITIES: i64 = 2;
/// `concise-mid-tag` key: `linked-tags` (index 3).
pub const COMID_KEY_LINKED_TAGS: i64 = 3;
/// `concise-mid-tag` key: `triples` (index 4).
pub const COMID_KEY_TRIPLES: i64 = 4;

// ===========================================================================
// CoMID role values (§11.7)
// ===========================================================================

/// `$comid-role-type-choice`: `tag-creator` (0).
pub const COMID_ROLE_TAG_CREATOR: i64 = 0;
/// `$comid-role-type-choice`: `creator` (1).
pub const COMID_ROLE_CREATOR: i64 = 1;
/// `$comid-role-type-choice`: `maintainer` (2).
pub const COMID_ROLE_MAINTAINER: i64 = 2;

// ===========================================================================
// Tag Identity Map keys (§5.1.1)
// ===========================================================================

/// `tag-identity-map` key: `tag-id` (index 0).
pub const TAG_IDENTITY_KEY_TAG_ID: i64 = 0;
/// `tag-identity-map` key: `tag-version` (index 1).
pub const TAG_IDENTITY_KEY_TAG_VERSION: i64 = 1;

// ===========================================================================
// Tag relation values (§5.1.3)
// ===========================================================================

/// `$tag-rel-type-choice`: `supplements` (0).
pub const TAG_REL_SUPPLEMENTS: i64 = 0;
/// `$tag-rel-type-choice`: `replaces` (1).
pub const TAG_REL_REPLACES: i64 = 1;

// ===========================================================================
// Linked Tag Map keys (§5.1.3)
// ===========================================================================

/// `linked-tag-map` key: `linked-tag-id` (index 0).
pub const LINKED_TAG_KEY_ID: i64 = 0;
/// `linked-tag-map` key: `tag-rel` (index 1).
pub const LINKED_TAG_KEY_REL: i64 = 1;

// ===========================================================================
// Validity Map keys (§7.3)
// ===========================================================================

/// `validity-map` key: `not-before` (index 0).
pub const VALIDITY_KEY_NOT_BEFORE: i64 = 0;
/// `validity-map` key: `not-after` (index 1).
pub const VALIDITY_KEY_NOT_AFTER: i64 = 1;

// ===========================================================================
// Class Map keys (§5.1.4.2)
// ===========================================================================

/// `class-map` key: `class-id` (index 0).
pub const CLASS_KEY_CLASS_ID: i64 = 0;
/// `class-map` key: `vendor` (index 1).
pub const CLASS_KEY_VENDOR: i64 = 1;
/// `class-map` key: `model` (index 2).
pub const CLASS_KEY_MODEL: i64 = 2;
/// `class-map` key: `layer` (index 3).
pub const CLASS_KEY_LAYER: i64 = 3;
/// `class-map` key: `index` (index 4).
pub const CLASS_KEY_INDEX: i64 = 4;

// ===========================================================================
// Environment Map keys (§5.1.4.1)
// ===========================================================================

/// `environment-map` key: `class` (index 0).
pub const ENV_KEY_CLASS: i64 = 0;
/// `environment-map` key: `instance` (index 1).
pub const ENV_KEY_INSTANCE: i64 = 1;
/// `environment-map` key: `group` (index 2).
pub const ENV_KEY_GROUP: i64 = 2;

// ===========================================================================
// Measurement Map keys (§5.1.4.5)
// ===========================================================================

/// `measurement-map` key: `mkey` (index 0).
pub const MEAS_KEY_MKEY: i64 = 0;
/// `measurement-map` key: `mval` (index 1).
pub const MEAS_KEY_MVAL: i64 = 1;
/// `measurement-map` key: `authorized-by` (index 2).
pub const MEAS_KEY_AUTHORIZED_BY: i64 = 2;

// ===========================================================================
// Measurement Values Map keys (§11.9 — "CoMID Measurement Values Map")
// ===========================================================================

/// `measurement-values-map` key: `version` (index 0).
pub const MVAL_KEY_VERSION: i64 = 0;
/// `measurement-values-map` key: `svn` (index 1).
pub const MVAL_KEY_SVN: i64 = 1;
/// `measurement-values-map` key: `digests` (index 2).
pub const MVAL_KEY_DIGESTS: i64 = 2;
/// `measurement-values-map` key: `flags` (index 3).
pub const MVAL_KEY_FLAGS: i64 = 3;
/// `measurement-values-map` key: `raw-value` (index 4).
pub const MVAL_KEY_RAW_VALUE: i64 = 4;
/// `measurement-values-map` key: `raw-value-mask-DEPRECATED` (index 5).
pub const MVAL_KEY_RAW_VALUE_MASK_DEPRECATED: i64 = 5;
/// `measurement-values-map` key: `mac-addr` (index 6).
pub const MVAL_KEY_MAC_ADDR: i64 = 6;
/// `measurement-values-map` key: `ip-addr` (index 7).
pub const MVAL_KEY_IP_ADDR: i64 = 7;
/// `measurement-values-map` key: `serial-number` (index 8).
pub const MVAL_KEY_SERIAL_NUMBER: i64 = 8;
/// `measurement-values-map` key: `ueid` (index 9).
pub const MVAL_KEY_UEID: i64 = 9;
/// `measurement-values-map` key: `uuid` (index 10).
pub const MVAL_KEY_UUID: i64 = 10;
/// `measurement-values-map` key: `name` (index 11).
pub const MVAL_KEY_NAME: i64 = 11;
/// `measurement-values-map` key: `cryptokeys` (index 13).
pub const MVAL_KEY_CRYPTOKEYS: i64 = 13;
/// `measurement-values-map` key: `integrity-registers` (index 14).
pub const MVAL_KEY_INTEGRITY_REGISTERS: i64 = 14;
/// `measurement-values-map` key: `int-range` (index 15).
pub const MVAL_KEY_INT_RANGE: i64 = 15;

// ===========================================================================
// Flags Map keys (§11.10 — "CoMID Flags Map" registry)
// ===========================================================================

/// `flags-map` key: `is-configured` (index 0).
pub const FLAG_KEY_IS_CONFIGURED: i64 = 0;
/// `flags-map` key: `is-secure` (index 1).
pub const FLAG_KEY_IS_SECURE: i64 = 1;
/// `flags-map` key: `is-recovery` (index 2).
pub const FLAG_KEY_IS_RECOVERY: i64 = 2;
/// `flags-map` key: `is-debug` (index 3).
pub const FLAG_KEY_IS_DEBUG: i64 = 3;
/// `flags-map` key: `is-replay-protected` (index 4).
pub const FLAG_KEY_IS_REPLAY_PROTECTED: i64 = 4;
/// `flags-map` key: `is-integrity-protected` (index 5).
pub const FLAG_KEY_IS_INTEGRITY_PROTECTED: i64 = 5;
/// `flags-map` key: `is-runtime-meas` (index 6).
pub const FLAG_KEY_IS_RUNTIME_MEAS: i64 = 6;
/// `flags-map` key: `is-immutable` (index 7).
pub const FLAG_KEY_IS_IMMUTABLE: i64 = 7;
/// `flags-map` key: `is-tcb` (index 8).
pub const FLAG_KEY_IS_TCB: i64 = 8;
/// `flags-map` key: `is-confidentiality-protected` (index 9).
pub const FLAG_KEY_IS_CONFIDENTIALITY_PROTECTED: i64 = 9;
/// `flags-map` key: `is-runtime-updatable` (index 10).
pub const FLAG_KEY_IS_RUNTIME_UPDATABLE: i64 = 10;

// ===========================================================================
// Triples Map keys (§11.8 — "CoMID Triples Map" registry)
// ===========================================================================

/// `triples-map` key: `reference-triples` (index 0).
pub const TRIPLES_KEY_REFERENCE: i64 = 0;
/// `triples-map` key: `endorsed-triples` (index 1).
pub const TRIPLES_KEY_ENDORSED: i64 = 1;
/// `triples-map` key: `identity-triples` (index 2).
pub const TRIPLES_KEY_IDENTITY: i64 = 2;
/// `triples-map` key: `attest-key-triples` (index 3).
pub const TRIPLES_KEY_ATTEST_KEY: i64 = 3;
/// `triples-map` key: `dependency-triples` (index 4).
pub const TRIPLES_KEY_DEPENDENCY: i64 = 4;
/// `triples-map` key: `membership-triples` (index 5).
pub const TRIPLES_KEY_MEMBERSHIP: i64 = 5;
/// `triples-map` key: `coswid-triples` (index 6).
pub const TRIPLES_KEY_COSWID: i64 = 6;
/// `triples-map` key: `conditional-endorsement-series-triples` (index 8).
pub const TRIPLES_KEY_COND_ENDORSEMENT_SERIES: i64 = 8;
/// `triples-map` key: `conditional-endorsement-triples` (index 10).
pub const TRIPLES_KEY_COND_ENDORSEMENT: i64 = 10;

// ===========================================================================
// Version Map keys (§5.1.4.5.3)
// ===========================================================================

/// `version-map` key: `version` (index 0).
pub const VERSION_KEY_VERSION: i64 = 0;
/// `version-map` key: `version-scheme` (index 1).
pub const VERSION_KEY_SCHEME: i64 = 1;

// ===========================================================================
// Version Scheme values (CoSWID §4.1, imported by CoRIM)
// ===========================================================================

/// `$version-scheme`: `multipartnumeric` (1).
pub const VERSION_SCHEME_MULTIPARTNUMERIC: i64 = 1;
/// `$version-scheme`: `multipartnumeric-suffix` (2).
pub const VERSION_SCHEME_MULTIPARTNUMERIC_SUFFIX: i64 = 2;
/// `$version-scheme`: `alphanumeric` (3).
pub const VERSION_SCHEME_ALPHANUMERIC: i64 = 3;
/// `$version-scheme`: `decimal` (4).
pub const VERSION_SCHEME_DECIMAL: i64 = 4;
/// `$version-scheme`: `semver` (16384).
pub const VERSION_SCHEME_SEMVER: i64 = 16384;

// ===========================================================================
// CoTL Map keys (§11.11)
// ===========================================================================

/// `concise-tl-tag` key: `tag-identity` (index 0).
pub const COTL_KEY_TAG_IDENTITY: i64 = 0;
/// `concise-tl-tag` key: `tags-list` (index 1).
pub const COTL_KEY_TAGS_LIST: i64 = 1;
/// `concise-tl-tag` key: `tl-validity` (index 2).
pub const COTL_KEY_VALIDITY: i64 = 2;

// ===========================================================================
// CoRIM Locator Map keys (§4.1.3)
// ===========================================================================

/// `corim-locator-map` key: `href` (index 0).
pub const LOCATOR_KEY_HREF: i64 = 0;
/// `corim-locator-map` key: `thumbprint` (index 1).
pub const LOCATOR_KEY_THUMBPRINT: i64 = 1;

// ===========================================================================
// Protected CoRIM Header keys (§4.2.1)
// ===========================================================================

/// COSE header: `alg` (index 1).
pub const COSE_HDR_ALG: i64 = 1;
/// COSE header: `content-type` (index 3).
pub const COSE_HDR_CONTENT_TYPE: i64 = 3;
/// CoRIM protected header: `corim-meta` (index 8).
pub const CORIM_HDR_META: i64 = 8;
/// CoRIM protected header: `CWT-Claims` (index 15).
pub const CORIM_HDR_CWT_CLAIMS: i64 = 15;
/// Hash envelope: `payload_hash_alg` (index 258).
pub const CORIM_HDR_PAYLOAD_HASH_ALG: i64 = 258;
/// Hash envelope: `payload_preimage_content_type` (index 259).
pub const CORIM_HDR_PAYLOAD_PREIMAGE_CONTENT_TYPE: i64 = 259;
/// Hash envelope: `payload_location` (index 260).
pub const CORIM_HDR_PAYLOAD_LOCATION: i64 = 260;

// ===========================================================================
// Byte size constraints (§7)
// ===========================================================================

/// UUID byte length: 16 bytes (§7.4).
pub const UUID_SIZE: usize = 16;
/// UEID minimum byte length: 7 bytes (§7.5).
pub const UEID_MIN_SIZE: usize = 7;
/// UEID maximum byte length: 33 bytes (§7.5).
pub const UEID_MAX_SIZE: usize = 33;
/// EUI-48 MAC address byte length: 6 bytes.
pub const EUI48_SIZE: usize = 6;
/// EUI-64 MAC address byte length: 8 bytes.
pub const EUI64_SIZE: usize = 8;
/// IPv4 address byte length: 4 bytes.
pub const IPV4_SIZE: usize = 4;
/// IPv6 address byte length: 16 bytes.
pub const IPV6_SIZE: usize = 16;

// ===========================================================================
// Identity / Attest-Key triple condition keys (§5.1.9, §5.1.10)
// ===========================================================================

/// `conditions` map key: `mkey` (index 0).
pub const KEY_TRIPLE_COND_MKEY: i64 = 0;
/// `conditions` map key: `authorized-by` (index 1).
pub const KEY_TRIPLE_COND_AUTHORIZED_BY: i64 = 1;

// ===========================================================================
// Media type string (§11.12)
// ===========================================================================

/// CoRIM CBOR media type: `application/rim+cbor`.
pub const MEDIA_TYPE_RIM_CBOR: &str = "application/rim+cbor";
/// CoRIM COSE media type: `application/rim+cose`.
pub const MEDIA_TYPE_RIM_COSE: &str = "application/rim+cose";

// ===========================================================================
// CoSWID constants (RFC 9393)
// ===========================================================================

/// CoSWID CBOR tag: `#6.1398229316` (0x53574944 = "SWID").
pub const TAG_COSWID_CBOR: u64 = 1398229316;

// --- concise-swid-tag map keys (RFC 9393 §2.3) ---

/// `tag-id` (index 0).
pub const SWID_KEY_TAG_ID: i64 = 0;
/// `software-name` (index 1).
pub const SWID_KEY_SOFTWARE_NAME: i64 = 1;
/// `entity` (index 2).
pub const SWID_KEY_ENTITY: i64 = 2;
/// `evidence` (index 3).
pub const SWID_KEY_EVIDENCE: i64 = 3;
/// `link` (index 4).
pub const SWID_KEY_LINK: i64 = 4;
/// `software-meta` (index 5).
pub const SWID_KEY_SOFTWARE_META: i64 = 5;
/// `payload` (index 6).
pub const SWID_KEY_PAYLOAD: i64 = 6;
/// `corpus` (index 8).
pub const SWID_KEY_CORPUS: i64 = 8;
/// `patch` (index 9).
pub const SWID_KEY_PATCH: i64 = 9;
/// `media` (index 10).
pub const SWID_KEY_MEDIA: i64 = 10;
/// `supplemental` (index 11).
pub const SWID_KEY_SUPPLEMENTAL: i64 = 11;
/// `tag-version` (index 12).
pub const SWID_KEY_TAG_VERSION: i64 = 12;
/// `software-version` (index 13).
pub const SWID_KEY_SOFTWARE_VERSION: i64 = 13;
/// `version-scheme` (index 14).
pub const SWID_KEY_VERSION_SCHEME: i64 = 14;
/// `lang` (index 15).
pub const SWID_KEY_LANG: i64 = 15;

// --- entity-entry map keys (RFC 9393 §2.6) ---

/// `entity-name` (index 31).
pub const SWID_KEY_ENTITY_NAME: i64 = 31;
/// `reg-id` (index 32).
pub const SWID_KEY_REG_ID: i64 = 32;
/// `role` (index 33).
pub const SWID_KEY_ROLE: i64 = 33;
/// `thumbprint` (index 34).
pub const SWID_KEY_THUMBPRINT: i64 = 34;

// --- link-entry map keys (RFC 9393 §2.7) ---

/// `artifact` (index 37).
pub const SWID_KEY_ARTIFACT: i64 = 37;
/// `href` (index 38).
pub const SWID_KEY_HREF: i64 = 38;
/// `ownership` (index 39).
pub const SWID_KEY_OWNERSHIP: i64 = 39;
/// `rel` (index 40).
pub const SWID_KEY_REL: i64 = 40;
/// `media-type` (index 41).
pub const SWID_KEY_MEDIA_TYPE: i64 = 41;
/// `use` (index 42).
pub const SWID_KEY_USE: i64 = 42;

// --- CoSWID entity role values (RFC 9393 §4.2) ---

/// `tagCreator` (1).
pub const SWID_ROLE_TAG_CREATOR: i64 = 1;
/// `softwareCreator` (2).
pub const SWID_ROLE_SOFTWARE_CREATOR: i64 = 2;
/// `aggregator` (3).
pub const SWID_ROLE_AGGREGATOR: i64 = 3;
/// `distributor` (4).
pub const SWID_ROLE_DISTRIBUTOR: i64 = 4;
/// `licensor` (5).
pub const SWID_ROLE_LICENSOR: i64 = 5;
/// `maintainer` (6).
pub const SWID_ROLE_MAINTAINER: i64 = 6;

// --- CoSWID link rel values (RFC 9393 §4.4) ---

/// `ancestor` (1).
pub const SWID_REL_ANCESTOR: i64 = 1;
/// `component` (2).
pub const SWID_REL_COMPONENT: i64 = 2;
/// `feature` (3).
pub const SWID_REL_FEATURE: i64 = 3;
/// `installationmedia` (4).
pub const SWID_REL_INSTALLATIONMEDIA: i64 = 4;
/// `packageinstaller` (5).
pub const SWID_REL_PACKAGEINSTALLER: i64 = 5;
/// `parent` (6).
pub const SWID_REL_PARENT: i64 = 6;
/// `patches` (7).
pub const SWID_REL_PATCHES: i64 = 7;
/// `requires` (8).
pub const SWID_REL_REQUIRES: i64 = 8;
/// `see-also` (9).
pub const SWID_REL_SEE_ALSO: i64 = 9;
/// `supersedes` (10).
pub const SWID_REL_SUPERSEDES: i64 = 10;
/// `supplemental` (11).
pub const SWID_REL_SUPPLEMENTAL: i64 = 11;

/// CoSWID media type: `application/swid+cbor`.
pub const MEDIA_TYPE_SWID_CBOR: &str = "application/swid+cbor";
