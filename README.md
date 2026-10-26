# corim

**Concise Reference Integrity Manifest (CoRIM)** — Rust implementation of
[draft-ietf-rats-corim-11](https://www.ietf.org/archive/id/draft-ietf-rats-corim-11.html).

This crate provides CBOR-native Rust types for the CoRIM / CoMID CDDL schema,
a builder API, validation/appraisal logic, and signed CoRIM (COSE_Sign1)
support for Remote Attestation (RATS) Endorsements and Reference Values.

## Features

- **Full CDDL coverage** — types for `corim-map`, `concise-mid-tag` (CoMID),
  `concise-tl-tag` (CoTL), all 9 triple types (reference, endorsed, identity,
  attest-key, trust dependency, domain membership, CoSWID, conditional
  endorsement, conditional endorsement series), `measurement-values-map` with
  all fields (digests, SVN, flags, raw-value, MAC/IP addresses, integrity
  registers, int-range, crypto keys, etc.).

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

- **Validation & Appraisal** — core and registered-profile validation,
  reference value matching (Phase 3), and conditional endorsement series
  application (Phase 4) per draft-11 §8.2.

- **Profile framework** — [`corim::profile`](corim/src/profile.rs) defines a
  `Profile` trait, a `ProfileRegistry`, and a `MatchContext` (epoch-aware)
  so downstream crates can plug in CoRIM profiles that introduce validation,
  matching rules, extra measurement-values-map fields, or non-core CBOR tags.
  First-party features cover Intel, Azure, Arm PSA, and Arm CCA Platform/Realm
  profiles.

- **CoSWID** — structured `ConciseSwidTag`, `SwidEntity`, `SwidLink` types
  per RFC 9393 with co-constraint validation (patch/supplemental, tag-creator
  role, patches link).

- **Optional JSON** — `json` feature gate adds `Value ↔ serde_json::Value`
  conversion preserving typed map keys, duplicate entries, tags, bytes, and
  every binary64 float bit.

- **TCG / NVIDIA decode interop** — accepts the legacy `#6.500` / `#6.502`
  outer wrappers, bare `corim-map` payloads, and TCG-style `#6.506(map)`
  CoMID nesting seen in real-world signed CoRIMs (notably NVIDIA NIC
  firmware). Builders emit draft-11 wire format; lossless JSON transcoding
  preserves existing wire forms without normalizing signed byte strings.
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

let mut values = MeasurementValuesMap::default();
values.digests = Some(vec![Digest::new(7, vec![0xAA; 48])]);
let meas = MeasurementMap {
    mkey: Some(MeasuredElement::Text("firmware".into())),
    mval: values,
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

This crate implements CoRIM per draft-ietf-rats-corim-11.

| Feature | Status |
|---------|--------|
| **CoMID** (§5) — `#6.506` | ✅ Fully modeled — types, builder, validation, appraisal |
| **CoTL** (§6) — `#6.508` | ✅ Fully modeled — `ConciseTlTag`, `CotlBuilder`, validity checks |
| **CoSWID** (RFC 9393) — `#6.505` | ✅ Structured — `ConciseSwidTag`, `SwidEntity`, `SwidLink`; payload/evidence opaque |
| **Signed CoRIM** (§4.2) — `#6.18` | ✅ Decode, validate, construct (attached + detached); no crypto dependency |
| CDDL extension sockets | ✅ Unknown keys preserved in `extra_entries`; registered profiles can validate and appraise them |
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
corim-cli validate myfile.corim

# Validate a signed CoRIM (auto-detected)
corim-cli validate signed.corim

# Partial validation: structural/profile checks only, temporal validity unchecked
corim-cli validate --skip-expiry archived.corim

# JSON output (signed CoRIMs also carry a "signed" object describing the
# COSE_Sign1 envelope and protected header)
corim-cli validate -f json myfile.corim

# Non-aborting structural and profile-semantic diagnose pass
corim-cli validate --diagnose myfile.corim

# Structural conformance check against a known-good baseline (JSON or CBOR)
corim-cli validate myfile.corim --baseline golden.json

# Generate from a readable, commented template (requires complete validation)
corim-cli generate template.json -o out.cbor

# Convert back to readable authoring JSON with decoded CoMID fields
corim-cli convert myfile.corim -o template.json

# Explicit raw interchange, including the entire signed envelope
corim-cli convert signed.cose --lossless -o signed.lossless.json

# Extract the unsigned CoRIM payload from a signed CoRIM
corim-cli extract signed.cose -o unsigned.cbor

# Extract the COSE protected header instead (raw bstr, or decoded JSON).
# Works on detached envelopes, where the header is all there is.
corim-cli extract signed.cose --header -o header.cbor
corim-cli extract signed.cose --header --json

# Sign (bring-your-own-signer): prepare a staging envelope + to-be-signed bytes,
# sign the TBS externally (HSM / openssl / ...), then inject the signature
corim-cli sign prepare unsigned.cbor --alg ES256 --signer-name "ACME Ltd." \
    --x5chain leaf.pem --out-staging staging.cose --out-tbs tbs.bin
corim-cli sign finalize staging.cose --signature sig.bin -o signed.cose
```

### VR72 Realm endorsement sample

[`corim-cli/templates/cca_realm_vr72.json`](corim-cli/templates/cca_realm_vr72.json)
contains illustrative references observed in a Vera/VR72 `VERA_CCA.bin`
sample: SHA-256 RIM
`723218af5344b4f87311ef2809703cfaf5d0dd7736bd4ec8e191abd43441f069`,
and a zero-filled 64-byte personalization value (`cca.rpv`). Optional
REM[0-3] references are omitted. These observed values are **not
independently trusted production references**.

The evidence token profile is `tag:arm.com,2024:realm#2.0.0`; the CoRIM
uses the distinct endorsement profile
`tag:arm.com,2025:endorsements/cca_realm#1.0.0`, per
[draft-ydb-rats-cca-endorsements-04 §3.2](https://www.ietf.org/archive/id/draft-ydb-rats-cca-endorsements-04.html#section-3.2).
The environment class ID contains the RIM from Realm claim 44238 as
tagged bytes (hex in the embedded CBOR byte string), not a hardware product ID or
device serial number. The class also carries user-supplied sample labels
`vendor: "NVIDIA"` and `model: "VR72"`; these are not extracted from the
Realm token. Environment matching treats these fields as constraints, so
a downstream verifier must populate matching vendor/model fields using
trusted context; the standard RIM-only Realm transformation alone will
not match this annotated environment. A
`conditional-endorsement-triples` entry expresses: **if `cca.rim` equals
the sample RIM (X), add an environment-level endorsement of exact SVN
0 (Y)**. The SVN is an illustrative assertion, not extracted from the
token, and is not included as an unconditional endorsement.

From the repository root (PowerShell), using the CLI's default features
to enable the registered CCA profile:

```powershell
cargo run -p corim-cli -- generate .\corim-cli\templates\cca_realm_vr72.json -o .\target\vr72-realm-sample.cbor
cargo run -p corim-cli -- validate .\target\vr72-realm-sample.cbor
cargo run -p corim-cli -- validate --diagnose .\target\vr72-realm-sample.cbor
```

These commands generate an unsigned CoRIM and check its structure and
registered-profile constraints; they do **not** appraise the Realm token
or execute the conditional endorsement. Signature verification, freshness,
Platform binding, and production trust are outside this sample's scope.
MEC-policy references are deliberately deferred: the token reports claim
44243 as 0 (shared), but the cited endorsement profile does not define a
CoMID mapping for that claim. The readable template retains its `$comment`
annotations; they are authoring metadata and are not encoded into CBOR.

### `validate -f json` — machine-readable report

`-f json` emits the validation summary as JSON. For a **signed** CoRIM it
also carries a `signed` object describing the COSE_Sign1 envelope and its
protected header — the same fields the text renderer shows:

```jsonc
{
  "status": "complete",
  "valid": true,
  "time_validated": true,
  "coverage": { "complete": true /* clock/profile/content details omitted */ },
  "signed": {
    "tag": 18,
    "protected": {
      "size": 5160,
      "alg": "PS384", "alg_id": -38,
      "content_type": "application/rim+cbor",
      "issuer": "ACC Endorsement Issuer",      // CWT `iss`
      "subject": "TDX-Trust-Endorsement",        // CWT `sub`
      "signer_name": "ACC Endorsement Issuer",   // corim-meta
      "has_cwt_claims": true, "has_corim_meta": true,
      "has_kid": true, "x5chain_count": 3, "has_x5t": true
    },
    "unprotected": { "entries": 1, "size": 771 },
    "payload": { "detached": false, "size": 456 },
    "signature": { "size": 384 },
    "signature_verified": false
  },
  "id": "…", "tags_count": 3, "comid_count": 3, "comids": [ … ]
}
```

`signature_verified` is always `false`: the tool does not authenticate
signatures or certificates. Default validation checks document structure,
temporal validity and registered profile constraints. A detached envelope or
hash-only document is incomplete for validation and exits `2`, as does an
invalid attached payload. Use `--diagnose`, `--edn`, or `extract --header` for
inspection. Unsigned CoRIMs have no `signed` object.

CoSWID-only and CoTL-only documents are supported, as are CoMID documents.
Library callers should use `corim::document::validate` with a
`ValidationContext`. It handles signed or unsigned documents, parser limits,
clock policy and registered profiles in one operation, and returns read-only
decoded data with explicit validation coverage:

```rust
use corim::document::{self, TimeCheck, ValidationContext};
use corim::profile::ProfileRegistry;

fn check(bytes: &[u8], now: i64) -> Result<(), corim::ValidationError> {
    let registry = ProfileRegistry::new();
    let context = ValidationContext::new(TimeCheck::At(now), &registry);
    let outcome = document::validate(bytes, &context)?;
    if !outcome.coverage().is_complete() {
        // Decide whether the reported omissions are acceptable to this caller.
        return Err(corim::ValidationError::Invalid("partial validation".into()));
    }
    Ok(())
}
```

An empty registry does not validate a declared profile. Such a document is
explicitly partial, not fully checked. Unknown tag content is also partial;
unknown extension keys alone are not. Coverage records clock/profile checks,
unexamined tag indexes and accepted document-level compatibility forms.
`with_detached_payload` supplies separately transported signed payload bytes.
Missing detached payloads and hash-only documents remain errors, not partial
successes. `document::inspect` is the separate framing/resource-only path for
transcoding; it preserves the raw tree and opaque byte strings.

Legacy validation entry points retain their published behavior, including
their CoMID prerequisite and separate profile-validation step. They do not
provide the new coverage guarantee.

`--skip-expiry` retains structural, header-consistency and profile checks but
skips comparisons against the clock. Partial validation exits `4` with
`"status": "partial"`, `"valid": null`, and `"time_validated": false`.
Unregistered profiles or unexamined tag content also exit `4`. Reports include
`coverage`; text output identifies the omitted checks. These outcomes do not
establish current validity. Failed checks report
`"valid": false`, `"time_validated": false`, and an `errors` array (exit `2`);
input I/O errors exit `1`. Empty documents and present-null validity fields are
invalid, including with `--skip-expiry`. In particular, JSON validation failures
remain JSON.

The protected state of a decoded signed envelope is read-only:
`protected()` exposes the decoded map and `protected_header_bytes()` exposes
the exact signed bytes. Use `CoseSign1Corim::from_parts` to derive a coherent
decoded header from existing bytes, or a signing builder to create a new one.
Editing a cloned header does not change an existing envelope or its signature.
The growing `MeasurementValuesMap`, `ProtectedCorimHeaderMap` and `CwtClaims`
structs are non-exhaustive. Use their constructors/builders or initialize a
measurement map with `Default::default()` and assign its public fields; external
exhaustive struct literals are not supported.

### `validate --baseline` — structural conformance check

`--baseline <FILE>` compares the CoRIM under validation against a
known-good reference and fails if they are not **structurally** the
same. The reference may be JSON, CBOR, or a signed CoRIM (auto-detected
and validated first). This is meant for generation pipelines: run it
right after `generate` to catch a dropped or mistyped field before the
CoRIM ships.

The same structural, registered-profile and optional clock checks apply to
both files, including JSON baselines. `--skip-expiry` applies to both inputs;
baseline JSON reports include `time_validated`. Invalid or incomplete baselines
exit `2` instead of yielding a conformance result. Missing or unreadable baseline
files exit `1`. Both failure categories produce JSON errors in JSON mode.

Baseline payload comparison currently supports CoMID tags only. A CoTL,
CoSWID, or other unsupported tag on either side, including in a mixed-tag
document, exits `2` instead of reporting conformance for unexamined content.
Ordinary validation without `--baseline` continues to support CoTL and CoSWID.
Malformed present JSON timestamps are rejected before template conversion;
omitted optional timestamps remain supported.

`corim::baseline::compare(&input, &baseline)` and `compare_headers()` return
`Result<ConformanceReport, ValidationError>`. Propagate errors with `?`, then
inspect `report.is_conformant()` for structural mismatches. Payload comparison
checks CoMID-only documents with default per-document decode limits; malformed
tags, unsupported tags and conversion failures return errors, not partial
reports. Clock, registered-profile, signature and certificate checks remain
separate responsibilities. The CLI performs those document checks before
comparison, excluding cryptographic verification.

CoMIDs, environments, keyed measurements, digests and key representations pair
one-to-one by typed identity. Matches with no differences under the same
comparison rules are reserved first, including nested unordered collections
and float-bit identity; remaining
same-identity entries pair in encounter order. Reordering keyed entries does
not reuse or discard duplicates. Unkeyed measurements and ordered series remain
positional. UUID IDs are identities, not array positions.

Register IDs and digest algorithms, key representations and thumbprint
algorithms, range forms and bound presence, and matcher forms and cardinality
are structural. Their leaf contents are values. Matcher sets are unordered.
Unknown measurement, header and CWT extensions use recursive CBOR shape:
map keys, value types, semantic tags and container structure are structural;
leaf contents are values. Map order is ignored; array order is significant.
Protected-header extensions preserve integer and text labels independently.
CWT `exp` and `nbf` preserve integer or fractional seconds as `NumericDate`;
baseline reporting does not truncate them. The header's `extra` map uses
`CoseLabel` keys; use `.into()` for existing integer keys. Integer timestamp
builder calls remain supported; fractional timestamps use
`NumericDate::Float(...)`. CLI JSON reports header and CWT extensions as
lossless map nodes, retaining the type of each integer or text key.
Keyed typed collections, extension maps and matcher sets use indexed queues
rather than repeated candidate scans. Comparison-consistent exact keys are
prepared before matching; reservation does not run full comparisons or build
temporary reports. Unkeyed measurements pair directly at their original indices.
Recursive key identity, duplicate multiplicity and ordered series are retained.
No profile-specific meaning is inferred for unknown extension values.
All CBOR-valued differences use the shared lossless JSON representation,
including finite and non-finite floats.

The structure/value boundary follows
[draft-ietf-rats-corim-11](https://www.ietf.org/archive/id/draft-ietf-rats-corim-11.html)
§8.2.4.4. **Structure** — which must match — is the environment, the
measurement keys, the *presence* and *type* of each measurement
attribute, the digest *algorithm(s)*, and the authorities. **Values** —
which may differ — are the measured bytes and scalars: digest values,
SVN numbers, flags, raw values, versions, and the like. Document
metadata that legitimately changes on every re-issue — `corim-id`,
`rim-validity`, `entities`, `dependent-rims`, and each CoMID's
`tag-version` / `language` / `entities` / `linked-tags` — is also
reported as a value difference.

```sh
corim-cli validate candidate.cbor --baseline golden.json
```

- Exit `0` — fully checked and structurally conformant (value-only differences
  are listed but do not fail).
- Exit `3` — a structural mismatch (missing, unexpected, or retyped
  field).
- Exit `4` — conformant, but input or baseline validation is partial. A
  structural mismatch still takes precedence and exits `3`.
- `--format json` emits the full diff as
  `{ result, conformant, baseline_format, target_format, compared, summary, structural_mismatches, value_differences }`.
  Long values (certificate chains and the like) are elided in the text
  report; the JSON report always carries them in full.

**Signed CoRIMs — protected-header comparison.** When **both** the
baseline and the target are signed, the COSE protected headers are
compared too (in addition to the payload, when present). Structural
header fields — `alg`, `content-type`, hash-envelope mode, the CWT
`iss` (signer identity), and the *presence* of `corim-meta` /
`CWT-Claims` / `kid` / `x5chain` / `x5bag` / `x5t` / `x5u` — must match;
signer name, `sub`, timestamps, certificate bytes, and other details are
reported as value differences. Signed inputs must have complete attached
payloads; detached/header-only baseline comparisons are not validation.
What was compared depends on the formats of the two files:

| baseline \ target | signed | unsigned |
| --- | --- | --- |
| **signed** | protected header + payload | payload |
| **unsigned** | payload | payload |

The output notes the detected format of each file and what was compared.

### `extract` / `sign` — signed CoRIM workflow

The tool performs **no cryptography**, so signing is a two-step,
bring-your-own-signer flow:

1. `sign prepare` wraps an unsigned CoRIM in a COSE_Sign1 protected
   header (algorithm, `CWT-Claims` signer identity, and an `x5chain`
   certificate chain from DER or PEM files, leaf-first) and writes a
   **staging** envelope (placeholder signature) plus the raw
   `Sig_structure1` **to-be-signed** bytes.
2. Sign the TBS bytes with your own key/HSM per the chosen COSE
   algorithm.
3. `sign finalize` injects that signature into the staging envelope,
   producing the final signed CoRIM.

`extract` reverses signing: it pulls the embedded unsigned CoRIM payload
back out of a signed CoRIM (attached payloads only). `validate` on a
signed CoRIM checks structure, temporal validity and registered profiles, but
the signature is **not** cryptographically verified.

### Readable JSON authoring

Readable templates remain the default document interface. They use named
fields, decoded `comids` / `coswids` / `cotls`, semantic type choices and
registered-profile aliases. Shipped [templates](corim-cli/templates/azure_manticore_auth_keyattest.json)
retain their original readable structure and comments:

```json
{
  "$comment": "Authoring metadata, not part of the encoded document.",
  "corim-id": "example",
  "comids": [{
    "tag-identity": { "id": "example-comid" },
    "triples": {
      "reference-triples": [[
        { "class": { "vendor": "Example", "model": "Device" } },
        [{ "key": "firmware", "value": {
          "//": "The expected minimum firmware SVN.",
          "svn": { "type": "min-svn", "value": 1 }
        }}]
      ]]
    }
  }]
}
```

`$comment` and `"//"` are annotation **keys** in standard JSON, not JSONC
syntax. They may appear in nested authoring objects and are stripped before
semantic decoding. Input byte/depth/node limits and duplicate-member checks
still run before annotation removal. Comment-like strings in actual lossless
CBOR data are never stripped.

Readable conversion is an authoring projection, not an arbitrary-wire codec.
It refuses data it cannot represent faithfully and recommends `--lossless`
instead of silently dropping it. Converting an attached signed document in
readable mode extracts its unsigned payload and includes an informational
`protected-header` summary; `generate` does not reuse that signature or header.
After editing a payload, sign it again using the external-signing workflow.

### Lossless interchange JSON

The library's `json` feature, CBOR-valued report fields, and explicit
`convert --lossless` output share one strict representation of the RFC 8949 §3
data model:

| CBOR value | JSON node |
| --- | --- |
| null, boolean, text | native JSON null, boolean, string |
| array | native array of encoded nodes |
| integer | `{"type":"integer","value":"-42"}` |
| float (all values) | `{"type":"float-bits","value":"8000000000000000"}` |
| byte string | `{"type":"byte-string","value":"00ff"}` |
| tag | `{"type":"tag","tag":"32","value":"https://example.com"}` |
| map | `{"type":"map","value":[[ENCODED_KEY,ENCODED_VALUE],...]}` |

Decimal integers and tag numbers are canonical strings; bytes and binary64
float bits use lowercase hexadecimal. Integer range is `[-2^64, 2^64-1]`;
tag numbers fit `u64`. Maps retain entry order, key types, and duplicate
multiplicity. Even maps whose text keys resemble codec wrappers are encoded
as map nodes. Opaque byte strings stay opaque: embedded CoMID CBOR and COSE
protected headers are **not** parsed or normalized by JSON conversion.
Report status, error, count, and other ordinary metadata remain ordinary JSON.

This codec does not interpret prose keys, semantic choices, aliases or
authoring annotations. Unknown/additional wrapper members, malformed scalars,
and duplicate JSON object members are errors. Generation and JSON baselines
select either readable or lossless input by its distinct root structure;
mixed forms are rejected, and a failed parse never falls back to another format.
`corim::json::parse_json` performs
bounded parsing with enough wrapper depth for 64-level CBOR trees; use it
instead of serde_json's default 128-level parser for document JSON.
`value_to_json` and `json_to_value` are fallible; generic
`to_json`/`to_json_pretty`/`from_json` use CBOR-mode serde.
JSON document input and string output share the named
`corim::json::DEFAULT_MAX_JSON_BYTES` limit of **16 MiB**. Hex, escaping,
wrappers, and pretty-printing can expand an otherwise valid CBOR document
beyond that limit. String serialization stops at the cap and returns an
explicit resource error, never silently truncating output. `convert` also
accounts for its trailing newline and completes bounded serialization before
writing stdout or touching an output file.

### `generate` — validate readable or lossless JSON

`generate` accepts a readable authoring template or a lossless document without
an input-mode flag. It runs the same non-cryptographic validation pipeline
before writing output. Invalid documents fail; partial coverage (including an
unregistered profile or unknown tag content) exits `4` without writing.
Lossless attached signed input retains the full envelope, signature, payload, and
exact protected-header byte string; no signature is produced or verified.
Detached envelopes cannot pass generation's attached-document validation gate.
`--profile URI` replaces an unsigned tag-501 document's profile with
`#6.32(tstr)` and is rejected for signed documents.

Readable input produces an unsigned document, with the same profile aliases
and known-byte coercions as the original authoring workflow. JSON baselines
accept both formats and apply validation exactly once. Authoring annotations
are not accepted as extra members of lossless wrappers.

### `convert` — readable by default, lossless when requested

`convert` reads one bounded, exactly framed document and emits a readable
template by default (to `-o FILE`, or stdout). Both modes enforce known embedded
framing and resource limits without authenticating signatures:

```sh
corim-cli convert myfile.corim -o template.json
corim-cli generate template.json -o roundtrip.corim

# Full-envelope interchange, without projecting an unsigned payload
corim-cli convert signed.cose --lossless -o signed.lossless.json
corim-cli generate signed.lossless.json -o roundtrip.cose
```

Detached (`nil` payload), hash envelopes and unmodeled data require
`--lossless`; readable mode cannot author a missing payload. Lossless conversion
never adds informational keys, peels wrappers or extracts the payload. It preserves the
raw data model, not original noncanonical CBOR integer widths or outer map
encoding order: re-encoding uses deterministic CBOR. Byte strings, in
particular signed protected headers and payloads, remain byte-exact.
`validate -f json` instead prints a validation summary whose CBOR-valued
fields use the same codec; `validate --edn` displays diagnostic notation.

Two worked examples show how to build fixtures directly with the builder
API (they write the CoRIM to stdout):

```sh
# minimal unsigned CoRIM fixture
cargo run -p corim-cli --example gen_sample > sample.corim

# minimal signed CoRIM fixture (COSE_Sign1 with a placeholder signature)
cargo run -p corim-cli --example gen_signed_sample > signed.corim
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
