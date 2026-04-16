# CoRIM Crate — Copilot Instructions

This document describes the code patterns and conventions used throughout the
`corim` Rust crate. Follow these rules when generating or modifying code to
ensure consistency across the codebase.

## Project overview

A Rust implementation of Concise Reference Integrity Manifest (CoRIM) per
[draft-ietf-rats-corim-10](https://www.ietf.org/archive/id/draft-ietf-rats-corim-10.html).
Three crates in a workspace: `corim` (library), `corim-macros` (proc-macro
derives), `corim-cli` (CLI tool). Zero external CBOR dependencies — uses an
in-house minimal encoder/decoder.

## Specification references

- **Primary spec**: draft-ietf-rats-corim-10 (CoRIM, CoMID, CoTL)
- **CBOR**: RFC 8949 (STD 94), deterministic encoding per §4.2.1
- **COSE**: RFC 9052 (STD 96), specifically COSE_Sign1 (§4)
- **CoSWID**: RFC 9393
- **CWT Claims**: RFC 8392 / RFC 9597
- **COSE Hash Envelope**: draft-ietf-cose-hash-envelope

Always cite the specific RFC/draft section in doc-comments and constant
definitions (e.g., `/// Per RFC 9052 §4.4`).

## Named constants — no magic numbers

Every numeric literal that corresponds to a wire-format key, tag number, or
protocol value MUST be defined as a named constant with a doc-comment citing
its source.

### CBOR tag constants (`types/tags.rs`)

All CBOR tag numbers from the CoRIM/CoMID/CoSWID registries live in
`types/tags.rs`. Use `pub const TAG_*: u64` naming. These are imported via
`use super::tags::*` throughout `types/`.

```rust
/// `tagged-unsigned-corim-map` = `#6.501(unsigned-corim-map)`.
pub const TAG_CORIM: u64 = 501;
```

### CDDL map key constants (`types/tags.rs`)

Integer keys for CBOR map fields (e.g., `&(id: 0)`) use module-level
constants in `tags.rs`, grouped by map type with comments matching the IANA
registry section.

```rust
// CoRIM Map keys (§12.3)
pub const CORIM_KEY_ID: i64 = 0;
pub const CORIM_KEY_TAGS: i64 = 1;
```

### COSE / CWT constants (`types/signed.rs`)

COSE header labels and CWT claim keys live at the top of `signed.rs`, before
any type definitions. COSE headers are `pub const COSE_HEADER_*: i64`.
CWT claim keys are `const CWT_CLAIM_*: i64` (crate-private, since they are
a different namespace from COSE headers despite overlapping numeric values).
String protocol constants use descriptive names:

```rust
pub const COSE_HEADER_ALG: i64 = 1;       // RFC 9052
const CWT_CLAIM_ISS: i64 = 1;             // RFC 8392 §4
pub const CORIM_CONTENT_TYPE: &str = "application/rim+cbor";
const SIG_STRUCTURE1_CONTEXT: &str = "Signature1";  // RFC 9052 §4.4
```

### Where NOT to use constants

Simple structural values like array lengths in match guards (e.g.,
`a.len() == 4` for the 4-element COSE_Sign1 array) are acceptable as inline
literals when the error message immediately explains the expectation.

## Integer safety — no `as` casts for narrowing

**NEVER** use `as i64`, `as u64`, `as usize`, or `as i128` for narrowing
conversions. These silently truncate.

### Required pattern

```rust
// ✅ Correct: returns an error on overflow
let key = i64::try_from(*n).map_err(|_| serde::de::Error::custom("out of range"))?;

// ❌ WRONG: silent truncation
let key = *n as i64;
```

### Widening casts

Widening casts (`i64 as i128`, `u64 as i128`) are acceptable since they
cannot lose data. Comment them when not obvious.

### Float-to-integer conversions

Always validate range before casting:

```rust
let n = *f;
if n.is_nan() || n.is_infinite() || n < (i64::MIN as f64) || n > (i64::MAX as f64) {
    return Err("out of range".into());
}
Ok(n as i64)
```

## Serde patterns for CBOR types

### Derive macros for CBOR maps

Structs that map to CDDL `{ ... }` maps use `CborSerialize`/`CborDeserialize`
derives with `#[cbor(key = N)]` attributes. Keys MUST be in ascending order.

```rust
#[derive(CborSerialize, CborDeserialize)]
pub struct CorimMap {
    #[cbor(key = 0)]
    pub id: CorimId,
    #[cbor(key = 1)]
    pub tags: Vec<ConciseTagChoice>,
    #[cbor(key = 2, optional)]
    pub dependent_rims: Option<Vec<CorimLocator>>,
}
```

### Hand-written serde for type-choice enums

Type-choice enums (CDDL `int / text / ...`) need hand-written `Serialize`
and `Deserialize` impls that go through `Value` for tag dispatch:

```rust
impl<'de> Deserialize<'de> for MyTypeChoice {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let val = Value::deserialize(d)?;
        match val {
            Value::Text(t) => Ok(Self::Text(t)),
            Value::Tag(TAG_FOO, inner) => { /* ... */ }
            _ => Err(serde::de::Error::custom("expected ...")),
        }
    }
}
```

Every `match` MUST have a catch-all `_ => Err(...)` arm. Never silently
accept unexpected input.

### Hand-written serde for CBOR maps (signed.rs pattern)

When a map has dynamic/extensible keys (e.g., COSE headers, CWT claims),
use hand-written serde with `Value::Map` iteration and named constant
matching:

```rust
for (k, v) in map {
    let key = match &k {
        Value::Integer(n) => i64::try_from(*n)
            .map_err(|_| serde::de::Error::custom("key out of range"))?,
        _ => continue,  // skip non-integer keys
    };
    match key {
        COSE_HEADER_ALG => { /* ... */ }
        COSE_HEADER_CONTENT_TYPE => { /* ... */ }
        _ => { extra.insert(key, v); }  // forward-compat
    }
}
```

Unknown keys MUST be skipped (or stored in an extras map) for forward
compatibility, never rejected.

## Error handling

### Error types

Four error enums in `error.rs`, all `#[non_exhaustive]`:
- `EncodeError` — CBOR serialization failures
- `DecodeError` — CBOR deserialization / structural failures
- `BuilderError` — builder API misuse (with `#[from] EncodeError`)
- `ValidationError` — RFC constraint violations

### When to use `String` vs typed enum variants

Use a **typed enum variant** (with structured fields) when callers are
expected to match on the specific failure condition programmatically:

```rust
// ✅ Caller can match: "was it expired or not-yet-valid?"
ValidationError::Expired
ValidationError::PayloadTooLarge { size, max }
DecodeError::UnexpectedTag { expected, found }
```

Use a **`String`-carrying variant** when the message is diagnostic-only
(not matched on), or when wrapping heterogeneous upstream error types:

```rust
// ✅ Wraps serde/io errors — caller only needs "decode failed"
DecodeError::Deserialization(String)

// ✅ Wraps 20+ Validate impls — caller only needs "validation failed"
ValidationError::Invalid(String)

// ✅ Many distinct one-off structural violations in COSE decode
DecodeError::InvalidStructure(String)
```

Do NOT add a new typed variant for every possible error message. Only
promote a `String` to a typed variant when there is a concrete caller
that needs to match on it. This follows the same pattern as
`std::io::Error::new(ErrorKind::Other, msg)`.

### `Validate` trait returns `String`

`Validate::valid()` returns `Result<(), String>` deliberately. The trait
is implemented by 20+ types, each with different constraints. A single
shared error enum would be unmaintainable; per-type error enums would
break trait-object usage. The `String` return is bridged to
`ValidationError::Invalid(String)` at the public API boundary.

### Rules

- All public functions return `Result`. No `panic!`, `unwrap()`, or
  `expect()` in non-test code unless provably safe (guarded by a prior
  length check — document with a comment).
- Serde impls use `serde::de::Error::custom(...)` / `serde::ser::Error::custom(...)`.
- Never use `unreachable!()` unless the preceding match arm already
  confirmed the variant (document with a comment).

## Type design rules

### `#[non_exhaustive]` on all public enums

Every public enum MUST have `#[non_exhaustive]` for semver safety.

### `#[must_use]` on all builder structs

Every builder struct (`ComidBuilder`, `CotlBuilder`, `CorimBuilder`,
`SignedCorimBuilder`) MUST have `#[must_use]`.

### Derive traits

All public types derive `Clone, Debug, PartialEq` at minimum. Add `Eq`
when the type contains no floats. Add `Default` where semantically
meaningful.

### Validate trait

Types with RFC-defined constraints implement `Validate`:

```rust
impl Validate for MyType {
    fn valid(&self) -> Result<(), String> {
        if self.required_field.is_none() {
            return Err("required_field must be present".into());
        }
        Ok(())
    }
}
```

## Builder pattern

Builders use a fluent API with `mut self` → `Self` for infallible setters,
and `Result<Self, BuilderError>` for fallible ones. The terminal `build()`
method validates all constraints. `build_bytes()` combines `build()` +
CBOR encoding.

For `SignedCorimBuilder`, the terminal methods are:
- `to_be_signed(&mut self, external_aad)` — emits the RFC 9052 TBS blob
- `build_with_signature(self, signature)` — attached payload mode
- `build_detached_with_signature(self, signature)` — detached (nil) payload

The builder caches the protected header bytes after the first
`to_be_signed()` call. Any setter that modifies the protected header MUST
set `self.cached_protected_bytes = None`.

## Signed CoRIM patterns (`types/signed.rs`)

### Architecture: no crypto dependency

The crate parses, validates, and constructs `#6.18(COSE_Sign1-corim)`
structures but does NOT perform cryptographic signature operations. The
caller:
1. Calls `to_be_signed()` / `to_be_signed_detached()` to get TBS bytes
2. Signs TBS externally with their crypto library
3. Calls `build_with_signature()` / `build_detached_with_signature()`

### Protected header bytes preservation

`CoseSign1Corim.protected_header_bytes` stores the exact `bstr` from the
COSE structure. This is the bytes that go into `Sig_structure1` for
verification. NEVER re-encode the protected header — always use the
original bytes.

### Attached vs detached payload

- `payload: Option<Vec<u8>>` — `Some` for attached, `None` for detached (nil)
- `to_be_signed()` — errors on detached envelopes (directs caller to use
  `to_be_signed_detached()`)
- `to_be_signed_detached(payload, aad)` — works for both modes (payload
  parameter takes precedence)
- `is_detached()` — convenience predicate

### COSE bstr-wrapped fields

`corim-meta` (key 8) is `bstr .cbor corim-meta-map` — it is CBOR-encoded
*inside* a CBOR byte string. On serialize, encode the inner map to bytes
first, then serialize as `Value::Bytes`. On deserialize, extract the byte
string, then decode the inner CBOR.

`CWT-Claims` (key 15) is directly a CBOR map (NOT bstr-wrapped). Use
`cbor::value::from_value()` to deserialize from the `Value` tree.

### Validation rules for protected header (§4.2.1)

1. `alg` (key 1) MUST be present
2. At least one of `corim-meta` (key 8) or `CWT-Claims` (key 15) MUST be
   present (the meta-group constraint)
3. Inline mode: `content-type` (key 3) MUST be present
4. Hash-envelope mode: `payload_preimage_content_type` (key 259) MUST be
   present
5. When both `corim-meta` and `CWT-Claims` are present:
   `signer-name` == `iss` (§4.2.1 consistency)

## File organization

```
corim/src/
  lib.rs              — crate root, Validate trait, doc examples
  error.rs            — 4 error enums (#[non_exhaustive])
  builder.rs          — ComidBuilder, CotlBuilder, CorimBuilder
  validate.rs         — decode_and_validate, matching, appraisal
  cbor/               — CBOR engine + serde bridge
  types/
    mod.rs            — module decls + selective re-exports
    tags.rs           — ALL RFC constants (CBOR tags, map keys, roles)
    common.rs         — type-choice enums, CborTime, EntityMap, etc.
    corim.rs          — CorimMap, ConciseTagChoice, CorimLocator, etc.
    comid.rs          — ComidTag (thin wrapper)
    environment.rs    — ClassMap, EnvironmentMap
    measurement.rs    — SvnChoice, FlagsMap, Digest, etc.
    triples.rs        — 9 triple types, TriplesMap
    coswid.rs         — ConciseSwidTag, SwidEntity, SwidLink
    signed.rs         — CoseSign1Corim, CwtClaims, SignedCorimBuilder
  json/               — optional JSON conversion (feature-gated)
```

## Testing conventions

- Tests live in `corim/tests/*.rs` (integration test files)
- Name test files by feature: `signed_corim_tests.rs`, `cddl_conformance_tests.rs`
- Every `Deserialize` error path needs a negative test
- Builder tests cover all constraint violations
- Round-trip tests: encode → decode → assert equality
- Use `cbor::encode` / `cbor::decode` directly, not through serde
- Test helpers (e.g., `build_sample_corim_bytes()`) are defined as
  `fn` at the top of each test file, not in the library

## Documentation style

- Module-level `//!` doc with CDDL excerpt in ` ```text ``` ` block
- Every public type/function has `///` doc-comment
- Struct fields get `///` doc citing the CDDL key name and index
- Use `[`backtick-links`]` for cross-references within the crate
- RFC section references use `§N.N` format (e.g., `§4.2.1`)

## Security audit checklist (for new code)

When adding new types or serde impls, verify:

1. ☐ Zero `as` narrowing casts — all use `try_from`
2. ☐ Zero `unwrap()` / `expect()` / `panic!()` in non-test code
   (unless provably safe with comment)
3. ☐ Zero `unsafe` blocks
4. ☐ Every `Deserialize` match has `_ => Err(...)` catch-all
5. ☐ All integer map keys use named constants
6. ☐ All string protocol values use named constants
7. ☐ `#[non_exhaustive]` on every public enum
8. ☐ `#[must_use]` on every builder struct
9. ☐ `Validate` impl covers all MUST/SHOULD constraints
10. ☐ Payload size checked against `MAX_PAYLOAD_SIZE` before decode
11. ☐ Forward-compatible: unknown map keys skipped, not rejected
12. ☐ Float-to-int conversions validate range (NaN, infinity, overflow)

## `no_std` support

The `corim` library crate supports `#![no_std]` with `alloc`.

### Feature gates

- `std` (default) — enables `SystemTime`-based validation, `std::error::Error` impls
- `json` — implies `std`, adds `serde_json` support
- No default features = `no_std` + `alloc` only

### `nostd_prelude` pattern

Every source file in `corim/src/` imports `use crate::nostd_prelude::*;`
which re-exports `String`, `Vec`, `Box`, `BTreeMap`, `ToString`, `ToOwned`
from `alloc`. This avoids per-file `use alloc::*` imports.

### CBOR encoder/decoder

The CBOR engine uses `&mut Vec<u8>` for encoding (not `impl Write`) and
`SliceReader` for decoding (not `impl Read`). No `std::io` dependency.

### `SystemTime` gating

`decode_and_validate()` and `decode_and_validate_full()` use
`SystemTime::now()` and are gated behind `#[cfg(feature = "std")]`.
The `_at` variants that take an explicit timestamp always work.

## Decode interop relaxations

The decoder accepts several encodings beyond strict CDDL for
interoperability with real-world producers:

### Bare (untagged) UUIDs

The CDDL defines `uuid-type = bytes .size 16` (bare) and
`tagged-uuid-type = #6.37(uuid-type)` (tagged). Some type-choices
like `$tag-id-type-choice` and `$corim-id-type-choice` accept bare
`uuid-type`. Others like `$class-id-type-choice` strictly require
`tagged-uuid-type`. Our decoder accepts bare 16-byte `bstr` as UUID
in ALL type-choices for interop, even where the CDDL says tagged-only.

This relaxation is **decode-only** — encoding always uses CBOR tag 37.

### Text digest algorithm identifiers

The CDDL says `eatmc.digest = [alg: int / text, val: bytes]`. Our
`Digest` struct stores `alg: i64`. Text algorithm IDs are accepted
on decode and stored as `alg = -1`. Full text-alg support is deferred
to a `Digest` struct redesign.

### Flat CWT claims in protected header

Real-world producers place CWT claims (keys 1/2/4/5) directly in the
protected header map instead of nesting under key 15. The decoder
type-dispatches: key 1 as `Integer` → `alg`, key 1 as `Text` → CWT
`iss`, and synthesizes a `CwtClaims` struct from flat fields.

### Non-empty with extension keys only

The CDDL `non-empty<M>` constraint means "at least one entry". Maps
with only extension keys (e.g., key 10001 for profile-specific data)
satisfy this constraint. The derive macro tracks `__had_any_entry`
to correctly handle maps where all known fields are `None` but
extension keys were present.
