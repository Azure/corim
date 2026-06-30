---
marp: true
theme: default
paginate: true
size: 16:9
title: CoRIM — Concise Reference Integrity Manifest
description: Introduction to CoRIM and the corim Rust crate
author: Ming-Wei Shih
header: "CoRIM — Concise Reference Integrity Manifest"
footer: "github.com/Azure/corim · crates.io/crates/corim"
style: |
  section { font-size: 26px; padding: 56px 64px; }
  section.lead h1 { font-size: 64px; margin-bottom: 12px; }
  section.lead h2 { font-size: 30px; color: #555; font-weight: 400; }
  section.lead p  { color: #777; font-size: 20px; }
  h2 { color: #1f4e79; border-bottom: 2px solid #1f4e79; padding-bottom: 4px; margin-top: 0; }
  code { font-size: 0.88em; }
  pre { font-size: 0.72em; line-height: 1.35; }
  table { font-size: 0.84em; }
  blockquote { border-left: 4px solid #1f4e79; color: #333; padding-left: 12px; }
---

<!-- _class: lead -->

# CoRIM

## Concise Reference Integrity Manifest in Rust

An AI-Assisted Rust implementation of `draft-ietf-rats-corim-10`

Ming-Wei Shih · Learn-it-all · 2026-06-05

[github.com/Azure/corim](https://github.com/Azure/corim) · [crates.io/crates/corim](https://crates.io/crates/corim)

---

<!-- _class: lead -->

# 1 · Why CoRIM?

---

## RATS in one slide

A **Verifier** decides whether an **Attester**'s reported state is
trustworthy (IETF RATS, [RFC 9334](https://www.rfc-editor.org/rfc/rfc9334)).
It needs three inputs:

- **Evidence** — signed claims the Attester reports about itself
  (TPM quote, TDX report, …).
- **Reference Values** — the *expected* claims for a known-good build.
  Verifier matches Evidence against these to confirm identity
  (“this really is firmware X v Y”).
- **Endorsements** — constraints from the supply chain that turn matched
  claims into a *trust decision* (“firmware X v Y is up-to-date / patched
  / authorized”).

> CoRIM is the **wire format** for Reference Values and Endorsements.

---

## What CoRIM is

**Concise Reference Integrity Manifest** — [`draft-ietf-rats-corim-10`](https://www.ietf.org/archive/id/draft-ietf-rats-corim-10.html)

- **CBOR**-encoded, deterministic (RFC 8949)
- **Signed** with **COSE_Sign1** (RFC 9052), CBOR tag `#6.18`
- Carries one or more *Concise Tags*:
  - **CoMID** — the actual measurements
  - **CoSWID** — software inventory (RFC 9393)
  - **CoTL** — trust list of CoRIM signers

> *"Firmware X v Y on platform Z has digest D, signed by key K."*

---

## The CoRIM document family

```text
┌── Signed CoRIM  (#6.18 = COSE_Sign1) ──────────────────────┐
│  protected header: alg, kid, corim-meta, CWT-Claims, …     │
│  payload (bstr .cbor):                                     │
│                                                            │
│    ┌── Unsigned CoRIM  (#6.501) ────────────────────────┐  │
│    │  id, tags[], validity?, entities?, profile?        │  │
│    │                                                    │  │
│    │   tags[] entries — each a bstr wrapping one of:    │  │
│    │     • #6.506  CoMID                                │  │
│    │     • #6.505  CoSWID                               │  │
│    │     • #6.508  CoTL                                 │  │
│    └────────────────────────────────────────────────────┘  │
│                                                            │
│  signature (bstr)                                          │
└────────────────────────────────────────────────────────────┘
```

---

<!-- _class: lead -->

# 2 · Why this crate?

---

## Motivation

**No CoRIM crate on crates.io when we started.**
[`veraison/corim-rs`](https://github.com/veraison/corim-rs) lived on GitHub
only — it didn't publish until *after* our initial release. Pulling an
unpublished git dep into Microsoft service code is a non-starter for
supply-chain review.

**Growing internal use cases — producer *and* consumer.**
TDX / SNP CVM, TDX Live Migration, TDISP — all need CoRIM for reference
values *and* endorsements, ideally on the IETF draft cadence.

**Owning the crate lets us iterate fast, meet M365 compliance, and align
with Microsoft secure-by-default Rust guidance.**

---

## What this repo ships

A **3-crate Cargo workspace** — [github.com/Azure/corim](https://github.com/Azure/corim)

| Crate | Role |
|---|---|
| [`corim`](https://crates.io/crates/corim)               | Library — types, builder, validation, signed CoRIM, CBOR engine |
| [`corim-macros`](https://crates.io/crates/corim-macros) | Proc-macro derives for integer-keyed CBOR map serde |
| `corim-cli`                                             | CLI to inspect / validate / diagnose CoRIM documents |

MSRV **Rust 1.85**, **MIT**-licensed. `corim` + `corim-macros` are on
crates.io (**v0.1.2**, 2026-06-01).

---

## Design properties → motivation

| Property | Motivation it serves |
|---|---|
| **Zero external CBOR dep** — in-house deterministic encoder | No actively-maintained CBOR crate fit; avoids transitive M365 supply-chain warnings |
| **Zero crypto dep** — emit/consume the RFC 9052 TBS blob, caller signs | Crypto stays in the org-approved production path; same M365 reason |
| **`no_std` + `alloc`** support on the library crate | Required by embedded consumers like **MigTD** (TDX Live Migration) |

---

## Built with AI — backed by RFCs, tests, and guardrails

- **Specs are the ground truth.** Types and constants generated against
  the [`cddl/`](https://github.com/Azure/corim/tree/main/cddl) schema;
  doc-comments cite the RFC § (`// RFC 9052 §4.4`).
- **75 % test coverage.** Broad unit + integration tests pin behavior,
  with the NVIDIA NIC-firmware fixture locking down a real-world wire
  format. CI gates at 70 %.
- **`copilot-instructions.md` — working principles, enforced.**
  Strategic-vs-tactical split · no magic numbers · no `as` narrowing
  casts · `#[non_exhaustive]` everywhere · no reflexive planning docs.
  Same rules every change, every contributor — *human or AI*.

---

<!-- _class: lead -->

# 3 · Inside the crate

---

## A CoMID is a bag of triples

Each triple binds an **environment** to a set of claims about it.

| Triple | Purpose |
|---|---|
| **Reference**          | Golden measurements (what Evidence should match) |
| **Endorsed**           | Claims the supply chain makes about an environment |
| **Identity**           | Cryptographic identity (instance keys, UEIDs) |
| **Attest-key**         | Keys that *sign* Evidence (TPM AK, DICE alias) |
| **Domain dep / member**| Cross-domain trust + membership |
| **CoSWID**             | Bind environments to CoSWID tags |
| **Conditional (×2)**   | Apply endorsements iff conditions hold |

All **nine** triple types fully modeled.

---

## A CoMID by example — Manticore (Azure HSM)

Real CoRIMs from Azure THIM, paraphrased:

**`Authenticity_endorsement_corim.cose` — Reference Triple**
*“Manticore firmware v3.4.2.4 has FW-register digest `0001…03ed…`. If
Evidence matches, the device is a genuine Manticore build.”*

**`Trust_endorsement_corim.cose` — Conditional Endorsement Series**
*“For the same environment: if SVN ≥ 1 and version is 3.4.2.4 …, then
this build is `UpToDate`. If SVN = 0, it's `OutOfDate`.”*

> Reference establishes **what it is**. Endorsement decides **what we trust it for**.

---

## Code layout

```text
corim/src/
  lib.rs            ── crate root, Validate trait
  builder.rs        ── ComidBuilder, CotlBuilder, CorimBuilder
  validate.rs       ── decode_and_validate, matching, appraisal
  compat.rs         ── TCG / NVIDIA decode relaxations
  diagnose.rs       ── non-aborting structural inspector
  profile.rs        ── Profile trait, registry, MatchContext
  cbor/             ── CBOR engine + serde bridge
  types/            ── tags, triples, measurement, signed, …
  profile/intel/    ── #[cfg(feature = "profile-intel")]
  json/             ── #[cfg(feature = "json")]
```

---

## Builder API — unsigned CoRIM

```rust
let env = EnvironmentMap {
    class: Some(ClassMap::new("ACME", "Widget")),
    ..Default::default()
};
let meas = MeasurementMap {
    mkey: Some(MeasuredElement::Text("firmware".into())),
    mval: MeasurementValuesMap {
        digests: Some(vec![Digest::new(7, vec![0xAA; 48])]),
        ..Default::default()
    },
    ..Default::default()
};
let comid = ComidBuilder::new(TagIdChoice::Text("my-comid".into()))
    .add_reference_triple(ReferenceTriple::new(env, vec![meas]))
    .build()?;
let bytes = CorimBuilder::new(CorimId::Text("my-corim".into()))
    .add_comid_tag(comid)?.build_bytes()?;        // #6.501 wrapped
```

---

## Signed CoRIM — without a crypto dep

The crate **parses, validates, and constructs** `#6.18` envelopes.
**Signing happens outside.**

```rust
let mut b = SignedCorimBuilder::new(-7 /* ES256 */, corim_bytes)
    .set_cwt_claims(CwtClaims::new("ACME Corp"));

let tbs       = b.to_be_signed(&[])?;          // RFC 9052 §4.4
let signature = my_signer.sign(&tbs);          // ring / openssl / HSM …
let signed    = b.build_with_signature(signature)?;
```

Supports both **attached** and **detached** (nil-payload) modes.

---

## Signed CoRIM — what we enforce

§4.2.1 protected-header rules:

- `alg` (key 1) **MUST** be present
- **At least one of** `corim-meta` (key 8) or `CWT-Claims` (key 15)
- Inline mode: `content-type` MUST be `application/rim+cbor`
- When both meta-fields present: `signer-name == iss`

Plus operational safety:

- Payload size capped **before** CBOR decode
- Protected-header `bstr` preserved verbatim — never re-encoded, so
  verification is byte-exact

---

## Profile framework

Profiles add non-core CBOR tags, profile-specific match semantics, and
extra measurement-value fields.

```rust
pub trait Profile {
    fn match_measurement(&self, evidence: &MVM, reference: &MVM,
                         ctx: &MatchContext) -> MatchOutcome;
    fn diagnose_extra_mvm_field(&self, k: i64, v: &Value) -> Option<Issue>;
}
```

- `ProfileRegistry` dispatches by `ProfileChoice` (URI or OID)
- Validate APIs are generic over `P: ?Sized + Profile`
- The `diagnose` walker consults the registered profile

---

## Intel profile (`profile-intel` feature)

[`draft-cds-rats-intel-corim-profile-07`](https://www.ietf.org/archive/id/draft-cds-rats-intel-corim-profile-07.html)

- `#6.60010` tagged expressions: `eq`, `lt`, `le`, `gt`, `ge`,
  `member`, `not-member`
- v07 tags `#6.60020` (digest sets) and `#6.60021` (text sets)
- **Mask-aware compare** for `#6.563` (`tagged-masked-raw-value`)
- **`tee.tcbdate` normalized** across 5 point-in-time encodings —
  encoder choice never breaks match

---

<!-- _class: lead -->

# 4 · Real-world inputs & tooling

---

## Interop — `corim::compat`

Real signed CoRIMs (NVIDIA NIC firmware, TCG-style producers) use the
**pre-PR-#337** wire format. We accept on **decode only**:

- Strip legacy outer `#6.500` / `#6.502` wrappers
- Synthesize `#6.501` for bare `corim-map` payloads
- Accept `#6.506(map)` and bare-bstr `tags[]` entries
- Accept `#6.32(text)` wrapped URIs, text alg IDs, flat CWT claims

**Encoders always emit strict draft-10.** `--diagnose` warns at each
path where a relaxation kicked in.

---

## `corim-cli` & `corim-web`

```sh
corim-cli --skip-expiry  myfile.corim    # validate (signed or unsigned)
corim-cli --edn          myfile.corim    # CBOR diagnostic notation
corim-cli --diagnose     myfile.corim    # non-aborting inspector
corim-cli --show-raw     signed.corim    # raw bstr dumps
```

<!-- **`corim-web`** — single-page web UI for the presentation demo:
fetches Manticore (Azure THIM) and NVIDIA RIMs live, then runs
decode / EDN / base64 / download on the bytes. -->

---

<!-- _class: lead -->

# 5 · Where it's going

---

## Driving use cases

Each item has already pulled concrete features into the crate.

**TDX Sign-Time Claims in CoRIM** — replace existing CoseSign1 envelope with
JWT payload format with signed CoRIM, aligning with industry standard.

**TDX Trust Endorsement** — define the baseline for TDX CVM and to be consumed
by MAA. Address the security gap and replace hard-coded reference values.

**MigTD Endorsement** - enable attestation for TDX with Live-Migration feature.

**TDISP local verifier in OpenHCL** — embed the decoder in OpenHCL's TDISP path.

---

## References

**Project**
- Repo — [github.com/Azure/corim](https://github.com/Azure/corim)
- Crates — [`corim`](https://crates.io/crates/corim) · [`corim-macros`](https://crates.io/crates/corim-macros)

**Specs**
- **CoRIM** — [`draft-ietf-rats-corim-10`](https://www.ietf.org/archive/id/draft-ietf-rats-corim-10.html)
- **RATS Arch** — [RFC 9334](https://www.rfc-editor.org/rfc/rfc9334)
- **CBOR** — [RFC 8949](https://www.rfc-editor.org/rfc/rfc8949)
- **COSE_Sign1** — [RFC 9052](https://www.rfc-editor.org/rfc/rfc9052)
- **CoSWID** — [RFC 9393](https://www.rfc-editor.org/rfc/rfc9393)
- **CWT Claims** — [RFC 8392](https://www.rfc-editor.org/rfc/rfc8392) / [RFC 9597](https://www.rfc-editor.org/rfc/rfc9597)
- **Intel profile** — [`draft-cds-rats-intel-corim-profile-07`](https://www.ietf.org/archive/id/draft-cds-rats-intel-corim-profile-07.html)

---

<!-- _class: lead -->

# Questions?

## Built in Rust · zero CBOR deps · zero crypto deps · `no_std`-ready

---

<!-- _class: lead -->

# Appendix

Kept for follow-up Q&A — not part of the main flow.

---

## Builder API — environment catalog

One `EnvironmentMap` is often shared across many triples. The env
catalog keeps that sharing **structural** at build time.

```rust
let mut b = ComidBuilder::new(tag);
let cpu = b.declare_env("cpu", cpu_env)?;            // EnvRef
let tpm = b.declare_env("tpm", tpm_env)?;

b.add_reference_triple_for(&cpu, ref_meas);
b.add_endorsed_triple_for(&cpu, end_meas);           // same env, by ref
b.add_conditional_endorsement_for(vec![cond_on(&tpm)], endorsements);

b.strict_links(true).build()?;                        // anchor lint
```

---

## Validation & appraisal

| Phase | API |
|---|---|
| Decode + structural validate         | `decode_and_validate` / `_full` / `_at` |
| Reference value matching (§9)        | `validate::match_reference_values` |
| Conditional endorsement series       | `validate::apply_conditional_endorsements` |
| Non-aborting diagnose                | `corim::diagnose` / CLI `--diagnose` |

`_at(timestamp)` variants accept an explicit clock — `no_std` builds
work without `SystemTime`.

---

## Security & quality posture

CI + pre-commit hook:

- `cargo fmt --check`
- `cargo clippy --all-features -D warnings`
- `RUSTDOCFLAGS="-D warnings" cargo doc --no-deps`
- `cargo test --doc -p corim --all-features`
- `cargo deny check` — zero-CBOR-deps invariant + license allowlist

Audited per change:

- Zero `as` narrowing casts — all via `try_from`
- Zero `unwrap` / `expect` / `panic` outside tests
- Zero `unsafe`; `#[non_exhaustive]` on every public enum
