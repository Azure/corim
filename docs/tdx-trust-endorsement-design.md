# Design: TDX Trust Endorsement — Platform TCB + Paravisor + Migration TD

Status: design, ready for implementation
Profile: Intel TDX, OID `6086480186f84d011001`

## Goal

Publish a signed trust-endorsement CoRIM for an Intel TDX platform that
carries three independently-sourced baselines:

1. The **platform TCB date** floor — an Intel-sourced microcode/firmware
   property of the hardware platform (indexed by FMSPC).
2. The **TDX paravisor** minimum SVN — a Microsoft software component whose
   SVN is *derived* by a separate paravisor mapping CoRIM.
3. The **bound migration TD** minimum SVN — a Microsoft software component
   whose SVN is *derived* by a separate migration-TD mapping CoRIM.

Each baseline has a **different source/provenance authority** and a
**different release cadence**, even though a **single publisher** (us)
signs and distributes the artifact.

## Two-stage appraisal pipeline (software SVNs are *derived*)

The paravisor and migration-TD SVNs are not raw fields in the TD report.
They are derived claims produced by a **mapping CoRIM** (the `tcb_mapping`
CESTR pattern): the report carries a measurement digest, the mapping CoRIM's
CESTR condition selects on that digest and **adds** the corresponding SVN.
This trust-endorsement CoRIM then appraises that *derived* SVN.

```text
Stage 1  evidence:        TD report → measurement digest D
Stage 2  mapping CoRIM:   CESTR [env: <component-env>]  if mval.digest == D → add mval.svn = N
Stage 3  trust CoRIM:     ref-triple [env: <component-env>]  require mval.svn >= floor
                                       ▲
                        MUST be the SAME environment as Stage 2's addition
```

The consequence: a software component's reference-triple environment **must
match the environment its mapping CoRIM emits the derived SVN into** — not
the platform FMSPC. The two artifacts share a cross-CoRIM environment
contract (see below).

## Structure: one signed CoRIM, three CoMIDs, one signature

```text
CoRIM  id = "Microsoft/TDX/trust-endorsement"   (single COSE_Sign1, Microsoft signs)
  profile: Intel OID 6086480186f84d011001

  ├─ CoMID #1  tag-id = <platform-tcb-uuid>   tag-version = T   [provenance: Intel]
  │    endorsed-triple
  │      environment: { class-id: #6.560(<fmspc>), vendor: "Intel" }
  │      endorsements:
  │        { mkey: "platform-tcb-date", mval: { -72: #6.1(<tcbdate-epoch>) } }   // tcbdate floor
  │
  ├─ CoMID #2  tag-id = <paravisor-uuid>      tag-version = P   [provenance: MS paravisor]
  │    reference-triple
  │      environment: { class: { vendor: "Intel", model: "TDX" } }
  │      measurements:
  │        { mkey: "paravisor-svn", mval: { svn: <P_min> (min) } }
  │
  └─ CoMID #3  tag-id = <mig-td-uuid>         tag-version = M   [provenance: MS migration TD]
       reference-triple
         environment:
           class:    { vendor: "Intel", model: "TDX" }   // same convention as paravisor
           instance: "migration-td"                       // component discriminator (tstr)
         measurements:
           { mkey: "migration-td-svn", mval: { svn: <M_min> (min) } }
```

Each software component's environment above **must be identical to the
environment its mapping CoRIM uses** when it adds the derived SVN.

## Design decisions and rationale

| Decision | Choice | Why |
|---|---|---|
| Platform TCB date environment | FMSPC in `class-id`, tagged `#6.560` | The tcbdate is a genuine Intel **hardware** property; FMSPC is its correct selector and the verifier already holds it from the PCK cert. Prefer the tagged form over bare bytes for self-description. |
| Paravisor / migration TD environment | **Component identity, not FMSPC** | These are **software** components. Their SVN floor is platform-independent, so they are matched by their own component environment — which must equal the environment their mapping CoRIM emits the derived SVN into. |
| Three-way split | **Three separate CoMIDs** | The three baselines differ by **environment identity, provenance authority, and release cadence** simultaneously → independent `tag-version` supersession lineages. |
| Packaging | **One CoRIM, one signature** | Single signing authority and single distribution path. The three CoMIDs version independently inside one envelope. |
| Republish model | Snapshot, not delta | Each publish re-states the full baseline for that `tag-id`; bump that CoMID's `tag-version`. Only the updated component's version moves. |

## Environment convention

The two software CoMIDs share one class convention, and migration TD adds an
instance for distinctness:

- **`class { vendor, model }` = the TEE / report type.** `{ vendor: "Intel",
  model: "TDX" }` says "this baseline is corroborated against a TDX report."
  It is *not* an authorship claim — the components are Microsoft software;
  `vendor: "Intel"` labels the TEE family, matching how the mapping CoRIMs
  target the TDX report.
- **`instance` = the component discriminator.** Paravisor uses the bare
  class (no instance); migration TD adds `instance: "migration-td"`. The
  differing instance keys keep the two environments **distinct**, so their
  derived SVNs land in separate buckets and never collide — even though both
  share `{ vendor: "Intel", model: "TDX" }`.
- **The instance value is a byte-exact foreign key** into the migration-TD
  mapping CoRIM (see cross-CoRIM contract). `"migration-td"` (tstr) is
  chosen over the legacy `"servtd-hash"`: the old name named the wrong
  component (service-TD) and leaked an encoding detail (hash). A tstr is
  preferred over a minted UUID here because this is a single-publisher,
  internal pipeline where readable diagnose/EDN output beats opaque
  global uniqueness.

## Cross-CoRIM environment contract

The paravisor and migration-TD SVNs are **derived** by separate mapping
CoRIMs (Stage 2). For appraisal to fire, each software CoMID's
reference-triple environment is effectively a **foreign key** into its
mapping CoRIM:

- CoMID #2 (paravisor) environment `{ class: { vendor: "Intel", model:
  "TDX" } }` **must equal** the environment the paravisor mapping CoRIM
  uses in its CESTR addition.
- CoMID #3 (migration TD) environment `{ class: { vendor: "Intel", model:
  "TDX" }, instance: "migration-td" }` **must equal** the environment the
  migration-TD mapping CoRIM uses in its CESTR addition.

If either mapping CoRIM's `class`/`instance` changes without the trust
CoRIM being updated in lockstep (or vice versa), the environments no longer
match and the SVN floor check **silently no-ops**. The trust CoRIM and its
two mapping CoRIMs are produced and maintained as a **synchronized set**.

## Augmentation ordering

The verifier MUST apply each mapping CoRIM's CESTR augmentation (Stage 2)
**before** this trust CoRIM's SVN appraisal (Stage 3) — otherwise the
derived SVN is not yet in the claims set when the floor is checked. Most
appraisal engines run all augmentation (CESTR / endorsed) before
corroboration; since we control the pipeline, this ordering is made
explicit rather than assumed.

## `mkey` assignment (per measurement)

Each measurement carries an explicit, self-describing `tstr` `mkey` so the
"what does this SVN refer to" attribution survives into the Accepted Claims
Set without an out-of-band legend:

| CoMID | `tag-id` | measurement `mkey` | `mval` |
|---|---|---|---|
| #1 Platform TCB | `<platform-tcb-uuid>` | `"platform-tcb-date"` | `-72: #6.1(<tcbdate-epoch>)` |
| #2 Paravisor | `<paravisor-uuid>` | `"paravisor-svn"` | `svn: <P_min> (min)` |
| #3 Migration TD | `<mig-td-uuid>` | `"migration-td-svn"` | `svn: <M_min> (min)` |

Rationale for explicit `mkey` (vs. relying on `tag-id`):

1. **`tag-id` is an opaque UUID** to a claims consumer — it identifies the
   provenance/version lineage, not the *meaning* of the SVN.
2. **`mkey` is the spec's designated "what is this measurement" key** and
   travels with the `mval` into the claims set, preserving attribution.
3. **Future-proof** against consolidating back to one CoMID: self-describing
   keys never collide.
4. **Use `tstr`** (`"paravisor-svn"`, `"migration-td-svn"`,
   `"platform-tcb-date"`) for readable diagnose/EDN output. Avoid bare small
   integers unless the profile defines their meaning (that was the
   `td_identity` anti-pattern).

Net: `tag-id` answers *whose baseline / which version lineage*; `mkey`
answers *what this number is*. Set both.

## Supersession contract

- The verifier keeps the **highest `tag-version` per `tag-id`**.
- Each baseline advances on its own lineage: a migration-TD update bumps
  **CoMID #3's `tag-version` only**; an Intel TCB-date update bumps
  **CoMID #1's** only; a paravisor release bumps **CoMID #2's** only. The
  other CoMIDs are untouched and retain their versions.
- **Never publish a partial snapshot** under an existing `tag-id` — each
  published CoMID must be the complete current baseline for that `tag-id`,
  or "latest wins" supersession silently drops the omitted measurements.

## tcbdate encoding

The `tee.tcbdate` floor (key `-72`) is encoded as `#6.1(<epoch-seconds>)`
(RFC 8949 §3.4.2 epoch time, POSIX `time_t` semantics: seconds since
1970-01-01T00:00:00Z, leap seconds excluded). The publishing pipeline
converts Intel's ISO 8601 publication date to integer epoch seconds at
build time. It lives in an **endorsed-triple** because Intel profile v07
§8.3.4 defines no comparison operator for `tee.tcbdate`; the value augments
the Accepted Claims Set and a downstream policy stage applies the freshness
floor.

## Versioning & telemetry

There are two distinct version concerns; they live in different places and
must not be conflated.

| Concern | Where it lives | Type | Consumed by |
|---|---|---|---|
| **Supersession** ("which baseline wins") | per-CoMID `tag-version` | uint | the verifier |
| **Release / distribution version** ("what did we ship") | NuGet package version, **mirrored into `corim-map.id`** | string | telemetry, support, audit |

Decisions:

1. **NuGet package version is the distribution source of truth.** It drives
   primary telemetry at build/restore/deploy time, where the package
   identity is in hand. For pipeline-stage metrics this alone is sufficient.
2. **Mirror that same version into `corim-map.id`** as a structured suffix,
   e.g. `"Microsoft/TDX/trust-endorsement/2026.06.0"`. This costs ~12 bytes,
   needs **no schema change** (it is the existing `id` string), and is not
   matched against evidence — so it has zero appraisal side effects. It
   recovers the version for any consumer holding only the CBOR bytes
   (verifier ingest, appraisal logs, cached/forwarded artifacts, raw-bytes
   bug reports) — the points where the filename has already evaporated.
3. **Set both from one pipeline variable.** A single `VERSION` feeds both the
   `.nupkg` version and the `id` suffix, so the package version and the
   on-wire identity are provably the same string and telemetry from the two
   layers joins cleanly.
4. **`tag-version` stays a plain per-component counter.** It is orthogonal,
   machine-only, and advances independently per CoMID.

Avoid: packing the release date into `tag-version` (e.g. `20260626`). It
works mechanically as a monotonic uint but re-couples the three components
to a shared bundle date — defeating the independent-supersession purpose of
the three-CoMID split. Keep the date in `id`; keep `tag-version` a counter.

## When to revisit this structure

- **Two separate CoRIMs** (instead of three CoMIDs in one): only if the
  sources need independent distribution channels or envelope-level
  revocation. Not the case today (single signer, single distribution path).
- **Merge CoMIDs**: only if two of the three baselines' provenance
  authorities unify *and* their environments and release cadences align so
  independent supersession is no longer needed. (Three is the natural
  stopping point — three authority × environment × cadence lineages; there
  is no fourth axis to split on.)

## Implementation inputs required

The implementing agent needs from the publisher:

1. Three `tag-id` UUIDs (platform TCB, paravisor, migration TD) — or mint
   fresh ones.
2. The platform **FMSPC** (6 bytes) for CoMID #1.
3. The **paravisor component environment** (`class: { vendor, model }`) —
   must match the paravisor mapping CoRIM.
4. The **migration-TD component environment**
   (`class: { vendor, model }` + `instance: "migration-td"`) — must match
   the migration-TD mapping CoRIM.
5. The two minimum SVN floors (`<P_min>`, `<M_min>`).
6. The tcbdate floor as epoch seconds (`<tcbdate-epoch>`).
