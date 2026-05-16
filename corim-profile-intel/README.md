# corim-profile-intel

Intel CoRIM profile plug-in for the [`corim`](../corim) crate.

Implements the [Intel Profile for Remote
Attestation](https://www.ietf.org/archive/id/draft-cds-rats-intel-corim-profile-03.html)
(`draft-cds-rats-intel-corim-profile-03`), profile OID
`2.16.840.1.113741.1.16.1`.

## What this crate does

- Provides [`IntelProfile`], a [`corim::profile::Profile`] implementation.
- Recognizes the Intel profile identifier on decoded CoRIM manifests.
- Renders Intel `measurement-values-map` extension keys (e.g.
  `tee.mrtee`, `tee.vendor`, `tee.tcb-comp-svn`) in `--diagnose`
  output, replacing the generic `extension key <N>` rendering.

## What this crate does NOT do (yet)

This is a minimum-viable profile registration. The following live in
follow-up commits:

- Typed accessors (`IntelMval`) that decode extension keys from
  `MeasurementValuesMap::extra_entries` into strongly-typed Rust fields.
- The `Expression` enum for the `#6.60010` operator-expression tag
  (`tagged-numeric-ge`, `tagged-exp-mask-eq`, etc.) defined in §8.1.
- Profile-aware appraisal matching (`Profile::match_measurement`) per
  §9 of the draft.

## Usage

```rust,no_run
use corim::diagnose;
use corim::profile::ProfileRegistry;
use corim_profile_intel::IntelProfile;

let bytes: Vec<u8> = std::fs::read("manifest.cbor").unwrap();
let mut registry = ProfileRegistry::new();
registry.register(Box::new(IntelProfile::new()));

let report = diagnose::inspect(&bytes, &registry);
print!("{}", report);
```
