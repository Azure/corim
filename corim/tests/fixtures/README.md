# Test data fixtures

This directory holds binary CoRIM / COSE_Sign1 fixtures used by the crate's
integration tests. By default `data/` is ignored by git (see the top-level
`.gitignore`); only files explicitly allow-listed there are tracked.

Each tracked fixture must be documented in this file with:

- **Source** — where the bytes came from (URL, vendor doc, or generator).
- **Why it's checked in** — which test or relaxation it pins down.
- **License / redistribution** — confirmation we can ship it.
- **SHA-256** — so accidental mutation is obvious in review.

## Currently tracked fixtures

### `nvidia_cx7_tcg_wrapped.cbor`

- **Size:** 700 bytes
- **SHA-256:** `c25735f67ed5691989fe26e1edfa15714fc32f91f5841f4ef1c09b67a957a9fa`
- **Source:** Fetched from NVIDIA's public RIM (Reference Integrity
  Manifest) service, which is the canonical distribution channel
  documented in ["NVIDIA Device Attestation and CoRIM-based Reference
  Measurement Sharing v5.0"][nv-pdf]. The wire format and CDDL are also
  documented online at [docs.nvidia.com — CoRIM Structure][nv-corim].

  Exact reproduction (verified — produces the SHA-256 above):

  ```sh
  curl -s 'https://rim.attestation.nvidia.com/v1/rim/NV_NIC_FIRMWARE_CX7_28.48.1000_MCX75310AAS-NEA' \
    | jq -r '.rim' \
    | base64 -d \
    > corim/tests/fixtures/nvidia_cx7_tcg_wrapped.cbor
  ```

  The endpoint is unauthenticated. The `NV_NIC_FIRMWARE_CX7_28.48.1000_MCX75310AAS-NEA`
  identifier pins the device family (ConnectX-7), firmware version
  (28.48.1000), and SKU (`MCX75310AAS-NEA`); other identifiers are
  listed in the v5.0 spec and on the NVIDIA docs site.
- **Wire shape:** `#6.500(#6.502(#6.18(COSE_Sign1)))` with a bare
  `corim-map` payload (no `#6.501`) and `tags[]` entries that are bare
  `bstr` rather than `#6.506(bstr)`. This is the pre-PR-#337 / TCG-style
  shape; see the "Decode interop relaxations" section of the top-level
  `README.md` and `.github/copilot-instructions.md` for the full
  rationale.
- **Why it's checked in:** Real-world regression fixture for the three
  decode-only relaxations in [`corim/src/compat.rs`](../../src/compat.rs):
  `peel_tcg_wrappers`, `wrap_bare_corim_map`, and the
  `ConciseTagChoice::BareBstr` variant. Exercised by
  [`corim/tests/tcg_compat_tests.rs`](../tcg_compat_tests.rs)
  via `include_bytes!`, so the file must be present at compile time.
- **License / redistribution:** NVIDIA publishes this sample as part of
  their public attestation documentation (the v5.0 PDF and the linked
  HTML page above are open-access, no login required). Redistribution
  of the unmodified bytes for interoperability testing is consistent
  with the documented purpose of the sample.
- **How to refresh:** Re-run the `curl | jq | base64 -d` pipeline shown
  above. Update the size and SHA-256 in this README in the same commit.
  If the wire shape changes (e.g. NVIDIA migrates to draft-10), update
  or remove the corresponding tests in `tcg_compat_tests.rs`.

[nv-pdf]: https://docs.nvidia.com/networking/display/nvidia-device-attestation-and-corim-based-reference-measurement-sharing-v5-0.pdf
[nv-corim]: https://docs.nvidia.com/networking/display/dpunicattestation/corim-structure
