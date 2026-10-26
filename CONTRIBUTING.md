# Contributing to CoRIM

This project welcomes contributions and suggestions. Most contributions require you to agree to a
Contributor License Agreement (CLA) declaring that you have the right to, and actually do, grant us
the rights to use your contribution. For details, visit [Contributor License Agreements](https://cla.opensource.microsoft.com).

When you submit a pull request, a CLA bot will automatically determine whether you need to provide
a CLA and decorate the PR appropriately (e.g., status check, comment). Simply follow the instructions
provided by the bot. You will only need to do this once across all repos using our CLA.

This project has adopted the [Microsoft Open Source Code of Conduct](https://opensource.microsoft.com/codeofconduct/).
For more information see the [Code of Conduct FAQ](https://opensource.microsoft.com/codeofconduct/faq/) or
contact [opencode@microsoft.com](mailto:opencode@microsoft.com) with any additional questions or comments.

## How to Contribute

### Reporting Issues

Please search the [existing issues](https://github.com/Azure/corim/issues) before filing new
issues to avoid duplicates. For new issues, file your bug or feature request as a new Issue.

When filing a bug report, please include:

- A clear description of the problem
- Steps to reproduce
- Expected vs. actual behavior
- Rust version (`rustc --version`)
- OS and architecture

### Submitting Pull Requests

1. Fork the repository and create a feature branch from `main`.
2. If you've added code, add tests that cover the new functionality.
3. Ensure the test suite passes: `cargo test --all`
4. Ensure your code is formatted: `cargo fmt --all -- --check`
5. Ensure clippy passes: `cargo clippy --all -- -D warnings`
6. Update documentation if you've changed APIs.
7. Submit your pull request.

### Development Setup

```bash
# Clone and build
git clone https://github.com/Azure/corim.git
cd corim
cargo build

# Install pre-commit hook (runs fmt + clippy + rustdoc before each commit)
cp scripts/pre-commit.sh .git/hooks/pre-commit && chmod +x .git/hooks/pre-commit

# Run tests
cargo test --all

# Run lints (ALWAYS do this before commit/push — CI will reject failures)
cargo fmt --all -- --check
cargo clippy --workspace -- -D warnings
RUSTDOCFLAGS="-D warnings" cargo doc --workspace --no-deps
```

> **⚠️ Before every commit and push**, run:
> ```bash
> cargo fmt --all && \
>   cargo clippy --workspace -- -D warnings && \
>   RUSTDOCFLAGS="-D warnings" cargo doc --workspace --no-deps && \
>   cargo test --workspace
> ```
> The CI pipeline rejects any formatting diffs, clippy warnings, or
> rustdoc warnings. The pre-commit hook automates the fmt + clippy + doc
> checks.

### Coding Guidelines

- Follow standard Rust idioms and naming conventions.
- All public APIs must have doc comments.
- Every source file must include the Microsoft copyright header:
  ```rust
  // Copyright (c) Microsoft Corporation.
  // Licensed under the MIT License.
  ```
- Keep CBOR backend abstraction intact — types must not import `ciborium` directly.
- New CDDL type additions should reference the relevant section of
  [draft-ietf-rats-corim-11](https://www.ietf.org/archive/id/draft-ietf-rats-corim-11.html).

## Releasing

Releases are published to crates.io by [`.github/workflows/release.yml`](.github/workflows/release.yml)
via crates.io [Trusted Publishing](https://crates.io/docs/trusted-publishing) (OIDC).
No long-lived API token is stored in the repo.

Runbook:

1. Bump the version in `corim/Cargo.toml`, `corim-macros/Cargo.toml`,
   `corim-cli/Cargo.toml`, and the `corim-macros` workspace dependency
   pin in the root `Cargo.toml`. Update `CHANGELOG.md`.
2. Run `cargo test --workspace`, `cargo clippy --workspace --all-targets -- -D warnings`,
   and `cargo deny check` locally.
3. Open a `release-vX.Y.Z` PR; merge after review.
4. Tag the merge commit and push:
   ```bash
   git tag vX.Y.Z && git push origin vX.Y.Z
   ```
5. The `Release` workflow will queue and pause on the `crates-io`
   environment. Approve the deployment in the Actions UI to publish
   `corim-macros` first, then `corim`.

The workflow pins the public Rust/Cargo **1.99.0** release (not the rolling `stable`
alias or a vendor build) and uses `--locked` for every release gate.
Cargo 1.99.0 supports stable
[`cargo package --workspace`](https://doc.rust-lang.org/1.99.0/cargo/commands/cargo-package.html#option-cargo-package---workspace),
so both crates can be verified together before their new versions exist in the
registry. This is the release toolchain pin, not a change to the library MSRV.
The library archive's generated lockfile includes the workspace macro archive's
checksum. Publishing the macro first and waiting for that exact checksum in the
index ensures per-crate repackaging resolves the same dependency. Independently
packaging the library against an older published macro at the same version is
not an equivalent reproduction check.

After packaging, the workflow copies both verified `.crate` archives and a
`SHA256SUMS` manifest into `target/release-artifacts/`. A SHA-pinned artifact action
uploads `verified-crates-vX.Y.Z` **before authentication or publication**; upload
failure blocks publication. These artifacts remain downloadable from the workflow
run even if publishing subsequently fails, with a 90-day retention period.
Download and retain them longer if needed; check the extracted files with
`sha256sum --check SHA256SUMS`.

Publishing
checks the sparse-index checksum for each exact version: an already-published
version is skipped only when its archive checksum matches the local package.
For an absent version, native `cargo publish --locked --all-features --dry-run`
first repackages and verifies the crate without uploading. Its archive must match
the saved verified checksum before an actual upload is attempted; dry-run
failures or drift stop publication. Matching existing versions skip both dry-run
and upload. Actual publication uses the same `--locked --all-features` options,
and its repackaged archive is checked again immediately afterward. This uses
Cargo's uploader, not a custom uploader; it is not atomic against changes between
dry-run and actual publication. Any later drift still fails the release and
blocks the dependent crate. The registry checksum must independently match those
same verified bytes.
After an upload, bounded polling waits for that checksum to appear before the
dependent crate is published. Registry errors, yanked versions and checksum
mismatches fail explicitly.

If only `corim-macros` was published, rerun the workflow on the same tag after
indexing completes. Do not move the tag. If a different Cargo packaging version
produces a different archive, the rerun fails safely; compare the artifacts and
use the original packaging toolchain rather than bypassing the checksum check.
The workflow never treats a failed upload as successful. A toolchain upgrade must
be reviewed explicitly; pinning the toolchain does not guarantee identical archive
bytes across Cargo versions, changed lockfiles or changed source revisions.

Run the isolated publishing tests with
`bash scripts/tests/publish-crate-tests.sh` and the workflow packaging tests with
`bash scripts/tests/release-packaging-tests.sh`. They replace Cargo and registry
requests with local stubs; they do not contact registries, upload crates or require
credentials. To compare real packaging in separate build directories without
publishing (only read-only dependency resolution accesses the registry):

```bash
CARGO_TARGET_DIR=target/repro-a cargo +1.99.0 package --workspace --exclude corim-cli --all-features --locked
CARGO_TARGET_DIR=target/repro-b cargo +1.99.0 package --workspace --exclude corim-cli --all-features --locked
cmp target/repro-a/package/corim-macros-X.Y.Z.crate target/repro-b/package/corim-macros-X.Y.Z.crate
cmp target/repro-a/package/corim-X.Y.Z.crate target/repro-b/package/corim-X.Y.Z.crate
```

Replace `X.Y.Z` with the release version. Use the same clean source revision and
lockfile for both runs; no `--allow-dirty` or checksum bypass is part of this check.

The `corim-cli` crate is intentionally not published (`publish = false`).

Trusted Publisher configuration on crates.io (one-time per crate, set at
`https://crates.io/crates/<name>/settings`):

| Field             | Value         |
|-------------------|---------------|
| Repository owner  | `Azure`       |
| Repository name   | `corim`       |
| Workflow filename | `release.yml` |
| Environment name  | `crates-io`   |
