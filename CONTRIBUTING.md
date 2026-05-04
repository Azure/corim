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

# Install pre-commit hook (runs fmt + clippy before each commit)
cp scripts/pre-commit.sh .git/hooks/pre-commit && chmod +x .git/hooks/pre-commit

# Run tests
cargo test --all

# Run lints (ALWAYS do this before commit/push — CI will reject failures)
cargo fmt --all -- --check
cargo clippy --workspace -- -D warnings
```

> **⚠️ Before every commit and push**, run:
> ```bash
> cargo fmt --all && cargo clippy --workspace -- -D warnings && cargo test --workspace
> ```
> The CI pipeline rejects any formatting diffs or clippy warnings.
> The pre-commit hook automates the fmt + clippy checks.

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
  [draft-ietf-rats-corim-10](https://www.ietf.org/archive/id/draft-ietf-rats-corim-10.html).

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

The `corim-cli` crate is intentionally not published (`publish = false`).

Trusted Publisher configuration on crates.io (one-time per crate, set at
`https://crates.io/crates/<name>/settings`):

| Field             | Value         |
|-------------------|---------------|
| Repository owner  | `Azure`       |
| Repository name   | `corim`       |
| Workflow filename | `release.yml` |
| Environment name  | `crates-io`   |

