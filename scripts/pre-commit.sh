#!/bin/sh
# Pre-commit hook: run formatting, clippy, and rustdoc checks before allowing commit.
# Install: cp scripts/pre-commit.sh .git/hooks/pre-commit && chmod +x .git/hooks/pre-commit

set -e

echo "=== Pre-commit: checking formatting ==="
cargo fmt --all -- --check
if [ $? -ne 0 ]; then
    echo "ERROR: cargo fmt check failed. Run 'cargo fmt --all' to fix."
    exit 1
fi

echo "=== Pre-commit: checking clippy ==="
cargo clippy --workspace -- -D warnings
if [ $? -ne 0 ]; then
    echo "ERROR: clippy check failed. Fix warnings before committing."
    exit 1
fi

echo "=== Pre-commit: checking rustdoc (mirrors CI Documentation job) ==="
RUSTDOCFLAGS="-D warnings" cargo doc --workspace --no-deps
if [ $? -ne 0 ]; then
    echo "ERROR: rustdoc check failed. Fix doc warnings before committing."
    exit 1
fi

echo "=== Pre-commit: all checks passed ==="
