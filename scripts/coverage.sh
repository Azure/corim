#!/bin/bash
# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
#
# Code coverage helper script for the corim workspace.
#
# Usage:
#   ./scripts/coverage.sh          # Text summary (default)
#   ./scripts/coverage.sh html     # HTML report → target/llvm-cov/html/
#   ./scripts/coverage.sh lcov     # LCOV file → lcov.info
#   ./scripts/coverage.sh check    # CI-mode: fail if < 70% line coverage
#
# Requires: cargo-llvm-cov + llvm-tools-preview
#   rustup component add llvm-tools-preview
#   cargo install cargo-llvm-cov

set -e

THRESHOLD=70
EXCLUDE='(corim-cli/|corim-macros/|src/lib\.rs$)'
FEATURES="json"

case "${1:-text}" in
  text)
    echo "=== Code Coverage (text summary) ==="
    cargo llvm-cov --workspace --features "$FEATURES" \
      --ignore-filename-regex "$EXCLUDE"
    ;;
  html)
    echo "=== Code Coverage (HTML report) ==="
    cargo llvm-cov --workspace --features "$FEATURES" \
      --ignore-filename-regex "$EXCLUDE" \
      --html
    echo "Report: target/llvm-cov/html/index.html"
    ;;
  lcov)
    echo "=== Code Coverage (LCOV export) ==="
    cargo llvm-cov --workspace --features "$FEATURES" \
      --ignore-filename-regex "$EXCLUDE" \
      --lcov --output-path lcov.info
    echo "LCOV: lcov.info"
    ;;
  check)
    echo "=== Code Coverage Gate (threshold: ${THRESHOLD}%) ==="
    cargo llvm-cov --workspace --features "$FEATURES" \
      --ignore-filename-regex "$EXCLUDE" \
      --fail-under-lines "$THRESHOLD"
    echo "✅ Coverage gate passed (≥${THRESHOLD}%)"
    ;;
  *)
    echo "Usage: $0 [text|html|lcov|check]"
    exit 1
    ;;
esac
