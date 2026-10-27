#!/usr/bin/env bash
# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
set -euo pipefail

root=$(cd "$(dirname "$0")/../.." && pwd)

awk '
    function check_step() {
        if (rust_action && toolchain != expected) {
            printf "%s: job %s must explicitly select toolchain %s\n", FILENAME, job, expected > "/dev/stderr"
            failed = 1
        }
        if (installer && tool != "cargo-llvm-cov") {
            printf "%s: coverage installer must explicitly select cargo-llvm-cov\n", FILENAME > "/dev/stderr"
            failed = 1
        }
        rust_action = installer = 0
        toolchain = tool = ""
    }
    FNR == 1 { check_step() }
    /^  [a-zA-Z0-9_-]+:$/ {
        check_step()
        job = $1
        sub(/:$/, "", job)
        expected = job == "build" ? "${{ matrix.rust }}" : "stable"
    }
    /^      - / { check_step() }
    /uses: / {
        action = $0
        sub(/^.*uses: */, "", action)
        sub(/ *#.*/, "", action)
        sub(/ *$/, "", action)
        if (action !~ /^\.\// && action !~ /^docker:\/\//) {
            ref = action
            sub(/^.*@/, "", ref)
            if (length(ref) != 40 || ref ~ /[^0-9a-f]/) {
                printf "%s:%d: action must use a full commit SHA: %s\n", FILENAME, FNR, action > "/dev/stderr"
                failed = 1
            }
        }
        rust_action = action ~ /^dtolnay\/rust-toolchain@/
        installer = action ~ /^taiki-e\/install-action@/
    }
    /^          toolchain: / {
        toolchain = $0
        sub(/^ *toolchain: */, "", toolchain)
    }
    /^          tools?: / {
        tool = $0
        sub(/^ *tools?: */, "", tool)
    }
    END { check_step(); exit failed }
' "$root"/.github/workflows/*.yml

echo "PASS action SHA pins and explicit Rust/tool selections"
