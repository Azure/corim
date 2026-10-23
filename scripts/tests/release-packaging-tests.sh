#!/usr/bin/env bash
# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
set -euo pipefail

root=$(cd "$(dirname "$0")/../.." && pwd)
fixture="$root/target/release-packaging-tests-$$-$RANDOM"
mkdir -p "$fixture/bin"
trap 'rm -rf "$fixture"' EXIT
workflow="$root/.github/workflows/release.yml"

# Execute the workflow's actual packaging block, not a duplicate of its logic.
awk '
    /- name: Package and verify both crates together/ { step = 1; next }
    step && /^      - / { exit }
    step && /run: \|/ { body = 1; next }
    body && /^          / { sub(/^          /, ""); print }
' "$workflow" > "$fixture/package.sh"
test -s "$fixture/package.sh"

cat > "$fixture/bin/cargo" <<'MOCK'
#!/usr/bin/env bash
set -euo pipefail
[[ "$*" == 'package --workspace --exclude corim-cli --all-features --locked' ]]
if [[ "$CASE" == package-failure ]]; then exit 42; fi
mkdir -p "$CARGO_TARGET_DIR/package"
printf 'verified macro bytes\n' > "$CARGO_TARGET_DIR/package/corim-macros-0.2.1.crate"
if [[ "$CASE" != missing-archive ]]; then
    printf 'verified library bytes\n' > "$CARGO_TARGET_DIR/package/corim-0.2.1.crate"
fi
MOCK
chmod +x "$fixture/bin/cargo"
export PATH="$fixture/bin:$PATH" GITHUB_REF_NAME=v0.2.1
export CARGO_TARGET_DIR="$fixture/build"

for CASE in success package-failure missing-archive; do
    export CASE
    mkdir "$fixture/$CASE"
    status=0
    (cd "$fixture/$CASE" && bash "$fixture/package.sh") > "$fixture/output" 2>&1 || status=$?
    if [[ "$CASE" == success ]]; then
        test "$status" -eq 0
        saved="$fixture/$CASE/target/release-artifacts"
        (cd "$saved" && sha256sum --check SHA256SUMS)
        cmp "$saved/corim-0.2.1.crate" "$CARGO_TARGET_DIR/package/corim-0.2.1.crate"
        cmp "$saved/corim-macros-0.2.1.crate" "$CARGO_TARGET_DIR/package/corim-macros-0.2.1.crate"
        # Repackaging cannot overwrite the saved evidence.
        printf 'repackaged bytes\n' > "$CARGO_TARGET_DIR/package/corim-0.2.1.crate"
        (cd "$saved" && sha256sum --check SHA256SUMS)
    else
        test "$status" -ne 0
        test ! -f "$fixture/$CASE/target/release-artifacts/SHA256SUMS"
    fi
    rm -rf "$CARGO_TARGET_DIR"
    printf 'PASS %s\n' "$CASE"
done

# Fail closed: artifact persistence must finish before registry authentication,
# without an always()/continue-on-error escape that could publish unverified bytes.
awk '
    /- name: Package and verify/ { package_line = NR }
    /- name: Retain verified/ { artifact_line = NR }
    /- name: Authenticate/ { auth_line = NR }
    /- name: Publish corim-macros/ { publish_line = NR }
    END {
        if (!(package_line && artifact_line > package_line &&
              auth_line > artifact_line && publish_line > auth_line)) exit 1
    }
' "$workflow"
if grep -Eq 'continue-on-error:|if:.*always\(\)' "$workflow"; then
    echo 'release must not continue after failed verification or artifact upload' >&2
    exit 1
fi
grep -q 'actions/upload-artifact@ea165f8d65b6e75b540449e92b4886f43607fa02' "$workflow"
grep -q 'if-no-files-found: error' "$workflow"
grep -q 'RUSTUP_TOOLCHAIN: 1.99.0' "$workflow"
if grep -E 'run: cargo (test|clippy|build|package)' "$workflow" | grep -v -- '--locked'; then
    echo 'release gate missing --locked' >&2
    exit 1
fi
printf 'PASS artifact ordering, pinned toolchain/action and locked gates\n'
