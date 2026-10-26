#!/usr/bin/env bash
# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
set -euo pipefail

root=$(cd "$(dirname "$0")/../.." && pwd)
temporary="$root/target/publish-crate-tests-$$-$RANDOM"
mkdir -p "$temporary"
cleanup() {
    rm -rf "$temporary"
}
trap cleanup EXIT
mkdir "$temporary/bin"
printf 'release package fixture\n' > "$temporary/archive.crate"
EXPECTED_CHECKSUM=$(sha256sum "$temporary/archive.crate")
export EXPECTED_CHECKSUM="${EXPECTED_CHECKSUM%% *}" FIXTURE="$temporary"
export CARGO_TARGET_DIR="$temporary/target"
mkdir -p "$CARGO_TARGET_DIR/package"

cat > "$temporary/bin/cargo" <<'MOCK'
#!/usr/bin/env bash
set -euo pipefail
printf '%s\n' "$*" >> "$FIXTURE/calls"
case "$*" in
    'publish --locked --all-features --dry-run -p corim-macros')
        phase=dry-run
        printf 'dry-run\n' >> "$FIXTURE/dry-runs"
        ;;
    'publish --locked --all-features -p corim-macros')
        phase=upload
        printf 'upload\n' >> "$FIXTURE/uploads"
        ;;
    *)
        echo "unexpected Cargo arguments: $*" >&2
        exit 1
        ;;
esac
case "$CASE" in
    existing-match|existing-mismatch|yanked)
        echo "error: version already exists" >&2
        exit 101
        ;;
    publish-failure)
        if [[ "$phase" == upload ]]; then
            echo "simulated publish failure" >&2
            exit 42
        fi
        ;;
    dry-run-failure)
        if [[ "$phase" == dry-run ]]; then
            echo "simulated dry-run failure" >&2
            exit 43
        fi
        ;;
esac
if [[ "$phase" == upload && ! -f "$FIXTURE/dry-run-complete" ]]; then
    echo "upload attempted before successful dry-run" >&2
    exit 1
fi
case "$CASE:$phase" in
    repackaged-mismatch:upload|pre-upload-drift:dry-run)
        printf 'different repackaged bytes\n' > "$CARGO_TARGET_DIR/package/corim-macros-0.2.1.crate"
        ;;
    repackaged-missing:upload|dry-run-missing:dry-run)
        rm -f "$CARGO_TARGET_DIR/package/corim-macros-0.2.1.crate"
        ;;
    *)
        cp "$FIXTURE/archive.crate" "$CARGO_TARGET_DIR/package/corim-macros-0.2.1.crate"
        ;;
esac
if [[ "$phase" == dry-run ]]; then
    touch "$FIXTURE/dry-run-complete"
else
    touch "$FIXTURE/published"
fi
MOCK

cat > "$temporary/bin/curl" <<'MOCK'
#!/usr/bin/env bash
set -euo pipefail
output=
while (($#)); do
    case "$1" in
        --output) output=$2; shift 2 ;;
        *) shift ;;
    esac
done
count=$(wc -l < "$FIXTURE/requests")
printf 'request\n' >> "$FIXTURE/requests"
case "$CASE" in
    network) echo 'simulated connection failure' >&2; exit 7 ;;
    http-error) printf 'unavailable' > "$output"; printf 503; exit ;;
    invalid-index) printf 'not json\n' > "$output"; printf 200; exit ;;
    empty-index) : > "$output"; printf 200; exit ;;
    whitespace-index) printf ' \t\n' > "$output"; printf 200; exit ;;
    missing-version) printf '{}\n' > "$output"; printf 200; exit ;;
    array-record) printf '[]\n' > "$output"; printf 200; exit ;;
    null-record) printf 'null\n' > "$output"; printf 200; exit ;;
    numeric-record) printf '42\n' > "$output"; printf 200; exit ;;
    string-record) printf '"metadata"\n' > "$output"; printf 200; exit ;;
    nonstring-version) printf '{"vers":42}\n' > "$output"; printf 200; exit ;;
    mixed-records)
        printf '{"vers":"0.2.0"}\n{}\n' > "$output"
        printf 200
        exit
        ;;
    post-upload-invalid-index)
        if [[ -f "$FIXTURE/published" ]]; then
            printf '{}\n' > "$output"
            printf 200
            exit
        fi
        ;;
    new-crate)
        if [[ ! -f "$FIXTURE/published" ]]; then
            printf 'not found' > "$output"
            printf 404
            exit
        fi
        ;;
esac
checksum=$EXPECTED_CHECKSUM
yanked=false
version=0.2.1
case "$CASE" in
    existing-mismatch) checksum=$(printf '%064d' 0) ;;
    invalid-checksum) checksum=invalid ;;
    post-upload-mismatch)
        if [[ -f "$FIXTURE/published" ]]; then
            checksum=$(printf '%064d' 0)
        else
            version=0.2.0
        fi
        ;;
    yanked) yanked=true ;;
    timeout) version=0.2.0 ;;
    delayed-index)
        if [[ ! -f "$FIXTURE/published" ]] || ((count < 3)); then
            version=0.2.0
        fi
        ;;
    publish-failure) version=0.2.0 ;;
    post-upload-invalid-index) version=0.2.0 ;;
    repackaged-mismatch|repackaged-missing|pre-upload-drift|dry-run-missing|dry-run-failure)
        if [[ ! -f "$FIXTURE/published" ]]; then version=0.2.0; fi
        ;;
esac
printf '{"vers":"%s","cksum":"%s","yanked":%s}\n' "$version" "$checksum" "$yanked" > "$output"
printf 200
MOCK

cat > "$temporary/bin/sleep" <<'MOCK'
#!/usr/bin/env bash
exit 0
MOCK
chmod +x "$temporary/bin/"*
export PATH="$temporary/bin:$PATH"

run_case() {
    export CASE=$1
    local expected_status=$2 expected_uploads=$3 message=$4
    local expected_dry_runs=${5:-$expected_uploads} status=0 archive uploads dry_runs
    archive="$temporary/archive.crate"
    if [[ "$CASE" == missing-archive ]]; then archive="$temporary/missing.crate"; fi
    : > "$temporary/calls"
    : > "$temporary/uploads"
    : > "$temporary/dry-runs"
    : > "$temporary/requests"
    rm -f "$temporary/published" "$temporary/dry-run-complete"
    rm -f "$CARGO_TARGET_DIR/package/corim-macros-0.2.1.crate"
    bash "$root/scripts/publish-crate.sh" corim-macros 0.2.1 "$archive" \
        > "$temporary/output" 2>&1 || status=$?
    uploads=$(wc -l < "$temporary/uploads")
    dry_runs=$(wc -l < "$temporary/dry-runs")
    if [[ "$expected_status" == success && "$status" != 0 ]] \
        || [[ "$expected_status" == failure && "$status" == 0 ]] \
        || [[ "$uploads" != "$expected_uploads" || "$dry_runs" != "$expected_dry_runs" ]] \
        || [[ "$expected_uploads" == 0 && -f "$temporary/published" ]] \
        || ! grep -q "$message" "$temporary/output"; then
        printf 'FAIL %s (status=%s, dry-runs=%s, uploads=%s)\n' "$CASE" "$status" "$dry_runs" "$uploads"
        cat "$temporary/output"
        return 1
    fi
    printf 'PASS %s\n' "$CASE"
}

failures=0
run_case existing-match success 0 'archive checksum matches' || failures=$((failures + 1))
run_case existing-mismatch failure 0 'checksum mismatch' || failures=$((failures + 1))
run_case delayed-index success 1 'Published' || failures=$((failures + 1))
run_case new-crate success 1 'Published' || failures=$((failures + 1))
run_case post-upload-mismatch failure 1 'checksum mismatch' || failures=$((failures + 1))
run_case invalid-checksum failure 0 'invalid registry checksum' || failures=$((failures + 1))
run_case timeout failure 1 'not indexed' || failures=$((failures + 1))
run_case network failure 0 'registry request failed' || failures=$((failures + 1))
run_case http-error failure 0 'HTTP 503' || failures=$((failures + 1))
run_case invalid-index failure 0 'parse error' || failures=$((failures + 1))
run_case empty-index failure 0 'empty registry index' || failures=$((failures + 1))
run_case whitespace-index failure 0 'empty registry index' || failures=$((failures + 1))
run_case missing-version failure 0 'string vers' || failures=$((failures + 1))
run_case array-record failure 0 'records must be objects' || failures=$((failures + 1))
run_case null-record failure 0 'records must be objects' || failures=$((failures + 1))
run_case numeric-record failure 0 'records must be objects' || failures=$((failures + 1))
run_case string-record failure 0 'records must be objects' || failures=$((failures + 1))
run_case nonstring-version failure 0 'string vers' || failures=$((failures + 1))
run_case mixed-records failure 0 'string vers' || failures=$((failures + 1))
run_case post-upload-invalid-index failure 1 'string vers' || failures=$((failures + 1))
run_case yanked failure 0 'yanked' || failures=$((failures + 1))
run_case publish-failure failure 1 'simulated publish failure' || failures=$((failures + 1))
run_case missing-archive failure 0 'missing archive' || failures=$((failures + 1))
run_case repackaged-mismatch failure 1 'repackaged archive checksum mismatch' || failures=$((failures + 1))
run_case repackaged-missing failure 1 'missing repackaged archive' || failures=$((failures + 1))
run_case pre-upload-drift failure 0 'repackaged archive checksum mismatch' 1 || failures=$((failures + 1))
run_case dry-run-missing failure 0 'missing repackaged archive' 1 || failures=$((failures + 1))
run_case dry-run-failure failure 0 'simulated dry-run failure' 1 || failures=$((failures + 1))
if ((failures)); then
    printf '%s publishing regressions failed\n' "$failures" >&2
    exit 1
fi
