#!/usr/bin/env bash
# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
set -euo pipefail

root=$(cd "$(dirname "$0")/../.." && pwd)
temporary=$(mktemp -d)
cleanup() {
    rm -f "$temporary/bin/cargo" "$temporary/bin/curl" "$temporary/bin/sleep" \
        "$temporary/archive.crate" "$temporary/calls" "$temporary/requests" \
        "$temporary/published" "$temporary/output"
    rmdir "$temporary/bin" "$temporary"
}
trap cleanup EXIT
mkdir "$temporary/bin"
printf 'release package fixture\n' > "$temporary/archive.crate"
EXPECTED_CHECKSUM=$(sha256sum "$temporary/archive.crate")
export EXPECTED_CHECKSUM="${EXPECTED_CHECKSUM%% *}" FIXTURE="$temporary"

cat > "$temporary/bin/cargo" <<'MOCK'
#!/usr/bin/env bash
set -euo pipefail
printf '%s\n' "$*" >> "$FIXTURE/calls"
case "$CASE" in
    existing-match|existing-mismatch|yanked)
        echo "error: version already exists" >&2
        exit 101
        ;;
    publish-failure)
        echo "simulated publish failure" >&2
        exit 42
        ;;
esac
touch "$FIXTURE/published"
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
esac
printf '{"vers":"%s","cksum":"%s","yanked":%s}\n' "$version" "$checksum" "$yanked" > "$output"
printf 200
MOCK

cat > "$temporary/bin/sleep" <<'MOCK'
#!/usr/bin/env bash
exit 0
MOCK
chmod +x "$temporary/bin/cargo" "$temporary/bin/curl" "$temporary/bin/sleep"
export PATH="$temporary/bin:$PATH"

run_case() {
    export CASE=$1
    local expected_status=$2 expected_calls=$3 message=$4 status=0 archive
    archive="$temporary/archive.crate"
    if [[ "$CASE" == missing-archive ]]; then archive="$temporary/missing.crate"; fi
    : > "$temporary/calls"
    : > "$temporary/requests"
    rm -f "$temporary/published"
    bash "$root/scripts/publish-crate.sh" corim-macros 0.2.1 "$archive" \
        > "$temporary/output" 2>&1 || status=$?
    if [[ "$expected_status" == success && "$status" != 0 ]] \
        || [[ "$expected_status" == failure && "$status" == 0 ]] \
        || [[ $(wc -l < "$temporary/calls") != "$expected_calls" ]] \
        || ! grep -q "$message" "$temporary/output"; then
        printf 'FAIL %s (status=%s, publish calls=%s)\n' "$CASE" "$status" "$(wc -l < "$temporary/calls")"
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
run_case yanked failure 0 'yanked' || failures=$((failures + 1))
run_case publish-failure failure 1 'simulated publish failure' || failures=$((failures + 1))
run_case missing-archive failure 0 'missing archive' || failures=$((failures + 1))
if ((failures)); then
    printf '%s publishing regressions failed\n' "$failures" >&2
    exit 1
fi
