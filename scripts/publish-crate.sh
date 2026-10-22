#!/usr/bin/env bash
# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
set -euo pipefail

if (($# != 3)); then
    echo "usage: publish-crate.sh PACKAGE VERSION ARCHIVE" >&2
    exit 1
fi
package=$1
version=$2
archive=$3
case "$package" in
    corim|corim-macros) ;;
    *) echo "unexpected release package: $package" >&2; exit 1 ;;
esac
if [[ ! "$version" =~ ^[0-9]+\.[0-9]+\.[0-9]+([-+][0-9A-Za-z.+-]+)?$ ]]; then
    echo "invalid release version: $version" >&2
    exit 1
fi
if [[ ! -f "$archive" ]]; then
    echo "missing archive: $archive" >&2
    exit 1
fi
local_checksum=$(sha256sum "$archive")
local_checksum=${local_checksum%% *}
target_dir=${CARGO_TARGET_DIR:-target}
mkdir -p "$target_dir"
response_dir="$target_dir/release-index-$$-$RANDOM"
mkdir "$response_dir"
response="$response_dir/response"
trap 'rm -f "$response"; rmdir "$response_dir"' EXIT

registry_checksum() {
    local status
    if ! status=$(curl --silent --show-error --connect-timeout 10 --max-time 30 \
        --output "$response" --write-out '%{http_code}' \
        "https://index.crates.io/co/ri/$package"); then
        echo "registry request failed for $package $version" >&2
        return 1
    fi
    case "$status" in
        404) return 0 ;;
        200) ;;
        *) echo "registry returned HTTP $status for $package $version" >&2; return 1 ;;
    esac
    jq -r -s --arg version "$version" '
        if length == 0 then error("empty registry index")
        elif any(.[]; type != "object") then error("registry index records must be objects")
        elif any(.[]; (.vers | type) != "string") then
            error("registry index records must have a string vers")
        else . end |
        map(select(.vers == $version)) |
        if length == 0 then ""
        elif length != 1 then error("duplicate registry version")
        else .[0] |
            if .yanked == true then error("release version is yanked")
            elif .yanked != false then error("missing registry yanked status")
            elif (.cksum | type) != "string" then error("missing registry checksum")
            elif (.cksum | test("^[0-9a-f]{64}$") | not) then error("invalid registry checksum")
            else .cksum end
        end
    ' "$response"
}

verify_checksum() {
    if [[ "$1" != "$local_checksum" ]]; then
        echo "registry archive checksum mismatch for $package $version" >&2
        echo "local=$local_checksum registry=$1" >&2
        return 1
    fi
}

checksum=$(registry_checksum)
if [[ -n "$checksum" ]]; then
    verify_checksum "$checksum"
    echo "Already published $package $version; archive checksum matches"
    exit 0
fi

cargo publish --locked --all-features -p "$package"
# Cargo repackages on publish. Compare its output with the independently saved
# verified archive, not with a file that Cargo may have just overwritten.
repackaged="$target_dir/package/$package-$version.crate"
if [[ ! -f "$repackaged" ]]; then
    echo "missing repackaged archive: $repackaged" >&2
    exit 1
fi
repackaged_checksum=$(sha256sum "$repackaged")
repackaged_checksum=${repackaged_checksum%% *}
if [[ "$repackaged_checksum" != "$local_checksum" ]]; then
    echo "repackaged archive checksum mismatch for $package $version" >&2
    echo "verified=$local_checksum repackaged=$repackaged_checksum" >&2
    exit 1
fi
for ((attempt = 1; attempt <= 30; attempt++)); do
    checksum=$(registry_checksum)
    if [[ -n "$checksum" ]]; then
        verify_checksum "$checksum"
        echo "Published $package $version; archive checksum matches"
        exit 0
    fi
    if ((attempt < 30)); then sleep 10; fi
done
echo "$package $version not indexed after 30 checks; rerun after indexing completes" >&2
exit 1
