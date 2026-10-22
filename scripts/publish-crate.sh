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
response=$(mktemp)
trap 'rm -f "$response"' EXIT

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

cargo publish --locked -p "$package"
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
