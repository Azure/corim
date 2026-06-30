#!/usr/bin/env bash
# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
#
# Fetch Manticore (AI HSM) endorsements from the THIM endpoint.
#
# This script mirrors the logic of ThimAiHsmEndorsementClient.cs:
#   1. GET  {base}/endorsement/manticore/names   -> list of endorsement names
#   2. GET  {base}/endorsement/manticore/{name}   -> raw endorsement bytes
#   3. Base64-URL encode each endorsement and emit a JSON array
#
# Prerequisites:
#   - curl, jq, base64 (coreutils)
#   - Network access to the THIM endpoint (IMDS or custom)
#
# Usage:
#   # From inside an Azure CVM (uses IMDS THIM endpoint):
#   ./fetch-manticore-endorsement.sh
#
#   # With a custom THIM base URL:
#   ./fetch-manticore-endorsement.sh --thim-url https://thim.example.com
#
#   # Save combined endorsement blob to a file:
#   ./fetch-manticore-endorsement.sh --output endorsements.json
#
#   # Save individual endorsements to a directory:
#   ./fetch-manticore-endorsement.sh --output-dir ./endorsements
#
#   # Verbose mode (prints progress to stderr):
#   ./fetch-manticore-endorsement.sh -v

set -euo pipefail

# ---------------------------------------------------------------------------
# Defaults
# ---------------------------------------------------------------------------
# The default THIM URL is the Azure IMDS-based THIM endpoint.
THIM_BASE_URL="http://169.254.169.254/metadata/THIM"
ENDORSEMENT_PATH="/endorsement/manticore"
OUTPUT_FILE=""
OUTPUT_DIR=""
SAVE_RAW=false
VERBOSE=false
MAX_RETRIES=3
RETRY_DELAY=2   # seconds; doubles on each retry (exponential backoff)
TIMEOUT=30       # curl timeout in seconds

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
usage() {
    cat <<EOF
Usage: $(basename "$0") [OPTIONS]

Fetch Manticore (AI HSM) endorsements from the THIM service.

Options:
  --thim-url URL    THIM service base URL
                    (default: $THIM_BASE_URL)
  --output FILE     Write the combined endorsement JSON to FILE
                    (default: stdout)
  --output-dir DIR  Also save each raw endorsement to DIR/{name}.bin
  --save-raw        Save each endorsement's raw response to a local
                    file named {name} (e.g. "authenticity", "trust")
  --retries N       Max retry attempts per HTTP request (default: $MAX_RETRIES)
  --timeout SECS    HTTP request timeout in seconds  (default: $TIMEOUT)
  -v, --verbose     Print progress messages to stderr
  -h, --help        Show this help and exit
EOF
}

log() {
    if $VERBOSE; then
        echo "[INFO] $*" >&2
    fi
}

err() {
    echo "[ERROR] $*" >&2
}

die() {
    err "$@"
    exit 1
}

# ---------------------------------------------------------------------------
# Dependency check
# ---------------------------------------------------------------------------
check_deps() {
    local missing=()
    for cmd in curl jq base64; do
        if ! command -v "$cmd" &>/dev/null; then
            missing+=("$cmd")
        fi
    done
    if [[ ${#missing[@]} -gt 0 ]]; then
        die "Missing required commands: ${missing[*]}. Please install them first."
    fi
}

# ---------------------------------------------------------------------------
# HTTP helpers with exponential-backoff retry
# ---------------------------------------------------------------------------
# Bash variables / command substitution silently strip NUL bytes (0x00),
# so binary responses MUST go straight to a file. CBOR/COSE payloads are
# full of NULs (length-prefixes, integer zeros, etc.).
#
# `http_get_to_file URL OUTFILE` — binary-safe; writes the response body
# directly to OUTFILE without ever crossing a shell variable.
# `http_get URL`                  — text-only; safe for JSON responses.
#                                   Do NOT use this for binary payloads.
http_get_to_file() {
    local url="$1"
    local outfile="$2"
    local attempt=0
    local delay=$RETRY_DELAY

    while true; do
        attempt=$((attempt + 1))
        log "HTTP GET $url -> $outfile (attempt $attempt/$MAX_RETRIES)"

        local http_code
        http_code=$(curl -s -o "$outfile" -w "%{http_code}" \
            --max-time "$TIMEOUT" \
            -H "Metadata: true" \
            "$url") || true

        if [[ "$http_code" -ge 200 && "$http_code" -lt 300 ]]; then
            return 0
        fi

        if [[ $attempt -ge $MAX_RETRIES ]]; then
            local body=""
            [[ -s "$outfile" ]] && body="$(head -c 512 "$outfile" | tr -dc '[:print:]')"
            rm -f "$outfile"
            die "Request to $url failed after $MAX_RETRIES attempts (last HTTP $http_code). Body (truncated): $body"
        fi

        log "Request failed (HTTP $http_code), retrying in ${delay}s..."
        sleep "$delay"
        delay=$((delay * 2))
    done
}

# Text-only variant: returns body on stdout via command substitution.
# Safe only for responses that are guaranteed NUL-free (JSON, XML, etc.).
http_get() {
    local url="$1"
    local tmpfile
    tmpfile=$(mktemp)
    # shellcheck disable=SC2064
    trap "rm -f '$tmpfile'" RETURN
    http_get_to_file "$url" "$tmpfile"
    cat "$tmpfile"
}

# ---------------------------------------------------------------------------
# Base64-URL encode (no padding) — RFC 4648 §5
# Reads binary from stdin, writes encoded text to stdout. Stream-only:
# never feed binary into a shell variable upstream of this function.
# ---------------------------------------------------------------------------
base64url_encode() {
    base64 -w0 | tr '+/' '-_' | tr -d '='
}

# Stream the contents of FILE through base64url_encode.
base64url_encode_file() {
    base64url_encode < "$1"
}

# ---------------------------------------------------------------------------
# Parse arguments
# ---------------------------------------------------------------------------
parse_args() {
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --thim-url)
                THIM_BASE_URL="$2"; shift 2 ;;
            --output|-o)
                OUTPUT_FILE="$2"; shift 2 ;;
            --output-dir)
                OUTPUT_DIR="$2"; shift 2 ;;
            --save-raw)
                SAVE_RAW=true; shift ;;
            --retries)
                MAX_RETRIES="$2"; shift 2 ;;
            --timeout)
                TIMEOUT="$2"; shift 2 ;;
            -v|--verbose)
                VERBOSE=true; shift ;;
            -h|--help)
                usage; exit 0 ;;
            *)
                die "Unknown option: $1. Use --help for usage." ;;
        esac
    done
}

# ---------------------------------------------------------------------------
# Step 1: Fetch endorsement names
# ---------------------------------------------------------------------------
fetch_endorsement_names() {
    local url="${THIM_BASE_URL}${ENDORSEMENT_PATH}/names"
    log "Fetching endorsement names from $url"

    local response
    response=$(http_get "$url")

    # The response is JSON: { "Names": ["authenticity", "trust", ...] }
    # (field name may vary in casing; handle both)
    local names
    names=$(echo "$response" | jq -r '(.Names // .names // [])[]' 2>/dev/null) || \
        die "Failed to parse endorsement names response: $response"

    if [[ -z "$names" ]]; then
        die "THIM returned no endorsement names. Response: $response"
    fi

    log "Endorsement names: $(echo "$names" | tr '\n' ', ')"
    echo "$names"
}

# ---------------------------------------------------------------------------
# Step 2: Download a single endorsement (binary-safe)
# ---------------------------------------------------------------------------
# Writes the raw bytes to OUTFILE. Echoes OUTFILE on stdout so callers can
# capture the path. NEVER returns the body itself — binary through a shell
# variable corrupts NUL bytes.
download_endorsement() {
    local name="$1"
    local outfile="$2"
    local url="${THIM_BASE_URL}${ENDORSEMENT_PATH}/${name}"
    log "Downloading endorsement '$name' from $url"

    http_get_to_file "$url" "$outfile"

    if [[ ! -s "$outfile" ]]; then
        die "THIM returned empty endorsement for '$name'"
    fi

    local size
    size=$(wc -c < "$outfile")
    log "Downloaded endorsement '$name': $size bytes"

    # Optionally copy raw endorsement into the output directory
    if [[ -n "$OUTPUT_DIR" ]]; then
        mkdir -p "$OUTPUT_DIR"
        local outpath="${OUTPUT_DIR}/${name}"
        cp "$outfile" "$outpath"
        log "Saved raw endorsement to $outpath"
    fi

    echo "$outfile"
}

# ---------------------------------------------------------------------------
# Step 3: Serialize all endorsements (given as file paths) as a JSON array
# of base64url strings. Streams each file through base64 to stay
# binary-safe.
# ---------------------------------------------------------------------------
serialize_endorsement_files() {
    local -a files=("$@")
    local first=true

    printf '['
    for f in "${files[@]}"; do
        if $first; then
            first=false
        else
            printf ','
        fi
        printf '"'
        base64url_encode_file "$f"
        printf '"'
    done
    printf ']'
}

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
main() {
    parse_args "$@"
    check_deps

    log "THIM base URL: $THIM_BASE_URL"
    log "Endorsement path: $ENDORSEMENT_PATH"

    # Step 1: Get endorsement names
    local names_url="${THIM_BASE_URL}${ENDORSEMENT_PATH}/names"
    echo "=========================================="
    echo "  GET ${names_url}"
    echo "=========================================="

    local names_response
    names_response=$(http_get "$names_url")
    echo "$names_response" | jq . 2>/dev/null || echo "$names_response"
    echo ""

    # Parse names from response
    local names_list
    names_list=$(echo "$names_response" | jq -r '(.Names // .names // [])[]' 2>/dev/null) || \
        die "Failed to parse endorsement names response: $names_response"

    if [[ -z "$names_list" ]]; then
        die "THIM returned no endorsement names. Response: $names_response"
    fi

    # Read names into an array
    local -a names=()
    while IFS= read -r name; do
        [[ -n "$name" ]] && names+=("$name")
    done <<< "$names_list"

    log "Found ${#names[@]} endorsement(s)"

    if [[ ${#names[@]} -eq 0 ]]; then
        die "THIM didn't return any AI HSM endorsements"
    fi

    # Step 2: Download each endorsement straight to a temp file
    # (binary-safe — NUL bytes in COSE/CBOR would be silently stripped
    # by command substitution if we went through a variable).
    local tmpdir
    tmpdir=$(mktemp -d)
    # shellcheck disable=SC2064
    trap "rm -rf '$tmpdir'" EXIT

    local -a endorsement_files=()
    for name in "${names[@]}"; do
        local endorsement_url="${THIM_BASE_URL}${ENDORSEMENT_PATH}/${name}"
        echo "=========================================="
        echo "  GET ${endorsement_url}"
        echo "=========================================="

        local safe_name="${name//\//_}"
        local tmpfile="${tmpdir}/${safe_name}"
        download_endorsement "$name" "$tmpfile" >/dev/null
        endorsement_files+=("$tmpfile")

        # Save raw output to a local file named after the endorsement
        if $SAVE_RAW; then
            cp "$tmpfile" "./${safe_name}"
            echo "  -> Saved raw response to ./${safe_name}"
        fi

        local size
        size=$(wc -c < "$tmpfile")
        echo "  ${size} bytes (binary CBOR/COSE; not pretty-printed)"
        echo ""
    done

    # Step 3: Serialize to JSON array of base64url strings (stream from files)
    echo "=========================================="
    echo "  Combined endorsements (base64url JSON)"
    echo "=========================================="
    if [[ -n "$OUTPUT_FILE" ]]; then
        serialize_endorsement_files "${endorsement_files[@]}" > "$OUTPUT_FILE"
        jq . "$OUTPUT_FILE" 2>/dev/null || cat "$OUTPUT_FILE"
        log "Combined endorsement JSON written to $OUTPUT_FILE"
    else
        local combined_tmp="${tmpdir}/combined.json"
        serialize_endorsement_files "${endorsement_files[@]}" > "$combined_tmp"
        jq . "$combined_tmp" 2>/dev/null || cat "$combined_tmp"
    fi

    log "Done — ${#endorsement_files[@]} endorsement(s) fetched successfully."
}

main "$@"
