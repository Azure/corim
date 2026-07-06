# fetch-manticore-endorsement

A shell script CLI that fetches **Manticore (AI HSM) endorsements** from
the Azure THIM (Trusted Hardware Identity Management) service.

This is a bash equivalent of the
`ThimAiHsmEndorsementClient.GetAllFirmwareEndorsementsAsync()` C# method.

## How it works

1. **GET** `{thim-url}/endorsement/manticore/names` — retrieves the list of
   endorsement names (e.g. `authenticity`, `trust`).
2. **GET** `{thim-url}/endorsement/manticore/{name}` — downloads each
   endorsement as raw bytes.
3. Base64-URL encodes each endorsement and emits a **JSON array of strings**
   to stdout (or a file), matching the serialization format expected by
   downstream consumers.

## Prerequisites

| Tool | Purpose |
|------|---------|
| `curl` | HTTP requests |
| `jq` | JSON parsing |
| `base64` | Base64 encoding (coreutils) |

## Usage

```bash
# From inside an Azure CVM (uses the IMDS THIM endpoint by default):
./fetch-manticore-endorsement.sh

# With a custom THIM service URL:
./fetch-manticore-endorsement.sh --thim-url https://thim.example.com

# Save combined endorsement JSON to a file:
./fetch-manticore-endorsement.sh --output endorsements.json

# Save individual raw endorsements to a directory:
./fetch-manticore-endorsement.sh --output-dir ./endorsements

# Verbose output (progress printed to stderr):
./fetch-manticore-endorsement.sh -v

# All options:
./fetch-manticore-endorsement.sh \
    --thim-url https://thim.example.com \
    --output endorsements.json \
    --output-dir ./raw \
    --retries 5 \
    --timeout 60 \
    -v
```

## Options

| Flag | Description | Default |
|------|-------------|---------|
| `--thim-url URL` | THIM service base URL | `http://169.254.169.254/metadata/THIM` |
| `--output FILE` | Write combined endorsement JSON to a file | stdout |
| `--output-dir DIR` | Save each raw endorsement as `DIR/{name}.bin` | _(none)_ |
| `--retries N` | Max retry attempts per HTTP request | `3` |
| `--timeout SECS` | HTTP request timeout in seconds | `30` |
| `-v, --verbose` | Print progress to stderr | off |
| `-h, --help` | Show help | |

## Output format

The output is a JSON array of base64url-encoded strings (no padding),
one per endorsement:

```json
["SGVsbG8gV29ybGQ","Rm9vQmFy"]
```

This matches the wire format produced by
`ThimAiHsmEndorsementClient.SerializeAllEndorsements()`.
