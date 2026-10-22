#!/usr/bin/env bash
# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
set -euo pipefail

cargo publish -p "$1"
