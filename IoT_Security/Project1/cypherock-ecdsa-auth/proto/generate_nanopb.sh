#!/bin/bash
set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
OUT_DIR="${SCRIPT_DIR}/../common"

echo "[GEN] Generating nanopb files into: ${OUT_DIR}"

# Use nanopb CLI script
nanopb_generator \
    -I "${SCRIPT_DIR}" \
    -D "${OUT_DIR}" \
    "${SCRIPT_DIR}/auth.proto"

echo "[GEN] Done."

