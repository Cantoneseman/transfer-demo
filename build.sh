#!/usr/bin/env bash
set -euo pipefail

PROJECT_DIR="$(cd "$(dirname "$0")" && pwd)"
BUILD_DIR="${PROJECT_DIR}/build"

echo "[build] Cleaning previous build..."
rm -rf "${BUILD_DIR}"
mkdir -p "${BUILD_DIR}"
cd "${BUILD_DIR}"

echo "[build] Configuring with CMake..."
cmake "${PROJECT_DIR}"

echo "[build] Compiling with $(nproc) parallel jobs..."
make -j"$(nproc)"

echo "[build] Done. Binaries:"
ls -lh xio_prototype_test test_ring test_uring_worker test_quic_engine test_data_probe
