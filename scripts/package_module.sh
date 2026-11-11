#!/usr/bin/env bash
set -euo pipefail

# ============================================================================
# Privacy Sentinel — Flashable BakaSU / KernelSU / Zygisk Next ZIP Packager
# ============================================================================

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
STAGE_DIR="${ROOT_DIR}/build/module-stage"
OUT_DIR="${ROOT_DIR}/build/release"
ZIP_NAME="${1:-PrivacySentinel-v2.0.0-arm64-garnet-bakaSU-a17.zip}"

rm -rf "$STAGE_DIR"
mkdir -p "$STAGE_DIR/bin" "$STAGE_DIR/zygisk" "$STAGE_DIR/apk" "$OUT_DIR"

# 1. Copy module metadata, scripts, SELinux policy & WebUI
cp -r "${ROOT_DIR}/module/"* "$STAGE_DIR/"

# 2. Copy Android NDK arm64-v8a / x86_64 binaries if built
if [ -f "${ROOT_DIR}/build/android-arm64-v8a/sentineld" ]; then
  cp "${ROOT_DIR}/build/android-arm64-v8a/sentineld" "$STAGE_DIR/bin/sentineld"
  cp "${ROOT_DIR}/build/android-arm64-v8a/sentinelctl" "$STAGE_DIR/bin/sentinelctl"
  cp "${ROOT_DIR}/build/android-arm64-v8a/libprivacy_sentinel_zygisk.so" "$STAGE_DIR/zygisk/arm64-v8a.so"
fi

if [ -f "${ROOT_DIR}/build/android-x86_64/libprivacy_sentinel_zygisk.so" ]; then
  cp "${ROOT_DIR}/build/android-x86_64/libprivacy_sentinel_zygisk.so" "$STAGE_DIR/zygisk/x86_64.so"
fi

# 3. Copy Vector LibXposed API 102 companion APK if built
if [ -f "${ROOT_DIR}/build/PrivacySentinelVector.apk" ]; then
  cp "${ROOT_DIR}/build/PrivacySentinelVector.apk" "$STAGE_DIR/apk/PrivacySentinelVector.apk"
fi

chmod +x "$STAGE_DIR/"*.sh "$STAGE_DIR/bin/"* 2>/dev/null || true

# 4. Create flashable ZIP archive (files at root of archive per KernelSU spec)
(
  cd "$STAGE_DIR"
  zip -r9 "${OUT_DIR}/${ZIP_NAME}" .
)

echo "[package_module] Packaged: ${OUT_DIR}/${ZIP_NAME}"
ls -lh "${OUT_DIR}/${ZIP_NAME}"
