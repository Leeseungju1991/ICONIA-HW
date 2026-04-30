#!/bin/bash
# =============================================================================
# ICONIA Firmware build helper (Linux / macOS / Git Bash)
# Usage:
#   ./build.sh dev          # default profile
#   ./build.sh prod
#   ./build.sh <name>       # any build_profiles/<name>.h
# =============================================================================
set -e

PROFILE="${1:-dev}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROFILE_FILE="${SCRIPT_DIR}/build_profiles/${PROFILE}.h"

if [ ! -f "${PROFILE_FILE}" ]; then
  echo "[BUILD] ERROR: unknown profile '${PROFILE}'"
  echo "[BUILD] available profiles:"
  ls "${SCRIPT_DIR}/build_profiles/" 2>/dev/null | grep '\.h$' | sed 's/\.h$//' | sed 's/^/  - /'
  exit 1
fi

cp -f "${PROFILE_FILE}" "${SCRIPT_DIR}/build_opt.h"
echo "[BUILD] profile=${PROFILE}"
echo "[BUILD] copied build_profiles/${PROFILE}.h -> build_opt.h"

# arduino-cli 호출. 사용자 환경에 arduino-cli 가 PATH 에 있어야 한다.
# FQBN 은 AI Thinker ESP32-CAM 핀맵을 쓰므로 esp32:esp32:esp32cam.
# Partition Scheme 은 partitions.csv 가 sketch 폴더에 있어 자동 인식된다.
if ! command -v arduino-cli >/dev/null 2>&1; then
  echo "[BUILD] WARN: arduino-cli not found in PATH. Skipping compile."
  echo "[BUILD] Open this sketch in Arduino IDE 2.x to build manually."
  echo "[BUILD] (build_opt.h is already set for profile=${PROFILE})"
  exit 0
fi

cd "${SCRIPT_DIR}"
arduino-cli compile \
  --fqbn esp32:esp32:esp32cam \
  --build-property "build.partitions=partitions" \
  --build-property "upload.maximum_size=1900544" \
  .

echo "[BUILD] done. Output under build/esp32.esp32.esp32cam/"
