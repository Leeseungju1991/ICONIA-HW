#!/bin/bash
# =============================================================================
# ICONIA Firmware build helper (Linux / macOS / Git Bash)
# Usage:
#   ./build.sh dev          # default profile, debug-friendly
#   ./build.sh prod         # production lockdown (Secure Boot V2 / Flash Enc)
#   ./build.sh <name>       # any build_profiles/<name>.h
#
# prod 빌드는 unsigned binary 만 산출한다. 서명 + eFuse burn 은 양산 라인
# fixture 가 별도 수행 — 비공개 키가 빌드 환경에 노출되지 않도록 의도적 분리.
# 라인 절차: docs/production_provisioning.md §3.
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

# -----------------------------------------------------------------------------
# prod 보안 잠금 매크로 정합성 검사 (출시 차단 가드)
# -----------------------------------------------------------------------------
# build.sh 자체 단계에서 매크로 부재를 사전 차단 — 누군가 실수로 prod.h 의
# 보안 매크로를 주석 처리하고 출하하는 사고를 막는다. 누락 시 빌드 거부.
if [ "${PROFILE}" = "prod" ]; then
  for mac in ICONIA_PRODUCTION_BUILD ICONIA_BLE_SECURE \
             ICONIA_REQUIRE_FACTORY_SEED ICONIA_LOCKDOWN \
             ICONIA_SECURE_VERSION; do
    if ! grep -q "^#define ${mac}" "${PROFILE_FILE}"; then
      echo "[BUILD] FATAL: prod profile missing required macro ${mac}"
      echo "[BUILD] refer to docs/production_provisioning.md"
      exit 2
    fi
  done
  echo "[BUILD] prod lockdown macros verified"
fi

# -----------------------------------------------------------------------------
# arduino-cli compile
# -----------------------------------------------------------------------------
if ! command -v arduino-cli >/dev/null 2>&1; then
  echo "[BUILD] WARN: arduino-cli not found in PATH. Skipping compile."
  echo "[BUILD] Open this sketch in Arduino IDE 2.x to build manually."
  echo "[BUILD] (build_opt.h is already set for profile=${PROFILE})"
  exit 0
fi

cd "${SCRIPT_DIR}"
arduino-cli compile \
  --warnings all \
  --fqbn esp32:esp32:esp32cam \
  --build-property "build.partitions=partitions" \
  --build-property "upload.maximum_size=1900544" \
  .

echo "[BUILD] done. Output under build/esp32.esp32.esp32cam/"

# -----------------------------------------------------------------------------
# prod 후속 안내: 빌드 산출물은 unsigned. 양산 라인이 sign + flash + eFuse burn
# 절차를 수행해야 한다.
# -----------------------------------------------------------------------------
if [ "${PROFILE}" = "prod" ]; then
  cat <<EOF

[BUILD] === PROD POST-BUILD CHECKLIST ===
Built artifact is UNSIGNED. Production line must:
  1) espsecure.py sign_data --version 2 --keyfile <hsm-or-airgap-key> ...
  2) espefuse.py burn_key_digest + SECURE_BOOT_EN=1
  3) espefuse.py FLASH_CRYPT_CNT=0xF (RELEASE flash encryption)
  4) espefuse.py JTAG_DISABLE=1, UART_DOWNLOAD_DIS=1
  5) factory_nvs seed/salt/seed_ver burn (per-device, lot CSV)
  6) QA validation: pairing, status notify, deep-sleep current, touch wake
Detailed procedure: HW/docs/production_provisioning.md §3
=================================
EOF
fi
