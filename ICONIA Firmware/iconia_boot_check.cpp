// =============================================================================
// iconia_boot_check — implementation
// 정본: docs/security_handshake.md §0~§2 + production_provisioning.md §3
// -----------------------------------------------------------------------------
// 본 파일은 Arduino-ESP32 core 3.x (ESP-IDF 5.x) 기반의 eFuse / secure boot /
// flash encryption API 를 사용한다. 일부 헤더는 IDF 버전에 따라 위치가 다를
// 수 있어 본 파일에서만 conditional include 를 한다.
// =============================================================================

#include "iconia_boot_check.h"

#include <Preferences.h>

#include "esp_system.h"
#include "esp_efuse.h"
#include "esp_efuse_table.h"
#include "esp_secure_boot.h"
#include "esp_flash_encrypt.h"
#include "esp_sleep.h"

#include "iconia_config.h"
#include "iconia_security.h"

namespace iconia {
namespace boot_check {

static constexpr const char* kPanicNs        = "panic";
static constexpr const char* kPanicKeyMask   = "boot_inv";
static constexpr const char* kPanicKeyAt     = "boot_inv_at";

// 단일 비트 추출 (가장 낮은 set bit).
static uint16_t lowestBit(uint16_t mask) {
  if (mask == 0) return 0;
  uint16_t b = 1;
  while ((mask & b) == 0) b <<= 1;
  return b;
}

// eFuse 헬퍼들 — IDF 의 esp_efuse_read_field_bit 사용. ESP_EFUSE_DIS_PAD_JTAG /
// ESP_EFUSE_DIS_DOWNLOAD_MODE 등은 esp_efuse_table.h 에서 노출.
static bool efuseBit(const esp_efuse_desc_t* const* field) {
  if (field == nullptr) return false;
  return esp_efuse_read_field_bit(field);
}

Result runAll() {
  Result r = {};
  r.pass = true;
  r.violationMask = 0;

  // DEV 빌드는 곧바로 통과. dev/bring-up 에서 디버깅 가능 유지.
  if (!iconia::config::kLockdown) {
    r.pass = true;
    return r;
  }

  // 1) PRODUCTION_BUILD 매크로
#if defined(ICONIA_PRODUCTION_BUILD) && (ICONIA_PRODUCTION_BUILD == 1)
  // 통과
#else
  r.violationMask |= kBitProductionBuildMacro;
#endif

  // 2) Secure Boot
  if (!esp_secure_boot_enabled()) {
    r.violationMask |= kBitSecureBootEnabled;
  }

  // 3) Flash Encryption RELEASE 모드
  //    개발 모드(DEVELOPMENT) 도 esp_flash_encryption_enabled() == true 를 반환
  //    하므로 mode 별도 확인 필요.
  if (!esp_flash_encryption_enabled()) {
    r.violationMask |= kBitFlashEncryptionRelease;
  } else {
    esp_flash_enc_mode_t mode = esp_get_flash_encryption_mode();
    if (mode != ESP_FLASH_ENC_MODE_RELEASE) {
      r.violationMask |= kBitFlashEncryptionRelease;
    }
  }

  // 4) JTAG disable. ESP-IDF 5.x 의 ESP_EFUSE_DIS_PAD_JTAG (혹은 USB JTAG 변종).
  //    필드가 정의되지 않은 SDK 환경(예: 일부 ESP32 변종)에서는 skip — 위반으로
  //    간주하지 않음. 양산 라인은 production_provisioning.md §3 Step 5 절차로
  //    별도 burn 하므로 본 검사는 보조 확인 용도.
#if defined(ESP_EFUSE_DIS_PAD_JTAG)
  if (!efuseBit(ESP_EFUSE_DIS_PAD_JTAG)) {
    r.violationMask |= kBitJtagDisabled;
  }
#endif

  // 5) UART download mode disable
#if defined(ESP_EFUSE_DIS_DOWNLOAD_MODE)
  if (!efuseBit(ESP_EFUSE_DIS_DOWNLOAD_MODE)) {
    r.violationMask |= kBitDownloadModeDisabled;
  }
#endif

  // 6) factory seed 무결성. iconia_security 가 이미 형식까지 검증.
  //    본 검사는 lockdown 빌드의 begin() 에서 별도로도 수행되지만, 본 모듈은
  //    "통합 invariant" 의 일부로 한 번 더 평가하여 panic_log 한 줄에 통합.
  iconia::security::FactorySeed s = iconia::security::loadFactorySeed();
  bool seedOk = s.valid;
  iconia::security::zeroizeFactorySeed(s);
  if (!seedOk) {
    r.violationMask |= kBitFactorySeedValid;
  }

  // 7) secure_version (anti-rollback). 부트로더가 이미 단조 증가 비교를 수행
  //    하므로 일반 부팅이 여기 도달했다는 것 자체가 통과의 증거. 단, eFuse 가
  //    아직 burn 안 된 신규 모듈은 통과 — kSecureVersion 자체가 0이면 위반.
  if (iconia::config::kSecureVersion < 1) {
    r.violationMask |= kBitSecureVersionOk;
  }

  if (r.violationMask != 0) {
    r.pass = false;
    r.firstViolationBit = lowestBit(r.violationMask);
  }
  return r;
}

void recordPanicLog(uint16_t violationMask) {
  Preferences p;
  if (!p.begin(kPanicNs, false)) {
    return;
  }
  p.putUShort(kPanicKeyMask, violationMask);
  p.putUInt(kPanicKeyAt, (uint32_t)millis());
  p.end();
}

PanicLog loadPanicLog() {
  PanicLog out = {};
  Preferences p;
  if (!p.begin(kPanicNs, true)) {
    return out;
  }
  uint16_t mask = p.getUShort(kPanicKeyMask, 0);
  uint32_t at   = p.getUInt(kPanicKeyAt, 0);
  p.end();
  if (mask == 0) {
    return out;
  }
  out.present = true;
  out.violationMask = mask;
  out.recordedAtMs = at;
  return out;
}

void clearPanicLog() {
  Preferences p;
  if (!p.begin(kPanicNs, false)) {
    return;
  }
  p.remove(kPanicKeyMask);
  p.remove(kPanicKeyAt);
  p.end();
}

[[noreturn]] void haltForever() {
  // 다음 wake 가 같은 invariant 에 다시 걸리도록 EXT1 wakeup 도 disable.
  // 사용자가 충전기를 뽑았다 꽂는 등 외부 트리거에서만 부팅이 재시도되며,
  // 부팅 재시도 시 동일 검사가 다시 동작 → 약화된 모드 진입 불가능.
  delay(500);
  esp_sleep_disable_wakeup_source(ESP_SLEEP_WAKEUP_ALL);
  esp_deep_sleep_start();
  // unreachable
  while (true) { /* 컴파일러 안심용 */ }
}

}  // namespace boot_check
}  // namespace iconia
