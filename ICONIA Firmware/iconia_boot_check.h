// =============================================================================
// iconia_boot_check — prod 빌드 부팅 시 보안 invariant 강제
// -----------------------------------------------------------------------------
// PROD 빌드에서만 동작. DEV 빌드는 모든 검사가 즉시 통과 (디버깅 가능 유지).
// 본 모듈이 검증하는 invariant 는 docs/security_handshake.md / production_provisioning.md
// 에 정의된 출시 차단 항목과 1:1 정합.
//
// 검증 항목 (모두 통과해야 정상 boot)
//   1) ICONIA_PRODUCTION_BUILD == 1   (매크로 자체)
//   2) eFuse SECURE_BOOT_EN           (esp_secure_boot_enabled())
//   3) eFuse FLASH_ENCRYPTION RELEASE (esp_flash_encryption_enabled() + RELEASE 모드)
//   4) eFuse DIS_PAD_JTAG / DIS_USB_JTAG
//   5) eFuse DIS_DOWNLOAD_MODE        (RELEASE 한정)
//   6) factory_nvs partition 마운트 + seed 무결성 (loadFactorySeed.valid)
//   7) secure_version >= ICONIA_SECURE_VERSION (anti-rollback)
//
// 하나라도 실패 시
//   - panic_log (NVS 네임스페이스 "panic", 키 "boot_inv") 에 위반 코드 + 시각 기록
//   - deep sleep 진입 (EXT1 wakeup disable → 다음 wake 도 동일 검사 강제)
//   - 펌웨어가 약화된 모드로 절대 동작하지 않음
//
// 위반 telemetry
//   - "다음 성공 업로드" 또는 "BLE 진단 char" 에 panic_log 동봉. 본 라운드는
//     서버 telemetry 페어로 emit (필드 정의: docs/operational_telemetry.md §4).
// =============================================================================

#pragma once

#include <Arduino.h>
#include <stdint.h>

namespace iconia {
namespace boot_check {

// 단일 invariant 의 코드 (panic_log 비트마스크 + telemetry).
// 0x00 = OK, 그 외는 위반 비트.
enum InvariantBit : uint16_t {
  kBitProductionBuildMacro    = 1u << 0,  // 0x0001
  kBitSecureBootEnabled       = 1u << 1,  // 0x0002
  kBitFlashEncryptionRelease  = 1u << 2,  // 0x0004
  kBitJtagDisabled            = 1u << 3,  // 0x0008
  kBitDownloadModeDisabled    = 1u << 4,  // 0x0010
  kBitFactorySeedValid        = 1u << 5,  // 0x0020
  kBitSecureVersionOk         = 1u << 6,  // 0x0040
};

// 검증 결과. violationMask == 0 이면 모두 통과.
struct Result {
  bool     pass;
  uint16_t violationMask;       // 위반 비트 OR
  // 위반이 있을 때만 의미 있는 첫 위반 코드(가장 낮은 비트의 단일 InvariantBit).
  // 시리얼 로그/panic_log 헤드라인 용도.
  uint16_t firstViolationBit;
};

// PROD 빌드에서 본 함수가 모든 검증을 수행. DEV 빌드는 즉시 pass=true 반환.
//
// 호출자(begin()) 는 결과를 보고 다음 분기:
//   - pass == true  → 일반 boot 진행
//   - pass == false → recordPanicLog + deepSleepWithoutWakeup() 로 영구 차단
Result runAll();

// 위반 발생 시 NVS 에 기록. 다음 성공 업로드에 동봉되어 운영 추적이 가능.
// keyspace: namespace="panic", key="boot_inv" (uint16), key="boot_inv_at" (uint32 ms).
void recordPanicLog(uint16_t violationMask);

// 직전 boot 에서 기록된 panic_log 를 NVS 에서 로드. 없으면 mask=0.
// 호출자(서버 multipart) 가 telemetry 필드로 동봉 후 clearPanicLog() 호출.
struct PanicLog {
  bool     present;
  uint16_t violationMask;
  uint32_t recordedAtMs;
};
PanicLog loadPanicLog();
void clearPanicLog();

// 위반 시 호출되는 fatal 분기. EXT1 wakeup disable + 즉시 deep sleep.
// 본 함수는 절대 반환하지 않는다.
[[noreturn]] void haltForever();

}  // namespace boot_check
}  // namespace iconia
