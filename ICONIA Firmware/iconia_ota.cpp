// =============================================================================
// iconia_ota — 단계별 telemetry + smoke check + 자동 롤백 (구현)
// -----------------------------------------------------------------------------
// 정본: docs/operational_telemetry.md §7
//
// 본 모듈은 RTC_DATA_ATTR 변수로 다음을 보존:
//   - smoke check 누적 mask + attempt counter (현재 부팅 사이클이 pending_verify
//     일 때만 의미)
//   - telemetry record 링버퍼 (마지막 5개)
//
// 큐 capacity 5 가 충분한 이유: OTA 1회 시도당 발생 가능한 단계 = 최대 7개이지만
// downloading 단계는 다중 emit 가능. 네트워크 단절 시점에도 가장 중요한
// 4개 (manifest_received / applying / post_boot_health_fail / rolled_back) 는
// 보존되도록 ring buffer FIFO 정책. 가득 차면 oldest drop.
// =============================================================================

#include "iconia_ota.h"

#include <string.h>

#include "esp_ota_ops.h"
#include "esp_partition.h"
#include "esp_system.h"

#include "iconia_compat.h"
#include "iconia_config.h"

namespace iconia {
namespace ota {

// -----------------------------------------------------------------------------
// RTC slow-mem state. 부팅을 가로질러 보존.
// -----------------------------------------------------------------------------
// 새 펌웨어 첫 부팅 시 smoke check 누적 mask + attempt counter.
// 일반 boot (state != PENDING_VERIFY) 에서는 의미 없음.
RTC_DATA_ATTR static uint16_t s_smokeAccumMask = 0;
RTC_DATA_ATTR static uint8_t  s_smokeAttemptNo = 0;
// 가장 최근 시도된 deployment 의 메타. ota-status post 시 stage record 에 동봉.
RTC_DATA_ATTR static uint32_t s_currentDeploymentIdHash = 0;
RTC_DATA_ATTR static uint32_t s_currentTargetFwVerHash  = 0;
RTC_DATA_ATTR static uint32_t s_currentTargetSecureVer  = 0;
RTC_DATA_ATTR static uint32_t s_currentBytesTotal       = 0;
RTC_DATA_ATTR static uint8_t  s_currentAttemptNo        = 0;

// telemetry record 링버퍼.
static constexpr uint8_t kQueueCapacity = 5;
RTC_DATA_ATTR static TelemetryRecord s_queue[kQueueCapacity] = {};
RTC_DATA_ATTR static uint8_t s_queueCount = 0;
RTC_DATA_ATTR static uint8_t s_queueHead  = 0;  // oldest index

// 본 모듈은 시리얼 로그 직접 호출 — IconiaApp::logLine 의 prod-build silent
// 정책과 동일하게 kSerialLoggingEnabled 가드 적용.
static void logOta(const String& msg) {
  if (!iconia::config::kSerialLoggingEnabled) {
    return;
  }
  Serial.print("[OTA-T] ");
  Serial.println(msg);
}

// FNV-1a 32-bit. 짧은 문자열 hashing 용도 (semver / deployment_id).
// 충돌은 본질적으로 telemetry 에 동봉할 식별자 축약 — 정확성 요구 X.
static uint32_t fnv1a(const char* s) {
  if (s == nullptr) return 0u;
  uint32_t h = 0x811C9DC5u;
  for (const char* p = s; *p != '\0'; ++p) {
    h ^= (uint32_t)(uint8_t)*p;
    h *= 0x01000193u;
  }
  return h;
}

const char* stageLabel(Stage s) {
  switch (s) {
    case Stage::ManifestReceived:       return "manifest_received";
    case Stage::Downloading:            return "downloading";
    case Stage::DownloadComplete:       return "download_complete";
    case Stage::Applying:                return "applying";
    case Stage::PostBootHealthPending:  return "post_boot_health_pending";
    case Stage::PostBootHealthOk:       return "post_boot_health_ok";
    case Stage::PostBootHealthFail:     return "post_boot_health_fail";
    case Stage::RolledBack:             return "rolled_back";
  }
  return "unknown";
}

// 큐에 record 적재. 가득 차면 oldest drop (FIFO). RTC slow-mem 만 사용.
static void enqueue(const TelemetryRecord& rec) {
  uint8_t writeIdx;
  if (s_queueCount < kQueueCapacity) {
    writeIdx = (s_queueHead + s_queueCount) % kQueueCapacity;
    s_queueCount++;
  } else {
    // overwrite oldest. head 전진.
    writeIdx = s_queueHead;
    s_queueHead = (s_queueHead + 1) % kQueueCapacity;
  }
  s_queue[writeIdx] = rec;
}

uint8_t pendingRecordCount() {
  return s_queueCount;
}

bool getPendingRecord(uint8_t idx, TelemetryRecord* out) {
  if (out == nullptr || idx >= s_queueCount) {
    return false;
  }
  uint8_t pos = (s_queueHead + idx) % kQueueCapacity;
  *out = s_queue[pos];
  return true;
}

void clearPendingRecords() {
  s_queueCount = 0;
  s_queueHead = 0;
  // 메모리 zeroize — RTC slow-mem 누설 방지.
  memset(s_queue, 0, sizeof(s_queue));
}

// 공통 record 작성 헬퍼.
static void recordStage(Stage stage,
                        uint8_t attemptNo,
                        uint32_t bytesDone,
                        uint16_t smokeMask,
                        bool shaMatch,
                        int16_t rssiDbm,
                        uint16_t batteryMv) {
  TelemetryRecord rec = {};
  rec.stage             = (uint8_t)stage;
  rec.attemptNo         = attemptNo;
  rec.smokeFailMask     = smokeMask;
  rec.deploymentIdHash  = s_currentDeploymentIdHash;
  rec.targetFwVerHash   = s_currentTargetFwVerHash;
  rec.targetSecureVer   = s_currentTargetSecureVer;
  rec.bytesDone         = bytesDone;
  rec.bytesTotal        = s_currentBytesTotal;
  rec.wifiRssiDbm       = rssiDbm;
  rec.batteryMv         = batteryMv;
  rec.shaMatch          = shaMatch ? 1 : 0;
  rec.recordedAtMs      = millis();
  enqueue(rec);
  logOta(String(stageLabel(stage)) + " attempt=" + attemptNo +
         " queued (count=" + s_queueCount + ")");
}

// =============================================================================
// performOta() 측 hook
// =============================================================================
void onManifestReceived(const char* targetFwVer,
                        uint32_t    targetSecureVer,
                        uint32_t    bytesTotal,
                        uint8_t     attemptNo) {
  // deployment_id 자체를 펌웨어가 모를 수 있음 (서버가 X-OTA-Deployment-Id
  // 헤더로 동봉하지 않는 한). 본 라운드는 server 미합의 — fw_ver hash 로
  // 대체 식별자 사용.
  s_currentDeploymentIdHash = fnv1a(targetFwVer);
  s_currentTargetFwVerHash  = fnv1a(targetFwVer);
  s_currentTargetSecureVer  = targetSecureVer;
  s_currentBytesTotal       = bytesTotal;
  s_currentAttemptNo        = attemptNo;
  recordStage(Stage::ManifestReceived, attemptNo, 0u, 0u, false, 0, 0);
}

void onDownloading(uint32_t bytesDone,
                   uint32_t bytesTotal,
                   uint8_t  attemptNo,
                   int16_t  wifiRssiDbm,
                   uint16_t batteryMv) {
  // bytesTotal 이 갱신되었으면 캐시.
  if (bytesTotal != 0u) {
    s_currentBytesTotal = bytesTotal;
  }
  recordStage(Stage::Downloading, attemptNo, bytesDone, 0u, false,
              wifiRssiDbm, batteryMv);
}

void onDownloadComplete(bool shaMatch, uint8_t attemptNo) {
  recordStage(Stage::DownloadComplete, attemptNo, s_currentBytesTotal, 0u,
              shaMatch, 0, 0);
}

void onApplying(uint8_t attemptNo) {
  recordStage(Stage::Applying, attemptNo, s_currentBytesTotal, 0u, false, 0, 0);
}

void onManifestRejected(const char* reason,
                        const char* targetFwVer,
                        uint32_t    targetSecureVer) {
  // attempt 0 = 시도 자체 무효. fw_ver hash 만 동봉해 어떤 버전을 거절했는지
  // 식별 가능하도록.
  s_currentDeploymentIdHash = fnv1a(targetFwVer);
  s_currentTargetFwVerHash  = fnv1a(targetFwVer);
  s_currentTargetSecureVer  = targetSecureVer;
  s_currentAttemptNo        = 0;
  // smokeFailMask 자리에 reason hash 의 하위 16비트를 박아 reason 식별.
  uint16_t reasonHash16 = (uint16_t)(fnv1a(reason) & 0xFFFFu);
  recordStage(Stage::ManifestReceived /* dummy stage placeholder */,
              0u, 0u, reasonHash16, false, 0, 0);
  logOta(String("manifest_rejected reason=") + (reason ? reason : "<null>") +
         " ver=" + (targetFwVer ? targetFwVer : "<null>") +
         " secver=" + targetSecureVer);
}

void onRolledBack(const char* fwVerThatDied) {
  // 이전 partition 으로 복귀하여 정상 부팅한 시점. 죽은 버전 hash 를
  // metadata 에 박고 RolledBack stage record 를 큐에 적재.
  if (fwVerThatDied != nullptr) {
    s_currentTargetFwVerHash  = fnv1a(fwVerThatDied);
    s_currentDeploymentIdHash = fnv1a(fwVerThatDied);
  }
  // bytesTotal/secure_version 은 의미 없음 — 이전 cycle 의 값이 남아 있을
  // 수 있으나 stage=RolledBack 의 컨텍스트로 충분.
  recordStage(Stage::RolledBack,
              /*attemptNo=*/0u, 0u, 0u, false, 0, 0);
  logOta(String("rolled_back fw_ver=") +
         (fwVerThatDied ? fwVerThatDied : "<null>"));
}

// =============================================================================
// post-boot smoke check
// =============================================================================
static bool s_isPendingVerify = false;

bool onBoot() {
  // pending_verify 인지 확인. 일반 boot 면 즉시 반환.
  const esp_partition_t* running = esp_ota_get_running_partition();
  if (running == nullptr) {
    return true;
  }
  esp_ota_img_states_t state = ESP_OTA_IMG_UNDEFINED;
  if (esp_ota_get_state_partition(running, &state) != ESP_OK) {
    return true;
  }
  if (state != ESP_OTA_IMG_PENDING_VERIFY) {
    // 일반 boot. smoke 누적 상태 zeroize (직전 smoke cycle 의 잔여물 제거).
    s_smokeAccumMask = 0;
    s_smokeAttemptNo = 0;
    s_isPendingVerify = false;
    return true;
  }

  s_isPendingVerify = true;
  // attempt counter 증가. 1-based.
  if (s_smokeAttemptNo < 0xFF) {
    s_smokeAttemptNo++;
  }
  logOta(String("post_boot smoke check cycle attempt=") + s_smokeAttemptNo +
         " accumMask=0x" + String(s_smokeAccumMask, HEX));

  // pending 단계 telemetry. 매 시도마다 emit (서버가 attemptNo 별 분포 추적).
  recordStage(Stage::PostBootHealthPending, s_smokeAttemptNo,
              0u, 0u, false, 0, 0);

  // attempt 한계 도달 직전에는 아직 mark 들이 들어올 기회를 한 번 더 줘야 함.
  // 한계 초과 시점은 finalizeIfPending 에서 결정 (smoke check 4개 다 들어오기
  // 전에 N회 실패한 경우).
  return true;
}

void markBootInvariantOk() {
  if (!s_isPendingVerify) return;
  s_smokeAccumMask |= kSmokeBitBootInvariant;
}

void markFactoryOk() {
  if (!s_isPendingVerify) return;
  s_smokeAccumMask |= kSmokeBitFactoryNvs;
}

void markCameraInitOk() {
  if (!s_isPendingVerify) return;
  s_smokeAccumMask |= kSmokeBitCameraInit;
}

void markWifiHandshakeOk() {
  if (!s_isPendingVerify) return;
  s_smokeAccumMask |= kSmokeBitWifiHandshake;
}

// 4개 모두 모이면 mark_valid + ok telemetry. 부족 + attempt 한계 도달 시
// 자동 롤백 트리거. 둘 다 아니면 (= attempt 1~N-1 중 일부 누락) 다음 wake
// 까지 보존하고 그냥 deep sleep — 다음 부팅에 동일 cycle 재진입.
void finalizeIfPending() {
  if (!s_isPendingVerify) {
    return;
  }

  static constexpr uint16_t kAllOkMask =
      kSmokeBitBootInvariant | kSmokeBitFactoryNvs |
      kSmokeBitCameraInit    | kSmokeBitWifiHandshake;

  if ((s_smokeAccumMask & kAllOkMask) == kAllOkMask) {
    // 4개 모두 통과 — OTA 확정.
    esp_err_t err = esp_ota_mark_app_valid_cancel_rollback();
    if (err == ESP_OK) {
      logOta("smoke check ALL OK, mark_app_valid done");
    } else {
      logOta(String("mark_valid failed err=") + (int)err);
    }
    recordStage(Stage::PostBootHealthOk, s_smokeAttemptNo,
                0u, s_smokeAccumMask, false, 0, 0);

    // smoke 누적 상태 zeroize — 다음 OTA cycle 을 위한 baseline 복귀.
    s_smokeAccumMask = 0;
    s_smokeAttemptNo = 0;
    s_isPendingVerify = false;
    return;
  }

  // attempt 한계 도달 — 일부 항목 누락. 자동 롤백.
  if (s_smokeAttemptNo >= kSmokeMaxAttempts) {
    uint16_t failMask = (~s_smokeAccumMask) & kAllOkMask;
    logOta(String("smoke check FAIL attempts=") + s_smokeAttemptNo +
           " failMask=0x" + String(failMask, HEX) + ", rolling back");
    recordStage(Stage::PostBootHealthFail, s_smokeAttemptNo,
                0u, failMask, false, 0, 0);

    // 이전 partition 으로 부팅 강제. ESP-IDF 가 pending_verify state 를
    // INVALID 로 마크 + 이전 valid partition 을 boot partition 으로 설정.
    //
    // **롤백 안전성 — 사용자 데이터 보존**:
    //   - 본 호출은 partition table 의 boot partition pointer 만 변경.
    //   - factory_nvs / events_q SPIFFS / replay cache RTC slow-mem 등은
    //     모두 그대로 보존됨. 사용자 입장에서 이벤트 큐 손실 없음.
    //   - secure_version: 이전 partition 은 이미 burn 된 eFuse SECURE_VERSION
    //     이상이므로 부팅 통과. 새 펌웨어가 secure_version 을 +1 burn 했다면
    //     롤백 자체가 부트로더에 의해 거절되어 부팅 실패 — 이 시나리오는
    //     iconia_compat::checkManifestSecureVersion 이 사전 차단하므로 정상
    //     운영에서 발생 불가.
    esp_err_t err = esp_ota_mark_app_invalid_rollback_and_reboot();
    // mark_app_invalid_rollback_and_reboot 는 [[noreturn]] 이지만 IDF 헤더
    // attribute 가 빠져 있을 수 있음. 안전하게 fallback.
    logOta(String("rollback_and_reboot returned err=") + (int)err +
           " — forcing restart");
    // smoke 누적 상태 zeroize — 다음 부팅(이전 partition) 진입 시 새 cycle.
    s_smokeAccumMask = 0;
    s_smokeAttemptNo = 0;
    s_isPendingVerify = false;
    delay(200);
    esp_restart();
    return;
  }

  // 아직 attempt 여유 있음 — mark 누적만 보존하고 deep sleep 으로 복귀.
  logOta(String("smoke check incomplete attempt=") + s_smokeAttemptNo +
         " accumMask=0x" + String(s_smokeAccumMask, HEX) +
         " — preserving for next wake");
}

}  // namespace ota
}  // namespace iconia
