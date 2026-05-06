// =============================================================================
// iconia_ota — 단계별 OTA telemetry + post-boot smoke check + 자동 롤백
// -----------------------------------------------------------------------------
// 본 모듈은 esp_https_ota 의 다운로드/플래시 자체는 변경하지 않는다.
// (그것은 iconia_app.cpp::performOta 가 계속 담당). 본 모듈이 책임지는 것:
//   1) 단계별 telemetry 7종 — manifest_received → ... → post_boot_health_ok/fail/rolled_back
//   2) 새 펌웨어 첫 부팅 시 post-boot smoke check 4항목
//   3) smoke check 실패 시 자동 롤백 트리거 (esp_ota_set_boot_partition)
//   4) 미전송 telemetry 의 RTC slow-mem 보존 (최대 5개) — 다음 부팅에 재전송
//
// 정본 — docs/operational_telemetry.md §7 OTA 7-stage telemetry
//
// 호출 그래프 (iconia_app.cpp 측 변경 최소):
//
//   begin()
//     ├─ ota::onBoot()                       // pending_verify 감지 + smoke 사이클 시작
//     │     └─ if pending: telemetry post_boot_health_pending
//     ├─ runEventFlow()
//     │     └─ uploadEventWithRetry() 성공
//     │           └─ ota::onSmokeCheckSuccess(camera_init_ok, wifi_ok, factory_ok)
//     │                 └─ if all 4 pass: esp_ota_mark_app_valid_cancel_rollback +
//     │                                     telemetry post_boot_health_ok
//     │                 └─ if N fails: esp_ota_set_boot_partition(prev) +
//     │                                  telemetry post_boot_health_fail +
//     │                                  ESP.restart()  (다음 부팅에서 rolled_back emit)
//     └─ enterDeepSleep()
//
//   performOta(...) (기존 함수 — 본 모듈은 hook 만 추가)
//     ├─ ota::onManifestReceived(...)        // 사이즈/sha 가드 통과 직후
//     ├─ ota::onDownloading(...)             // 청크 루프 중 1초마다
//     ├─ ota::onDownloadComplete(...)        // sha256 검증 결과 emit
//     └─ ota::onApplying()                   // esp_https_ota_finish 직전
//
// secure_version 정합:
//   - 서버 매니페스트의 target_secure_version 이 펌웨어 현재 kSecureVersion 이하면
//     iconia_compat::checkManifestSecureVersion 이 거절 → onManifestRejected 호출.
//   - eFuse SECURE_VERSION 후퇴는 ESP-IDF 부트로더가 강제 차단하므로
//     본 모듈이 수동 후퇴를 시도하는 코드 경로는 존재 X.
//
// 주의:
//   - 본 모듈은 시리얼 로그 + RTC slow-mem 큐 + 다음 부팅에 재전송 트리거 만 한다.
//     실제 HTTPS POST /ota-status 호출은 iconia_app.cpp 가 Wi-Fi up 상태에서 수행.
//     서버 endpoint 프로토콜 (필드명/JSON 스키마) 은 server 측이 정의 중 —
//     본 라운드는 telemetry record 만 enqueue, 실제 전송은 다음 라운드 합의 후.
// =============================================================================

#pragma once

#include <Arduino.h>
#include <stdint.h>

namespace iconia {
namespace ota {

// OTA 7-stage telemetry 라벨. server 측 ota-status endpoint 의 stage 필드와
// 1:1 정합. 변경 시 docs/operational_telemetry.md §7 + server 동시 갱신 필수.
//
// 영역:
//   0..3   : 다운로드 단계 (서버 매니페스트 수신 → 파티션 swap)
//   4..6   : post-boot 자가점검 단계
//   7      : 롤백 확정 (이전 partition 복귀 후)
enum class Stage : uint8_t {
  ManifestReceived       = 0,
  Downloading            = 1,
  DownloadComplete       = 2,
  Applying               = 3,
  PostBootHealthPending  = 4,
  PostBootHealthOk       = 5,
  PostBootHealthFail     = 6,
  RolledBack             = 7,
};

const char* stageLabel(Stage s);

// 단일 telemetry 항목. RTC slow-mem 에 마지막 5개 보존 — 네트워크 단절 시
// 다음 부팅의 첫 업로드 직후에 일괄 emit 가능.
//
// 본 구조는 RTC_DATA_ATTR 배열에 들어가므로 POD 만 사용. String 금지.
//
// 필드 의미:
//   stage              : 7단계 라벨
//   deploymentId       : 서버가 발급한 deployment id (해시 첫 8 hex char)
//   targetFwVerHash    : "1.2.3" semver 의 8B truncated FNV-1a hash
//   targetSecureVer    : 서버 매니페스트의 target_secure_version
//   bytesDone          : Downloading 단계에서만 의미. 그 외 0.
//   bytesTotal         : 전체 펌웨어 크기. 미정 시 0.
//   attemptNo          : 동일 deployment 의 N번째 시도 (1-based).
//   wifiRssiDbm        : 단계 emit 시점의 RSSI. 미연결 시 0.
//   batteryMv          : 단계 emit 시점의 배터리 mV.
//   smokeFailMask      : PostBootHealthFail 단계에서만 사용. 비트마스크 §SmokeBit.
//   shaMatch           : DownloadComplete 단계에서만 사용. true=일치.
//   recordedAtMs       : millis() 기준 emit 시각 (RTC slow-mem 의 millis 는
//                        부팅마다 0 reset 이지만 stage 순서 추론용으로 충분).
struct TelemetryRecord {
  uint8_t  stage;
  uint8_t  attemptNo;
  uint16_t smokeFailMask;
  uint32_t deploymentIdHash;
  uint32_t targetFwVerHash;
  uint32_t targetSecureVer;
  uint32_t bytesDone;
  uint32_t bytesTotal;
  int16_t  wifiRssiDbm;
  uint16_t batteryMv;
  uint8_t  shaMatch;          // 0/1
  uint8_t  reserved[3];
  uint32_t recordedAtMs;
};

// post-boot smoke check 4항목 비트마스크. 4개 모두 OK 여야 OTA 확정.
// 어느 비트가 실패했는지 telemetry 에 emit 하여 서버가 패턴 분석 가능.
enum SmokeBit : uint16_t {
  kSmokeBitBootInvariant   = 1u << 0,  // iconia_boot_check::runAll().pass
  kSmokeBitFactoryNvs      = 1u << 1,  // factory seed valid
  kSmokeBitCameraInit      = 1u << 2,  // 1회 camera init OK
  kSmokeBitWifiHandshake   = 1u << 3,  // 1회 Wi-Fi 연결 + 서버 200 응답
};

// 새 펌웨어 첫 부팅 시 smoke check 누적 시도 횟수 한계. 이 값에 도달해도
// kSmokeBitWifiHandshake 가 안 통과면 자동 롤백.
//
// 시나리오: 양산 라인 첫 페어링 시 사용자 환경에서 Wi-Fi AP 가 켜지기 전에
// 첫 부팅이 들어올 수 있으므로 1회로 끊지 말고 N회까지 허용. N 사이클 동안
// 다른 3개 (boot/factory/camera) 는 매번 통과해야 함.
static constexpr uint8_t kSmokeMaxAttempts = 3;

// =============================================================================
// 부팅 직후 진입점.
// =============================================================================
// pending_verify 파티션이면 smoke check 사이클 시작. RTC slow-mem 의 smoke
// 시도 카운터를 +1, 한계 도달 시 자동 롤백. 호출자(begin())는 본 함수가
// 반환한 후 일반 boot flow 계속 진행.
//
// 반환: true = 정상 boot 진행. false = 본 함수 내부에서 롤백 트리거 +
//      ESP.restart() 직전이라 호출자는 그대로 반환해야 함 (실제로는 restart
//      이후이므로 코드 흐름은 도달하지 않음).
bool onBoot();

// =============================================================================
// performOta() 단계별 hook.
// =============================================================================
// 모두 silent emit — 시리얼 로그 + RTC slow-mem record. 실제 HTTPS POST 는
// iconia_app.cpp 가 Wi-Fi up 상태에서 별도로 flush.
void onManifestReceived(const char* targetFwVer,
                        uint32_t    targetSecureVer,
                        uint32_t    bytesTotal,
                        uint8_t     attemptNo);

void onDownloading(uint32_t bytesDone,
                   uint32_t bytesTotal,
                   uint8_t  attemptNo,
                   int16_t  wifiRssiDbm,
                   uint16_t batteryMv);

void onDownloadComplete(bool     shaMatch,
                        uint8_t  attemptNo);

void onApplying(uint8_t attemptNo);

// 매니페스트 자체 거절 (anti-rollback / sha mismatch) — performOta 진입 전
// 가드 단계에서 호출. attemptNo 는 0 (시도 자체 무효).
void onManifestRejected(const char* reason,
                        const char* targetFwVer,
                        uint32_t    targetSecureVer);

// 부팅 직후 detectRollbackOnBoot 가 INVALID/ABORTED 상태를 감지했을 때 호출.
// 본 호출 시점은 이미 이전 partition 으로 복귀 + 정상 부팅 진행 중이므로,
// fwVerThatDied 는 NVS 의 ota_attempt_ver (= 자가점검 실패하여 롤백된 버전).
void onRolledBack(const char* fwVerThatDied);

// =============================================================================
// post-boot smoke check API.
// =============================================================================
// 호출자(iconia_app.cpp) 가 단계별로 호출. 본 모듈은 누적 mask 만 들고 다님.
//
// markBootInvariantOk / markFactoryOk : begin() 초기 단계에서 호출.
// markCameraInitOk                    : runEventFlow() 의 initCamera() 직후.
// markWifiHandshakeOk                 : uploadEventWithRetry() 첫 200 응답 후.
//
// finalizeIfPending: 위 4개 모두 누적되면 esp_ota_mark_app_valid_cancel_rollback
//                    + telemetry PostBootHealthOk emit.
// pending_verify 가 아니면 모든 mark 호출은 no-op.
void markBootInvariantOk();
void markFactoryOk();
void markCameraInitOk();
void markWifiHandshakeOk();
void finalizeIfPending();

// =============================================================================
// telemetry 큐 외부 접근 (iconia_app.cpp 가 Wi-Fi up 시 flush 책임).
// =============================================================================
// 본 라운드는 server 측 ota-status endpoint 스펙 미합의 — flush 함수는
// stub 으로만 노출. 실제 HTTPS 전송 본체는 다음 라운드.

// 큐에 보존된 미전송 record 수 (0..5).
uint8_t pendingRecordCount();

// 큐 N번째 record 사본 가져오기 (oldest-first). idx >= count 면 false.
bool getPendingRecord(uint8_t idx, TelemetryRecord* out);

// 서버가 ota-status 200 응답 회신했을 때 호출. 큐 비우기.
void clearPendingRecords();

}  // namespace ota
}  // namespace iconia
