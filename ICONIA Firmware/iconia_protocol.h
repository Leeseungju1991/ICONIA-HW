#pragma once

namespace iconia {
namespace protocol {

static constexpr const char* kApiPath = "/api/event";
static constexpr const char* kApiKeyHeader = "X-API-Key";
static constexpr const char* kCommandHeader = "X-ICONIA-Command";
static constexpr const char* kCommandEnterProvisioning = "enter_provisioning";
static constexpr const char* kCommandOta = "ota";

// OTA-related response headers (서버가 ota 명령과 함께 동봉).
// 계약: aws-infra와 합의된 정확한 헤더명. 절대 임의 변경 금지.
static constexpr const char* kOtaUrlHeader = "X-OTA-Url";
static constexpr const char* kOtaSha256Header = "X-OTA-Sha256";
static constexpr const char* kOtaVersionHeader = "X-OTA-Version";
static constexpr const char* kOtaSizeHeader = "X-OTA-Size";

static constexpr const char* kFieldTouch = "touch";
static constexpr const char* kFieldDeviceId = "device_id";
static constexpr const char* kFieldBattery = "battery";
static constexpr const char* kFieldImage = "image";
// 멱등성 키. 동일 wake에서 재시도 시 같은 값을 유지하여 서버 측 dedup이 가능
// 하도록 함. 형식: "<deviceMacNoColons>-<wakeMs>-<rand4hex>" (총 ~26자).
// 서버 합의는 별도 작업 — 본 펌웨어는 매 요청에 항상 emit.
static constexpr const char* kFieldEventId = "event_id";
// 모든 /api/event 요청에 항상 포함되는 펌웨어 자기보고 필드.
static constexpr const char* kFieldFirmwareVersion = "firmware_version";
// 직전 OTA 시도 결과 보고 필드(옵션 페어). 보고할 결과가 없으면 두 필드 모두
// multipart에서 생략. 한 쪽만 있으면 서버가 무시하므로 항상 페어로 emit.
// aws-infra와 합의된 정확한 필드명. 절대 임의 변경 금지.
static constexpr const char* kFieldLastOtaResult = "last_ota_result";
static constexpr const char* kFieldLastOtaAttemptedVersion = "last_ota_attempted_version";
static constexpr const char* kImageFileName = "event.jpg";
static constexpr const char* kImageContentType = "image/jpeg";

static constexpr const char* kTouchLeft = "left";
static constexpr const char* kTouchRight = "right";
static constexpr const char* kTouchNone = "none";

// last_ota_result enum 화이트리스트. 서버가 metric 차원으로 그대로 사용하므로
// 새 값 추가 시 aws-infra와 동시 합의 필요. 빈 문자열/그 외 값은 절대 emit X.
static constexpr const char* kOtaResultSuccess = "success";
static constexpr const char* kOtaResultShaMismatch = "sha_mismatch";
static constexpr const char* kOtaResultDownloadFailed = "download_failed";
static constexpr const char* kOtaResultFlashFailed = "flash_failed";
static constexpr const char* kOtaResultRolledBack = "rolled_back";
static constexpr const char* kOtaResultVersionRejected = "version_rejected";

}  // namespace protocol
}  // namespace iconia
