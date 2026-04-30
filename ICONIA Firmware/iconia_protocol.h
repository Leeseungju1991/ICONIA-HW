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
// 모든 /api/event 요청에 항상 포함되는 펌웨어 자기보고 필드.
static constexpr const char* kFieldFirmwareVersion = "firmware_version";
static constexpr const char* kImageFileName = "event.jpg";
static constexpr const char* kImageContentType = "image/jpeg";

static constexpr const char* kTouchLeft = "left";
static constexpr const char* kTouchRight = "right";
static constexpr const char* kTouchNone = "none";

}  // namespace protocol
}  // namespace iconia
