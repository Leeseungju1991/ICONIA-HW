#pragma once

namespace iconia {
namespace protocol {

static constexpr const char* kApiPath = "/api/event";
static constexpr const char* kApiKeyHeader = "X-API-Key";
static constexpr const char* kCommandHeader = "X-ICONIA-Command";
static constexpr const char* kCommandEnterProvisioning = "enter_provisioning";

static constexpr const char* kFieldTouch = "touch";
static constexpr const char* kFieldDeviceId = "device_id";
static constexpr const char* kFieldBattery = "battery";
static constexpr const char* kFieldFirmwareVersion = "firmware_version";
static constexpr const char* kFieldImage = "image";
static constexpr const char* kImageFileName = "event.jpg";
static constexpr const char* kImageContentType = "image/jpeg";

static constexpr const char* kTouchLeft = "left";
static constexpr const char* kTouchRight = "right";
static constexpr const char* kTouchNone = "none";

}  // namespace protocol
}  // namespace iconia
