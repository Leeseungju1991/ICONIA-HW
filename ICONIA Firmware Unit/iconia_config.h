#pragma once

#include <Arduino.h>
#include "esp_camera.h"

namespace iconia {
namespace config {

// AWS Route53 domain -> EC2 HTTPS endpoint. The server implements POST /api/event.
static constexpr const char* kApiEndpoint = "https://api.example.com/api/event";

// Must match server/.env DEVICE_API_KEY.
static constexpr const char* kApiKey = "CHANGE_ME_LONG_RANDOM_DEVICE_KEY";
static constexpr const char* kFirmwareVersion = "ICONIA_FW_1.2.0";

// Put the production root CA here. During hardware bring-up only, insecure TLS can be allowed.
static constexpr const char* kServerRootCaPem = R"PEM(

)PEM";

static constexpr bool kAllowInsecureTlsWhenRootCaMissing = true;

// Two independent capacitive touch IC outputs. Must be RTC GPIO pins for EXT1 wakeup.
static constexpr int kTouchRightGpio = 13;
static constexpr int kTouchLeftGpio = 14;
static constexpr int kTouchActiveLevel = HIGH;

// ADC1 battery input through resistor divider.
static constexpr int kBatteryAdcPin = 33;
static constexpr float kBatteryAdcReferenceV = 3.3f;
static constexpr float kBatteryDividerRatio = 2.0f;
static constexpr float kBatteryEmptyV = 3.30f;
static constexpr float kBatteryFullV = 4.20f;
static constexpr int kBatteryCriticalPercent = 5;

static constexpr int kLedGpio = 4;
static constexpr int kCameraPowerDownGpio = 32;

static constexpr uint32_t kTouchDebounceMs = 2000;
static constexpr uint32_t kProvisioningTimeoutMs = 120000;
static constexpr uint32_t kWifiConnectTimeoutMs = 15000;
static constexpr uint32_t kServerResponseTimeoutMs = 20000;
static constexpr uint8_t kWifiRetryCount = 3;
static constexpr uint8_t kUploadRetryCount = 3;
static constexpr framesize_t kCaptureFrameSize = FRAMESIZE_VGA;
static constexpr int kCaptureJpegQuality = 12;

static constexpr const char* kMultipartBoundary = "----ICONIABoundary7d9f1c";

// BLE GATT provisioning: app writes SSID/password once; firmware stores them in NVS.
static constexpr const char* kBleServiceUuid = "48f1f79e-817d-4105-a96f-4e2d2d6031e0";
static constexpr const char* kBleSsidCharUuid = "48f1f79e-817d-4105-a96f-4e2d2d6031e1";
static constexpr const char* kBlePasswordCharUuid = "48f1f79e-817d-4105-a96f-4e2d2d6031e2";
static constexpr const char* kBleStatusCharUuid = "48f1f79e-817d-4105-a96f-4e2d2d6031e3";

// AI Thinker ESP32-CAM / OV2640 pin map. Replace with the final PCB pinout.
static constexpr int kPwdnGpio = 32;
static constexpr int kResetGpio = -1;
static constexpr int kXclkGpio = 0;
static constexpr int kSiodGpio = 26;
static constexpr int kSiocGpio = 27;
static constexpr int kY9Gpio = 35;
static constexpr int kY8Gpio = 34;
static constexpr int kY7Gpio = 39;
static constexpr int kY6Gpio = 36;
static constexpr int kY5Gpio = 21;
static constexpr int kY4Gpio = 19;
static constexpr int kY3Gpio = 18;
static constexpr int kY2Gpio = 5;
static constexpr int kVsyncGpio = 25;
static constexpr int kHrefGpio = 23;
static constexpr int kPclkGpio = 22;

}  // namespace config
}  // namespace iconia
