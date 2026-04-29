#pragma once

#include <Arduino.h>
#include "esp_camera.h"

namespace iconia {
namespace config {

// -----------------------------------------------------------------------------
// Build-time secret injection
// -----------------------------------------------------------------------------
// All sensitive constants below MUST be supplied at compile time via build
// macros, never edited inline in source. The placeholder defaults are kept so
// the file still compiles in a fresh checkout, but a runtime guard in
// IconiaApp::begin() halts the device if a placeholder is detected at boot.
//
// Arduino IDE (1.x / 2.x):
//   Create a sibling file `build_opt.h` in the sketch folder containing:
//     -DICONIA_API_ENDPOINT="\"https://api.iconia.example.com/api/event\""
//     -DICONIA_API_KEY="\"<32+ char random key from secrets manager>\""
//     -DICONIA_CERT_FP_SHA1="\"AA:BB:...:99\""   // optional, see below
//   The Arduino build system reads `build_opt.h` automatically (since core
//   1.6.x). Do NOT commit this file.
//
// arduino-cli:
//   arduino-cli compile \
//     --build-property "build.extra_flags=\
//       -DICONIA_API_ENDPOINT=\\\"https://...\\\" \
//       -DICONIA_API_KEY=\\\"...\\\""
//
// PlatformIO equivalent (if migrated later):
//   build_flags = -DICONIA_API_KEY="\"...\""
// -----------------------------------------------------------------------------

// AWS Route53 domain -> EC2 HTTPS endpoint. The server implements POST /api/event.
// Production endpoint is loaded from NVS (key: "api_endpoint") at boot; this
// constant is only the bring-up fallback when NVS is empty.
#ifdef ICONIA_API_ENDPOINT
static constexpr const char* kApiEndpoint = ICONIA_API_ENDPOINT;
#else
static constexpr const char* kApiEndpoint = "https://api.example.com/api/event";
#endif

// SECURITY: do NOT ship a real API key in source. The production key is
// provisioned into encrypted NVS (key: "api_key") via BLE provisioning or
// factory flashing. The placeholder below is intentionally invalid; the boot
// guard refuses to run if it survives into the binary.
#ifdef ICONIA_API_KEY
static constexpr const char* kApiKey = ICONIA_API_KEY;
#else
static constexpr const char* kApiKey = "CHANGE_ME_LONG_RANDOM_DEVICE_KEY";
#endif

// Sentinel literals checked at boot. Keep in sync with the #else fallbacks
// above. Any of these surviving into a flashed binary halts the device.
static constexpr const char* kPlaceholderApiKey1 = "REPLACE_WITH_API_KEY";
static constexpr const char* kPlaceholderApiKey2 = "CHANGE_ME_LONG_RANDOM_DEVICE_KEY";
static constexpr const char* kPlaceholderEndpoint = "https://api.example.com/api/event";

static constexpr const char* kFirmwareVersion = "ICONIA_FW_1.2.0";

// Put the production root CA here at flashing time (or load from NVS).
static constexpr const char* kServerRootCaPem = R"PEM(

)PEM";

// SECURITY: must be false in production. setInsecure() disables certificate
// validation and exposes the device to MITM. Override at compile time only
// for bring-up: -DICONIA_ALLOW_INSECURE_TLS=1
#ifdef ICONIA_ALLOW_INSECURE_TLS
static constexpr bool kAllowInsecureTlsWhenRootCaMissing = (ICONIA_ALLOW_INSECURE_TLS != 0);
#else
static constexpr bool kAllowInsecureTlsWhenRootCaMissing = false;
#endif

// Optional fingerprint pinning of the server leaf certificate. Used as a
// defense-in-depth layer ON TOP OF setCACert(); does not replace it.
//
// ESP32 Arduino core 3.x uses mbedTLS (not BearSSL), so we pin via the
// post-handshake hooks. Two formats supported:
//
//   kServerCertFingerprintSha1 — 40 hex chars ":" separated, e.g.
//     "AA:BB:CC:...:99". Verified against the connected peer with
//     NetworkClientSecure::verify(fingerprint, host).
//   kServerCertSpkiSha256B64   — 32-byte SPKI SHA-256 in 44-char base64.
//     Verified with our own helper using getPeerCertificate() and the
//     mbedtls_md_* API. Stronger than leaf-cert SHA-1; survives leaf
//     rotation as long as the public key is reused.
//
// Rotation: when the server certificate or key is renewed (ACM rotates leaf
// cert every ~13 months by default; key only on opt-in rotation), the new
// fingerprint must be flashed. Plan the OTA/factory-flash schedule to
// overlap with the cert rotation window.
#ifdef ICONIA_CERT_FP_SHA1
static constexpr const char* kServerCertFingerprintSha1 = ICONIA_CERT_FP_SHA1;
#else
static constexpr const char* kServerCertFingerprintSha1 = "";
#endif

// -----------------------------------------------------------------------------
// BLE Secure provisioning (opt-in)
// -----------------------------------------------------------------------------
// When enabled, the SSID/password characteristics require an encrypted MITM-
// protected link (Just Works secure connections, ESP_LE_AUTH_REQ_SC_MITM_BOND).
// Default is OFF because the current RN app pairs without bonding; flipping
// this on without a coordinated app update breaks first-time setup.
//
// Enable after rn-mobile aligns the pairing UX:
//   -DICONIA_BLE_SECURE=1
// -----------------------------------------------------------------------------
#ifdef ICONIA_BLE_SECURE
static constexpr bool kBleSecureMode = (ICONIA_BLE_SECURE != 0);
#else
static constexpr bool kBleSecureMode = false;
#endif

// Provisioning nonce TTL (matches the 2-min advertising window). The app must
// echo back the current nonce inside the SSID payload (or a dedicated char)
// once secure mode is on; replays beyond this window are rejected.
static constexpr uint32_t kBleNonceTtlMs = 120000;

// -----------------------------------------------------------------------------
// Production logging
// -----------------------------------------------------------------------------
// Verbose Serial.print() leaks SSID, partial credentials, device ID, IP, and
// command headers over UART. For shipping firmware:
//   -DICONIA_PRODUCTION_BUILD=1
// silences logLine() and skips Serial.begin() entirely. Bring-up builds keep
// the default (verbose).
// -----------------------------------------------------------------------------
#ifdef ICONIA_PRODUCTION_BUILD
static constexpr bool kSerialLoggingEnabled = (ICONIA_PRODUCTION_BUILD == 0);
#else
static constexpr bool kSerialLoggingEnabled = true;
#endif

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

// BLE advertising interval (units of 0.625 ms). 2048 = 1280 ms, balances
// discoverability with current draw during the 2-min provisioning window.
static constexpr uint16_t kBleAdvIntervalMin = 2048;
static constexpr uint16_t kBleAdvIntervalMax = 4096;  // 2560 ms ceiling

// Battery ADC oversampling. Higher = less noise but longer wake time.
static constexpr int kBatteryAdcSampleCount = 16;

// CPU frequency profile. Active networking uses 240 MHz; everything else
// runs at 80 MHz to cut current. ESP-IDF DFS is not used because Arduino
// core does not configure pm_config by default.
static constexpr uint32_t kCpuFrequencyActiveMhz = 240;
static constexpr uint32_t kCpuFrequencyIdleMhz = 80;

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
