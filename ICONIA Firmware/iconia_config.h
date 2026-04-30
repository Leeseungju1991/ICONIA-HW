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
// 권장 흐름 — Build Profiles (./build.sh dev | prod):
//   매크로 정본은 build_profiles/dev.h / prod.h 에 박아 두고, 빌드 스크립트
//   (build.sh / build.bat) 가 선택된 profile 을 sketch 폴더의 build_opt.h 로
//   복사한다. build_opt.h 는 .gitignore 대상.
//   상세: ICONIA Firmware/build_profiles/README.md 참조.
//
// 수동(프로파일 미사용) 절차도 호환:
//   Arduino IDE (1.x / 2.x):
//     Create a sibling file `build_opt.h` in the sketch folder containing:
//       -DICONIA_API_ENDPOINT="\"https://api.iconia.example.com/api/event\""
//       -DICONIA_API_KEY="\"<32+ char random key from secrets manager>\""
//       -DICONIA_CERT_FP_SHA1="\"AA:BB:...:99\""   // optional, see below
//     The Arduino build system reads `build_opt.h` automatically (since core
//     1.6.x). Do NOT commit this file.
//
//   arduino-cli:
//     arduino-cli compile \
//       --build-property "build.extra_flags=\
//         -DICONIA_API_ENDPOINT=\\\"https://...\\\" \
//         -DICONIA_API_KEY=\\\"...\\\""
//
//   PlatformIO equivalent (if migrated later):
//     build_flags = -DICONIA_API_KEY="\"...\""
// -----------------------------------------------------------------------------

// Production endpoint. Final value is loaded from NVS (key: "api_endpoint") at
// boot; this constant is only the bring-up fallback when NVS is empty.
#ifdef ICONIA_API_ENDPOINT
static constexpr const char* kApiEndpoint = ICONIA_API_ENDPOINT;
#else
static constexpr const char* kApiEndpoint = "https://api.example.com/api/event";
#endif

// SECURITY: do NOT ship a real API key in source. Production key is provisioned
// into encrypted NVS (key: "api_key") via the BLE provisioning channel or
// factory flashing. The placeholder below is intentionally invalid; the boot
// guard refuses to run if it survives into the binary.
#ifdef ICONIA_API_KEY
static constexpr const char* kApiKey = ICONIA_API_KEY;
#else
static constexpr const char* kApiKey = "REPLACE_WITH_API_KEY";
#endif

// Sentinel literals checked at boot. Keep in sync with the #else fallbacks
// above. Any of these surviving into a flashed binary halts the device.
static constexpr const char* kPlaceholderApiKey1 = "REPLACE_WITH_API_KEY";
static constexpr const char* kPlaceholderApiKey2 = "CHANGE_ME_LONG_RANDOM_DEVICE_KEY";
static constexpr const char* kPlaceholderEndpoint = "https://api.example.com/api/event";

// -----------------------------------------------------------------------------
// Firmware version (semver). 서버에 매 /api/event 요청마다 firmware_version
// 필드로 보고됨. OTA 후 자가 점검(첫 정상 업로드 성공) 시점에서 새 버전이
// 서버 로그에 노출됨으로써 롤아웃 진척을 추적할 수 있다.
//
// placeholder("0.0.0-placeholder")는 부팅 가드로 차단된다. factory flash
// 또는 빌드 매크로로 반드시 실제 버전을 주입해야 한다:
//   -DICONIA_FIRMWARE_VERSION="\"1.0.0\""
// -----------------------------------------------------------------------------
#ifdef ICONIA_FIRMWARE_VERSION
static constexpr const char* kFirmwareVersion = ICONIA_FIRMWARE_VERSION;
#else
static constexpr const char* kFirmwareVersion = "0.0.0-placeholder";
#endif
static constexpr const char* kPlaceholderFirmwareVersion = "0.0.0-placeholder";

// Set the production root CA at flashing time (or load from NVS).
static constexpr const char* kServerRootCaPem = R"PEM(

)PEM";

// S3 presigned URL용 별도 root CA. Amazon Trust Services 체인이 server
// 엔드포인트 발급 CA와 다를 수 있으므로 분리. 운영에서는 빌드 시점에
// AmazonRootCA1.pem 등을 매크로로 주입한다:
//   -DICONIA_S3_ROOT_CA_PEM="\"-----BEGIN CERTIFICATE-----\\n...\""
// 비어 있으면 OTA 진입 자체가 거부된다(setInsecure 폴백 금지).
#ifdef ICONIA_S3_ROOT_CA_PEM
static constexpr const char* kS3RootCaPem = ICONIA_S3_ROOT_CA_PEM;
#else
static constexpr const char* kS3RootCaPem = R"PEM(

)PEM";
#endif

// 운영 가드: kS3RootCaPem이 비어 있는 상태에서 OTA를 시도하면 업로드된
// 펌웨어 무결성을 보장할 수 없으므로 거부. ICONIA_ALLOW_INSECURE_OTA=1을
// 명시한 경우에만 setInsecure 허용(개발 bring-up 전용).
#ifdef ICONIA_ALLOW_INSECURE_OTA
static constexpr bool kAllowInsecureOtaWhenRootCaMissing = (ICONIA_ALLOW_INSECURE_OTA != 0);
#else
static constexpr bool kAllowInsecureOtaWhenRootCaMissing = false;
#endif

// OTA 진입 가드 임계값.
// - 배터리 50% 이상에서만 시도 (다운로드+플래시 + 자가점검 부팅 = 200mA 수준이
//   수십 초 지속, 잔량 부족 시 중단되면 롤백 파티션 부팅 → 재시도 루프 위험)
// - RSSI -75 dBm 보다 좋아야 시도 (TLS 다운로드 도중 끊기면 불완전 펌웨어 위험)
static constexpr int kBatteryOtaMinPercent = 50;
static constexpr int kRssiOtaMinDbm = -75;

// OTA 다운로드/플래시 동안 임시로 늘리는 watchdog timeout.
// 1.5MB 펌웨어 + 느린 Wi-Fi(~200kbps)에서 60초가 안전 마진.
// OTA 종료 후 kWatchdogDefaultTimeoutMs로 복귀.
static constexpr uint32_t kWatchdogOtaTimeoutMs = 60000;
static constexpr uint32_t kWatchdogDefaultTimeoutMs = 30000;

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

static constexpr int kTouchRightGpio = 13;
static constexpr int kTouchLeftGpio = 14;
static constexpr int kTouchActiveLevel = HIGH;

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

static constexpr const char* kBleServiceUuid = "48f1f79e-817d-4105-a96f-4e2d2d6031e0";
static constexpr const char* kBleSsidCharUuid = "48f1f79e-817d-4105-a96f-4e2d2d6031e1";
static constexpr const char* kBlePasswordCharUuid = "48f1f79e-817d-4105-a96f-4e2d2d6031e2";
static constexpr const char* kBleStatusCharUuid = "48f1f79e-817d-4105-a96f-4e2d2d6031e3";

// AI Thinker ESP32-CAM pin map
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
