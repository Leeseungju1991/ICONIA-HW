#pragma once

#include <Arduino.h>
#include <Preferences.h>
#include <WiFi.h>
#include <WiFiClientSecure.h>
#include <BLE2902.h>
#include <BLEDevice.h>
#include <BLEServer.h>
#include <BLEUtils.h>

#include "esp_camera.h"

class ProvisioningServerCallbacks;
class SsidCallbacks;
class PasswordCallbacks;

class IconiaApp {
 public:
  void begin();
  void loop();

 private:
  enum class DeviceMode : uint8_t {
    Idle,
    Provisioning,
    EventFlow,
  };

  enum class TouchDirection : uint8_t {
    None,
    Right,
    Left,
  };

  enum class NextAction : uint8_t {
    None,
    EnterProvisioning,
    Ota,
  };

  // 서버가 ota 명령과 함께 동봉한 헤더 묶음. 진입 가드 통과 시에만 실제 사용.
  // url은 S3 presigned(쿼리 파라미터에 서명 포함, 5분 TTL). 로깅 시 호스트만
  // 노출하고 쿼리는 마스킹할 것.
  struct OtaCommand {
    String url;
    String sha256;     // 소문자 hex 64자
    String version;    // semver, sanity/log 용도
    int64_t sizeBytes; // 선택. -1이면 미지정.
    bool present;
  };

  struct WifiCredentials {
    String ssid;
    String password;
    bool valid;
  };

  struct BatteryStatus {
    bool configured;
    bool valid;
    uint16_t raw;
    float pinVoltage;
    float batteryVoltage;
    int percent;
  };

  struct EventPayload {
    char deviceId[18];
    const char* touch;
    int batteryPercent;
    const uint8_t* imageData;
    size_t imageLen;
  };

  struct UploadResult {
    bool success;
    NextAction nextAction;
    OtaCommand ota;
  };

  struct ParsedUrl {
    String host;
    String path;
    uint16_t port;
    bool valid;
  };

  void logLine(const String& message);
  static int clampPercent(int value);

  bool openPreferences();
  WifiCredentials loadWifiCredentials();
  bool saveWifiCredentials(const String& ssid, const String& password);
  void clearWifiCredentials();

  void initBatteryMonitor();
  BatteryStatus readBatteryStatus();

  camera_config_t buildCameraConfig();
  bool initCamera();
  void deinitCamera();
  camera_fb_t* captureImage();

  uint64_t touchWakeMask() const;
  TouchDirection touchDirectionFromWake() const;
  void enterDeepSleep();

  void buildDeviceId(char* outBuffer, size_t outBufferLen) const;
  String bleDeviceName() const;
  static const char* touchToString(TouchDirection direction);

  ParsedUrl parseHttpsUrl(const char* url) const;
  bool connectToWifi(const WifiCredentials& creds);
  bool connectToWifiWithRetry(const WifiCredentials& creds, uint8_t retryCount);
  bool configureSecureClient(WiFiClientSecure& client);

  static bool writeAll(WiFiClient& client, const uint8_t* data, size_t len);
  static bool readLine(WiFiClientSecure& client, char* buffer, size_t bufferSize);
  static char* skipSpaces(char* text);
  static void trimRight(char* text);
  static bool lineHasReprovisionCommand(const char* text);
  static size_t multipartTextFieldLength(const char* boundary, const char* fieldName, const char* fieldValue);
  static size_t multipartImageHeaderLength(const char* boundary, const char* fieldName, const char* fileName);
  static bool writeMultipartTextField(WiFiClient& client, const char* boundary, const char* fieldName, const char* fieldValue);
  static bool writeMultipartImageHeader(WiFiClient& client, const char* boundary, const char* fieldName, const char* fileName);

  UploadResult readHttpResponseAndCommand(WiFiClientSecure& client);
  UploadResult postEventMultipart(const EventPayload& payload);
  UploadResult uploadEventWithRetry(const EventPayload& payload);

  void notifyProvisioningStatus(const String& status);
  void startProvisioningBle();
  void stopProvisioningBle();
  void handleProvisioningAttempt();

  // Boot-time guards
  bool placeholderSecretsPresent() const;
  void haltOnPlaceholderSecrets();

  // OTA 클라이언트 (esp_https_ota 기반).
  // performOta: presigned URL 다운로드 → SHA-256 검증 → 듀얼 파티션 플래시.
  //             성공 반환 후 호출자는 ESP.restart() 해야 함.
  // canEnterOta: 가드 사전 검사(배터리/RSSI/계약 헤더 형식). 미달 사유 로깅.
  // sanitizeUrlForLog: presigned URL의 쿼리(서명) 마스킹.
  // markAppValidIfPending: pending_verify 파티션이면 자가점검 통과 표시.
  bool canEnterOta(const OtaCommand& ota, int batteryPercent, int rssiDbm) const;
  bool performOta(const OtaCommand& ota);
  String sanitizeUrlForLog(const String& url) const;
  void markAppValidIfPending();
  static bool hexStringIsLowerSha256(const String& s);
  static bool stringStartsWithHttps(const String& s);

  // BLE secure-mode helpers (no-ops when kBleSecureMode is false)
  void generateProvisioningNonce();
  bool provisioningNonceValid() const;
  void publishProvisioningNonce(BLECharacteristic* nonceCharacteristic);

  NextAction runEventFlow(const WifiCredentials& creds);

  Preferences preferences_;
  DeviceMode mode_ = DeviceMode::Idle;
  bool bleClientConnected_ = false;
  bool provisioningAttemptPending_ = false;
  bool pendingSsidReceived_ = false;
  bool pendingPasswordReceived_ = false;
  unsigned long provisioningStartMs_ = 0;
  String pendingSsid_;
  String pendingPassword_;

  BLEServer* bleServer_ = nullptr;
  BLECharacteristic* bleStatusCharacteristic_ = nullptr;
  BLECharacteristic* bleNonceCharacteristic_ = nullptr;

  // 16-byte one-time provisioning nonce (only populated when kBleSecureMode).
  uint8_t provisioningNonce_[16] = {0};
  unsigned long provisioningNonceMs_ = 0;
  bool provisioningNonceValid_ = false;

  friend class ProvisioningServerCallbacks;
  friend class SsidCallbacks;
  friend class PasswordCallbacks;
};
