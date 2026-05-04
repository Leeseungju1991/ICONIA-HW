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
    // 멱등성 키. uploadEventWithRetry에서 1회 생성 → 모든 재시도에서 동일 값 유지.
    // 형식: "<MAC12hex>-<wakeMs>-<rand4hex>". null-terminator 포함 32자 buffer면 충분.
    char eventId[40];
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
  // event_id 생성 — wake당 1회 호출. deviceId(콜론 제거)와 millis(), 32-bit
  // hardware random 4바이트(=8 hex chars 중 상위 4 hex)를 조합해 충돌 가능성을
  // 통계적으로 무시할 수 있는 수준으로 낮춤.
  void buildEventId(const char* deviceId, char* outBuffer, size_t outBufferLen) const;
  String bleDeviceName() const;
  static const char* touchToString(TouchDirection direction);

  ParsedUrl parseHttpsUrl(const char* url) const;
  // connectToWifi: outAuthFailed로 인증 실패(WL_CONNECT_FAILED) 분리 신호.
  // - true 반환: 연결 성공. outAuthFailed는 false.
  // - false 반환: 연결 실패. outAuthFailed가 true면 비밀번호 잘못 가능성.
  //   false면 일시적 장애(NO_SSID, timeout 등). 호출자가 NVS 카운터 정책을 결정.
  bool connectToWifi(const WifiCredentials& creds, bool* outAuthFailed = nullptr);
  // connectToWifiWithRetry: 모든 attempt가 WL_CONNECT_FAILED인 경우만 NVS 영속
  // 카운터를 증가. 성공 시 카운터 0 reset. 임계치(kWifiAuthFailEraseThreshold)
  // 도달 시 wifi 자격증명 erase + 다음 부팅 BLE provisioning 자동 진입.
  bool connectToWifiWithRetry(const WifiCredentials& creds, uint8_t retryCount);
  bool configureSecureClient(WiFiClientSecure& client);

  // Wi-Fi 인증 실패 카운터 도우미. NVS key: "wifi_fail_cnt".
  uint32_t loadWifiAuthFailCount();
  void saveWifiAuthFailCount(uint32_t count);
  void resetWifiAuthFailCount();

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
  // canEnterOta: 가드 사전 검사(배터리/RSSI/계약 헤더 형식 + 다운그레이드).
  //              미달 사유는 분류 로깅, 다운그레이드 거부는 NVS에 결과 기록.
  // sanitizeUrlForLog: presigned URL의 쿼리(서명) 마스킹.
  // markAppValidIfPending: pending_verify 파티션이면 자가점검 통과 표시 +
  //                        NVS에 success 결과 기록(다음 보고에 포함).
  bool canEnterOta(const OtaCommand& ota, int batteryPercent, int rssiDbm);
  bool performOta(const OtaCommand& ota);
  String sanitizeUrlForLog(const String& url) const;
  void markAppValidIfPending();
  static bool hexStringIsLowerSha256(const String& s);
  static bool stringStartsWithHttps(const String& s);

  // OTA 결과 보고 채널.
  // recordOtaResult: NVS(ota_result/ota_attempt_ver) 페어로 결과 영속화.
  //                  enum 화이트리스트와 semver 형식을 통과한 값만 저장.
  //                  실패는 swallow(시리얼 경고만) — OTA 정상 흐름을 막지 않음.
  // loadLastOtaReport: 다음 multipart에 첨부할 페어를 NVS에서 읽어옴.
  //                    페어 정합성(둘 다 존재 + 형식 통과) 깨지면 erase + false.
  // clearLastOtaReport: 응답 success 직후 호출하여 중복 emit 방지.
  // detectRollbackOnBoot: 부팅 직후 ESP_OTA_IMG_INVALID 등으로 롤백 추론하여
  //                       ota_result=rolled_back 기록(직전 attempt_ver 유지).
  void recordOtaResult(const char* resultEnum, const char* attemptedVersion);
  bool loadLastOtaReport(String& outResult, String& outVersion);
  void clearLastOtaReport();
  void detectRollbackOnBoot();
  static bool isAllowedOtaResult(const char* resultEnum);
  static bool isValidSemver(const char* version);
  static bool parseSemver(const char* version, int& major, int& minor, int& patch);
  static int compareSemver(int aMajor, int aMinor, int aPatch,
                           int bMajor, int bMinor, int bPatch);

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
