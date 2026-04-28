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
    const char* firmwareVersion;
    const uint8_t* imageData;
    size_t imageLen;
  };

  struct UploadResult {
    bool success;
    NextAction nextAction;
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

  friend class ProvisioningServerCallbacks;
  friend class SsidCallbacks;
  friend class PasswordCallbacks;
};
