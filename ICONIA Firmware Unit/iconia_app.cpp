#include "iconia_app.h"

#include <string.h>
#include <strings.h>
#include <string>

#include "esp32-hal-cpu.h"
#include "esp_bt.h"
#include "esp_bt_main.h"
#include "esp_random.h"
#include "esp_sleep.h"
#include "esp_system.h"
#include "esp_task_wdt.h"
#include "esp_wifi.h"
#include "driver/rtc_io.h"

#if CONFIG_BT_BLE_SMP_ENABLE
#include <BLESecurity.h>
#endif

#include "iconia_config.h"
#include "iconia_protocol.h"

IconiaApp* gAppInstance = nullptr;

class ProvisioningServerCallbacks : public BLEServerCallbacks {
 public:
  void onConnect(BLEServer* server) override {
    (void)server;
    if (gAppInstance == nullptr) {
      return;
    }
    gAppInstance->bleClientConnected_ = true;
    gAppInstance->notifyProvisioningStatus("connected");
  }

  void onDisconnect(BLEServer* server) override {
    (void)server;
    if (gAppInstance == nullptr) {
      return;
    }
    gAppInstance->bleClientConnected_ = false;
    BLEDevice::startAdvertising();
    gAppInstance->notifyProvisioningStatus("advertising");
  }
};

class SsidCallbacks : public BLECharacteristicCallbacks {
 public:
  void onWrite(BLECharacteristic* characteristic) override {
    if (gAppInstance == nullptr) {
      return;
    }

    std::string value = characteristic->getValue();
    gAppInstance->pendingSsid_ = String(value.c_str());
    gAppInstance->pendingSsid_.trim();
    gAppInstance->pendingSsidReceived_ = true;

    if (gAppInstance->pendingSsidReceived_ && gAppInstance->pendingPasswordReceived_) {
      gAppInstance->provisioningAttemptPending_ = true;
    }
  }
};

class PasswordCallbacks : public BLECharacteristicCallbacks {
 public:
  void onWrite(BLECharacteristic* characteristic) override {
    if (gAppInstance == nullptr) {
      return;
    }

    std::string value = characteristic->getValue();
    gAppInstance->pendingPassword_ = String(value.c_str());
    gAppInstance->pendingPasswordReceived_ = true;

    if (gAppInstance->pendingSsidReceived_ && gAppInstance->pendingPasswordReceived_) {
      gAppInstance->provisioningAttemptPending_ = true;
    }
  }
};

void IconiaApp::begin() {
  gAppInstance = this;

  // Drop to idle clock as early as possible. Networking paths bump it back up.
  setCpuFrequencyMhz(iconia::config::kCpuFrequencyIdleMhz);

  // Brown-out detector: do NOT disable. The Arduino core leaves it enabled at
  // the chip's factory threshold (~2.43 V) — exactly what a Li-Po BQ24075
  // system needs to avoid undefined behaviour on a deep discharge.
  // We explicitly do NOT call WRITE_PERI_REG(RTC_CNTL_BROWN_OUT_REG, 0).

  // Task watchdog: cover the main task. Wi-Fi/TLS handshake under bad signal
  // can deadlock the network thread; the TWDT forces a reset and the next
  // wake retries. 30 s covers the worst-case capture + 3-attempt upload loop.
  // ESP-IDF 5.x signature (Arduino core 3.x is built on it).
  const esp_task_wdt_config_t wdtConfig = {
    /*timeout_ms=*/30000,
    /*idle_core_mask=*/0,
    /*trigger_panic=*/true,
  };
  if (esp_task_wdt_reconfigure(&wdtConfig) != ESP_OK) {
    esp_task_wdt_init(&wdtConfig);
  }
  esp_task_wdt_add(nullptr);

  if (iconia::config::kSerialLoggingEnabled) {
    Serial.begin(115200);
    delay(1000);
    Serial.println();
    logLine("[BOOT] ICONIA firmware start");
  }

  // Boot guard: refuse to run with placeholder secrets. This catches the case
  // where a developer flashes a build that forgot the -DICONIA_API_KEY flag.
  haltOnPlaceholderSecrets();

  pinMode(iconia::config::kLedGpio, OUTPUT);
  digitalWrite(iconia::config::kLedGpio, LOW);
  pinMode(iconia::config::kCameraPowerDownGpio, OUTPUT);
  digitalWrite(iconia::config::kCameraPowerDownGpio, HIGH);
  pinMode(iconia::config::kTouchRightGpio, INPUT);
  pinMode(iconia::config::kTouchLeftGpio, INPUT);

  initBatteryMonitor();

  if (!openPreferences()) {
    logLine("[FATAL] failed to open NVS preferences");
    delay(1000);
    enterDeepSleep();
    return;
  }

  WifiCredentials creds = loadWifiCredentials();
  if (!creds.valid) {
    logLine("[BOOT] no Wi-Fi credentials, entering BLE provisioning");
    startProvisioningBle();
    return;
  }

  NextAction nextAction = runEventFlow(creds);
  if (nextAction == NextAction::EnterProvisioning) {
    startProvisioningBle();
    return;
  }

  logLine("[EVENT] flow complete");
  delay(300);
  enterDeepSleep();
}

void IconiaApp::loop() {
  // Feed the task watchdog every iteration so a healthy provisioning wait
  // does not get killed.
  esp_task_wdt_reset();

  if (mode_ != DeviceMode::Provisioning) {
    delay(200);
    return;
  }

  // Expire the per-session BLE nonce (secure mode only).
  if (iconia::config::kBleSecureMode &&
      provisioningNonceValid_ &&
      !provisioningNonceValid()) {
    provisioningNonceValid_ = false;
    notifyProvisioningStatus("nonce_expired");
  }

  if (provisioningAttemptPending_) {
    handleProvisioningAttempt();
  }

  if ((millis() - provisioningStartMs_) >= iconia::config::kProvisioningTimeoutMs) {
    notifyProvisioningStatus("timeout");
    stopProvisioningBle();
    enterDeepSleep();
  }

  delay(50);
}

void IconiaApp::logLine(const String& message) {
  if (!iconia::config::kSerialLoggingEnabled) {
    return;
  }
  Serial.println(message);
  Serial.flush();
}

bool IconiaApp::placeholderSecretsPresent() const {
  if (strcmp(iconia::config::kApiKey, iconia::config::kPlaceholderApiKey1) == 0) {
    return true;
  }
  if (strcmp(iconia::config::kApiKey, iconia::config::kPlaceholderApiKey2) == 0) {
    return true;
  }
  if (strcmp(iconia::config::kApiEndpoint, iconia::config::kPlaceholderEndpoint) == 0) {
    return true;
  }
  return false;
}

void IconiaApp::haltOnPlaceholderSecrets() {
  if (!placeholderSecretsPresent()) {
    return;
  }

  // Visible failure mode: log if Serial is on, then deep-sleep forever.
  // A device with placeholder credentials must never reach the network code.
  logLine("[FATAL] placeholder secrets detected; rebuild with "
          "-DICONIA_API_KEY=... -DICONIA_API_ENDPOINT=...");
  delay(500);

  // Disable EXT1 wakeup so a touch cannot accidentally retry.
  esp_sleep_disable_wakeup_source(ESP_SLEEP_WAKEUP_ALL);
  esp_deep_sleep_start();
}

void IconiaApp::generateProvisioningNonce() {
  // Wi-Fi/BLE radios are guaranteed to be enabled before this call (BLE init
  // happens in startProvisioningBle), so esp_random() pulls from the
  // hardware RNG, not the boot-time PRNG.
  for (int i = 0; i < 16; i += 4) {
    uint32_t r = esp_random();
    provisioningNonce_[i + 0] = (uint8_t)(r >> 0);
    provisioningNonce_[i + 1] = (uint8_t)(r >> 8);
    provisioningNonce_[i + 2] = (uint8_t)(r >> 16);
    provisioningNonce_[i + 3] = (uint8_t)(r >> 24);
  }
  provisioningNonceMs_ = millis();
  provisioningNonceValid_ = true;
}

bool IconiaApp::provisioningNonceValid() const {
  if (!provisioningNonceValid_) {
    return false;
  }
  return (millis() - provisioningNonceMs_) < iconia::config::kBleNonceTtlMs;
}

void IconiaApp::publishProvisioningNonce(BLECharacteristic* nonceCharacteristic) {
  if (nonceCharacteristic == nullptr) {
    return;
  }
  // Expose the 16 bytes raw via a READ-only characteristic. The app reads it
  // immediately after secure pairing and uses it as a session token in the
  // SSID/password ciphertext envelope (interface to be defined with rn-mobile).
  nonceCharacteristic->setValue(provisioningNonce_, sizeof(provisioningNonce_));
}

int IconiaApp::clampPercent(int value) {
  if (value < 0) {
    return 0;
  }
  if (value > 100) {
    return 100;
  }
  return value;
}

bool IconiaApp::openPreferences() {
  return preferences_.begin("iconia", false);
}

IconiaApp::WifiCredentials IconiaApp::loadWifiCredentials() {
  WifiCredentials creds = {};
  creds.ssid = preferences_.getString("wifi_ssid", "");
  creds.password = preferences_.getString("wifi_pw", "");
  creds.valid = creds.ssid.length() > 0;
  return creds;
}

bool IconiaApp::saveWifiCredentials(const String& ssid, const String& password) {
  preferences_.putString("wifi_ssid", ssid);
  preferences_.putString("wifi_pw", password);
  return preferences_.getString("wifi_ssid", "") == ssid &&
         preferences_.getString("wifi_pw", "__READBACK_ERROR__") == password;
}

void IconiaApp::clearWifiCredentials() {
  preferences_.remove("wifi_ssid");
  preferences_.remove("wifi_pw");
}

void IconiaApp::initBatteryMonitor() {
  if (iconia::config::kBatteryAdcPin >= 0) {
    pinMode(iconia::config::kBatteryAdcPin, INPUT);
    analogReadResolution(12);
    analogSetPinAttenuation(iconia::config::kBatteryAdcPin, ADC_11db);
  }
}

IconiaApp::BatteryStatus IconiaApp::readBatteryStatus() {
  BatteryStatus status = {};
  if (iconia::config::kBatteryAdcPin < 0) {
    status.configured = false;
    status.valid = false;
    return status;
  }

  status.configured = true;

  uint32_t acc = 0;
  const int samples = iconia::config::kBatteryAdcSampleCount;
  for (int i = 0; i < samples; ++i) {
    acc += analogRead(iconia::config::kBatteryAdcPin);
    delay(2);
  }

  status.raw = acc / samples;
  status.pinVoltage = (status.raw / 4095.0f) * iconia::config::kBatteryAdcReferenceV;
  status.batteryVoltage = status.pinVoltage * iconia::config::kBatteryDividerRatio;
  status.percent = clampPercent(
    static_cast<int>(((status.batteryVoltage - iconia::config::kBatteryEmptyV) * 100.0f) /
                     (iconia::config::kBatteryFullV - iconia::config::kBatteryEmptyV))
  );
  status.valid = true;
  return status;
}

camera_config_t IconiaApp::buildCameraConfig() {
  camera_config_t config = {};
  config.ledc_channel = LEDC_CHANNEL_0;
  config.ledc_timer = LEDC_TIMER_0;
  config.pin_d0 = iconia::config::kY2Gpio;
  config.pin_d1 = iconia::config::kY3Gpio;
  config.pin_d2 = iconia::config::kY4Gpio;
  config.pin_d3 = iconia::config::kY5Gpio;
  config.pin_d4 = iconia::config::kY6Gpio;
  config.pin_d5 = iconia::config::kY7Gpio;
  config.pin_d6 = iconia::config::kY8Gpio;
  config.pin_d7 = iconia::config::kY9Gpio;
  config.pin_xclk = iconia::config::kXclkGpio;
  config.pin_pclk = iconia::config::kPclkGpio;
  config.pin_vsync = iconia::config::kVsyncGpio;
  config.pin_href = iconia::config::kHrefGpio;
  config.pin_sccb_sda = iconia::config::kSiodGpio;
  config.pin_sccb_scl = iconia::config::kSiocGpio;
  config.pin_pwdn = iconia::config::kPwdnGpio;
  config.pin_reset = iconia::config::kResetGpio;
  config.xclk_freq_hz = 20000000;
  config.pixel_format = PIXFORMAT_JPEG;
  config.frame_size = psramFound() ? iconia::config::kCaptureFrameSize : FRAMESIZE_VGA;
  config.jpeg_quality = psramFound() ? iconia::config::kCaptureJpegQuality : 14;
  config.fb_count = 1;
  config.grab_mode = CAMERA_GRAB_WHEN_EMPTY;
  return config;
}

bool IconiaApp::initCamera() {
  // Release any RTC-hold left over from the previous deep sleep before
  // toggling PWDN, otherwise the level latches and the sensor never powers up.
  rtc_gpio_hold_dis((gpio_num_t)iconia::config::kCameraPowerDownGpio);
  pinMode(iconia::config::kCameraPowerDownGpio, OUTPUT);
  digitalWrite(iconia::config::kCameraPowerDownGpio, LOW);
  // OV2640 needs >= ~10 ms after PWDN goes low before SCCB is reachable.
  delay(50);

  camera_config_t config = buildCameraConfig();
  if (esp_camera_init(&config) != ESP_OK) {
    logLine("[ERROR] camera init failed");
    return false;
  }

  sensor_t* sensor = esp_camera_sensor_get();
  if (sensor != nullptr) {
    sensor->set_vflip(sensor, 1);
    sensor->set_brightness(sensor, 0);
    sensor->set_saturation(sensor, 0);
  }

  delay(300);
  return true;
}

void IconiaApp::deinitCamera() {
  esp_camera_deinit();
  digitalWrite(iconia::config::kCameraPowerDownGpio, HIGH);
}

camera_fb_t* IconiaApp::captureImage() {
  if (!initCamera()) {
    return nullptr;
  }

  camera_fb_t* warmupFrame = esp_camera_fb_get();
  if (warmupFrame != nullptr) {
    esp_camera_fb_return(warmupFrame);
    delay(100);
  }

  camera_fb_t* frame = esp_camera_fb_get();
  if (frame == nullptr) {
    logLine("[ERROR] camera capture failed");
    deinitCamera();
    return nullptr;
  }

  return frame;
}

uint64_t IconiaApp::touchWakeMask() const {
  return (1ULL << iconia::config::kTouchRightGpio) | (1ULL << iconia::config::kTouchLeftGpio);
}

IconiaApp::TouchDirection IconiaApp::touchDirectionFromWake() const {
  if (esp_sleep_get_wakeup_cause() != ESP_SLEEP_WAKEUP_EXT1) {
    return TouchDirection::None;
  }

  uint64_t wakeMask = esp_sleep_get_ext1_wakeup_status();
  if (wakeMask & (1ULL << iconia::config::kTouchRightGpio)) {
    return TouchDirection::Right;
  }
  if (wakeMask & (1ULL << iconia::config::kTouchLeftGpio)) {
    return TouchDirection::Left;
  }
  return TouchDirection::None;
}

void IconiaApp::enterDeepSleep() {
  logLine("[POWER] entering deep sleep");

  // Detach the task watchdog before we sleep. Otherwise the watchdog list
  // still references the (about-to-be-suspended) task on next wake and
  // esp_task_wdt_add() returns ESP_ERR_INVALID_ARG.
  esp_task_wdt_delete(nullptr);

  // 1. Wi-Fi: disconnect -> stop -> deinit (full RF + driver shutdown)
  WiFi.disconnect(true, true);
  WiFi.mode(WIFI_OFF);
  esp_wifi_stop();
  esp_wifi_deinit();

  // 2. BLE/Bluedroid: ensure controller is fully disabled (btStop alone may
  // leave the controller in INITED state, drawing extra current in sleep).
  if (esp_bluedroid_get_status() == ESP_BLUEDROID_STATUS_ENABLED) {
    esp_bluedroid_disable();
    esp_bluedroid_deinit();
  }
  if (esp_bt_controller_get_status() == ESP_BT_CONTROLLER_STATUS_ENABLED) {
    esp_bt_controller_disable();
  }
  if (esp_bt_controller_get_status() == ESP_BT_CONTROLLER_STATUS_INITED) {
    esp_bt_controller_deinit();
  }
  esp_bt_controller_mem_release(ESP_BT_MODE_BTDM);

  // 3. Camera PWDN must stay HIGH while sleeping (OV2640 power-down).
  rtc_gpio_init((gpio_num_t)iconia::config::kCameraPowerDownGpio);
  rtc_gpio_set_direction((gpio_num_t)iconia::config::kCameraPowerDownGpio,
                         RTC_GPIO_MODE_OUTPUT_ONLY);
  rtc_gpio_set_level((gpio_num_t)iconia::config::kCameraPowerDownGpio, 1);
  rtc_gpio_hold_en((gpio_num_t)iconia::config::kCameraPowerDownGpio);

  // 4. Isolate every other pin to eliminate floating-input leakage.
  // Wakeup pins are exempt — they must keep their pull configuration.
  esp_sleep_config_gpio_isolate();

  // 5. Power down RTC peripherals we do not need (RTC slow mem keeps wakeup state).
  esp_sleep_pd_config(ESP_PD_DOMAIN_RTC_PERIPH, ESP_PD_OPTION_OFF);
  esp_sleep_pd_config(ESP_PD_DOMAIN_RTC_SLOW_MEM, ESP_PD_OPTION_OFF);
  esp_sleep_pd_config(ESP_PD_DOMAIN_RTC_FAST_MEM, ESP_PD_OPTION_OFF);

  delay(50);
  esp_sleep_enable_ext1_wakeup(touchWakeMask(), ESP_EXT1_WAKEUP_ANY_HIGH);
  esp_deep_sleep_start();
}

void IconiaApp::buildDeviceId(char* outBuffer, size_t outBufferLen) const {
  uint8_t mac[6] = {0};
  esp_read_mac(mac, ESP_MAC_WIFI_STA);
  snprintf(
    outBuffer,
    outBufferLen,
    "%02X:%02X:%02X:%02X:%02X:%02X",
    mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]
  );
}

String IconiaApp::bleDeviceName() const {
  char deviceId[18];
  buildDeviceId(deviceId, sizeof(deviceId));
  String compact(deviceId);
  compact.replace(":", "");
  if (compact.length() >= 4) {
    compact = compact.substring(compact.length() - 4);
  }
  return "ICONIA-" + compact;
}

const char* IconiaApp::touchToString(TouchDirection direction) {
  switch (direction) {
    case TouchDirection::Right: return iconia::protocol::kTouchRight;
    case TouchDirection::Left:  return iconia::protocol::kTouchLeft;
    default:                   return iconia::protocol::kTouchNone;
  }
}

IconiaApp::ParsedUrl IconiaApp::parseHttpsUrl(const char* url) const {
  ParsedUrl parsed = {};
  parsed.port = 443;

  String full(url);
  if (!full.startsWith("https://")) {
    return parsed;
  }

  String remainder = full.substring(strlen("https://"));
  int slashIndex = remainder.indexOf('/');
  String hostPort = slashIndex >= 0 ? remainder.substring(0, slashIndex) : remainder;
  parsed.path = slashIndex >= 0 ? remainder.substring(slashIndex) : "/";

  int colonIndex = hostPort.indexOf(':');
  if (colonIndex >= 0) {
    parsed.host = hostPort.substring(0, colonIndex);
    parsed.port = static_cast<uint16_t>(hostPort.substring(colonIndex + 1).toInt());
  } else {
    parsed.host = hostPort;
  }

  parsed.valid = parsed.host.length() > 0 && parsed.path.length() > 0 && parsed.port > 0;
  return parsed;
}

bool IconiaApp::connectToWifi(const WifiCredentials& creds) {
  // Full clock for the (short) connect+TLS phase. Reverted in enterDeepSleep().
  setCpuFrequencyMhz(iconia::config::kCpuFrequencyActiveMhz);

  WiFi.mode(WIFI_STA);
  // WIFI_PS_MAX_MODEM = aggressive modem sleep between DTIM beacons.
  // Cuts ~30-40 mA average during the connected idle window.
  WiFi.setSleep(WIFI_PS_MAX_MODEM);
  WiFi.begin(creds.ssid.c_str(), creds.password.c_str());

  unsigned long startMs = millis();
  while (WiFi.status() != WL_CONNECTED &&
         (millis() - startMs) < iconia::config::kWifiConnectTimeoutMs) {
    delay(250);
    esp_task_wdt_reset();
  }

  if (WiFi.status() == WL_CONNECTED) {
    logLine("[WIFI] connected: " + WiFi.localIP().toString());
    return true;
  }

  WiFi.disconnect(true, true);
  logLine("[WIFI] connection failed");
  return false;
}

bool IconiaApp::connectToWifiWithRetry(const WifiCredentials& creds, uint8_t retryCount) {
  for (uint8_t attempt = 1; attempt <= retryCount; ++attempt) {
    logLine("[WIFI] connect attempt " + String(attempt) + "/" + String(retryCount));
    if (connectToWifi(creds)) {
      return true;
    }
    delay(800);
  }
  return false;
}

bool IconiaApp::configureSecureClient(WiFiClientSecure& client) {
  bool caConfigured = false;

  if (strlen(iconia::config::kServerRootCaPem) > 16) {
    client.setCACert(iconia::config::kServerRootCaPem);
    caConfigured = true;
  }

  if (caConfigured) {
    return true;
  }

  if (iconia::config::kAllowInsecureTlsWhenRootCaMissing) {
    client.setInsecure();
    logLine("[WARN] TLS root CA missing, using insecure mode");
    return true;
  }

  logLine("[ERROR] TLS root CA is not configured");
  return false;
}

// Post-connect leaf-cert pinning. Defense-in-depth on top of CA verification.
// Returns true if pinning is disabled (empty fingerprint) OR the connected
// peer's cert matches the configured fingerprint. Returns false to abort
// the upload if the cert is wrong.
//
// ESP32 Arduino core 3.x exposes verify(const char* fingerprint,
// const char* domain) which compares the SHA-1 over the DER-encoded cert.
// Empty fingerprint disables this layer; the CA chain check still runs.
static bool verifyServerFingerprint(WiFiClientSecure& client, const char* host) {
  if (strlen(iconia::config::kServerCertFingerprintSha1) < 40) {
    return true;  // pinning disabled
  }
  return client.verify(iconia::config::kServerCertFingerprintSha1, host);
}

bool IconiaApp::writeAll(WiFiClient& client, const uint8_t* data, size_t len) {
  size_t written = 0;
  while (written < len) {
    size_t step = client.write(data + written, len - written);
    if (step == 0) {
      return false;
    }
    written += step;
  }
  return true;
}

bool IconiaApp::readLine(WiFiClientSecure& client, char* buffer, size_t bufferSize) {
  if (bufferSize == 0) {
    return false;
  }

  size_t len = client.readBytesUntil('\n', buffer, bufferSize - 1);
  if (len == 0 && !client.available()) {
    buffer[0] = '\0';
    return false;
  }

  buffer[len] = '\0';
  while (len > 0 && (buffer[len - 1] == '\r' || buffer[len - 1] == '\n')) {
    buffer[--len] = '\0';
  }
  return true;
}

char* IconiaApp::skipSpaces(char* text) {
  while (*text == ' ' || *text == '\t') {
    ++text;
  }
  return text;
}

void IconiaApp::trimRight(char* text) {
  size_t len = strlen(text);
  while (len > 0 && (text[len - 1] == ' ' || text[len - 1] == '\t' || text[len - 1] == '\r')) {
    text[--len] = '\0';
  }
}

bool IconiaApp::lineHasReprovisionCommand(const char* text) {
  return strstr(text, iconia::protocol::kCommandEnterProvisioning) != nullptr;
}

size_t IconiaApp::multipartTextFieldLength(const char* boundary, const char* fieldName, const char* fieldValue) {
  return strlen("--") + strlen(boundary) + strlen("\r\n") +
         strlen("Content-Disposition: form-data; name=\"") + strlen(fieldName) + strlen("\"\r\n\r\n") +
         strlen(fieldValue) + strlen("\r\n");
}

size_t IconiaApp::multipartImageHeaderLength(const char* boundary, const char* fieldName, const char* fileName) {
  return strlen("--") + strlen(boundary) + strlen("\r\n") +
         strlen("Content-Disposition: form-data; name=\"") + strlen(fieldName) +
         strlen("\"; filename=\"") + strlen(fileName) + strlen("\"\r\n") +
         strlen("Content-Type: image/jpeg\r\n\r\n");
}

bool IconiaApp::writeMultipartTextField(WiFiClient& client, const char* boundary, const char* fieldName, const char* fieldValue) {
  char header[128];
  int headerLen = snprintf(
    header,
    sizeof(header),
    "--%s\r\nContent-Disposition: form-data; name=\"%s\"\r\n\r\n",
    boundary,
    fieldName
  );

  if (headerLen <= 0 || static_cast<size_t>(headerLen) >= sizeof(header)) {
    return false;
  }

  return writeAll(client, reinterpret_cast<const uint8_t*>(header), static_cast<size_t>(headerLen)) &&
         writeAll(client, reinterpret_cast<const uint8_t*>(fieldValue), strlen(fieldValue)) &&
         writeAll(client, reinterpret_cast<const uint8_t*>("\r\n"), 2);
}

bool IconiaApp::writeMultipartImageHeader(WiFiClient& client, const char* boundary, const char* fieldName, const char* fileName) {
  char header[196];
  int headerLen = snprintf(
    header,
    sizeof(header),
    "--%s\r\nContent-Disposition: form-data; name=\"%s\"; filename=\"%s\"\r\n"
    "Content-Type: %s\r\n\r\n",
    boundary,
    fieldName,
    fileName,
    iconia::protocol::kImageContentType
  );

  if (headerLen <= 0 || static_cast<size_t>(headerLen) >= sizeof(header)) {
    return false;
  }

  return writeAll(client, reinterpret_cast<const uint8_t*>(header), static_cast<size_t>(headerLen));
}

IconiaApp::UploadResult IconiaApp::readHttpResponseAndCommand(WiFiClientSecure& client) {
  UploadResult result = {false, NextAction::None};
  char line[160];

  if (!readLine(client, line, sizeof(line))) {
    return result;
  }

  Serial.println(line);
  result.success = (strncmp(line, "HTTP/1.1 2", 10) == 0) || (strncmp(line, "HTTP/1.0 2", 10) == 0);

  while (client.connected() || client.available()) {
    if (!readLine(client, line, sizeof(line))) {
      break;
    }

    if (line[0] == '\0') {
      break;
    }

    char* colon = strchr(line, ':');
    if (colon == nullptr) {
      continue;
    }

    *colon = '\0';
    char* value = skipSpaces(colon + 1);
    trimRight(value);

    if (strcasecmp(line, iconia::protocol::kCommandHeader) == 0 &&
        strcasecmp(value, iconia::protocol::kCommandEnterProvisioning) == 0) {
      result.nextAction = NextAction::EnterProvisioning;
    }
  }

  if (client.available()) {
    char body[96];
    size_t bodyLen = client.readBytes(body, sizeof(body) - 1);
    body[bodyLen] = '\0';
    if (lineHasReprovisionCommand(body)) {
      result.nextAction = NextAction::EnterProvisioning;
    }
  }

  return result;
}

IconiaApp::UploadResult IconiaApp::postEventMultipart(const EventPayload& payload) {
  UploadResult result = {false, NextAction::None};
  ParsedUrl endpoint = parseHttpsUrl(iconia::config::kApiEndpoint);
  if (!endpoint.valid) {
    logLine("[ERROR] invalid API endpoint");
    return result;
  }

  char batteryText[8];
  snprintf(batteryText, sizeof(batteryText), "%d", payload.batteryPercent);

  size_t contentLength = 0;
  contentLength += multipartTextFieldLength(iconia::config::kMultipartBoundary, iconia::protocol::kFieldTouch, payload.touch);
  contentLength += multipartTextFieldLength(iconia::config::kMultipartBoundary, iconia::protocol::kFieldDeviceId, payload.deviceId);
  contentLength += multipartTextFieldLength(iconia::config::kMultipartBoundary, iconia::protocol::kFieldBattery, batteryText);
  contentLength += multipartTextFieldLength(
    iconia::config::kMultipartBoundary,
    iconia::protocol::kFieldFirmwareVersion,
    payload.firmwareVersion
  );
  contentLength += multipartImageHeaderLength(iconia::config::kMultipartBoundary, iconia::protocol::kFieldImage, iconia::protocol::kImageFileName);
  contentLength += payload.imageLen;
  contentLength += strlen("\r\n--") + strlen(iconia::config::kMultipartBoundary) + strlen("--\r\n");

  WiFiClientSecure client;
  client.setTimeout(iconia::config::kServerResponseTimeoutMs / 1000);
  if (!configureSecureClient(client)) {
    return result;
  }

  if (!client.connect(endpoint.host.c_str(), endpoint.port)) {
    logLine("[ERROR] HTTPS connection failed");
    return result;
  }

  if (!verifyServerFingerprint(client, endpoint.host.c_str())) {
    logLine("[ERROR] server fingerprint mismatch, aborting upload");
    client.stop();
    return result;
  }

  char headers[384];
  int headerLen = snprintf(
    headers,
    sizeof(headers),
    "POST %s HTTP/1.1\r\n"
    "Host: %s\r\n"
    "User-Agent: ICONIA-ESP32/1.0\r\n"
    "%s: %s\r\n"
    "Content-Type: multipart/form-data; boundary=%s\r\n"
    "Content-Length: %u\r\n"
    "Connection: close\r\n\r\n",
    endpoint.path.c_str(),
    endpoint.host.c_str(),
    iconia::protocol::kApiKeyHeader,
    iconia::config::kApiKey,
    iconia::config::kMultipartBoundary,
    static_cast<unsigned int>(contentLength)
  );

  if (headerLen <= 0 || static_cast<size_t>(headerLen) >= sizeof(headers) ||
      !writeAll(client, reinterpret_cast<const uint8_t*>(headers), static_cast<size_t>(headerLen)) ||
      !writeMultipartTextField(client, iconia::config::kMultipartBoundary, iconia::protocol::kFieldTouch, payload.touch) ||
      !writeMultipartTextField(client, iconia::config::kMultipartBoundary, iconia::protocol::kFieldDeviceId, payload.deviceId) ||
      !writeMultipartTextField(client, iconia::config::kMultipartBoundary, iconia::protocol::kFieldBattery, batteryText) ||
      !writeMultipartTextField(
        client,
        iconia::config::kMultipartBoundary,
        iconia::protocol::kFieldFirmwareVersion,
        payload.firmwareVersion
      ) ||
      !writeMultipartImageHeader(client, iconia::config::kMultipartBoundary, iconia::protocol::kFieldImage, iconia::protocol::kImageFileName) ||
      !writeAll(client, payload.imageData, payload.imageLen) ||
      !writeAll(client, reinterpret_cast<const uint8_t*>("\r\n--"), 4) ||
      !writeAll(client, reinterpret_cast<const uint8_t*>(iconia::config::kMultipartBoundary), strlen(iconia::config::kMultipartBoundary)) ||
      !writeAll(client, reinterpret_cast<const uint8_t*>("--\r\n"), 4)) {
    logLine("[ERROR] HTTPS request write failed");
    client.stop();
    return result;
  }

  result = readHttpResponseAndCommand(client);
  client.stop();
  return result;
}

IconiaApp::UploadResult IconiaApp::uploadEventWithRetry(const EventPayload& payload) {
  UploadResult result = {false, NextAction::None};

  for (uint8_t attempt = 1; attempt <= iconia::config::kUploadRetryCount; ++attempt) {
    logLine("[HTTPS] upload attempt " + String(attempt) + "/" + String(iconia::config::kUploadRetryCount));
    result = postEventMultipart(payload);
    if (result.nextAction == NextAction::EnterProvisioning) {
      logLine("[HTTPS] server requested reprovisioning");
      return result;
    }
    if (result.success) {
      logLine("[HTTPS] upload success");
      return result;
    }
    delay(1000);
  }

  logLine("[HTTPS] upload failed after retries");
  return result;
}

void IconiaApp::notifyProvisioningStatus(const String& status) {
  logLine("[BLE] " + status);
  if (bleStatusCharacteristic_ == nullptr) {
    return;
  }

  bleStatusCharacteristic_->setValue(status.c_str());
  if (bleClientConnected_) {
    bleStatusCharacteristic_->notify();
  }
}

void IconiaApp::startProvisioningBle() {
  mode_ = DeviceMode::Provisioning;
  provisioningStartMs_ = millis();
  pendingSsid_ = "";
  pendingPassword_ = "";
  provisioningAttemptPending_ = false;
  pendingSsidReceived_ = false;
  pendingPasswordReceived_ = false;
  provisioningNonceValid_ = false;

  BLEDevice::init(bleDeviceName().c_str());

  bleServer_ = BLEDevice::createServer();
  bleServer_->setCallbacks(new ProvisioningServerCallbacks());

  BLEService* service = bleServer_->createService(iconia::config::kBleServiceUuid);

  BLECharacteristic* ssidCharacteristic = service->createCharacteristic(
    iconia::config::kBleSsidCharUuid,
    BLECharacteristic::PROPERTY_WRITE_NR
  );
  ssidCharacteristic->setCallbacks(new SsidCallbacks());

  BLECharacteristic* passwordCharacteristic = service->createCharacteristic(
    iconia::config::kBlePasswordCharUuid,
    BLECharacteristic::PROPERTY_WRITE_NR
  );
  passwordCharacteristic->setCallbacks(new PasswordCallbacks());

  bleStatusCharacteristic_ = service->createCharacteristic(
    iconia::config::kBleStatusCharUuid,
    BLECharacteristic::PROPERTY_NOTIFY | BLECharacteristic::PROPERTY_READ
  );
  bleStatusCharacteristic_->addDescriptor(new BLE2902());
  bleStatusCharacteristic_->setValue("advertising");

  // Optional secure-mode hardening. Compile-time gated; default OFF.
  // -------------------------------------------------------------------------
  // Interface contract for rn-mobile when this is flipped on:
  //   1. App connects, triggers Just Works pairing (ESP_LE_AUTH_REQ_SC_MITM_BOND).
  //   2. App reads the 16-byte Nonce characteristic immediately after pairing.
  //   3. App sends SSID + password as <nonce-prefixed AEAD ciphertext> across
  //      the existing SSID/password characteristics. (AEAD scheme TBD; suggest
  //      AES-128-GCM with the BLE LTK as key.)
  //   4. Firmware verifies nonce (TTL: kBleNonceTtlMs) before accepting.
  // -------------------------------------------------------------------------
  if (iconia::config::kBleSecureMode) {
#if CONFIG_BT_BLE_SMP_ENABLE
    BLESecurity* security = new BLESecurity();
    security->setAuthenticationMode(ESP_LE_AUTH_REQ_SC_MITM_BOND);
    security->setCapability(ESP_IO_CAP_NONE);  // doll has no display/keyboard
    security->setInitEncryptionKey(ESP_BLE_ENC_KEY_MASK | ESP_BLE_ID_KEY_MASK);
    security->setRespEncryptionKey(ESP_BLE_ENC_KEY_MASK | ESP_BLE_ID_KEY_MASK);

    ssidCharacteristic->setAccessPermissions(
      ESP_GATT_PERM_WRITE_ENC_MITM
    );
    passwordCharacteristic->setAccessPermissions(
      ESP_GATT_PERM_WRITE_ENC_MITM
    );

    // Read-only nonce characteristic (UUID = status UUID + 1 to keep the
    // scheme deterministic; replace with a dedicated UUID when rn-mobile
    // confirms the pairing flow).
    bleNonceCharacteristic_ = service->createCharacteristic(
      "48f1f79e-817d-4105-a96f-4e2d2d6031e4",
      ESP_GATT_CHAR_PROP_BIT_READ
    );
    bleNonceCharacteristic_->setAccessPermissions(ESP_GATT_PERM_READ_ENC_MITM);

    generateProvisioningNonce();
    publishProvisioningNonce(bleNonceCharacteristic_);
    logLine("[BLE] secure mode enabled, nonce published");
#else
    logLine("[WARN] kBleSecureMode set but SMP not compiled in core");
#endif
  }

  service->start();
  BLEAdvertising* advertising = BLEDevice::getAdvertising();
  advertising->addServiceUUID(iconia::config::kBleServiceUuid);
  advertising->setScanResponse(true);
  // Long advertising interval (1280-2560 ms) cuts BLE current ~3-4x vs the
  // 100 ms default. Provisioning is one-shot at first boot, so discovery
  // latency of <3 s is acceptable.
  advertising->setMinInterval(iconia::config::kBleAdvIntervalMin);
  advertising->setMaxInterval(iconia::config::kBleAdvIntervalMax);
  advertising->start();

  notifyProvisioningStatus("advertising");
}

void IconiaApp::stopProvisioningBle() {
  BLEDevice::getAdvertising()->stop();
  BLEDevice::deinit(false);
  bleServer_ = nullptr;
  bleStatusCharacteristic_ = nullptr;
  bleNonceCharacteristic_ = nullptr;
  bleClientConnected_ = false;
  provisioningNonceValid_ = false;
  // Wipe the nonce buffer so it does not survive in heap fragments.
  memset(provisioningNonce_, 0, sizeof(provisioningNonce_));
}

void IconiaApp::handleProvisioningAttempt() {
  provisioningAttemptPending_ = false;

  if (pendingSsid_.length() == 0) {
    notifyProvisioningStatus("invalid_credentials");
    pendingSsidReceived_ = false;
    pendingPasswordReceived_ = false;
    return;
  }

  notifyProvisioningStatus("wifi_connecting");

  WifiCredentials pending = {};
  pending.ssid = pendingSsid_;
  pending.password = pendingPassword_;
  pending.valid = true;

  if (!connectToWifiWithRetry(pending, iconia::config::kWifiRetryCount)) {
    notifyProvisioningStatus("wifi_failed");
    pendingSsidReceived_ = false;
    pendingPasswordReceived_ = false;
    return;
  }

  if (!saveWifiCredentials(pending.ssid, pending.password)) {
    notifyProvisioningStatus("nvs_save_failed");
    WiFi.disconnect(true, true);
    pendingSsidReceived_ = false;
    pendingPasswordReceived_ = false;
    return;
  }

  notifyProvisioningStatus("provisioning_success");
  delay(400);
  stopProvisioningBle();
  enterDeepSleep();
}

IconiaApp::NextAction IconiaApp::runEventFlow(const WifiCredentials& creds) {
  mode_ = DeviceMode::EventFlow;

  TouchDirection direction = touchDirectionFromWake();
  if (direction == TouchDirection::None) {
    logLine("[EVENT] wake cause is not touch, returning to sleep");
    return NextAction::None;
  }

  logLine("[EVENT] wake direction: " + String(touchToString(direction)));
  delay(iconia::config::kTouchDebounceMs);

  BatteryStatus battery = readBatteryStatus();
  if (!battery.valid) {
    logLine("[ERROR] battery read failed");
    return NextAction::None;
  }

  logLine("[BATTERY] " + String(battery.percent) + "% / " + String(battery.batteryVoltage, 2) + "V");
  if (battery.percent < iconia::config::kBatteryCriticalPercent) {
    logLine("[POWER] battery too low, skip capture and upload");
    return NextAction::None;
  }

  camera_fb_t* frame = captureImage();
  if (frame == nullptr) {
    return NextAction::None;
  }

  if (!connectToWifiWithRetry(creds, iconia::config::kWifiRetryCount)) {
    esp_camera_fb_return(frame);
    deinitCamera();
    return NextAction::None;
  }

  EventPayload payload = {};
  buildDeviceId(payload.deviceId, sizeof(payload.deviceId));
  payload.touch = touchToString(direction);
  payload.batteryPercent = battery.percent;
  payload.firmwareVersion = iconia::config::kFirmwareVersion;
  payload.imageData = frame->buf;
  payload.imageLen = frame->len;

  UploadResult uploadResult = uploadEventWithRetry(payload);

  esp_camera_fb_return(frame);
  deinitCamera();
  WiFi.disconnect(true, true);
  WiFi.mode(WIFI_OFF);

  if (uploadResult.nextAction == NextAction::EnterProvisioning) {
    logLine("[SERVER] reprovision requested");
    clearWifiCredentials();
    return NextAction::EnterProvisioning;
  }

  return NextAction::None;
}
