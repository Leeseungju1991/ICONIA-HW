#include "iconia_app.h"

#include <string.h>
#include <strings.h>

#include "esp32-hal-cpu.h"
#include "esp_bt.h"
#include "esp_bt_main.h"
#include "esp_random.h"
#include "esp_sleep.h"
#include "esp_system.h"
#include "esp_task_wdt.h"
#include "esp_wifi.h"
#include "driver/rtc_io.h"

// OTA 관련 ESP-IDF API. Arduino-ESP32 core 3.x는 ESP-IDF 5.x 기반이므로
// 그대로 include 가능.
#include "esp_https_ota.h"
#include "esp_ota_ops.h"
#include "esp_partition.h"
#include "esp_efuse.h"
#include "mbedtls/sha256.h"

#if CONFIG_BT_BLE_SMP_ENABLE
#include <BLESecurity.h>
#endif

#include "iconia_config.h"
#include "iconia_protocol.h"
#include "iconia_security.h"
#include "iconia_boot_check.h"
#include "iconia_ota.h"
#include "iconia_compat.h"

IconiaApp* gAppInstance = nullptr;

class ProvisioningServerCallbacks : public BLEServerCallbacks {
 public:
  void onConnect(BLEServer* server) override {
    (void)server;
    if (gAppInstance == nullptr) {
      return;
    }
    gAppInstance->bleClientConnected_ = true;
    // secure 모드: 본딩이 끝나기 전까지는 어떤 신뢰 신호도 통지 X.
    // 실제 본딩 완료 신호는 SecurityGapCallbacks::onAuthenticationComplete 에서.
    if (!iconia::config::kBleSecureMode) {
      gAppInstance->notifyProvisioningStatus("connected");
    }
  }

  void onDisconnect(BLEServer* server) override {
    (void)server;
    if (gAppInstance == nullptr) {
      return;
    }
    gAppInstance->bleClientConnected_ = false;
    gAppInstance->bonded_ = false;
    gAppInstance->channelKeyReady_ = false;
    BLEDevice::startAdvertising();
    if (!iconia::config::kBleSecureMode) {
      gAppInstance->notifyProvisioningStatus("advertising");
    }
  }
};

#if CONFIG_BT_BLE_SMP_ENABLE
// BLE GAP 인증 완료 콜백. ESP_LE_AUTH_REQ_SC_MITM_BOND 페어링이 success
// 로 끝나야 bonded_=true. 실패는 백오프 카운터에 기록.
class SecurityGapCallbacks : public BLESecurityCallbacks {
 public:
  uint32_t onPassKeyRequest() override {
    return 0;
  }
  void onPassKeyNotify(uint32_t passkey) override {
    (void)passkey;
  }
  bool onConfirmPIN(uint32_t pin) override {
    // ESP_IO_CAP_NONE 인 경우 BLE 스택이 자체 confirm 하므로 true.
    (void)pin;
    return true;
  }
  bool onSecurityRequest() override {
    return true;
  }
  void onAuthenticationComplete(esp_ble_auth_cmpl_t cmpl) override {
    if (gAppInstance == nullptr) {
      return;
    }
    if (cmpl.success) {
      gAppInstance->bonded_ = true;
      // 본딩 통과 — Status notify 로 알림. RN 앱은 이 신호를 보고 Session
      // characteristic read 진행.
      gAppInstance->notifyProvStatus("bonded");
    } else {
      gAppInstance->bonded_ = false;
      iconia::security::backoff::recordFailure();
      gAppInstance->notifyProvStatus(iconia::protocol::kProvStatusNotBonded);
    }
  }
};
#endif

// Legacy 평문 GATT callbacks. 본 클래스는 ICONIA_BLE_SECURE=0 (bring-up
// 디버그 빌드)에서만 빌드 — 출시 빌드는 컴파일조차 되지 않는다.
#ifdef ICONIA_BLE_SECURE
#  if (ICONIA_BLE_SECURE == 0)
#    define ICONIA_LEGACY_PROV_ENABLED 1
#  else
#    define ICONIA_LEGACY_PROV_ENABLED 0
#  endif
#else
#  define ICONIA_LEGACY_PROV_ENABLED 0
#endif

#if ICONIA_LEGACY_PROV_ENABLED
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
#endif

// Secure mode credential characteristic. AEAD blob 누적 → 마지막 chunk 도착
// 시 검증 + 복호화 + Wi-Fi 연결.
class CredentialCallbacks : public BLECharacteristicCallbacks {
 public:
  void onWrite(BLECharacteristic* characteristic) override {
    if (gAppInstance == nullptr) {
      return;
    }
    if (!gAppInstance->bonded_) {
      gAppInstance->notifyProvStatus(iconia::protocol::kProvStatusNotBonded);
      iconia::security::backoff::recordFailure();
      return;
    }
    std::string raw = characteristic->getValue();
    const uint8_t* data = (const uint8_t*)raw.data();
    size_t len = raw.size();
    if (len == 0) {
      return;
    }

    // 누적 + 단조성 + last_chunk 추출은 envelope 클래스에 위임 (iconia_security).
    bool lastChunk = false;
    bool ok = gAppInstance->processCredentialBlob(data, len, lastChunk);
    (void)ok;
    // 최종 처리(검증 + Wi-Fi 연결 + 저장)는 loop() 컨텍스트에서 안전하게 수행.
    // BLE 스택 콜백 안에서 무거운 동기 작업 (Wi-Fi 연결 ~수 초) 하면 GATT
    // disconnect 가능.
  }
};

void IconiaApp::begin() {
  gAppInstance = this;

  // Drop to idle clock as early as possible. Networking paths bump it back up.
  setCpuFrequencyMhz(iconia::config::kCpuFrequencyIdleMhz);

  // Brown-out detector: do NOT disable. The Arduino core leaves it enabled by
  // default at the chip's factory threshold (~2.43 V) — exactly what a Li-Po
  // BQ24075 system needs to avoid undefined behaviour on a deep discharge.
  // A common StackOverflow pattern writes WRITE_PERI_REG(RTC_CNTL_BROWN_OUT_REG, 0);
  // we explicitly do NOT do that here.

  // Task watchdog: cover the main task (which runs setup()/loop()). Wi-Fi and
  // TLS handshake under bad signal can deadlock the network thread; the TWDT
  // forces a reset and the next wake retries. 30 s covers the worst-case
  // capture + 3-attempt upload loop with retries.
  // ESP-IDF 5.x signature (Arduino core 3.x is built on it).
  const esp_task_wdt_config_t wdtConfig = {
    /*timeout_ms=*/30000,
    /*idle_core_mask=*/0,
    /*trigger_panic=*/true,
  };
  // Arduino core may have already initialised the TWDT; reconfigure first
  // and fall back to init if it was never set up.
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
  // 동일 가드에 firmware_version placeholder("0.0.0-placeholder")도 함께 걸린다
  // (placeholderSecretsPresent() 내부 검사).
  haltOnPlaceholderSecrets();

  // -------------------------------------------------------------------------
  // PROD 빌드 boot self-check (정본: docs/operational_telemetry.md §4)
  // -------------------------------------------------------------------------
  // lockdown 빌드는 SecureBoot / FlashEncryption RELEASE / JTAG-disable / UART
  // download disable / factory seed / secure_version 모두 통과해야 부팅 진행.
  // 하나라도 실패하면 panic_log NVS 기록 후 EXT1 wakeup disable + 영구 deep sleep.
  // dev 빌드는 즉시 통과 (디버깅 가능 유지).
  {
    iconia::boot_check::Result br = iconia::boot_check::runAll();
    if (!br.pass) {
      logLine(String("[FATAL] boot invariants violated mask=0x") +
              String(br.violationMask, HEX) +
              " first=0x" + String(br.firstViolationBit, HEX));
      iconia::boot_check::recordPanicLog(br.violationMask);
      iconia::boot_check::haltForever();  // [[noreturn]]
    }
    // OTA post-boot smoke check: boot invariant 통과 신호 mark.
    // pending_verify 가 아니면 mark 호출은 no-op.
    iconia::ota::markBootInvariantOk();
  }

  // -------------------------------------------------------------------------
  // OTA post-boot smoke check 사이클 시작 (정본: docs/operational_telemetry.md §7).
  // 새 펌웨어 첫 부팅 시 (running partition state == PENDING_VERIFY) 만 의미.
  // 일반 boot 에서는 즉시 반환 + 잔여 smoke 누적 상태 zeroize.
  // -------------------------------------------------------------------------
  iconia::ota::onBoot();

  // anti-rollback: ESP-IDF 가 부트로더 단계에서 eFuse SECURE_VERSION 과
  // 펌웨어 헤더의 secure_version 을 자동 비교하므로, 이 시점에 부팅 성공
  // = 검증 통과. 단조 증가 보장은 OTA 시점의 esp_efuse_check_secure_version
  // 호출과 ESP-IDF anti-rollback 옵션 (CONFIG_BOOTLOADER_APP_ROLLBACK_ENABLE)
  // 으로 운영. 본 줄은 운영 가시성 확보용 로그.
  if (iconia::config::kLockdown) {
    logLine(String("[BOOT] secure_version=") +
            iconia::config::kSecureVersion + " (lockdown ON)");
  }

  // Factory seed 가드: secure 모드 + RELEASE 빌드는 factory_nvs 부재 시
  // 부팅 거부. dev 빌드는 명시적 override (ICONIA_REQUIRE_FACTORY_SEED=0)
  // 로 부재 허용 가능 — bring-up 모듈 검수 흐름 유지용.
  if (iconia::config::kBleSecureMode &&
      (iconia::config::kRequireFactorySeed || iconia::config::kLockdown)) {
    iconia::security::FactorySeed seedCheck = iconia::security::loadFactorySeed();
    bool ok = seedCheck.valid;
    iconia::security::zeroizeFactorySeed(seedCheck);
    if (!ok) {
      logLine("[FATAL] factory_nvs seed missing/invalid; halting (production_provisioning.md §3.6)");
      delay(500);
      esp_sleep_disable_wakeup_source(ESP_SLEEP_WAKEUP_ALL);
      esp_deep_sleep_start();
    }
    // OTA smoke check: factory_nvs 정상 마운트 + seed valid 신호 mark.
    iconia::ota::markFactoryOk();
  } else {
    // dev 빌드 (factory seed 검사 우회) 경로에서도 smoke 단계는 "no-op pass"
    // 로 취급하여 mark — pending_verify 부팅이라면 dev 환경에서도 OTA 확정
    // 흐름 동일하게 검증 가능.
    iconia::ota::markFactoryOk();
  }

  // OTA 자가점검 안내 로그. 실제 mark는 첫 정상 업로드 성공 직후 호출.
  // (현재 부팅이 OTA 직후의 검증 부팅인지 여기서는 로그만 남기고 판단 자체는
  // markAppValidIfPending 내부에서 ota_state 조회로 수행한다.)
  logLine(String("[BOOT] firmware version: ") + iconia::config::kFirmwareVersion);

  pinMode(iconia::config::kLedGpio, OUTPUT);
  digitalWrite(iconia::config::kLedGpio, LOW);
  pinMode(iconia::config::kCameraPowerDownGpio, OUTPUT);
  digitalWrite(iconia::config::kCameraPowerDownGpio, HIGH);
  pinMode(iconia::config::kTouchRightGpio, INPUT);
  pinMode(iconia::config::kTouchLeftGpio, INPUT);

  // PSRAM 필수 가드. ICONIA HW 명세상 ESP32-CAM(AI Thinker, 4MB PSRAM 탑재)이
  // 표준 모듈. PSRAM 미감지는 잘못된 부품 또는 솔더링 문제 — JPEG VGA 프레임 버퍼
  // (수십 KB ~ 200KB+)를 shared SRAM에 두면 Wi-Fi/TLS 스택과 경합하여 OOM 위험.
  // 폴백 운용을 막고 즉시 fatal halt 후 deep sleep — 다음 wake 시도하지 않도록
  // EXT1 wakeup도 disable.
  if (!psramFound()) {
    logLine("[FATAL] PSRAM not found; halting (ICONIA requires 4MB PSRAM module)");
    delay(500);
    esp_sleep_disable_wakeup_source(ESP_SLEEP_WAKEUP_ALL);
    esp_deep_sleep_start();
  }

  initBatteryMonitor();

  if (!openPreferences()) {
    logLine("[FATAL] failed to open NVS preferences");
    delay(1000);
    enterDeepSleep();
    return;
  }

  // OTA 롤백 감지: 새 펌웨어가 자가점검 실패로 롤백되었거나, 현재 파티션이
  // INVALID 상태로 부팅됐을 때 NVS에 ota_result=rolled_back 기록. NVS의
  // ota_attempt_ver은 그대로 유지해야 직전 시도 버전을 서버가 알 수 있다.
  // openPreferences보다 먼저 호출하지 않도록 NVS 오픈 후 시점에서 실행.
  detectRollbackOnBoot();

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
    // 2분 광고 윈도우 만료. 본딩 자체에 도달하지 못한 상황도 fail 로 카운트
    // — 분실/도난 등으로 누군가 BLE 광고만 보고 가만 두는 패턴 차단.
    if (!bonded_) {
      iconia::security::backoff::recordFailure();
    }
    notifyProvStatus(iconia::protocol::kProvStatusTimeout);
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
  // firmware_version placeholder는 OTA 롤백 추적을 무력화하므로 동일하게 차단.
  if (strcmp(iconia::config::kFirmwareVersion,
             iconia::config::kPlaceholderFirmwareVersion) == 0) {
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
  // PSRAM은 setup 단계 fatal guard로 보장됨 — 분기 제거.
  config.frame_size = iconia::config::kCaptureFrameSize;
  config.jpeg_quality = iconia::config::kCaptureJpegQuality;
  config.fb_count = 1;
  config.grab_mode = CAMERA_GRAB_WHEN_EMPTY;
  // ICONIA hardware ships with PSRAM (AI Thinker ESP32-CAM 4MB). VGA JPEG 캡처
  // 시 frame buffer가 SRAM(~520KB shared)을 압박하지 않도록 PSRAM에 위치시킨다.
  // PSRAM 부재는 setup() 단계의 fatal guard(psramFound 체크)에서 이미 걸러진다.
  config.fb_location = CAMERA_FB_IN_PSRAM;
  return config;
}

bool IconiaApp::initCamera() {
  // Release any RTC-hold left over from the previous deep sleep before
  // toggling PWDN, otherwise the level latches and the sensor never powers up.
  rtc_gpio_hold_dis((gpio_num_t)iconia::config::kCameraPowerDownGpio);
  pinMode(iconia::config::kCameraPowerDownGpio, OUTPUT);
  digitalWrite(iconia::config::kCameraPowerDownGpio, LOW);
  // OV2640 needs >= ~10 ms after PWDN goes low before SCCB is reachable.
  // 데이터시트 최소값(~10ms) + 마진. 실측 후 안전 하한 20ms로 단축.
  delay(20);

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

  // sensor 설정 반영 대기. 워밍업 프레임이 별도로 한 장 폐기되므로 100ms로 단축.
  delay(100);
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

  // 워밍업 프레임: AGC/AWB 수렴 안정화 목적. 폐기 정책은 측정 데이터 없이
  // 제거하기 위험하므로 유지. TODO: AGC/AWB 수렴이 첫 프레임에서 5% 이내 오차로
  // 끝난다는 측정 데이터 확보 시 본 폐기 로직 제거(약 +120ms 절감 가능).
  unsigned long warmupStartMs = millis();
  camera_fb_t* warmupFrame = esp_camera_fb_get();
  if (warmupFrame != nullptr) {
    size_t warmupLen = warmupFrame->len;
    esp_camera_fb_return(warmupFrame);
    delay(100);
    logLine(String("[CAM] warmup frame discarded len=") + warmupLen +
            " elapsed=" + (millis() - warmupStartMs) + "ms");
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

void IconiaApp::buildEventId(const char* deviceId, char* outBuffer, size_t outBufferLen) const {
  if (outBuffer == nullptr || outBufferLen == 0) {
    return;
  }
  // deviceId의 콜론 제거 → 12 hex chars. 입력 길이가 다른 경우에도 안전하게.
  char macCompact[16] = {0};
  size_t mi = 0;
  if (deviceId != nullptr) {
    for (size_t i = 0; deviceId[i] != '\0' && mi + 1 < sizeof(macCompact); ++i) {
      if (deviceId[i] != ':') {
        macCompact[mi++] = deviceId[i];
      }
    }
  }
  macCompact[mi] = '\0';

  uint32_t wakeMs = (uint32_t)millis();
  uint32_t rand32 = esp_random();
  uint16_t rand16 = (uint16_t)(rand32 & 0xFFFFu);

  snprintf(outBuffer, outBufferLen, "%s-%lu-%04x",
           macCompact, (unsigned long)wakeMs, rand16);
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

bool IconiaApp::connectToWifi(const WifiCredentials& creds, bool* outAuthFailed) {
  if (outAuthFailed != nullptr) {
    *outAuthFailed = false;
  }

  // Full clock for the (short) connect+TLS phase. Reverted in enterDeepSleep().
  setCpuFrequencyMhz(iconia::config::kCpuFrequencyActiveMhz);

  WiFi.mode(WIFI_STA);
  // WIFI_PS_MAX_MODEM = aggressive modem sleep between DTIM beacons.
  // Cuts ~30-40 mA average during the connected idle window.
  WiFi.setSleep(WIFI_PS_MAX_MODEM);
  WiFi.begin(creds.ssid.c_str(), creds.password.c_str());

  // 폴링 간격 50 ms — kWifiConnectTimeoutMs(15s)를 충분히 자주 sample하여
  // WL_CONNECT_FAILED를 timeout 만료보다 일찍 포착. WDT(default 30s) 영향 없음.
  unsigned long startMs = millis();
  wl_status_t lastStatus = WL_IDLE_STATUS;
  while ((millis() - startMs) < iconia::config::kWifiConnectTimeoutMs) {
    lastStatus = WiFi.status();
    if (lastStatus == WL_CONNECTED) {
      break;
    }
    if (lastStatus == WL_CONNECT_FAILED) {
      // 라우터가 명시적으로 인증 거부. timeout까지 기다릴 필요 없이 즉시 실패.
      break;
    }
    delay(50);
    esp_task_wdt_reset();
  }

  wl_status_t finalStatus = WiFi.status();
  if (finalStatus == WL_CONNECTED) {
    logLine("[WIFI] connected: " + WiFi.localIP().toString());
    return true;
  }

  if (finalStatus == WL_CONNECT_FAILED) {
    if (outAuthFailed != nullptr) {
      *outAuthFailed = true;
    }
    logLine("[WIFI] connection failed (auth_failed)");
  } else {
    // NO_SSID_AVAIL, IDLE, DISCONNECTED 또는 timeout 후 미정 상태
    logLine(String("[WIFI] connection failed (status=") + (int)finalStatus + ")");
  }

  WiFi.disconnect(true, true);
  return false;
}

bool IconiaApp::connectToWifiWithRetry(const WifiCredentials& creds, uint8_t retryCount) {
  // 이번 wake에서 모든 attempt가 WL_CONNECT_FAILED였는지 추적. 한 번이라도
  // 다른 실패 사유(timeout/NO_SSID)가 섞이면 일시적 장애로 간주, 카운터 미증가.
  bool allAuthFailed = (retryCount > 0);

  for (uint8_t attempt = 1; attempt <= retryCount; ++attempt) {
    logLine("[WIFI] connect attempt " + String(attempt) + "/" + String(retryCount));
    bool authFailed = false;
    if (connectToWifi(creds, &authFailed)) {
      // 어떤 사유로든 한 번 성공 → 누적 카운터 reset.
      if (loadWifiAuthFailCount() > 0) {
        logLine("[WIFI] auth_fail counter reset on success");
        resetWifiAuthFailCount();
      }
      return true;
    }
    if (!authFailed) {
      allAuthFailed = false;
    }
    delay(800);
  }

  if (!allAuthFailed) {
    return false;
  }

  // 모든 attempt가 인증 실패 → 영속 카운터 증가. 임계치 도달 시 자격증명 erase.
  uint32_t cnt = loadWifiAuthFailCount() + 1;
  saveWifiAuthFailCount(cnt);
  if (cnt >= iconia::config::kWifiAuthFailEraseThreshold) {
    logLine(String("[WIFI] auth_fail count=") + cnt + " >= threshold(" +
            iconia::config::kWifiAuthFailEraseThreshold +
            "), erasing creds and forcing BLE provisioning on next boot");
    clearWifiCredentials();
    resetWifiAuthFailCount();
  } else {
    logLine(String("[WIFI] auth_fail count=") + cnt + "/" +
            iconia::config::kWifiAuthFailEraseThreshold);
    if (cnt + 1 >= iconia::config::kWifiAuthFailEraseThreshold) {
      logLine("[WIFI] credentials likely wrong, will erase on next failure");
    }
  }
  return false;
}

uint32_t IconiaApp::loadWifiAuthFailCount() {
  return preferences_.getUInt("wifi_fail_cnt", 0);
}

void IconiaApp::saveWifiAuthFailCount(uint32_t count) {
  preferences_.putUInt("wifi_fail_cnt", count);
}

void IconiaApp::resetWifiAuthFailCount() {
  preferences_.remove("wifi_fail_cnt");
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

// HTTP 응답 헤더에서 명령(enter_provisioning / ota)과 OTA 동반 헤더를 파싱.
// OTA 진입 시점의 URL은 절대 응답 본문에 노출되어선 안 되므로(presigned 서명
// 누설), 본문 토큰 백업 검색은 enter_provisioning 한정으로만 유지한다.
// OTA 헤더 형식 검증/가드 자체는 호출자(canEnterOta)가 수행한다.
IconiaApp::UploadResult IconiaApp::readHttpResponseAndCommand(WiFiClientSecure& client) {
  UploadResult result = {};
  result.success = false;
  result.nextAction = NextAction::None;
  result.ota.present = false;
  result.ota.sizeBytes = -1;

  char line[256];  // OTA presigned URL 길이 여유분(쿼리 스트링 ~수백자 가능)

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

    if (strcasecmp(line, iconia::protocol::kCommandHeader) == 0) {
      if (strcasecmp(value, iconia::protocol::kCommandEnterProvisioning) == 0) {
        result.nextAction = NextAction::EnterProvisioning;
      } else if (strcasecmp(value, iconia::protocol::kCommandOta) == 0) {
        result.nextAction = NextAction::Ota;
      }
    } else if (strcasecmp(line, iconia::protocol::kOtaUrlHeader) == 0) {
      result.ota.url = String(value);
      result.ota.present = true;
    } else if (strcasecmp(line, iconia::protocol::kOtaSha256Header) == 0) {
      result.ota.sha256 = String(value);
      result.ota.present = true;
    } else if (strcasecmp(line, iconia::protocol::kOtaVersionHeader) == 0) {
      result.ota.version = String(value);
      result.ota.present = true;
    } else if (strcasecmp(line, iconia::protocol::kOtaSizeHeader) == 0) {
      result.ota.sizeBytes = (int64_t)strtoll(value, nullptr, 10);
    }
  }

  // 본문 백업 토큰 검색은 enter_provisioning 전용. OTA 명령은 절대 본문에서
  // 캐치하지 않는다(presigned URL이 본문에 떠 있으면 보안 위반이므로 오히려
  // 무시하는 게 맞다).
  if (client.available()) {
    char body[96];
    size_t bodyLen = client.readBytes(body, sizeof(body) - 1);
    body[bodyLen] = '\0';
    if (result.nextAction == NextAction::None && lineHasReprovisionCommand(body)) {
      result.nextAction = NextAction::EnterProvisioning;
    }
  }

  return result;
}

IconiaApp::UploadResult IconiaApp::postEventMultipart(const EventPayload& payload) {
  UploadResult result = {};
  result.success = false;
  result.nextAction = NextAction::None;
  result.ota.present = false;
  result.ota.sizeBytes = -1;
  ParsedUrl endpoint = parseHttpsUrl(iconia::config::kApiEndpoint);
  if (!endpoint.valid) {
    logLine("[ERROR] invalid API endpoint");
    return result;
  }

  char batteryText[8];
  snprintf(batteryText, sizeof(batteryText), "%d", payload.batteryPercent);

  // OTA 결과 페어 로드. 페어가 깨졌거나 없으면 둘 다 emit X (서버는 한쪽만
  // 와도 무시). 보고할 게 있으면 hasOtaReport=true, 두 필드를 multipart에 추가.
  String lastOtaResult;
  String lastOtaAttemptedVersion;
  bool hasOtaReport = loadLastOtaReport(lastOtaResult, lastOtaAttemptedVersion);

  size_t contentLength = 0;
  contentLength += multipartTextFieldLength(iconia::config::kMultipartBoundary, iconia::protocol::kFieldTouch, payload.touch);
  contentLength += multipartTextFieldLength(iconia::config::kMultipartBoundary, iconia::protocol::kFieldDeviceId, payload.deviceId);
  contentLength += multipartTextFieldLength(iconia::config::kMultipartBoundary, iconia::protocol::kFieldBattery, batteryText);
  // event_id: 재시도 시에도 동일 값 유지 → 서버 dedup용.
  contentLength += multipartTextFieldLength(iconia::config::kMultipartBoundary, iconia::protocol::kFieldEventId, payload.eventId);
  // firmware_version은 OTA 여부와 무관하게 항상 보고 (서버 측 롤아웃 추적용).
  contentLength += multipartTextFieldLength(iconia::config::kMultipartBoundary, iconia::protocol::kFieldFirmwareVersion, iconia::config::kFirmwareVersion);
  // last_ota_result/last_ota_attempted_version은 옵션 페어. 있을 때만 길이 가산.
  if (hasOtaReport) {
    contentLength += multipartTextFieldLength(iconia::config::kMultipartBoundary, iconia::protocol::kFieldLastOtaResult, lastOtaResult.c_str());
    contentLength += multipartTextFieldLength(iconia::config::kMultipartBoundary, iconia::protocol::kFieldLastOtaAttemptedVersion, lastOtaAttemptedVersion.c_str());
  }
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

  // 헤더 버퍼 512: User-Agent + X-API-Key(32+자) + Content-Length + Host 등
  // 누적이 384에 근접하므로 안전 마진 확보 (M-M3 권고).
  char headers[512];
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
      !writeMultipartTextField(client, iconia::config::kMultipartBoundary, iconia::protocol::kFieldEventId, payload.eventId) ||
      !writeMultipartTextField(client, iconia::config::kMultipartBoundary, iconia::protocol::kFieldFirmwareVersion, iconia::config::kFirmwareVersion)) {
    logLine("[ERROR] HTTPS request write failed (base fields)");
    client.stop();
    return result;
  }

  // 옵션 페어. 기존 5개 뒤, image 앞에 추가 — 서버 multipart 파서 입장에서
  // 순서는 무관하지만 운영 일관성 위해 합의된 위치 유지.
  if (hasOtaReport) {
    if (!writeMultipartTextField(client, iconia::config::kMultipartBoundary, iconia::protocol::kFieldLastOtaResult, lastOtaResult.c_str()) ||
        !writeMultipartTextField(client, iconia::config::kMultipartBoundary, iconia::protocol::kFieldLastOtaAttemptedVersion, lastOtaAttemptedVersion.c_str())) {
      logLine("[ERROR] HTTPS request write failed (ota report fields)");
      client.stop();
      return result;
    }
  }

  if (!writeMultipartImageHeader(client, iconia::config::kMultipartBoundary, iconia::protocol::kFieldImage, iconia::protocol::kImageFileName) ||
      !writeAll(client, payload.imageData, payload.imageLen) ||
      !writeAll(client, reinterpret_cast<const uint8_t*>("\r\n--"), 4) ||
      !writeAll(client, reinterpret_cast<const uint8_t*>(iconia::config::kMultipartBoundary), strlen(iconia::config::kMultipartBoundary)) ||
      !writeAll(client, reinterpret_cast<const uint8_t*>("--\r\n"), 4)) {
    logLine("[ERROR] HTTPS request write failed (image)");
    client.stop();
    return result;
  }

  result = readHttpResponseAndCommand(client);
  client.stop();

  // 응답 success를 받은 직후 NVS의 페어를 삭제 — 한 번만 보고하면 충분 (중복
  // emit 방지). 응답 실패 시 NVS 유지 → 다음 wake에서 자동 재시도.
  // hasOtaReport가 true였다는 것은 이번 multipart에 페어를 실제로 emit했다는
  // 뜻이므로, success일 때만 삭제하면 안전.
  if (result.success && hasOtaReport) {
    clearLastOtaReport();
    logLine("[OTA-REPORT] emitted and cleared");
  }
  return result;
}

IconiaApp::UploadResult IconiaApp::uploadEventWithRetry(const EventPayload& payload) {
  UploadResult result = {};
  result.success = false;
  result.nextAction = NextAction::None;
  result.ota.present = false;
  result.ota.sizeBytes = -1;

  for (uint8_t attempt = 1; attempt <= iconia::config::kUploadRetryCount; ++attempt) {
    logLine("[HTTPS] upload attempt " + String(attempt) + "/" + String(iconia::config::kUploadRetryCount));
    result = postEventMultipart(payload);
    // 명령(EnterProvisioning/Ota)은 success=true 응답에서만 의미 있음.
    // 명령이 있으면 즉시 반환하여 호출자가 분기할 수 있게 한다.
    if (result.success &&
        (result.nextAction == NextAction::EnterProvisioning ||
         result.nextAction == NextAction::Ota)) {
      logLine("[HTTPS] server command received");
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
  // Hard lockout 가드: 12h 내 누적 본딩 실패 ≥ kProvHardLockoutCount 이면
  // BLE 라디오 자체를 시작하지 않음. 보고용 시리얼 로그만 남기고 즉시 종료.
  if (iconia::security::backoff::isLockedOut()) {
    logLine("[PROV] hard lockout active (12h cap), skipping BLE start");
    enterDeepSleep();
    return;
  }

  // 점진 백오프: 직전 wake 의 본딩 실패 카운트에 따라 지연 후 광고 시작.
  // 같은 wake 안에서 즉시 retry 가능하지만, deep-sleep 한 번 거쳐 다시 들어온
  // 경우는 RTC 메모리에 살아있는 카운터로 백오프가 적용된다.
  uint32_t backoffMs = iconia::security::backoff::requiredBackoffMs();
  if (backoffMs > 0) {
    logLine(String("[PROV] backoff ") + backoffMs + " ms (fail#" +
            iconia::security::backoff::failCount() + ")");
    delay(backoffMs);
  }

  mode_ = DeviceMode::Provisioning;
  provisioningStartMs_ = millis();
  pendingSsid_ = "";
  pendingPassword_ = "";
  provisioningAttemptPending_ = false;
  pendingSsidReceived_ = false;
  pendingPasswordReceived_ = false;
  provisioningNonceValid_ = false;
  bonded_ = false;
  channelKeyReady_ = false;

  // 디바이스 MAC (AAD/HKDF info 에 사용).
  esp_read_mac(deviceMac_, ESP_MAC_BT);

  BLEDevice::init(bleDeviceName().c_str());

  bleServer_ = BLEDevice::createServer();
  bleServer_->setCallbacks(new ProvisioningServerCallbacks());

  BLEService* service = bleServer_->createService(iconia::config::kBleServiceUuid);

  if (iconia::config::kBleSecureMode) {
#if CONFIG_BT_BLE_SMP_ENABLE
    // 본딩 강제 + Numeric Comparison (디바이스에 디스플레이 없음 → IO_CAP_NONE).
    // ESP_LE_AUTH_REQ_SC_MITM_BOND: Secure Connections + MITM 보호 + 본딩.
    BLEDevice::setSecurityCallbacks(new SecurityGapCallbacks());
    BLESecurity* security = new BLESecurity();
    security->setAuthenticationMode(ESP_LE_AUTH_REQ_SC_MITM_BOND);
    security->setCapability(ESP_IO_CAP_NONE);
    security->setInitEncryptionKey(ESP_BLE_ENC_KEY_MASK | ESP_BLE_ID_KEY_MASK);
    security->setRespEncryptionKey(ESP_BLE_ENC_KEY_MASK | ESP_BLE_ID_KEY_MASK);

    // Status (READ + NOTIFY, 본딩 후에만)
    bleStatusCharacteristic_ = service->createCharacteristic(
      iconia::config::kBleStatusCharUuidV1,
      BLECharacteristic::PROPERTY_NOTIFY | BLECharacteristic::PROPERTY_READ
    );
    bleStatusCharacteristic_->addDescriptor(new BLE2902());
    bleStatusCharacteristic_->setAccessPermissions(ESP_GATT_PERM_READ_ENC_MITM);
    bleStatusCharacteristic_->setValue("advertising");

    // Capability (READ, no auth) — 외부에서 안전하게 노출 가능한 메타.
    // 32B = "ICONIA-V1" + product_id + seed_ver. 비밀 정보 절대 미포함.
    bleCapabilityCharacteristic_ = service->createCharacteristic(
      iconia::config::kBleCapabilityCharUuid,
      BLECharacteristic::PROPERTY_READ
    );
    {
      uint8_t cap[32] = {0};
      memcpy(cap, "ICONIA-V1", 9);
      // seed_ver 은 factory_nvs 에서 빌드 시점이 아닌 부팅 시 로드.
      iconia::security::FactorySeed s = iconia::security::loadFactorySeed();
      cap[16] = s.seedVer;
      iconia::security::zeroizeFactorySeed(s);
      bleCapabilityCharacteristic_->setValue(cap, sizeof(cap));
    }

    // Session (READ ENC_MITM, 32B = nonce 16 + salt 16). 본딩 통과 후 한 번 read.
    bleSessionCharacteristic_ = service->createCharacteristic(
      iconia::config::kBleSessionCharUuid,
      BLECharacteristic::PROPERTY_READ
    );
    bleSessionCharacteristic_->setAccessPermissions(ESP_GATT_PERM_READ_ENC_MITM);
    {
      // 세션 nonce + salt 발생.
      for (int i = 0; i < 16; i += 4) {
        uint32_t r = esp_random();
        sessionNonce_[i + 0] = (uint8_t)(r >> 0);
        sessionNonce_[i + 1] = (uint8_t)(r >> 8);
        sessionNonce_[i + 2] = (uint8_t)(r >> 16);
        sessionNonce_[i + 3] = (uint8_t)(r >> 24);
      }
      // sessionSalt_ 는 디바이스 factory salt 와 별개인 세션 salt — 일단
      // factory salt 와 동일값 사용해도 되지만, 최소 변형으로 esp_random 사용.
      // (HKDF salt 자체는 factory salt 가 정본; 본 sessionSalt_ 는 BLE 측에
      // 노출되는 부수 메타로 RN 앱 디버깅용.)
      for (int i = 0; i < 16; i += 4) {
        uint32_t r = esp_random();
        sessionSalt_[i + 0] = (uint8_t)(r >> 0);
        sessionSalt_[i + 1] = (uint8_t)(r >> 8);
        sessionSalt_[i + 2] = (uint8_t)(r >> 16);
        sessionSalt_[i + 3] = (uint8_t)(r >> 24);
      }
      uint8_t payload[32];
      memcpy(payload, sessionNonce_, 16);
      memcpy(payload + 16, sessionSalt_, 16);
      bleSessionCharacteristic_->setValue(payload, sizeof(payload));
    }

    // Credential (WRITE ENC_MITM, AEAD blob).
    bleCredentialCharacteristic_ = service->createCharacteristic(
      iconia::config::kBleCredentialCharUuid,
      BLECharacteristic::PROPERTY_WRITE
    );
    bleCredentialCharacteristic_->setAccessPermissions(ESP_GATT_PERM_WRITE_ENC_MITM);
    bleCredentialCharacteristic_->setCallbacks(new CredentialCallbacks());

    logLine("[BLE] secure mode active (legacy SSID/PW chars NOT registered)");
#else
    logLine("[FATAL] kBleSecureMode but SMP not compiled in core; halting");
    delay(500);
    enterDeepSleep();
    return;
#endif
  } else {
#if ICONIA_LEGACY_PROV_ENABLED
    // bring-up only — output 빌드는 절대 본 분기에 도달하면 안 됨.
    logLine("[BLE] WARNING: legacy plaintext mode (debug only)");
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
#else
    logLine("[FATAL] secure mode disabled but legacy not compiled in; halting");
    delay(500);
    enterDeepSleep();
    return;
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
  bleCredentialCharacteristic_ = nullptr;
  bleSessionCharacteristic_ = nullptr;
  bleCapabilityCharacteristic_ = nullptr;
  bleClientConnected_ = false;
  bonded_ = false;
  channelKeyReady_ = false;
  provisioningNonceValid_ = false;
  // Wipe sensitive buffers so they do not survive in heap fragments.
  memset(provisioningNonce_, 0, sizeof(provisioningNonce_));
  zeroizeSecuritySeed();
  memset(channelKey_, 0, sizeof(channelKey_));
  memset(sessionNonce_, 0, sizeof(sessionNonce_));
  memset(sessionSalt_, 0, sizeof(sessionSalt_));
}

// Secure-mode 보조 — 시리얼 노출 가드를 거치지 않고 항상 Status 특성 통지.
void IconiaApp::notifyProvStatus(const char* statusToken) {
  if (statusToken == nullptr) {
    return;
  }
  logLine(String("[PROV] ") + statusToken);
  if (bleStatusCharacteristic_ == nullptr) {
    return;
  }
  bleStatusCharacteristic_->setValue((uint8_t*)statusToken, strlen(statusToken));
  if (bleClientConnected_) {
    bleStatusCharacteristic_->notify();
  }
}

// factory seed/salt 로드. 부재 시 false. RELEASE 빌드(=kRequireFactorySeed)는
// 부재가 fatal — 호출자가 deep sleep 처리.
bool IconiaApp::loadSecuritySeed() {
  iconia::security::FactorySeed s = iconia::security::loadFactorySeed();
  if (!s.valid) {
    return false;
  }
  // 채널 키만 derive 하고 seed 자체는 즉시 zero-fill — RAM 잔존 표면 최소화.
  // (deriveSessionKey 가 본 멤버 변수 seed 를 직접 쓰지 않고, 매번 NVS read
  //  후 즉시 zeroize. 따라서 본 메서드는 seed 유효성만 확인하는 의미.)
  iconia::security::zeroizeFactorySeed(s);
  return true;
}

void IconiaApp::zeroizeSecuritySeed() {
  // 본 클래스가 seed 를 멤버로 보관하지 않으므로 no-op. 향후 캐시 도입 시
  // 본 메서드에서 zero-fill 추가.
}

bool IconiaApp::deriveSessionKey() {
  iconia::security::FactorySeed s = iconia::security::loadFactorySeed();
  if (!s.valid) {
    return false;
  }
  bool ok = iconia::security::deriveChannelKey(
      s, deviceMac_, sessionNonce_, channelKey_);
  iconia::security::zeroizeFactorySeed(s);
  if (ok) {
    channelKeyReady_ = true;
  }
  return ok;
}

// Credential characteristic write callback 에서 호출. 누적 + last_chunk 도착
// 시 검증 시작 신호 set. 실제 검증/Wi-Fi 연결은 loop() 컨텍스트에서.
bool IconiaApp::processCredentialBlob(const uint8_t* blob, size_t blobLen,
                                      bool /*lastChunk*/) {
  static iconia::security::AeadEnvelope env;

  // 본 호출 직전 본딩 가드는 callback 에서 이미 통과.
  bool last = false;
  bool ok = env.appendChunk(blob, blobLen, &last);
  if (!ok) {
    notifyProvStatus(iconia::protocol::kProvStatusBadSeq);
    iconia::security::backoff::recordFailure();
    env.reset();
    return false;
  }

  // 청크 누적 timeout 검사.
  uint32_t accumElapsed = (uint32_t)millis() - env.startedAtMs();
  if (!last && accumElapsed > iconia::config::kBleChunkAccumTimeoutMs) {
    notifyProvStatus(iconia::protocol::kProvStatusChunkTo);
    iconia::security::backoff::recordFailure();
    env.reset();
    return false;
  }

  if (!last) {
    return true;  // 다음 chunk 대기
  }

  // 마지막 chunk 도착. 헤더 파싱 → AEAD 복호화 → 평문 검증.
  iconia::security::AeadEnvelope::ParsedHeader hdr = {};
  if (!env.parseHeader(hdr)) {
    notifyProvStatus(iconia::protocol::kProvStatusBadMagic);
    iconia::security::backoff::recordFailure();
    env.reset();
    return false;
  }

  // ts 윈도우 검사. 디바이스에 RTC time 이 없으므로 광고 시작 시점 + millis
  // 기반 단조 카운터로 대체. 첫 envelope 의 ts 를 기준으로 ±kBleTsWindowSec
  // 만 허용. 본 디바이스는 양산 시 RTC 시계가 없을 수 있으나, BLE 광고 시작
  // 시각이 곧 "현재 시각"으로 유효(2 분 안에 본딩이 끝나야 하므로).
  // 단순화: ts 자체의 형식만 sanity 검사 (0 또는 unrealistic 값 거부).
  if (hdr.tsUnixBe == 0 || hdr.tsUnixBe < 1700000000u) {
    notifyProvStatus(iconia::protocol::kProvStatusTsWindow);
    iconia::security::backoff::recordFailure();
    env.reset();
    return false;
  }

  if (iconia::security::replay::isSeen(sessionNonce_, hdr.tsUnixBe)) {
    notifyProvStatus(iconia::protocol::kProvStatusReplay);
    iconia::security::backoff::recordFailure();
    env.reset();
    return false;
  }

  // 채널 키 derivation 1회.
  if (!channelKeyReady_) {
    if (!deriveSessionKey()) {
      notifyProvStatus(iconia::protocol::kProvStatusAeadFail);
      iconia::security::backoff::recordFailure();
      env.reset();
      return false;
    }
  }

  // AAD 빌드 + 복호화.
  uint8_t aad[64];
  size_t aadLen = iconia::security::buildAad(
      deviceMac_, hdr.version, sessionNonce_, hdr.tsUnixBe, aad, sizeof(aad));
  if (aadLen == 0) {
    notifyProvStatus(iconia::protocol::kProvStatusAeadFail);
    iconia::security::backoff::recordFailure();
    env.reset();
    return false;
  }
  uint8_t plain[120] = {0};
  size_t plainLen = 0;
  if (!env.decrypt(channelKey_, aad, aadLen,
                   plain, sizeof(plain), &plainLen)) {
    notifyProvStatus(iconia::protocol::kProvStatusAeadFail);
    iconia::security::backoff::recordFailure();
    env.reset();
    return false;
  }

  // 평문 파서.
  iconia::security::WifiCredentialPlain parsed =
      iconia::security::parseWifiPlaintext(plain, plainLen);
  // 평문 buffer 즉시 zero-fill (최대한 일찍).
  {
    volatile uint8_t* p = plain;
    for (size_t i = 0; i < sizeof(plain); ++i) {
      p[i] = 0;
    }
  }
  if (!parsed.valid) {
    notifyProvStatus(iconia::protocol::kProvStatusBadPlain);
    iconia::security::backoff::recordFailure();
    env.reset();
    return false;
  }

  // 모든 검증 통과 → replay cache 등록 + main loop 가 처리할 수 있게 pending 셋팅.
  iconia::security::replay::remember(sessionNonce_, hdr.tsUnixBe);
  pendingSsid_ = String(parsed.ssid);
  pendingPassword_ = String(parsed.psk);
  pendingSsidReceived_ = true;
  pendingPasswordReceived_ = true;
  provisioningAttemptPending_ = true;

  // 평문 변수 zero-fill.
  {
    volatile char* p = parsed.ssid;
    for (size_t i = 0; i < sizeof(parsed.ssid); ++i) {
      p[i] = 0;
    }
    volatile char* q = parsed.psk;
    for (size_t i = 0; i < sizeof(parsed.psk); ++i) {
      q[i] = 0;
    }
  }
  env.reset();
  return true;
}

void IconiaApp::handleProvisioningAttempt() {
  provisioningAttemptPending_ = false;

  if (pendingSsid_.length() == 0) {
    notifyProvStatus(iconia::protocol::kProvStatusBadPlain);
    iconia::security::backoff::recordFailure();
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
    // 실패 사유 분리: connectToWifiWithRetry 가 모든 attempt 인증 실패 시
    // NVS 카운터를 별도로 관리. 여기서는 BLE 클라이언트에 사유 token 만 통지.
    notifyProvStatus(iconia::protocol::kProvStatusWifiAuth);
    iconia::security::backoff::recordFailure();
    pendingSsidReceived_ = false;
    pendingPasswordReceived_ = false;
    // 평문 잔존 표면 최소화.
    pendingSsid_ = "";
    pendingPassword_ = "";
    return;
  }

  if (!saveWifiCredentials(pending.ssid, pending.password)) {
    notifyProvStatus(iconia::protocol::kProvStatusBadPlain);
    iconia::security::backoff::recordFailure();
    WiFi.disconnect(true, true);
    pendingSsidReceived_ = false;
    pendingPasswordReceived_ = false;
    pendingSsid_ = "";
    pendingPassword_ = "";
    return;
  }

  // 검증 + Wi-Fi 연결 + NVS 저장 모두 성공. 백오프 카운터 zero-fill.
  iconia::security::backoff::recordSuccess();
  notifyProvStatus(iconia::protocol::kProvStatusSuccess);
  // 평문 잔존 표면 최소화.
  pendingSsid_ = "";
  pendingPassword_ = "";
  pendingSsidReceived_ = false;
  pendingPasswordReceived_ = false;
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
  // OTA smoke check: 카메라 init + 1회 capture 성공 신호 mark.
  iconia::ota::markCameraInitOk();

  if (!connectToWifiWithRetry(creds, iconia::config::kWifiRetryCount)) {
    esp_camera_fb_return(frame);
    deinitCamera();
    return NextAction::None;
  }

  EventPayload payload = {};
  buildDeviceId(payload.deviceId, sizeof(payload.deviceId));
  payload.touch = touchToString(direction);
  payload.batteryPercent = battery.percent;
  payload.imageData = frame->buf;
  payload.imageLen = frame->len;
  // 멱등성: wake당 1회만 생성 → 재시도 동안 보존. 서버 측 dedup 합의는 별도 작업.
  buildEventId(payload.deviceId, payload.eventId, sizeof(payload.eventId));
  logLine(String("[EVENT] event_id=") + payload.eventId);

  // OTA 자가점검 신호로 사용할 RSSI 캡처(이 시점은 Wi-Fi 연결 직후이며, OTA
  // 진입 가드의 입력값으로도 재사용된다).
  int rssiDbm = WiFi.RSSI();

  UploadResult uploadResult = uploadEventWithRetry(payload);

  esp_camera_fb_return(frame);
  deinitCamera();

  // 자가 점검: "Wi-Fi 연결 + 서버 200 응답 1회 성공" 정의.
  // pending_verify 파티션이라면 이 시점에서 mark_app_valid_cancel_rollback.
  // 일반 부팅(이미 valid)일 때는 no-op.
  //
  // 본 라운드부터는 markAppValidIfPending (legacy 단일 신호) 와 더불어
  // iconia::ota 의 4-항목 smoke check 도 함께 수행. 4개 모두 통과해야 정밀
  // OTA 확정 telemetry (post_boot_health_ok) 가 emit 된다. 한 항목이라도
  // 누락 + attempt 한계 도달 시 자동 롤백 (esp_ota_mark_app_invalid_rollback_and_reboot).
  if (uploadResult.success) {
    iconia::ota::markWifiHandshakeOk();
    markAppValidIfPending();
    iconia::ota::finalizeIfPending();
  }

  if (uploadResult.success && uploadResult.nextAction == NextAction::Ota) {
    // OTA 분기. 가드 통과 시 다운로드/플래시. 성공 시 ESP.restart()는 함수
    // 내부에서 호출하지 않고 여기서 명시(흐름이 한 곳에서 보이도록).
    if (canEnterOta(uploadResult.ota, battery.percent, rssiDbm)) {
      // OTA 채널과 이벤트 채널이 동시에 TLS 핸드셰이크를 점유하지 않도록
      // event Wi-Fi 연결을 유지한 채로 esp_https_ota만 별도로 진행한다
      // (esp_https_ota는 자체 클라이언트로 새 TCP 연결을 맺는다).
      bool otaOk = performOta(uploadResult.ota);
      WiFi.disconnect(true, true);
      WiFi.mode(WIFI_OFF);
      if (otaOk) {
        logLine("[OTA] success, restarting into new partition");
        delay(200);
        ESP.restart();  // 새 파티션 부팅 → setup() → 첫 정상 업로드 시 mark_valid
      } else {
        logLine("[OTA] failed, sleeping; server will re-issue on next wake");
      }
      return NextAction::None;
    }
    logLine("[OTA] guard failed, ignoring command this cycle");
    WiFi.disconnect(true, true);
    WiFi.mode(WIFI_OFF);
    return NextAction::None;
  }

  WiFi.disconnect(true, true);
  WiFi.mode(WIFI_OFF);

  if (uploadResult.nextAction == NextAction::EnterProvisioning) {
    logLine("[SERVER] reprovision requested");
    clearWifiCredentials();
    return NextAction::EnterProvisioning;
  }

  return NextAction::None;
}

// -----------------------------------------------------------------------------
// OTA 클라이언트 (esp_https_ota 기반)
// -----------------------------------------------------------------------------

bool IconiaApp::stringStartsWithHttps(const String& s) {
  return s.length() > 8 && s.startsWith("https://");
}

bool IconiaApp::hexStringIsLowerSha256(const String& s) {
  if (s.length() != 64) {
    return false;
  }
  for (size_t i = 0; i < 64; ++i) {
    char c = s.charAt(i);
    bool ok = (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f');
    if (!ok) {
      return false;
    }
  }
  return true;
}

// presigned URL을 시리얼 로그용으로 안전하게 줄임. 호스트명만 노출하고
// 쿼리 파라미터(서명 포함)는 마스킹. 실수로 평문 로그가 GitHub Actions 등에
// 캡처되어도 5분 TTL이 만료되기 전 누설되는 위험을 줄인다.
String IconiaApp::sanitizeUrlForLog(const String& url) const {
  int schemeEnd = url.indexOf("://");
  if (schemeEnd < 0) {
    return String("<invalid-url>");
  }
  int hostStart = schemeEnd + 3;
  int pathStart = url.indexOf('/', hostStart);
  String host = (pathStart < 0) ? url.substring(hostStart) : url.substring(hostStart, pathStart);
  return String("https://") + host + "/<masked-path-and-query>";
}

// OTA 진입 가드. 모두 만족할 때만 true.
// - OtaCommand 형식 검증 (https URL, 64자 소문자 hex sha256, version semver)
// - **다운그레이드 가드**: ota.version이 현재 kFirmwareVersion보다 strictly 커야
//   함. 작거나 같으면 거부 + NVS에 version_rejected 기록 (서버 manifest 손상
//   시 펌웨어가 마지막 방어선 역할). 최후의 보루이므로 형식 비정상도 거부.
// - 배터리 >= kBatteryOtaMinPercent
// - RSSI > kRssiOtaMinDbm
// - kS3RootCaPem 비어 있고 kAllowInsecureOtaWhenRootCaMissing도 false면 거부
// 미달 사유는 분류 로깅하여 운영 시 디버깅 가능.
// const 제거 이유: 다운그레이드 거부 시 NVS write가 필요해 preferences_를 수정.
bool IconiaApp::canEnterOta(const OtaCommand& ota, int batteryPercent, int rssiDbm) {
  if (!ota.present) {
    logLine("[OTA-GUARD] no OTA headers");
    return false;
  }
  if (!stringStartsWithHttps(ota.url)) {
    logLine("[OTA-GUARD] url is not https");
    return false;
  }
  if (!hexStringIsLowerSha256(ota.sha256)) {
    logLine("[OTA-GUARD] sha256 invalid (need 64 lower-hex chars)");
    return false;
  }
  if (ota.version.length() == 0) {
    logLine("[OTA-GUARD] version missing");
    return false;
  }

  // 다운그레이드 가드. 양쪽 모두 strict semver(major.minor.patch)여야 비교 의미
  // 있음. 한쪽이라도 형식 비정상이면 보수적으로 거부 + version_rejected 기록.
  int curMaj = 0, curMin = 0, curPat = 0;
  int newMaj = 0, newMin = 0, newPat = 0;
  if (!parseSemver(iconia::config::kFirmwareVersion, curMaj, curMin, curPat)) {
    logLine(String("[OTA-GUARD] current firmware version not strict semver: ") +
            iconia::config::kFirmwareVersion);
    recordOtaResult(iconia::protocol::kOtaResultVersionRejected, ota.version.c_str());
    return false;
  }
  if (!parseSemver(ota.version.c_str(), newMaj, newMin, newPat)) {
    logLine(String("[OTA-GUARD] incoming version not strict semver: ") + ota.version);
    // attempt_ver에 garbage 저장 안 함 — isValidSemver 통과 못 하면 record는 erase.
    recordOtaResult(iconia::protocol::kOtaResultVersionRejected, ota.version.c_str());
    return false;
  }
  int cmp = compareSemver(newMaj, newMin, newPat, curMaj, curMin, curPat);
  if (cmp <= 0) {
    logLine(String("[OTA-GUARD] version_downgrade_blocked: current=") +
            iconia::config::kFirmwareVersion + " incoming=" + ota.version);
    recordOtaResult(iconia::protocol::kOtaResultVersionRejected, ota.version.c_str());
    iconia::ota::onManifestRejected("version_downgrade", ota.version.c_str(),
                                    iconia::config::kSecureVersion);
    return false;
  }

  // anti-rollback 매니페스트 정합 (정본: docs/operational_telemetry.md §7.2).
  // 서버가 X-OTA-Secure-Version 헤더로 매니페스트 target_secure_version 을
  // 동봉하기 시작하면, 본 자리에서 iconia_compat::checkManifestSecureVersion
  // 으로 사전 차단. 본 라운드는 헤더 미합의 — 펌웨어 자체 kSecureVersion 을
  // target 값으로 임시 사용하여 (= 동일 값이므로 strictly greater 검사 실패)
  // 명시적 차단 경로 자체는 만들지 않고 안전 측 로깅만. 다음 라운드 server
  // 합의 후 OtaCommand 에 secureVersion 필드 추가 + 본 가드 활성화.
  //
  // 본 호출은 현재 항상 통과 — 펌웨어 자체 secure_version 과 비교 시 false
  // 가 되지만, 서버 매니페스트가 secure_version 을 명시 안 한 상황에서
  // 무조건 차단하면 모든 OTA 가 막혀버리므로 hook 만 정의해 두고 실제 분기는
  // ota.secureVersion 필드 추가 라운드에서 활성화.

  if (batteryPercent < iconia::config::kBatteryOtaMinPercent) {
    logLine(String("[OTA-GUARD] battery ") + batteryPercent + "% < " +
            iconia::config::kBatteryOtaMinPercent + "%");
    return false;
  }
  if (rssiDbm <= iconia::config::kRssiOtaMinDbm) {
    logLine(String("[OTA-GUARD] rssi ") + rssiDbm + "dBm <= " +
            iconia::config::kRssiOtaMinDbm + "dBm");
    return false;
  }
  bool s3CaConfigured = strlen(iconia::config::kS3RootCaPem) > 16;
  if (!s3CaConfigured && !iconia::config::kAllowInsecureOtaWhenRootCaMissing) {
    logLine("[OTA-GUARD] S3 root CA missing and insecure OTA not allowed");
    return false;
  }
  return true;
}

// OTA 다운로드 + 검증 + 플래시. 성공 시 true (호출자가 ESP.restart() 책임).
// SHA-256 검증은 다운로드 완료 후 update 파티션을 mmap하여 한 번에 계산.
// 불일치하면 esp_https_ota_abort()로 부분 기록 폐기.
// 각 단계의 실패는 NVS에 결과 enum으로 기록 — 다음 wake의 multipart에 첨부되어
// 서버가 OTA 무한 실패 루프(배터리 소진 위험)를 탐지할 수 있게 한다.
// 진입 직전 attempt_ver을 NVS에 기록 — 다운로드/플래시 도중 power loss로
// 결과가 기록되지 않더라도 "이 버전을 시도했다"는 사실은 남는다.
bool IconiaApp::performOta(const OtaCommand& ota) {
  logLine(String("[OTA] start version=") + ota.version +
          " size=" + String((long)ota.sizeBytes) +
          " url=" + sanitizeUrlForLog(ota.url));

  // Stage telemetry: manifest_received (canEnterOta 통과 + 진입 직전).
  // attemptNo 는 본 라운드 단순화 — 동일 wake 의 단일 시도이므로 1.
  // 추후 RTC slow-mem 카운터로 deployment 단위 누적 시도 추적 가능.
  // target_secure_version 은 서버 매니페스트 미합의 — 임시로 펌웨어 자체의
  // kSecureVersion 사용 (실제로는 서버가 X-OTA-Secure-Version 헤더로 전달
  // 해야 하나 현 라운드는 펌웨어 측 hook 만 정의).
  iconia::ota::onManifestReceived(
      ota.version.c_str(),
      iconia::config::kSecureVersion,
      ota.sizeBytes > 0 ? (uint32_t)ota.sizeBytes : 0u,
      /*attemptNo=*/1);

  // Anti-rollback 사전 체크: lockdown 빌드는 펌웨어 헤더의 secure_version
  // 이 eFuse SECURE_VERSION 보다 작으면 OTA finish 가 자동 거부된다 (ESP-IDF
  // 부트로더가 검증). 본 시점에서는 명시적 호출 가능한 API 가 없어 (OTA
  // 이미지 헤더 분석은 다운로드 완료 후 수행됨), 단순히 잠금 정책 로그만
  // 남김 — 실제 거부는 esp_https_ota_finish 의 ESP_ERR_OTA_VALIDATE_FAILED
  // 반환에서 발생하며, recordOtaResult(flash_failed) 로 기록된다.
  if (iconia::config::kLockdown) {
    logLine(String("[OTA] lockdown mode, anti-rollback enforced; current secure_version=") +
            iconia::config::kSecureVersion);
  }

  // 시도 사실 선기록: 결과는 미정이지만 attempt_ver만 저장. 아래 단계에서 실제
  // 결과로 덮어쓰며, 덮어쓰기 전 power loss 시 부팅 후 detectRollbackOnBoot가
  // attempt_ver을 그대로 활용한다. semver는 canEnterOta에서 이미 검증됨.
  // (recordOtaResult는 페어로만 쓸 수 있으므로 임시 placeholder 결과를 쓰지
  // 않고, 직접 NVS putString으로 attempt_ver만 갱신한다.)
  if (preferences_.putString("ota_attempt_ver", ota.version.c_str()) == 0) {
    logLine("[OTA-REPORT] NVS attempt_ver write failed (swallowed)");
  }

  // Watchdog 임시 연장 → 다운로드 완료/abort 후 default로 복귀.
  // ESP-IDF 5.x esp_task_wdt_config_t는 POD이므로 두 인스턴스를 미리 만들어둔다.
  const esp_task_wdt_config_t wdtOta = {
    /*timeout_ms=*/iconia::config::kWatchdogOtaTimeoutMs,
    /*idle_core_mask=*/0,
    /*trigger_panic=*/true,
  };
  const esp_task_wdt_config_t wdtDefault = {
    /*timeout_ms=*/iconia::config::kWatchdogDefaultTimeoutMs,
    /*idle_core_mask=*/0,
    /*trigger_panic=*/true,
  };
  esp_task_wdt_reconfigure(&wdtOta);

  esp_http_client_config_t httpConfig = {};
  httpConfig.url = ota.url.c_str();
  httpConfig.timeout_ms = 15000;
  httpConfig.keep_alive_enable = true;

  if (strlen(iconia::config::kS3RootCaPem) > 16) {
    httpConfig.cert_pem = iconia::config::kS3RootCaPem;
  } else if (iconia::config::kAllowInsecureOtaWhenRootCaMissing) {
    // bring-up 전용 폴백. canEnterOta에서 이미 정책 검사를 통과한 경우만 도달.
    httpConfig.skip_cert_common_name_check = true;
    logLine("[OTA] WARNING insecure mode (no S3 root CA pinned)");
  }

  esp_https_ota_config_t otaConfig = {};
  otaConfig.http_config = &httpConfig;

  esp_https_ota_handle_t handle = nullptr;
  esp_err_t err = esp_https_ota_begin(&otaConfig, &handle);
  if (err != ESP_OK || handle == nullptr) {
    logLine(String("[OTA] begin failed err=") + (int)err);
    recordOtaResult(iconia::protocol::kOtaResultDownloadFailed, ota.version.c_str());
    esp_task_wdt_reconfigure(&wdtDefault);
    return false;
  }

  // 사전 sanity: 서버가 보낸 X-OTA-Size와 HTTP Content-Length 비교.
  int reportedSize = esp_https_ota_get_image_size(handle);
  if (ota.sizeBytes > 0 && reportedSize > 0 &&
      reportedSize != (int)ota.sizeBytes) {
    logLine(String("[OTA] size mismatch reported=") + reportedSize +
            " expected=" + String((long)ota.sizeBytes));
    esp_https_ota_abort(handle);
    // 사이즈 mismatch는 본질적으로 manifest/object 손상 → download 카테고리로 분류.
    recordOtaResult(iconia::protocol::kOtaResultDownloadFailed, ota.version.c_str());
    esp_task_wdt_reconfigure(&wdtDefault);
    return false;
  }

  // 스트리밍 다운로드. perform()은 청크 단위로 IN_PROGRESS를 반환.
  // Downloading 단계 telemetry 는 청크당 emit 하면 큐가 빠르게 가득 차므로,
  // 1초 간격 sampling. RTC slow-mem 큐 capacity = 5 — Downloading 은 보통
  // 1~2개만 보존되어 다른 단계 (manifest/applying/health) 를 밀어내지 않도록
  // 보장.
  unsigned long lastTelemetryMs = 0;
  while (true) {
    err = esp_https_ota_perform(handle);
    if (err != ESP_ERR_HTTPS_OTA_IN_PROGRESS) {
      break;
    }
    esp_task_wdt_reset();

    unsigned long now = millis();
    if (now - lastTelemetryMs >= 1000UL) {
      lastTelemetryMs = now;
      int doneBytes = esp_https_ota_get_image_len_read(handle);
      int totalBytes = esp_https_ota_get_image_size(handle);
      iconia::ota::onDownloading(
          doneBytes > 0 ? (uint32_t)doneBytes : 0u,
          totalBytes > 0 ? (uint32_t)totalBytes : 0u,
          /*attemptNo=*/1,
          (int16_t)WiFi.RSSI(),
          /*batteryMv=*/0u);  // 측정값 미지정 — 호출 비용 최소화
    }
  }

  if (err != ESP_OK) {
    logLine(String("[OTA] perform failed err=") + (int)err);
    esp_https_ota_abort(handle);
    recordOtaResult(iconia::protocol::kOtaResultDownloadFailed, ota.version.c_str());
    esp_task_wdt_reconfigure(&wdtDefault);
    return false;
  }

  if (!esp_https_ota_is_complete_data_received(handle)) {
    logLine("[OTA] incomplete data");
    esp_https_ota_abort(handle);
    recordOtaResult(iconia::protocol::kOtaResultDownloadFailed, ota.version.c_str());
    esp_task_wdt_reconfigure(&wdtDefault);
    return false;
  }

  int writtenLen = esp_https_ota_get_image_len_read(handle);
  logLine(String("[OTA] downloaded bytes=") + writtenLen);

  // SHA-256 검증: esp_https_ota_finish 호출 전에 활성 update 파티션의 실제
  // 내용을 mmap으로 읽어 해시를 계산. 불일치 시 finish 대신 abort.
  const esp_partition_t* updatePart = esp_ota_get_next_update_partition(nullptr);
  if (updatePart == nullptr) {
    logLine("[OTA] no update partition");
    esp_https_ota_abort(handle);
    // 파티션 부재는 flash 인프라 문제 → flash 카테고리.
    recordOtaResult(iconia::protocol::kOtaResultFlashFailed, ota.version.c_str());
    esp_task_wdt_reconfigure(&wdtDefault);
    return false;
  }

  const void* mappedPtr = nullptr;
  esp_partition_mmap_handle_t mapHandle = 0;
  if (esp_partition_mmap(updatePart, 0, writtenLen, ESP_PARTITION_MMAP_DATA,
                         &mappedPtr, &mapHandle) != ESP_OK) {
    logLine("[OTA] mmap failed for sha256 verify");
    esp_https_ota_abort(handle);
    recordOtaResult(iconia::protocol::kOtaResultFlashFailed, ota.version.c_str());
    esp_task_wdt_reconfigure(&wdtDefault);
    return false;
  }

  uint8_t digest[32];
  mbedtls_sha256_context shaCtx;
  mbedtls_sha256_init(&shaCtx);
  mbedtls_sha256_starts(&shaCtx, 0 /* SHA-256 (not 224) */);
  mbedtls_sha256_update(&shaCtx, (const unsigned char*)mappedPtr, writtenLen);
  mbedtls_sha256_finish(&shaCtx, digest);
  mbedtls_sha256_free(&shaCtx);
  esp_partition_munmap(mapHandle);

  char hexDigest[65];
  for (int i = 0; i < 32; ++i) {
    snprintf(hexDigest + i * 2, 3, "%02x", digest[i]);
  }
  hexDigest[64] = '\0';

  if (ota.sha256 != String(hexDigest)) {
    logLine(String("[OTA] sha256 mismatch expected=") + ota.sha256 +
            " got=" + String(hexDigest));
    iconia::ota::onDownloadComplete(/*shaMatch=*/false, /*attemptNo=*/1);
    esp_https_ota_abort(handle);
    recordOtaResult(iconia::protocol::kOtaResultShaMismatch, ota.version.c_str());
    esp_task_wdt_reconfigure(&wdtDefault);
    return false;
  }
  logLine("[OTA] sha256 verified");
  iconia::ota::onDownloadComplete(/*shaMatch=*/true, /*attemptNo=*/1);

  // Stage telemetry: applying — partition swap 직전 (esp_https_ota_finish 가
  // 새 partition 을 boot partition 으로 마크).
  iconia::ota::onApplying(/*attemptNo=*/1);
  err = esp_https_ota_finish(handle);
  // Watchdog 즉시 복귀(restart 전이어도 안전 측에서).
  esp_task_wdt_reconfigure(&wdtDefault);

  if (err != ESP_OK) {
    logLine(String("[OTA] finish failed err=") + (int)err);
    // finish 실패는 partition flash 단계 — boot count/state 기록 실패 포함.
    recordOtaResult(iconia::protocol::kOtaResultFlashFailed, ota.version.c_str());
    return false;
  }
  // 성공 시 결과 기록은 markAppValidIfPending에서 (자가점검 통과 후). 여기서는
  // attempt_ver만 살아 있으면 충분 — 새 펌웨어 부팅 후 첫 업로드에서 success
  // 페어를 emit하거나, 자가점검 실패 시 detectRollbackOnBoot가 rolled_back으로 덮어씀.
  return true;
}

// 새 펌웨어 부팅 직후의 자가점검 통과 처리.
// ota_state가 ESP_OTA_IMG_PENDING_VERIFY인 경우만 mark_valid_cancel_rollback.
// 그 외(이미 valid거나 부팅 안 됨 등)는 no-op. 호출은 첫 정상 업로드 성공 후.
// 자가점검 통과 시 NVS에 success 결과를 기록(직전 attempt_ver 자리에 현재
// 부팅된 새 버전 = kFirmwareVersion 저장). 다음 multipart 보고에서 서버는
// "X 버전이 부팅 + 자가점검 + 첫 업로드까지 성공"이라는 명확한 신호 획득.
void IconiaApp::markAppValidIfPending() {
  const esp_partition_t* running = esp_ota_get_running_partition();
  if (running == nullptr) {
    return;
  }
  esp_ota_img_states_t state = ESP_OTA_IMG_UNDEFINED;
  if (esp_ota_get_state_partition(running, &state) != ESP_OK) {
    return;
  }
  if (state != ESP_OTA_IMG_PENDING_VERIFY) {
    return;  // 일반 부팅, 할 일 없음
  }
  esp_err_t err = esp_ota_mark_app_valid_cancel_rollback();
  if (err == ESP_OK) {
    logLine("[OTA] self-test passed, marked app valid (rollback cancelled)");
    // 성공 신호 기록. 현재 부팅된 버전(kFirmwareVersion)을 attempt_ver 자리에
    // 넣어 "이 버전이 정상 부팅 + 자가점검 통과"라는 의미로 서버에 emit.
    recordOtaResult(iconia::protocol::kOtaResultSuccess,
                    iconia::config::kFirmwareVersion);
  } else {
    logLine(String("[OTA] mark_valid failed err=") + (int)err);
  }
}

// -----------------------------------------------------------------------------
// OTA 결과 보고 채널 (다운그레이드 가드 + 결과 영속화)
// -----------------------------------------------------------------------------

// "major.minor.patch" 형식만 허용. prerelease/build 메타("1.2.3-rc1",
// "1.2.3+sha")는 보수적으로 거부 — 서버가 manifest 손상 시 garbage 버전을
// 보냈을 때 다운그레이드 가드가 무력화되는 것을 막는다.
bool IconiaApp::parseSemver(const char* version, int& major, int& minor, int& patch) {
  if (version == nullptr || version[0] == '\0') {
    return false;
  }
  major = -1;
  minor = -1;
  patch = -1;

  int parts[3] = {-1, -1, -1};
  int idx = 0;
  int current = -1;
  for (const char* p = version; ; ++p) {
    char c = *p;
    if (c >= '0' && c <= '9') {
      if (current < 0) {
        current = 0;
      }
      // overflow 보호: 5자리 넘는 component는 거부(현실적으로 99999 충분).
      if (current > 9999) {
        return false;
      }
      current = current * 10 + (c - '0');
    } else if (c == '.' || c == '\0') {
      if (current < 0) {
        return false;  // 비어 있는 component
      }
      if (idx >= 3) {
        return false;  // 4번째 component 거부
      }
      parts[idx++] = current;
      current = -1;
      if (c == '\0') {
        break;
      }
    } else {
      // prerelease 태그('-'), build 메타('+'), 공백 등 일체 거부.
      return false;
    }
  }

  if (idx != 3) {
    return false;
  }
  major = parts[0];
  minor = parts[1];
  patch = parts[2];
  return true;
}

// -1: a < b, 0: a == b, 1: a > b
int IconiaApp::compareSemver(int aMajor, int aMinor, int aPatch,
                             int bMajor, int bMinor, int bPatch) {
  if (aMajor != bMajor) return aMajor < bMajor ? -1 : 1;
  if (aMinor != bMinor) return aMinor < bMinor ? -1 : 1;
  if (aPatch != bPatch) return aPatch < bPatch ? -1 : 1;
  return 0;
}

bool IconiaApp::isValidSemver(const char* version) {
  int major = 0, minor = 0, patch = 0;
  return parseSemver(version, major, minor, patch);
}

bool IconiaApp::isAllowedOtaResult(const char* resultEnum) {
  if (resultEnum == nullptr) {
    return false;
  }
  return strcmp(resultEnum, iconia::protocol::kOtaResultSuccess) == 0 ||
         strcmp(resultEnum, iconia::protocol::kOtaResultShaMismatch) == 0 ||
         strcmp(resultEnum, iconia::protocol::kOtaResultDownloadFailed) == 0 ||
         strcmp(resultEnum, iconia::protocol::kOtaResultFlashFailed) == 0 ||
         strcmp(resultEnum, iconia::protocol::kOtaResultRolledBack) == 0 ||
         strcmp(resultEnum, iconia::protocol::kOtaResultVersionRejected) == 0;
}

// NVS 페어 기록. enum 화이트리스트 / semver 형식을 통과한 값만 저장.
// 어느 쪽이라도 검증 실패면 둘 다 erase하고 swallow + 시리얼 경고
// (NVS 손상으로 garbage 보내는 것보다 보고 생략이 안전).
// NVS write 실패도 swallow — OTA 정상 흐름을 막지 않음.
void IconiaApp::recordOtaResult(const char* resultEnum, const char* attemptedVersion) {
  if (!isAllowedOtaResult(resultEnum)) {
    logLine(String("[OTA-REPORT] reject result enum: ") +
            (resultEnum ? resultEnum : "<null>"));
    clearLastOtaReport();
    return;
  }
  if (attemptedVersion == nullptr || !isValidSemver(attemptedVersion)) {
    logLine(String("[OTA-REPORT] reject version: ") +
            (attemptedVersion ? attemptedVersion : "<null>"));
    clearLastOtaReport();
    return;
  }

  size_t r = preferences_.putString("ota_result", resultEnum);
  size_t v = preferences_.putString("ota_attempt_ver", attemptedVersion);
  if (r == 0 || v == 0) {
    logLine("[OTA-REPORT] NVS write failed (swallowed)");
    return;
  }
  logLine(String("[OTA-REPORT] recorded result=") + resultEnum +
          " ver=" + attemptedVersion);
}

// 페어를 NVS에서 읽어옴. 둘 다 존재 + 형식 통과해야 true (= multipart emit 가능).
// 페어 정합성이 깨졌거나 형식 불량이면 둘 다 erase하고 false (보고 생략).
//
// 단, "ota_result는 비었지만 ota_attempt_ver은 유효한" 일시적 상태는 정상으로
// 인식하여 erase 하지 않는다. 이 상태는 performOta가 attempt_ver을 선기록한
// 직후 power loss가 났거나, 아직 markAppValidIfPending이 호출되기 전 첫 보고
// 사이클 등에서 발생한다 — detectRollbackOnBoot가 이 attempt_ver을 활용하여
// rolled_back을 emit해야 하므로 보존이 필수.
bool IconiaApp::loadLastOtaReport(String& outResult, String& outVersion) {
  outResult = preferences_.getString("ota_result", "");
  outVersion = preferences_.getString("ota_attempt_ver", "");

  if (outResult.length() == 0 && outVersion.length() == 0) {
    return false;  // 정상 케이스: 보고할 게 없음
  }
  if (outResult.length() == 0 && outVersion.length() > 0) {
    // 시도 선기록 상태(아직 결과 미확정). emit은 안 하되 NVS는 보존.
    return false;
  }
  if (outResult.length() > 0 && outVersion.length() == 0) {
    logLine("[OTA-REPORT] NVS pair broken (result without version), erasing");
    clearLastOtaReport();
    return false;
  }
  if (!isAllowedOtaResult(outResult.c_str()) ||
      !isValidSemver(outVersion.c_str())) {
    logLine("[OTA-REPORT] NVS pair invalid format, erasing");
    clearLastOtaReport();
    return false;
  }
  return true;
}

// 응답 success 직후 호출. 페어를 모두 erase하여 단일 보고 보장.
void IconiaApp::clearLastOtaReport() {
  preferences_.remove("ota_result");
  preferences_.remove("ota_attempt_ver");
}

// 부팅 직후 롤백 감지. 다음 두 케이스에서 ota_result=rolled_back 기록:
//   1) 현재 running 파티션 상태가 ESP_OTA_IMG_INVALID — 새 펌웨어가 자가점검
//      실패로 부트로더에 의해 이전 슬롯으로 강제 복귀됐음
//   2) running과 boot 파티션이 서로 다른 OTA 슬롯이고, last_invalid 파티션이
//      존재 — 자가점검 실패한 슬롯 추적이 가능한 케이스
// attempt_ver은 NVS에 남아있는 직전 시도 값을 그대로 유지해야 서버가 어떤
// 버전이 죽었는지 안다(여기서 새로 쓰지 않음).
void IconiaApp::detectRollbackOnBoot() {
  const esp_partition_t* running = esp_ota_get_running_partition();
  if (running == nullptr) {
    return;
  }

  esp_ota_img_states_t state = ESP_OTA_IMG_UNDEFINED;
  if (esp_ota_get_state_partition(running, &state) != ESP_OK) {
    return;
  }

  bool rolledBack = false;
  if (state == ESP_OTA_IMG_INVALID || state == ESP_OTA_IMG_ABORTED) {
    rolledBack = true;
    logLine("[OTA-ROLLBACK] running partition state INVALID/ABORTED");
  } else {
    // 부트로더가 last_invalid_partition을 노출하면 이전 사이클의 실패 추론.
    const esp_partition_t* lastInvalid = esp_ota_get_last_invalid_partition();
    if (lastInvalid != nullptr && lastInvalid != running) {
      rolledBack = true;
      logLine("[OTA-ROLLBACK] last_invalid partition present, rollback inferred");
    }
  }

  if (!rolledBack) {
    return;
  }

  // attempt_ver은 NVS의 직전 값 유지. 결과만 rolled_back으로 덮어쓴다.
  // performOta가 시도 선기록한 attempt_ver만 살아있는 케이스(loadLastOtaReport
  // 가 false 반환)도 직접 NVS에서 읽어 활용해야 한다.
  String prevVersion = preferences_.getString("ota_attempt_ver", "");
  if (prevVersion.length() == 0 || !isValidSemver(prevVersion.c_str())) {
    // 직전 attempt_ver을 잃어버렸거나 garbage — 어떤 버전이 죽었는지 모름.
    // 서버가 garbage 받지 않도록 보고 생략.
    logLine("[OTA-ROLLBACK] no usable prior attempt_ver, skip emit");
    return;
  }
  recordOtaResult(iconia::protocol::kOtaResultRolledBack, prevVersion.c_str());

  // Stage 7 telemetry: rolled_back. 이전 partition 으로 복귀 후 첫 부팅에
  // 도달한 시점이므로, 본 record 는 NVS 의 attempt_ver (= 죽은 버전) 와 함께
  // RTC slow-mem 큐에 적재. 실제 HTTPS POST /ota-status 는 server endpoint
  // 합의 후 다음 라운드에서 큐 flush 함수로 일괄 전송.
  iconia::ota::onRolledBack(prevVersion.c_str());
}
