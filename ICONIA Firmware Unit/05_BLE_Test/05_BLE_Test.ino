// =============================================================================
// 05_BLE_Test
// -----------------------------------------------------------------------------
// 목적:
//   프로덕션 펌웨어와 동일한 GATT 서비스/특성 UUID 로 BLE 광고를 띄우고,
//   SSID / Password 특성에 들어오는 Write Without Response 데이터를 그대로
//   Status 특성으로 echo notify 합니다. RN 앱이 Discovery / Write / Notify
//   파이프라인을 정상으로 잡는지 검수하는 용도.
//
// 합격 기준:
//   1) 핸드폰의 nRF Connect 또는 운영 RN 앱에서 "ICONIA-XXXX" 광고가 보임
//   2) SSID/PW 특성에 임의 문자열 write → Status 특성에 echo notify 도착
//   3) Serial 에 "[BLE] SSID write: ..." / "[BLE] PW write: ..." 출력
//
// 주의:
//   - UUID, 디바이스명 prefix 모두 프로덕션 펌웨어와 동일하게 유지해야
//     검수의 의미가 있다. 임의 변경 금지.
//   - 본 sketch 는 본딩/암호화를 강제하지 않는다 (legacy plaintext 검수 전용).
//   - V1 secure handshake (docs/security_handshake.md) 검수는 본 sketch 가 아닌
//     실제 펌웨어 (build_profiles/dev.h, ICONIA_BLE_SECURE=1) 로 수행한다.
//     본 sketch 는 GATT Discovery / 광고 / Notify 파이프라인만 검수.
// =============================================================================

#include <Arduino.h>
#include <BLEDevice.h>
#include <BLEServer.h>
#include <BLEUtils.h>
#include <BLE2902.h>

// iconia_config.h 와 동일한 UUID
static const char* kServiceUuid     = "48f1f79e-817d-4105-a96f-4e2d2d6031e0";
static const char* kSsidCharUuid    = "48f1f79e-817d-4105-a96f-4e2d2d6031e1";
static const char* kPasswordCharUuid= "48f1f79e-817d-4105-a96f-4e2d2d6031e2";
static const char* kStatusCharUuid  = "48f1f79e-817d-4105-a96f-4e2d2d6031e3";

BLECharacteristic* g_status = nullptr;

static void notifyStatus(const String& s) {
  if (!g_status) return;
  g_status->setValue((uint8_t*)s.c_str(), s.length());
  g_status->notify();
}

class SsidCb : public BLECharacteristicCallbacks {
  void onWrite(BLECharacteristic* c) override {
    String v = String(c->getValue().c_str());
    Serial.printf("[BLE] SSID write: '%s' (%u bytes)\n",
                  v.c_str(), (unsigned)v.length());
    notifyStatus(String("ssid_echo:") + v);
  }
};

class PwCb : public BLECharacteristicCallbacks {
  void onWrite(BLECharacteristic* c) override {
    String v = String(c->getValue().c_str());
    Serial.printf("[BLE] PW write: %u bytes (내용 비공개)\n",
                  (unsigned)v.length());
    notifyStatus(String("pw_echo_len:") + String((int)v.length()));
  }
};

class ConnCb : public BLEServerCallbacks {
  void onConnect(BLEServer*) override {
    Serial.println("[BLE] central connected");
    notifyStatus("connected");
  }
  void onDisconnect(BLEServer* s) override {
    Serial.println("[BLE] central disconnected — 광고 재시작");
    s->getAdvertising()->start();
  }
};

void setup() {
  Serial.begin(115200);
  delay(200);
  Serial.println();
  Serial.println("=== 05_BLE_Test ===");

  // 디바이스명: ICONIA-XXXX (MAC 마지막 4자리) — 프로덕션과 동일 규칙
  uint8_t mac[6]; esp_read_mac(mac, ESP_MAC_BT);
  char name[16];
  snprintf(name, sizeof(name), "ICONIA-%02X%02X", mac[4], mac[5]);
  Serial.printf("[BLE] device name = %s\n", name);

  BLEDevice::init(name);
  BLEServer* server = BLEDevice::createServer();
  server->setCallbacks(new ConnCb());

  BLEService* svc = server->createService(kServiceUuid);

  auto* ssid = svc->createCharacteristic(
      kSsidCharUuid, BLECharacteristic::PROPERTY_WRITE_NR);
  ssid->setCallbacks(new SsidCb());

  auto* pw = svc->createCharacteristic(
      kPasswordCharUuid, BLECharacteristic::PROPERTY_WRITE_NR);
  pw->setCallbacks(new PwCb());

  g_status = svc->createCharacteristic(
      kStatusCharUuid,
      BLECharacteristic::PROPERTY_READ | BLECharacteristic::PROPERTY_NOTIFY);
  g_status->addDescriptor(new BLE2902());
  g_status->setValue("advertising");

  svc->start();

  BLEAdvertising* adv = BLEDevice::getAdvertising();
  adv->addServiceUUID(kServiceUuid);
  adv->setScanResponse(true);
  // 광고 인터벌(units of 0.625 ms): 2048=1280ms, 4096=2560ms — 프로덕션과 동일
  adv->setMinInterval(2048);
  adv->setMaxInterval(4096);
  BLEDevice::startAdvertising();

  Serial.println("[BLE] advertising started — nRF Connect 등으로 접속하여 write 테스트");
}

void loop() {
  delay(2000);
}
