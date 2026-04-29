// =============================================================================
// 04_WiFi_Test
// -----------------------------------------------------------------------------
// 목적:
//   STA 모드로 지정 SSID/PW 에 연결되는지, IP 와 RSSI 를 가져올 수 있는지
//   확인합니다. 프로덕션 펌웨어의 Wi-Fi 연결 타임아웃(15초)을 동일하게 사용.
//
// 합격 기준:
//   1) "[WIFI] connected" 가 15초 안에 출력
//   2) IP 가 192.168.x.x / 10.x.x.x 등 유효 사설망으로 보임
//   3) RSSI 가 -80 dBm 보다 강함 (현장 시험 환경 기준)
//
// 주의:
//   본 sketch 의 SSID/PW 는 평문 상수입니다. 검수용 임시 라우터를 사용하고
//   파일을 외부로 유출하지 마십시오. 운영 펌웨어는 BLE 프로비저닝으로 NVS
//   에 저장된 자격증명을 사용합니다.
// =============================================================================

#include <Arduino.h>
#include <WiFi.h>

// TODO: 본인 환경에 맞게 수정 (검수 후 placeholder 로 되돌릴 것)
static const char* kTestSsid     = "YOUR_SSID_HERE";
static const char* kTestPassword = "YOUR_PASSWORD_HERE";

static constexpr uint32_t kConnectTimeoutMs = 15000;

void setup() {
  Serial.begin(115200);
  delay(200);
  Serial.println();
  Serial.println("=== 04_WiFi_Test ===");
  Serial.printf("[WIFI] connecting to '%s' ...\n", kTestSsid);

  WiFi.mode(WIFI_STA);
  WiFi.setSleep(true);  // 모뎀 슬립 — 프로덕션과 동일
  WiFi.begin(kTestSsid, kTestPassword);

  uint32_t start = millis();
  while (WiFi.status() != WL_CONNECTED &&
         millis() - start < kConnectTimeoutMs) {
    delay(250);
    Serial.print('.');
  }
  Serial.println();

  if (WiFi.status() == WL_CONNECTED) {
    Serial.println("[WIFI] connected");
    Serial.print("[WIFI] IP   = "); Serial.println(WiFi.localIP());
    Serial.print("[WIFI] GW   = "); Serial.println(WiFi.gatewayIP());
    Serial.print("[WIFI] DNS  = "); Serial.println(WiFi.dnsIP());
    Serial.print("[WIFI] MAC  = "); Serial.println(WiFi.macAddress());
    Serial.print("[WIFI] RSSI = "); Serial.print(WiFi.RSSI()); Serial.println(" dBm");
  } else {
    Serial.println("[WIFI] connect FAILED — SSID/PW/RSSI/AP 보안설정 확인");
  }
}

void loop() {
  if (WiFi.status() == WL_CONNECTED) {
    Serial.printf("[WIFI] alive RSSI=%d dBm\n", WiFi.RSSI());
  } else {
    Serial.println("[WIFI] disconnected");
  }
  delay(5000);
}
