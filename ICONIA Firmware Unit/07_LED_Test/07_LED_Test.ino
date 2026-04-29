// =============================================================================
// 07_LED_Test
// -----------------------------------------------------------------------------
// 목적:
//   상태 표시용 LED(GPIO4) 가 핀 점퍼 / 회로 / 극성 모두 정상인지 확인.
//   Blink sanity check — 1Hz 로 깜빡인다.
//
//   GPIO4 는 프로덕션 펌웨어 `iconia_config.h` 의 kLedGpio 와 동일.
//
// 합격 기준:
//   1) Serial 에 "[LED] HIGH" / "[LED] LOW" 가 1초 간격으로 토글
//   2) 보드 위 LED 가 동일 주기로 깜빡임
//   3) 깜빡이지 않으면: 핀 점퍼, 극성(N-MOS / 직결), 풀다운 저항 점검
// =============================================================================

#include <Arduino.h>

static constexpr int kLedGpio = 4;

void setup() {
  Serial.begin(115200);
  delay(200);
  Serial.println();
  Serial.println("=== 07_LED_Test ===");
  pinMode(kLedGpio, OUTPUT);
  digitalWrite(kLedGpio, LOW);
  Serial.printf("[LED] driving GPIO%d at 1 Hz\n", kLedGpio);
}

void loop() {
  digitalWrite(kLedGpio, HIGH);
  Serial.println("[LED] HIGH");
  delay(500);
  digitalWrite(kLedGpio, LOW);
  Serial.println("[LED] LOW");
  delay(500);
}
