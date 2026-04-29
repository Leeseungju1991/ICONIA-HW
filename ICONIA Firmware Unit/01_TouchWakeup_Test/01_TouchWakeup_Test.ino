// =============================================================================
// 01_TouchWakeup_Test
// -----------------------------------------------------------------------------
// 목적:
//   ICONIA 본체에 부착된 좌/우 터치 IC 출력이 ESP32 RTC GPIO 13 / 14 에서
//   active HIGH 신호로 정상 인가되는지, 그리고 EXT1 wakeup 으로 Deep Sleep
//   에서 즉시 깨어나는지 검수합니다.
//
//   본 sketch 의 핀맵은 프로덕션 펌웨어(`ICONIA Firmware/iconia_config.h`)와
//   동일합니다. 회로 변경 시 이 값을 펌웨어와 함께 수정해야 합니다.
//
// 합격 기준:
//   1) 부팅 후 Serial 에 "READY: 터치 대기 중" 이 보임
//   2) 손을 오른쪽(GPIO13)에 대면 "TOUCH DETECTED: RIGHT (HIGH)" 출력
//   3) 손을 왼쪽(GPIO14)에 대면 "TOUCH DETECTED: LEFT  (HIGH)"  출력
//   4) 5초 동안 입력이 없으면 EXT1 wakeup 으로 Deep Sleep 진입,
//      이후 터치 시 부팅 사유 ESP_SLEEP_WAKEUP_EXT1 로 다시 깨어남
// =============================================================================

#include <Arduino.h>
#include "esp_sleep.h"
#include "driver/rtc_io.h"

// 프로덕션 펌웨어와 동일한 핀 (iconia_config.h)
static constexpr int kTouchRightGpio = 13;
static constexpr int kTouchLeftGpio  = 14;
static constexpr uint64_t kWakeMask =
    (1ULL << kTouchRightGpio) | (1ULL << kTouchLeftGpio);

static constexpr uint32_t kIdleEnterSleepMs = 5000;  // 입력 없으면 5초 후 슬립

void printWakeReason() {
  esp_sleep_wakeup_cause_t cause = esp_sleep_get_wakeup_cause();
  Serial.print("[BOOT] wakeup cause = ");
  switch (cause) {
    case ESP_SLEEP_WAKEUP_EXT1:
      Serial.println("EXT1 (터치)");
      {
        uint64_t status = esp_sleep_get_ext1_wakeup_status();
        if (status & (1ULL << kTouchRightGpio)) {
          Serial.println("[BOOT] 깨운 핀: GPIO13 (RIGHT)");
        }
        if (status & (1ULL << kTouchLeftGpio)) {
          Serial.println("[BOOT] 깨운 핀: GPIO14 (LEFT)");
        }
      }
      break;
    case ESP_SLEEP_WAKEUP_UNDEFINED:
      Serial.println("UNDEFINED (전원 ON 또는 리셋)");
      break;
    default:
      Serial.print("기타 ("); Serial.print((int)cause); Serial.println(")");
      break;
  }
}

void setup() {
  Serial.begin(115200);
  delay(200);
  Serial.println();
  Serial.println("=== 01_TouchWakeup_Test ===");
  printWakeReason();

  // 입력 풀다운 — 터치 IC 가 LOW idle / HIGH active 라는 가정
  pinMode(kTouchRightGpio, INPUT_PULLDOWN);
  pinMode(kTouchLeftGpio,  INPUT_PULLDOWN);

  Serial.println("READY: 터치 대기 중 (5초 무입력 시 Deep Sleep)");
}

void loop() {
  static uint32_t lastEvent = millis();
  int r = digitalRead(kTouchRightGpio);
  int l = digitalRead(kTouchLeftGpio);

  if (r == HIGH) {
    Serial.println("TOUCH DETECTED: RIGHT (HIGH)");
    lastEvent = millis();
    delay(300);  // 단순 디바운스
  }
  if (l == HIGH) {
    Serial.println("TOUCH DETECTED: LEFT  (HIGH)");
    lastEvent = millis();
    delay(300);
  }

  if (millis() - lastEvent > kIdleEnterSleepMs) {
    Serial.println("[SLEEP] 5초 무입력 → EXT1 wakeup 등록 후 Deep Sleep 진입");
    Serial.flush();

    // RTC GPIO 로 전환하고 풀다운 활성화
    rtc_gpio_pulldown_en((gpio_num_t)kTouchRightGpio);
    rtc_gpio_pulldown_en((gpio_num_t)kTouchLeftGpio);
    rtc_gpio_pullup_dis((gpio_num_t)kTouchRightGpio);
    rtc_gpio_pullup_dis((gpio_num_t)kTouchLeftGpio);

    esp_sleep_enable_ext1_wakeup(kWakeMask, ESP_EXT1_WAKEUP_ANY_HIGH);
    esp_deep_sleep_start();
  }

  delay(20);
}
