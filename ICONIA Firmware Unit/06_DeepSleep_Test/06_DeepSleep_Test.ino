// =============================================================================
// 06_DeepSleep_Test
// -----------------------------------------------------------------------------
// 목적:
//   Deep Sleep ↔ wakeup 사이클이 안정적으로 도는지, RTC SLOW MEM 의 카운터가
//   유지되는지, EXT1 wakeup(GPIO13/14)이 슬립을 해제하는지 검수.
//   전류계를 같이 물면 슬립 전류가 약 15µA 이하로 떨어지는지 확인 가능.
//
// 동작:
//   - 부팅 → 카운터 +1 출력 → 10초 대기 → Deep Sleep
//   - 터치(GPIO13/14 HIGH) 또는 타이머(없음) 로 wakeup
//   - 카운터는 RTC_DATA_ATTR 변수라 wakeup 사이에 보존됨
//
// 합격 기준:
//   1) "[BOOT] count = N" 의 N 이 wakeup 마다 1씩 증가
//   2) "[BOOT] cause = EXT1" / mask 에서 깨운 핀 GPIO 가 명시됨
//   3) 멀티미터로 슬립 구간 전류 측정 시 µA 수준
// =============================================================================

#include <Arduino.h>
#include "esp_sleep.h"
#include "driver/rtc_io.h"

static constexpr int kTouchRightGpio = 13;
static constexpr int kTouchLeftGpio  = 14;
static constexpr uint64_t kWakeMask =
    (1ULL << kTouchRightGpio) | (1ULL << kTouchLeftGpio);

static constexpr uint32_t kAwakeMs = 10000;

RTC_DATA_ATTR uint32_t g_bootCount = 0;

void printWakeReason() {
  esp_sleep_wakeup_cause_t c = esp_sleep_get_wakeup_cause();
  switch (c) {
    case ESP_SLEEP_WAKEUP_EXT1: {
      uint64_t st = esp_sleep_get_ext1_wakeup_status();
      Serial.print("[BOOT] cause = EXT1, mask = 0x");
      Serial.println((unsigned long)st, HEX);
      if (st & (1ULL << kTouchRightGpio)) Serial.println("[BOOT]  -> RIGHT(GPIO13)");
      if (st & (1ULL << kTouchLeftGpio))  Serial.println("[BOOT]  -> LEFT (GPIO14)");
      break;
    }
    case ESP_SLEEP_WAKEUP_UNDEFINED:
      Serial.println("[BOOT] cause = power-on / reset");
      break;
    default:
      Serial.printf("[BOOT] cause = %d\n", (int)c);
      break;
  }
}

void setup() {
  Serial.begin(115200);
  delay(200);
  Serial.println();
  Serial.println("=== 06_DeepSleep_Test ===");

  g_bootCount += 1;
  Serial.printf("[BOOT] count = %u\n", (unsigned)g_bootCount);
  printWakeReason();

  Serial.printf("[AWAKE] %u ms 후 Deep Sleep 진입\n", (unsigned)kAwakeMs);
}

void loop() {
  static uint32_t start = millis();
  if (millis() - start >= kAwakeMs) {
    Serial.println("[SLEEP] EXT1 등록 (GPIO13/14 ANY_HIGH) → 슬립");
    Serial.flush();

    rtc_gpio_pulldown_en((gpio_num_t)kTouchRightGpio);
    rtc_gpio_pulldown_en((gpio_num_t)kTouchLeftGpio);
    rtc_gpio_pullup_dis((gpio_num_t)kTouchRightGpio);
    rtc_gpio_pullup_dis((gpio_num_t)kTouchLeftGpio);

    esp_sleep_enable_ext1_wakeup(kWakeMask, ESP_EXT1_WAKEUP_ANY_HIGH);
    // 슬립 전류 최소화: RTC peripherals OFF
    esp_sleep_pd_config(ESP_PD_DOMAIN_RTC_PERIPH, ESP_PD_OPTION_OFF);
    esp_deep_sleep_start();
  }
  delay(500);
}
