// =============================================================================
// 03_BatteryADC_Test
// -----------------------------------------------------------------------------
// 목적:
//   GPIO33(ADC1) 분압 회로에서 Li-Po 배터리 전압을 1초 주기로 읽어
//   ADC raw, 환산 전압(V), 잔량(%) 을 Serial 로 출력합니다.
//   분압비(2.0), 만/공 임계(4.20 V / 3.30 V) 모두 프로덕션 펌웨어와 동일.
//
// 합격 기준:
//   1) 만충 상태에서 "battery=4.10~4.20 V, 90~100%" 부근
//   2) 충전 케이블 분리 시 천천히 전압이 떨어지는 추세 관찰
//   3) ADC raw 값이 16회 평균으로 진동 폭 ±10 LSB 이내
// =============================================================================

#include <Arduino.h>
#include "esp_adc_cal.h"

static constexpr int   kBatteryAdcPin       = 33;
static constexpr float kBatteryAdcReferenceV = 3.3f;
static constexpr float kBatteryDividerRatio  = 2.0f;
static constexpr float kBatteryEmptyV        = 3.30f;
static constexpr float kBatteryFullV         = 4.20f;
static constexpr int   kSampleCount          = 16;

esp_adc_cal_characteristics_t adc_chars;

float readBatteryVolts() {
  uint32_t acc = 0;
  for (int i = 0; i < kSampleCount; ++i) {
    acc += analogRead(kBatteryAdcPin);
    delayMicroseconds(200);
  }
  uint32_t raw = acc / kSampleCount;

  // 캘리브레이션이 가능한 칩이면 mV 환산값 사용, 아니면 단순 비율
  uint32_t mv = esp_adc_cal_raw_to_voltage(raw, &adc_chars);
  float pinV = mv / 1000.0f;
  float battV = pinV * kBatteryDividerRatio;
  Serial.printf("[BATT] raw=%4u mv=%4u pin=%.3fV batt=%.3fV ",
                (unsigned)raw, (unsigned)mv, pinV, battV);
  return battV;
}

int voltsToPercent(float v) {
  if (v <= kBatteryEmptyV) return 0;
  if (v >= kBatteryFullV)  return 100;
  return (int)((v - kBatteryEmptyV) /
               (kBatteryFullV - kBatteryEmptyV) * 100.0f);
}

void setup() {
  Serial.begin(115200);
  delay(200);
  Serial.println();
  Serial.println("=== 03_BatteryADC_Test ===");

  analogReadResolution(12);
  analogSetPinAttenuation(kBatteryAdcPin, ADC_11db);

  // ADC1_CHANNEL_5 == GPIO33
  esp_adc_cal_characterize(ADC_UNIT_1, ADC_ATTEN_DB_11,
                           ADC_WIDTH_BIT_12, 1100, &adc_chars);
  Serial.printf("[BATT] divider=%.2f empty=%.2fV full=%.2fV\n",
                kBatteryDividerRatio, kBatteryEmptyV, kBatteryFullV);
}

void loop() {
  float v = readBatteryVolts();
  Serial.printf("pct=%d%%\n", voltsToPercent(v));
  delay(1000);
}
