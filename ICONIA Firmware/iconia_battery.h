// =============================================================================
// iconia_battery — 배터리 임계 + dV/dt 보호 + 충전 상태 분기
// -----------------------------------------------------------------------------
// 본 모듈은 기존 readBatteryStatus() 의 단일 임계(5%) 대신, 양산 수준의
// 다단계 임계 + 이상치 검출 + 충전 중/방전 중 정책 분리를 책임진다.
// 카메라 capture / Wi-Fi 업로드 / OTA / BLE adv 진입 직전에 호출되어 "이번
// 동작을 허용할지" 를 단일 enum 으로 답한다.
//
// 정본: HW 시스템 정의서 §4.2 전원 정책 + docs/operational_telemetry.md §3
//
// 구현 원칙
//   - ADC 캘리브레이션은 기존 iconia_app.cpp::readBatteryStatus 가 담당.
//     본 모듈은 그 결과(BatteryReading)만 입력으로 받아 정책 평가.
//   - dV/dt: 직전 스냅샷을 RTC slow-mem 에 보존(부팅 간 단조 카운터 + 마지막
//     전압). |dV/dt| > 100 mV/s 면 abnormal_drop 로 분류 → 안전 차단.
//   - 충전 중(VBUS 감지) vs 방전 중: VBUS 핀이 보드 디자인에 따라 다르므로
//     본 헤더는 booleen `isCharging` 을 외부에서 받는 인터페이스만 정의.
//     초기 보드는 VBUS 감지 회로가 없을 수 있어 false 디폴트 안전 동작.
// =============================================================================

#pragma once

#include <Arduino.h>
#include <stdint.h>

namespace iconia {
namespace battery {

// HW 시스템 정의서 §4.2 전원 정책 + 본 라운드 양산 강화.
// 단위: V (배터리 단자 전압, divider 보정 후).
//
// 4.0 V 이상 = normal     : 모든 동작 허용 (capture + upload + OTA + BLE)
// 3.7 V 이상 = sustain    : 모든 동작 허용. OTA 는 별도 가드(50% 임계) 적용.
// 3.5 V 이상 = emergency  : 업로드 1회만 허용. capture 보류, OTA 거부.
// 3.3 V 이상 = critical   : 즉시 deep sleep + 다음 wake 시 동일 검사.
// 3.3 V 미만 = shutdown   : EXT1 wake source disable + 강제 deep sleep.
//                            (사용자가 충전기 꽂으면 BQ24075 가 시스템을 다시
//                             부팅시키는 시점에 wake mask 재설정.)
static constexpr float kVoltageNormalMin    = 4.00f;
static constexpr float kVoltageSustainMin   = 3.70f;
static constexpr float kVoltageEmergencyMin = 3.50f;
static constexpr float kVoltageCriticalMin  = 3.30f;

// 비정상 상한(부풀어 오른 셀 / 충전 IC 폭주). BQ24075 정상 충전 cutoff 4.20 V
// + 측정 분압 오차 5% 마진 → 4.30 V 이상은 비정상으로 간주.
static constexpr float kVoltageAbnormalUpper = 4.30f;

// dV/dt 이상 강하 임계: 100 mV/s. 정상 방전(수십 mV/min)보다 1~2 자리수 빠름.
// (ADC 노이즈로 인한 false positive 방지 위해 |delta_v| > 0.05 V AND 두
// 스냅샷 간격이 0.5 s 이상일 때만 평가.)
static constexpr float kAbnormalDvDtMvPerSec = 100.0f;

// 정책 평가 결과. 호출자(runEventFlow / OTA 가드 / BLE 진입)는 이 결과로 분기.
enum class Policy : uint8_t {
  Normal     = 0,  // 모든 동작 허용
  Sustain    = 1,  // 모든 동작 허용 (단 OTA 는 별도 50% 가드)
  Emergency  = 2,  // 업로드 1회만 허용 (capture 보류, OTA 거부)
  Critical   = 3,  // 즉시 deep sleep, 다음 wake 동일 검사
  Shutdown   = 4,  // EXT1 wake disable, 강제 deep sleep
  Abnormal   = 5,  // 4.30 V 초과 또는 dV/dt 이상 → 안전 차단 + telemetry
};

// 임의 단계가 capture 를 허용하는지.
bool allowsCapture(Policy p);
// 업로드 1회 허용 여부 (Normal/Sustain/Emergency 만 true).
bool allowsUpload(Policy p);
// OTA 진입 허용 (Normal 만; sustain 은 별도 50% 임계로 OTA 가드 처리).
bool allowsOta(Policy p);

// 평가 입력. iconia_app.cpp::readBatteryStatus 가 채워 호출.
struct Reading {
  float voltage;       // 배터리 단자 V
  int   percent;       // 0..100 (기존 계산 그대로 받아 보고용)
  bool  isCharging;    // VBUS 감지 (없으면 false). policy 분기에 사용.
  uint32_t snapshotMs; // millis() 시각. dV/dt 계산에 사용.
};

// 정책 평가 + telemetry sample 발행. 직전 스냅샷은 RTC slow-mem 에 보존.
//
// outDvDtMvPerSec : 직전 스냅샷과의 변화율. 비교 가능한 직전값이 없으면 NaN.
// outAbnormalReason : Abnormal 일 때 사유 문자열 ("over_voltage" / "abrupt_drop").
//                     Abnormal 이 아니면 nullptr 로 둠. 호출자가 telemetry 에 동봉.
Policy evaluate(const Reading& r,
                float* outDvDtMvPerSec = nullptr,
                const char** outAbnormalReason = nullptr);

// Critical / Shutdown 진입 직전 호출. RTC slow-mem 의 직전 스냅샷을 강제 갱신
// 해 다음 wake 가 dV/dt 비교를 정상 시작할 수 있게 한다 (false positive 방지).
void persistSnapshot(const Reading& r);

}  // namespace battery
}  // namespace iconia
