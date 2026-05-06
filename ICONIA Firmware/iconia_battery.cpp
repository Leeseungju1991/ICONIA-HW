// =============================================================================
// iconia_battery — implementation
// 정본: HW 시스템 정의서 §4.2 + docs/operational_telemetry.md §3
// =============================================================================

#include "iconia_battery.h"

#include <math.h>
#include "esp_attr.h"  // RTC_DATA_ATTR

namespace iconia {
namespace battery {

// 직전 스냅샷 (RTC slow-mem, 부팅 간 보존).
// dV/dt 계산은 본 두 변수만으로 수행. 16B 미만으로 매우 가볍다.
RTC_DATA_ATTR static float    s_prevVoltage = 0.0f;
RTC_DATA_ATTR static uint32_t s_prevSnapshotEpochSec = 0;
RTC_DATA_ATTR static uint8_t  s_prevValid = 0;  // 0 = 비교 가능한 직전값 없음

bool allowsCapture(Policy p) {
  return p == Policy::Normal || p == Policy::Sustain;
}
bool allowsUpload(Policy p) {
  return p == Policy::Normal || p == Policy::Sustain || p == Policy::Emergency;
}
bool allowsOta(Policy p) {
  return p == Policy::Normal;
}

// 단조 시각 추정. RTC time 이 없으므로 millis() 를 second 단위로 환산하여
// "스냅샷 간 경과 시간" 만 계산. 절대 시각은 사용 안 함.
// 부팅 간 보존을 위해 RTC 단조 카운터(esp_timer_get_time → us) 가 더 정확하지만
// 본 모듈은 1 ms 단위 정밀도면 충분.
static uint32_t snapshotEpochSecFromMs(uint32_t ms) {
  return ms / 1000u;
}

Policy evaluate(const Reading& r,
                float* outDvDtMvPerSec,
                const char** outAbnormalReason) {
  if (outDvDtMvPerSec) {
    *outDvDtMvPerSec = NAN;
  }
  if (outAbnormalReason) {
    *outAbnormalReason = nullptr;
  }

  // 1) 비정상 상한 — 즉시 Abnormal 분류 (충전 중/방전 중 무관).
  if (r.voltage > kVoltageAbnormalUpper) {
    if (outAbnormalReason) {
      *outAbnormalReason = "over_voltage";
    }
    return Policy::Abnormal;
  }

  // 2) dV/dt 검사 (비교 가능한 직전 스냅샷이 있고 간격 0.5 s 이상일 때만).
  uint32_t nowSec = snapshotEpochSecFromMs(r.snapshotMs);
  if (s_prevValid != 0 && nowSec > s_prevSnapshotEpochSec) {
    uint32_t dtSec = nowSec - s_prevSnapshotEpochSec;
    // RTC slow-mem 보존 + 1 s 정밀도라 dt < 1 인 경우는 0 으로 떨어진다 → 평가 skip.
    if (dtSec >= 1) {
      float dv = r.voltage - s_prevVoltage;
      float dvdtMv = (dv * 1000.0f) / (float)dtSec;
      if (outDvDtMvPerSec) {
        *outDvDtMvPerSec = dvdtMv;
      }
      // 충전 중에는 dV/dt 양수가 정상 (충전 IC 가 빠르게 끌어올림). 방전 중에만
      // 급격한 하강을 abnormal 로 판정.
      if (!r.isCharging && dvdtMv < -kAbnormalDvDtMvPerSec) {
        // 추가 sanity: 절대 dV 도 0.05 V 이상이어야 noise 와 구분.
        if (dv < -0.05f) {
          if (outAbnormalReason) {
            *outAbnormalReason = "abrupt_drop";
          }
          return Policy::Abnormal;
        }
      }
    }
  }

  // 3) 충전 중에는 sustain 정책으로 평탄화 (충전 도중 voltage 가 일시적으로
  //    낮게 측정되더라도 emergency/critical 로 떨어뜨리지 않음 — 충전 IC 가
  //    실제로는 셀을 밀어올리는 중).
  if (r.isCharging) {
    // 충전 중에도 critical 미만이면 정말 문제 (PSU 출력 부족 등) → critical 로.
    if (r.voltage < kVoltageCriticalMin) {
      return Policy::Critical;
    }
    return Policy::Sustain;
  }

  // 4) 방전 중 — 단계적 임계 적용.
  if (r.voltage >= kVoltageNormalMin)    return Policy::Normal;
  if (r.voltage >= kVoltageSustainMin)   return Policy::Sustain;
  if (r.voltage >= kVoltageEmergencyMin) return Policy::Emergency;
  if (r.voltage >= kVoltageCriticalMin)  return Policy::Critical;
  return Policy::Shutdown;
}

void persistSnapshot(const Reading& r) {
  s_prevVoltage = r.voltage;
  s_prevSnapshotEpochSec = snapshotEpochSecFromMs(r.snapshotMs);
  s_prevValid = 1;
}

}  // namespace battery
}  // namespace iconia
