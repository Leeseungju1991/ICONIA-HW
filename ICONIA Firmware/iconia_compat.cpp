// =============================================================================
// iconia_compat — 부트 시 호환성 셀프 체크 (구현)
// -----------------------------------------------------------------------------
// 정본: docs/operational_telemetry.md §7
// =============================================================================

#include "iconia_compat.h"

#include "iconia_config.h"

namespace iconia {
namespace compat {

// RTC slow-mem 캐시. deep sleep 사이클을 가로질러 verdict 보존 — health
// endpoint 가 일시 5xx 응답이라도 직전 사이클의 verdict 으로 잠정 동작 가능.
// 8B 미만 — RTC slow-mem 8KB 한계 대비 무시 가능.
RTC_DATA_ATTR static CachedVerdict s_cachedVerdict = {
  /*verdict=*/Verdict::Unknown,
  /*observedServerApiVersion=*/0u,
  /*recordedAtUptimeMs=*/0u,
};

Verdict evaluate(uint32_t observedServerApiVersion) {
  if (observedServerApiVersion == 0u) {
    // 호출자가 health 응답을 받지 못했음. 직전 cached verdict 가 있으면
    // 그것을 그대로 신뢰 (서버 일시 장애 동안 "내가 호환되었던 사실" 유지).
    // cached verdict 도 Unknown 이면 잠정 Compatible 로 폴백 — 안 그러면
    // 신규 양산 디바이스가 첫 health 응답 전에 영영 lockout.
    if (s_cachedVerdict.verdict != Verdict::Unknown) {
      return s_cachedVerdict.verdict;
    }
    s_cachedVerdict.verdict = Verdict::Unknown;
    s_cachedVerdict.observedServerApiVersion = 0u;
    s_cachedVerdict.recordedAtUptimeMs = millis();
    return Verdict::Unknown;
  }

  Verdict v;
  if (observedServerApiVersion < kCompatServerApiMin ||
      observedServerApiVersion > kCompatServerApiMax) {
    v = Verdict::Incompatible;
  } else {
    v = Verdict::Compatible;
  }

  s_cachedVerdict.verdict = v;
  s_cachedVerdict.observedServerApiVersion = observedServerApiVersion;
  s_cachedVerdict.recordedAtUptimeMs = millis();
  return v;
}

CachedVerdict loadCached() {
  return s_cachedVerdict;
}

bool checkManifestSecureVersion(uint32_t targetSecureVersion) {
  // anti-rollback 핵심 invariant: 서버가 발급한 매니페스트가 현재 펌웨어의
  // secure_version 보다 작거나 같으면 거절.
  //   - strictly less than: 명백한 다운그레이드 → 거절
  //   - equal: 의미적 다운그레이드 (보안 패치 없는 빌드 재배포) → 거절
  // strictly greater 만 허용. 이 정책은 eFuse SECURE_VERSION 단조 증가 burn
  // 정책과도 정합 (burn 후 더 작은 값을 가진 펌웨어는 부트로더 단계에서 거절).
  if (targetSecureVersion <= iconia::config::kSecureVersion) {
    return false;
  }
  return true;
}

const char* verdictLabel(Verdict v) {
  switch (v) {
    case Verdict::Unknown:           return "unknown";
    case Verdict::Compatible:        return "compatible";
    case Verdict::Incompatible:      return "incompatible";
    case Verdict::ManifestRejected:  return "manifest_rejected";
  }
  return "unknown";
}

}  // namespace compat
}  // namespace iconia
