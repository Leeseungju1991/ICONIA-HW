// =============================================================================
// iconia_compat — 부트 시 호환성 셀프 체크
// -----------------------------------------------------------------------------
// 본 모듈은 펌웨어 빌드 시점에 컴파일된 호환성 매트릭스 사본
// (kCompatServerApiMin / kCompatServerApiMax — build_profiles/*.h) 를 활용,
// 서버의 health endpoint 가 보고하는 api_version 을 부팅 직후(또는 첫 Wi-Fi
// 연결 직후) 비교하여 미호환 디바이스의 자기보호 모드 진입을 결정한다.
//
// 정본 — docs/operational_telemetry.md §7 호환성 셀프 체크
//
// 매트릭스 정합:
//   - 서버 측 firmware_deployment / cohort 매트릭스 와 1:1 정합되어야 함.
//   - 매트릭스 자체는 server 도메인 책임. 본 펌웨어는 "내가 호환되는 server
//     api_version 의 닫힌 구간" 만 안다.
//
// 호환성 위배 시 펌웨어 동작 (CompatibilityVerdict::Incompatible):
//   - telemetry "compat_fail" emit (다음 성공 업로드 페어링 또는 BLE 진단 char)
//   - 이벤트 업로드 보류. 카메라/터치 wake 자체는 정상 — 다만 multipart POST
//     단계에서 incompatible flag 확인 후 즉시 deep sleep.
//   - BLE 진단 채널만 활성. 사용자가 모바일로 firmware/app 업데이트 안내 수신
//     가능. (본 라운드는 BLE 진단 char 미추가 — 펌웨어 측 hook 만 정의)
// =============================================================================

#pragma once

#include <Arduino.h>
#include <stdint.h>

namespace iconia {
namespace compat {

// 서버 health endpoint 응답 페이로드의 api_version 필드 (정수). 서버 측
// 합의된 단조 증가 정수. 형식 변경 (예: semver 문자열) 시 본 모듈과 server
// 동시 갱신 필요.
//
// 본 라운드 합의: api_version 은 단순 uint32_t 정수.
//   - 1: 초기 베이스라인 (cohort/deployment endpoint 없음)
//   - 2: ota-status endpoint 추가 + cohort 점진 배포 (현재 작업 중)
//   - 그 이후 변경 시 +1 ~ +N 단조 증가.
//
// 펌웨어가 호환되는 닫힌 구간 [kCompatServerApiMin, kCompatServerApiMax] 는
// build_profiles/{dev,prod}.h 에서 매크로로 주입.

#ifndef ICONIA_COMPAT_SERVER_API_MIN
#  define ICONIA_COMPAT_SERVER_API_MIN 1u
#endif
#ifndef ICONIA_COMPAT_SERVER_API_MAX
#  define ICONIA_COMPAT_SERVER_API_MAX 2u
#endif

static constexpr uint32_t kCompatServerApiMin = ICONIA_COMPAT_SERVER_API_MIN;
static constexpr uint32_t kCompatServerApiMax = ICONIA_COMPAT_SERVER_API_MAX;

// 셀프 체크 결과.
enum class Verdict : uint8_t {
  Unknown = 0,        // 아직 health endpoint 응답 받지 못함 — 잠정 허용
  Compatible = 1,     // [min, max] 범위 안. 정상 동작.
  Incompatible = 2,   // 범위 밖. 이벤트 업로드 보류.
  ManifestRejected = 3, // OTA 매니페스트 자체 거절 (anti-rollback / sha mismatch).
};

// 셀프 체크 실행 후 RTC slow-mem 에 결과 캐시. 다음 wake 까지 보존되며 health
// endpoint 재호출 비용 절감.
struct CachedVerdict {
  Verdict  verdict;
  uint32_t observedServerApiVersion;  // 마지막 health 응답 값. 0 = unknown.
  uint32_t recordedAtUptimeMs;
};

// 부팅 후 1회 호출. 인자는 health endpoint 가 반환한 api_version 정수
// (서버 응답 파싱은 호출자 책임 — 호출자가 응답 못 받았으면 본 함수를
// 호출하지 않거나 0 을 넘겨 Unknown 으로 캐시).
//
// 반환값: 결정된 Verdict.
Verdict evaluate(uint32_t observedServerApiVersion);

// RTC slow-mem 의 직전 verdict 조회. 부팅 직후 health endpoint 응답 도달
// 전까지 잠정 동작 모드 결정에 사용.
CachedVerdict loadCached();

// OTA 매니페스트 정합 검증. 서버 응답 헤더의 target_secure_version /
// target_sha256 (펌웨어 클라이언트가 esp_https_ota 다운로드 후 별도 검증)
// 정합성을 안티-롤백 + 무결성 관점에서 사전 차단.
//
// targetSecureVersion: 서버 매니페스트의 안티-롤백 target.
//                      펌웨어 현재 kSecureVersion 보다 작으면 즉시 거절.
// 반환: true = 진행 가능, false = 매니페스트 자체 위배 (telemetry 기록 책임은 호출자).
bool checkManifestSecureVersion(uint32_t targetSecureVersion);

// telemetry helper. 부팅 직후 BLE 진단 채널 또는 다음 성공 업로드 페어로
// 보낼 수 있도록 현 verdict 의 단순 라벨 문자열 반환.
const char* verdictLabel(Verdict v);

}  // namespace compat
}  // namespace iconia
