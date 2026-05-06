// =============================================================================
// iconia_session — BLE 프로비저닝 세션 상태머신 (단계별 timeout/retry/ACK 정교화)
// -----------------------------------------------------------------------------
// 본 모듈은 docs/security_handshake.md §6 의 정상 흐름을 명시적 상태머신으로
// 표현해, "어디서 멈춰있고 어디서 실패했는지" 가 운영성 관점에서 한 눈에 보이도록
// 한다. 보안 핸드셰이크 1 바이트도 변경하지 않으며, 기존 iconia_security
// (HKDF/AEAD/Replay/Backoff) 의 호출 순서/AAD/IV 구성은 전부 그대로 사용한다.
//
// 본 라운드 추가 책임:
//   1) 단계별 timeout 명시 (GAP 본딩 30s, Capability/Session 5s+1retry,
//      Credential 60s, Status notify 누락 차단)
//   2) 진행률 ACK (information codes 0x10..0x1F) 발송 시점 통일
//   3) tearDown 시 모든 키 자료/세션 버퍼 zero-fill 일관 보장
//
// 기존 iconia_app.cpp 의 startProvisioningBle / processCredentialBlob /
// handleProvisioningAttempt 흐름은 살아있다. 본 클래스는 그 흐름의 "상태"를
// 보관하고, 단계 전환 + timeout 검사 + 정보 코드 발송 hooks 만 제공한다.
// 즉 BLE GATT 등록/삭제, 콜백 결합 자체는 iconia_app.cpp 에서 계속 담당한다.
// =============================================================================

#pragma once

#include <Arduino.h>
#include <stdint.h>

namespace iconia {
namespace session {

// 단계 (security_handshake.md §6 의 정상 흐름)
enum class Stage : uint8_t {
  Idle = 0,           // 시작 전
  Advertising,        // BLE adv 시작 ~ connect
  Connecting,         // GAP connect 수신 ~ pairing 시작 전
  Bonding,            // Pairing/LTK 교환 진행 중 (timeout = kBondingTimeoutMs)
  Bonded,             // bonded_=true (LTK 검증 완료)
  Capability,         // Capability char read 대기 (timeout = kCapabilityTimeoutMs)
  Session,            // Session char read 대기 (= 채널 키 derivation 직전)
  CredentialAccum,    // Credential write 누적 (timeout = kCredentialTimeoutMs)
  WifiVerify,         // 디코드된 SSID/PSK 로 Wi-Fi 연결 시도
  Success,            // 0x00 success notify 송신 후 종료 진행
  Failed,             // 단계별 실패 — 코드는 별도로 보존
  TimedOut,           // 광고 윈도우 만료 (kProvisioningTimeoutMs)
};

// 단계별 timeout (ms). docs/security_handshake.md §4 와 정합.
//   - Bonding 30s : 일반 Numeric Comparison UX 가 사용자 confirm 까지 약 5~15s.
//                   여유 + 약한 BLE link 재전송 고려해 30s.
//   - Capability/Session 5s : RN 앱이 read 1회 즉시 수행. 5s 내 미발생 시 1회 retry
//                   허용 후 abort. (state machine 이 InternalRetry 슬롯 1회 보존.)
//   - Credential 60s : 사용자가 SSID 선택 + PSK 입력 + write 완료까지의 UX 시간
//                   포함. 그 이상은 세션 만료 (status 0xFB:session_expired).
static constexpr uint32_t kBondingTimeoutMs       = 30000;
static constexpr uint32_t kCapabilityTimeoutMs    = 5000;
static constexpr uint32_t kSessionReadTimeoutMs   = 5000;
static constexpr uint32_t kCredentialTimeoutMs    = 60000;

// Capability/Session 단계는 1회 internal retry 허용. 그 외 단계는 0회.
static constexpr uint8_t kPreCredRetryBudget = 1;

class StateMachine {
 public:
  void reset();
  void advanceTo(Stage next);
  Stage stage() const { return stage_; }
  uint32_t enteredAtMs() const { return enteredAtMs_; }

  // 현재 단계의 timeout 초과 여부. 초과 시 호출자가 abort + status 통보.
  // false = 시간 내. true = 초과 → caller 가 advanceTo(Failed/TimedOut).
  bool isStageExpired(uint32_t nowMs) const;

  // pre-credential 단계(Capability/Session) 재시도 1회 소비.
  // true 반환: 재시도 가능, 카운터 1 차감. 호출자가 다시 같은 단계로 enter.
  // false: 예산 소진 — abort 해야 함.
  bool consumeInternalRetry();

  // 진행률 정보 코드 송신용 토큰. notify_status 콜백이 직접 채널에 push.
  // 토큰은 docs/security_handshake.md §8 의 0x10..0x1F 정보 영역.
  static const char* infoTokenForStage(Stage s);

 private:
  Stage stage_ = Stage::Idle;
  uint32_t enteredAtMs_ = 0;
  uint8_t retriesUsed_ = 0;
};

}  // namespace session
}  // namespace iconia
