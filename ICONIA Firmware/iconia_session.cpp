// =============================================================================
// iconia_session — implementation
// 정본: docs/security_handshake.md §6 + docs/operational_telemetry.md §2.1
// =============================================================================

#include "iconia_session.h"

namespace iconia {
namespace session {

void StateMachine::reset() {
  stage_ = Stage::Idle;
  enteredAtMs_ = 0;
  retriesUsed_ = 0;
}

void StateMachine::advanceTo(Stage next) {
  stage_ = next;
  enteredAtMs_ = (uint32_t)millis();
  // 단계 전환마다 retry 예산은 새 단계 기준으로 재산정 (Capability/Session 만
  // pre-credential retry 슬롯을 사용). 본 클래스는 단순히 카운터를 0으로 리셋
  // 하지 않고 "어떤 단계에서 retry 를 썼는지" 를 보존하기 위해 그대로 둔다 —
  // pre-credential 단계 재진입 시 consumeInternalRetry 가 동일 budget 을
  // 1회만 허용한다.
  if (next == Stage::Idle || next == Stage::Bonded ||
      next == Stage::CredentialAccum || next == Stage::Success ||
      next == Stage::Failed || next == Stage::TimedOut) {
    // 단계가 명백히 "다른 책임 영역"으로 넘어갔으므로 retry 카운터 reset
    retriesUsed_ = 0;
  }
}

bool StateMachine::isStageExpired(uint32_t nowMs) const {
  uint32_t elapsed = nowMs - enteredAtMs_;
  switch (stage_) {
    case Stage::Bonding:
      return elapsed > kBondingTimeoutMs;
    case Stage::Capability:
      return elapsed > kCapabilityTimeoutMs;
    case Stage::Session:
      return elapsed > kSessionReadTimeoutMs;
    case Stage::CredentialAccum:
      return elapsed > kCredentialTimeoutMs;
    // Advertising / WifiVerify 등의 timeout 은 상위 흐름의 기존 가드 사용:
    //   - Advertising: kProvisioningTimeoutMs (2 분, app loop)
    //   - WifiVerify : connectToWifiWithRetry 내부 attempt timeout
    default:
      return false;
  }
}

bool StateMachine::consumeInternalRetry() {
  if (stage_ != Stage::Capability && stage_ != Stage::Session) {
    return false;
  }
  if (retriesUsed_ >= kPreCredRetryBudget) {
    return false;
  }
  retriesUsed_++;
  enteredAtMs_ = (uint32_t)millis();  // 재진입 시 stage timer 리셋
  return true;
}

const char* StateMachine::infoTokenForStage(Stage s) {
  // docs/security_handshake.md §8 의 정보 코드(0x10..0x1F).
  // 펌웨어/모바일/서버가 동일 라벨 사용 — 변경 시 §8 동기 필수.
  switch (s) {
    case Stage::Advertising:     return "0x10:advertising";
    case Stage::Connecting:      return "0x11:connecting";
    case Stage::Bonding:         return "0x12:bonding";
    case Stage::Bonded:          return "0x13:bonded";
    case Stage::Capability:      return "0x14:capability_read";
    case Stage::Session:         return "0x15:session_read";
    case Stage::CredentialAccum: return "0x16:credential_recv";
    case Stage::WifiVerify:      return "0x17:wifi_verify";
    case Stage::Success:         return "0x00:success";
    default:                     return nullptr;
  }
}

}  // namespace session
}  // namespace iconia
