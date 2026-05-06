// =============================================================================
// iconia_security — BLE 프로비저닝 보안 미들웨어
// -----------------------------------------------------------------------------
// 본 모듈은 기존 PersonaClient/Wi-Fi/카메라 비즈니스 로직과 무관하게,
// "BLE 페어링 → 자격증명 검증 → Wi-Fi 연결" 구간에만 끼어드는 보안 미들웨어.
// 정본 스펙: HW/docs/security_handshake.md
//
// 본 헤더가 노출하는 API 그룹:
//   1) FactorySeed         : factory_nvs partition 에서 seed/salt 로드 (RO).
//   2) ChannelKey          : HKDF-SHA256 으로 세션 채널 키 유도.
//   3) AeadEnvelope        : AEAD blob 누적/파싱/AES-256-GCM 복호화.
//   4) ReplayCache         : RTC slow-mem 기반 (nonce, ts) 중복 거부.
//   5) ProvBackoff         : 본딩/검증 실패 카운터 + 점진 백오프 + 12h hard cap.
//
// 주의: AES-256-GCM/HKDF 는 ESP-IDF 가 제공하는 mbedtls 헤더를 그대로 사용
// (Arduino-ESP32 core 3.x = ESP-IDF 5.x 기반).
// =============================================================================

#pragma once

#include <Arduino.h>
#include <stdint.h>
#include <stddef.h>

namespace iconia {
namespace security {

// ---------------------------------------------------------------------------
// 1. Factory Seed (read-only NVS)
// ---------------------------------------------------------------------------
struct FactorySeed {
  uint8_t seed[32];
  uint8_t salt[16];
  uint8_t seedVer;
  bool valid;
};

// factory_nvs 네임스페이스에서 seed/salt 를 로드. 부재 또는 형식 비정상이면
// valid=false. 양산 burn 절차는 docs/production_provisioning.md §3 Step 6.
FactorySeed loadFactorySeed();

// FactorySeed 내부 비밀 영역을 0 으로 덮어쓰기. 사용 종료 직후 호출.
void zeroizeFactorySeed(FactorySeed& seed);

// ---------------------------------------------------------------------------
// 2. Channel key derivation (HKDF-SHA256)
// ---------------------------------------------------------------------------
// info = "ICONIA-PROV-CH-v1" || device_mac(6B) || session_nonce(16B)
// salt = factory salt(16B)
// ikm  = factory seed(32B)
// out  = 32B (AES-256 key)
// 반환: true = 성공.
bool deriveChannelKey(const FactorySeed& seed,
                      const uint8_t deviceMac[6],
                      const uint8_t sessionNonce[16],
                      uint8_t outKey32[32]);

// ---------------------------------------------------------------------------
// 3. AEAD envelope (AES-256-GCM)
// ---------------------------------------------------------------------------
// 봉투 누적 버퍼. 단일 GATT write 가 envelope 전체를 담을 수도 있고,
// 여러 chunk 로 나뉠 수도 있다 (security_handshake.md §3.2).
class AeadEnvelope {
 public:
  // chunk 누적. 누적 길이가 kProvMaxBlobLen 초과 또는 last_chunk seq < 직전 seq
  // 면 false (호출자가 즉시 abort 처리).
  bool appendChunk(const uint8_t* data, size_t len, bool* outLastChunkReceived);

  // 누적된 envelope 의 헤더 영역 파싱. magic/version/flags/seq/ts/iv/ct_len/tag
  // 위치를 outRefs 에 채움. 형식 위반 시 false.
  // 참조 포인터들의 lifetime 은 본 객체의 buffer 와 일치.
  struct ParsedHeader {
    uint8_t version;
    uint8_t flags;
    uint16_t seqLast;
    uint32_t tsUnixBe;       // big-endian wire format → host order 로 변환된 값
    const uint8_t* iv;       // 12B (kProvIvLen)
    uint16_t ctLen;
    const uint8_t* ct;       // ct_len B
    const uint8_t* tag;      // 16B (kProvTagLen)
  };
  bool parseHeader(ParsedHeader& outHeader) const;

  // 평문 복호화. plainBuf 는 ct_len 이상 크기로 제공.
  // aad 는 호출자가 미리 빌드 (security_handshake.md §3.3).
  bool decrypt(const uint8_t key32[32],
               const uint8_t* aad, size_t aadLen,
               uint8_t* plainBuf, size_t plainBufLen,
               size_t* outPlainLen) const;

  // 누적 시작 시각 (millis). chunk timeout 검사용.
  uint32_t startedAtMs() const { return startedAtMs_; }
  size_t accumulatedBytes() const { return len_; }

  void reset();

 private:
  uint8_t buf_[/*kProvMaxBlobLen*/ 512] = {0};
  size_t len_ = 0;
  uint16_t lastSeq_ = 0;
  uint32_t startedAtMs_ = 0;
};

// AEAD 평문(ssid_len|ssid|psk_len|psk|reserved) 파서 (§3.1).
struct WifiCredentialPlain {
  char ssid[33];   // null-terminated, max 32
  char psk[64];    // null-terminated, max 63
  bool valid;
};
WifiCredentialPlain parseWifiPlaintext(const uint8_t* plain, size_t len);

// AAD 빌더 (§3.3). 결과 bytes 는 outBuf (>= 64B 권장) 에 기록, 실제 길이는
// outLen 에 반환. 형식: "ICONIA-PROV-AAD-v1" || mac(6) || version(1) || nonce(16) || ts_be(4)
size_t buildAad(const uint8_t deviceMac[6],
                uint8_t version,
                const uint8_t sessionNonce[16],
                uint32_t tsUnixBe,
                uint8_t* outBuf, size_t outBufLen);

// ---------------------------------------------------------------------------
// 4. Replay cache (RTC slow-mem, 부팅 간 보존)
// ---------------------------------------------------------------------------
// (sessionNonce, tsUnix) 페어를 8B truncated SHA-256 으로 keep.
// kProvReplayCacheSlots 개의 ring buffer.
namespace replay {
  bool isSeen(const uint8_t sessionNonce[16], uint32_t tsUnixBe);
  void remember(const uint8_t sessionNonce[16], uint32_t tsUnixBe);
}  // namespace replay

// ---------------------------------------------------------------------------
// 5. 본딩/검증 실패 백오프 + 12h hard cap (RTC slow-mem)
// ---------------------------------------------------------------------------
namespace backoff {
  // 카운터 read-only 조회. (lockout 체크에 사용)
  uint16_t failCount();

  // 12h 윈도우 lockout 활성 여부. true 면 본 wake 에서 BLE 시작 금지.
  bool isLockedOut();

  // 다음 시도까지 적용해야 할 백오프 시간 (ms). 0 이면 즉시 시도 가능.
  uint32_t requiredBackoffMs();

  // 본딩 또는 §4 검증 단계 1~9 중 하나라도 실패 시 호출.
  // 12h 윈도우 누적 ≥ kProvHardLockoutCount 가 되면 lockout flag set.
  void recordFailure();

  // 자격증명 검증 + Wi-Fi 연결 1회 성공 시 호출. 카운터/타임스탬프/lockout
  // 모두 zero-fill.
  void recordSuccess();
}  // namespace backoff

}  // namespace security
}  // namespace iconia
