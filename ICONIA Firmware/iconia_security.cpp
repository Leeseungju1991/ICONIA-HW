// =============================================================================
// iconia_security — implementation. 정본 스펙: HW/docs/security_handshake.md
// =============================================================================

#include "iconia_security.h"

#include <string.h>
#include <Preferences.h>

#include "esp_attr.h"        // RTC_DATA_ATTR
#include "esp_random.h"
#include "esp_system.h"
#include "esp_timer.h"

#include "mbedtls/gcm.h"
#include "mbedtls/hkdf.h"
#include "mbedtls/md.h"
#include "mbedtls/sha256.h"

#include "iconia_config.h"
#include "iconia_protocol.h"

namespace iconia {
namespace security {

// ---------------------------------------------------------------------------
// 1. Factory Seed
// ---------------------------------------------------------------------------
FactorySeed loadFactorySeed() {
  FactorySeed out = {};
  out.valid = false;

  Preferences prefs;
  // mode=true → read-only. write 권한 없음 → factory partition 무결성 보장.
  if (!prefs.begin(iconia::config::kFactoryNvsNamespace, true)) {
    return out;
  }

  size_t seedSize = prefs.getBytes(
      iconia::config::kFactoryKeySeed, out.seed, sizeof(out.seed));
  size_t saltSize = prefs.getBytes(
      iconia::config::kFactoryKeySeedSalt, out.salt, sizeof(out.salt));
  out.seedVer = (uint8_t)prefs.getUChar(
      iconia::config::kFactoryKeySeedVer, 0);

  prefs.end();

  if (seedSize != iconia::config::kFactorySeedLen) {
    return out;
  }
  if (saltSize != iconia::config::kFactorySeedSaltLen) {
    return out;
  }
  if (out.seedVer == 0) {
    return out;
  }
  out.valid = true;
  return out;
}

void zeroizeFactorySeed(FactorySeed& seed) {
  // volatile to deter optimizer eliding the memset.
  volatile uint8_t* p = seed.seed;
  for (size_t i = 0; i < sizeof(seed.seed); ++i) {
    p[i] = 0;
  }
  volatile uint8_t* q = seed.salt;
  for (size_t i = 0; i < sizeof(seed.salt); ++i) {
    q[i] = 0;
  }
  seed.seedVer = 0;
  seed.valid = false;
}

// ---------------------------------------------------------------------------
// 2. HKDF-SHA256 channel key
// ---------------------------------------------------------------------------
bool deriveChannelKey(const FactorySeed& seed,
                      const uint8_t deviceMac[6],
                      const uint8_t sessionNonce[16],
                      uint8_t outKey32[32]) {
  if (!seed.valid) {
    return false;
  }

  // info = prefix || mac(6) || nonce(16)
  uint8_t info[64] = {0};
  size_t prefixLen = strlen(iconia::protocol::kProvHkdfInfoPrefix);
  if (prefixLen + 6 + 16 > sizeof(info)) {
    return false;
  }
  memcpy(info, iconia::protocol::kProvHkdfInfoPrefix, prefixLen);
  memcpy(info + prefixLen, deviceMac, 6);
  memcpy(info + prefixLen + 6, sessionNonce, 16);
  size_t infoLen = prefixLen + 6 + 16;

  const mbedtls_md_info_t* md = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
  if (md == nullptr) {
    return false;
  }
  int rc = mbedtls_hkdf(
      md,
      seed.salt, sizeof(seed.salt),       // salt
      seed.seed, sizeof(seed.seed),       // ikm
      info, infoLen,                      // info
      outKey32, 32);
  return rc == 0;
}

// ---------------------------------------------------------------------------
// 3. AEAD envelope
// ---------------------------------------------------------------------------
bool AeadEnvelope::appendChunk(const uint8_t* data, size_t len,
                               bool* outLastChunkReceived) {
  if (outLastChunkReceived != nullptr) {
    *outLastChunkReceived = false;
  }
  if (data == nullptr || len == 0) {
    return false;
  }

  // chunk 단위 길이 sanity: BLE MTU 한계 + 봉투 헤더 고려. 단일 chunk 가
  // 240B 를 넘으면 잘못된 fragmentation.
  if (len > 240) {
    return false;
  }

  // 누적 시각 마킹 (첫 chunk 진입 시점).
  if (len_ == 0) {
    startedAtMs_ = (uint32_t)millis();
    lastSeq_ = 0;
  }

  if (len_ + len > sizeof(buf_)) {
    return false;
  }
  memcpy(buf_ + len_, data, len);
  len_ += len;

  // 헤더 한 번이라도 누적되면 seq 단조성 검사.
  if (len_ >= iconia::protocol::kProvHeaderLen) {
    // seq big-endian @ offset = 4(magic)+1(ver)+1(flags) = 6
    uint16_t seq =
        ((uint16_t)buf_[6] << 8) | (uint16_t)buf_[7];
    if (lastSeq_ != 0 && seq < lastSeq_) {
      return false;
    }
    lastSeq_ = seq;

    uint8_t flags = buf_[5];
    if (flags & iconia::protocol::kProvFlagLastChunk) {
      if (outLastChunkReceived != nullptr) {
        *outLastChunkReceived = true;
      }
    }
  }
  return true;
}

bool AeadEnvelope::parseHeader(ParsedHeader& outHeader) const {
  if (len_ < iconia::protocol::kProvHeaderLen + iconia::protocol::kProvTagLen) {
    return false;
  }
  // magic LE 비교
  uint32_t magic = ((uint32_t)buf_[0]) |
                   ((uint32_t)buf_[1] << 8) |
                   ((uint32_t)buf_[2] << 16) |
                   ((uint32_t)buf_[3] << 24);
  if (magic != iconia::protocol::kProvEnvMagicLE) {
    return false;
  }
  outHeader.version  = buf_[4];
  outHeader.flags    = buf_[5];
  outHeader.seqLast  = ((uint16_t)buf_[6] << 8) | (uint16_t)buf_[7];
  outHeader.tsUnixBe = ((uint32_t)buf_[8]  << 24) |
                       ((uint32_t)buf_[9]  << 16) |
                       ((uint32_t)buf_[10] << 8)  |
                       ((uint32_t)buf_[11]);
  if (outHeader.version != iconia::protocol::kProvEnvVersion) {
    return false;
  }
  outHeader.iv = buf_ + 12;             // 12B
  uint16_t ctLen = ((uint16_t)buf_[24] << 8) | (uint16_t)buf_[25];
  outHeader.ctLen = ctLen;

  size_t expected = iconia::protocol::kProvHeaderLen + ctLen + iconia::protocol::kProvTagLen;
  if (expected > len_) {
    return false;
  }
  if (ctLen > 0xFE) {  // sanity: plaintext ≤ 1+32+1+63+8 = 105B 가 정상
    return false;
  }
  outHeader.ct = buf_ + iconia::protocol::kProvHeaderLen;
  outHeader.tag = outHeader.ct + ctLen;
  return true;
}

bool AeadEnvelope::decrypt(const uint8_t key32[32],
                           const uint8_t* aad, size_t aadLen,
                           uint8_t* plainBuf, size_t plainBufLen,
                           size_t* outPlainLen) const {
  ParsedHeader hdr = {};
  if (!parseHeader(hdr)) {
    return false;
  }
  if (plainBufLen < hdr.ctLen) {
    return false;
  }

  mbedtls_gcm_context gcm;
  mbedtls_gcm_init(&gcm);
  int rc = mbedtls_gcm_setkey(&gcm, MBEDTLS_CIPHER_ID_AES, key32, 256);
  if (rc != 0) {
    mbedtls_gcm_free(&gcm);
    return false;
  }
  rc = mbedtls_gcm_auth_decrypt(
      &gcm,
      hdr.ctLen,
      hdr.iv, iconia::protocol::kProvIvLen,
      aad, aadLen,
      hdr.tag, iconia::protocol::kProvTagLen,
      hdr.ct, plainBuf);
  mbedtls_gcm_free(&gcm);
  if (rc != 0) {
    return false;
  }
  if (outPlainLen != nullptr) {
    *outPlainLen = hdr.ctLen;
  }
  return true;
}

void AeadEnvelope::reset() {
  // 비밀 누설 방지: 누적 buffer 를 zero-fill 후 길이 초기화.
  volatile uint8_t* p = buf_;
  for (size_t i = 0; i < sizeof(buf_); ++i) {
    p[i] = 0;
  }
  len_ = 0;
  lastSeq_ = 0;
  startedAtMs_ = 0;
}

WifiCredentialPlain parseWifiPlaintext(const uint8_t* plain, size_t len) {
  WifiCredentialPlain out = {};
  out.valid = false;
  if (plain == nullptr || len < 2) {
    return out;
  }
  size_t i = 0;
  uint8_t ssidLen = plain[i++];
  if (ssidLen < 1 || ssidLen > iconia::protocol::kProvSsidMax) {
    return out;
  }
  if (i + ssidLen > len) {
    return out;
  }
  memcpy(out.ssid, plain + i, ssidLen);
  out.ssid[ssidLen] = '\0';
  i += ssidLen;

  if (i + 1 > len) {
    return out;
  }
  uint8_t pskLen = plain[i++];
  if (pskLen > iconia::protocol::kProvPskMax) {
    return out;
  }
  if (i + pskLen > len) {
    return out;
  }
  memcpy(out.psk, plain + i, pskLen);
  out.psk[pskLen] = '\0';
  i += pskLen;

  // reserved 8B 는 형식 검사 없음 — 다음 단계로 이행.
  // (i + 8 가 len 을 넘어도 ciphertext truncation 가능성 있어 strict 거부 X.)
  out.valid = true;
  return out;
}

size_t buildAad(const uint8_t deviceMac[6],
                uint8_t version,
                const uint8_t sessionNonce[16],
                uint32_t tsUnixBe,
                uint8_t* outBuf, size_t outBufLen) {
  size_t prefixLen = strlen(iconia::protocol::kProvAadPrefix);
  size_t total = prefixLen + 6 + 1 + 16 + 4;
  if (outBufLen < total) {
    return 0;
  }
  size_t i = 0;
  memcpy(outBuf + i, iconia::protocol::kProvAadPrefix, prefixLen);
  i += prefixLen;
  memcpy(outBuf + i, deviceMac, 6);
  i += 6;
  outBuf[i++] = version;
  memcpy(outBuf + i, sessionNonce, 16);
  i += 16;
  // tsUnixBe 는 이미 host-order int. wire format 으로 다시 big-endian write.
  outBuf[i++] = (uint8_t)((tsUnixBe >> 24) & 0xFF);
  outBuf[i++] = (uint8_t)((tsUnixBe >> 16) & 0xFF);
  outBuf[i++] = (uint8_t)((tsUnixBe >> 8) & 0xFF);
  outBuf[i++] = (uint8_t)(tsUnixBe & 0xFF);
  return i;
}

// ---------------------------------------------------------------------------
// 4. Replay cache (RTC slow-mem)
// ---------------------------------------------------------------------------
// 8B truncated SHA-256 of (nonce || ts) per slot. ring buffer.
RTC_DATA_ATTR static uint64_t s_replayCache[16] = {0};
RTC_DATA_ATTR static uint8_t  s_replayHead = 0;

namespace replay {

static uint64_t hashKey(const uint8_t sessionNonce[16], uint32_t tsUnixBe) {
  uint8_t buf[20];
  memcpy(buf, sessionNonce, 16);
  buf[16] = (uint8_t)((tsUnixBe >> 24) & 0xFF);
  buf[17] = (uint8_t)((tsUnixBe >> 16) & 0xFF);
  buf[18] = (uint8_t)((tsUnixBe >> 8) & 0xFF);
  buf[19] = (uint8_t)(tsUnixBe & 0xFF);

  uint8_t digest[32];
  mbedtls_sha256_context ctx;
  mbedtls_sha256_init(&ctx);
  mbedtls_sha256_starts(&ctx, 0);
  mbedtls_sha256_update(&ctx, buf, sizeof(buf));
  mbedtls_sha256_finish(&ctx, digest);
  mbedtls_sha256_free(&ctx);

  uint64_t key = 0;
  for (int i = 0; i < 8; ++i) {
    key = (key << 8) | (uint64_t)digest[i];
  }
  return key;
}

bool isSeen(const uint8_t sessionNonce[16], uint32_t tsUnixBe) {
  uint64_t key = hashKey(sessionNonce, tsUnixBe);
  for (size_t i = 0; i < iconia::config::kProvReplayCacheSlots; ++i) {
    if (s_replayCache[i] == key) {
      return true;
    }
  }
  return false;
}

void remember(const uint8_t sessionNonce[16], uint32_t tsUnixBe) {
  uint64_t key = hashKey(sessionNonce, tsUnixBe);
  s_replayCache[s_replayHead % iconia::config::kProvReplayCacheSlots] = key;
  s_replayHead = (uint8_t)((s_replayHead + 1) % iconia::config::kProvReplayCacheSlots);
}

}  // namespace replay

// ---------------------------------------------------------------------------
// 5. Backoff + 12h hard cap (RTC slow-mem)
// ---------------------------------------------------------------------------
RTC_DATA_ATTR static uint16_t s_provFailCount = 0;
RTC_DATA_ATTR static uint64_t s_provFirstFailUs = 0;     // 12h 윈도우 시작
RTC_DATA_ATTR static uint64_t s_provLastFailUs = 0;      // 마지막 실패 RTC ts
RTC_DATA_ATTR static uint8_t  s_provLockoutFlag = 0;     // 1 = locked
RTC_DATA_ATTR static uint64_t s_provLockoutSetUs = 0;    // lockout 시작 시각

namespace backoff {

static uint64_t nowUs() {
  return (uint64_t)esp_timer_get_time();
}

uint16_t failCount() {
  return s_provFailCount;
}

bool isLockedOut() {
  if (!s_provLockoutFlag) {
    return false;
  }
  // 12h 경과 시 자동 해제.
  uint64_t elapsed = nowUs() - s_provLockoutSetUs;
  if (elapsed >= iconia::config::kProvLockoutWindowUs) {
    s_provLockoutFlag = 0;
    s_provLockoutSetUs = 0;
    s_provFailCount = 0;
    s_provFirstFailUs = 0;
    s_provLastFailUs = 0;
    return false;
  }
  return true;
}

uint32_t requiredBackoffMs() {
  if (s_provFailCount == 0) {
    return 0;
  }
  // table index = min(fail-1, slots-1)
  size_t idx = (size_t)(s_provFailCount - 1);
  if (idx >= iconia::config::kProvBackoffSlots) {
    idx = iconia::config::kProvBackoffSlots - 1;
  }
  uint32_t need = iconia::config::kProvBackoffMs[idx];

  // 마지막 실패로부터 경과시간이 백오프 미만이면 잔여시간 반환.
  uint64_t now = nowUs();
  uint64_t elapsedUs = (now > s_provLastFailUs) ? (now - s_provLastFailUs) : 0;
  uint32_t elapsedMs = (uint32_t)(elapsedUs / 1000ULL);
  if (elapsedMs >= need) {
    return 0;
  }
  return need - elapsedMs;
}

void recordFailure() {
  uint64_t now = nowUs();

  // 12h 윈도우 외부 첫 실패면 윈도우 리셋.
  if (s_provFirstFailUs == 0 ||
      (now - s_provFirstFailUs) >= iconia::config::kProvLockoutWindowUs) {
    s_provFirstFailUs = now;
    s_provFailCount = 0;
  }

  if (s_provFailCount < UINT16_MAX) {
    s_provFailCount++;
  }
  s_provLastFailUs = now;

  if (s_provFailCount >= iconia::config::kProvHardLockoutCount) {
    s_provLockoutFlag = 1;
    s_provLockoutSetUs = now;
  }
}

void recordSuccess() {
  s_provFailCount = 0;
  s_provFirstFailUs = 0;
  s_provLastFailUs = 0;
  s_provLockoutFlag = 0;
  s_provLockoutSetUs = 0;
}

}  // namespace backoff

}  // namespace security
}  // namespace iconia
