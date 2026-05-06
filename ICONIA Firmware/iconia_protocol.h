#pragma once

namespace iconia {
namespace protocol {

static constexpr const char* kApiPath = "/api/event";
static constexpr const char* kApiKeyHeader = "X-API-Key";
static constexpr const char* kCommandHeader = "X-ICONIA-Command";
static constexpr const char* kCommandEnterProvisioning = "enter_provisioning";
static constexpr const char* kCommandOta = "ota";

// OTA-related response headers (서버가 ota 명령과 함께 동봉).
// 계약: aws-infra와 합의된 정확한 헤더명. 절대 임의 변경 금지.
static constexpr const char* kOtaUrlHeader = "X-OTA-Url";
static constexpr const char* kOtaSha256Header = "X-OTA-Sha256";
static constexpr const char* kOtaVersionHeader = "X-OTA-Version";
static constexpr const char* kOtaSizeHeader = "X-OTA-Size";

static constexpr const char* kFieldTouch = "touch";
static constexpr const char* kFieldDeviceId = "device_id";
static constexpr const char* kFieldBattery = "battery";
static constexpr const char* kFieldImage = "image";
// 멱등성 키. 동일 wake에서 재시도 시 같은 값을 유지하여 서버 측 dedup이 가능
// 하도록 함. 형식: "<deviceMacNoColons>-<wakeMs>-<rand4hex>" (총 ~26자).
// 서버 합의는 별도 작업 — 본 펌웨어는 매 요청에 항상 emit.
static constexpr const char* kFieldEventId = "event_id";
// 모든 /api/event 요청에 항상 포함되는 펌웨어 자기보고 필드.
static constexpr const char* kFieldFirmwareVersion = "firmware_version";
// 직전 OTA 시도 결과 보고 필드(옵션 페어). 보고할 결과가 없으면 두 필드 모두
// multipart에서 생략. 한 쪽만 있으면 서버가 무시하므로 항상 페어로 emit.
// aws-infra와 합의된 정확한 필드명. 절대 임의 변경 금지.
static constexpr const char* kFieldLastOtaResult = "last_ota_result";
static constexpr const char* kFieldLastOtaAttemptedVersion = "last_ota_attempted_version";
static constexpr const char* kImageFileName = "event.jpg";
static constexpr const char* kImageContentType = "image/jpeg";

static constexpr const char* kTouchLeft = "left";
static constexpr const char* kTouchRight = "right";
static constexpr const char* kTouchNone = "none";

// last_ota_result enum 화이트리스트. 서버가 metric 차원으로 그대로 사용하므로
// 새 값 추가 시 aws-infra와 동시 합의 필요. 빈 문자열/그 외 값은 절대 emit X.
static constexpr const char* kOtaResultSuccess = "success";
static constexpr const char* kOtaResultShaMismatch = "sha_mismatch";
static constexpr const char* kOtaResultDownloadFailed = "download_failed";
static constexpr const char* kOtaResultFlashFailed = "flash_failed";
static constexpr const char* kOtaResultRolledBack = "rolled_back";
static constexpr const char* kOtaResultVersionRejected = "version_rejected";

// ---------------------------------------------------------------------------
// BLE secure provisioning (정본 스펙: HW/docs/security_handshake.md)
// ---------------------------------------------------------------------------
// 본 상수들은 펌웨어/모바일/문서 세 곳이 동일하게 참조해야 한다. 변경 시
// security_handshake.md 의 §3 envelope, §8 error codes 와 동시 갱신.

// 봉투 magic + 버전. magic = ASCII "ICN1".
static constexpr uint32_t kProvEnvMagicLE = 0x314E4349u;  // little-endian: 'I''C''N''1'
static constexpr uint8_t  kProvEnvVersion = 0x01;

// 고정 길이 (security_handshake.md §3.2)
static constexpr size_t kProvMagicLen      = 4;
static constexpr size_t kProvVersionLen    = 1;
static constexpr size_t kProvFlagsLen      = 1;
static constexpr size_t kProvSeqLen        = 2;
static constexpr size_t kProvTsLen         = 4;
static constexpr size_t kProvIvLen         = 12;   // AES-GCM IV
static constexpr size_t kProvCtLenLen      = 2;
static constexpr size_t kProvTagLen        = 16;   // AES-GCM auth tag
static constexpr size_t kProvHeaderLen =
    kProvMagicLen + kProvVersionLen + kProvFlagsLen + kProvSeqLen +
    kProvTsLen + kProvIvLen + kProvCtLenLen;        // = 26

static constexpr uint8_t kProvFlagLastChunk = 0x01;

// AAD prefix string (security_handshake.md §3.3)
static constexpr const char* kProvAadPrefix = "ICONIA-PROV-AAD-v1";

// HKDF info string (security_handshake.md §1.2)
static constexpr const char* kProvHkdfInfoPrefix = "ICONIA-PROV-CH-v1";

// Plaintext field bounds (security_handshake.md §3.1)
static constexpr size_t kProvSsidMax = 32;
static constexpr size_t kProvPskMax  = 63;
static constexpr size_t kProvReservedLen = 8;

// 누적 AEAD blob 최대치. 단일 chunk MTU(=20~244) 보다 충분히 크되, 무한
// append 공격 차단. 펌웨어는 누적 길이 > kProvMaxBlobLen 이면 즉시 abort.
static constexpr size_t kProvMaxBlobLen = 512;

// Status notify payload 형식: "0xNN:label". 코드는 docs/security_handshake.md §8
// 표와 1:1 정합. 추가/변경 시 §8 + docs/operational_telemetry.md §1 동시 갱신.
//
// 코드 영역 분류 (number space 충돌 방지)
//   0x00         success
//   0x01..0x0A   기존 검증 실패 (보안 핸드셰이크 단계 — 본 라운드 변경 없음)
//   0x10..0x1F   진행률 정보 코드 (본 라운드 신설; 정상 흐름 ACK)
//   0x20..0x2F   Wi-Fi 단계 실패 세분화 (본 라운드 신설)
//   0xFB         session_expired (본 라운드 신설; 60s credential 미수신)
//   0xFE         locked_out (12h hard cap)
//   0xFF         timeout (2 분 광고 윈도우)
//
// 본 라운드 신설 코드의 recoverable / retry-after / 사용자 카피 매핑은
// docs/security_handshake.md §8 표 참조.
static constexpr const char* kProvStatusSuccess        = "0x00:success";
static constexpr const char* kProvStatusNotBonded      = "0x01:not_bonded";
static constexpr const char* kProvStatusBadMagic       = "0x02:bad_magic";
static constexpr const char* kProvStatusBadSeq         = "0x03:bad_seq";
static constexpr const char* kProvStatusChunkTo        = "0x04:chunk_timeout";
static constexpr const char* kProvStatusTsWindow       = "0x05:ts_window";
static constexpr const char* kProvStatusReplay         = "0x06:replay";
static constexpr const char* kProvStatusAeadFail       = "0x07:aead_fail";
static constexpr const char* kProvStatusBadPlain       = "0x08:bad_plaintext";
static constexpr const char* kProvStatusWifiAuth       = "0x09:wifi_auth_fail";
static constexpr const char* kProvStatusWifiNoAp       = "0x0A:wifi_no_ap";

// 진행률 정보 코드 (본 라운드 신설; iconia_session.cpp::infoTokenForStage 와 1:1).
static constexpr const char* kProvInfoAdvertising      = "0x10:advertising";
static constexpr const char* kProvInfoConnecting       = "0x11:connecting";
static constexpr const char* kProvInfoBonding          = "0x12:bonding";
static constexpr const char* kProvInfoBonded           = "0x13:bonded";
static constexpr const char* kProvInfoCapabilityRead   = "0x14:capability_read";
static constexpr const char* kProvInfoSessionRead      = "0x15:session_read";
static constexpr const char* kProvInfoCredentialRecv   = "0x16:credential_recv";
static constexpr const char* kProvInfoWifiVerify       = "0x17:wifi_verify";

// Wi-Fi 단계 실패 세분화 (본 라운드 신설) — recoverable / retry-after 메타는
// docs/security_handshake.md §8 표. 기존 0x09/0x0A 와 의미가 부분 중복이지만,
// 본 신설 코드는 "사용자 친화 메시지 + retry-after hint" 동봉 가능한 신규 영역.
// 펌웨어/모바일 합의 후 0x09/0x0A 점진 deprecate.
static constexpr const char* kProvStatusBadQrFormat    = "0x20:bad_qr_format";
static constexpr const char* kProvStatusPinMismatch    = "0x21:pin_mismatch";
static constexpr const char* kProvStatusSsidNotFound   = "0x22:ssid_not_found";
static constexpr const char* kProvStatusWifiAuthFail   = "0x23:wifi_auth_fail";
static constexpr const char* kProvStatusWifiTimeout    = "0x24:wifi_timeout";
static constexpr const char* kProvStatusWifiNoInternet = "0x25:wifi_no_internet";

static constexpr const char* kProvStatusSessionExpired = "0xFB:session_expired";
static constexpr const char* kProvStatusLockedOut      = "0xFE:locked_out";
static constexpr const char* kProvStatusTimeout        = "0xFF:timeout";

}  // namespace protocol
}  // namespace iconia
