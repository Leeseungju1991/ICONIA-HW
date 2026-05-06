# ICONIA Operational Telemetry — 정본 v1

본 문서는 ESP32 펌웨어가 운영 단계에서 외부(서버 / BLE 진단 char / 시리얼)에
노출하는 모든 운영성 신호의 정본 정의이다. 서버 / 모바일 에이전트가 본
문서만 보고도 자족적으로 정합 구현이 가능해야 한다.

> 적용 범위: ICONIA AI 인형 (성인 한정 IoT 제품). 보안 핸드셰이크 자체의
> 정본은 `security_handshake.md`. 본 문서는 핸드셰이크 단계가 아닌
> "이벤트 업로드 / 배터리 / 부팅 invariant" 의 운영성 정의.

---

## 1. BLE Provisioning Status — 코드 영역 인덱스

| 영역 | 의미 |
|------|------|
| `0x00` | success |
| `0x01..0x0A` | 핸드셰이크 단계 검증 실패 (보안) — `security_handshake.md` §8 참조 |
| `0x10..0x1F` | 진행률 정보 코드 (정상 흐름 ACK) |
| `0x20..0x2F` | Wi-Fi 단계 실패 세분화 |
| `0xFB` | session_expired (60s credential 미수신) |
| `0xFE` | locked_out (12h hard cap) |
| `0xFF` | timeout (2 분 광고 윈도우 만료) |

전체 코드 표 + recoverable / retry-after / 사용자 카피는
`security_handshake.md` §8 단일 진리.

---

## 2. 이벤트 업로드 신뢰성

### 2.1 재시도 정책 (네트워크 단계)

펌웨어는 다음 백오프 스케줄로 Wi-Fi 연결 + HTTPS 업로드를 시도한다.
부팅 간 RTC slow-mem 에 누적 attempt 카운터를 보존.

| attempt # | 다음 시도까지 지연 | jitter |
|-----------|-------------------|--------|
| 1 | 1 s   | ±25% |
| 2 | 2 s   | ±25% |
| 3 | 4 s   | ±25% |
| 4 | 8 s   | ±25% |
| 5 | 16 s  | ±25% |
| 6+ | 30 s (cap) | ±25% |

누적 12회 또는 24h 한계 도달 시:
- LED 패턴 (3회 빠른 깜빡임 × 3 burst) 으로 사용자 가시 신호.
- 다음 부팅 시 BLE 재진입 옵션 (사용자 개입). 자격증명 erase 는 기존
  `kWifiAuthFailEraseThreshold` 정책과 별도 — 본 한계는 "AP 자체는 정상이지만
  서버 도달 불가" 상황을 분리해 다룬다.

### 2.2 실패 카테고리 (failure_category)

업로드 실패는 단순 boolean 이 아니라 다음 카테고리로 분류해 RTC slow-mem 에
별도 카운터로 누적. 다음 성공 업로드의 telemetry 페어로 동봉(향후 서버 계약
확장 시).

| 코드 | 라벨 | 설명 |
|------|------|------|
| `0x00` | none | 정상 (실패 아님) |
| `0x10` | wifi_assoc_fail | AP 결합 자체 실패 (NO_SSID / auth_fail 분기 별도) |
| `0x11` | dns_lookup_fail | DNS 조회 실패 |
| `0x12` | tcp_connect_fail | TCP 연결 실패 (라우팅/NAT/방화벽) |
| `0x13` | tls_handshake_fail | TLS 핸드셰이크 실패 (인증서/시간/SNI) |
| `0x14` | http_4xx | 서버 4xx 응답 (인증/요청 형식) |
| `0x15` | http_5xx | 서버 5xx 응답 (서버 측 일시 장애) |
| `0x16` | network_unreachable | route 자체 없음 (게이트웨이/IP 미할당) |
| `0x17` | timeout_response | 본문 타임아웃 (서버 응답 미도착) |
| `0x18` | fingerprint_mismatch | 서버 인증서 fingerprint 핀닝 위반 |

### 2.3 Persistent Queue (events_q partition)

업로드 실패 이벤트(JPEG + 메타) 는 `events_q` SPIFFS partition 에 보존.
부팅 시 `iconia::upload_queue::begin()` 호출 → 비어있지 않으면 우선 flush.

- partition: `events_q`, offset 0x350000, size 0xB0000 (704 KB)
- ring buffer 슬롯: 8개 (`kSlotCount`)
- 슬롯당 평균 ~120 KB (VGA q12 JPEG + 32B 메타)
- 가득 차면 가장 오래된 entry FIFO drop + `totalDroppedFull` 카운터 인상
- 큐 통계: RTC slow-mem `QueueStats { totalEnqueued, totalDroppedFull, totalFlushedOk }`

**event_id 정합** — `iconia_app.cpp::buildEventId` 가 emit 한 키를 큐에 보존,
서버 `idempotencyCache` 의 24h dedup 윈도우와 1:1 정합. 큐에 2일 이상 머문
entry 는 "TTL 초과" 사유로 drop (서버에서 어차피 dedup 미스). 본 라운드는
TTL 미적용 — `totalDroppedFull` 만 보존.

### 2.4 구조화 로그 라인

매 업로드 시도마다 시리얼 + (다음 성공 업로드의 telemetry 페어) 에 다음 필드:

```
event_id          : 26~32자 멱등 키
attempt_no        : 1, 2, 3, ...
failure_category  : §2.2 코드
wifi_rssi         : dBm (정수, 미연결 시 0)
battery_mv        : 정수 mV
uptime_ms         : millis() 절대값
ts_offset_first_ms: 첫 시도부터 본 시도까지 ms 차이
```

PROD 빌드는 시리얼 출력이 차단된다 (`ICONIA_PRODUCTION_BUILD=1`) → 본 로그
라인은 RAM 누적 후 다음 성공 업로드에 동봉. (서버 계약 확장 별도 합의 필요 —
`integration-reviewer` 위임.)

### 2.5 BLE 진단 char (선택 v2)

향후 v2 에서 펌웨어가 BLE 진단 read-only characteristic 을 추가해 다음 정보를
노출 가능 (UUID 미정):

```
last_failure_reason : §2.2 코드
last_failure_at_ms  : 절대 millis
queue_depth         : 현재 큐 entry 수
panic_mask          : §4 boot invariant 위반 비트마스크
```

본 라운드는 char 자체 미추가 — 정의만 동결.

---

## 3. 배터리 정책 (`iconia_battery.{h,cpp}`)

### 3.1 단계별 임계 (방전 중 기준)

| Policy | 전압 | 허용 동작 |
|--------|------|-----------|
| Normal     | ≥ 4.00 V | capture + upload + OTA + BLE |
| Sustain    | ≥ 3.70 V | capture + upload + BLE (OTA 별도 50% 가드) |
| Emergency  | ≥ 3.50 V | upload 1회만 (capture 보류, OTA 거부) |
| Critical   | ≥ 3.30 V | 즉시 deep sleep |
| Shutdown   | < 3.30 V | EXT1 wake disable + 강제 deep sleep |
| Abnormal   | > 4.30 V 또는 dV/dt > 100 mV/s 강하 | 안전 차단 + telemetry |

### 3.2 충전 중(VBUS 감지) 분기

- 충전 중: 항상 `Sustain` 으로 평탄화. 단 < 3.30 V 면 `Critical` (PSU 출력 부족 등).
- 충전 중 dV/dt 양수는 정상 신호 → abnormal 판정 제외.
- VBUS 감지 회로 부재 시 `isCharging=false` 디폴트 → 보수적 분기.

### 3.3 ADC 스냅샷 발행 시점

- 매 wake 직후 (capture 전)
- 매 capture 직전
- 매 업로드 직전
- OTA 진입 가드 입력값
- BLE provisioning 진입 가드 입력값

### 3.4 dV/dt 계산

- RTC slow-mem 에 직전 스냅샷(`s_prevVoltage`, `s_prevSnapshotEpochSec`) 보존.
- 두 스냅샷 간격 ≥ 1 s 일 때만 평가. 그보다 짧은 간격은 ADC 노이즈 영향 큼.
- 절대 dV ≥ 0.05 V AND |dV/dt| > 100 mV/s 동시 만족 시 Abnormal.
- Critical / Shutdown 진입 직전 `persistSnapshot` 호출하여 다음 wake 가 비교
  기준을 정상 시작하도록.

---

## 4. 부팅 시 보안 invariant (`iconia_boot_check.{h,cpp}`)

### 4.1 검증 항목 + 비트마스크

| 비트 | InvariantBit | 의미 |
|------|--------------|------|
| `0x0001` | kBitProductionBuildMacro    | `ICONIA_PRODUCTION_BUILD == 1` |
| `0x0002` | kBitSecureBootEnabled       | `esp_secure_boot_enabled()` |
| `0x0004` | kBitFlashEncryptionRelease  | RELEASE 모드 flash encryption |
| `0x0008` | kBitJtagDisabled            | eFuse `DIS_PAD_JTAG` |
| `0x0010` | kBitDownloadModeDisabled    | eFuse `DIS_DOWNLOAD_MODE` |
| `0x0020` | kBitFactorySeedValid        | factory_nvs seed 무결성 |
| `0x0040` | kBitSecureVersionOk         | `kSecureVersion >= 1` (anti-rollback) |

PROD 빌드(`kLockdown=true`) 에서만 검증 수행. DEV 빌드는 즉시 pass.

### 4.2 위반 시 동작 흐름

```
boot
 │
 ├─ haltOnPlaceholderSecrets  (기존 가드)
 │
 ├─ boot_check::runAll
 │     │
 │     ├─ pass=true  ─── 정상 boot 진행 (기존 흐름)
 │     │
 │     └─ pass=false ───┐
 │                       │
 │                       ▼
 │                recordPanicLog(violationMask)   // NVS "panic"/"boot_inv"
 │                       │
 │                       ▼
 │                haltForever()
 │                       │
 │                       ├─ esp_sleep_disable_wakeup_source(ALL)
 │                       └─ esp_deep_sleep_start()
 │
 (다음 wake)
       │
       └─ 동일 검사 → 약화된 모드로 절대 도달 불가
```

### 4.3 Telemetry 동봉

`loadPanicLog()` 가 직전 boot 의 violationMask 를 반환. 본 라운드는 다음 성공
업로드에 동봉할 수 있도록 NVS 보존만 활성화 — 서버 multipart 필드 추가는
별도 합의 (`integration-reviewer`). 동봉 시 권장 필드명:

```
boot_invariant_mask         : "0x0024" 같은 4자리 hex (16-bit)
boot_invariant_recorded_ms  : 정수 ms
```

---

## 5. RTC slow-mem 사용 요약

| 변수 | 위치 | 용도 |
|------|------|------|
| `s_replayCache[16]` | iconia_security | replay 8B truncated SHA-256 ring |
| `s_provFailCount` 등 | iconia_security | 본딩 실패 백오프/lockout |
| `s_prevVoltage` 등 | iconia_battery | 부팅 간 dV/dt 비교 |
| `s_stats` (QueueStats) | iconia_upload_queue | 큐 누적 카운터 |

총 사용량 ~256B 미만. RTC slow-mem 8 KB 한계 대비 여유 충분.

---

## 7. OTA 단계별 telemetry + post-boot smoke check + 자동 롤백

본 절의 정본 구현은 `iconia_ota.{h,cpp}`. 매트릭스 셀프 체크는
`iconia_compat.{h,cpp}`. 단계별 record 는 RTC slow-mem 큐(capacity 5)
에 보존되어, 네트워크 단절 시에도 다음 부팅의 첫 업로드 직후에 일괄
flush 가능. 실제 HTTPS POST `/api/v1/devices/:id/ota-status` 의 페이로드
스키마는 server 도메인이 정의 — 본 펌웨어는 record 적재만 책임.

### 7.1 7-단계 stage 라벨

| stage | enum | 발생 시점 | 핵심 필드 |
|------|------|------|------|
| 0 | `manifest_received` | `canEnterOta` 통과 + `performOta` 진입 직후 | deployment_id, target fw_ver, target_secure_version |
| 1 | `downloading` | `esp_https_ota_perform` 청크 루프, 1초 sampling | bytes_done / bytes_total, attempt_no, wifi_rssi, battery_mv |
| 2 | `download_complete` | 자체 SHA-256 mmap 검증 직후 | sha_match (true/false) |
| 3 | `applying` | `esp_https_ota_finish` 직전 (partition swap 직전) | — |
| 4 | `post_boot_health_pending` | 새 펌웨어 첫 부팅 — `running.state == PENDING_VERIFY` 감지 시 | smoke_attempt_no |
| 5 | `post_boot_health_ok` | smoke check 4항목 모두 통과 → `esp_ota_mark_app_valid_cancel_rollback` 호출 후 | smokeAccumMask |
| 6 | `post_boot_health_fail` | smoke check 누적 attempt N 도달 + 일부 항목 누락 → 자동 롤백 트리거 직전 | smokeFailMask (누락 비트) |
| 7 | `rolled_back` | 이전 partition 으로 복귀 후 정상 부팅 → `detectRollbackOnBoot` 가 INVALID/ABORTED 감지 | fwVerThatDied |

추가 보조 emit:
- `manifest_rejected` (stage=0, reason hash 동봉) — `canEnterOta` 의 downgrade /
  sha 형식 / version 형식 거절 시. anti-rollback 매니페스트 위반도 동일 경로.

### 7.2 post-boot smoke check 4항목

| 비트 | SmokeBit | 검사 | 호출 위치 |
|------|----------|------|----------|
| `0x0001` | `kSmokeBitBootInvariant`   | `iconia_boot_check::runAll().pass` | begin() boot_check 직후 |
| `0x0002` | `kSmokeBitFactoryNvs`      | factory seed valid | begin() factory seed 검증 직후 |
| `0x0004` | `kSmokeBitCameraInit`      | 1회 camera init + capture 성공 | runEventFlow() captureImage 직후 |
| `0x0008` | `kSmokeBitWifiHandshake`   | 1회 Wi-Fi 연결 + 서버 200 응답 | runEventFlow() uploadResult.success 직후 |

`finalizeIfPending`:
- 4비트 모두 set → `esp_ota_mark_app_valid_cancel_rollback` + stage 5 emit + smoke 누적 zeroize.
- attempt_no >= `kSmokeMaxAttempts` (3) + 일부 비트 누락 → `esp_ota_mark_app_invalid_rollback_and_reboot` + stage 6 emit + ESP.restart.
- 그 외 (attempt 1~2 + 일부 누락) → 누적 mask 보존 + deep sleep → 다음 wake 가 같은 cycle 재시도.

attempt 한계 3회의 근거:
- 1회로 끊으면 양산 라인 첫 페어링 환경에서 사용자가 Wi-Fi AP 를 켜기 전에 도달한 첫 wake 가 무조건 롤백 → false-positive.
- 무한 허용 시 정상 부팅 안 되는 펌웨어가 영원히 OTA 슬롯 점유.
- 3회 = 사용자 행동 (페어링 후 첫 터치) 의 리트라이 윈도우 + 충분한 하드 컷.

### 7.3 자동 롤백 안전 시퀀스

```
[새 펌웨어 부팅]
  ├─ ota::onBoot()                       // PENDING_VERIFY 감지 + attempt++
  │     └─ telemetry stage 4 (pending)
  ├─ ota::markBootInvariantOk()          // boot_check 통과 시
  ├─ ota::markFactoryOk()                // factory seed 통과 시
  ├─ runEventFlow()
  │     ├─ ota::markCameraInitOk()       // capture 성공 시
  │     └─ ota::markWifiHandshakeOk()    // 200 응답 후
  └─ ota::finalizeIfPending()
        │
        ├─ all-OK   → mark_app_valid + telemetry stage 5  → 이후 일반 boot
        │
        ├─ attempt < 3 + 일부 누락
        │             → 누적 mask 보존 + deep sleep
        │             → 다음 wake 에서 같은 cycle 진입 (s_smokeAttemptNo++)
        │
        └─ attempt >= 3 + 일부 누락
              → telemetry stage 6 (failMask)
              → esp_ota_mark_app_invalid_rollback_and_reboot
              → 부트로더가 이전 partition 의 valid 슬롯 선택
              → ESP.restart
              [이전 partition 부팅]
              ├─ detectRollbackOnBoot() 가 INVALID/ABORTED 감지
              │     └─ recordOtaResult(rolled_back, prevVersion)
              │     └─ ota::onRolledBack(prevVersion)  → telemetry stage 7
              └─ 이후 일반 boot 흐름 — factory_nvs / events_q / replay cache /
                 NVS Wi-Fi 자격증명 모두 그대로 보존 (사용자 데이터 손실 없음).
```

### 7.4 secure_version anti-rollback 정합

본 자동 롤백 시퀀스는 anti-rollback eFuse 를 절대 후퇴시키지 않는다:

- 신규 펌웨어가 `kSecureVersion` 을 +1 하지 않은 빌드 (= 보안 패치 외 일반
  feature 릴리스) 일 때만 롤백 가능. 이전 partition 의 secure_version 이
  현재 burn 된 eFuse 와 같으므로 부트로더가 통과시킴.
- 신규 펌웨어가 `kSecureVersion` 을 +1 한 경우, 부팅 자체에 성공했다는 것은
  이미 eFuse SECURE_VERSION 이 자동 burn (단조 증가) 되었음을 의미.
  이 상태에서 이전 partition 으로 복귀하면 부트로더가 거절 → 부팅 실패.
  → 이 시나리오는 **펌웨어가 절대 발생시키면 안 된다**. 매니페스트 가드:
  - 서버 매니페스트 `target_secure_version` <= 펌웨어 현재 `kSecureVersion`
    → `iconia_compat::checkManifestSecureVersion` false → 거절 (sha mismatch
    경로 동등). `manifest_rejected` telemetry emit.
  - server 측은 cohort 점진 배포 시 secure_version 후퇴 매니페스트를 절대
    발급하지 않는다 (sliding window 롤백 정책에서도).
- 결론: 펌웨어 측 자동 롤백은 "secure_version 동일 펌웨어의 자가점검
  실패" 만 처리. eFuse 는 절대 후퇴 시도 X.

### 7.5 sliding window 롤백 정책과의 정합

server 측 cohort 기반 sliding window 롤백 정책 (1% → 5% → 25% → 100% 같은
점진 배포 + 임계 실패율 도달 시 즉시 stop):

- 펌웨어 stage 6 (`post_boot_health_fail`) 비율이 cohort 임계치 초과 시
  server 가 cohort 진척 stop + 미배포 디바이스에 매니페스트 배포 중지.
- 이미 OTA 받은 디바이스는 펌웨어 자체 자동 롤백이 stage 7 emit → server
  가 deployment_id 별 rolled_back 카운터 누적.
- server 가 별도 "force rollback" 명령 (= 더 낮은 fw_ver 매니페스트 강제
  배포) 을 보낼 때는 secure_version 후퇴 금지 정책 위반이므로 **절대 X**.
  대신 새 hotfix 릴리스 (fw_ver 더 높음, secure_version 같음 또는 +1) 로
  로 forward-roll.

### 7.6 호환성 매트릭스 셀프 체크

`iconia_compat::evaluate(observedServerApiVersion)`:

- 빌드 시점에 `build_profiles/{dev,prod}.h` 에 박힌 `kCompatServerApiMin` /
  `kCompatServerApiMax` 닫힌 구간과 server `health` endpoint 응답의
  `api_version` 정수 비교.
- `Compatible`: 정상 동작.
- `Incompatible`: 이벤트 업로드 보류 + BLE 진단 채널만 활성 (본 라운드는
  진단 char 미추가 — 정의만 동결, §2.5 와 동일).
- `Unknown`: health 응답 미수신 시 fallback. 이전 cycle cached verdict 가
  있으면 그것을 신뢰, 없으면 잠정 Compatible (신규 양산 디바이스의 첫
  health 응답 도달 전 영영 lockout 방지).

server v1 / v2 정합 (현 라운드):
- v1 = legacy `/api/event` 만, ota-status endpoint 없음.
- v2 = ota-status endpoint + cohort 점진 배포 + 매트릭스 동결.

dev 매트릭스: `[1, 3]` (선행 검증 가능 윈도우). prod 매트릭스: `[1, 2]`
(검증 통과한 server 버전까지만). server 가 v3 으로 올라갈 때는 dev
빌드로 통합 검증 후 OTA 라운드에 prod max 를 +1 하여 배포.

### 7.7 manifest 정합 검증 (펌웨어 측)

| 검증 | 위치 | 실패 시 |
|------|------|--------|
| URL prefix `https://` | `canEnterOta::stringStartsWithHttps` | 거절, 시리얼 로그 |
| sha256 64 lower-hex | `canEnterOta::hexStringIsLowerSha256` | 거절, 시리얼 로그 |
| version strict semver | `canEnterOta::parseSemver` | `version_rejected` + `manifest_rejected` telemetry |
| 다운그레이드 차단 | `canEnterOta::compareSemver` | `version_rejected` + `manifest_rejected` telemetry |
| anti-rollback (target_secure_version > 현재) | `iconia_compat::checkManifestSecureVersion` (server 헤더 합의 후 활성) | `manifest_rejected` telemetry |
| 다운로드 sha 일치 | `performOta` 의 mmap + mbedtls_sha256 | `sha_mismatch` enum + `download_complete(false)` telemetry |
| Secure Boot V2 chain | IDF 기본 (`esp_https_ota_finish` 가 검증 실패 시 ESP_ERR_OTA_VALIDATE_FAILED) | `flash_failed` enum |

### 7.8 RTC slow-mem 큐

| 항목 | 위치 | 용량 |
|------|------|------|
| `s_queue[5]` | iconia_ota | 5 × ~32B = 160B |
| `s_smokeAccumMask`, `s_smokeAttemptNo` | iconia_ota | 4B |
| `s_currentDeploymentIdHash` 외 5개 | iconia_ota | 24B |
| `s_cachedVerdict` | iconia_compat | 12B |

총 ~200B. §5 의 기존 사용량과 합산하여 8KB 한계 대비 여유 충분.

---

## 6. 변경 이력

- v1 (2026-05-06): 초안. 본 라운드 신설 — Wi-Fi 백오프 jitter, persistent queue,
  배터리 다단계 임계 + dV/dt 가드, prod boot invariant 검사. 서버 합의가
  필요한 telemetry 필드 추가는 별도 라운드 (`integration-reviewer`).
- v2 (2026-05-06): §7 추가 — OTA 7-stage telemetry, post-boot smoke check 4항목,
  자동 롤백 시퀀스, secure_version anti-rollback 정합, sliding window 롤백
  정책, 호환성 매트릭스 셀프 체크, manifest 정합 검증. 정본 구현은
  `iconia_ota.{h,cpp}` + `iconia_compat.{h,cpp}`. server `/api/v1/devices/:id/ota-status`
  endpoint 페이로드 스키마는 server 도메인이 정의 (라운드 진행 중).
  본 펌웨어는 RTC slow-mem 큐 적재까지만 책임 — 실제 HTTPS POST 전송
  본체는 다음 라운드 server 합의 후 추가.
