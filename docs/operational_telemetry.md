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

## 6. 변경 이력

- v1 (2026-05-06): 초안. 본 라운드 신설 — Wi-Fi 백오프 jitter, persistent queue,
  배터리 다단계 임계 + dV/dt 가드, prod boot invariant 검사. 서버 합의가
  필요한 telemetry 필드 추가는 별도 라운드 (`integration-reviewer`).
