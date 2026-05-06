# ICONIA BLE Provisioning — Secure Handshake (정본 v1)

본 문서는 ESP32 펌웨어 / RN 모바일 앱 / 서버 측 페어링 가이드 코드가
공통으로 따라야 하는 **BLE 온보딩 보안 프로토콜**의 정본 스펙이다.
세 도메인 모두 본 문서만으로 자족적으로 정합 구현이 가능해야 한다.

> 적용 범위: ICONIA AI 인형 (성인 한정 IoT 제품). 어린이용 안전 / COPPA
> 조항은 적용 대상이 아님.

---

## 0. 위협 모델

| 위협 | 가정 | 본 프로토콜의 대응 |
|------|------|--------------------|
| BLE 스니퍼(라디오 청취) | 공격자가 페어링 구간 패킷을 모두 캡처 | 자격증명은 항상 AEAD 암호문으로만 송신 |
| MITM (가짜 디바이스/가짜 폰) | 공격자가 페어링 시점 두 endpoint 사이에 끼어듦 | (1) BLE Secure Connections + Numeric Comparison, (2) 디바이스별 factory seed 기반 채널 키 |
| Replay (이전 세션 캡처 재전송) | 공격자가 정상 세션 캡처본을 다시 인형에 보냄 | 매 세션 nonce + 4B unix-like timestamp + RTC 메모리 nonce 캐시 |
| Brute force (잘못된 자격증명 반복 시도) | 분실/도난 인형으로 무차별 시도 | 본딩 실패 카운터 + 점진 백오프 + 12h hard cap |
| 펌웨어 추출 후 키 탈취 | 공격자가 flash dump 시도 | Flash Encryption (AES-XTS-256) + Secure Boot V2 (별도 문서: `production_provisioning.md`) |

---

## 1. 키 자료 (Keying Material)

### 1.1 Factory Seed (PSK)

- 디바이스별 **32바이트 랜덤** 비밀 값.
- 양산 라인에서 HSM 또는 격리된 키 발급 워크스테이션에서 생성.
- **read-only NVS partition** (`factory` 네임스페이스, 라벨 `factory_nvs`)
  안에 `seed`, `pid`(product id), `mfg_date`, `seed_ver` 4개 키로 burn.
- 펌웨어 코드/리포에는 절대 포함하지 않는다. `production_provisioning.md`
  의 "Step 4: Burn factory seed" 절차 준수.
- 동일 seed 가 두 디바이스에 중복 burn 되는 것은 정책 위반 — 제조 측은
  생성 단계에서 중복 검사 (DB / Bloom filter) 수행.

### 1.2 채널 키 유도 (HKDF-SHA256)

```
salt   = 16B     (BLE advertise 시 함께 노출되는 디바이스별 salt; factory_nvs[seed_salt])
ikm    = seed    (factory_nvs[seed], 32B)
info   = "ICONIA-PROV-CH-v1" || device_mac (6B) || session_nonce (16B)
chan_k = HKDF-SHA256(salt, ikm, info)[:32]   // 32바이트 AES-256-GCM 키
```

- `device_mac` 은 BLE peer address (Public, 6B big-endian).
- `session_nonce` 는 디바이스가 세션마다 새로 발생시키는 16B 랜덤값.
- `chan_k` 는 **세션 1회용**. 본 세션이 끝나면(성공/실패/타임아웃 무관)
  RAM에서 즉시 zero-fill.

### 1.3 BLE Bonding LTK

- 본딩 자체는 ESP32 BLE 스택의 LTK (BLE 4.2 Secure Connections)를 사용.
- LTK 와 채널 키는 **분리** 운용 — LTK 만으로 자격증명 복호화는 불가.
  (LTK 가 누설되어도 factory seed 가 있어야 자격증명 평문 획득 가능.)

---

## 2. GATT 프로파일

### 2.1 서비스 UUID

```
Service:  48f1f79e-817d-4105-a96f-4e2d2d6031e0   (legacy 와 동일)
```

### 2.2 특성 (Characteristics)

기존 SSID / Password 평문 특성은 **deprecate**. v1 secure 프로토콜은
다음 4 개 characteristic 만 사용한다.

| 이름 | UUID | Properties | 권한 | 길이 |
|------|------|------------|------|------|
| Status      | `...-6031e3` | READ + NOTIFY  | READ_ENC_MITM | 가변 ASCII |
| Capability  | `...-6031e5` | READ           | READ          | 32B (advertise 외 추가 메타) |
| Session     | `...-6031e6` | READ           | READ_ENC_MITM | 32B (`session_nonce` 16B + `salt` 16B) |
| Credential  | `...-6031e7` | WRITE          | WRITE_ENC_MITM | ≤ 240B (AEAD blob, 청크 가능) |

**삭제(deprecated):**

- `...-6031e1` (legacy SSID plaintext write)
- `...-6031e2` (legacy Password plaintext write)
- `...-6031e4` (legacy nonce read; v1 에서 Session 으로 흡수)

> 펌웨어는 v1 부팅 시 위 두 deprecated 특성을 **GATT 에 등록조차 하지
> 않는다**. RN 앱이 옛 UUID 로 write 하면 GATT_REQ_NOT_SUPPORTED 반환 →
> 앱은 신 UUID 로 마이그레이션 요청.

### 2.3 본딩 강제

- `Credential`, `Session`, `Status` characteristic 의 권한은 모두
  `*_ENC_MITM` (`ESP_GATT_PERM_*_ENC_MITM`).
- 본딩되지 않은 client 가 read/write 시 GATT 스택이 자동으로 Insufficient
  Authentication (`0x05`) 반환 → 페어링 (Numeric Comparison) 시작.
- `setIOCap = ESP_IO_CAP_OUT` (디바이스에 6자리 passkey 디스플레이가 없으므로
  실제로는 `ESP_IO_CAP_NONE`). 자세한 페어링 UX 는 `rn-mobile` 팀과 합의.
- 본딩 성공 후에만 펌웨어가 internal `bonded_=true` 플래그를 set.
  Credential write callback 진입 시 `bonded_==false` 면 즉시 reject
  (에러 0x01 응답 noti).

---

## 3. AEAD 봉투 (Credential Envelope)

### 3.1 평문 (Plaintext, P)

```
P = ssid_len  (1B, 1 ≤ ssid_len ≤ 32)
  | ssid      (ssid_len B,  ASCII 또는 UTF-8)
  | psk_len   (1B, 0 ≤ psk_len ≤ 63)
  | psk       (psk_len B,   ASCII 또는 UTF-8)
  | reserved  (8B,          앱은 0x00 채움; 펌웨어는 무시)
```

- WPA2-PSK 64자 hex 그대로 보내는 경우도 동일 범위. WPA Enterprise 미지원.

### 3.2 봉투 (Envelope, E)

송신 단위 (RN → 디바이스, **단일 GATT write 또는 청크**):

```
E = magic        (4B, ASCII "ICN1")
  | version      (1B, 0x01)
  | flags        (1B, bit0=last_chunk, bit1..7=reserved 0)
  | seq          (2B, big-endian, 청크 일련번호; 1부터 시작)
  | ts_unix_be   (4B, big-endian, 앱 측 epoch sec, UTC)
  | gcm_iv       (12B, 채널 키 첫 사용 시 랜덤; 청크간 동일)
  | ct_len_be    (2B, big-endian, ciphertext + tag 합계 바이트)
  | ct           (ct_len B, AES-256-GCM ciphertext)
  | tag          (16B, AES-256-GCM auth tag, ct 의 tail 16B 가 아니라 별도)
```

> 청크가 필요한 경우 (BLE MTU 23 기본; 협상 후 ATT_MTU 확장) seq=1..N
> 으로 분할. 마지막 청크는 `flags.bit0=1`. 펌웨어는 `last_chunk` 받기 전까지
> 누적 버퍼에 append, 누적 길이 > `ICONIA_MAX_CRED_BLOB`(=512B) 면 즉시 abort.

### 3.3 AEAD 파라미터

```
algorithm     = AES-256-GCM
key           = chan_k                      (HKDF 결과, §1.2)
iv (nonce)    = E.gcm_iv                    (12B, 청크별 동일)
aad           = "ICONIA-PROV-AAD-v1"
              | device_mac          (6B)
              | E.version           (1B)
              | session_nonce       (16B, Session char 가 발행한 값)
              | E.ts_unix_be        (4B)
plaintext     = P                           (§3.1)
ciphertext    = AES-256-GCM-Enc(key, iv, aad, P)
tag           = 16B
```

- AAD 에 `session_nonce` 를 넣음으로써 동일한 세션 안에서만 ciphertext
  유효 — 다른 세션에서 캡처한 봉투 재전송 (replay) 시 GCM 인증 실패.
- `ts_unix_be` 도 AAD 포함 — 시계 약간 어긋나도 무결성은 보장, 단
  ±10 분 윈도우 검사는 §4 에서 별도 수행.

---

## 4. 검증 규칙 (펌웨어 측)

`Credential` characteristic write 수신 후 펌웨어는 다음을 순서대로 수행.
하나라도 실패하면 **Status notify** 로 에러 코드 보내고 RAM 누적 버퍼 zero-fill,
이번 세션 종료 (BLE 라디오 유지, 카운터 §5 증가).

| 단계 | 검사 | 실패 시 코드 |
|------|------|--------------|
| 1 | `bonded_==true` (LTK 검증된 client) | `0x01 ERR_NOT_BONDED` |
| 2 | `magic == "ICN1"` && `version == 0x01` | `0x02 ERR_BAD_MAGIC` |
| 3 | `seq` 단조 증가 (1..N), 누적 길이 ≤ 512B | `0x03 ERR_BAD_SEQ` |
| 4 | `last_chunk` 받기 전 timeout 30s 미만 | `0x04 ERR_CHUNK_TIMEOUT` |
| 5 | `\|ts_unix - device_now\| ≤ 600` (10 분) — `device_now` 는 RTC 가 없으므로 BLE 광고 시작 시점부터 millis() 기준 단조 카운터 + ts 첫 값으로 동기 | `0x05 ERR_TS_OUT_OF_WINDOW` |
| 6 | `(session_nonce, ts_unix)` 페어가 RTC slow-mem replay cache 에 없음 | `0x06 ERR_REPLAY` |
| 7 | AES-256-GCM 검증 통과 (tag 일치) | `0x07 ERR_AEAD_FAIL` |
| 8 | `ssid_len` ∈ [1, 32], `psk_len` ∈ [0, 63] | `0x08 ERR_BAD_PLAINTEXT` |
| 9 | 디코드된 SSID/PSK 로 Wi-Fi 연결 시도 (3회 재시도) — 성공 시 0x00 SUCCESS | `0x09 ERR_WIFI_AUTH_FAIL`, `0x0A ERR_WIFI_NO_AP` |

검증 통과 후에만 자격증명을 NVS (`iconia` 네임스페이스, `wifi_ssid`/`wifi_pw`)
에 저장 → `0x00 SUCCESS` notify → BLE 라디오 OFF (§7) → deep sleep.

---

## 5. Replay / Brute-force 방어

### 5.1 Per-session replay cache

- 펌웨어는 RTC slow-mem 에 **최근 16 세션의 `(session_nonce, ts_unix)`
  hash** 를 8B truncated SHA-256 으로 keep. 부팅 간 보존.
- Step 6 에서 일치하는 entry 가 있으면 즉시 reject.

### 5.2 본딩 실패 카운터 (RTC slow-mem)

- 키: `prov_fail_cnt` (uint16), `prov_fail_first_ms` (uint64, 첫 실패 시 RTC ms)
- "본딩 실패" 정의: ESP-IDF `ESP_GAP_BLE_AUTH_CMPL_EVT` 이벤트의 `success==false`,
  또는 §4 의 1~9 단계 중 하나라도 실패.
- 매 실패 후 다음 본딩 시도까지 **점진 백오프**:

| 누적 실패 | 다음 시도까지 지연 |
|-----------|-----|
| 1 | 1 s |
| 2 | 4 s |
| 3 | 16 s |
| 4 | 60 s |
| 5+ | 60 s (cap) |

- 12시간 윈도우 누적 실패 ≥ 20 회 → 펌웨어가 **`prov_lockout` flag 를 RTC slow-mem 에
  set 하고 즉시 deep sleep**. 다음 wake 시 lockout flag 가 살아있고 12h 미만 경과면
  BLE 광고 자체를 시작하지 않는다 (Status 통지도 없음). 12h 경과 후 lockout 자동 해제.
- 정상 본딩 + Wi-Fi 검증 성공 → 카운터/타임스탬프/lockout 모두 zero-fill.

---

## 6. 메시지 시퀀스 (정상 흐름)

```
┌─ App (RN) ─┐                                    ┌─ Doll (ESP32) ─┐
              ◀─── BLE adv: name=ICONIA-XXXX ──────
              (서비스 UUID, ManufacturerData=PID)
   user tap "pair"
              ─── connect ───────────────────────▶
              ◀── insufficient authentication ────  (Status read 시도 시)
              ── Pair Request (SC, MITM=1) ──────▶
              ◀─── Numeric Comparison value ──────
   user confirm 6-digit
              ── Pairing OK / LTK 교환 ────────────
                                                   bonded_ = true
              ── Read Session(32B) ──────────────▶
              ◀── session_nonce(16) + salt(16) ───
   chan_k = HKDF(seed, salt, info)
   *주의*: 앱이 seed 를 갖고 있어야 한다.
   v1 에서는 OOB 채널(QR 코드 또는
   서버 발급)로 앱이 seed 를 미리 받아둠.
   상세는 rn-mobile 합의 문서.
              ── Write Credential (E, chunk1..N) ▶
                                                   §4 1~9 검증
                                                   Wi-Fi 연결
              ◀── Status notify "0x00 SUCCESS" ───
              ◀── disconnect ─────────────────────
                                                   §7 종료 → deep sleep
```

---

## 7. 프로비저닝 모드 종료

다음 조건이 모두 충족되면 펌웨어는 BLE 라디오를 끄고 GATT 서비스를
unregister 후 deep sleep.

1. `bonded_ == true`
2. §4 의 모든 단계 통과 후 자격증명 NVS 저장 성공
3. 자격증명으로 Wi-Fi 연결 1회 성공 (NVS 에 저장된 자격증명이 실제로 통하는지 검증)

부팅 시 `wifi_ssid` 가 NVS 에 존재하면 BLE 자체를 시작하지 않는다 (기존
`iconia_app.cpp` 흐름 유지). 즉 본 secure 모드는 첫 1회 또는 reprovision
명령 수신 시에만 활성화.

---

## 8. 에러 코드 (Status notify payload)

`Status` characteristic 의 notify payload 는 ASCII 한 줄, 형식:

```
"0x{code_hex}:{label}"
```

| code | label | 설명 |
|------|-------|------|
| 0x00 | success | 자격증명 검증 + Wi-Fi 연결 성공 |
| 0x01 | not_bonded | 본딩 안 된 클라이언트 write |
| 0x02 | bad_magic | magic/version 불일치 |
| 0x03 | bad_seq | seq 단조성 위반/길이 초과 |
| 0x04 | chunk_timeout | last_chunk 30s 내 미수신 |
| 0x05 | ts_window | timestamp 윈도우 ±10 분 초과 |
| 0x06 | replay | nonce/ts 페어가 cache 에 존재 |
| 0x07 | aead_fail | AES-GCM 인증 실패 |
| 0x08 | bad_plaintext | ssid/psk 길이 위반 |
| 0x09 | wifi_auth_fail | Wi-Fi 비밀번호 불일치 |
| 0x0A | wifi_no_ap | Wi-Fi AP 발견 실패 |
| 0xFE | locked_out | 12h hard cap 도달, 라디오 강제 종료 |
| 0xFF | timeout | 2분 광고 윈도우 만료 |

---

## 9. 호환성 / 마이그레이션

- 본 v1 은 **Hard cut-over**. 출시 전 모든 양산 디바이스는 secure-mode-only
  펌웨어로 출하. legacy 평문 GATT 경로는 코드에서 제거.
- 시판 후 발견된 인증 문제로 secure 비활성화가 불가피한 경우, OTA 로 secure 빌드
  플래그를 끄는 대신, **OTA 자체를 거부하고 RMA**. 보안 다운그레이드는 정책상 금지.

---

## 10. 참고 구현 위치 (ESP32 측)

- `iconia_security.{h,cpp}`: HKDF / AES-GCM / RTC 카운터 / replay cache.
- `iconia_app.cpp::startProvisioningBle`: GATT 등록 + 권한 설정.
- `iconia_app.cpp::CredentialCallbacks::onWrite`: §3, §4 처리.
- `partitions.csv`: `factory_nvs` (RO) 추가.
- `production_provisioning.md`: factory seed burn 절차.

---

## 12. 서버 등록 클레임 (App 중계)

본 절은 §6 의 BLE 자격증명 봉투와 **별개의 채널** 인 "서버 디바이스 등록"
경로의 정합 규약이다. App 이 BLE 페어링 성공 직후 서버에 디바이스 소유권을
요청할 때 사용된다. v1 본 라운드부터 정본의 일부로 흡수.

### 12.1 메시지 구성

```
message  = device_id || "|" || nonce || "|" || ts || "|" || owner_claim
hmac_hex = HMAC-SHA256(factory_seed, message)   // hex, lower-case 64 chars
```

- `device_id`   : 정규화된 MAC `AA:BB:CC:DD:EE:FF` (대문자, 콜론 구분).
- `nonce`       : ASCII 16..128 자. base64 또는 hex 권장. 5분 TTL 안에서 1회.
- `ts`          : Unix epoch **seconds** (정수). ms 단위는 서버가 자동 변환.
- `owner_claim` : 사용자 식별자(보통 user_id). 빈 문자열 허용 (사전 등록 단계).
- `factory_seed`: §1.1 의 32B factory seed. 펌웨어가 BLE 측 봉투 키 유도와
  **동일한 비밀**을 본 HMAC 의 키로 재사용 — 서버는 §1.1 양산 등록 단계에서
  KEK 로 ciphertext + pepper-hash 쌍을 보관하고 검증 시 복호화 후 비교.

### 12.2 시간/재전송 정책

- ts skew      : ±90 초 (서버 권장). HW 정본의 BLE 측 ±10분 (§4 step 5) 와는 다름 —
  **본 절의 HMAC 검증은 BLE 채널 외부**이므로 서버 시계 기준이 더 엄격.
- nonce TTL    : 5 분. 서버 측 in-process replay cache 또는 Redis 로 보관.
- replay key   : `device_id || "|" || nonce`. 같은 페어가 TTL 안에 재도착 시 거절.

### 12.3 HW 측 책임

- 펌웨어는 본 HMAC 자체를 발급하지 않을 수도 있다 — 정본 v1 BLE 흐름은 §6 까지
  (provisioning_success notify) 만 다룬다. App 측이 BLE 페어링 성공 직후
  factory seed (OOB 채널로 미리 입수) + nonce/ts/owner_claim 으로 직접 HMAC 산출
  하여 서버 `/api/v1/devices/pair` 에 첨부하는 모델이 v1 의 정합 흐름.
- 향후 (v2 후보) 펌웨어가 직접 BLE 측 별도 char 로 본 HMAC blob 을 발급하는
  경로를 도입할 경우 §2.2 에 새 characteristic 을 추가한다 (UUID 미정).

### 12.4 서버 측 매핑

서버 코드 매핑은 `Server/docs/security_handshake_server.md` §3 (실패 코드) 와
`Server/src/services/provisioningService.js::buildHmacMessage` 의 `${deviceId}|${nonce}|${ts}|${ownerClaim}` 가
본 §12.1 정의와 1:1 일치해야 한다. 어긋나면 **등록 자체가 절대 성공하지
못한다** — 출시 차단.

---

## 13. 변경 이력

- v1.1 (2026-05-06): §12 서버 등록 클레임 흡수 (기존 단방향 BLE 정본 → BLE+서버
  통합 정본). §2.2 에 deprecated 평문 char e1/e2 명시 보강.
- v1   (2026-05-06): 초안. legacy 평문 GATT deprecate.
