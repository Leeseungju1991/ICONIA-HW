# ICONIA 양산 프로비저닝 절차 (정본 v1)

본 문서는 ICONIA AI 인형(성인 한정 IoT 제품)의 ESP32 펌웨어를 **출시
가능한 양산 디바이스**로 만들기 위해 양산 라인이 수행해야 하는 모든
순서를 정의한다. 보안 잠금 (Secure Boot V2, Flash Encryption, JTAG
disable, factory seed burn) 은 모두 **양산 라인에서만** 수행되며,
한 번 burn 된 eFuse 는 절대 되돌릴 수 없다.

> 적용 대상: 출시용 RELEASE 펌웨어 (`./build.sh prod`).
> DEV 빌드 (`./build.sh dev`) 는 본 문서의 eFuse burn 단계를 수행하지
> 않는다 — 디버깅 가능 상태 유지.

---

## 0. 책임 분담

| 단계 | 수행자 | 장비 |
|------|--------|------|
| 키 생성 | 보안 책임자 1인 | HSM 또는 air-gap 워크스테이션 |
| 키 보관 | 보안 책임자 + 백업 보관자 | HSM, 오프라인 USB (분리 보관) |
| 제조 라인 burn | 위탁 제조사(EMS) | 자체 fixture + esptool.py |
| 검증 | 위탁 제조사 QA | shielded box + 시리얼 + 광 검사 |

---

## 1. 사전 준비 — 키 페어 생성 (1회)

### 1.1 Secure Boot V2 서명 키

ESP32-WROOM-32 (classic) 기준 — Secure Boot V2 는 **RSA-3072 PSS**
서명 사용 (ESP-IDF 5.x 지원). ECDSA-P256 은 ESP32-S3/C3/C6 에서만 가능.

> **칩셋 확인:** 본 펌웨어의 현재 타겟은 `esp32:esp32:esp32cam` =
> **ESP32-WROOM-32 (ESP32 classic)**. Flash Encryption AES-XTS-256 은
> ESP32-S3/C3 전용. ESP32 classic 에서는 **AES-256 (XTS 아님, ESP32 의
> "Flash Encryption" 모드) 또는 AES-128** 이 한계. 본 문서는 두 칩셋을
> 모두 지원하도록 분기 표기한다.

```bash
# 1회만 수행. HSM 사용 권장. 워크스테이션은 air-gap.
espsecure.py generate_signing_key --version 2 \
    --scheme rsa3072 secure_boot_signing_key.pem
# (S3/C3 옵션) ECDSA-P256:
# espsecure.py generate_signing_key --version 2 \
#     --scheme ecdsa256 secure_boot_signing_key.pem

# 공개키 다이제스트 추출 (eFuse 에 burn 할 값)
espsecure.py extract_public_key --version 2 \
    --keyfile secure_boot_signing_key.pem secure_boot_pubkey.pem
```

**보관 정책:**
- `secure_boot_signing_key.pem` 은 절대 리포 / CI / 일반 워크스테이션에
  두지 않는다.
- HSM 사용 시: `pkcs11` 슬롯에 import, 서명 시 `espsecure.py
  --keyfile-pkcs11-uri` 사용.
- HSM 미사용 시: AES-256 암호화된 USB 2개에 분리 보관 (보안 책임자 +
  백업 보관자), 각 USB 의 마운트 패스프레이즈는 서로 다른 사람이 보유.
- 키 회전: 출시 후 유출 의심 사건 발생 시 새 키 생성 → 새 펌웨어 빌드 →
  OTA 배포 → 모든 디바이스가 새 키로 검증되는 첫 부팅 성공 후 구 키 폐기.
  Secure Boot V2 는 eFuse 에 **공개키 다이제스트 슬롯 3개** 가 있어 키
  회전 가능 (자세한 ESP-IDF 가이드 참조).

### 1.2 Flash Encryption 키

- ESP32 (classic): **AES-256-bit Flash Encryption key** 1개. 첫 부팅 자동
  생성을 권장 (`CONFIG_SECURE_FLASH_ENC_ENABLED + RELEASE`). 키는 eFuse
  내부에서만 살고 외부로 노출 안 됨.
- ESP32-S3/C3: AES-XTS-256 (또는 AES-XTS-128) 자동 생성 가능.
- 수동 생성/주입은 권장하지 않음 — 키 관리 표면이 늘어남.

### 1.3 OTA 서명 키

Secure Boot V2 와 **동일한 키**를 OTA 펌웨어 서명에도 사용. 별도 키 분리는
ESP-IDF `esp_https_ota` 의 자체 검증과 호환되지 않으므로 운영 단순화 위해
하나로 통합.

### 1.4 Factory seed pool 생성

디바이스별 32B 랜덤 시드 N 개 (양산 lot 크기) 를 사전 생성. CSV 형식:

```
device_serial,seed_hex(64),seed_salt_hex(32),seed_ver
ICN-2026-000001,b3c4...e7,0a91...c2,1
ICN-2026-000002,...
```

- 생성: HSM 또는 air-gap 워크스테이션에서 `os.urandom(32)`.
- 중복 검사: SQLite UNIQUE constraint 또는 Bloom filter 로 lot 내/lot 간
  중복 0 확인.
- 보관: AES-256-GCM 으로 암호화 후 DB 보관. 운영 종료 시 backup 1년 유지
  후 폐기 (RMA 시 디바이스별 seed 재발급 정책 별도 합의).
- 라인으로 전송: production fixture PC 에 lot 단위 (~1000건) 만 노출,
  burn 후 fixture 측 메모리에서 zero-fill.

---

## 2. 펌웨어 빌드 (PROD 프로파일)

### 2.1 빌드 명령

```bash
cd "ICONIA Firmware"
./build.sh prod
# Windows:
build.bat prod
```

`./build.sh prod` 는 다음을 자동 수행:

1. `build_profiles/prod.h` → `build_opt.h` 복사.
2. `arduino-cli compile --fqbn esp32:esp32:esp32cam` (또는 `esp32:esp32:esp32s3`).
3. **빌드 완료 후 서명되지 않은 raw `.bin` 만 산출.**
4. 후속 단계 (서명, 암호화) 는 본 절차 §3 에서 수동 수행 — 키가 빌드
   환경에 노출되지 않도록 의도적으로 분리.

빌드 산출물 위치:
```
build/esp32.esp32.esp32cam/ICONIA_Firmware.ino.bin
```

### 2.2 PROD 프로파일이 강제하는 보안 플래그

`build_profiles/prod.h` 가 다음을 모두 정의:

```
ICONIA_PRODUCTION_BUILD=1     // 시리얼 로그 OFF
ICONIA_BLE_SECURE=1           // legacy 평문 BLE 경로 컴파일조차 안 됨
ICONIA_REQUIRE_FACTORY_SEED=1 // factory_nvs[seed] 부재 시 부팅 거부
ICONIA_LOCKDOWN=1             // anti-rollback / OTA 서명 검증 강제
```

DEV 프로파일에는 위 매크로가 모두 미정의 → 디버깅 가능.

---

## 3. 라인 burn 절차 (디바이스 1대당)

> 각 단계는 fixture PC 의 `provision.py` 스크립트가 자동 수행하되,
> 검증 단계는 QA 가 수동 확인.

### Step 1: 빈 ESP32 모듈 검수

```bash
esptool.py --chip esp32 --port COMx flash_id
esptool.py --chip esp32 --port COMx read_efuse_summary
```

기대값:
- Chip type: ESP32-D0WD-V3 (또는 PICO-D4 등 발주한 SKU 와 일치)
- `FLASH_CRYPT_CNT == 0` (암호화 미적용)
- `SECURE_BOOT_EN == 0`

### Step 2: 펌웨어 + partition table flash (서명/암호화 전)

```bash
esptool.py --chip esp32 --port COMx --baud 921600 write_flash \
    0x1000  bootloader.bin \
    0x8000  partitions.bin \
    0x10000 ICONIA_Firmware.ino.bin
```

> 이 시점은 **plaintext flash**. 다음 step 의 secure boot enable 직전까지만
> 유효한 임시 상태.

### Step 3: Secure Boot V2 활성화 + 공개키 burn

```bash
# 공개키 다이제스트 burn (BLOCK_KEY0 ~ KEY2 중 첫 빈 슬롯)
espefuse.py --chip esp32 --port COMx burn_key_digest \
    --keyfile secure_boot_pubkey.pem

# Secure Boot V2 enable bit
espefuse.py --chip esp32 --port COMx burn_efuse SECURE_BOOT_EN 1
```

> 이 시점부터 서명되지 않은 부트로더로 부팅 불가.

### Step 4: Flash Encryption 활성화 (RELEASE 모드)

```bash
# RELEASE: FLASH_CRYPT_CNT 가 hard-cap (0xF) 까지 burn 되도록 강제 →
# 추후 plaintext flash 자체가 불가능하도록 잠금.
espefuse.py --chip esp32 --port COMx burn_efuse FLASH_CRYPT_CNT 0xF

# 첫 부팅 시 부트로더가 자체적으로 flash 영역을 자동 암호화 (key 는 eFuse
# 내부에서 자동 생성). 이후 모든 OTA 는 signed + encrypted 가 강제됨.
```

### Step 5: JTAG / UART download mode 비활성화 (RELEASE)

```bash
# JTAG 비활성 (분실/도난 시 디버그 인터페이스 통한 dump 차단)
espefuse.py --chip esp32 --port COMx burn_efuse JTAG_DISABLE 1
# 또는 ESP32-S3:
# espefuse.py --chip esp32s3 --port COMx burn_efuse DIS_PAD_JTAG 1
# espefuse.py --chip esp32s3 --port COMx burn_efuse DIS_USB_JTAG 1

# UART download 모드 비활성 (RELEASE 한정). burn 후 esptool 의 모든 flash
# 명령이 거부됨 — RMA 시 모듈 단위 교체 정책 필수.
espefuse.py --chip esp32 --port COMx burn_efuse \
    UART_DOWNLOAD_DIS 1
# ESP32-S3: DIS_DOWNLOAD_MODE
```

> ⚠️ Step 5 는 절대 되돌릴 수 없다. 양산 fixture 가 Step 1~4 의 검증을 통과한
> 디바이스에 한해서만 수행할 것.

### Step 6: factory_nvs 시드 burn

```bash
# 사전 생성된 lot CSV 에서 다음 시리얼 행을 pop.
python provision.py burn_seed \
    --port COMx \
    --serial ICN-2026-000001
```

`provision.py` 내부:

1. CSV 에서 `seed_hex`, `seed_salt_hex`, `seed_ver` 추출.
2. `nvs_partition_gen.py` 로 다음 키-값을 가진 NVS partition image 생성:
   - 네임스페이스: `factory`
   - keys: `seed` (32B BLOB), `seed_salt` (16B BLOB), `pid` (string, "ICONIA-V1"),
     `mfg_date` (string, "YYYY-MM-DD"), `seed_ver` (uint8, 1)
3. `factory_nvs` partition (offset = `partitions.csv` 의 entry) 위치에
   `esptool.py write_flash` (이 시점은 이미 flash encryption 이 활성이므로
   esptool 의 `--encrypt` 옵션 사용).
4. fixture 메모리에서 seed 재료 zero-fill.

### Step 7: anti-rollback 보안 버전 burn

```bash
# secure_version 은 펌웨어 빌드 시 build_opt.h 의 ICONIA_SECURE_VERSION
# 으로 박혀있고, 부팅 시 esp_efuse_check_secure_version 이 검증.
# eFuse 측 secure_version 은 펌웨어가 첫 부팅에서 자동 burn (단조 증가).
# 본 step 은 라인에서 별도 명령 없이 그냥 첫 부팅을 트리거하면 자동 처리됨.
echo "[INFO] secure_version is self-burned by firmware on first boot"
```

### Step 8: 부팅 검증 (QA)

1. fixture power-on → 시리얼 OFF (PRODUCTION_BUILD=1).
2. **광 검사**: 인형 외피 부착 후 BLE 광고 (`ICONIA-XXXX`) 가 nRF Connect 등으로 보이는지.
3. **Numeric Comparison 페어링**: QA 휴대폰에서 페어링 → 6-digit 일치 → 본딩 성공.
4. **Status notify**: QA 앱에서 dummy credential blob (테스트용 고정 SSID/PW) 주입 → `0x00 success` 수신.
5. **deep sleep 전류**: shielded box 내 전류계 (µA 분해능) 로 ≤ 30 µA 측정.
6. **터치 wake**: 좌/우 터치 패드 자극 → wake → 시리얼 미출력 + 카메라 셔터 사운드 (LED 신호 음소거 모드) 확인.
7. 위 6 항목 모두 통과 → fixture 측 DB 에 시리얼 + lot + burn 시각 + QA 사인 기록.

---

## 4. RMA / 폐기 정책

- Step 5 이후는 디버깅 인터페이스 부재 → RMA 는 **모듈 교체** (보드 단위).
- 폐기 시: factory seed 가 burn 된 모듈은 분쇄 또는 특수 폐기. 단순 박스
  포장 후 일반 e-waste 로 보내지 말 것 (eFuse 추출 risk).

---

## 5. 양산 라인 추가 장비 / 키 보관 요구

| 항목 | 세부 |
|------|------|
| HSM | YubiHSM 2 또는 동급 (Secure Boot 키 보관 + 서명) |
| Air-gap 워크스테이션 | 키 생성 / lot CSV 생성 전용. 네트워크 NIC 물리 제거 권장. |
| Production fixture | esp32 USB-UART 어댑터 + 자동화 PC + 광검사 카메라 + shielded box (전류 측정) |
| AES-256 USB 2개 | Secure Boot 비공개 키 백업 (분리 보관) |
| Lot CSV DB | SQLite + 디스크 암호화. 백업 1년 보존, 기간 만료 후 폐기. |
| 시리얼 라벨 인쇄기 | factory_nvs 의 `mfg_date`, 디바이스 시리얼 매핑 출력 |
| QA 휴대폰 (2대) | iOS/Android 각 1대. RN 페어링 앱 (테스트 빌드) 설치. |
| 전류계 (µA) | Joulescope JS220 또는 동급. shielded box 내장. |

### 키 보관 정책 요약

1. **Secure Boot 비공개 키**: HSM. 백업은 AES-USB 2개 분리 보관. 워크스테이션
   하드디스크에 절대 평문 저장 금지.
2. **Factory seed pool**: 생성 즉시 AES-256-GCM 암호화 후 DB. 마스터 키는
   HSM. 라인으로 lot 단위 (~1000건) 만 일시 export, burn 후 fixture 측에서
   zero-fill.
3. **API key (서버 발급)**: 운영 secrets manager 에서만. `prod.h` 의
   `PROD_API_KEY_PLACEHOLDER` 자리는 빌드 시점에만 치환되고, 빌드 산출물
   (`build_opt.h`) 은 .gitignore 대상.
4. **OTA 서명 키**: Secure Boot 키와 동일. 회전 시 §1.1 의 ESP-IDF 키
   회전 가이드 적용.

---

## 6. PROD 도메인 / API key placeholder 치환 (양산 빌드 직전 필수)

`build_profiles/prod.h` 의 두 매크로는 양산 빌드 직전 실값으로 교체:

| 토큰 | 위치 | 교체 방법 |
|------|------|-----------|
| `ICONIA_PROD_DOMAIN_PLACEHOLDER` | `prod.h` line 33 | `sed -i` 또는 EAS secret 또는 `envsubst` |
| `PROD_API_KEY_PLACEHOLDER` | `prod.h` line 34 | 운영 secrets manager 발급값 — 절대 git commit 금지 |

치환 누락 시 firmware-ci 의 **`placeholder-guard` job 이 main merge / release tag 단계에서 자동 차단**한다 (검사 토큰: 위 2종 + `__FILL_ME__` / `placeholder` / `changeme` / `your-domain-here`). 양산 라인 운영자가 한 번이라도 빠뜨리면 100% 출하 실패하던 구조 → CI 가 사전 적출.

---

## 7. 변경 이력

- v1 (2026-05-06): 초안. ESP32 classic + S3 분기 표기.
- v1.1 (2026-05-06): §6 PROD placeholder 치환 체크리스트 + firmware-ci `placeholder-guard` 게이트 추가.
