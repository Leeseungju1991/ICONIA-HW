# ICONIA Firmware (ESP32)

ICONIA AI 인형(ESP32 기반 IoT 제품, **성인 사용자 한정**)의 펌웨어 리포지토리입니다.
본 리포는 **양산 펌웨어**와 **부품 단위 검수용 sketch** 두 종을 명확히 분리해 보관합니다.

> 본 제품은 성인 한정 사용자 대상입니다. 어린이용 장난감 안전 기준 / COPPA 등은 적용 대상이 아닙니다.

---

## 폴더 구조

| 폴더 | 역할 | 수정 정책 |
|---|---|---|
| **`ICONIA Firmware/`** | **프로덕션 펌웨어.** 실제 인형에 플래시되는 단일 Arduino 스케치. 터치 wakeup → 배터리 측정 → 카메라 캡처 → HTTPS multipart 업로드 → BLE 프로비저닝 → Deep Sleep 의 전 시퀀스를 담당. | 변경은 회귀 시험과 명세 리뷰를 거쳐야 함 |
| **`ICONIA Firmware Unit/`** | **부품 단위 검수용 Arduino sketch 모음.** 신규 보드 입고 / 부품 교체 / 핀맵 변경 시 페리페럴이 정상인지 빠르게 확인하는 도구. 7종 sketch (터치 / 카메라 / 배터리 ADC / Wi-Fi / BLE / Deep Sleep / LED). | 검수 절차에 맞게 자유롭게 추가·수정 가능 |

두 폴더의 모든 핀 번호 / GATT UUID / NVS 키는 **동일하게 유지**됩니다. 단위 테스트는 프로덕션 핀맵을 그대로 사용해야 검수 의미가 있기 때문입니다.

---

## 하드웨어 구성

`ICONIA Firmware/iconia_config.h` 에 정의된 실제 상수값 기준입니다.

### MCU / 카메라
- ESP32-WROOM-32 (Arduino-ESP32 core 3.x, ESP-IDF 5.x 기반)
- OV2640 — AI Thinker ESP32-CAM 핀맵
- 외부 PSRAM 권장 (없어도 동작은 가능)

### 핀 배정

| 기능 | GPIO | 비고 |
|---|---|---|
| 터치 (오른쪽) | 13 | RTC GPIO, EXT1 wakeup, active HIGH |
| 터치 (왼쪽) | 14 | RTC GPIO, EXT1 wakeup, active HIGH |
| 배터리 ADC | 33 | ADC1 ch.5, 분압비 2.0, ADC_11db |
| 상태 LED | 4 | |
| 카메라 PWDN | 32 | Deep Sleep 중 RTC hold(HIGH) |
| 카메라 XCLK | 0 | 20 MHz |
| 카메라 SCCB SDA / SCL | 26 / 27 | |
| 카메라 D0~D7 | 5, 18, 19, 21, 36, 39, 34, 35 | |
| 카메라 VSYNC / HREF / PCLK | 25 / 23 / 22 | |

### 배터리 / 캡처 파라미터
- 분압 후 ADC1 채널에서 16회 오버샘플 평균
- 만충 4.20 V → 0% 임계 3.30 V (선형 매핑)
- 5% 미만이면 촬영·전송 생략 후 즉시 Deep Sleep 복귀
- 캡처 해상도: VGA / JPEG quality 12 (PSRAM 없으면 quality 14)

### BLE GATT 서비스 (V1 secure handshake)
- 서비스 UUID `48f1f79e-817d-4105-a96f-4e2d2d6031e0`
  - `...e3` Status — Notify / Read (READ_ENC_MITM)
  - `...e5` Capability — Read (no auth, 32B 메타)
  - `...e6` Session — Read (READ_ENC_MITM, 16B nonce + 16B salt)
  - `...e7` Credential — Write (WRITE_ENC_MITM, AES-256-GCM AEAD blob)
- 본딩: `ESP_LE_AUTH_REQ_SC_MITM_BOND` 강제. legacy `...e1`/`...e2` 평문 SSID/PW
  특성은 secure 빌드에서 **GATT 등록조차 하지 않는다**.
- 정본 스펙: [`docs/security_handshake.md`](./docs/security_handshake.md)

### NVS 네임스페이스
- `iconia` 네임스페이스: `wifi_ssid`, `wifi_pw`, OTA 보고 페어 등
- `factory` 네임스페이스 (RO at runtime): `seed`(32B), `seed_salt`(16B),
  `pid`, `mfg_date`, `seed_ver`. 양산 라인에서만 burn — 정본 절차:
  [`docs/production_provisioning.md`](./docs/production_provisioning.md)
- 자격증명은 BLE secure handshake 로만 주입 (소스 / 커밋 금지)

### 출시 잠금 빌드 (`./build.sh prod`)
- Secure Boot V2 + Flash Encryption + JTAG/UART download disable + anti-rollback
  + factory seed 가드를 **모두** 강제. 미달 빌드는 prod 매크로 정합성 검사에서
  거부 (`build.sh` 가 자체 차단).
- prod 빌드 산출물은 unsigned — 양산 라인 fixture 가 sign + eFuse burn 별도 수행
  (서명 키 빌드 환경 노출 방지).

---

## 동작 시퀀스 (프로덕션 펌웨어 기준)

### 부팅 직후
1. CPU 클럭을 80 MHz 로 낮춰 초기 전류 절감
2. Task Watchdog 30 s 등록
3. 빌드 시 주입된 API Key·엔드포인트가 placeholder 인지 검사 → 검출 시 영구 Deep Sleep
4. NVS(`iconia`)에서 Wi-Fi 자격증명 로드

### Wi-Fi 자격증명 부재 시 — BLE 프로비저닝
1. `ICONIA-XXXX` (XXXX = MAC 마지막 4자리) 광고 시작, 인터벌 1280 ~ 2560 ms
2. SSID + Password 둘 다 수신되면 Wi-Fi 연결 시도
3. 성공 시 NVS 저장 → Status `provisioning_success` → Deep Sleep
4. 2분 동안 자격증명 미수신 시 Status `timeout` → Deep Sleep
5. Status 키워드: `advertising`, `connected`, `wifi_connecting`, `wifi_failed`, `nvs_save_failed`, `invalid_credentials`, `provisioning_success`, `timeout`

### 평상시 — 터치 → 촬영 → 업로드
1. Deep Sleep 대기 (EXT1 mask: GPIO 13 / 14, ANY_HIGH)
2. 터치로 wakeup → wakeup status 비트로 좌·우 결정
3. 2 s 소프트웨어 디바운스
4. 배터리 ADC 16회 평균. 5% 미만이면 종료
5. PWDN LOW → OV2640 init → 워밍업 1프레임 폐기 → 캡처
6. CPU 240 MHz 승격, Wi-Fi STA 연결 (최대 15 s, 모뎀 슬립)
7. HTTPS POST `/api/event` (multipart/form-data)
8. 응답 헤더/바디의 `X-ICONIA-Command: enter_provisioning` 검사
9. Wi-Fi / 카메라 정리 → Deep Sleep
   - 명령이 있었으면 NVS 자격증명 삭제 후 BLE 프로비저닝 진입

### Deep Sleep 진입 정리
- Wi-Fi `disconnect → stop → deinit`
- BLE Bluedroid disable + controller deinit + `ESP_BT_MODE_BTDM` 메모리 회수
- 카메라 PWDN 핀 RTC hold(HIGH) — 슬립 중 누설 차단
- `esp_sleep_config_gpio_isolate()` 로 wakeup 핀 외 모든 GPIO 격리
- RTC peripherals / RTC SLOW·FAST MEM 도메인 OFF

### 재시도·실패 정책
- Wi-Fi 연결: 3회, 회당 800 ms 대기
- 업로드: 3회, 회당 1 s 대기
- **전송 실패 시 로컬 저장 없이 포기** — 사용자 음성 / 이미지 데이터 잔존 방지

---

## 서버로 보내는 페이로드

`POST <kApiEndpoint>` (HTTPS, `Content-Type: multipart/form-data`)

| 헤더 | 값 |
|---|---|
| `X-API-Key` | 빌드 시 주입된 키 |
| `User-Agent` | `ICONIA-ESP32/1.0` |
| `Connection` | `close` |

| 폼 필드 | 값 |
|---|---|
| `touch` | `"left"` 또는 `"right"` |
| `device_id` | MAC 주소 `XX:XX:XX:XX:XX:XX` |
| `battery` | 0~100 정수 |
| `image` | JPEG 바이너리 (`event.jpg`, `image/jpeg`) |

서버 응답에 `X-ICONIA-Command: enter_provisioning` 이 포함되면 펌웨어는 NVS 자격증명을 삭제하고 즉시 BLE 프로비저닝 모드로 재진입합니다.

---

## 빌드 / 플래시 (Arduino IDE 2.x)

### 1. 보드 설정
- Boards Manager → **esp32 by Espressif** core 3.x 설치
- Board: **ESP32 Dev Module**
- Partition Scheme: **Huge APP** (BLE + 카메라 동시 포함)
- PSRAM: **Enabled** (있을 경우)
- Upload Speed: 921600 / Serial Monitor baud: **115200**

### 2. 라이브러리
ESP32 core 3.x 에 내장된 헤더만 사용합니다. 외부 라이브러리 불필요.
- `WiFi.h`, `WiFiClientSecure.h`, `Preferences.h`, `BLEDevice.h`
- `esp_camera.h`, `esp_sleep.h`, `esp_task_wdt.h`, `driver/rtc_io.h`

### 3. Build Profiles (dev / prod 분리)

매크로 정본은 `ICONIA Firmware/build_profiles/dev.h` 와 `prod.h` 입니다. 빌드 스크립트가 선택된 프로파일을 sketch 폴더의 **`build_opt.h`** 로 복사하면, Arduino-ESP32 코어가 이를 컴파일러 추가 플래그로 자동 인식합니다. `build_opt.h` 는 `.gitignore` 대상이며 커밋되지 않습니다.

#### dev / prod 차이

| 항목 | dev | prod |
|---|---|---|
| `ICONIA_API_ENDPOINT` | `https://iconia.onrender.com/api/event` | `https://api.iconia.ICONIA_PROD_DOMAIN_PLACEHOLDER/api/event` *(교체 필요)* |
| `ICONIA_API_KEY` | `DEV_API_KEY_PLACEHOLDER` *(교체 필요)* | `PROD_API_KEY_PLACEHOLDER` *(교체 필요)* |
| `ICONIA_FIRMWARE_VERSION` | `1.0.0-dev` | `1.0.0` |
| 스토리지 (서버 측) | Cloudflare R2 | AWS S3 |
| `ICONIA_OTA_DEBUG` | `1` | `0` |
| Server / S3 root CA | ISRG Root X1 + Amazon Root CA 1 bundle | 동일 bundle |

#### 사용법

```bash
# Linux / macOS / Git Bash
./build.sh dev
./build.sh prod

# Windows cmd
build.bat dev
build.bat prod
```

스크립트는 두 단계로 동작합니다.
1. `build_profiles/<profile>.h` → `build_opt.h` 복사
2. arduino-cli 가 PATH 에 있으면 `arduino-cli compile --fqbn esp32:esp32:esp32cam` 실행. 없으면 Step 1 만 수행하고 종료(Arduino IDE GUI 사용자 대응).

#### Arduino IDE GUI 절차

arduino-cli 미설치 환경에서는 다음 흐름으로 사용:
1. `build.bat dev` (또는 `./build.sh dev`) 1 회 실행 → `build_opt.h` 생성
2. Arduino IDE 2.x 에서 `ICONIA_Firmware.ino` 열고 Upload — `build_opt.h` 는 IDE 가 자동 include

#### 첫 빌드 전 사용자가 채워야 할 값

| 파일 | 필수 교체 |
|---|---|
| `build_profiles/dev.h` | `DEV_API_KEY_PLACEHOLDER` → 실제 dev API key |
| `build_profiles/prod.h` | `ICONIA_PROD_DOMAIN_PLACEHOLDER` → 운영 도메인, `PROD_API_KEY_PLACEHOLDER` → 실제 운영 API key |

CA PEM 은 dev/prod 양쪽에 ISRG Root X1 + Amazon Root CA 1 bundle 이 이미 박혀 있어 추가 작업 불필요. R2 leaf 가 이 두 CA 외 발급자(예: Google Trust Services)로 변경되면 해당 CA 를 `ICONIA_S3_ROOT_CA_PEM` 에 append.

자세한 매크로 일람과 placeholder/부팅 가드 관계는 [`ICONIA Firmware/build_profiles/README.md`](./ICONIA%20Firmware/build_profiles/README.md) 참조.

### 4. 선택 빌드 플래그 (build_profiles 안에서 정의)

| 매크로 | 의미 |
|---|---|
| `-DICONIA_PRODUCTION_BUILD=1` | Serial 로그 OFF (출하용). prod 출하 직전 활성 검토 |
| `-DICONIA_BLE_SECURE=1` | BLE Just Works + MITM 본딩 + 16바이트 nonce 적용 |
| `-DICONIA_ALLOW_INSECURE_TLS=1` | bring-up 전용. 운영 사용 금지 |

### 5. 보안 권장사항
- 운영 빌드에서 `kServerRootCaPem` 에 실제 root CA PEM 을 박거나 NVS 로 주입
- `setInsecure()` 사용 금지 (`ICONIA_ALLOW_INSECURE_TLS` OFF 유지)
- API Key 는 펌웨어 바이너리에 평문 상수로 들어가므로 공장 플래시 단계에서 디바이스별 고유 키로 주입

---

## 단위 테스트 (`ICONIA Firmware Unit/`) 사용 가이드

`ICONIA Firmware Unit/` 의 7개 sketch 는 프로덕션 핀맵·UUID 를 그대로 쓰는 검수용 도구입니다. 다음 시점에 활용합니다.

| 시점 | 활용 sketch |
|---|---|
| 신규 보드 입고 sanity check | `07_LED_Test` → `03_BatteryADC_Test` → `01_TouchWakeup_Test` |
| 안테나 / RF 부품 교체 후 | `04_WiFi_Test`, `05_BLE_Test` |
| 카메라 모듈 교체 후 | `02_Camera_Test` |
| 슬립 전류 회귀 측정 | `06_DeepSleep_Test` (멀티미터 동시 사용) |
| 핀맵 변경 검토 시 | 영향 받는 단계만 선택 빌드 |

상세 합격 기준과 Arduino IDE 설정은 [`ICONIA Firmware Unit/README.md`](./ICONIA%20Firmware%20Unit/README.md) 참조.

---

## 펌웨어 책임 범위

펌웨어는 다음만 담당합니다.

- BLE 프로비저닝 + NVS 저장
- EXT1 터치 wakeup 처리
- 배터리 ADC 측정
- OV2640 JPEG 캡처
- HTTPS multipart 업로드 (재시도 3회)
- 서버 명령 `enter_provisioning` 해석
- Deep Sleep 복귀

이미지 영구 저장, Vision 분석, AI 응답 생성, 사용자 계정 관리 등은 모두 서버·AI·앱 도메인의 책임이며, 펌웨어는 전송 후 즉시 자원을 정리하고 슬립으로 복귀합니다.

---

## 라이선스 / 주의

- 본 제품은 **성인 한정** 사용자 대상 IoT 제품입니다. 어린이 / 청소년 사용을 가정한 안전·개인정보 기준은 적용 대상이 아닙니다.
- 카메라가 탑재된 IoT 제품의 특성상, 운영 단계에서 KC / FCC / RoHS 등 무선·전자제품 인증을 별도로 진행해야 합니다.
- API Key, 서버 인증서, NVS 에 저장된 사용자 자격증명은 **절대 커밋하지 않습니다**. 모든 비밀값은 `build_opt.h` 또는 공장 플래시 절차로 주입합니다.
