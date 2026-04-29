# ICONIA Firmware Unit Tests

ICONIA 본체에 들어가는 ESP32 보드의 **부품·드라이버 단위 검수용** Arduino sketch 모음입니다.
프로덕션 펌웨어(`../ICONIA Firmware/`)를 통째로 플래시하기 전에, **각 페리페럴이 제대로 붙었는지 빠르게 확인**하는 용도로 사용합니다.

> 본 폴더의 sketch 들은 프로덕션 동작을 흉내 내지 않습니다.
> 실제 동작 시퀀스(터치 wakeup → 카메라 → 업로드 → 슬립)는 `../ICONIA Firmware/` 만 담당합니다.

---

## 사용 시점

- 신규 PCB / 신규 배치(batch) 입고 시 수입 검수
- 카메라 / 터치 / 안테나 등 부품 교체 후 회귀 시험
- 핀맵 변경 검토 시 동작 가능성 확인
- 양산 라인의 1차 펑션 테스트 fixture 베이스

## 폴더 구조

| sketch | 검증 대상 | 핵심 핀/리소스 |
|---|---|---|
| `01_TouchWakeup_Test/` | 좌/우 터치 IC + EXT1 wakeup | GPIO 13(R) / 14(L) |
| `02_Camera_Test/` | OV2640 init + JPEG 캡처 | AI Thinker pinout, PWDN 32 |
| `03_BatteryADC_Test/` | 배터리 분압 + ADC1 + 캘리브레이션 | GPIO 33, ADC_11db |
| `04_WiFi_Test/` | STA 연결 / IP / RSSI | (Wi-Fi only) |
| `05_BLE_Test/` | 프로덕션과 동일 UUID GATT echo | (BLE only) |
| `06_DeepSleep_Test/` | Deep Sleep ↔ EXT1 wakeup 사이클 | GPIO 13/14, RTC mem |
| `07_LED_Test/` | 상태 LED blink sanity | GPIO 4 |

각 sketch 는 자체 완결되어 있어 해당 폴더만 Arduino IDE 로 열면 바로 빌드·플래시할 수 있습니다.

## 권장 플래시 순서

전원·기본 GPIO 부터 통신·복합 동작 순으로 점검합니다.

1. `07_LED_Test` — 보드 살아 있는지 가장 먼저 확인
2. `03_BatteryADC_Test` — 전원 측정이 가능해야 이후 단계가 의미 있음
3. `01_TouchWakeup_Test` — 입력 sanity
4. `04_WiFi_Test` — 안테나 / RF 프론트엔드
5. `05_BLE_Test` — RF 두 번째 채널
6. `02_Camera_Test` — 가장 까다로운 페리페럴
7. `06_DeepSleep_Test` — 위 단계들 모두 통과한 뒤 슬립 전류 측정

## 합격 기준 요약

| sketch | 합격 기준 (Serial 로그) |
|---|---|
| 01 | 손 터치 시 `TOUCH DETECTED: RIGHT/LEFT (HIGH)` 출력, 5초 무입력 시 슬립 후 재 wakeup |
| 02 | `[CAM] init OK` + 매 3초 `frame captured: <bytes>` 가 8~30 KB 부근 |
| 03 | 만충 4.10~4.20 V / 90~100% 부근, raw 값 진동 ±10 LSB 이내 |
| 04 | 15초 안에 `[WIFI] connected`, IP/RSSI 출력 |
| 05 | nRF Connect 등에서 `ICONIA-XXXX` 광고 관측, write → status notify echo |
| 06 | `count` 가 wakeup 마다 +1, `cause = EXT1` 와 깨운 핀이 명시됨 |
| 07 | LED 가 GPIO4 에서 1 Hz 토글 |

## Arduino IDE 설정 (전 sketch 공통)

- **Boards Manager** → `esp32 by Espressif` core 3.x 설치
- **Board:** `ESP32 Dev Module` (또는 사용 중인 모듈)
- **CPU Frequency:** 240 MHz
- **Flash Size:** 4 MB
- **Partition Scheme:** `Huge APP (3MB No OTA / 1MB SPIFFS)` — 카메라/BLE 동시 적재
- **PSRAM:** `Enabled` (02_Camera 용)
- **Upload Speed:** 921600
- **Serial Monitor baud:** **115200**

추가 외부 라이브러리는 필요 없습니다. ESP32 core 가 모든 헤더(`esp_camera.h`, `BLEDevice.h`, `WiFi.h`, `driver/rtc_io.h`, `esp_adc_cal.h`)를 포함합니다.

## 비밀값 / 자격증명 취급

- `04_WiFi_Test` 의 SSID / Password 는 **검수용 더미 라우터** 에서만 사용하십시오.
  검수 종료 후 sketch 를 placeholder(`YOUR_SSID_HERE`)로 되돌려 커밋합니다.
- 운영 펌웨어는 BLE 프로비저닝으로 NVS 에 자격증명을 받으며, 본 단위 테스트는 그 흐름을 검증하지 않습니다(05 는 echo 만 수행).
