// ICONIA Firmware entry point.
//
// 빌드 시 주의:
// - Tools > Partition Scheme: 동봉된 sketch 폴더의 partitions.csv를
//   사용해야 OTA 듀얼 슬롯이 활성화된다. Arduino IDE 2.x는 sketch 폴더의
//   partitions.csv를 자동 인식한다(Custom 옵션 또는 board의 custom 메뉴).
//   기본 "Huge APP"으로 빌드하면 OTA 진입 시점에 esp_ota_get_next_update_partition
//   가 nullptr을 반환하므로 OTA가 실패한다.
// - Board: ESP32 Dev Module (또는 AI Thinker ESP32-CAM)
// - Flash Size: 4MB (32Mb)
// - PSRAM: Enabled (ESP32-CAM 모듈 권장)
//
// 빌드 시점 매크로(build_opt.h 권장):
//   -DICONIA_API_ENDPOINT="\"https://...\""
//   -DICONIA_API_KEY="\"<32+ chars>\""
//   -DICONIA_FIRMWARE_VERSION="\"1.0.0\""
//   -DICONIA_S3_ROOT_CA_PEM="\"-----BEGIN CERTIFICATE-----\\n...\""
//   (선택) -DICONIA_CERT_FP_SHA1="\"AA:BB:...\""
//   (선택) -DICONIA_PRODUCTION_BUILD=1
//
// 매크로가 빠지면 부팅 시점 가드(haltOnPlaceholderSecrets)가 디바이스를
// 영구 deep sleep으로 보낸다.

#include "iconia_app.h"

static IconiaApp gIconiaApp;

void setup() {
  gIconiaApp.begin();
}

void loop() {
  gIconiaApp.loop();
}
