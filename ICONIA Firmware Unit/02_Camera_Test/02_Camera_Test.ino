// =============================================================================
// 02_Camera_Test
// -----------------------------------------------------------------------------
// 목적:
//   OV2640 카메라 모듈이 AI Thinker ESP32-CAM 핀맵으로 정상 init 되는지,
//   PWDN(GPIO32) 게이팅이 제대로 동작하는지, JPEG 1프레임 캡처에 성공하는지
//   확인합니다.
//
//   핀맵은 프로덕션 펌웨어(`ICONIA Firmware/iconia_config.h`)와 동일합니다.
//
// 합격 기준:
//   1) "[CAM] init OK" 출력
//   2) 매 3초마다 "[CAM] frame captured: <byte>" 가 0이 아닌 크기로 출력
//      (VGA + quality 12 기준 보통 8~30 KB 사이)
//   3) Serial 에 init failure 0x... 메시지가 나오면 핀맵 / 전원 / PSRAM 점검
// =============================================================================

#include <Arduino.h>
#include "esp_camera.h"
#include "driver/rtc_io.h"

// AI Thinker pinout — iconia_config.h 와 동일
#define PWDN_GPIO_NUM     32
#define RESET_GPIO_NUM    -1
#define XCLK_GPIO_NUM      0
#define SIOD_GPIO_NUM     26
#define SIOC_GPIO_NUM     27
#define Y9_GPIO_NUM       35
#define Y8_GPIO_NUM       34
#define Y7_GPIO_NUM       39
#define Y6_GPIO_NUM       36
#define Y5_GPIO_NUM       21
#define Y4_GPIO_NUM       19
#define Y3_GPIO_NUM       18
#define Y2_GPIO_NUM        5
#define VSYNC_GPIO_NUM    25
#define HREF_GPIO_NUM     23
#define PCLK_GPIO_NUM     22

bool initCamera() {
  // Deep Sleep 직후 PWDN 이 RTC hold(HIGH)일 수 있으므로 해제하고 LOW 로 내림
  rtc_gpio_hold_dis((gpio_num_t)PWDN_GPIO_NUM);
  pinMode(PWDN_GPIO_NUM, OUTPUT);
  digitalWrite(PWDN_GPIO_NUM, LOW);
  delay(10);

  camera_config_t config = {};
  config.ledc_channel = LEDC_CHANNEL_0;
  config.ledc_timer = LEDC_TIMER_0;
  config.pin_d0 = Y2_GPIO_NUM;
  config.pin_d1 = Y3_GPIO_NUM;
  config.pin_d2 = Y4_GPIO_NUM;
  config.pin_d3 = Y5_GPIO_NUM;
  config.pin_d4 = Y6_GPIO_NUM;
  config.pin_d5 = Y7_GPIO_NUM;
  config.pin_d6 = Y8_GPIO_NUM;
  config.pin_d7 = Y9_GPIO_NUM;
  config.pin_xclk = XCLK_GPIO_NUM;
  config.pin_pclk = PCLK_GPIO_NUM;
  config.pin_vsync = VSYNC_GPIO_NUM;
  config.pin_href = HREF_GPIO_NUM;
  config.pin_sccb_sda = SIOD_GPIO_NUM;
  config.pin_sccb_scl = SIOC_GPIO_NUM;
  config.pin_pwdn = PWDN_GPIO_NUM;
  config.pin_reset = RESET_GPIO_NUM;
  config.xclk_freq_hz = 20000000;
  config.pixel_format = PIXFORMAT_JPEG;
  config.frame_size = FRAMESIZE_VGA;
  config.jpeg_quality = 12;
  config.fb_count = 1;
  config.fb_location = psramFound() ? CAMERA_FB_IN_PSRAM : CAMERA_FB_IN_DRAM;
  config.grab_mode = CAMERA_GRAB_LATEST;

  esp_err_t err = esp_camera_init(&config);
  if (err != ESP_OK) {
    Serial.printf("[CAM] init failure 0x%x\n", err);
    return false;
  }
  Serial.println("[CAM] init OK");
  Serial.printf("[CAM] PSRAM = %s\n", psramFound() ? "yes" : "no");
  return true;
}

void setup() {
  Serial.begin(115200);
  delay(200);
  Serial.println();
  Serial.println("=== 02_Camera_Test ===");

  if (!initCamera()) {
    Serial.println("[CAM] init 실패 — 핀맵 / 전원 / PSRAM 확인 필요");
    return;
  }

  // 워밍업 프레임 1장 폐기 (AGC/AWB 안정화)
  camera_fb_t* warm = esp_camera_fb_get();
  if (warm) {
    Serial.printf("[CAM] warmup frame: %u bytes (폐기)\n", (unsigned)warm->len);
    esp_camera_fb_return(warm);
  }
}

void loop() {
  camera_fb_t* fb = esp_camera_fb_get();
  if (!fb) {
    Serial.println("[CAM] fb_get FAILED");
  } else {
    Serial.printf("[CAM] frame captured: %u bytes (%dx%d)\n",
                  (unsigned)fb->len, fb->width, fb->height);
    esp_camera_fb_return(fb);
  }
  delay(3000);
}
