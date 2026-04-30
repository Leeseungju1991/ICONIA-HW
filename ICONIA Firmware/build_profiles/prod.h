// =============================================================================
// ICONIA Firmware — PROD build profile
// =============================================================================
// 이 파일은 build.sh / build.bat 가 build_opt.h 로 복사한다.
// build_opt.h 는 .gitignore 대상이며, 본 파일이 매크로 정본이다.
//
// 적용 환경:
//   - 서버 엔드포인트: https://api.iconia.<사내> (AWS ACM 발급 인증서)
//   - 스토리지: AWS S3
//   - 펌웨어 버전: 정식 semver (suffix 없음)
//   - OTA 디버그 로그 OFF (시리얼 노이즈 최소화, 정보 노출 최소화)
//
// 사용법:
//   ./build.sh prod         (Linux/Mac/Git Bash)
//   build.bat prod          (Windows cmd)
//
// 첫 빌드 전 필수 작업:
//   1) ICONIA_API_ENDPOINT 의 <사내> 부분을 실제 운영 도메인으로 교체
//      예: "https://api.iconia.example-corp.com/api/event"
//   2) ICONIA_API_KEY 의 PROD_API_KEY_PLACEHOLDER 를 실제 운영 API key로 교체
//      (운영 secrets manager 에서 발급, 절대 Git 커밋 금지)
//   3) (선택) ICONIA_CERT_FP_SHA1 핀닝 활성화 — leaf 인증서 SHA-1 fingerprint
//   4) 운영 빌드는 반드시 ICONIA_PRODUCTION_BUILD=1 도 같이 정의해 시리얼 로그
//      차단을 검토하라. 기본값은 시리얼 ON (bring-up 호환).
// =============================================================================

#pragma once

// -----------------------------------------------------------------------------
// 서버 엔드포인트 / 인증
// -----------------------------------------------------------------------------
// TODO(prod): <사내> 자리를 실제 운영 도메인으로 교체할 것.
#define ICONIA_API_ENDPOINT "https://api.iconia.<사내>/api/event"
#define ICONIA_API_KEY      "PROD_API_KEY_PLACEHOLDER"

// -----------------------------------------------------------------------------
// 펌웨어 버전 (서버에 매 요청마다 firmware_version 필드로 보고)
// -----------------------------------------------------------------------------
#define ICONIA_FIRMWARE_VERSION "1.0.0"

// -----------------------------------------------------------------------------
// Server root CA bundle
// 운영 서버는 AWS ACM 발급 인증서 사용 (Amazon Trust Services 체인).
// dev 와의 파일 구조 대칭성 유지를 위해 동일하게 ISRG Root X1 + Amazon Root CA 1
// bundle 을 박는다. ACM 인증서는 Amazon Root CA 1 으로 체이닝되며, ISRG 가
// 추가로 신뢰돼도 운영상 무해하다.
// -----------------------------------------------------------------------------
#define ICONIA_SERVER_ROOT_CA_PEM \
"-----BEGIN CERTIFICATE-----\n" \
"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\n" \
"-----END CERTIFICATE-----\n" \
"-----BEGIN CERTIFICATE-----\n" \
"MIIDQTCCAimgAwIBAgITBmyfz5m/jAo54vB4ikPmljZbyjANBgkqhkiG9w0BAQsF\n" \
"ADA5MQswCQYDVQQGEwJVUzEPMA0GA1UEChMGQW1hem9uMRkwFwYDVQQDExBBbWF6\n" \
"b24gUm9vdCBDQSAxMB4XDTE1MDUyNjAwMDAwMFoXDTM4MDExNzAwMDAwMFowOTEL\n" \
"MAkGA1UEBhMCVVMxDzANBgNVBAoTBkFtYXpvbjEZMBcGA1UEAxMQQW1hem9uIFJv\n" \
"b3QgQ0EgMTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBALJ4gHHKeNXj\n" \
"ca9HgFB0fW7Y14h29Jlo91ghYPl0hAEvrAIthtOgQ3pOsqTQNroBvo3bSMgHFzZM\n" \
"9O6II8c+6zf1tRn4SWiw3te5djgdYZ6k/oI2peVKVuRF4fn9tBb6dNqcmzU5L/qw\n" \
"IFAGbHrQgLKm+a/sRxmPUDgH3KKHOVj4utWp+UhnMJbulHheb4mjUcAwhmahRWa6\n" \
"VOujw5H5SNz/0egwLX0tdHA114gk957EWW67c4cX8jJGKLhD+rcdqsq08p8kDi1L\n" \
"93FcXmn/6pUCyziKrlA4b9v7LWIbxcceVOF34GfID5yHI9Y/QCB/IIDEgEw+OyQm\n" \
"jgSubJrIqg0CAwEAAaNCMEAwDwYDVR0TAQH/BAUwAwEB/zAOBgNVHQ8BAf8EBAMC\n" \
"AYYwHQYDVR0OBBYEFIQYzIU07LwMlJQuCFmcx7IQTgoIMA0GCSqGSIb3DQEBCwUA\n" \
"A4IBAQCY8jdaQZChGsV2USggNiMOruYou6r4lK5IpDB/G/wkjUu0yKGX9rbxenDI\n" \
"U5PMCCjjmCXPI6T53iHTfIUJrU6adTrCC2qJeHZERxhlbI1Bjjt/msv0tadQ1wUs\n" \
"N+gDS63pYaACbvXy8MWy7Vu33PqUXHeeE6V/Uq2V8viTO96LXFvKWlJbYK8U90vv\n" \
"o/ufQJVtMVT8QtPHRh8jrdkPSHCa2XV4cdFyQzR1bldZwgJcJmApzyMZFo6IQ6XU\n" \
"5MsI+yMRQ+hDKXJioaldXgjUkK642M4UwtBV8ob2xJNDd2ZhwLnoQdeXeGADbkpy\n" \
"rqXRfboQnoZsG4q5WTP468SQvvG5\n" \
"-----END CERTIFICATE-----\n"

// -----------------------------------------------------------------------------
// S3 root CA — 운영은 AWS S3 (Amazon Trust Services). Server CA bundle 과
// 동일 PEM 사용. ACM 인증서 회전 시 Amazon Root CA 가 다른 root (예: ISRG)로
// cross-sign 되더라도 본 bundle 에 ISRG 가 이미 포함돼 무중단.
// -----------------------------------------------------------------------------
#define ICONIA_S3_ROOT_CA_PEM ICONIA_SERVER_ROOT_CA_PEM

// -----------------------------------------------------------------------------
// 옵션 매크로 (prod 기본값)
// -----------------------------------------------------------------------------
// 운영은 OTA 디버그 로그 OFF.
#define ICONIA_OTA_DEBUG 0

// 다음 매크로들은 prod 에서 의도적으로 미정의 — iconia_config.h 의 #else 분기로
// 안전 기본값 적용:
//   ICONIA_CERT_FP_SHA1        : 미정의 (운영 시 leaf SHA-1 결정 후 활성화 검토)
//   ICONIA_ALLOW_INSECURE_TLS  : 절대 정의 금지 (TLS 검증 항상 ON)
//   ICONIA_ALLOW_INSECURE_OTA  : 절대 정의 금지 (OTA root CA 부재 시 차단)
//   ICONIA_BLE_SECURE          : 운영 시 1 로 활성 검토 (앱 호환 합의 후)
//   ICONIA_PRODUCTION_BUILD    : 운영 시 1 로 활성 검토 (시리얼 로그 OFF)
//
// 운영 출하 직전에 다음 두 매크로 추가 정의를 권장:
//   #define ICONIA_PRODUCTION_BUILD 1
//   #define ICONIA_BLE_SECURE       1
