# Build Profiles

`build.sh dev` / `build.bat prod` 1 줄로 산출 .bin 을 분리하기 위한 매크로 정본 폴더입니다. 이 폴더의 파일이 정본이며, 빌드 스크립트가 선택된 프로파일을 sketch 폴더의 `build_opt.h` 로 복사합니다. `build_opt.h` 는 git ignore 입니다.

## 매크로 일람

| 매크로 | 의미 | dev | prod |
|---|---|---|---|
| `ICONIA_API_ENDPOINT` | 서버 multipart POST URL | `https://iconia.onrender.com/api/event` | `https://api.iconia.ICONIA_PROD_DOMAIN_PLACEHOLDER/api/event` *(교체 필요)* |
| `ICONIA_API_KEY` | `X-API-Key` 헤더 값 | `DEV_API_KEY_PLACEHOLDER` *(교체 필요)* | `PROD_API_KEY_PLACEHOLDER` *(교체 필요)* |
| `ICONIA_FIRMWARE_VERSION` | 서버에 보고되는 버전 문자열 | `1.0.0-dev` | `1.0.0` |
| `ICONIA_SERVER_ROOT_CA_PEM` | 서버 TLS 검증용 root CA bundle | ISRG Root X1 + Amazon Root CA 1 | ISRG Root X1 + Amazon Root CA 1 |
| `ICONIA_S3_ROOT_CA_PEM` | OTA 펌웨어 다운로드 root CA | Server CA 와 동일 bundle | Server CA 와 동일 bundle |
| `ICONIA_OTA_DEBUG` | OTA 디버그 verbosity | `1` | `0` |
| `ICONIA_CERT_FP_SHA1` | leaf 인증서 SHA-1 핀닝 | (미정의) | (미정의 — 운영 시 결정) |
| `ICONIA_ALLOW_INSECURE_TLS` | TLS 검증 비활성 (bring-up only) | (미정의) | **절대 정의 금지** |
| `ICONIA_ALLOW_INSECURE_OTA` | OTA root CA 부재 시 setInsecure 폴백 | (미정의) | **절대 정의 금지** |
| `ICONIA_BLE_SECURE` | BLE 본딩 + AEAD secure 핸드셰이크 강제 (정본: docs/security_handshake.md) | `1` | `1` *(필수)* |
| `ICONIA_PRODUCTION_BUILD` | 시리얼 로그 OFF | (미정의 — bring-up) | `1` *(필수)* |
| `ICONIA_REQUIRE_FACTORY_SEED` | factory_nvs seed 부재 시 부팅 거부 | `0` (bring-up 모듈 허용) | `1` *(필수)* |
| `ICONIA_LOCKDOWN` | anti-rollback / Insecure 폴백 차단 통합 가드 | (미정의) | `1` *(필수)* |
| `ICONIA_SECURE_VERSION` | 펌웨어 보안 버전 (eFuse 단조 증가) | (미정의 = 1) | `1` *(보안 패치 시 +1)* |

## CA PEM 처리 정책

dev/prod 양쪽 모두 **ISRG Root X1 + Amazon Root CA 1 두 개를 cert chain bundle 형태**로 박았습니다.
- ISRG Root X1: Render(Let's Encrypt) leaf 검증
- Amazon Root CA 1: AWS ACM / S3 leaf 검증
- 둘을 concat 한 PEM 은 ESP32 `WiFiClientSecure::setCACert` 가 모두 신뢰함
- dev 가 prod 의 CA 를, prod 가 dev 의 CA 를 추가로 신뢰해도 보안상 무해 — 운영자 작업 부담을 줄이기 위해 동일 bundle 사용

추후 R2 leaf 가 ISRG/Amazon 외 발급자(예: Google Trust Services)로 변경되면 해당 root CA PEM 을 `ICONIA_S3_ROOT_CA_PEM` 에 append 하세요.

## 첫 빌드 전 체크리스트

### dev
1. `build_profiles/dev.h` 열기
2. `ICONIA_API_KEY` 의 `DEV_API_KEY_PLACEHOLDER` 를 실제 dev API key 로 교체
3. (선택) `ICONIA_API_ENDPOINT` 가 현재 dev 서버 호스트 (`iconia.onrender.com`) 와 일치하는지 확인

### prod
1. `build_profiles/prod.h` 열기
2. `ICONIA_API_ENDPOINT` 의 `ICONIA_PROD_DOMAIN_PLACEHOLDER` 를 실제 운영 도메인으로 교체
   - 예: `https://api.iconia.example-corp.com/api/event`
3. `ICONIA_API_KEY` 의 `PROD_API_KEY_PLACEHOLDER` 를 실제 운영 API key 로 교체
4. 보안 잠금 매크로 5종은 prod.h 에 이미 정의되어 있고 `build.sh prod` /
   `build.bat prod` 가 컴파일 전 자체 검증한다. 임의로 주석 처리하면 빌드 거부.
5. 양산 라인 절차: `HW/docs/production_provisioning.md` §3 참조 (Secure Boot
   서명, Flash Encryption, JTAG/UART download disable, factory seed burn).

## placeholder 와 부팅 가드의 관계

`iconia_app.cpp::haltOnPlaceholderSecrets()` 는 다음 sentinel 값만 거부합니다:
- API Key: `"REPLACE_WITH_API_KEY"`, `"CHANGE_ME_LONG_RANDOM_DEVICE_KEY"`
- Endpoint: `"https://api.example.com/api/event"`
- Firmware version: `"0.0.0-placeholder"`

`DEV_API_KEY_PLACEHOLDER` / `PROD_API_KEY_PLACEHOLDER` 는 위 sentinel 과 다른 값이라 **부팅 가드를 통과합니다**. 그러나 실제 서버는 이 키로 보낸 요청에 401 을 반환할 것이므로, **운영/스테이징 빌드 전에 반드시 실값으로 교체**하세요.

## 새 프로파일 추가하기

예를 들어 `staging` 환경을 추가하려면:
1. `build_profiles/staging.h` 작성 (dev.h 복사 후 값 변경)
2. `./build.sh staging` 또는 `build.bat staging` 으로 빌드
3. 별도 스크립트 수정 불필요 — 스크립트는 `build_profiles/<arg>.h` 를 동적으로 찾음
