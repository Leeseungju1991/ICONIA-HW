<!--
ICONIA HW 펌웨어 PR 템플릿.
보안 잠금 / 핸드셰이크 정합이 깨지면 4개 리포 (HW/Server/AI/App) 가 동시 영향.
체크리스트는 머지 전 모두 확인할 것.
-->

## 변경 요약

<!-- 1~3줄. 무엇을, 왜. -->

## 영향 범위

- [ ] dev 빌드만 (bring-up / 디버그)
- [ ] prod 빌드 영향 (서명·eFuse 정합 검토 필요)
- [ ] BLE 핸드셰이크 또는 factory seed 변경
- [ ] 다른 리포 (Server / AI / App) PR 동시 필요

## 체크리스트 (모두 통과해야 머지)

- [ ] `docs/security_handshake.md` 변경 시 Server / AI / App 리포의 짝 PR 을 동시 검토했다 (혹은 변경 없음).
- [ ] `arduino-cli compile` 이 **dev / prod 두 프로파일 모두 통과** 했다 (`build.sh dev`, `build.sh prod`). CI 의 `compile-dev` / `compile-prod` job 도 green.
- [ ] **비공개 키 / 시드 / 시리얼 lot CSV 가 staged 에 없다** — `*.pem` / `*.der` / `*_priv.*` / `secrets/` / `lot*.csv` / `factory_seed*.csv`. CI `secure-boot-precondition` job 이 검증.
- [ ] **anti-rollback `ICONIA_SECURE_VERSION` 인상 필요 여부**를 검토했다 (보안 패치라면 +1, 아니면 사유 명시).
- [ ] 시리얼 로그 / Insecure 폴백 매크로 (`ICONIA_ALLOW_INSECURE_TLS` 등) 가 prod 빌드에 끼어들지 않았다.
- [ ] 새 GPIO 사용 시 RTC / EXT1 wakeup 호환성, ESP32 사용 불가 핀(6-11) 회피 검증 완료.
- [ ] Deep Sleep 진입 전 페리페럴 정리 시퀀스 (카메라 → Wi-Fi → BLE → I2C/SPI → GPIO hold) 영향 검토.

## 검증 증거

<!--
시리얼 로그, 전류 측정값, 패킷 캡처, 스코프 사진 등.
"빌드만 통과" 는 검증이 아님 — 실제 동작 신호 첨부 권장.
-->

## 라벨

<!--
docs/security_handshake.md 또는 docs/production_provisioning.md 를 변경한 PR 은
'security-spec-change' 라벨이 강제된다 (CI handshake-doc-guard job).
다른 리포 정합 검토를 사람이 의식적으로 했다는 서명.
-->
