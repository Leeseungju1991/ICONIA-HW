@echo off
REM =============================================================================
REM ICONIA Firmware build helper (Windows cmd)
REM Usage:
REM   build.bat dev          (default, debug-friendly)
REM   build.bat prod         (production lockdown — Secure Boot V2 / Flash Enc)
REM   build.bat <name>       (any build_profiles\<name>.h)
REM
REM prod 빌드는 unsigned binary 만 산출. 서명 + eFuse burn 은 양산 라인
REM fixture 가 별도 수행. 절차: docs\production_provisioning.md §3.
REM =============================================================================
setlocal enabledelayedexpansion

set "PROFILE=%~1"
if "%PROFILE%"=="" set "PROFILE=dev"

set "SCRIPT_DIR=%~dp0"
set "PROFILE_FILE=%SCRIPT_DIR%build_profiles\%PROFILE%.h"

if not exist "%PROFILE_FILE%" (
  echo [BUILD] ERROR: unknown profile '%PROFILE%'
  echo [BUILD] available profiles:
  dir /b "%SCRIPT_DIR%build_profiles\*.h" 2>nul
  exit /b 1
)

copy /Y "%PROFILE_FILE%" "%SCRIPT_DIR%build_opt.h" >nul
echo [BUILD] profile=%PROFILE%
echo [BUILD] copied build_profiles\%PROFILE%.h -^> build_opt.h

REM -----------------------------------------------------------------------------
REM prod 보안 잠금 매크로 정합성 검사 (출시 차단 가드)
REM -----------------------------------------------------------------------------
if /I "%PROFILE%"=="prod" (
  for %%M in (ICONIA_PRODUCTION_BUILD ICONIA_BLE_SECURE ICONIA_REQUIRE_FACTORY_SEED ICONIA_LOCKDOWN ICONIA_SECURE_VERSION) do (
    findstr /R /C:"^#define %%M" "%PROFILE_FILE%" >nul
    if errorlevel 1 (
      echo [BUILD] FATAL: prod profile missing required macro %%M
      echo [BUILD] refer to docs\production_provisioning.md
      exit /b 2
    )
  )
  echo [BUILD] prod lockdown macros verified
)

REM -----------------------------------------------------------------------------
REM arduino-cli compile
REM -----------------------------------------------------------------------------
where arduino-cli >nul 2>nul
if errorlevel 1 (
  echo [BUILD] WARN: arduino-cli not found in PATH. Skipping compile.
  echo [BUILD] Open this sketch in Arduino IDE 2.x to build manually.
  echo [BUILD] ^(build_opt.h is already set for profile=%PROFILE%^)
  exit /b 0
)

pushd "%SCRIPT_DIR%"
arduino-cli compile ^
  --warnings all ^
  --fqbn esp32:esp32:esp32cam ^
  --build-property "build.partitions=partitions" ^
  --build-property "upload.maximum_size=1900544" ^
  .
set "RC=%ERRORLEVEL%"
popd

if not "%RC%"=="0" (
  echo [BUILD] FAILED rc=%RC%
  exit /b %RC%
)

echo [BUILD] done. Output under build\esp32.esp32.esp32cam\

if /I "%PROFILE%"=="prod" (
  echo.
  echo [BUILD] === PROD POST-BUILD CHECKLIST ===
  echo Built artifact is UNSIGNED. Production line must:
  echo   1^) espsecure.py sign_data --version 2 --keyfile ^<hsm-or-airgap-key^>
  echo   2^) espefuse.py burn_key_digest + SECURE_BOOT_EN=1
  echo   3^) espefuse.py FLASH_CRYPT_CNT=0xF
  echo   4^) espefuse.py JTAG_DISABLE=1, UART_DOWNLOAD_DIS=1
  echo   5^) factory_nvs seed/salt/seed_ver burn ^(per-device, lot CSV^)
  echo   6^) QA validation: pairing, status notify, deep-sleep current, touch wake
  echo Detailed procedure: HW\docs\production_provisioning.md §3
  echo =================================
)

endlocal
