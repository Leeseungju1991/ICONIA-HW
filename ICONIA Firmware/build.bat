@echo off
REM =============================================================================
REM ICONIA Firmware build helper (Windows cmd)
REM Usage:
REM   build.bat dev          (default)
REM   build.bat prod
REM   build.bat <name>       (any build_profiles\<name>.h)
REM =============================================================================
setlocal

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

where arduino-cli >nul 2>nul
if errorlevel 1 (
  echo [BUILD] WARN: arduino-cli not found in PATH. Skipping compile.
  echo [BUILD] Open this sketch in Arduino IDE 2.x to build manually.
  echo [BUILD] (build_opt.h is already set for profile=%PROFILE%)
  exit /b 0
)

pushd "%SCRIPT_DIR%"
arduino-cli compile ^
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
endlocal
