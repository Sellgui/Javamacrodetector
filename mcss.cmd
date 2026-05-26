@echo off
setlocal
title Cheat detector
cd /d "%~dp0"

echo Cheat detector
echo --------------
echo.

if not exist "%~dp0mcss.ps1" (
  echo [ERROR] mcss.ps1 was not found.
  echo Make sure you extracted the full zip before running this command.
  echo.
  pause
  exit /b 1
)

if not exist "%~dp0MinecraftScreenShareScanner.java" (
  echo [WARN] MinecraftScreenShareScanner.java was not found.
  echo Running the PowerShell scanner only.
  echo.
)

where powershell.exe >nul 2>nul
if errorlevel 1 (
  echo [ERROR] PowerShell was not found on this PC.
  echo.
  pause
  exit /b 1
)

powershell.exe -NoLogo -NoProfile -ExecutionPolicy Bypass -File "%~dp0mcss.ps1" -NoPause
set "SCAN_EXIT=%errorlevel%"

echo.
if not "%SCAN_EXIT%"=="0" (
  echo Scanner stopped with error code %SCAN_EXIT%.
) else (
  echo Scanner finished.
)
echo.
pause
exit /b %SCAN_EXIT%
