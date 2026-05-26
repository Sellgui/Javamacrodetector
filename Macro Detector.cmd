@echo off
setlocal
title Macro Detector by sellgui

set "SCRIPT=%~dp0Macro Detector.ps1"
if not exist "%SCRIPT%" (
  echo Macro Detector.ps1 was not found next to this launcher.
  pause
  exit /b 1
)

powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%SCRIPT%"
set "CODE=%ERRORLEVEL%"
echo.
if "%CODE%"=="2" (
  echo Macro evidence was found.
) else if "%CODE%"=="1" (
  echo Possible macro traces were found.
) else (
  echo No strict macro evidence was found.
)
echo.
pause
exit /b %CODE%
