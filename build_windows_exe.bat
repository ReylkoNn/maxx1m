@echo off
title Max1m - Build Windows EXE
cd /d "%~dp0"

echo =================================================================
echo   Max1m - Building standalone Windows app Max1m.exe + ZIP
echo =================================================================
echo.

"%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe" -NoProfile -ExecutionPolicy Bypass -File "%~dp0packaging\build_windows.ps1"
if errorlevel 1 goto :fail

echo.
echo Ready! Next steps:
echo   1. Run run_local_test_server.bat to start the server on port 8000
echo   2. Run run_two_windows.bat to open 2 isolated Max1m windows
echo.
pause
exit /b 0

:fail
echo.
echo [ERROR] Build failed. Please check the messages above.
pause
exit /b 1
