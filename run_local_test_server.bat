@echo off
title Max1m - Local Test Server on port 8000
cd /d "%~dp0"

"%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe" -NoProfile -ExecutionPolicy Bypass -File "%~dp0packaging\start_local_server.ps1"
pause
