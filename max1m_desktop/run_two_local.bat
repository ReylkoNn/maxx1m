@echo off
title Max1m - Launch 2 Local Python Instances
cd /d "%~dp0.."

"%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe" -NoProfile -ExecutionPolicy Bypass -File "%~dp0..\packaging\start_two_windows.ps1"
if errorlevel 1 pause
