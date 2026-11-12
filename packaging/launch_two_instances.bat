@echo off
title Max1m - Launch 2 Isolated Instances
cd /d "%~dp0"

echo [1/2] Starting Window #1 ...
start "" "%~dp0Max1m.exe" --instance 1

timeout /t 2 /nobreak >nul

echo [2/2] Starting Window #2 ...
start "" "%~dp0Max1m.exe" --instance 2
