@echo off
chcp 65001 >nul
title Max1m — Запуск 2 локальных клиентов (Python) для теста через туннель
cd /d "%~dp0"

set "PY_EXE=python"
if exist "%~dp0.venv\Scripts\python.exe" set "PY_EXE=%~dp0.venv\Scripts\python.exe"
if exist "%~dp0venv\Scripts\python.exe" set "PY_EXE=%~dp0venv\Scripts\python.exe"

echo [1/2] Запуск Клиента #1 (профиль ~/.max1m) ...
start "Max1m Client #1" "%PY_EXE%" "%~dp0run_desktop.py" --instance 1

timeout /t 2 /nobreak >nul

echo [2/2] Запуск Клиента #2 (изолированный профиль ~/.max1m_inst_2) ...
start "Max1m Client #2" "%PY_EXE%" "%~dp0run_desktop.py" --instance 2

echo Оба окна запущены! В «Расширенных настройках» укажите адрес вашего HTTPS-туннеля
echo (например https://xxxx.trycloudflare.com или https://xxxx.tuna.am) или http://127.0.0.1:8000.
