@echo off
chcp 65001 >nul
title Max1m — Локальный сервер для теста через туннель (порт 8000)
cd /d "%~dp0max1m_backend"

set "PY_EXE=python"
if exist "%~dp0max1m_backend\.venv\Scripts\python.exe" set "PY_EXE=%~dp0max1m_backend\.venv\Scripts\python.exe"
if exist "%~dp0max1m_backend\venv\Scripts\python.exe" set "PY_EXE=%~dp0max1m_backend\venv\Scripts\python.exe"

if not exist "%~dp0max1m_backend\.venv\Scripts\python.exe" (
    if not exist "%~dp0max1m_backend\venv\Scripts\python.exe" (
        echo [1/3] Создаём виртуальное окружение max1m_backend\.venv ...
        python -m venv "%~dp0max1m_backend\.venv"
        set "PY_EXE=%~dp0max1m_backend\.venv\Scripts\python.exe"
        "%~dp0max1m_backend\.venv\Scripts\pip.exe" install --upgrade pip wheel
        "%~dp0max1m_backend\.venv\Scripts\pip.exe" install -r "%~dp0max1m_backend\requirements.txt"
    )
)

REM Автогенерация криптостойкого SECRET_KEY в .env, если файла ещё нет
"%PY_EXE%" -c "import pathlib, secrets; p = pathlib.Path('.env'); p.exists() and len(p.read_text()) > 40 or p.write_text('SECRET_KEY=' + secrets.token_hex(32) + '\n', encoding='utf-8')"

REM Повышенные лимиты для локального теста 2 окон с одного ПК через 127.0.0.1 туннель
set "RATE_LIMIT_LOGIN=60/minute"
set "RATE_LIMIT_REGISTER=30/hour"
set "CALL_STUN_URLS=stun:stun.cloudflare.com:3478"

echo.
echo =================================================================
echo   Генерируем 2 свежих инвайт-кода для Окна #1 и Окна #2:
echo =================================================================
"%PY_EXE%" create_invite.py
"%PY_EXE%" create_invite.py
echo.
echo =================================================================
echo   Сервер слушает http://127.0.0.1:8000 (пробросьте его туннелем,
echo   например: cloudflared tunnel --url http://127.0.0.1:8000)
echo =================================================================
echo.

"%PY_EXE%" run_server.py
pause
