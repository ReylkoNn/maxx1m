@echo off
chcp 65001 >nul
title Max1m — Запуск 2 изолированных окон на одном ПК
cd /d "%~dp0"

if exist "%~dp0packaging\dist\Max1m\Max1m.exe" (
    echo [EXE] Найден собранный клиент packaging\dist\Max1m\Max1m.exe!
    echo [1/2] Запускаем Окно #1 (профиль ~/.max1m) ...
    start "" "%~dp0packaging\dist\Max1m\Max1m.exe" --instance 1
    timeout /t 2 /nobreak >nul
    echo [2/2] Запускаем Окно #2 (изолированный профиль ~/.max1m_inst_2) ...
    start "" "%~dp0packaging\dist\Max1m\Max1m.exe" --instance 2
    goto :done
)

echo [Python] Max1m.exe ещё не собран — запускаем 2 окна напрямую из исходников...
call "%~dp0max1m_desktop\run_two_local.bat"
exit /b 0

:done
echo.
echo Оба окна запущены! В каждом окне укажите HTTPS-адрес вашего туннеля
echo (или http://127.0.0.1:8000), зарегистрируйте 2 аккаунта и протестируйте созвон!
