@echo off
chcp 65001 >nul
title Max1m — Сборка Windows-приложения (Max1m.exe)
cd /d "%~dp0"

echo =================================================================
echo   Сборка автономного Windows-клиента Max1m (Max1m.exe + ZIP)
echo =================================================================
echo.

powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0packaging\build_windows.ps1"
if errorlevel 1 (
    echo.
    echo [ОШИБКА] Сборка завершилась с ошибкой. Проверьте вывод выше.
    pause
    exit /b 1
)

echo.
echo Теперь вы можете запустить сразу 2 независимых окна для теста через туннель:
echo   -> двойным кликом по run_two_windows.bat
echo   -> или из папки packaging\dist\Max1m\launch_two_instances.bat
echo.
pause
