@echo off
title Max1m - WebRTC diagnose
cd /d "%~dp0"

set "DVPY=%~d0\.m1b\dv\Scripts\python.exe"
if exist "%DVPY%" (
    "%DVPY%" "%~dp0max1m_desktop\diagnose_webrtc.py"
    goto :done
)

py -3.15 "%~dp0max1m_desktop\diagnose_webrtc.py" 2>nul
if not errorlevel 1 goto :done

python "%~dp0max1m_desktop\diagnose_webrtc.py"

:done
echo.
pause
