@echo off
setlocal
cd /d "%~dp0"
title ai-dast-core Service

echo ======================================================================
echo    AI-DAST-CORE - DAST Security Console
echo ======================================================================
echo Dang khoi dong Web Dashboard tai http://127.0.0.1:8093 ...
echo (Giu cua so nay mo khi ban su dung Web UI)
echo.

start "" "http://127.0.0.1:8093"

.\.venv\Scripts\python.exe -m app.main serve --host 127.0.0.1 --port 8093 --api-allowed-host "*" --api-allowed-port 80 --api-allowed-port 443 --api-allowed-port 8099 --api-allow-private --api-allow-active --api-allow-injection
pause
