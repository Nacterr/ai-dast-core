@echo off
title AI DAST Online - Cloudflare Tunnel
color 0B
echo ======================================================================
echo           AI DAST CORE - KHOI TAO DUONG HAM CLOUDFLARE ONLINE
echo ======================================================================
echo.
echo [1/2] Dang kiem tra va khoi dong Backend AI DAST tren cong 8093...
start /b "" ".venv\Scripts\python.exe" -m app.main serve --host 127.0.0.1 --port 8093 --api-allowed-host "*" --api-allowed-port 80 --api-allowed-port 443 --api-allowed-port 8099 --api-allow-private --api-allow-active --api-allow-injection
timeout /t 2 /nobreak >nul

echo [2/2] Dang tao duong ham Cloudflare Tunnel (HTTPS cong khai toan cau)...
echo.
echo ----------------------------------------------------------------------
echo  Vui long tim dong co link: https://xxxx.trycloudflare.com duoi day
echo  Gui duong link do cho ban be hoac mo tren dien thoai de su dung!
echo ----------------------------------------------------------------------
echo.
tools\cloudflared.exe tunnel --url http://127.0.0.1:8093
pause
