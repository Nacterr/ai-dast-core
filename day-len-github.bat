@echo off
cd /d "%~dp0"
title Day code len GitHub (https://github.com/Nacterr/ai-dast-core)
color 0A
echo ======================================================================
echo          DANG DAY MA NGUON LEN GITHUB REPOSITORY NACTERR
echo ======================================================================
echo.
git push -u origin main
echo.
if %ERRORLEVEL% equ 0 (
    echo ======================================================================
    echo   [THANH CONG] Toan bo ma nguon da duoc day len GitHub thanh cong!
    echo   Xem repo tai: https://github.com/Nacterr/ai-dast-core
    echo ======================================================================
) else (
    echo ======================================================================
    echo   [LUU Y] Neu chua dang nhap, trinh duyet se yeu cau dang nhap GitHub.
    echo   Vui long bam dang nhap roi chay lai file nay.
    echo ======================================================================
)
pause
