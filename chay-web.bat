@echo off
cd /d "%~dp0"
echo ====================================================================
echo   AI DAST PRO - Web Security Console (/system/llm, /tasks, ...)
echo ====================================================================
.\.venv\Scripts\python.exe -m app.artex_web
pause
