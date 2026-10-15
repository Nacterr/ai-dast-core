@echo off
cd /d "%~dp0"
echo ====================================================================
echo   ARTEX - AI DAST PRO Web Demo Console (/system/llm, /tasks, ...)
echo ====================================================================
.\.venv\Scripts\python.exe -m app.artex_web
pause
