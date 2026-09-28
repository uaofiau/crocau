@echo off
cd /d "%~dp0"
echo Starting crocau with visible console (diagnostics)...
powershell.exe -NoProfile -ExecutionPolicy Bypass -STA -File "%~dp0crocau.ps1"
echo.
echo Exit code: %ERRORLEVEL%
pause
