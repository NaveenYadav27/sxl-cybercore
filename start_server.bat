@echo off
title ShadowXLab - CyberCore Visual Platform Server
echo ========================================================
echo Starting ShadowXLab CyberCore Visual Platform...
echo Local URL:     http://localhost:3000
echo ========================================================
echo.

where python >nul 2>nul
if %errorlevel% equ 0 (
    start http://localhost:3000
    python -m http.server 3000
    goto end
)

where npx >nul 2>nul
if %errorlevel% equ 0 (
    start http://localhost:3000
    npx serve . -l 3000
    goto end
)

start index.html
:end
pause
