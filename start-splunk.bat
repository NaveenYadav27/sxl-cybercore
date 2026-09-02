@echo off
title ShadowXLab - Splunk Enterprise Security Standalone
echo ============================================================
echo   SHADOWXLAB SPLUNK ENTERPRISE SECURITY STANDALONE
echo ============================================================
echo   Checking Node.js environment...

where node >nul 2>nul
if %errorlevel% neq 0 (
    echo [ERROR] Node.js is not installed or not in PATH.
    echo Please install Node.js from https://nodejs.org/ to run the standalone server.
    pause
    exit /b 1
)

echo   Starting Localhost Splunk ES Ingestion Engine on Port 8000...
start "" http://localhost:8000/splunk.html
node server.js
pause
