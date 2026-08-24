@echo off
title ShadowXLab CyberCore Deployment Tool
echo ========================================================
echo Deploying ShadowXLab CyberCore to:
echo Target Domain: sxl-cybercore.shadowxlab.com
echo ========================================================
echo.
echo Select deployment method:
echo [1] Deploy via Cloudflare Pages (wrangler pages deploy)
echo [2] Deploy via Vercel (npx vercel --prod)
echo [3] Deploy via Netlify (npx netlify deploy --prod)
echo [4] Exit
echo.

set /p choice="Enter choice [1-4]: "

if "%choice%"=="1" (
    echo.
    echo Running Cloudflare Pages deployment...
    npx wrangler pages deploy . --project-name=sxl-cybercore
    goto end
)

if "%choice%"=="2" (
    echo.
    echo Running Vercel deployment...
    npx vercel --prod
    goto end
)

if "%choice%"=="3" (
    echo.
    echo Running Netlify deployment...
    npx netlify deploy --prod --dir=.
    goto end
)

:end
echo.
echo Deployment process complete.
pause
