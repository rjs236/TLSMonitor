@echo off
setlocal enabledelayedexpansion
title TLS SOC Monitor - Public Internet Link Generator
cd /d "%~dp0"

echo ==============================================================================
echo   TLS-Based Secure Web Application Monitoring and Threat Detection System
echo   Public Sharing Console - Generate Worldwide Accessible URL
echo ==============================================================================
echo.

:: 1. Ensure Python Virtual Environment exists
if not exist "..\venv\Scripts\python.exe" (
    echo [!] Virtual environment not found at ..\venv
    echo [*] Please run: python -m venv venv and install requirements first.
    pause
    exit /b 1
)

:: 2. Check / Start Flask Server
echo [*] Checking local server status...
netstat -ano | findstr ":8443" >nul 2>&1
if %errorlevel% neq 0 (
    echo [*] Starting HTTPS Flask server on port 8443 in background...
    start "TLS Monitor Server (Port 8443)" /min cmd /c "..\venv\Scripts\python.exe app.py --port 8443"
    timeout /t 3 /nobreak >nul
) else (
    echo [✓] Local HTTPS server is already active on port 8443.
)

:: 3. Check for cloudflared.exe or download it
if not exist "cloudflared.exe" (
    echo [*] Cloudflare Tunnel binary not found. Downloading standalone cloudflared.exe...
    echo [*] Source: Cloudflare Official GitHub Release (Single executable, no install needed)
    powershell -Command "[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12; (New-Object System.Net.WebClient).DownloadFile('https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-windows-amd64.exe', 'cloudflared.exe')"
)

if exist "cloudflared.exe" (
    echo.
    echo ==============================================================================
    echo  [✓] Launching Cloudflare Tunnel (Zero-Configuration Global HTTPS)
    echo ==============================================================================
    echo  - Accessible by ANYONE on ANY device (iPhone, Android, Mac, Windows, Linux)
    echo  - Encrypted with Cloudflare's trusted global SSL certificate (No browser warnings)
    echo  - Note: Keep this command prompt window open to keep the public link active.
    echo ==============================================================================
    echo.
    echo [*] Establishing secure tunnel to https://localhost:8443...
    echo.
    .\cloudflared.exe tunnel --url https://localhost:8443 --no-tls-verify
    pause
    exit /b 0
)

:: 4. Fallback Option: Localtunnel via npx (if Node.js installed)
where npx >nul 2>&1
if %errorlevel% equ 0 (
    echo.
    echo [!] cloudflared.exe not available. Using Localtunnel via npx...
    echo [*] Note: Keep this window open to maintain public access.
    echo.
    npx localtunnel --port 8443 --local-https --allow-invalid-cert
    pause
    exit /b 0
)

:: 5. Fallback Option: Pinggy via OpenSSH
where ssh >nul 2>&1
if %errorlevel% equ 0 (
    echo.
    echo [!] Using OpenSSH Pinggy tunnel...
    echo.
    ssh -p 443 -R0:localhost:8443 a.pinggy.io
    pause
    exit /b 0
)

echo.
echo [!] Unable to automatically create a public tunnel.
echo [*] Local Wi-Fi sharing is active: Devices on the same Wi-Fi can open:
ipconfig | findstr "IPv4"
pause

