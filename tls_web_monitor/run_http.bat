@echo off
cd /d "%~dp0"
echo ==============================================================================
echo   TLS-Based Secure Web Application Monitoring and Threat Detection System
echo   Launching HTTP Mode on Port 5000 (Unencrypted / Testing Only)
echo ==============================================================================
..\venv\Scripts\python.exe app.py --http
pause

