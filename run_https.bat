@echo off
cd /d "%~dp0\tls_web_monitor"
echo ==============================================================================
echo   TLS-Based Secure Web Application Monitoring and Threat Detection System
echo   Launching HTTPS Server on Port 8443 (Encrypted TLS Mode)
echo ==============================================================================
..\venv\Scripts\python.exe app.py --port 8443
pause

