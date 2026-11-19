# TLS-Based Secure Web Application Monitoring and Threat Detection System

[![Python Version](https://img.shields.io/badge/Python-3.12%20%7C%203.13%20%7C%203.14-blue.svg)](https://www.python.org/)
[![Framework](https://img.shields.io/badge/Flask-3.1-black.svg)](https://flask.palletsprojects.com/)
[![Cryptographic Security](https://img.shields.io/badge/Security-TLS%201.3%20%2F%201.2%20%7C%20HMAC--SHA256-00f5d4.svg)](#)
[![Database](https://img.shields.io/badge/Database-SQLite3%20(Parameterized)-blueviolet.svg)](#)
[![Automated Tests](https://img.shields.io/badge/Pytest-22%20Passed%20(100%25)-brightgreen.svg)](#)
[![Capstone Tier](https://img.shields.io/badge/Academic%20Tier-University%20Capstone-success.svg)](#)

---

## Quick Start (Windows PowerShell)

The capstone project is located inside `tls_web_monitor/`.

### 1. Launch in 1 Click
Double-click:
- **`run_https.bat`**: Launches the server in HTTPS mode on **port 8443** (Encrypted TLS Tunnel).
- **`run_tests.bat`**: Runs the 22 automated Pytest verification tests.

### 2. Manual PowerShell Commands
```powershell
# 1. Activate virtual environment
.\venv\Scripts\Activate.ps1

# 2. Seed realistic demonstration data (if not already seeded)
python tls_web_monitor\scripts\seed_demo_data.py

# 3. Start HTTPS server on Port 8443
cd tls_web_monitor
python app.py --port 8443
```

### 3. Open in Browser
Navigate to:
```
https://localhost:8443
```
Click **Advanced** &rarr; **Proceed to localhost (unsafe)** to complete the TLS handshake.

### 4. Demonstration Credentials
- **Administrator**: `admin` / `AdminPass123!` (Access SOC Dashboard, Request Logs, Threat Alerts, Security Testing)
- **Standard User**: `demo_user` / `UserPass123!` (Standard User Portal)

---

For complete architectural details, module specifications, security analysis, and test reports, see the full documentation in [tls_web_monitor/README.md](tls_web_monitor/README.md).

