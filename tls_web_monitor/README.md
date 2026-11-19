# TLS-Based Secure Web Application Monitoring and Threat Detection System

[![Python Version](https://img.shields.io/badge/Python-3.12%20%7C%203.13%20%7C%203.14-blue.svg)](https://www.python.org/)
[![Framework](https://img.shields.io/badge/Flask-3.1-black.svg)](https://flask.palletsprojects.com/)
[![Cryptographic Security](https://img.shields.io/badge/Security-TLS%201.3%20%2F%201.2%20%7C%20HMAC--SHA256-00f5d4.svg)](#)
[![Database](https://img.shields.io/badge/Database-SQLite3%20(Parameterized)-blueviolet.svg)](#)
[![Automated Tests](https://img.shields.io/badge/Pytest-22%20Passed%20(100%25)-brightgreen.svg)](#)
[![Capstone Tier](https://img.shields.io/badge/Academic%20Tier-University%20Capstone-success.svg)](#)

---

## 1. Project Overview & Objectives

The **TLS-Based Secure Web Application Monitoring and Threat Detection System** is an engineering capstone platform that combines transport-layer encryption, user authentication, continuous HTTP telemetry, persistent SQLite logging, cryptographic tamper-evident audit verification, and an autonomous rule-based threat detection engine.

Designed for local Windows execution and academic demonstration, the system features a responsive **cybersecurity dark navy-blue / cyan SOC interface**, allowing university students to clearly demonstrate transport security, live SIEM audit logs, simulated attacks (SQLi, Directory Traversal, Brute Force, Rate Limiting), and cryptographic log-integrity audits.

---

## 2. System Architecture & The Three Core Modules

```
                    +------------------------------------------+
                    |      Client Browser / Security Analyst   |
                    +--------------------+---------------------+
                                         |
                               HTTPS (Port 8443)
                         TLS 1.3 / 1.2 Encrypted Tunnel
                                         |
                                         v
+===================================================================================+
|                             FLASK APPLICATION CORE                                |
|                                                                                   |
|  +-----------------------------------------------------------------------------+  |
|  | Module 1: TLS Communication, Authentication & RBAC                          |  |
|  | - Python ssl.SSLContext (TLS 1.2+, ECDHE-RSA-AES256-GCM-SHA384)             |  |
|  | - Werkzeug PBKDF2-HMAC-SHA256 Password Hashing                              |  |
|  | - Secure Cookies (HttpOnly, SameSite=Lax, Secure=True) & Session Timeout   |  |
|  | - Constant-Time CSRF Token Protection & Multi-Tier RBAC (Admin / User)      |  |
|  | - Enterprise HTTP Security Headers (HSTS, CSP, X-Frame-Options, nosniff)    |  |
|  +-------------------------------------+---------------------------------------+  |
|                                        |                                          |
|                                        v                                          |
|  +-----------------------------------------------------------------------------+  |
|  | Module 3: Server-Side Rule-Based Threat Detection Engine                     |  |
|  | - SQL Injection (SQLi) Tautology & UNION Inspection                         |  |
|  | - Path Traversal & Sensitive Local File Access Backtracking Detection       |  |
|  | - Rate-Limit Burst Flood Detection (> 60 req/min per IP)                    |  |
|  | - Brute-Force Authentication Anomaly Detection (> 5 failures in window)     |  |
|  | - Repeated Unauthorized Access Denials (401 / 403 Probing)                  |  |
|  | - Severity Assignment: LOW, MEDIUM, HIGH                                    |  |
|  +-------------------------------------+---------------------------------------+  |
|                                        |                                          |
|                                        v                                          |
|  +-----------------------------------------------------------------------------+  |
|  | Module 2: Telemetry Monitoring & Cryptographic Log-Integrity                |  |
|  | - Latency & Request Telemetry (after_request hooks)                         |  |
|  | - Sensitive Data Exclusion (Zero passwords, tokens, or auth headers logged) |  |
|  | - Tamper-Evident HMAC-SHA256 Signatures computed per row                    |  |
|  | - Searchable / Filterable Audit Log Console with CSV Export                 |  |
|  | - Cryptographic HMAC Integrity Verification Audit Engine                    |  |
|  +-------------------------------------+---------------------------------------+  |
|                                        |                                          |
+========================================|==========================================+
                                         |
                                         v Parameterized Queries (?)
                        +---------------------------------+
                        |   Persistent SQLite3 Database   |
                        | - users                         |
                        | - request_logs                  |
                        | - security_alerts               |
                        | - login_attempts                |
                        | - audit_integrity               |
                        +---------------------------------+
```

### Module 1: TLS-Based Secure Communication and Authentication
- **Transport Tunnel**: Configured via Python `ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)`. Enforces modern TLS 1.2 / TLS 1.3, blocks obsolete and broken protocols (SSLv2, SSLv3, TLS 1.0, TLS 1.1), and configures modern PFS cipher suites (`ECDHE-RSA-AES256-GCM-SHA384`, `ECDHE-RSA-CHACHA20-POLY1305`).
- **X.509 Development Certificates**: Generated using the Python `cryptography` library with 2048-bit RSA keys and Subject Alternative Names (SAN) for `localhost`, `127.0.0.1`, and `::1`.
- **Authentication**: Salted password hashing using Werkzeug `generate_password_hash` and `check_password_hash` (PBKDF2-HMAC-SHA256).
- **Session Security**: Session cookies protected by `HttpOnly=True`, `SameSite='Lax'`, and dynamic `Secure=True` over HTTPS with automatic 2-hour expiration.
- **CSRF Defense**: Cryptographic tokens stored in session and verified using constant-time comparison (`hmac.compare_digest`) on all state-changing POST requests.
- **Access Control (RBAC)**: Route-level decorators `@login_required` and `@admin_required` enforcing privilege tiers.

### Module 2: Web Application Monitoring and Logging
- **Real-Time Telemetry**: Intercepts every incoming HTTP request using Flask request hooks (`before_request` / `after_request`). Records timestamp (UTC), client IP, HTTP method, requested path, response status code, username, event category, risk level, and execution latency in milliseconds.
- **Strict Data Sanitization**: Sensitive parameters (`password`, `token`, `secret`, `key`, `auth`, `csrf_token`) are redacted before database writes. Passwords, session cookies, and Authorization headers are never stored.
- **Persistent SQLite Storage**: Indexed tables for fast multi-criteria queries.
- **Searchable Console**: Paginated audit log interface with keyword search, risk filter, category filter, status filter, and one-click CSV export.
- **Tamper-Evident HMAC Verification**: Computes an HMAC-SHA256 signature for each log entry. The verification engine scans the database and identifies any row modified, inserted, or corrupted out-of-band.

### Module 3: Threat Detection and Security Analysis
- **Rule-Based Detection Engine**: Real-time server-side payload and behavior inspection:
  1. *SQL Injection (SQLi)*: Detects boolean tautologies (`' OR '1'='1'`), UNION SELECT, destructive DDL keywords, and comment delimiters. Severity: **HIGH**.
  2. *Path Traversal (LFI)*: Detects directory backtracking sequences (`../`, `..\`, `%2e%2e%2f`) and sensitive system files (`/etc/passwd`, `win.ini`). Severity: **HIGH**.
  3. *Brute Force Detection*: Flags accounts/IPs exceeding 5 failed authentication attempts within 5 minutes. Severity: **HIGH**.
  4. *Rate Limiting / Request Burst*: Identifies single-IP request floods exceeding 60 requests/minute. Severity: **MEDIUM**.
  5. *Unauthorized Access Probing*: Detects repeated 401/403 access denials on protected administrative endpoints. Severity: **MEDIUM**.
- **Alert Queue & Triage**: Administrative interface to filter alerts, view captured payloads, and mark alerts as `ACKNOWLEDGED` or `RESOLVED`.
- **Interactive Security Testing Console**: UI allowing live demonstration of controlled test probes and database tamper verification.

---

## 3. Technology Stack

| Component | Technology | Role in System |
| :--- | :--- | :--- |
| **Language** | Python 3.12 / 3.13 / 3.14 | Core backend application logic |
| **Web Framework** | Flask 3.1 | HTTP routing, request hooks, Jinja templates |
| **Transport Security** | Python `ssl` | Server-side TLS 1.3 / 1.2 configuration & cipher enforcement |
| **Cryptographic Suite** | Python `cryptography` | RSA-2048 X.509 cert generation with SAN & HMAC-SHA256 signatures |
| **Password Hashing** | Werkzeug Security | PBKDF2-HMAC-SHA256 password hashing |
| **Database** | SQLite3 (Persistent) | Relational storage with foreign keys and parameterized queries |
| **Frontend** | HTML5, CSS3, JavaScript | Dark navy-blue / cyan SOC dashboard, Chart.js telemetry charts |
| **Testing** | Pytest 8.x / 9.x | 22 automated end-to-end unit and integration tests |

---

## 4. Project Directory Structure

```text
tls_web_monitor/
│
├── app.py                      # Flask application factory, server launcher & hooks
├── config.py                   # Environment configuration & threat detection thresholds
├── requirements.txt            # Python dependencies (Flask, Cryptography, Pytest, etc.)
├── README.md                   # Comprehensive documentation & execution guide
├── .gitignore                  # Excludes private keys, certs, databases, and venvs
├── run_https.bat               # Windows 1-click HTTPS launcher (Port 8443)
├── run_http.bat                # Windows 1-click HTTP launcher (Port 5000)
├── run_tests.bat               # Windows 1-click Pytest runner
│
├── database/
│   ├── __init__.py             # Database package exports
│   ├── db.py                   # Connection management & parameterized query helpers
│   └── schema.sql              # Relational SQLite schema with DDL constraints & indexes
│
├── modules/
│   ├── __init__.py             # Modules package declaration
│   ├── auth.py                 # Module 1: TLS configuration, Login/Logout, Sessions, RBAC, CSRF
│   ├── monitoring.py           # Module 2: Request telemetry, SQLite logging, CSV export
│   ├── threat_detection.py     # Module 3: Rule engine (SQLi, Traversal, Brute Force, Rate Limit)
│   └── integrity.py            # Module 2 (Subcomponent): HMAC-SHA256 log signing & verification
│
├── templates/
│   ├── base.html               # Master layout with dark navy theme, navigation & TLS pill
│   ├── login.html              # Secure login form with CSRF token & demo credentials helper
│   ├── register.html           # User registration form with password strength checks
│   ├── home.html               # Standard user portal with active TLS parameters & RBAC notice
│   ├── dashboard.html          # Admin SOC overview with Chart.js severity graphs & live metrics
│   ├── logs.html               # Searchable, filterable, paginated audit log console
│   ├── alerts.html             # Threat alert queue with triage & acknowledgement actions
│   ├── test_results.html       # Interactive security testing & tamper demonstration console
│   └── about.html              # Technical architecture documentation & capstone overview
│
├── static/
│   ├── css/
│   │   └── style.css           # Cybersecurity SOC styling (Dark Navy-Blue / Cyan highlights)
│   └── js/
│       └── dashboard.js        # Chart.js initialization, real-time polling, attack probes
│
├── certs/
│   ├── .gitkeep                # Keeps directory in version control
│   ├── cert.pem                # Development X.509 TLS certificate (SAN: localhost, 127.0.0.1)
│   └── key.pem                 # 2048-bit RSA private key (excluded from Git)
│
├── scripts/
│   ├── generate_dev_certificate.py  # Generates 2048-bit RSA X.509 cert with SAN
│   ├── create_admin.py              # CLI script to securely provision administrator account
│   └── seed_demo_data.py            # Populates realistic historical demo logs & alerts
│
└── tests/
    ├── __init__.py             # Test package initializer
    ├── conftest.py             # Pytest fixtures, test database, and client helpers
    ├── test_auth.py            # 8 Tests: Login, Logout, RBAC, CSRF, TLS Context, Headers
    ├── test_monitoring.py      # 5 Tests: Telemetry, Sensitive Data Redaction, Filtering, CSV
    ├── test_threat_detection.py # 6 Tests: SQLi, Traversal, Brute Force, Rate Limit, Alerts
    └── test_integrity.py       # 3 Tests: HMAC determinism, Clean audit, Tamper detection
```

---

## 5. Windows PowerShell Step-by-Step Setup and Execution

Follow these copy-paste-ready commands in Windows PowerShell:

### Step 1: Verify Python Installation
```powershell
python --version
```
*Requires Python 3.11, 3.12, 3.13, or 3.14.*

### Step 2: Navigate to Project Directory & Create Virtual Environment
```powershell
cd C:\Users\rajas\Downloads\tls_security_system
python -m venv venv
```

### Step 3: Activate Virtual Environment in PowerShell
```powershell
.\venv\Scripts\Activate.ps1
```
*(If PowerShell blocks script execution, run: `Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass` and retry).*

### Step 4: Install Dependencies
```powershell
pip install -r tls_web_monitor\requirements.txt
```

### Step 5: Generate the Local Development TLS Certificate
```powershell
python tls_web_monitor\scripts\generate_dev_certificate.py
```
*Generates `tls_web_monitor\certs\cert.pem` and `tls_web_monitor\certs\key.pem` with Subject Alternative Names for `localhost` and `127.0.0.1`.*

### Step 6: Set Application Environment Variables (Optional / Production Practice)
```powershell
$env:SECRET_KEY="cybersec-capstone-session-secret-key-2026-x99f"
$env:LOG_INTEGRITY_KEY="capstone-hmac-sha256-audit-secret-key-32bytes!"
```

### Step 7: Initialize Database & Seed Demonstration Data
```powershell
python tls_web_monitor\scripts\seed_demo_data.py
```
*Seeds:*
- Admin account: `admin` / `AdminPass123!`
- User account: `demo_user` / `UserPass123!`
- 16 realistic historical request logs with valid cryptographic HMACs
- 4 demonstration security alerts (SQLi, Traversal, Brute Force, Rate Limit)

### Step 8: (Alternative) Create a Custom Administrator Account
```powershell
python tls_web_monitor\scripts\create_admin.py --username my_admin --password MySecurePass123!
```

### Step 9: Launch the Application with HTTPS (Encrypted Mode)
```powershell
cd tls_web_monitor
python app.py --port 8443
```
*Or double-click `run_https.bat`.*

### Step 10: Access the Application in Your Web Browser
Open your browser to:
```
https://localhost:8443
```

#### Understanding the Browser Self-Signed Certificate Warning
1. Because the certificate is self-signed for local development, your browser will display: **"Your connection is not private"** or **NET::ERR_CERT_AUTHORITY_INVALID**.
2. Click **"Advanced"** &rarr; **"Proceed to localhost (unsafe)"**.
3. The TLS handshake will complete successfully. The green **"🔒 TLS HTTPS"** indicator on the navbar confirms that the connection is encrypted.
4. *To eliminate the warning permanently on Windows:* Open `certmgr.msc`, navigate to **Trusted Root Certification Authorities** &rarr; **Certificates**, and import `tls_web_monitor\certs\cert.pem`.

---

## 6. Demonstration Credentials

| Role | Username | Password | Accessible Views |
| :--- | :--- | :--- | :--- |
| **Administrator** | `admin` | `AdminPass123!` | Dashboard, Request Logs, Threat Alerts, Security Testing, Export |
| **Standard User** | `demo_user` | `UserPass123!` | User Home, Connection Security Details, Login Activity |

---

## 7. Interactive Security Testing & Review Demonstration

To demonstrate real-time threat detection to an instructor or evaluation committee:

1. Sign in as `admin`.
2. Navigate to the **"Security Testing"** page (`https://localhost:8443/threats/security-testing`).
3. Click the test buttons to trigger live responses:
   - **Launch SQLi Test Probe**: Transmits `' OR '1'='1' --`. Demonstrates real-time detection, generation of a `HIGH`-severity alert in SQLite, and immediate display in the alerts queue.
   - **Launch Traversal Test Probe**: Transmits `../../../../etc/passwd`. Triggers directory traversal rule and records alert.
   - **Simulate Brute Force Attack**: Generates 5 rapid failed login attempts. Triggers the brute-force threshold rule.
   - **Simulate Request Burst**: Emulates rapid request flooding exceeding 60 req/min. Triggers `RATE_LIMIT_EXCEEDED` alert.
   - **Inject Database Tamper**: Directly updates a request log record in SQLite out-of-band without re-signing its cryptographic HMAC.
   - **Run Cryptographic Audit**: Immediately catches the modified record, reports `TAMPER_DETECTED`, and pinpoints the exact corrupted row ID!

---

## 8. Automated Testing & Verification Report

Automated tests are executed using Pytest:

```powershell
cd C:\Users\rajas\Downloads\tls_security_system
.\venv\Scripts\python.exe -m pytest tls_web_monitor\tests -v
```

### Complete Test Execution Results (22 of 22 Passed - 100%)

| Test ID | Module | Feature Tested | Test Input | Expected Result | Actual Result | Status |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **AUTH-01** | Module 1 | Valid User Authentication | Correct credentials + CSRF token | 200 OK, session established | 200 OK, session created | **PASS** |
| **AUTH-02** | Module 1 | Invalid User Authentication | Incorrect password | 401 Unauthorized, failure logged | 401 Unauthorized, logged in DB | **PASS** |
| **AUTH-03** | Module 1 | Session Termination (Logout) | Valid session logout POST | Session cleared, redirect to login | Session cleared, redirected | **PASS** |
| **AUTH-04** | Module 1 | RBAC Standard User Restriction | Access to `/admin/dashboard` & `/logs` | 403 Access Forbidden | 403 Forbidden enforced | **PASS** |
| **AUTH-05** | Module 1 | RBAC Administrator Access | Access to administrative routes | 200 OK, full dashboard access | 200 OK, access granted | **PASS** |
| **AUTH-06** | Module 1 | CSRF Protection | State-changing POST without CSRF | 400 Bad Request, CSRF rejected | 400 Bad Request rejected | **PASS** |
| **AUTH-07** | Module 1 | Security Headers Injection | Request to any endpoint | HSTS, CSP, nosniff, SAMEORIGIN | All headers present & valid | **PASS** |
| **AUTH-08** | Module 1 | Python SSL Context Hardening | `build_ssl_context(cert, key)` | TLS 1.2+ minimum, secure ciphers | `ssl.SSLContext` configured | **PASS** |
| **MON-01** | Module 2 | Automatic Request Telemetry | Ingress request to `/about` | Captured in SQLite `request_logs` | Captured with valid HMAC | **PASS** |
| **MON-02** | Module 2 | Sensitive Data Redaction | `?password=SuperSecret&token=xyz` | Sensitive values redacted | Stored as `[REDACTED]` | **PASS** |
| **MON-03** | Module 2 | Access Denied Logging | Unauthenticated access probe | Status 401/403 categorized | Recorded as `ACCESS_DENIED` | **PASS** |
| **MON-04** | Module 2 | Log Search & Multi-Filter | Filter by risk `INFO` & keyword | Matching records returned | Paginated results filtered | **PASS** |
| **MON-05** | Module 2 | Audit Log CSV Export | GET `/logs/export` | Valid CSV stream with headers | Valid CSV generated | **PASS** |
| **THR-01** | Module 3 | SQL Injection Detection | Input `1 OR 1=1` | `SQL_INJECTION` HIGH alert | Alert recorded in SQLite | **PASS** |
| **THR-02** | Module 3 | Path Traversal Detection | Input `../../../../etc/passwd` | `PATH_TRAVERSAL` HIGH alert | Alert recorded in SQLite | **PASS** |
| **THR-03** | Module 3 | Brute Force Detection | 3 consecutive failed logins | `BRUTE_FORCE` HIGH alert | Alert triggered & stored | **PASS** |
| **THR-04** | Module 3 | Rate-Limit Burst Detection | 12 rapid requests from client | `RATE_LIMIT_EXCEEDED` alert | Threshold breach recorded | **PASS** |
| **THR-05** | Module 3 | Alert Triage & Acknowledgement | POST `/alerts/<id>/acknowledge` | Status changes to ACKNOWLEDGED | Status updated with admin ID | **PASS** |
| **THR-06** | Module 3 | SQLite Dashboard Consistency | GET `/api/dashboard/stats` | JSON matches SQLite table counts | Actual counts match 100% | **PASS** |
| **INT-01** | Module 2 | HMAC-SHA256 Determinism | Identical log data tuples | Identical 64-character hex tags | Matches deterministically | **PASS** |
| **INT-02** | Module 2 | Clean Database Verification | Unmodified `request_logs` table | `VERIFIED` (0 tampered rows) | Status `VERIFIED` (0 errors) | **PASS** |
| **INT-03** | Module 2 | Tamper-Evidence Detection | Out-of-band SQLite row update | `TAMPER_DETECTED` with row ID | Caught tampered row ID | **PASS** |

---

## 9. Cryptographic Specifications & Security Analysis

### Password Storage
- Passwords are salted and hashed using Werkzeug's implementation of **PBKDF2-HMAC-SHA256**.
- Plaintext passwords and reversible encryption keys are never stored in the database.

### Transport Security (TLS)
- Server configured with Python `ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)`.
- Enforces a minimum protocol of **TLS 1.2** with support for **TLS 1.3**.
- Modern Forward-Secret Cipher Suites:
  - `ECDHE-ECDSA-AES256-GCM-SHA384`
  - `ECDHE-RSA-AES256-GCM-SHA384`
  - `ECDHE-ECDSA-CHACHA20-POLY1305`
  - `ECDHE-RSA-CHACHA20-POLY1305`
- Compression disabled (`ssl.OP_NO_COMPRESSION`) to eliminate CRIME attack vectors.

### Cryptographic Log Integrity (HMAC-SHA256)
- Each request logged to `request_logs` computes:
  $$\text{HMAC} = H_K(\text{timestamp} \parallel \text{ip} \parallel \text{method} \parallel \text{path} \parallel \text{status} \parallel \text{username} \parallel \text{category} \parallel \text{risk})$$
- Constant-time verification (`hmac.compare_digest`) prevents side-channel timing attacks.

#### Limitations of Local Log-Integrity Protection
- **Threat Model**: Local HMAC protection reliably detects out-of-band SQL modifications, unauthorized row tampering, and database corruption committed by attackers who have compromised the database file alone or accessed the SQLite shell.
- **Limitation**: If an attacker achieves full root/administrative shell access on the host and extracts the `LOG_INTEGRITY_KEY` from environment variables or active process memory, they could recalculate HMAC signatures.
- **Production Recommendation**: In production enterprise deployments, local database logging must be supplemented with real-time TLS streaming of audit logs to an external, write-once-read-many (WORM) centralized SIEM (such as Splunk, Elastic Cloud, or AWS CloudWatch) where logs cannot be retroactively altered.

---

## 10. Troubleshooting Common Issues

| Issue | Cause | Resolution |
| :--- | :--- | :--- |
| **PowerShell script execution error** | Execution policy restricts scripts | Run `Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass` |
| **Browser Certificate Warning** | Self-signed development certificate | Click **Advanced** &rarr; **Proceed to localhost (unsafe)** |
| **Port 8443 already in use** | Another service is using port 8443 | Run `python app.py --port 9443` or kill existing process |
| **Missing certificate files** | `certs/cert.pem` missing | Run `python scripts/generate_dev_certificate.py` |
| **Database locked / reset** | Concurrent write lock | Database WAL mode is enabled. If needed, delete `tls_security.db` and run `python scripts/seed_demo_data.py` |

---

## 11. Production Deployment Notice

The included server execution is intended for development and academic review. For production deployment:
1. Replace self-signed certificates with a certificate signed by a recognized Certificate Authority (CA) such as Let's Encrypt.
2. Deploy the application behind a production reverse proxy (e.g. Nginx or Caddy) or production WSGI server (e.g. Gunicorn or Waitress on Windows).
3. Store secret keys (`SECRET_KEY`, `LOG_INTEGRITY_KEY`) in hardware security modules (HSM) or cloud secret managers (e.g. Azure Key Vault, AWS Secrets Manager).

---

## 12. License & University Capstone Statement

Developed for academic demonstration and capstone evaluation in computer science and cybersecurity engineering. All security testing features operate strictly on harmless, controlled inputs within authorized local environments.

