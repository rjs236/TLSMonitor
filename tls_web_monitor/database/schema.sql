-- ==============================================================================
-- TLS-Based Secure Web Application Monitoring and Threat Detection System
-- SQLite Relational Database Schema
-- ==============================================================================

PRAGMA foreign_keys = ON;

-- ------------------------------------------------------------------------------
-- Table 1: Users (Role-Based Access Control)
-- ------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL COLLATE NOCASE,
    password_hash TEXT NOT NULL,
    role TEXT NOT NULL DEFAULT 'user' CHECK (role IN ('admin', 'user')),
    created_at TEXT NOT NULL,
    last_login TEXT,
    is_active INTEGER NOT NULL DEFAULT 1 CHECK (is_active IN (0, 1))
);

CREATE INDEX IF NOT EXISTS idx_users_username ON users(username);
CREATE INDEX IF NOT EXISTS idx_users_role ON users(role);

-- ------------------------------------------------------------------------------
-- Table 2: Login Attempts (Tracking for Brute-Force & Credential Stuffing Detection)
-- ------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS login_attempts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp TEXT NOT NULL,
    ip_address TEXT NOT NULL,
    username TEXT NOT NULL,
    success INTEGER NOT NULL DEFAULT 0 CHECK (success IN (0, 1)),
    failure_reason TEXT
);

CREATE INDEX IF NOT EXISTS idx_login_attempts_ip_time ON login_attempts(ip_address, timestamp);
CREATE INDEX IF NOT EXISTS idx_login_attempts_user_time ON login_attempts(username, timestamp);
CREATE INDEX IF NOT EXISTS idx_login_attempts_timestamp ON login_attempts(timestamp);

-- ------------------------------------------------------------------------------
-- Table 3: Request Logs (SIEM & Continuous Web Application Monitoring)
-- ------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS request_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp TEXT NOT NULL,
    ip_address TEXT NOT NULL,
    method TEXT NOT NULL,
    path TEXT NOT NULL,
    status_code INTEGER NOT NULL,
    username TEXT DEFAULT 'Anonymous',
    event_category TEXT NOT NULL DEFAULT 'HTTP_REQUEST',
    risk_level TEXT NOT NULL DEFAULT 'INFO' CHECK (risk_level IN ('INFO', 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL')),
    duration_ms REAL DEFAULT 0.0,
    hmac_signature TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_request_logs_timestamp ON request_logs(timestamp);
CREATE INDEX IF NOT EXISTS idx_request_logs_ip ON request_logs(ip_address);
CREATE INDEX IF NOT EXISTS idx_request_logs_status ON request_logs(status_code);
CREATE INDEX IF NOT EXISTS idx_request_logs_risk ON request_logs(risk_level);
CREATE INDEX IF NOT EXISTS idx_request_logs_category ON request_logs(event_category);
CREATE INDEX IF NOT EXISTS idx_request_logs_username ON request_logs(username);

-- ------------------------------------------------------------------------------
-- Table 4: Security Alerts (Autonomous Rule-Based Threat Detection Output)
-- ------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS security_alerts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp TEXT NOT NULL,
    alert_type TEXT NOT NULL,
    severity TEXT NOT NULL CHECK (severity IN ('LOW', 'MEDIUM', 'HIGH')),
    source_ip TEXT NOT NULL,
    reason TEXT NOT NULL,
    payload_sample TEXT,
    status TEXT NOT NULL DEFAULT 'OPEN' CHECK (status IN ('OPEN', 'ACKNOWLEDGED', 'RESOLVED')),
    acknowledged_by TEXT,
    acknowledged_at TEXT
);

CREATE INDEX IF NOT EXISTS idx_security_alerts_timestamp ON security_alerts(timestamp);
CREATE INDEX IF NOT EXISTS idx_security_alerts_status ON security_alerts(status);
CREATE INDEX IF NOT EXISTS idx_security_alerts_severity ON security_alerts(severity);
CREATE INDEX IF NOT EXISTS idx_security_alerts_ip ON security_alerts(source_ip);
CREATE INDEX IF NOT EXISTS idx_security_alerts_type ON security_alerts(alert_type);

-- ------------------------------------------------------------------------------
-- Table 5: Audit Integrity (Cryptographic Tamper-Evidence Verification History)
-- ------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS audit_integrity (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp TEXT NOT NULL,
    records_audited INTEGER NOT NULL,
    tampered_records_found INTEGER NOT NULL,
    status TEXT NOT NULL CHECK (status IN ('VERIFIED', 'TAMPER_DETECTED', 'EMPTY')),
    details TEXT,
    verified_by TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_audit_integrity_timestamp ON audit_integrity(timestamp);
CREATE INDEX IF NOT EXISTS idx_audit_integrity_status ON audit_integrity(status);

