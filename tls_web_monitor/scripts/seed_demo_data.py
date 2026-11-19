"""
Optional Demo Data Seeding Script for Capstone Reviews.
Populates SQLite with realistic demonstration data:
- Standard user (demo_user) and administrator (admin)
- Realistic historical request logs with cryptographically valid HMAC signatures
- Realistic threat alerts (SQLi, Brute Force, Rate Limit, Directory Traversal)
- A historical integrity audit record
All data is clearly identified for demonstration purposes.
"""

import os
import sys
from datetime import datetime, timedelta, timezone
from werkzeug.security import generate_password_hash

# Ensure project root is on sys.path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from database.db import init_db, query_db, execute_db
from modules.integrity import compute_log_hmac


def seed_demo_data(db_path: str = None):
    """Seeds realistic demonstration data."""
    init_db(db_path=db_path)
    print("[*] Initializing and seeding demo records...")

    now = datetime.now(timezone.utc)

    # 1. Seed Users
    users_to_seed = [
        ("admin", "AdminPass123!", "admin"),
        ("demo_user", "UserPass123!", "user"),
        ("analyst_jane", "JanePass123!", "user"),
    ]

    for username, password, role in users_to_seed:
        existing = query_db("SELECT id FROM users WHERE username = ?", (username,), one=True, db_path=db_path)
        if not existing:
            p_hash = generate_password_hash(password)
            created_at = (now - timedelta(days=5)).isoformat()
            execute_db(
                "INSERT INTO users (username, password_hash, role, created_at, is_active) VALUES (?, ?, ?, ?, 1)",
                (username, p_hash, role, created_at),
                db_path=db_path
            )
            print(f"[+] Created demo user: {username} ({role})")

    # 2. Seed Realistic Historical Request Logs with Valid HMACs
    demo_requests = [
        (now - timedelta(minutes=65), "192.168.1.105", "GET", "/", 200, "Anonymous", "HTTP_REQUEST", "INFO", 12.4),
        (now - timedelta(minutes=60), "192.168.1.105", "GET", "/auth/login", 200, "Anonymous", "HTTP_REQUEST", "INFO", 8.1),
        (now - timedelta(minutes=58), "192.168.1.105", "POST", "/auth/login", 200, "demo_user", "AUTH_LOGIN_SUCCESS", "INFO", 45.2),
        (now - timedelta(minutes=55), "192.168.1.105", "GET", "/home", 200, "demo_user", "HTTP_REQUEST", "INFO", 15.6),
        (now - timedelta(minutes=50), "192.168.1.105", "GET", "/admin/dashboard", 403, "demo_user", "ACCESS_DENIED", "MEDIUM", 6.8),
        (now - timedelta(minutes=45), "203.0.113.42", "POST", "/auth/login", 401, "Anonymous", "AUTH_LOGIN_FAILURE", "LOW", 38.0),
        (now - timedelta(minutes=44), "203.0.113.42", "POST", "/auth/login", 401, "Anonymous", "AUTH_LOGIN_FAILURE", "LOW", 36.5),
        (now - timedelta(minutes=43), "203.0.113.42", "POST", "/auth/login", 401, "Anonymous", "AUTH_LOGIN_FAILURE", "LOW", 37.1),
        (now - timedelta(minutes=42), "203.0.113.42", "POST", "/auth/login", 401, "Anonymous", "AUTH_LOGIN_FAILURE", "LOW", 39.2),
        (now - timedelta(minutes=41), "203.0.113.42", "POST", "/auth/login", 401, "Anonymous", "AUTH_LOGIN_FAILURE", "LOW", 35.8),
        (now - timedelta(minutes=30), "198.51.100.27", "GET", "/search?q=%27+OR+%271%27%3D%271", 200, "Anonymous", "SUSPICIOUS_REQUEST", "HIGH", 18.2),
        (now - timedelta(minutes=25), "198.51.100.27", "GET", "/files?doc=../../../../etc/passwd", 200, "Anonymous", "SUSPICIOUS_REQUEST", "HIGH", 14.7),
        (now - timedelta(minutes=15), "127.0.0.1", "POST", "/auth/login", 200, "admin", "AUTH_LOGIN_SUCCESS", "INFO", 42.1),
        (now - timedelta(minutes=14), "127.0.0.1", "GET", "/admin/dashboard", 200, "admin", "ADMIN_ACTION", "INFO", 22.3),
        (now - timedelta(minutes=10), "127.0.0.1", "GET", "/logs", 200, "admin", "ADMIN_ACTION", "INFO", 31.0),
        (now - timedelta(minutes=5), "127.0.0.1", "GET", "/alerts", 200, "admin", "ADMIN_ACTION", "INFO", 25.4),
    ]

    for ts, ip, method, path, status_code, username, category, risk, dur in demo_requests:
        ts_iso = ts.isoformat()
        hmac_sig = compute_log_hmac(
            timestamp=ts_iso,
            ip_address=ip,
            method=method,
            path=path,
            status_code=status_code,
            username=username,
            event_category=category,
            risk_level=risk
        )
        execute_db(
            """INSERT INTO request_logs 
               (timestamp, ip_address, method, path, status_code, username, event_category, risk_level, duration_ms, hmac_signature)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (ts_iso, ip, method, path, status_code, username, category, risk, dur, hmac_sig),
            db_path=db_path
        )
    print(f"[+] Inserted {len(demo_requests)} realistic audit request logs with HMAC signatures.")

    # 3. Seed Realistic Threat Alerts
    demo_alerts = [
        (
            (now - timedelta(minutes=40)).isoformat(),
            "BRUTE_FORCE",
            "HIGH",
            "203.0.113.42",
            "Repeated failed logins detected (5 failures) targeting user 'admin'",
            "Simulated 5 authentication failures in window",
            "ACKNOWLEDGED",
            "admin",
            (now - timedelta(minutes=12)).isoformat()
        ),
        (
            (now - timedelta(minutes=30)).isoformat(),
            "SQL_INJECTION",
            "HIGH",
            "198.51.100.27",
            "Potential SQL Injection payload signature detected in request input",
            "' OR '1'='1' --",
            "OPEN",
            None,
            None
        ),
        (
            (now - timedelta(minutes=25)).isoformat(),
            "PATH_TRAVERSAL",
            "HIGH",
            "198.51.100.27",
            "Suspicious directory traversal or sensitive operating system file pattern detected",
            "../../../../etc/passwd",
            "OPEN",
            None,
            None
        ),
        (
            (now - timedelta(minutes=20)).isoformat(),
            "RATE_LIMIT_EXCEEDED",
            "MEDIUM",
            "198.51.100.27",
            "Excessive request frequency: 82 requests within 60s (Threshold: 60)",
            "Rate: 82 req / 60s from IP 198.51.100.27",
            "OPEN",
            None,
            None
        ),
    ]

    for ts, a_type, sev, ip, reason, sample, status, ack_by, ack_at in demo_alerts:
        execute_db(
            """INSERT INTO security_alerts 
               (timestamp, alert_type, severity, source_ip, reason, payload_sample, status, acknowledged_by, acknowledged_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (ts, a_type, sev, ip, reason, sample, status, ack_by, ack_at),
            db_path=db_path
        )
    print(f"[+] Inserted {len(demo_alerts)} demonstration security alerts.")

    # 4. Seed Audit Integrity Entry
    audit_ts = (now - timedelta(minutes=8)).isoformat()
    execute_db(
        """INSERT INTO audit_integrity 
           (timestamp, records_audited, tampered_records_found, status, details, verified_by)
           VALUES (?, ?, ?, 'VERIFIED', 'All demo logs cryptographically verified with zero mismatches.', 'admin')""",
        (audit_ts, len(demo_requests), 0),
        db_path=db_path
    )
    print(f"[+] Seeded baseline audit integrity checkpoint.")
    print("[+] Seeding complete! Database ready for university demonstration.")


if __name__ == "__main__":
    seed_demo_data()

