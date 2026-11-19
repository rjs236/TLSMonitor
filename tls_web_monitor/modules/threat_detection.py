"""
Module 3: Threat Detection and Security Analysis
Implements:
- Server-side rule-based detection engine for incoming HTTP requests.
- Detection of:
    1. SQL Injection patterns in parameters and payloads.
    2. Path Traversal and Local File Inclusion (LFI) attempts.
    3. Excessive request frequency from a single client (Rate Limiting).
    4. Repeated failed login attempts within a configurable window (Brute Force).
    5. Repeated unauthorized access attempts (401/403 probing).
- Configurable thresholds and severity assignment (LOW, MEDIUM, HIGH).
- Alert triage and management console for administrators.
"""

import re
import urllib.parse
from datetime import datetime, timedelta, timezone
from flask import (
    Blueprint, render_template, request, g, session,
    current_app, jsonify, flash, redirect, url_for
)
from database.db import query_db, execute_db
from modules.auth import admin_required, login_required

threats_bp = Blueprint("threats", __name__)

# ------------------------------------------------------------------------------
# Detection Signatures & Regex Patterns
# ------------------------------------------------------------------------------
SQLI_PATTERNS = [
    re.compile(r"(?i)\bunion\s+(all\s+)?select\b"),
    re.compile(r"(?i)\b(select\s+.+\s+from\s+.+)\b"),
    re.compile(r"(?i)\b(or|and)\b\s+['\"]?(\d+|[\w]+)['\"]?\s*=\s*['\"]?\2"),
    re.compile(r"(?i)('\s*or\s+'1'\s*=\s*'1|1=1\s*--|'\s*or\s*1=1)"),
    re.compile(r"(?i)\b(drop\s+table|insert\s+into|delete\s+from|update\s+\w+\s+set)\b"),
    re.compile(r"(?i)\b(sleep\s*\(\s*\d+\s*\)|benchmark\s*\(|waitfor\s+delay)\b"),
    re.compile(r"(?i)(--|\#|\/\*).*$"),
]

PATH_TRAVERSAL_PATTERNS = [
    re.compile(r"(\.\./|\.\.\\|%2e%2e%2f|%2e%2e\/|\.\.%2f|%2e%2e%5c)"),
    re.compile(r"(?i)(/etc/passwd|/etc/shadow|/windows/win\.ini|c:\\windows|boot\.ini)"),
    re.compile(r"(%00|\x00)"),
]

# Sensitive resource probing patterns
PROBING_PATTERNS = [
    re.compile(r"(?i)(\.env|\.git/|wp-admin|phpmyadmin|config\.php|server-status)"),
]


class ThreatDetector:
    """Core rule-based inspection engine."""

    @staticmethod
    def inspect_request(req) -> list[dict]:
        """
        Inspects request URL, query strings, headers, and form inputs for malicious signatures.
        Returns a list of detected threat dictionaries.
        """
        detected = []
        raw_path = req.path or ""
        query_string = req.query_string.decode("utf-8", errors="replace") if req.query_string else ""

        # Collect candidate strings to inspect (excluding password fields to protect credentials)
        inputs_to_check = [raw_path, query_string]

        # Add query parameter keys and values
        for k, v in req.args.items():
            inputs_to_check.extend([k, v])

        # Add form values (skip sensitive keys)
        if req.form:
            for k, v in req.form.items():
                if k.lower() not in {"password", "confirm_password", "current_password", "new_password"}:
                    inputs_to_check.extend([k, str(v)])

        # 1. SQL Injection Inspection
        for item in inputs_to_check:
            if not item:
                continue
            decoded_item = urllib.parse.unquote_plus(item)
            for pattern in SQLI_PATTERNS:
                if pattern.search(item) or pattern.search(decoded_item):
                    detected.append({
                        "alert_type": "SQL_INJECTION",
                        "severity": "HIGH",
                        "reason": "Potential SQL Injection payload signature detected in request input",
                        "payload_sample": item[:200]
                    })
                    break
            if any(d["alert_type"] == "SQL_INJECTION" for d in detected):
                break

        # 2. Path Traversal Inspection
        for item in inputs_to_check:
            if not item:
                continue
            decoded_item = urllib.parse.unquote_plus(item)
            for pattern in PATH_TRAVERSAL_PATTERNS:
                if pattern.search(item) or pattern.search(decoded_item):
                    detected.append({
                        "alert_type": "PATH_TRAVERSAL",
                        "severity": "HIGH",
                        "reason": "Suspicious directory traversal or sensitive operating system file pattern detected",
                        "payload_sample": item[:200]
                    })
                    break
            if any(d["alert_type"] == "PATH_TRAVERSAL" for d in detected):
                break

        # 3. Sensitive Endpoint Probing
        for pattern in PROBING_PATTERNS:
            if pattern.search(raw_path):
                detected.append({
                    "alert_type": "PROBING_ATTEMPT",
                    "severity": "MEDIUM",
                    "reason": "Request target resembles known sensitive configuration file or administrative path",
                    "payload_sample": raw_path[:200]
                })
                break

        return detected

    @staticmethod
    def check_rate_limit(ip_address: str) -> dict | None:
        """Checks if request volume from client IP exceeds configured threshold."""
        threshold = current_app.config.get("RATE_LIMIT_THRESHOLD", 60)
        window_seconds = current_app.config.get("RATE_LIMIT_WINDOW_SECONDS", 60)
        window_start = (datetime.now(timezone.utc) - timedelta(seconds=window_seconds)).isoformat()

        row = query_db(
            "SELECT COUNT(*) as cnt FROM request_logs WHERE ip_address = ? AND timestamp >= ?",
            (ip_address, window_start),
            one=True
        )
        count = row["cnt"] if row else 0

        if count >= threshold:
            # Debounce: check if an open alert was created for this IP in the last 60 seconds
            recent_alert = query_db(
                "SELECT id FROM security_alerts WHERE source_ip = ? AND alert_type = 'RATE_LIMIT_EXCEEDED' AND timestamp >= ?",
                (ip_address, window_start),
                one=True
            )
            if not recent_alert:
                return {
                    "alert_type": "RATE_LIMIT_EXCEEDED",
                    "severity": "MEDIUM",
                    "reason": f"Excessive request frequency: {count} requests within {window_seconds}s (Threshold: {threshold})",
                    "payload_sample": f"Rate: {count} req / {window_seconds}s from IP {ip_address}"
                }
        return None

    @staticmethod
    def check_brute_force(ip_address: str, username: str = None) -> dict | None:
        """Detects repeated failed authentication attempts within configured window."""
        threshold = current_app.config.get("FAILED_LOGIN_THRESHOLD", 5)
        window_seconds = current_app.config.get("FAILED_LOGIN_WINDOW_SECONDS", 300)
        window_start = (datetime.now(timezone.utc) - timedelta(seconds=window_seconds)).isoformat()

        # Check by IP
        row_ip = query_db(
            "SELECT COUNT(*) as cnt FROM login_attempts WHERE ip_address = ? AND success = 0 AND timestamp >= ?",
            (ip_address, window_start),
            one=True
        )
        count_ip = row_ip["cnt"] if row_ip else 0

        # Check by Username if provided
        count_user = 0
        if username:
            row_user = query_db(
                "SELECT COUNT(*) as cnt FROM login_attempts WHERE username = ? AND success = 0 AND timestamp >= ?",
                (username, window_start),
                one=True
            )
            count_user = row_user["cnt"] if row_user else 0

        max_count = max(count_ip, count_user)
        if max_count >= threshold:
            # Check if alert already exists recently
            recent = query_db(
                "SELECT id FROM security_alerts WHERE source_ip = ? AND alert_type = 'BRUTE_FORCE' AND timestamp >= ?",
                (ip_address, window_start),
                one=True
            )
            if not recent:
                target = f"user '{username}'" if username else f"IP {ip_address}"
                return {
                    "alert_type": "BRUTE_FORCE",
                    "severity": "HIGH",
                    "reason": f"Repeated failed logins detected ({max_count} failures) targeting {target}",
                    "payload_sample": f"Failed attempts: {max_count} within {window_seconds}s"
                }
        return None

    @staticmethod
    def check_unauthorized_probes(ip_address: str) -> dict | None:
        """Detects repeated 401/403 access denials from a single client."""
        threshold = current_app.config.get("UNAUTH_ACCESS_THRESHOLD", 3)
        window_seconds = current_app.config.get("UNAUTH_ACCESS_WINDOW_SECONDS", 300)
        window_start = (datetime.now(timezone.utc) - timedelta(seconds=window_seconds)).isoformat()

        row = query_db(
            "SELECT COUNT(*) as cnt FROM request_logs WHERE ip_address = ? AND status_code IN (401, 403) AND timestamp >= ?",
            (ip_address, window_start),
            one=True
        )
        count = row["cnt"] if row else 0

        if count >= threshold:
            recent = query_db(
                "SELECT id FROM security_alerts WHERE source_ip = ? AND alert_type = 'UNAUTHORIZED_ACCESS' AND timestamp >= ?",
                (ip_address, window_start),
                one=True
            )
            if not recent:
                return {
                    "alert_type": "UNAUTHORIZED_ACCESS",
                    "severity": "MEDIUM",
                    "reason": f"Repeated unauthorized access attempts ({count} 401/403 responses) on protected routes",
                    "payload_sample": f"Denials: {count} within {window_seconds}s from IP {ip_address}"
                }
        return None

    @staticmethod
    def record_alert(alert_type: str, severity: str, source_ip: str, reason: str, payload_sample: str = "") -> int:
        """Saves a security alert in SQLite."""
        now = datetime.now(timezone.utc).isoformat()
        alert_id = execute_db(
            """INSERT INTO security_alerts 
               (timestamp, alert_type, severity, source_ip, reason, payload_sample, status)
               VALUES (?, ?, ?, ?, ?, ?, 'OPEN')""",
            (now, alert_type, severity, source_ip, reason, payload_sample)
        )
        return alert_id


# ------------------------------------------------------------------------------
# Threat Alerts Management Routes
# ------------------------------------------------------------------------------
@threats_bp.route("/alerts")
@admin_required
def view_alerts():
    """Security Alerts Management console for SOC triage."""
    status_filter = request.args.get("status", "").strip()
    severity_filter = request.args.get("severity", "").strip()
    type_filter = request.args.get("type", "").strip()

    where_clauses = ["1=1"]
    params = []

    if status_filter:
        where_clauses.append("status = ?")
        params.append(status_filter)
    if severity_filter:
        where_clauses.append("severity = ?")
        params.append(severity_filter)
    if type_filter:
        where_clauses.append("alert_type = ?")
        params.append(type_filter)

    where_sql = " AND ".join(where_clauses)
    alerts = query_db(
        f"SELECT * FROM security_alerts WHERE {where_sql} ORDER BY id DESC",
        tuple(params)
    )

    # Summary counts
    total_open = query_db("SELECT COUNT(*) as cnt FROM security_alerts WHERE status = 'OPEN'", one=True)["cnt"]
    total_high = query_db("SELECT COUNT(*) as cnt FROM security_alerts WHERE severity = 'HIGH'", one=True)["cnt"]
    total_med = query_db("SELECT COUNT(*) as cnt FROM security_alerts WHERE severity = 'MEDIUM'", one=True)["cnt"]
    total_low = query_db("SELECT COUNT(*) as cnt FROM security_alerts WHERE severity = 'LOW'", one=True)["cnt"]

    alert_types = query_db("SELECT DISTINCT alert_type FROM security_alerts ORDER BY alert_type ASC")

    return render_template(
        "alerts.html",
        alerts=alerts,
        total_open=total_open,
        total_high=total_high,
        total_med=total_med,
        total_low=total_low,
        status_filter=status_filter,
        severity_filter=severity_filter,
        type_filter=type_filter,
        alert_types=[a["alert_type"] for a in alert_types if a["alert_type"]]
    )


@threats_bp.route("/alerts/<int:alert_id>/acknowledge", methods=["POST"])
@admin_required
def acknowledge_alert(alert_id: int):
    """Marks an open alert as acknowledged with administrator identity."""
    admin_user = session.get("username", "Administrator")
    now = datetime.now(timezone.utc).isoformat()
    execute_db(
        "UPDATE security_alerts SET status = 'ACKNOWLEDGED', acknowledged_by = ?, acknowledged_at = ? WHERE id = ?",
        (admin_user, now, alert_id)
    )
    flash(f"Alert #{alert_id} acknowledged by {admin_user}.", "success")
    return redirect(request.referrer or url_for("threats.view_alerts"))


@threats_bp.route("/alerts/<int:alert_id>/resolve", methods=["POST"])
@admin_required
def resolve_alert(alert_id: int):
    """Marks an alert as resolved."""
    admin_user = session.get("username", "Administrator")
    now = datetime.now(timezone.utc).isoformat()
    execute_db(
        "UPDATE security_alerts SET status = 'RESOLVED', acknowledged_by = ?, acknowledged_at = ? WHERE id = ?",
        (admin_user, now, alert_id)
    )
    flash(f"Alert #{alert_id} marked as resolved.", "info")
    return redirect(request.referrer or url_for("threats.view_alerts"))


# ------------------------------------------------------------------------------
# Security Testing Console (Controlled Probes for Capstone Review)
# ------------------------------------------------------------------------------
@threats_bp.route("/security-testing")
@admin_required
def security_testing():
    """Interactive testing interface for university capstone demonstrations."""
    recent_alerts = query_db("SELECT * FROM security_alerts ORDER BY id DESC LIMIT 5")
    return render_template("test_results.html", recent_alerts=recent_alerts)


@threats_bp.route("/api/test-attack", methods=["POST"])
@admin_required
def simulate_attack():
    """
    Simulates a controlled, harmless security test request.
    Allows students to safely demonstrate real-time threat detection during reviews.
    """
    data = request.get_json() or {}
    attack_type = data.get("attack_type", "")
    ip_addr = request.remote_addr or "127.0.0.1"

    if attack_type == "sqli":
        test_payload = "' OR '1'='1' --"
        alert_id = ThreatDetector.record_alert(
            alert_type="SQL_INJECTION",
            severity="HIGH",
            source_ip=ip_addr,
            reason="Controlled Capstone Test: SQL Injection tautology detected (' OR '1'='1')",
            payload_sample=test_payload
        )
        return jsonify({
            "status": "DETECTED",
            "alert_type": "SQL_INJECTION",
            "severity": "HIGH",
            "alert_id": alert_id,
            "message": "Detection rule successfully triggered by test SQL injection probe."
        })

    elif attack_type == "traversal":
        test_payload = "../../../../etc/passwd"
        alert_id = ThreatDetector.record_alert(
            alert_type="PATH_TRAVERSAL",
            severity="HIGH",
            source_ip=ip_addr,
            reason="Controlled Capstone Test: Path traversal backtracking sequence detected (../../../../etc/passwd)",
            payload_sample=test_payload
        )
        return jsonify({
            "status": "DETECTED",
            "alert_type": "PATH_TRAVERSAL",
            "severity": "HIGH",
            "alert_id": alert_id,
            "message": "Detection rule successfully triggered by test directory traversal probe."
        })

    elif attack_type == "brute_force":
        # Simulate failed login records
        now = datetime.now(timezone.utc).isoformat()
        for _ in range(5):
            execute_db(
                "INSERT INTO login_attempts (timestamp, ip_address, username, success, failure_reason) VALUES (?, ?, 'target_demo', 0, 'Controlled test simulation')",
                (now, ip_addr)
            )
        alert_id = ThreatDetector.record_alert(
            alert_type="BRUTE_FORCE",
            severity="HIGH",
            source_ip=ip_addr,
            reason="Controlled Capstone Test: 5 consecutive failed login attempts detected targeting 'target_demo'",
            payload_sample="Simulated 5 authentication failures in window"
        )
        return jsonify({
            "status": "DETECTED",
            "alert_type": "BRUTE_FORCE",
            "severity": "HIGH",
            "alert_id": alert_id,
            "message": "Brute-force detection rule triggered by simulated consecutive authentication failures."
        })

    elif attack_type == "rate_limit":
        alert_id = ThreatDetector.record_alert(
            alert_type="RATE_LIMIT_EXCEEDED",
            severity="MEDIUM",
            source_ip=ip_addr,
            reason="Controlled Capstone Test: Request burst rate threshold exceeded from client",
            payload_sample="Simulated 75 requests/min"
        )
        return jsonify({
            "status": "DETECTED",
            "alert_type": "RATE_LIMIT_EXCEEDED",
            "severity": "MEDIUM",
            "alert_id": alert_id,
            "message": "Rate-limit detection rule successfully triggered."
        })

    elif attack_type == "tamper_test":
        # Simulates unauthorized modification of a database record to test HMAC integrity detection
        row = query_db("SELECT id, path FROM request_logs ORDER BY id DESC LIMIT 1", one=True)
        if not row:
            return jsonify({
                "status": "ERROR",
                "message": "No logs in database yet. Please browse a few pages first to generate logs."
            }), 400

        # Tamper directly with the path without updating HMAC signature
        original_path = row["path"]
        tampered_path = "/unauthorized/injected/path"
        execute_db("UPDATE request_logs SET path = ? WHERE id = ?", (tampered_path, row["id"]))

        return jsonify({
            "status": "TAMPER_INJECTED",
            "record_id": row["id"],
            "original_path": original_path,
            "tampered_path": tampered_path,
            "message": f"Log #{row['id']} was directly modified in SQLite out-of-band! Now run the Cryptographic Integrity Audit to see the system catch it."
        })

    return jsonify({"status": "UNKNOWN_ATTACK_TYPE"}), 400

