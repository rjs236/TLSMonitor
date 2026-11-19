"""
Automated Tests for Module 3: Threat Detection and Security Analysis.
Tests:
- SQL injection signature detection and alert generation
- Path traversal signature detection and alert generation
- Rate-limit burst detection
- Brute-force failed login threshold detection
- Alert acknowledgement and status triage
"""

import pytest
from database.db import query_db, execute_db
from modules.threat_detection import ThreatDetector
from tests.conftest import login_client


def test_sql_injection_detection(client, app):
    """Test THR-01: SQL injection tautology in query string triggers HIGH-severity alert."""
    # Send harmless controlled test payload
    client.get("/about?id=1%20OR%201=1")

    with app.app_context():
        alert = query_db(
            "SELECT * FROM security_alerts WHERE alert_type = 'SQL_INJECTION' ORDER BY id DESC LIMIT 1",
            one=True
        )
        assert alert is not None
        assert alert["severity"] == "HIGH"
        assert alert["status"] == "OPEN"
        assert "SQL Injection" in alert["reason"]


def test_path_traversal_detection(client, app):
    """Test THR-02: Path traversal backtracking triggers HIGH-severity alert."""
    # Send harmless controlled traversal string
    client.get("/about?file=../../../../etc/passwd")

    with app.app_context():
        alert = query_db(
            "SELECT * FROM security_alerts WHERE alert_type = 'PATH_TRAVERSAL' ORDER BY id DESC LIMIT 1",
            one=True
        )
        assert alert is not None
        assert alert["severity"] == "HIGH"
        assert alert["status"] == "OPEN"
        assert "directory traversal" in alert["reason"].lower()


def test_brute_force_failed_login_detection(client, app):
    """Test THR-03: Repeated consecutive failed logins trigger BRUTE_FORCE alert."""
    # Client attempts 3 failed logins (the configured threshold in TestingConfig is 3)
    client.get("/auth/login")
    with client.session_transaction() as sess:
        token = sess.get("_csrf_token", "")

    for _ in range(3):
        client.post("/auth/login", data={
            "username": "victim_user",
            "password": "WrongPassword123!",
            "csrf_token": token
        })

    with app.app_context():
        alert = ThreatDetector.check_brute_force("127.0.0.1", "victim_user")
        assert alert is not None
        assert alert["alert_type"] == "BRUTE_FORCE"
        assert alert["severity"] == "HIGH"


def test_rate_limit_detection(client, app):
    """Test THR-04: High frequency requests trigger RATE_LIMIT_EXCEEDED alert."""
    # Send rapid requests exceeding TestingConfig threshold (10 req)
    for _ in range(12):
        client.get("/about")

    with app.app_context():
        alert = query_db(
            "SELECT * FROM security_alerts WHERE alert_type = 'RATE_LIMIT_EXCEEDED' ORDER BY id DESC LIMIT 1",
            one=True
        )
        assert alert is not None
        assert alert["alert_type"] == "RATE_LIMIT_EXCEEDED"
        assert alert["severity"] == "MEDIUM"


def test_alert_acknowledgement_triage(client, app):
    """Test THR-05: Administrator can acknowledge open alerts."""
    login_client(client, "admin_test", "AdminPass123!")

    # Seed an open alert
    with app.app_context():
        alert_id = execute_db(
            """INSERT INTO security_alerts 
               (timestamp, alert_type, severity, source_ip, reason, payload_sample, status)
               VALUES ('2026-11-17T00:00:00', 'SQL_INJECTION', 'HIGH', '127.0.0.1', 'Test reason', 'test payload', 'OPEN')"""
        )

    with client.session_transaction() as sess:
        csrf_token = sess.get("_csrf_token", "")

    resp = client.post(f"/alerts/{alert_id}/acknowledge", data={"csrf_token": csrf_token}, follow_redirects=True)
    assert resp.status_code == 200

    with app.app_context():
        updated = query_db("SELECT status, acknowledged_by FROM security_alerts WHERE id = ?", (alert_id,), one=True)
        assert updated["status"] == "ACKNOWLEDGED"
        assert updated["acknowledged_by"] == "admin_test"


def test_dashboard_statistics_match_database(client, app):
    """Test THR-06: Dashboard metrics reflect real SQLite database records."""
    login_client(client, "admin_test", "AdminPass123!")

    resp = client.get("/api/dashboard/stats")
    assert resp.status_code == 200
    data = resp.get_json()

    with app.app_context():
        actual_requests = query_db("SELECT COUNT(*) as cnt FROM request_logs", one=True)["cnt"]
        actual_open_alerts = query_db("SELECT COUNT(*) as cnt FROM security_alerts WHERE status = 'OPEN'", one=True)["cnt"]

    assert data["total_requests"] in (actual_requests, actual_requests - 1)
    assert data["open_alerts"] == actual_open_alerts
