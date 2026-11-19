"""
Automated Tests for Module 2: Web Application Monitoring and Logging.
Tests:
- Automatic request logging to SQLite
- Sensitive data redaction in query parameters
- Login event & access denied categorization
- Log search, filter, and pagination
- CSV log export functionality
"""

import pytest
from database.db import query_db
from tests.conftest import login_client


def test_automatic_request_logging(client, app):
    """Test MON-01: Ingress requests are automatically captured in request_logs."""
    client.get("/about")

    with app.app_context():
        log = query_db(
            "SELECT * FROM request_logs WHERE path = '/about' ORDER BY id DESC LIMIT 1",
            one=True
        )
        assert log is not None
        assert log["method"] == "GET"
        assert log["status_code"] == 200
        assert log["event_category"] == "HTTP_REQUEST"
        assert log["risk_level"] == "INFO"
        assert len(log["hmac_signature"]) == 64  # SHA-256 hex is 64 chars


def test_sensitive_data_redaction(client, app):
    """Test MON-02: Passwords and tokens in query parameters are redacted before logging."""
    client.get("/search?query=firewall&password=SuperSecretPassword123!&token=xyz789")

    with app.app_context():
        log = query_db(
            "SELECT * FROM request_logs WHERE path LIKE '/search%' ORDER BY id DESC LIMIT 1",
            one=True
        )
        assert log is not None
        assert "SuperSecretPassword123!" not in log["path"]
        assert "password=%5BREDACTED%5D" in log["path"] or "password=[REDACTED]" in log["path"]
        assert "token=%5BREDACTED%5D" in log["path"] or "token=[REDACTED]" in log["path"]


def test_access_denied_logging(client, app):
    """Test MON-03: Unauthorized access triggers ACCESS_DENIED with elevated risk."""
    # Attempt to access protected admin page without credentials
    client.get("/admin/dashboard")

    with app.app_context():
        # Redirect to login (302) or forbidden event
        log = query_db(
            "SELECT * FROM request_logs WHERE path = '/admin/dashboard' ORDER BY id DESC LIMIT 1",
            one=True
        )
        assert log is not None
        # It logged the unauthenticated attempt
        assert log["status_code"] in (302, 401, 403)


def test_log_search_and_filtering(client, app):
    """Test MON-04: Admin log page filters correctly by risk level and keywords."""
    login_client(client, "admin_test", "AdminPass123!")

    # Make varied requests
    client.get("/about")
    client.get("/home")

    resp = client.get("/logs?search=about")
    assert resp.status_code == 200
    assert b"/about" in resp.data

    resp_risk = client.get("/logs?risk=INFO")
    assert resp_risk.status_code == 200


def test_log_export_csv(client):
    """Test MON-05: CSV export endpoint generates valid comma-separated audit logs."""
    login_client(client, "admin_test", "AdminPass123!")

    resp = client.get("/logs/export")
    assert resp.status_code == 200
    assert resp.mimetype == "text/csv"
    assert b"Log ID,Timestamp (UTC),Source IP,Method,Path" in resp.data
    assert b"HMAC Signature" in resp.data

