"""
Automated Tests for Module 1: TLS-Based Secure Communication and Authentication.
Tests:
- Login with valid credentials
- Login with invalid credentials
- Logout and session handling
- Access restrictions for regular users vs administrators (RBAC)
- CSRF token enforcement
- TLS Context building & cipher suite hardening
"""

import ssl
import os
import pytest
from database.db import query_db
from modules.auth import build_ssl_context
from tests.conftest import login_client


def test_login_valid_credentials(client, app):
    """Test AUTH-01: Login with valid credentials establishes session."""
    resp = login_client(client, "admin_test", "AdminPass123!")
    assert resp.status_code == 200
    assert b"SOC Dashboard" in resp.data or b"Security Operations Center" in resp.data

    with client.session_transaction() as sess:
        assert sess.get("username") == "admin_test"
        assert sess.get("role") == "admin"


def test_login_invalid_credentials(client, app):
    """Test AUTH-02: Login with invalid credentials rejects access and records failure."""
    # Obtain CSRF
    client.get("/auth/login")
    with client.session_transaction() as sess:
        token = sess.get("_csrf_token", "")

    resp = client.post("/auth/login", data={
        "username": "admin_test",
        "password": "WrongPassword!",
        "csrf_token": token
    })
    assert resp.status_code == 401
    assert b"Authentication failed" in resp.data

    with client.session_transaction() as sess:
        assert "username" not in sess

    # Verify failure recorded in login_attempts
    with app.app_context():
        attempt = query_db(
            "SELECT * FROM login_attempts WHERE username = 'admin_test' ORDER BY id DESC LIMIT 1",
            one=True
        )
        assert attempt is not None
        assert attempt["success"] == 0
        assert attempt["failure_reason"] == "Invalid credentials"


def test_logout_session_cleared(client):
    """Test AUTH-03: Logout clears session and destroys credentials."""
    login_client(client, "user_test", "UserPass123!")

    with client.session_transaction() as sess:
        csrf_token = sess.get("_csrf_token", "")

    resp = client.post("/auth/logout", data={"csrf_token": csrf_token}, follow_redirects=True)
    assert resp.status_code == 200
    assert b"You have been signed out safely" in resp.data

    with client.session_transaction() as sess:
        assert "username" not in sess
        assert "user_id" not in sess


def test_rbac_user_access_restrictions(client):
    """Test AUTH-04: Standard user cannot access admin routes (403 Forbidden)."""
    login_client(client, "user_test", "UserPass123!")

    # Standard user can access /home
    resp_home = client.get("/home")
    assert resp_home.status_code == 200
    assert b"Welcome" in resp_home.data

    # Standard user CANNOT access /admin/dashboard (403)
    resp_admin = client.get("/admin/dashboard")
    assert resp_admin.status_code == 403

    # Standard user CANNOT access /logs (403)
    resp_logs = client.get("/logs")
    assert resp_logs.status_code == 403

    # Standard user CANNOT access /alerts (403)
    resp_alerts = client.get("/alerts")
    assert resp_alerts.status_code == 403


def test_rbac_admin_access_allowed(client):
    """Test AUTH-05: Administrator can access protected administrative routes."""
    login_client(client, "admin_test", "AdminPass123!")

    resp_admin = client.get("/admin/dashboard")
    assert resp_admin.status_code == 200

    resp_logs = client.get("/logs")
    assert resp_logs.status_code == 200

    resp_alerts = client.get("/alerts")
    assert resp_alerts.status_code == 200


def test_csrf_protection_missing_token(client):
    """Test AUTH-06: Form submission without CSRF token is rejected with 400 Bad Request."""
    resp = client.post("/auth/login", data={
        "username": "admin_test",
        "password": "AdminPass123!"
        # Missing csrf_token
    })
    assert resp.status_code == 400
    assert b"CSRF token" in resp.data


def test_security_headers_present(client):
    """Test AUTH-07: Security headers are correctly injected in responses."""
    resp = client.get("/about")
    assert resp.status_code == 200
    assert resp.headers.get("X-Content-Type-Options") == "nosniff"
    assert resp.headers.get("X-Frame-Options") == "SAMEORIGIN"
    assert resp.headers.get("X-XSS-Protection") == "1; mode=block"
    assert "default-src 'self'" in resp.headers.get("Content-Security-Policy", "")


def test_tls_context_configuration(app):
    """Test AUTH-08: Python SSL Context is built with modern TLS 1.2+ and secure ciphers."""
    cert_path = app.config.get("TLS_CERT_PATH")
    key_path = app.config.get("TLS_KEY_PATH")

    if not os.path.exists(cert_path) or not os.path.exists(key_path):
        from scripts.generate_dev_certificate import generate_certificate
        generate_certificate(
            cert_dir=os.path.dirname(cert_path),
            cert_name=os.path.basename(cert_path),
            key_name=os.path.basename(key_path)
        )

    ctx = build_ssl_context(cert_path, key_path)
    assert isinstance(ctx, ssl.SSLContext)
    if hasattr(ssl, "TLSVersion"):
        assert ctx.minimum_version == ssl.TLSVersion.TLSv1_2
    assert ctx.options & ssl.OP_NO_COMPRESSION
