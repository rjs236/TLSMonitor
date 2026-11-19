"""
Pytest Fixtures and Shared Test Configuration.
Provides isolated SQLite test databases, Flask test clients, and session helpers.
"""

import os
import sys
import tempfile
import pytest

# Ensure project root is on sys.path
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from app import create_app
from config import TestingConfig
from database.db import init_db, execute_db
from werkzeug.security import generate_password_hash
from datetime import datetime, timezone


@pytest.fixture
def app():
    """Creates a clean, isolated Flask application instance with a temporary SQLite database."""
    db_fd, db_path = tempfile.mkstemp(suffix=".db")
    os.close(db_fd)

    class CustomTestingConfig(TestingConfig):
        DATABASE_PATH = db_path
        TESTING = True
        SECRET_KEY = "test-secret-key-32bytes-for-session-testing!"
        LOG_INTEGRITY_KEY = "test-hmac-key-32bytes-for-integrity!"
        WTF_CSRF_ENABLED = False
        FAILED_LOGIN_THRESHOLD = 3
        FAILED_LOGIN_WINDOW_SECONDS = 60
        RATE_LIMIT_THRESHOLD = 10
        RATE_LIMIT_WINDOW_SECONDS = 30
        UNAUTH_ACCESS_THRESHOLD = 2
        UNAUTH_ACCESS_WINDOW_SECONDS = 60

    app = create_app(CustomTestingConfig)

    with app.app_context():
        init_db(db_path=db_path)

        # Seed standard test admin and test user
        now = datetime.now(timezone.utc).isoformat()
        admin_hash = generate_password_hash("AdminPass123!")
        user_hash = generate_password_hash("UserPass123!")

        execute_db(
            "INSERT INTO users (username, password_hash, role, created_at, is_active) VALUES (?, ?, 'admin', ?, 1)",
            ("admin_test", admin_hash, now),
            db_path=db_path
        )
        execute_db(
            "INSERT INTO users (username, password_hash, role, created_at, is_active) VALUES (?, ?, 'user', ?, 1)",
            ("user_test", user_hash, now),
            db_path=db_path
        )

    yield app

    # Cleanup temp database
    try:
        if os.path.exists(db_path):
            os.remove(db_path)
    except Exception:
        pass


@pytest.fixture
def client(app):
    """Flask test client."""
    return app.test_client()


def login_client(client, username, password):
    """Helper to authenticate a test client session with CSRF handling."""
    # Obtain CSRF token from login page
    resp = client.get("/auth/login")
    with client.session_transaction() as sess:
        csrf_token = sess.get("_csrf_token", "")

    return client.post("/auth/login", data={
        "username": username,
        "password": password,
        "csrf_token": csrf_token
    }, follow_redirects=True)

