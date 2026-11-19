"""
Application Configuration
Encapsulates environment settings, session policies, TLS certificate locations,
and configurable threat detection thresholds.
"""

import os
import secrets
from datetime import timedelta

BASE_DIR = os.path.abspath(os.path.dirname(__file__))


class Config:
    """Base application configuration."""

    # Secret key for session signing and CSRF tokens
    SECRET_KEY = os.environ.get("SECRET_KEY", secrets.token_hex(32))

    # SQLite Database location
    DATABASE_PATH = os.environ.get(
        "DATABASE_PATH",
        os.path.join(BASE_DIR, "tls_security.db")
    )

    # Session & Cookie Security
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = "Lax"
    SESSION_COOKIE_SECURE = os.environ.get("SESSION_COOKIE_SECURE", "False").lower() in ("true", "1")
    PERMANENT_SESSION_LIFETIME = timedelta(hours=2)

    # TLS Paths (Local self-signed development certificates)
    TLS_CERT_PATH = os.environ.get(
        "TLS_CERT_PATH",
        os.path.join(BASE_DIR, "certs", "cert.pem")
    )
    TLS_KEY_PATH = os.environ.get(
        "TLS_KEY_PATH",
        os.path.join(BASE_DIR, "certs", "key.pem")
    )

    # Log Integrity HMAC Secret Key
    LOG_INTEGRITY_KEY = os.environ.get(
        "LOG_INTEGRITY_KEY",
        "default-hmac-dev-key-7f9a1b2c3d4e5f6a7b8c9d0e1f2a3b4c"
    )

    # Threat Detection Engine Configurable Thresholds
    # 1. Failed Logins: Flag brute force after N failures within window seconds
    FAILED_LOGIN_THRESHOLD = int(os.environ.get("FAILED_LOGIN_THRESHOLD", 5))
    FAILED_LOGIN_WINDOW_SECONDS = int(os.environ.get("FAILED_LOGIN_WINDOW_SECONDS", 300))

    # 2. Rate Limiting: Flag high-frequency request bursts from single IP
    RATE_LIMIT_THRESHOLD = int(os.environ.get("RATE_LIMIT_THRESHOLD", 60))
    RATE_LIMIT_WINDOW_SECONDS = int(os.environ.get("RATE_LIMIT_WINDOW_SECONDS", 60))

    # 3. Repeated Unauthorized Access Probes (401/403)
    UNAUTH_ACCESS_THRESHOLD = int(os.environ.get("UNAUTH_ACCESS_THRESHOLD", 3))
    UNAUTH_ACCESS_WINDOW_SECONDS = int(os.environ.get("UNAUTH_ACCESS_WINDOW_SECONDS", 300))

    # Application Metadata
    APP_NAME = "TLS-Based Secure Web Application Monitoring and Threat Detection System"
    APP_VERSION = "1.0.0-University-Capstone"


class DevelopmentConfig(Config):
    """Development configuration with debugging enabled."""
    DEBUG = True


class TestingConfig(Config):
    """Testing configuration with in-memory or isolated database."""
    TESTING = True
    DATABASE_PATH = os.path.join(BASE_DIR, "test_tls_security.db")
    SESSION_COOKIE_SECURE = False
    FAILED_LOGIN_THRESHOLD = 3
    FAILED_LOGIN_WINDOW_SECONDS = 60
    RATE_LIMIT_THRESHOLD = 15
    RATE_LIMIT_WINDOW_SECONDS = 30
    UNAUTH_ACCESS_THRESHOLD = 2
    UNAUTH_ACCESS_WINDOW_SECONDS = 60


class ProductionConfig(Config):
    """Production configuration enforcing HTTPS and strict cookies."""
    DEBUG = False
    SESSION_COOKIE_SECURE = True

