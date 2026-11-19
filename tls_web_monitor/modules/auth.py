"""
Module 1: TLS-Based Secure Communication and Authentication
Implements:
- User login, logout, and registration with Werkzeug password hashing.
- Role-based access control (Admin and User roles).
- Session security and CSRF token generation/verification.
- Route decorators for authentication and role restriction.
- Python ssl.SSLContext configuration for modern TLS/HTTPS.
"""

import ssl
import re
import hmac
import secrets
from functools import wraps
from datetime import datetime, timezone
from flask import (
    Blueprint, render_template, request, redirect,
    url_for, session, flash, g, abort, current_app
)
from werkzeug.security import generate_password_hash, check_password_hash
from database.db import query_db, execute_db

auth_bp = Blueprint("auth", __name__, url_prefix="/auth")


# ------------------------------------------------------------------------------
# 1. TLS Context Configuration
# ------------------------------------------------------------------------------
def build_ssl_context(cert_path: str, key_path: str) -> ssl.SSLContext:
    """
    Creates a secure, hardened Python ssl.SSLContext for HTTPS.
    Enforces TLS 1.2 and TLS 1.3, disables obsolete protocols (SSLv2, SSLv3, TLSv1, TLSv1.1),
    and specifies high-strength modern cipher suites with Perfect Forward Secrecy (PFS).
    """
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)

    # Enforce minimum TLS 1.2, allow TLS 1.3
    if hasattr(ssl, "TLSVersion"):
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2

    # Disable insecure options and compression (mitigate CRIME attack)
    ctx.options |= ssl.OP_NO_COMPRESSION
    if hasattr(ssl, "OP_SINGLE_ECDH_USE"):
        ctx.options |= ssl.OP_SINGLE_ECDH_USE
    if hasattr(ssl, "OP_CIPHER_SERVER_PREFERENCE"):
        ctx.options |= ssl.OP_CIPHER_SERVER_PREFERENCE

    # Set robust modern cipher suites
    CIPHERS = (
        "ECDHE-ECDSA-AES256-GCM-SHA384:"
        "ECDHE-RSA-AES256-GCM-SHA384:"
        "ECDHE-ECDSA-CHACHA20-POLY1305:"
        "ECDHE-RSA-CHACHA20-POLY1305:"
        "ECDHE-ECDSA-AES128-GCM-SHA256:"
        "ECDHE-RSA-AES128-GCM-SHA256"
    )
    ctx.set_ciphers(CIPHERS)
    ctx.load_cert_chain(certfile=cert_path, keyfile=key_path)
    return ctx


# ------------------------------------------------------------------------------
# 2. CSRF Protection
# ------------------------------------------------------------------------------
def generate_csrf_token() -> str:
    """Generates and caches a cryptographically secure CSRF token in the session."""
    if "_csrf_token" not in session:
        session["_csrf_token"] = secrets.token_hex(32)
    return session["_csrf_token"]


def validate_csrf_token(token_from_request: str) -> bool:
    """Validates CSRF token using constant-time comparison to prevent timing attacks."""
    session_token = session.get("_csrf_token")
    if not session_token or not token_from_request:
        return False
    return hmac.compare_digest(session_token, token_from_request)


# ------------------------------------------------------------------------------
# 3. Access Control Decorators (RBAC)
# ------------------------------------------------------------------------------
def get_current_user():
    """Retrieves authenticated user record from database using session user_id."""
    user_id = session.get("user_id")
    if not user_id:
        return None
    if not hasattr(g, "current_user"):
        g.current_user = query_db(
            "SELECT id, username, role, is_active, last_login, created_at FROM users WHERE id = ? AND is_active = 1",
            (user_id,),
            one=True
        )
    return g.current_user


def login_required(f):
    """Decorator requiring a logged-in user session."""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        user = get_current_user()
        if not user:
            flash("Authentication required. Please sign in to access this page.", "warning")
            return redirect(url_for("auth.login", next=request.path))
        return f(*args, **kwargs)
    return decorated_function


def admin_required(f):
    """Decorator requiring an authenticated user with 'admin' role."""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        user = get_current_user()
        if not user:
            flash("Authentication required. Please sign in to access this page.", "warning")
            return redirect(url_for("auth.login", next=request.path))
        if user["role"] != "admin":
            flash("Access Denied: Administrative privileges are required for this action.", "danger")
            abort(403)
        return f(*args, **kwargs)
    return decorated_function


# ------------------------------------------------------------------------------
# 4. Input Validation Helpers
# ------------------------------------------------------------------------------
def validate_username(username: str) -> bool:
    """Validates username: 3-30 chars, alphanumeric plus underscores or hyphens."""
    if not username or not isinstance(username, str):
        return False
    return bool(re.match(r"^[a-zA-Z0-9_\-]{3,30}$", username.strip()))


def validate_password_strength(password: str) -> tuple[bool, str]:
    """Validates password length and complexity."""
    if not password or len(password) < 8:
        return False, "Password must be at least 8 characters long."
    if not re.search(r"[A-Za-z]", password):
        return False, "Password must contain at least one letter."
    if not re.search(r"[0-9]", password):
        return False, "Password must contain at least one digit."
    return True, ""


# ------------------------------------------------------------------------------
# 5. Authentication Routes
# ------------------------------------------------------------------------------
@auth_bp.route("/login", methods=["GET", "POST"])
def login():
    """Handles secure user authentication with brute-force logging."""
    if get_current_user():
        user = get_current_user()
        if user["role"] == "admin":
            return redirect(url_for("admin_dashboard"))
        return redirect(url_for("user_home"))

    if request.method == "POST":
        # Verify CSRF token
        csrf_token = request.form.get("csrf_token", "")
        if not validate_csrf_token(csrf_token):
            flash("Security check failed: Invalid CSRF token. Please try again.", "danger")
            return render_template("login.html"), 400

        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        ip_addr = request.remote_addr or "127.0.0.1"
        now = datetime.now(timezone.utc).isoformat()

        if not username or not password:
            flash("Please provide both username and password.", "warning")
            return render_template("login.html"), 400

        # Query user record securely
        user = query_db(
            "SELECT id, username, password_hash, role, is_active FROM users WHERE username = ?",
            (username,),
            one=True
        )

        login_success = False
        failure_reason = None

        if user and user["is_active"] and check_password_hash(user["password_hash"], password):
            login_success = True
        elif not user:
            failure_reason = "User not found"
        elif not user["is_active"]:
            failure_reason = "Account disabled"
        else:
            failure_reason = "Invalid credentials"

        # Record login attempt in SQLite for threat monitoring
        execute_db(
            "INSERT INTO login_attempts (timestamp, ip_address, username, success, failure_reason) VALUES (?, ?, ?, ?, ?)",
            (now, ip_addr, username, 1 if login_success else 0, failure_reason)
        )

        if login_success:
            # Set up secure session
            session.clear()
            session.permanent = True
            session["user_id"] = user["id"]
            session["username"] = user["username"]
            session["role"] = user["role"]
            generate_csrf_token()

            # Update last login timestamp
            execute_db("UPDATE users SET last_login = ? WHERE id = ?", (now, user["id"]))

            # Tag request for logging
            g.auth_event = "AUTH_LOGIN_SUCCESS"
            g.authenticated_username = user["username"]

            flash(f"Welcome back, {user['username']}! Secure session established.", "success")
            next_url = request.args.get("next")
            if next_url and next_url.startswith("/"):
                return redirect(next_url)
            if user["role"] == "admin":
                return redirect(url_for("admin_dashboard"))
            return redirect(url_for("user_home"))
        else:
            g.auth_event = "AUTH_LOGIN_FAILURE"
            g.attempted_username = username
            flash("Authentication failed. Invalid username or password.", "danger")
            return render_template("login.html"), 401

    return render_template("login.html")


@auth_bp.route("/logout", methods=["POST", "GET"])
def logout():
    """Terminates active session securely."""
    username = session.get("username", "Anonymous")
    g.auth_event = "AUTH_LOGOUT"
    g.authenticated_username = username
    session.clear()
    flash("You have been signed out safely. TLS session cleared.", "info")
    return redirect(url_for("auth.login"))


@auth_bp.route("/register", methods=["GET", "POST"])
def register():
    """User self-registration (assigns standard 'user' role)."""
    if get_current_user():
        return redirect(url_for("user_home"))

    if request.method == "POST":
        csrf_token = request.form.get("csrf_token", "")
        if not validate_csrf_token(csrf_token):
            flash("Security check failed: Invalid CSRF token.", "danger")
            return render_template("register.html"), 400

        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        confirm = request.form.get("confirm_password", "")

        if not validate_username(username):
            flash("Username must be 3-30 characters alphanumeric (letters, numbers, underscores).", "warning")
            return render_template("register.html"), 400

        if password != confirm:
            flash("Passwords do not match.", "warning")
            return render_template("register.html"), 400

        is_valid, msg = validate_password_strength(password)
        if not is_valid:
            flash(msg, "warning")
            return render_template("register.html"), 400

        existing = query_db("SELECT id FROM users WHERE username = ?", (username,), one=True)
        if existing:
            flash("Username is already taken. Please choose another.", "warning")
            return render_template("register.html"), 400

        p_hash = generate_password_hash(password)
        now = datetime.now(timezone.utc).isoformat()
        execute_db(
            "INSERT INTO users (username, password_hash, role, created_at, is_active) VALUES (?, ?, 'user', ?, 1)",
            (username, p_hash, now)
        )
        flash(f"Account for '{username}' created successfully! You can now log in.", "success")
        return redirect(url_for("auth.login"))

    return render_template("register.html")
