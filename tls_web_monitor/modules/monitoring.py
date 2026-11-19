"""
Module 2: Web Application Monitoring and Logging
Implements:
- Automatic request telemetry and performance tracking.
- Parameterized SQLite logging with sensitive data redaction (zero passwords/cookies logged).
- Tamper-evident HMAC signature calculation per log record.
- Searchable and filterable administrative log console with pagination and CSV export.
"""

import time
import io
import csv
import urllib.parse
from datetime import datetime, timezone
from flask import (
    Blueprint, render_template, request, g, session,
    current_app, Response, jsonify, flash, redirect, url_for
)
from database.db import query_db, execute_db
from modules.auth import admin_required, login_required, get_current_user
from modules.integrity import compute_log_hmac, verify_log_integrity

monitoring_bp = Blueprint("monitoring", __name__)

SENSITIVE_PARAM_NAMES = {"password", "pass", "pwd", "secret", "token", "key", "auth", "csrf_token"}


def sanitize_query_string(query_string: str) -> str:
    """Redacts sensitive values (passwords, tokens) from query parameters before logging."""
    if not query_string:
        return ""
    try:
        parsed = urllib.parse.parse_qsl(query_string, keep_blank_values=True)
        sanitized = []
        for k, v in parsed:
            if k.lower() in SENSITIVE_PARAM_NAMES:
                sanitized.append((k, "[REDACTED]"))
            else:
                sanitized.append((k, v))
        return urllib.parse.urlencode(sanitized)
    except Exception:
        return "[UNPARSEABLE_QUERY]"


def record_request_log(response):
    """
    Called in after_request hook to record the request and response in SQLite.
    Computes cryptographic HMAC signature on insertion for tamper-evidence.
    """
    # Prevent duplicate logging in case of redirects or error cascades
    if getattr(g, "request_logged", False):
        return response

    # Skip logging static asset requests (favicons, css, js) to keep audit log focused
    if request.path.startswith("/static/"):
        return response

    g.request_logged = True
    start_time = getattr(g, "start_time", None)
    duration_ms = (time.perf_counter() - start_time) * 1000 if start_time else 0.0

    # Determine Client IP (respecting proxy header if present safely)
    client_ip = request.headers.get("X-Forwarded-For", "").split(",")[0].strip() or request.remote_addr or "127.0.0.1"

    method = request.method
    sanitized_qs = sanitize_query_string(request.query_string.decode("utf-8", errors="replace"))
    path = request.path + (f"?{sanitized_qs}" if sanitized_qs else "")
    status_code = response.status_code

    # Authenticated username
    username = (
        getattr(g, "authenticated_username", None)
        or session.get("username")
        or "Anonymous"
    )

    # Determine event category
    if hasattr(g, "auth_event"):
        event_category = g.auth_event
    elif getattr(g, "threat_detected", False):
        event_category = "SUSPICIOUS_REQUEST"
    elif status_code in (401, 403):
        event_category = "ACCESS_DENIED"
    elif request.path.startswith("/admin") or request.path.startswith("/logs") or request.path.startswith("/alerts"):
        event_category = "ADMIN_ACTION"
    else:
        event_category = "HTTP_REQUEST"

    # Determine risk level
    if getattr(g, "threat_risk_level", None):
        risk_level = g.threat_risk_level
    elif status_code in (401, 403):
        risk_level = "MEDIUM"
    elif status_code >= 500:
        risk_level = "LOW"
    else:
        risk_level = "INFO"

    now_iso = datetime.now(timezone.utc).isoformat()
    integrity_key = current_app.config.get("LOG_INTEGRITY_KEY")

    # Compute tamper-evident HMAC
    hmac_sig = compute_log_hmac(
        timestamp=now_iso,
        ip_address=client_ip,
        method=method,
        path=path,
        status_code=status_code,
        username=username,
        event_category=event_category,
        risk_level=risk_level,
        secret_key=integrity_key
    )

    try:
        execute_db(
            """INSERT INTO request_logs 
               (timestamp, ip_address, method, path, status_code, username, event_category, risk_level, duration_ms, hmac_signature)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (now_iso, client_ip, method, path, status_code, username, event_category, risk_level, round(duration_ms, 2), hmac_sig)
        )
    except Exception as err:
        current_app.logger.error("Failed to write request log: %s", err)

    return response


# ------------------------------------------------------------------------------
# Administrative Log Management Routes
# ------------------------------------------------------------------------------
@monitoring_bp.route("/logs")
@admin_required
def view_logs():
    """Searchable, filterable, and paginated audit logs page for administrators."""
    search = request.args.get("search", "").strip()
    status_filter = request.args.get("status", "").strip()
    risk_filter = request.args.get("risk", "").strip()
    category_filter = request.args.get("category", "").strip()
    ip_filter = request.args.get("ip", "").strip()

    try:
        page = max(1, int(request.args.get("page", 1)))
    except ValueError:
        page = 1
    per_page = 20

    # Build dynamic query safely using parameters
    where_clauses = ["1=1"]
    params = []

    if search:
        where_clauses.append("(path LIKE ? OR username LIKE ? OR ip_address LIKE ?)")
        search_param = f"%{search}%"
        params.extend([search_param, search_param, search_param])

    if status_filter:
        where_clauses.append("status_code = ?")
        params.append(int(status_filter))

    if risk_filter:
        where_clauses.append("risk_level = ?")
        params.append(risk_filter)

    if category_filter:
        where_clauses.append("event_category = ?")
        params.append(category_filter)

    if ip_filter:
        where_clauses.append("ip_address = ?")
        params.append(ip_filter)

    where_sql = " AND ".join(where_clauses)

    # Count total matching rows
    count_row = query_db(
        f"SELECT COUNT(*) as total FROM request_logs WHERE {where_sql}",
        tuple(params),
        one=True
    )
    total_records = count_row["total"] if count_row else 0
    total_pages = max(1, (total_records + per_page - 1) // per_page)

    # Fetch paginated rows
    offset = (page - 1) * per_page
    fetch_params = list(params) + [per_page, offset]
    logs = query_db(
        f"SELECT * FROM request_logs WHERE {where_sql} ORDER BY id DESC LIMIT ? OFFSET ?",
        tuple(fetch_params)
    )

    # Distinct categories and risk levels for dropdown filters
    categories = query_db("SELECT DISTINCT event_category FROM request_logs ORDER BY event_category ASC")
    risk_levels = ["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"]

    return render_template(
        "logs.html",
        logs=logs,
        page=page,
        total_pages=total_pages,
        total_records=total_records,
        search=search,
        status_filter=status_filter,
        risk_filter=risk_filter,
        category_filter=category_filter,
        ip_filter=ip_filter,
        categories=[c["event_category"] for c in categories if c["event_category"]],
        risk_levels=risk_levels
    )


@monitoring_bp.route("/logs/export")
@admin_required
def export_logs_csv():
    """Exports audit logs to CSV for incident response and regulatory reporting."""
    logs = query_db("SELECT id, timestamp, ip_address, method, path, status_code, username, event_category, risk_level, duration_ms, hmac_signature FROM request_logs ORDER BY id DESC")

    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow([
        "Log ID", "Timestamp (UTC)", "Source IP", "Method", "Path",
        "Status Code", "Username", "Event Category", "Risk Level",
        "Duration (ms)", "HMAC Signature"
    ])

    for row in logs:
        writer.writerow([
            row["id"], row["timestamp"], row["ip_address"], row["method"],
            row["path"], row["status_code"], row["username"], row["event_category"],
            row["risk_level"], row["duration_ms"], row["hmac_signature"]
        ])

    filename = f"security_audit_logs_{datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')}.csv"
    return Response(
        output.getvalue(),
        mimetype="text/csv",
        headers={"Content-Disposition": f"attachment; filename={filename}"}
    )


@monitoring_bp.route("/api/audit/verify", methods=["POST"])
@admin_required
def run_integrity_audit():
    """Triggers cryptographic HMAC integrity audit across all stored logs."""
    admin_user = session.get("username", "Administrator")
    result = verify_log_integrity(verified_by=admin_user)
    return jsonify(result)

