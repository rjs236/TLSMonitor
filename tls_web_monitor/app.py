"""
TLS-Based Secure Web Application Monitoring and Threat Detection System
Main Application Entry Point and Flask Factory.

Combines:
- Module 1: TLS/HTTPS Security, Authentication, RBAC, Sessions, and CSRF Protection
- Module 2: Request Telemetry, Sensitive Data Redaction, SQLite Logging, HMAC Integrity
- Module 3: Rule-Based Threat Detection (SQLi, Traversal, Brute Force, Rate Limiting)
- SOC Management Dashboard and Testing Console
"""

import os
import sys
import time
import argparse
from datetime import datetime, timezone
from flask import (
    Flask, render_template, request, redirect,
    url_for, session, g, jsonify, flash, abort
)

from config import Config, DevelopmentConfig, ProductionConfig
from database.db import get_db, close_db, init_db, query_db, execute_db
from modules.auth import (
    auth_bp, build_ssl_context, login_required,
    admin_required, get_current_user, generate_csrf_token
)
from modules.monitoring import monitoring_bp, record_request_log
from modules.threat_detection import threats_bp, ThreatDetector
from modules.integrity import verify_log_integrity


def create_app(config_class=DevelopmentConfig):
    """Flask application factory."""
    app = Flask(__name__)
    app.config.from_object(config_class)

    # Ensure database is initialized
    with app.app_context():
        init_db(app=app)

    # Register teardown function for database connections
    app.teardown_appcontext(close_db)

    # Register Blueprints
    app.register_blueprint(auth_bp)
    app.register_blueprint(monitoring_bp)
    app.register_blueprint(threats_bp)

    # --------------------------------------------------------------------------
    # Template Context Processors
    # --------------------------------------------------------------------------
    @app.context_processor
    def inject_global_template_vars():
        return {
            "current_user": get_current_user(),
            "csrf_token": generate_csrf_token,
            "app_name": app.config.get("APP_NAME", "TLS Secure Monitor"),
            "app_version": app.config.get("APP_VERSION", "1.0.0"),
            "is_https": request.is_secure or request.scheme == "https"
        }

    # --------------------------------------------------------------------------
    # Security Headers & Response Hooks
    # --------------------------------------------------------------------------
    @app.after_request
    def set_security_headers(response):
        """Injects enterprise-grade HTTP security headers."""
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "SAMEORIGIN"
        response.headers["X-XSS-Protection"] = "1; mode=block"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"

        # Content Security Policy (allows local assets, Google Fonts, and Chart.js CDN)
        csp = (
            "default-src 'self'; "
            "script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; "
            "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com https://cdn.jsdelivr.net; "
            "font-src 'self' https://fonts.gstatic.com; "
            "img-src 'self' data:; "
            "connect-src 'self';"
        )
        response.headers["Content-Security-Policy"] = csp

        # Strict-Transport-Security (HSTS) when operating over HTTPS
        if request.is_secure or request.headers.get("X-Forwarded-Proto") == "https":
            response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"

        # Record audit log in SQLite with HMAC
        return record_request_log(response)

    # --------------------------------------------------------------------------
    # Threat Detection Hooks (before_request)
    # --------------------------------------------------------------------------
    @app.before_request
    def monitor_and_inspect_request():
        g.start_time = time.perf_counter()
        g.threat_detected = False
        g.threat_risk_level = None

        # Exclude static assets from detection scans to preserve performance
        if request.path.startswith("/static/"):
            return

        client_ip = request.headers.get("X-Forwarded-For", "").split(",")[0].strip() or request.remote_addr or "127.0.0.1"

        # 1. Rule-based input inspection (SQLi, Traversal, Probing)
        threats = ThreatDetector.inspect_request(request)
        for threat in threats:
            g.threat_detected = True
            g.threat_risk_level = threat["severity"]
            ThreatDetector.record_alert(
                alert_type=threat["alert_type"],
                severity=threat["severity"],
                source_ip=client_ip,
                reason=threat["reason"],
                payload_sample=threat.get("payload_sample", "")
            )

        # 2. Rate limit burst inspection
        rate_alert = ThreatDetector.check_rate_limit(client_ip)
        if rate_alert:
            g.threat_detected = True
            if not g.threat_risk_level:
                g.threat_risk_level = rate_alert["severity"]
            ThreatDetector.record_alert(
                alert_type=rate_alert["alert_type"],
                severity=rate_alert["severity"],
                source_ip=client_ip,
                reason=rate_alert["reason"],
                payload_sample=rate_alert.get("payload_sample", "")
            )

        # 3. Repeated unauthorized access probe inspection
        unauth_alert = ThreatDetector.check_unauthorized_probes(client_ip)
        if unauth_alert:
            g.threat_detected = True
            if not g.threat_risk_level:
                g.threat_risk_level = unauth_alert["severity"]
            ThreatDetector.record_alert(
                alert_type=unauth_alert["alert_type"],
                severity=unauth_alert["severity"],
                source_ip=client_ip,
                reason=unauth_alert["reason"],
                payload_sample=unauth_alert.get("payload_sample", "")
            )

    # --------------------------------------------------------------------------
    # Custom Error Handlers (Prevents stack trace leakage)
    # --------------------------------------------------------------------------
    @app.errorhandler(400)
    def bad_request(error):
        return render_template(
            "base.html",
            error_code=400,
            error_title="400 - Bad Request",
            error_message="The application was unable to process the request due to invalid input or security validation failure."
        ), 400

    @app.errorhandler(403)
    def access_denied(error):
        return render_template(
            "base.html",
            error_code=403,
            error_title="403 - Access Forbidden",
            error_message="You do not possess the required security privileges or administrative role to access this resource."
        ), 403

    @app.errorhandler(404)
    def page_not_found(error):
        return render_template(
            "base.html",
            error_code=404,
            error_title="404 - Resource Not Found",
            error_message="The requested endpoint or resource does not exist on this secure server."
        ), 404

    @app.errorhandler(500)
    def internal_server_error(error):
        return render_template(
            "base.html",
            error_code=500,
            error_title="500 - Internal Security Error",
            error_message="An unexpected condition was encountered. Detailed stack trace has been safely suppressed."
        ), 500

    # --------------------------------------------------------------------------
    # Application Routes
    # --------------------------------------------------------------------------
    @app.route("/")
    def index():
        """Route entry point: routes authenticated users or redirects to login."""
        user = get_current_user()
        if not user:
            return redirect(url_for("auth.login"))
        if user["role"] == "admin":
            return redirect(url_for("admin_dashboard"))
        return redirect(url_for("user_home"))

    @app.route("/home")
    @login_required
    def user_home():
        """User home page displaying active session and TLS status."""
        user = get_current_user()
        client_ip = request.remote_addr or "127.0.0.1"
        recent_logins = query_db(
            "SELECT timestamp, ip_address, success FROM login_attempts WHERE username = ? ORDER BY id DESC LIMIT 5",
            (user["username"],)
        )
        return render_template("home.html", user=user, client_ip=client_ip, recent_logins=recent_logins)

    @app.route("/admin/dashboard")
    @admin_required
    def admin_dashboard():
        """
        Administrator Security Operations Center (SOC) Dashboard.
        Computes all statistics directly from persistent SQLite records.
        """
        # 1. Total Monitored Requests
        total_requests = query_db("SELECT COUNT(*) as cnt FROM request_logs", one=True)["cnt"]

        # 2. Successful Logins
        success_logins = query_db("SELECT COUNT(*) as cnt FROM login_attempts WHERE success = 1", one=True)["cnt"]

        # 3. Failed Logins
        failed_logins = query_db("SELECT COUNT(*) as cnt FROM login_attempts WHERE success = 0", one=True)["cnt"]

        # 4. Suspicious Events
        suspicious_events = query_db(
            "SELECT COUNT(*) as cnt FROM request_logs WHERE event_category = 'SUSPICIOUS_REQUEST' OR risk_level IN ('MEDIUM', 'HIGH', 'CRITICAL')",
            one=True
        )["cnt"]

        # 5. Open Security Alerts
        open_alerts = query_db("SELECT COUNT(*) as cnt FROM security_alerts WHERE status = 'OPEN'", one=True)["cnt"]

        # 6. Alert Severity Distribution
        high_alerts = query_db("SELECT COUNT(*) as cnt FROM security_alerts WHERE severity = 'HIGH'", one=True)["cnt"]
        med_alerts = query_db("SELECT COUNT(*) as cnt FROM security_alerts WHERE severity = 'MEDIUM'", one=True)["cnt"]
        low_alerts = query_db("SELECT COUNT(*) as cnt FROM security_alerts WHERE severity = 'LOW'", one=True)["cnt"]

        # 7. Recent Request Activity (Last 10 records)
        recent_requests = query_db("SELECT * FROM request_logs ORDER BY id DESC LIMIT 10")

        # 8. Recent Security Alerts (Last 5 records)
        recent_alerts = query_db("SELECT * FROM security_alerts ORDER BY id DESC LIMIT 5")

        # 9. Latest Integrity Audit
        latest_audit = query_db("SELECT * FROM audit_integrity ORDER BY id DESC LIMIT 1", one=True)

        return render_template(
            "dashboard.html",
            total_requests=total_requests,
            success_logins=success_logins,
            failed_logins=failed_logins,
            suspicious_events=suspicious_events,
            open_alerts=open_alerts,
            high_alerts=high_alerts,
            med_alerts=med_alerts,
            low_alerts=low_alerts,
            recent_requests=recent_requests,
            recent_alerts=recent_alerts,
            latest_audit=latest_audit
        )

    @app.route("/about")
    def about():
        """About the Capstone Project: Architecture, Objectives, Tech Stack."""
        return render_template("about.html")

    @app.route("/api/dashboard/stats")
    @admin_required
    def api_dashboard_stats():
        """JSON endpoint returning live dashboard metrics for dynamic chart rendering."""
        total_requests = query_db("SELECT COUNT(*) as cnt FROM request_logs", one=True)["cnt"]
        success_logins = query_db("SELECT COUNT(*) as cnt FROM login_attempts WHERE success = 1", one=True)["cnt"]
        failed_logins = query_db("SELECT COUNT(*) as cnt FROM login_attempts WHERE success = 0", one=True)["cnt"]
        open_alerts = query_db("SELECT COUNT(*) as cnt FROM security_alerts WHERE status = 'OPEN'", one=True)["cnt"]
        high_alerts = query_db("SELECT COUNT(*) as cnt FROM security_alerts WHERE severity = 'HIGH'", one=True)["cnt"]
        med_alerts = query_db("SELECT COUNT(*) as cnt FROM security_alerts WHERE severity = 'MEDIUM'", one=True)["cnt"]
        low_alerts = query_db("SELECT COUNT(*) as cnt FROM security_alerts WHERE severity = 'LOW'", one=True)["cnt"]

        # Category breakdown
        categories = query_db("SELECT event_category, COUNT(*) as cnt FROM request_logs GROUP BY event_category")
        category_data = {c["event_category"]: c["cnt"] for c in categories}

        return jsonify({
            "total_requests": total_requests,
            "success_logins": success_logins,
            "failed_logins": failed_logins,
            "open_alerts": open_alerts,
            "severity_distribution": {
                "HIGH": high_alerts,
                "MEDIUM": med_alerts,
                "LOW": low_alerts
            },
            "category_data": category_data
        })

    @app.route("/api/tls-info")
    def api_tls_info():
        """Returns live transport-layer security inspection data."""
        return jsonify({
            "scheme": request.scheme,
            "is_secure": request.is_secure,
            "client_ip": request.remote_addr,
            "server_port": request.environ.get("SERVER_PORT", "unknown"),
            "protocol": request.environ.get("SERVER_PROTOCOL", "HTTP/1.1"),
            "ssl_version": request.environ.get("SSL_PROTOCOL", "TLSv1.3 (Simulated / Local)"),
            "cipher": request.environ.get("SSL_CIPHER", "ECDHE-RSA-AES256-GCM-SHA384"),
            "hsts_active": bool(request.is_secure)
        })

    return app


# ------------------------------------------------------------------------------
# Server Launch Orchestration
# ------------------------------------------------------------------------------
def run_server():
    """CLI launcher for local development server."""
    parser = argparse.ArgumentParser(description="Run TLS Secure Web Application Monitoring System.")
    parser.add_argument("--port", type=int, default=8443, help="Port to listen on [default: 8443]")
    parser.add_argument("--host", default="0.0.0.0", help="Host interface [default: 0.0.0.0 (allows LAN & external access)]")
    parser.add_argument("--http", action="store_true", help="Run in unencrypted HTTP mode (port 5000) for testing")
    args = parser.parse_args()

    app = create_app(DevelopmentConfig)

    cert_path = app.config.get("TLS_CERT_PATH")
    key_path = app.config.get("TLS_KEY_PATH")

    # Detect local LAN IP for convenient display
    import socket
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        lan_ip = s.getsockname()[0]
        s.close()
    except Exception:
        lan_ip = "127.0.0.1"

    if args.http:
        http_port = 5000 if args.port == 8443 else args.port
        print("\n" + "=" * 78)
        print(" [!] CAUTION: Starting server in UNENCRYPTED HTTP mode")
        print(f" [*] Local:   http://localhost:{http_port}")
        print(f" [*] Network: http://{lan_ip}:{http_port}")
        print("=" * 78 + "\n")
        app.run(host=args.host, port=http_port, debug=True)
    else:
        # Check if TLS certificates exist, generate if missing
        if not os.path.exists(cert_path) or not os.path.exists(key_path):
            print(f"[*] Development TLS certificates not found. Generating automatically...")
            from scripts.generate_dev_certificate import generate_certificate
            generate_certificate(
                cert_dir=os.path.dirname(cert_path),
                cert_name=os.path.basename(cert_path),
                key_name=os.path.basename(key_path)
            )

        ssl_ctx = build_ssl_context(cert_path, key_path)

        print("\n" + "=" * 78)
        print("  TLS-Based Secure Web Application Monitoring and Threat Detection System")
        print("=" * 78)
        print(f" [✓] Mode:              HTTPS (Encrypted TLS Tunnel)")
        print(f" [✓] Local URL:         https://localhost:{args.port}")
        print(f" [✓] Network (Any Device on Wi-Fi): https://{lan_ip}:{args.port}")
        print(f" [✓] Certificate:       {cert_path}")
        print(f" [✓] Private Key:       {key_path}")
        print(f" [✓] Database:          {app.config.get('DATABASE_PATH')}")
        print("-" * 78)
        print(" [i] Any Device Access:")
        print(f"     1. Same Wi-Fi: Open https://{lan_ip}:{args.port} on your mobile or tablet.")
        print("     2. Worldwide Internet: Run 'share_public_link.bat' to get an instant")
        print("        trusted Cloudflare/Localtunnel URL accessible by anyone anywhere!")
        print("=" * 78 + "\n")

        app.run(host=args.host, port=args.port, ssl_context=ssl_ctx, debug=True)


if __name__ == "__main__":
    run_server()

