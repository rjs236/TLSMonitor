"""
Automated Tests for Module 2: Cryptographic Log-Integrity Verification.
Tests:
- HMAC-SHA256 signature generation
- Baseline verification of clean audit logs
- Detection of out-of-band database row tampering
- Recording of audit results in the audit_integrity table
"""

import pytest
from database.db import query_db, execute_db
from modules.integrity import compute_log_hmac, verify_log_integrity


def test_hmac_signature_generation():
    """Test INT-01: compute_log_hmac produces deterministic 64-character hex signature."""
    sig1 = compute_log_hmac(
        timestamp="2026-11-17T12:00:00",
        ip_address="127.0.0.1",
        method="GET",
        path="/home",
        status_code=200,
        username="admin_test",
        event_category="HTTP_REQUEST",
        risk_level="INFO",
        secret_key="my-test-secret-key"
    )
    assert len(sig1) == 64
    assert isinstance(sig1, str)

    # Determinism check
    sig2 = compute_log_hmac(
        timestamp="2026-11-17T12:00:00",
        ip_address="127.0.0.1",
        method="GET",
        path="/home",
        status_code=200,
        username="admin_test",
        event_category="HTTP_REQUEST",
        risk_level="INFO",
        secret_key="my-test-secret-key"
    )
    assert sig1 == sig2

    # Divergence on different data
    sig3 = compute_log_hmac(
        timestamp="2026-11-17T12:00:01",
        ip_address="127.0.0.1",
        method="GET",
        path="/home",
        status_code=200,
        username="admin_test",
        event_category="HTTP_REQUEST",
        risk_level="INFO",
        secret_key="my-test-secret-key"
    )
    assert sig1 != sig3


def test_integrity_audit_clean_database(app, client):
    """Test INT-02: Unmodified request logs pass cryptographic verification with status VERIFIED."""
    # Generate some logged requests
    client.get("/about")
    client.get("/auth/login")

    with app.app_context():
        result = verify_log_integrity(verified_by="TestAuditor")
        assert result["status"] == "VERIFIED"
        assert result["tampered_records_found"] == 0
        assert result["records_audited"] >= 2

        # Check recorded checkpoint in audit_integrity
        audit_entry = query_db(
            "SELECT * FROM audit_integrity ORDER BY id DESC LIMIT 1",
            one=True
        )
        assert audit_entry is not None
        assert audit_entry["status"] == "VERIFIED"
        assert audit_entry["verified_by"] == "TestAuditor"


def test_integrity_audit_detects_tampered_record(app, client):
    """Test INT-03: Out-of-band SQLite database tampering is immediately caught by HMAC audit."""
    # Generate log entry
    client.get("/about")

    with app.app_context():
        # Get target log entry
        row = query_db("SELECT id, path FROM request_logs ORDER BY id DESC LIMIT 1", one=True)
        assert row is not None

        # Directly tamper with SQLite data without updating cryptographic HMAC
        execute_db(
            "UPDATE request_logs SET path = '/injected/malicious/tamper' WHERE id = ?",
            (row["id"],)
        )

        # Run integrity verification
        result = verify_log_integrity(verified_by="TestAuditor")
        assert result["status"] == "TAMPER_DETECTED"
        assert result["tampered_records_found"] >= 1
        tampered_ids = [r["id"] for r in result["tampered_records"]]
        assert row["id"] in tampered_ids

        # Check recorded failure in audit_integrity
        audit_entry = query_db(
            "SELECT * FROM audit_integrity ORDER BY id DESC LIMIT 1",
            one=True
        )
        assert audit_entry is not None
        assert audit_entry["status"] == "TAMPER_DETECTED"

