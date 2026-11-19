"""
Module 2 (Subcomponent): Cryptographic Log-Integrity Verification.
Uses HMAC-SHA256 (via Python cryptography / hmac) to generate tamper-evident signatures
for request logs and verify the database against unauthorized modifications.
"""

import os
import hmac
import hashlib
from datetime import datetime, timezone
from cryptography.hazmat.primitives import hashes, hmac as crypto_hmac
from database.db import query_db, execute_db


def compute_log_hmac(
    timestamp: str,
    ip_address: str,
    method: str,
    path: str,
    status_code: int,
    username: str,
    event_category: str,
    risk_level: str,
    secret_key: str = None
) -> str:
    """
    Computes an HMAC-SHA256 signature for an individual log entry.
    Canonical format: timestamp|ip_address|method|path|status_code|username|event_category|risk_level
    """
    if secret_key is None:
        try:
            from flask import current_app
            if current_app:
                secret_key = current_app.config.get("LOG_INTEGRITY_KEY")
        except Exception:
            pass

    if secret_key is None:
        secret_key = os.environ.get(
            "LOG_INTEGRITY_KEY",
            "default-hmac-dev-key-7f9a1b2c3d4e5f6a7b8c9d0e1f2a3b4c"
        )

    canonical_data = (
        f"{timestamp}|{ip_address}|{method}|{path}|"
        f"{status_code}|{username or 'Anonymous'}|{event_category}|{risk_level}"
    ).encode("utf-8")

    # Use cryptography library HMAC
    h = crypto_hmac.HMAC(secret_key.encode("utf-8"), hashes.SHA256())
    h.update(canonical_data)
    return h.finalize().hex()


def verify_log_integrity(verified_by: str = "Administrator", secret_key: str = None, db_path: str = None) -> dict:
    """
    Scans every record in the request_logs table and verifies its HMAC signature.
    Identifies any rows that have been inserted, updated, or corrupted out-of-band.
    Logs the audit result to the audit_integrity table.

    Security & Limitation Documentation:
    -----------------------------------
    - Purpose: Detects unauthorized database tampering (e.g. an attacker modifying SQL records
      to hide their traces after an exploit).
    - How it works: Each row is signed with HMAC-SHA256 using a server-side secret key.
    - Security Limitation: If an attacker attains root/administrative shell access and reads the
      LOG_INTEGRITY_KEY from server memory or environment files, they could forge HMACs.
      In production enterprise environments, local logs must be supplemented by real-time TLS forwarding
      to a remote WORM (Write Once, Read Many) SIEM or append-only log ledger.
    """
    if secret_key is None:
        try:
            from flask import current_app
            if current_app:
                secret_key = current_app.config.get("LOG_INTEGRITY_KEY")
        except Exception:
            pass

    if secret_key is None:
        secret_key = os.environ.get(
            "LOG_INTEGRITY_KEY",
            "default-hmac-dev-key-7f9a1b2c3d4e5f6a7b8c9d0e1f2a3b4c"
        )

    rows = query_db(
        "SELECT id, timestamp, ip_address, method, path, status_code, username, event_category, risk_level, hmac_signature FROM request_logs ORDER BY id ASC",
        db_path=db_path
    )

    total_records = len(rows)
    tampered_records = []

    for row in rows:
        expected_sig = compute_log_hmac(
            timestamp=row["timestamp"],
            ip_address=row["ip_address"],
            method=row["method"],
            path=row["path"],
            status_code=row["status_code"],
            username=row["username"],
            event_category=row["event_category"],
            risk_level=row["risk_level"],
            secret_key=secret_key
        )

        stored_sig = row["hmac_signature"] or ""
        if not hmac.compare_digest(expected_sig, stored_sig):
            tampered_records.append({
                "id": row["id"],
                "timestamp": row["timestamp"],
                "path": row["path"],
                "stored_signature": stored_sig,
                "expected_signature": expected_sig
            })

    now = datetime.now(timezone.utc).isoformat()
    if total_records == 0:
        status = "EMPTY"
        details = "No request logs found in database to audit."
    elif len(tampered_records) == 0:
        status = "VERIFIED"
        details = f"All {total_records} log entries cryptographically verified. No tampering detected."
    else:
        status = "TAMPER_DETECTED"
        tampered_ids = [str(r["id"]) for r in tampered_records]
        details = f"Tampering detected in {len(tampered_records)} record(s): IDs [{', '.join(tampered_ids[:10])}]."

    # Record audit in audit_integrity table
    execute_db(
        "INSERT INTO audit_integrity (timestamp, records_audited, tampered_records_found, status, details, verified_by) VALUES (?, ?, ?, ?, ?, ?)",
        (now, total_records, len(tampered_records), status, details, verified_by),
        db_path=db_path
    )

    return {
        "status": status,
        "records_audited": total_records,
        "tampered_records_found": len(tampered_records),
        "tampered_records": tampered_records,
        "timestamp": now,
        "details": details,
        "verified_by": verified_by
    }
