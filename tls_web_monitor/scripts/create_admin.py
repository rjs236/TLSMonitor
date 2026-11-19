"""
Safe First-Administrator Account Creation Script.
Safely provisions an initial administrative account with Werkzeug-hashed passwords.
Does not hardcode credentials or secrets.
"""

import os
import sys
import getpass
import argparse
from datetime import datetime, timezone
from werkzeug.security import generate_password_hash

# Ensure project root is on sys.path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from database.db import init_db, query_db, execute_db


def create_admin_user(username: str = None, password: str = None, db_path: str = None):
    """Provisions or updates an administrator user in SQLite."""
    # Ensure database schema is initialized
    init_db(db_path=db_path)

    if not username:
        username = os.environ.get("ADMIN_USERNAME")
    if not username:
        try:
            username = input("Enter administrator username [default: admin]: ").strip() or "admin"
        except (EOFError, KeyboardInterrupt):
            print("\n[!] Setup aborted.")
            return False

    # Check if user already exists
    existing_user = query_db(
        "SELECT id, username, role FROM users WHERE username = ?",
        (username,),
        one=True,
        db_path=db_path
    )

    if not password:
        password = os.environ.get("ADMIN_PASSWORD")
    if not password:
        try:
            while True:
                p1 = getpass.getpass(f"Enter password for admin '{username}': ")
                if len(p1) < 8:
                    print("[!] Password must be at least 8 characters long.")
                    continue
                p2 = getpass.getpass("Confirm password: ")
                if p1 != p2:
                    print("[!] Passwords do not match. Please try again.")
                    continue
                password = p1
                break
        except (EOFError, KeyboardInterrupt):
            print("\n[!] Setup aborted.")
            return False

    if len(password) < 8:
        print("[!] Error: Administrator password must be at least 8 characters long.")
        return False

    # Hash using Werkzeug (PBKDF2/scrypt)
    password_hash = generate_password_hash(password)
    now = datetime.now(timezone.utc).isoformat()

    if existing_user:
        execute_db(
            "UPDATE users SET password_hash = ?, role = 'admin', is_active = 1 WHERE id = ?",
            (password_hash, existing_user["id"]),
            db_path=db_path
        )
        print(f"[+] Existing user '{username}' successfully elevated and password updated.")
    else:
        execute_db(
            "INSERT INTO users (username, password_hash, role, created_at, is_active) VALUES (?, ?, 'admin', ?, 1)",
            (username, password_hash, now),
            db_path=db_path
        )
        print(f"[+] Administrator account '{username}' created successfully.")

    return True


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Create or update an administrative user.")
    parser.add_argument("--username", help="Administrator username")
    parser.add_argument("--password", help="Administrator password (min 8 chars)")
    parser.add_argument("--db", help="Path to SQLite database file")
    args = parser.parse_args()

    create_admin_user(username=args.username, password=args.password, db_path=args.db)

