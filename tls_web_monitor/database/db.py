"""Database management and parameterized query execution layer."""

import os
import sqlite3
import logging
from flask import g, current_app

logger = logging.getLogger(__name__)

SCHEMA_PATH = os.path.join(os.path.dirname(__file__), "schema.sql")


def get_db(db_path=None):
    """
    Get a database connection.
    If called within a Flask application context, binds the connection to Flask's `g` context.
    Otherwise returns a standalone sqlite3 connection.
    """
    if db_path is None:
        if current_app:
            db_path = current_app.config.get("DATABASE_PATH")
        else:
            db_path = os.environ.get(
                "DATABASE_PATH",
                os.path.join(os.path.dirname(os.path.dirname(__file__)), "tls_security.db")
            )

    # Ensure parent directory exists
    os.makedirs(os.path.dirname(os.path.abspath(db_path)), exist_ok=True)

    # In Flask request context, reuse connection on g
    try:
        if "db" not in g or getattr(g, "db_path", None) != db_path:
            conn = sqlite3.connect(db_path, detect_types=sqlite3.PARSE_DECLTYPES)
            conn.row_factory = sqlite3.Row
            conn.execute("PRAGMA foreign_keys = ON;")
            conn.execute("PRAGMA journal_mode = WAL;")
            g.db = conn
            g.db_path = db_path
        return g.db
    except RuntimeError:
        # Outside Flask application context
        conn = sqlite3.connect(db_path, detect_types=sqlite3.PARSE_DECLTYPES)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys = ON;")
        conn.execute("PRAGMA journal_mode = WAL;")
        return conn


def close_db(e=None):
    """Closes the current database connection if open."""
    db = getattr(g, "db", None)
    if db is not None:
        try:
            db.close()
        except Exception as err:
            logger.warning("Error closing database connection: %s", err)
        g.db = None


def init_db(app=None, db_path=None):
    """
    Initializes database schema using schema.sql.
    Can be run within an app context or with an explicit db_path.
    """
    if db_path is None:
        if app:
            db_path = app.config.get("DATABASE_PATH")
        elif current_app:
            db_path = current_app.config.get("DATABASE_PATH")
        else:
            db_path = os.environ.get(
                "DATABASE_PATH",
                os.path.join(os.path.dirname(os.path.dirname(__file__)), "tls_security.db")
            )

    os.makedirs(os.path.dirname(os.path.abspath(db_path)), exist_ok=True)
    with sqlite3.connect(db_path) as conn:
        conn.execute("PRAGMA foreign_keys = ON;")
        with open(SCHEMA_PATH, "r", encoding="utf-8") as f:
            conn.executescript(f.read())
        conn.commit()
    logger.info("Database initialized successfully at: %s", db_path)
    return db_path


def query_db(query: str, args=(), one=False, db_path=None):
    """
    Executes a parameterized read query.
    Always uses parameter binding ('?') to prevent SQL injection.
    """
    db = get_db(db_path)
    cur = db.cursor()
    cur.execute(query, args)
    rv = cur.fetchall()
    cur.close()
    return (rv[0] if rv else None) if one else rv


def execute_db(query: str, args=(), db_path=None):
    """
    Executes a parameterized write query (INSERT/UPDATE/DELETE).
    Commits transaction and returns the lastrowid.
    """
    db = get_db(db_path)
    cur = db.cursor()
    cur.execute(query, args)
    db.commit()
    last_id = cur.lastrowid
    row_count = cur.rowcount
    cur.close()
    return last_id if last_id else row_count

