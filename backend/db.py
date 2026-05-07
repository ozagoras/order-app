"""
db.py
All PostgreSQL database operations for the NFC beach bar system.
"""

import os
import uuid
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone

import psycopg2
import psycopg2.extras


def _get_database_url() -> str:
    url = os.environ.get("DATABASE_URL")
    if not url:
        raise ValueError("DATABASE_URL is not set in your .env file")
    return url


@contextmanager
def _get_conn():
    conn = psycopg2.connect(_get_database_url())
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


# ---------------------------------------------------------------------------
# nfc_tags table
# ---------------------------------------------------------------------------

def get_tag(uid: str) -> dict | None:
    with _get_conn() as conn:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            cur.execute(
                "SELECT uid, table_id, last_counter FROM nfc_tags WHERE uid = %s",
                (uid.upper(),)
            )
            row = cur.fetchone()
            return dict(row) if row else None


def update_last_counter(uid: str, new_counter: int) -> None:
    with _get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(
                "UPDATE nfc_tags SET last_counter = %s WHERE uid = %s",
                (new_counter, uid.upper())
            )


def register_tag(uid: str, table_id: str) -> dict:
    uid_clean      = uid.upper()
    table_id_clean = table_id.strip()
    with _get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO nfc_tags (uid, table_id, last_counter)
                VALUES (%s, %s, 0)
                ON CONFLICT (uid) DO UPDATE
                    SET table_id     = EXCLUDED.table_id,
                        last_counter = 0
                """,
                (uid_clean, table_id_clean)
            )
    return {"uid": uid_clean, "table_id": table_id_clean, "last_counter": 0}


# ---------------------------------------------------------------------------
# sessions table
# ---------------------------------------------------------------------------

def create_session(uid: str, table_id: str, counter: int) -> dict:
    """
    Create a new session after a valid NFC tap.
    Token is stored separately via store_token() after generation.
    """
    session_id = str(uuid.uuid4())
    expires_at = datetime.now(timezone.utc) + timedelta(minutes=5)

    with _get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO sessions (id, uid, table_id, counter, token, used, expires_at)
                VALUES (%s, %s, %s, %s, '', FALSE, %s)
                """,
                (session_id, uid.upper(), table_id, counter, expires_at)
            )

    return {
        "id":         session_id,
        "uid":        uid.upper(),
        "table_id":   table_id,
        "counter":    counter,
        "used":       False,
        "expires_at": expires_at.isoformat(),
    }


def store_token(session_id: str, token: str) -> None:
    """Store the generated HMAC token in the session row."""
    with _get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(
                "UPDATE sessions SET token = %s WHERE id = %s",
                (token.upper(), session_id)
            )


def get_session_by_token(token: str) -> dict | None:
    """
    Look up a session by its opaque HMAC token.
    Used in /order to validate the redirect token.
    """
    with _get_conn() as conn:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            cur.execute(
                """
                SELECT * FROM sessions
                WHERE token      = %s
                  AND used       = FALSE
                  AND expires_at > %s
                """,
                (token.upper(), datetime.now(timezone.utc))
            )
            row = cur.fetchone()
            return dict(row) if row else None


def get_session(session_id: str) -> dict | None:
    with _get_conn() as conn:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            cur.execute("SELECT * FROM sessions WHERE id = %s", (session_id,))
            row = cur.fetchone()
            return dict(row) if row else None


def consume_session(session_id: str) -> dict | None:
    """Atomically mark session as used."""
    now = datetime.now(timezone.utc)
    with _get_conn() as conn:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            cur.execute(
                """
                UPDATE sessions
                SET used = TRUE
                WHERE id         = %s
                  AND used       = FALSE
                  AND expires_at > %s
                RETURNING *
                """,
                (session_id, now)
            )
            row = cur.fetchone()
            return dict(row) if row else None