"""
db.py
All PostgreSQL database operations for the NFC beach bar system.
Uses psycopg2 — standard Python PostgreSQL driver.
Connects to a Render PostgreSQL instance via DATABASE_URL.

Tables used:
    nfc_tags  — maps chip UID to table ID, tracks last seen counter
    sessions  — single-use sessions created on every valid NFC tap
"""

import os
import uuid
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone

import psycopg2
import psycopg2.extras  # provides RealDictCursor — rows come back as dicts


# ---------------------------------------------------------------------------
# Connection
# ---------------------------------------------------------------------------

def _get_database_url() -> str:
    url = os.environ.get("DATABASE_URL")
    if not url:
        raise ValueError("DATABASE_URL is not set in your .env file")
    return url


@contextmanager
def _get_conn():
    """
    Context manager that opens a connection, yields it, commits on success,
    rolls back on any exception, and always closes the connection.

    Render PostgreSQL requires SSL. psycopg2 handles this automatically
    when sslmode is included in the DATABASE_URL (Render includes it by default).
    """
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
#
# Schema:
#   uid           TEXT    PRIMARY KEY   — chip hardware UID e.g. "04A1B2C3D4E5F6"
#   table_id      TEXT    NOT NULL      — e.g. "Table-7" or "Beach-A3"
#   last_counter  INTEGER NOT NULL DEFAULT 0
# ---------------------------------------------------------------------------

def get_tag(uid: str) -> dict | None:
    """
    Look up a registered NFC tag by UID.
    Returns the row as a dict, or None if the UID is not registered.

    Called on every customer scan to:
      - confirm the chip is registered (not a rogue tag)
      - get the table_id
      - get last_counter for replay protection
    """
    with _get_conn() as conn:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            cur.execute(
                "SELECT uid, table_id, last_counter FROM nfc_tags WHERE uid = %s",
                (uid.upper(),)
            )
            row = cur.fetchone()
            return dict(row) if row else None


def update_last_counter(uid: str, new_counter: int) -> None:
    """
    Save the latest counter value for a chip after a valid scan.

    This is the core replay protection:
    any future scan with counter <= new_counter will be rejected.

    Called immediately after creating the session — from this point
    the old URL is permanently dead.
    """
    with _get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(
                "UPDATE nfc_tags SET last_counter = %s WHERE uid = %s",
                (new_counter, uid.upper())
            )


def register_tag(uid: str, table_id: str) -> dict:
    """
    Register a new NFC tag or update an existing one.
    Called from POST /api/register-tag (the /nfc-writer page).

    Uses INSERT ... ON CONFLICT DO UPDATE (upsert) so re-registering
    an existing tag just updates the table_id and resets last_counter to 0.
    """
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

    return {
        "uid":          uid_clean,
        "table_id":     table_id_clean,
        "last_counter": 0,
    }


# ---------------------------------------------------------------------------
# sessions table
#
# Schema:
#   id          UUID        PRIMARY KEY DEFAULT gen_random_uuid()
#   uid         TEXT        NOT NULL
#   table_id    TEXT        NOT NULL
#   counter     INTEGER     NOT NULL
#   used        BOOLEAN     NOT NULL DEFAULT FALSE
#   expires_at  TIMESTAMPTZ NOT NULL
#   created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
# ---------------------------------------------------------------------------

def create_session(uid: str, table_id: str, counter: int) -> dict:
    """
    Create a new single-use session after a valid NFC tap.

    The session:
      - Has a unique UUID generated server-side
      - Expires in 5 minutes
      - Can only be consumed once (used flag)
      - Is tied to this specific chip tap (uid + counter)
    """
    session_id = str(uuid.uuid4())
    expires_at = datetime.now(timezone.utc) + timedelta(minutes=5)

    with _get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO sessions (id, uid, table_id, counter, used, expires_at)
                VALUES (%s, %s, %s, %s, FALSE, %s)
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


def get_session(session_id: str) -> dict | None:
    """
    Fetch a session by its UUID.
    Returns the row as a dict, or None if not found.
    """
    with _get_conn() as conn:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            cur.execute(
                "SELECT * FROM sessions WHERE id = %s",
                (session_id,)
            )
            row = cur.fetchone()
            return dict(row) if row else None


def consume_session(session_id: str) -> dict | None:
    """
    Attempt to consume a session — mark it as used=TRUE.

    Uses a single atomic UPDATE ... WHERE to avoid race conditions:
    checks that the session exists, is not used, and is not expired
    all in one query. Only marks used=TRUE if all conditions pass.

    Returns the session dict if successfully consumed, None if rejected.
    Called when the customer's order page first loads.
    """
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