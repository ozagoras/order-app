"""
db.py
All PostgreSQL database operations for the NFC beach bar system.
"""

import os
import uuid
import json
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
# nfc_tags
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
# sessions
# ---------------------------------------------------------------------------

def create_session(uid: str, table_id: str, counter: int) -> dict:
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
    with _get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(
                "UPDATE sessions SET token = %s WHERE id = %s",
                (token.upper(), session_id)
            )


def get_session_by_token(token: str) -> dict | None:
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


def kill_session(session_id: str) -> None:
    """
    Immediately kill a session after order is placed.
    Sets used=TRUE and expires_at=NOW() so it can never be used again.
    """
    with _get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                UPDATE sessions
                SET used = TRUE, expires_at = NOW()
                WHERE id = %s
                """,
                (session_id,)
            )


def consume_session(session_id: str) -> dict | None:
    now = datetime.now(timezone.utc)
    with _get_conn() as conn:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            cur.execute(
                """
                UPDATE sessions SET used = TRUE
                WHERE id = %s AND used = FALSE AND expires_at > %s
                RETURNING *
                """,
                (session_id, now)
            )
            row = cur.fetchone()
            return dict(row) if row else None


# ---------------------------------------------------------------------------
# orders
# ---------------------------------------------------------------------------

def create_order(session_id: str, table_id: str, items: list, total: float) -> dict:
    order_id = str(uuid.uuid4())
    with _get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO orders (id, session_id, table_id, items, status, total)
                VALUES (%s, %s, %s, %s, 'pending', %s)
                """,
                (order_id, session_id, table_id, json.dumps(items), total)
            )
    return {
        "id":         order_id,
        "session_id": session_id,
        "table_id":   table_id,
        "items":      items,
        "status":     "pending",
        "total":      total,
    }


def get_all_orders() -> list:
    with _get_conn() as conn:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            cur.execute(
                """
                SELECT id, session_id, table_id, items, status, total, created_at, updated_at
                FROM orders
                ORDER BY created_at DESC
                LIMIT 100
                """
            )
            rows = cur.fetchall()
            result = []
            for r in rows:
                # Convert RealDictRow to plain dict first to avoid
                # conflict with Python's built-in dict.items() method
                row = {
                    "id":         r["id"],
                    "session_id": r["session_id"],
                    "table_id":   r["table_id"],
                    "order_items": r["items"] if isinstance(r["items"], list) else json.loads(r["items"]) if r["items"] else [],
                    "status":     r["status"],
                    "total":      float(r["total"]),
                    "created_at": r["created_at"],
                    "updated_at": r["updated_at"],
                }
                result.append(row)
            return result


def get_orders_by_status(status: str) -> list:
    with _get_conn() as conn:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            cur.execute(
                "SELECT * FROM orders WHERE status = %s ORDER BY created_at DESC",
                (status,)
            )
            rows = cur.fetchall()
            return [dict(r) for r in rows]


def update_order_status(order_id: str, status: str) -> dict | None:
    with _get_conn() as conn:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            cur.execute(
                """
                UPDATE orders SET status = %s, updated_at = NOW()
                WHERE id = %s
                RETURNING *
                """,
                (status, order_id)
            )
            row = cur.fetchone()
            return dict(row) if row else None


# ---------------------------------------------------------------------------
# admin_users
# ---------------------------------------------------------------------------

def get_admin_user(username: str) -> dict | None:
    with _get_conn() as conn:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            cur.execute(
                "SELECT * FROM admin_users WHERE username = %s",
                (username,)
            )
            row = cur.fetchone()
            return dict(row) if row else None