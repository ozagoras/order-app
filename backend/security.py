"""
security.py
Token generation and authentication decorators.

Extracted verbatim (behaviour-identical) from app.py, where the HMAC token
construction was written inline three times and the auth decorators were mixed
in with the routes. Nothing here changes what the app does — same HMAC-SHA256,
same 32-char uppercase truncation, same session keys, same 8-hour admin expiry.
"""

import os
import hmac
import hashlib
import logging
from functools import wraps
from datetime import datetime, timezone

from flask import session, redirect, url_for

logger = logging.getLogger(__name__)

# Admin session absolute expiry — 8 hours after login regardless of activity
ADMIN_SESSION_HOURS = 8

WAITER_SESSION_KEY = "waiter_logged_in"


def _secret() -> str:
    return os.environ.get("SECRET_KEY", "changeme")


def _hmac32(message: str) -> str:
    """HMAC-SHA256 of message, truncated to 32 uppercase hex chars."""
    return hmac.new(
        key=_secret().encode(),
        msg=message.encode(),
        digestmod=hashlib.sha256,
    ).hexdigest()[:32].upper()


def generate_token(uid: str, ctr: str, session_id: str) -> str:
    return _hmac32(f"{uid}:{ctr}:{session_id}")


def generate_refresh_token(session_id: str, counter) -> str:
    return _hmac32(f"refresh:{session_id}:{counter}")


# ---------------------------------------------------------------------------
# Auth decorators
# ---------------------------------------------------------------------------

def admin_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if not session.get("admin_logged_in"):
            return redirect(url_for("admin_login"))

        # Absolute expiry — session dies 8 hours after login, not reset by activity
        login_time = session.get("admin_login_time")
        if not login_time:
            session.clear()
            return redirect(url_for("admin_login"))

        elapsed = datetime.now(timezone.utc).timestamp() - login_time
        if elapsed > ADMIN_SESSION_HOURS * 3600:
            session.clear()
            logger.info("Admin session expired after %d hours", ADMIN_SESSION_HOURS)
            return redirect(url_for("admin_login"))

        return f(*args, **kwargs)
    return decorated


def waiter_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if not session.get(WAITER_SESSION_KEY):
            return redirect(url_for("waiter_login"))
        return f(*args, **kwargs)
    return decorated