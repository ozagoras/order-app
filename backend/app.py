"""
app.py
Flask backend + simple HTML frontend for the NFC Beach Bar ordering system.

Security model — two step redirect + browser session cookie:
  Step 1: /nfc   — chip lands here with uid + ctr
                   validates counter, generates opaque token, redirects
  Step 2: /order — customer sees only the opaque token
                   on first load: consumes token, sets browser cookie
                   on refresh:    validates cookie instead of token
                   cookie is valid for 5 minutes
                   anyone else opening the same URL is rejected
"""

import os
import hmac
import hashlib
import logging
from datetime import datetime, timezone, timedelta
from flask import Flask, request, jsonify, render_template, redirect, make_response
from flask_cors import CORS
from dotenv import load_dotenv

from db import (
    get_tag,
    update_last_counter,
    create_session,
    consume_session,
    get_session_by_token,
    get_session,
    register_tag,
    store_token,
)

load_dotenv()

app = Flask(__name__)
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

BASE_URL = os.environ.get("BASE_URL", "http://localhost:5000")
CORS(app, origins=[BASE_URL])

# Cookie name stored in customer browser
SESSION_COOKIE = "nfc_session"


def generate_token(uid: str, ctr: str, session_id: str) -> str:
    """
    Generate an unpredictable opaque token using HMAC-SHA256.
    Combines uid + ctr + session_id with SECRET_KEY.
    """
    secret  = os.environ.get("SECRET_KEY", "changeme")
    message = f"{uid}:{ctr}:{session_id}".encode()
    return hmac.new(
        key=secret.encode(),
        msg=message,
        digestmod=hashlib.sha256
    ).hexdigest()[:32].upper()


# ===========================================================================
# HTML PAGES
# ===========================================================================

@app.route("/nfc-writer")
def nfc_writer_page():
    return render_template("nfc_writer.html")


@app.route("/nfc")
def nfc_landing():
    """
    Step 1 — Entry point from NFC chip tap.
    Chip generates: /nfc?uid=XXX&ctr=XXX

    Validates uid + counter, generates opaque HMAC token,
    redirects customer to /order?token=XXXX
    """
    uid = request.args.get("uid", "").strip().upper()
    ctr = request.args.get("ctr", "").strip().upper()

    def render_error(title, message):
        return render_template(
            "order.html",
            error=message,
            error_title=title,
            table_id=None,
            session_id=None,
        )

    # 1 — Both parameters must be present
    if not uid or not ctr:
        logger.warning("NFC landing missing params uid=%s ctr=%s", uid, ctr)
        return render_error("Invalid link", "This page must be opened by tapping an NFC tag.")

    # 2 — Look up the tag
    tag = get_tag(uid)
    if not tag:
        logger.warning("Unregistered tag uid=%s", uid)
        return render_error("Tag not registered", "Complete setup in /nfc-writer first.")

    # 3 — Counter must have advanced
    try:
        incoming_counter = int(ctr, 16)
    except ValueError:
        return render_error("Invalid link", "Malformed counter value.")

    last_counter = tag.get("last_counter", 0)
    if incoming_counter <= last_counter:
        logger.warning("Replay detected uid=%s incoming=%d last=%d",
                       uid, incoming_counter, last_counter)
        return render_error("Link already used", "Please tap the NFC tag again.")

    # 4 — Create session + generate token
    table_id    = tag["table_id"]
    new_session = create_session(uid, table_id, incoming_counter)
    token       = generate_token(uid, ctr, new_session["id"])

    # 5 — Store token + update counter
    store_token(new_session["id"], token)
    update_last_counter(uid, incoming_counter)

    logger.info("Valid tap: uid=%s table=%s ctr=%d token=%s",
                uid, table_id, incoming_counter, token)

    # 6 — Redirect to /order with opaque token
    return redirect(f"/order?token={token}")


@app.route("/order")
def order_page():
    """
    Step 2 — Customer order page.

    Two paths:
      A) First load — token in URL query string
         - Look up session by token
         - Consume session (marks used=TRUE)
         - Set browser cookie with session_id + expiry
         - Render order page

      B) Refresh — session_id in browser cookie
         - Read cookie
         - Validate session still exists and not expired
         - Render order page (no token needed)

    This allows the customer to refresh freely for 5 minutes.
    Anyone else opening the same URL is rejected because
    the token is already consumed and they have no cookie.
    """
    token      = request.args.get("token", "").strip().upper()
    cookie_sid = request.cookies.get(SESSION_COOKIE, "").strip()

    def render_error(title, message):
        return render_template(
            "order.html",
            error=message,
            error_title=title,
            table_id=None,
            session_id=None,
        )

    # -----------------------------------------------------------------------
    # Path B — Refresh: customer already has a cookie
    # -----------------------------------------------------------------------
    if cookie_sid and not token:
        session = get_session(cookie_sid)

        if not session:
            return render_error("Session not found", "Please tap the NFC tag again.")

        # Check session has not expired
        expires_at = session["expires_at"]
        if isinstance(expires_at, str):
            expires_at = datetime.fromisoformat(expires_at)
        if expires_at.tzinfo is None:
            expires_at = expires_at.replace(tzinfo=timezone.utc)

        if datetime.now(timezone.utc) > expires_at:
            return render_error("Session expired", "Please tap the NFC tag again.")

        logger.info("Refresh via cookie: session=%s table=%s", cookie_sid, session["table_id"])

        return render_template(
            "order.html",
            error=None,
            error_title=None,
            table_id=session["table_id"],
            session_id=session["id"],
        )

    # -----------------------------------------------------------------------
    # Path A — First load: token in URL
    # -----------------------------------------------------------------------
    if not token:
        return render_error("Invalid link", "This page must be opened by tapping an NFC tag.")

    # Look up session by token
    session = get_session_by_token(token)
    if not session:
        return render_error(
            "Invalid or expired token",
            "This link has already been used or expired. Please tap the NFC tag again."
        )

    # Consume session — marks used=TRUE so nobody else can use this token
    consumed = consume_session(session["id"])
    if not consumed:
        return render_error("Link already used", "Please tap the NFC tag again.")

    logger.info("Order page first load: table=%s session=%s",
                session["table_id"], session["id"])

    # Build response and set browser cookie
    # Cookie contains session_id — used for refresh validation
    response = make_response(render_template(
        "order.html",
        error=None,
        error_title=None,
        table_id=session["table_id"],
        session_id=session["id"],
    ))

    # Set cookie to expire at the same time as the session (5 minutes)
    expires_at = session["expires_at"]
    if isinstance(expires_at, str):
        expires_at = datetime.fromisoformat(expires_at)
    if expires_at.tzinfo is None:
        expires_at = expires_at.replace(tzinfo=timezone.utc)

    response.set_cookie(
        SESSION_COOKIE,
        value=session["id"],
        expires=expires_at,
        httponly=True,    # not accessible via JavaScript
        secure=True,      # HTTPS only
        samesite="Strict" # not sent on cross-site requests
    )

    return response


# ===========================================================================
# API ENDPOINTS
# ===========================================================================

@app.route("/api/register-tag", methods=["POST"])
def register_tag_route():
    body     = request.get_json(silent=True) or {}
    uid      = body.get("uid",     "").strip().upper()
    table_id = body.get("tableId", "").strip()

    if not uid:
        return jsonify({"error": "Missing uid"}), 400
    if not table_id:
        return jsonify({"error": "Missing tableId"}), 400

    tag = register_tag(uid, table_id)
    logger.info("Tag registered: uid=%s table=%s", uid, table_id)

    return jsonify({
        "success": True,
        "uid":     tag["uid"],
        "tableId": tag["table_id"],
    }), 200


@app.route("/api/health", methods=["GET"])
def health():
    return jsonify({"status": "ok"}), 200


# ===========================================================================
# Error handlers
# ===========================================================================

@app.errorhandler(404)
def not_found(e):
    return jsonify({"error": "Route not found"}), 404

@app.errorhandler(405)
def method_not_allowed(e):
    return jsonify({"error": "Method not allowed"}), 405

@app.errorhandler(500)
def server_error(e):
    logger.error("Internal server error: %s", str(e))
    return jsonify({"error": "Internal server error"}), 500


# ===========================================================================
# Entry point
# ===========================================================================

if __name__ == "__main__":
    port  = int(os.environ.get("PORT", 5000))
    debug = os.environ.get("FLASK_ENV") == "development"
    logger.info("Starting Flask NFC backend on port %d (debug=%s)", port, debug)
    app.run(host="0.0.0.0", port=port, debug=debug)