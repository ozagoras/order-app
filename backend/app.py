"""
app.py
Flask backend + simple HTML frontend for the NFC Beach Bar ordering system.

Security model — two step redirect:
  Step 1: /nfc  — chip lands here with uid + ctr
                  validates counter, generates opaque token, redirects
  Step 2: /order — customer sees only the opaque token
                   token is HMAC-SHA256(secret, uid+ctr+session_id)
                   unpredictable without the secret key
                   single-use, 5 minute expiry

The counter in the chip URL is never exposed to the customer.
The token cannot be guessed or incremented — it is cryptographically random.
"""

import os
import hmac
import hashlib
import logging
from flask import Flask, request, jsonify, render_template, redirect, url_for
from flask_cors import CORS
from dotenv import load_dotenv

from db import (
    get_tag,
    update_last_counter,
    create_session,
    consume_session,
    get_session_by_token,
    register_tag,
)

load_dotenv()

app = Flask(__name__)
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

BASE_URL = os.environ.get("BASE_URL", "http://localhost:5000")
CORS(app, origins=[BASE_URL])


def generate_token(uid: str, ctr: str, session_id: str) -> str:
    """
    Generate an unpredictable opaque token using HMAC-SHA256.

    Combines uid + ctr + session_id with your SECRET_KEY.
    Without the secret key, this token cannot be guessed or forged
    even if uid and ctr are known.

    Returns first 32 hex chars (16 bytes) — short enough for a URL,
    long enough to be cryptographically secure.
    """
    secret = os.environ.get("SECRET_KEY", "changeme")
    message = f"{uid}:{ctr}:{session_id}".encode()
    token = hmac.new(
        key=secret.encode(),
        msg=message,
        digestmod=hashlib.sha256
    ).hexdigest()[:32].upper()
    return token


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
    The chip generates this URL: /nfc?uid=XXX&ctr=XXX

    Validates uid + counter, generates an opaque token,
    redirects customer to /order?token=XXXX

    The customer never sees uid or ctr in their browser.
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
            token=None,
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

    # 4 — Generate opaque token
    table_id    = tag["table_id"]
    new_session = create_session(uid, table_id, incoming_counter)
    token       = generate_token(uid, ctr, new_session["id"])

    # 5 — Store token in session, update counter
    update_last_counter(uid, incoming_counter)

    # Store the token in the session row
    from db import store_token
    store_token(new_session["id"], token)

    logger.info("Valid tap: uid=%s table=%s ctr=%d token=%s",
                uid, table_id, incoming_counter, token)

    # 6 — Redirect to /order with only the opaque token
    # Customer sees: /order?token=A3F1C82E904D7B56...
    # uid and ctr are gone from the URL
    return redirect(f"/order?token={token}")


@app.route("/order")
def order_page():
    """
    Step 2 — Customer order page.
    Only accepts an opaque token — no uid or ctr visible.

    The token is:
      - HMAC-SHA256(secret, uid+ctr+session_id)
      - Single-use
      - Expires in 5 minutes
      - Cannot be guessed or incremented
    """
    token = request.args.get("token", "").strip().upper()

    def render_error(title, message):
        return render_template(
            "order.html",
            error=message,
            error_title=title,
            table_id=None,
            session_id=None,
            token=None,
        )

    if not token:
        return render_error("Invalid link", "This page must be opened by tapping an NFC tag.")

    # Look up session by token
    session = get_session_by_token(token)
    if not session:
        return render_error("Invalid token", "This link is invalid or has expired.")

    # Consume the session — marks it used=TRUE
    consumed = consume_session(session["id"])
    if not consumed:
        return render_error("Link already used", "Please tap the NFC tag again.")

    logger.info("Order page loaded: table=%s session=%s",
                session["table_id"], session["id"])

    return render_template(
        "order.html",
        error=None,
        error_title=None,
        table_id=session["table_id"],
        session_id=session["id"],
        token=token,
    )


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