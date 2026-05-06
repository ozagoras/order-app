"""
app.py
Flask backend + simple HTML frontend for the NFC Beach Bar ordering system.
Served by Gunicorn in production.

Pages (HTML):
    GET  /nfc-writer        — admin page to register NFC tags to tables
    GET  /order             — customer order page (opened by NFC tap)

API endpoints (JSON):
    GET  /api/session       — validate NFC scan, create session
    POST /api/consume       — mark session used when order page loads
    POST /api/register-tag  — register UID → table mapping
    GET  /api/health        — health check
"""

import os
import logging
from flask import Flask, request, jsonify, render_template
from flask_cors import CORS
from dotenv import load_dotenv

from token_utils import verify_sdm_cmac
from db import (
    get_tag,
    update_last_counter,
    create_session,
    get_session,
    consume_session,
    register_tag,
)

# ---------------------------------------------------------------------------
# App setup
# ---------------------------------------------------------------------------

load_dotenv()

app = Flask(__name__)
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# CORS — restrict to your own domain in production
# BASE_URL is set in Render environment variables e.g. https://beach-bar.onrender.com
BASE_URL = os.environ.get("BASE_URL", "http://localhost:5000")
CORS(app, origins=[BASE_URL])


# ===========================================================================
# HTML PAGES
# ===========================================================================

@app.route("/nfc-writer")
def nfc_writer_page():
    """
    Admin page — register NFC chip UIDs to table IDs.
    Open this on Android Chrome during one-time tag setup.
    """
    return render_template("nfc_writer.html")


@app.route("/order")
def order_page():
    """
    Customer-facing order page.
    Opened automatically when a customer taps an NFC tag.
    Expects: ?uid=XX&ctr=XX&cmac=XX (injected by the chip)
    """
    return render_template("order.html")


# ===========================================================================
# API ENDPOINTS
# ===========================================================================

@app.route("/api/session", methods=["GET"])
def session():
    """
    Validate an NFC tap and create a single-use session.

    Called by order.html JS immediately on page load.
    Query params: uid, ctr, cmac
    Returns:      { sessionId, tableId }

    Validation chain:
      1. uid, ctr, cmac must be present
      2. CMAC verified cryptographically  — proves tap is genuine
      3. UID looked up in nfc_tags        — confirms tag is registered
      4. counter > last_counter           — replay protection
      5. New session created              — 5 min expiry, used=false
      6. last_counter updated             — old URL permanently dead
    """
    uid  = request.args.get("uid",  "").strip().upper()
    ctr  = request.args.get("ctr",  "").strip().upper()
    cmac = request.args.get("cmac", "").strip().upper()

    # 1 — All three parameters must be present
    if not uid or not ctr or not cmac:
        logger.warning("Session missing params uid=%s ctr=%s cmac=%s", uid, ctr, cmac)
        return jsonify({"error": "Missing uid, ctr, or cmac"}), 400

    # 2 — Cryptographic CMAC verification
    if not verify_sdm_cmac(uid, ctr, cmac):
        logger.warning("CMAC failed uid=%s ctr=%s", uid, ctr)
        return jsonify({"error": "Invalid CMAC — tap rejected"}), 401

    # 3 — Look up the tag in the database
    tag = get_tag(uid)
    if not tag:
        logger.warning("Unregistered tag uid=%s", uid)
        return jsonify({"error": "Tag not registered — complete setup in /nfc-writer first"}), 404

    # 4 — Replay protection
    incoming_counter = int(ctr, 16)
    last_counter     = tag.get("last_counter", 0)

    if incoming_counter <= last_counter:
        logger.warning("Replay detected uid=%s incoming=%d last=%d", uid, incoming_counter, last_counter)
        return jsonify({"error": "Replay detected — this URL has already been used"}), 401

    # 5 — Create session
    table_id    = tag["table_id"]
    new_session = create_session(uid, table_id, incoming_counter)

    # 6 — Update last_counter — old URL is permanently dead
    update_last_counter(uid, incoming_counter)

    logger.info("Valid tap: uid=%s table=%s session=%s", uid, table_id, new_session["id"])

    return jsonify({
        "sessionId": new_session["id"],
        "tableId":   table_id,
    }), 200


@app.route("/api/consume", methods=["POST"])
def consume():
    """
    Mark a session as used — called when the order page first loads.
    Prevents copy/paste reuse of the URL.

    Body:    { "sessionId": "uuid" }
    Returns: { "tableId": "Table-7" }
    """
    body       = request.get_json(silent=True) or {}
    session_id = body.get("sessionId", "").strip()

    if not session_id:
        return jsonify({"error": "Missing sessionId"}), 400

    session = consume_session(session_id)

    if not session:
        existing = get_session(session_id)
        if not existing:
            return jsonify({"error": "Session not found"}), 404
        if existing.get("used"):
            return jsonify({"error": "Session already used — tap the tag again"}), 401
        return jsonify({"error": "Session expired — tap the tag again"}), 401

    logger.info("Session consumed: id=%s table=%s", session_id, session["table_id"])

    return jsonify({
        "tableId": session["table_id"],
    }), 200


@app.route("/api/register-tag", methods=["POST"])
def register_tag_route():
    """
    Register a NFC tag UID to a table ID.
    Called by the /nfc-writer page during one-time tag setup.

    Body:    { "uid": "04A1B2C3D4E5F6", "tableId": "Table-7" }
    Returns: { "success": true, "uid": "...", "tableId": "..." }
    """
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
    """Health check — confirms server is running."""
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
# Entry point — used locally only
# In production Gunicorn calls app directly, not this block
# ===========================================================================

if __name__ == "__main__":
    port  = int(os.environ.get("PORT", 5000))
    debug = os.environ.get("FLASK_ENV") == "development"
    logger.info("Starting Flask NFC backend on port %d (debug=%s)", port, debug)
    app.run(host="0.0.0.0", port=port, debug=debug)