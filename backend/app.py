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

Admin:
  /admin/login   — login page
  /admin         — dashboard showing all orders
  /admin/order/<id>/status — update order status
"""

import os
import uuid
import hmac
import hashlib
import logging
from datetime import datetime, timezone, timedelta
from functools import wraps
from flask import (Flask, request, jsonify, render_template,
                   redirect, make_response, session, url_for)
from flask_cors import CORS
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from dotenv import load_dotenv

import bcrypt

from db import (
    get_tag,
    update_last_counter,
    create_session,
    create_session_full,
    consume_session,
    get_session_by_token,
    get_session_by_refresh_token,
    get_session,
    kill_session,
    register_tag,
    store_token,
    store_refresh_token,
    create_order,
    get_all_orders,
    update_order_status,
    get_admin_user,
)

load_dotenv()

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "changeme")
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
app.config["PERMANENT_SESSION_LIFETIME"] = timedelta(hours=8)
# SESSION_PERMANENT = False means cookie dies when browser closes
# The user must log in fresh every time they open the browser
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

BASE_URL = os.environ.get("BASE_URL", "http://localhost:5000")
CORS(app, origins=[BASE_URL])

# Rate limiter — protects admin login from brute force
limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=[],          # no global limit — only apply where needed
    storage_uri="memory://"     # in-memory storage, resets on restart
)

SESSION_COOKIE = "nfc_session"


def generate_token(uid: str, ctr: str, session_id: str) -> str:
    secret  = os.environ.get("SECRET_KEY", "changeme")
    message = f"{uid}:{ctr}:{session_id}".encode()
    return hmac.new(
        key=secret.encode(),
        msg=message,
        digestmod=hashlib.sha256
    ).hexdigest()[:32].upper()


# ---------------------------------------------------------------------------
# Admin auth decorator
# ---------------------------------------------------------------------------

# Admin session absolute expiry — 8 hours after login regardless of activity
ADMIN_SESSION_HOURS = 8

def admin_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if not session.get("admin_logged_in"):
            return redirect(url_for("admin_login"))

        # Absolute expiry — session dies 8 hours after login
        # Not reset by activity — browser open or not, session expires
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


# ===========================================================================
# CUSTOMER PAGES
# ===========================================================================

@app.route("/nfc-writer")
def nfc_writer_page():
    return render_template("nfc_writer.html")


@app.route("/nfc")
def nfc_landing():
    uid = request.args.get("uid", "").strip().upper()
    ctr = request.args.get("ctr", "").strip().upper()

    def render_error(title, message):
        return render_template("order.html", error=message, error_title=title,
                               table_id=None, session_id=None, counter=None,
                               refresh_token=None)

    # 1 — Parameters must be present
    if not uid or not ctr:
        return render_error("Invalid link", "This page must be opened by tapping an NFC tag.")

    # 2 — Single DB call: get tag + validate in one query
    tag = get_tag(uid)
    if not tag:
        return render_error("Tag not registered", "Complete setup in /nfc-writer first.")

    try:
        incoming_counter = int(ctr, 16)
    except ValueError:
        return render_error("Invalid link", "Malformed counter value.")

    # 3 — Replay protection
    if incoming_counter <= tag.get("last_counter", 0):
        logger.warning("Replay detected uid=%s incoming=%d last=%d",
                       uid, incoming_counter, tag["last_counter"])
        return render_error("Link already used", "Please tap the NFC tag again.")

    # 4 — Generate all tokens in Python (no DB needed yet)
    table_id      = tag["table_id"]
    session_id    = str(uuid.uuid4())
    token         = generate_token(uid, ctr, session_id)
    secret        = os.environ.get("SECRET_KEY", "changeme")
    refresh_token = hmac.new(
        key=secret.encode(),
        msg=f"refresh:{session_id}:{incoming_counter}".encode(),
        digestmod=hashlib.sha256
    ).hexdigest()[:32].upper()

    # 5 — Single DB transaction: insert session + update counter
    create_session_full(uid, table_id, incoming_counter, token, refresh_token)

    logger.info("Valid tap: uid=%s table=%s ctr=%d", uid, table_id, incoming_counter)

    # 6 — Redirect to /order — uid and ctr never appear in browser history
    return redirect(f"/order?token={token}")


@app.route("/order", methods=["GET", "POST"])
def order_page():
    # -----------------------------------------------------------------------
    # POST — Customer submits order
    # Cookie must be present — proves this is the device that tapped
    # -----------------------------------------------------------------------
    if request.method == "POST":
        refresh_token = request.headers.get("X-Refresh-Token", "").strip().upper()
        if not refresh_token:
            return jsonify({"error": "Unauthorized"}), 401

        sess = get_session_by_refresh_token(refresh_token)
        if not sess:
            return jsonify({"error": "Session not found or expired"}), 404

        body  = request.get_json(silent=True) or {}
        items = body.get("items", [])
        if not items:
            return jsonify({"error": "No items in order"}), 400

        total   = sum(item.get("price", 0) * item.get("qty", 1) for item in items)
        payment = body.get("payment", "cash").strip()
        order   = create_order(sess["id"], sess["table_id"], items, total, payment)

        # Kill the session immediately after order is placed
        kill_session(sess["id"])

        logger.info("Order placed and session killed: table=%s total=%.2f session=%s",
                    sess["table_id"], total, sess["id"])

        return jsonify({"success": True, "orderId": order["id"]}), 200

    # -----------------------------------------------------------------------
    # GET — Show the order page
    # -----------------------------------------------------------------------
    token         = request.args.get("token", "").strip().upper()
    refresh_token = request.headers.get("X-Refresh-Token", "").strip().upper()

    logger.info("Order page hit: token=%s refresh=%s",
                token[:8] if token else "none",
                refresh_token[:8] if refresh_token else "none")

    def render_error(title, message):
        return render_template("order.html", error=message, error_title=title,
                               table_id=None, session_id=None, counter=None,
                               refresh_token=None)

    # -----------------------------------------------------------------------
    # Path B — Refresh: client sends X-Refresh-Token header
    # This token lives only in sessionStorage — not a cookie, not in URL
    # Cannot be accessed from another browser tab or device
    # -----------------------------------------------------------------------
    if refresh_token and not token:
        sess = get_session_by_refresh_token(refresh_token)
        if not sess:
            return render_error("Session expired", "Please tap the NFC tag again.")

        expires_at = sess["expires_at"]
        if isinstance(expires_at, str):
            expires_at = datetime.fromisoformat(expires_at)
        if expires_at.tzinfo is None:
            expires_at = expires_at.replace(tzinfo=timezone.utc)
        if datetime.now(timezone.utc) > expires_at:
            return render_error("Session expired", "Please tap the NFC tag again.")

        logger.info("Refresh via sessionStorage token: session=%s table=%s",
                    sess["id"], sess["table_id"])
        return render_template("order.html", error=None, error_title=None,
                               table_id=sess["table_id"], session_id=sess["id"],
                               counter=sess["counter"], refresh_token=refresh_token)

    # -----------------------------------------------------------------------
    # Path A — First load: token in URL
    # Consume token, generate refresh_token, return it to client
    # Client stores refresh_token in sessionStorage only
    # -----------------------------------------------------------------------
    if not token:
        return render_error("Invalid link", "This page must be opened by tapping an NFC tag.")

    sess = get_session_by_token(token)
    if not sess:
        return render_error("Invalid or expired token",
                            "This link has already been used or expired. Please tap the NFC tag again.")

    consumed = consume_session(sess["id"])
    if not consumed:
        return render_error("Link already used", "Please tap the NFC tag again.")

    # Generate a refresh token — stored only in browser sessionStorage
    # Never in URL, never in cookie — inaccessible from other browsers
    secret        = os.environ.get("SECRET_KEY", "changeme")
    refresh_token = hmac.new(
        key=secret.encode(),
        msg=f"refresh:{sess['id']}:{sess['counter']}".encode(),
        digestmod=hashlib.sha256
    ).hexdigest()[:32].upper()

    store_refresh_token(sess["id"], refresh_token)

    logger.info("Order page first load: table=%s session=%s", sess["table_id"], sess["id"])

    return render_template("order.html", error=None, error_title=None,
                           table_id=sess["table_id"], session_id=sess["id"],
                           counter=sess["counter"], refresh_token=refresh_token)


# ===========================================================================
# ADMIN PAGES
# ===========================================================================

@app.route("/admin/login", methods=["GET", "POST"])
@limiter.limit("5 per minute")
@limiter.limit("10 per hour")
def admin_login():
    error = None
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "").strip()

        user = get_admin_user(username)
        if user and bcrypt.checkpw(password.encode(), user["password_hash"].encode()):
            session.permanent = False  # cookie dies when browser closes
            session["admin_logged_in"]  = True
            session["admin_username"]   = username
            session["admin_login_time"] = datetime.now(timezone.utc).timestamp()
            return redirect(url_for("admin_dashboard"))
        else:
            error = "Invalid username or password"

    return render_template("admin_login.html", error=error)


@app.route("/admin/logout")
def admin_logout():
    session.clear()
    return redirect(url_for("admin_login"))


@app.route("/admin")
@admin_required
def admin_dashboard():
    raw_orders = get_all_orders()

    # Prepare data in Python — avoid complex Jinja2 filters
    orders = []
    for o in raw_orders:
        # Format time safely
        created_at = o.get("created_at")
        if created_at and hasattr(created_at, "strftime"):
            time_str = created_at.strftime("%H:%M")
        elif isinstance(created_at, str):
            time_str = created_at[11:16]
        else:
            time_str = ""

        # Pass raw ISO timestamp — browser JS will convert to local time
        created_at = o.get("created_at")
        if created_at and hasattr(created_at, "isoformat"):
            iso_time = created_at.isoformat()
        elif isinstance(created_at, str):
            iso_time = created_at
        else:
            iso_time = ""

        orders.append({
            "id":          str(o["id"]),
            "short_id":    str(o["id"])[:8].upper(),
            "table_id":    o["table_id"],
            "order_items": o["order_items"],
            "status":      o["status"],
            "total":       float(o["total"]),
            "payment":     o.get("payment", "cash"),
            "iso_time":    iso_time,
        })

    pending_count   = sum(1 for o in orders if o["status"] == "pending")
    preparing_count = sum(1 for o in orders if o["status"] == "preparing")
    ready_count     = sum(1 for o in orders if o["status"] == "ready")
    delivered_count = sum(1 for o in orders if o["status"] == "delivered")

    return render_template(
        "admin.html",
        orders=orders,
        pending_count=pending_count,
        preparing_count=preparing_count,
        ready_count=ready_count,
        delivered_count=delivered_count,
    )


@app.route("/admin/order/<order_id>/status", methods=["POST"])
@admin_required
def update_status(order_id):
    status = request.form.get("status", "").strip()
    if status not in ("pending", "preparing", "ready", "delivered"):
        return jsonify({"error": "Invalid status"}), 400

    update_order_status(order_id, status)
    return redirect(url_for("admin_dashboard"))


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
    return jsonify({"success": True, "uid": tag["uid"], "tableId": tag["table_id"]}), 200


@app.route("/api/health", methods=["GET"])
def health():
    return jsonify({"status": "ok"}), 200


# ===========================================================================
# Error handlers
# ===========================================================================

@app.errorhandler(404)
def not_found(e):
    return jsonify({"error": "Route not found"}), 404

@app.errorhandler(429)
def rate_limit_exceeded(e):
    return render_template("admin_login.html",
                           error="Too many attempts. Please wait and try again."), 429

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