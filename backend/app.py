"""
app.py
Flask backend + HTML frontend for the NFC Beach Bar ordering system.

This file now contains ONLY routing and request/response glue. The pieces that
were previously inlined here have moved to focused modules, with no change to
behaviour:
  * security.py    — generate_token / generate_refresh_token, admin/waiter auth
  * serializers.py — the order->JSON shape (was copy-pasted in 3 routes)
  * menu.py        — menu fetch + the name-map (get_name_map moved here)
  * db.py          — all database access (unchanged)

Security model — two-step redirect + sessionStorage refresh token:
  /nfc   — chip lands here with uid + ctr; validates counter, makes token, redirects
  /order — GET first load consumes token and issues a refresh token (sessionStorage)
           GET refresh validates the refresh token; POST places the order
"""

import os
import uuid
import logging
from datetime import datetime, timezone, timedelta

import bcrypt
from flask import (Flask, request, jsonify, render_template,
                   redirect, session, url_for)
from flask_cors import CORS
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from dotenv import load_dotenv

from menu import fetch_menu, get_name_map
from security import (generate_token, generate_refresh_token,
                      admin_required, waiter_required, WAITER_SESSION_KEY)
from serializers import orders_to_view
from db import (
    get_tag,
    create_session_full,
    consume_session,
    get_session_by_token,
    get_session_by_refresh_token,
    kill_session,
    register_tag,
    store_refresh_token,
    create_order,
    get_all_orders,
    get_all_tags,
    update_order_status,
    get_admin_user,
)

load_dotenv()

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "changeme")
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
app.config["PERMANENT_SESSION_LIFETIME"] = timedelta(hours=8)

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

BASE_URL = os.environ.get("BASE_URL", "http://localhost:5000")
CORS(app, origins=[BASE_URL])

# Rate limiter — protects login routes from brute force
limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=[],
    storage_uri="memory://",
)

VALID_STATUSES = ("pending", "preparing", "ready", "delivered", "cancelled")


# ===========================================================================
# CUSTOMER PAGES
# ===========================================================================

def _order_error(title, message):
    return render_template("order.html", error=message, error_title=title,
                           table_id=None, session_id=None, counter=None,
                           refresh_token=None, menu=[])


@app.route("/nfc-writer")
def nfc_writer_page():
    return render_template("nfc_writer.html")


@app.route("/nfc")
def nfc_landing():
    uid = request.args.get("uid", "").strip().upper()
    ctr = request.args.get("ctr", "").strip().upper()

    # 1 — Parameters must be present
    if not uid or not ctr:
        return _order_error("Invalid link", "This page must be opened by tapping an NFC tag.")

    # 2 — Resolve + validate tag
    tag = get_tag(uid)
    if not tag:
        return _order_error("Tag not registered", "Complete setup in /nfc-writer first.")

    try:
        incoming_counter = int(ctr, 16)
    except ValueError:
        return _order_error("Invalid link", "Malformed counter value.")

    # 3 — Replay protection
    if incoming_counter <= tag.get("last_counter", 0):
        logger.warning("Replay detected uid=%s incoming=%d last=%d",
                       uid, incoming_counter, tag["last_counter"])
        return _order_error("Link already used", "Please tap the NFC tag again.")

    # 4 — Generate tokens
    table_id      = tag["table_id"]
    session_id    = str(uuid.uuid4())
    token         = generate_token(uid, ctr, session_id)
    refresh_token = generate_refresh_token(session_id, incoming_counter)

    # 5 — Single DB transaction: insert session + bump counter
    create_session_full(uid, table_id, incoming_counter, token, refresh_token)
    logger.info("Valid tap: uid=%s table=%s ctr=%d", uid, table_id, incoming_counter)

    # 6 — Redirect — uid/ctr never appear in browser history
    return redirect(f"/order?token={token}")


@app.route("/order", methods=["GET", "POST"])
def order_page():
    if request.method == "POST":
        return _place_customer_order()
    return _serve_order_page()


def _place_customer_order():
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

    kill_session(sess["id"])
    logger.info("Order placed and session killed: table=%s total=%.2f session=%s",
                sess["table_id"], total, sess["id"])
    return jsonify({"success": True, "orderId": order["id"]}), 200


def _serve_order_page():
    token         = request.args.get("token", "").strip().upper()
    refresh_token = request.headers.get("X-Refresh-Token", "").strip().upper()

    logger.info("Order page hit: token=%s refresh=%s",
                token[:8] if token else "none",
                refresh_token[:8] if refresh_token else "none")

    # Path B — Refresh via sessionStorage token (no URL token)
    if refresh_token and not token:
        sess = get_session_by_refresh_token(refresh_token)
        if not sess:
            return _order_error("Session expired", "Please tap the NFC tag again.")

        expires_at = sess["expires_at"]
        if isinstance(expires_at, str):
            expires_at = datetime.fromisoformat(expires_at)
        if expires_at.tzinfo is None:
            expires_at = expires_at.replace(tzinfo=timezone.utc)
        if datetime.now(timezone.utc) > expires_at:
            return _order_error("Session expired", "Please tap the NFC tag again.")

        logger.info("Refresh via sessionStorage token: session=%s table=%s",
                    sess["id"], sess["table_id"])
        return render_template("order.html", error=None, error_title=None,
                               table_id=sess["table_id"], session_id=sess["id"],
                               counter=sess["counter"], refresh_token=refresh_token,
                               menu=fetch_menu())

    # Path A — First load via URL token
    if not token:
        return _order_error("Invalid link", "This page must be opened by tapping an NFC tag.")

    sess = get_session_by_token(token)
    if not sess:
        return _order_error("Invalid or expired token",
                            "This link has already been used or expired. Please tap the NFC tag again.")

    if not consume_session(sess["id"]):
        return _order_error("Link already used", "Please tap the NFC tag again.")

    refresh_token = generate_refresh_token(sess["id"], sess["counter"])
    store_refresh_token(sess["id"], refresh_token)
    logger.info("Order page first load: table=%s session=%s", sess["table_id"], sess["id"])

    return render_template("order.html", error=None, error_title=None,
                           table_id=sess["table_id"], session_id=sess["id"],
                           counter=sess["counter"], refresh_token=refresh_token,
                           menu=fetch_menu())


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
            session.permanent = False
            session["admin_logged_in"]  = True
            session["admin_username"]   = username
            session["admin_login_time"] = datetime.now(timezone.utc).timestamp()
            return redirect(url_for("admin_dashboard"))
        error = "Invalid username or password"
    return render_template("admin_login.html", error=error)


@app.route("/admin/logout")
def admin_logout():
    session.clear()
    return redirect(url_for("admin_login"))


@app.route("/admin")
@admin_required
def admin_dashboard():
    orders = orders_to_view(get_all_orders())

    counts = {s: sum(1 for o in orders if o["status"] == s) for s in VALID_STATUSES}

    from collections import defaultdict
    tables_map = defaultdict(list)
    for o in orders:
        tables_map[o["table_id"]].append(o)

    return render_template(
        "admin.html",
        orders=orders,
        tables=sorted(tables_map.keys()),
        tables_map=dict(tables_map),
        pending_count=counts["pending"],
        preparing_count=counts["preparing"],
        ready_count=counts["ready"],
        delivered_count=counts["delivered"],
        cancelled_count=counts["cancelled"],
    )


@app.route("/admin/order/<order_id>/status", methods=["POST"])
@admin_required
def update_status(order_id):
    if request.is_json:
        status = (request.get_json() or {}).get("status", "").strip()
    else:
        status = request.form.get("status", "").strip()

    if status not in VALID_STATUSES:
        return jsonify({"error": "Invalid status"}), 400

    update_order_status(order_id, status)

    if request.is_json or request.headers.get("X-Requested-With") == "fetch":
        return jsonify({"success": True, "status": status}), 200
    return redirect(url_for("admin_dashboard"))


# ===========================================================================
# WAITER ROUTES
# ===========================================================================

@app.route("/waiter/login", methods=["GET", "POST"])
@limiter.limit("5 per minute")
@limiter.limit("10 per hour")
def waiter_login():
    error = None
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "").strip()
        # Note: intentionally shares the admin_users account (single combined
        # account for admin+waiter, per current design).
        user = get_admin_user(username)
        if user and bcrypt.checkpw(password.encode(), user["password_hash"].encode()):
            session.permanent = False
            session[WAITER_SESSION_KEY] = True
            session["waiter_username"]  = username
            return redirect(url_for("waiter_order"))
        error = "Invalid username or password"
    return render_template("waiter_login.html", error=error)


@app.route("/waiter/logout")
def waiter_logout():
    session.pop(WAITER_SESSION_KEY, None)
    session.pop("waiter_username", None)
    return redirect(url_for("waiter_login"))


@app.route("/waiter")
@waiter_required
def waiter_order():
    return render_template(
        "waiter_order.html",
        menu=fetch_menu(),
        tags=get_all_tags(),
        username=session.get("waiter_username", "Waiter"),
    )


@app.route("/waiter/orders")
@waiter_required
def waiter_orders_api():
    """Read-only orders list for the waiter view — same data as admin, JSON."""
    return jsonify({"orders": orders_to_view(get_all_orders())}), 200


@app.route("/waiter/order", methods=["POST"])
@waiter_required
def waiter_place_order():
    body     = request.get_json(silent=True) or {}
    table_id = body.get("tableId", "").strip()
    items    = body.get("items",   [])
    payment  = body.get("payment", "cash").strip()

    if not table_id:
        return jsonify({"error": "Missing tableId"}), 400
    if not items:
        return jsonify({"error": "No items in order"}), 400

    total  = sum(item.get("price", 0) * item.get("qty", 1) for item in items)
    waiter = session.get("waiter_username", "staff")
    order  = create_order(
        session_id=str(uuid.uuid4()),
        table_id=table_id,
        items=items,
        total=total,
        payment=payment,
        source="waiter",
        waiter_name=waiter,
    )
    logger.info("Waiter order: table=%s total=%.2f by=%s", table_id, total, waiter)
    return jsonify({"success": True, "orderId": order["id"]}), 200


# ===========================================================================
# API ENDPOINTS
# ===========================================================================

@app.route("/api/admin-orders")
@admin_required
def api_admin_orders():
    """Orders JSON for the admin dashboard soft refresh."""
    return jsonify({"orders": orders_to_view(get_all_orders())})


@app.route("/api/menu-names")
def api_menu_names():
    return jsonify(get_name_map())


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