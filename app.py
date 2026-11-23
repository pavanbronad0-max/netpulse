import os
import secrets
import time
import uuid
from collections import deque
from functools import wraps
from io import BytesIO

from dotenv import load_dotenv

load_dotenv()

from flask import (
    Flask, jsonify, make_response, redirect, render_template, request, send_file, session,
)
from flask_socketio import SocketIO, emit
from werkzeug.utils import secure_filename

import config
from auth import authenticate, login_required, register_user
from database import init_db, transaction
from discovery import NODE_ID, start_discovery
from encryption import decrypt_at_rest, encrypt_at_rest, fingerprint, public_key_b64
from file_transfer import (
    download_content, get_transfer, mark_decision, receive_from_peer, send_to_peer,
)
from network_monitor import current_network_stats, export_csv
from telemetry import snapshot


def _secret_key():
    config.DATA_DIR.mkdir(parents=True, exist_ok=True)
    if not config.SECRET_FILE.exists():
        config.SECRET_FILE.write_bytes(secrets.token_bytes(32))
        try:
            os.chmod(config.SECRET_FILE, 0o600)
        except OSError:
            pass
    return config.SECRET_FILE.read_bytes()


app = Flask(__name__)
app.config.update(
    SECRET_KEY=os.environ.get("NETPULSE_SECRET_KEY") or _secret_key(),
    MAX_CONTENT_LENGTH=config.MAX_FILE_SIZE * 2 + 1024 * 1024,
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SECURE=config.COOKIE_SECURE or bool(config.TLS_CERT_FILE and config.TLS_KEY_FILE),
    SESSION_COOKIE_SAMESITE="Lax",
    PERMANENT_SESSION_LIFETIME=60 * 60 * 12,
)
socketio = SocketIO(app, async_mode="threading", cors_allowed_origins=[])
telemetry_history = deque(maxlen=600)
_monitor_started = False


@app.after_request
def security_headers(response):
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; script-src 'self' https://cdn.socket.io; "
        "style-src 'self'; img-src 'self' data:; connect-src 'self' ws: wss:; "
        "font-src 'self'; object-src 'none'; frame-ancestors 'none'; base-uri 'self'"
    )
    return response


@app.errorhandler(413)
def request_too_large(_error):
    return jsonify({"error": f"Request exceeds the configured {config.MAX_FILE_SIZE // (1024 * 1024)} MB file limit."}), 413


def csrf_protected(function):
    @wraps(function)
    def wrapped(*args, **kwargs):
        expected = session.get("csrf_token")
        supplied = request.headers.get("X-CSRF-Token", "")
        if not expected or not secrets.compare_digest(expected, supplied):
            return jsonify({"error": "Invalid CSRF token"}), 403
        return function(*args, **kwargs)
    return wrapped


def _peer_dict(row, now=None):
    now = time.time() if now is None else now
    return {
        "node_id": row["node_id"],
        "name": row["name"],
        "hostname": row["hostname"],
        "ip_address": row["ip_address"],
        "fingerprint": row["fingerprint"],
        "trusted": bool(row["trusted"]),
        "last_seen": row["last_seen"],
        "online": now - row["last_seen"] < 15,
    }


def _activity(user_id, message):
    with transaction() as db:
        db.execute("INSERT INTO activities(user_id,message) VALUES (?,?)", (user_id, message))


@app.get("/")
def home():
    return render_template("dashboard.html")


@app.get("/login")
def login_page():
    return render_template("login.html")


@app.get("/health")
def health():
    return jsonify({"status": "ok"})


@app.get("/api/auth/csrf")
def csrf_token():
    session.setdefault("csrf_token", secrets.token_urlsafe(32))
    return jsonify({"csrf_token": session["csrf_token"]})


@app.get("/api/auth/me")
def current_user():
    user_id = session.get("user_id")
    if not user_id:
        return jsonify({"authenticated": False})
    with transaction() as db:
        user = db.execute("SELECT id,username FROM users WHERE id=?", (user_id,)).fetchone()
    if not user:
        session.clear()
        return jsonify({"authenticated": False})
    return jsonify({"authenticated": True, "user": dict(user)})


@app.post("/api/auth/register")
def register():
    body = request.get_json(silent=True) or {}
    try:
        user = register_user(body.get("username"), body.get("password"))
    except ValueError as exc:
        return jsonify({"error": str(exc)}), 400
    session.clear()
    session["user_id"] = user["id"]
    session["username"] = user["username"]
    session.permanent = True
    session["csrf_token"] = secrets.token_urlsafe(32)
    return jsonify({"user": user}), 201


@app.post("/api/auth/login")
def login():
    body = request.get_json(silent=True) or {}
    username, password = body.get("username", ""), body.get("password", "")
    if not isinstance(username, str) or not isinstance(password, str):
        return jsonify({"error": "Invalid username or password."}), 400
    user, error = authenticate(username, password, request.remote_addr or "unknown")
    if error:
        return jsonify({"error": error}), 429 if error.startswith("Too many") else 401
    session.clear()
    session["user_id"] = user["id"]
    session["username"] = user["username"]
    session.permanent = True
    session["csrf_token"] = secrets.token_urlsafe(32)
    _activity(user["id"], "Signed in")
    return jsonify({"user": user})


@app.post("/api/auth/logout")
@login_required
@csrf_protected
def logout():
    session.clear()
    return jsonify({"ok": True})


@app.get("/api/dashboard")
@login_required
def dashboard_data():
    user_id = session["user_id"]
    now = time.time()
    with transaction() as db:
        peers = db.execute("SELECT last_seen FROM peers").fetchall()
        transfer_count = db.execute(
            "SELECT COUNT(*) AS count FROM transfers WHERE owner_id=? AND status IN ('Available','Accepted','Delivered — awaiting approval')",
            (user_id,),
        ).fetchone()["count"]
        activities = db.execute(
            "SELECT message,created_at FROM activities WHERE user_id=? ORDER BY id DESC LIMIT 8",
            (user_id,),
        ).fetchall()
    metrics = snapshot()
    telemetry_history.append(metrics)
    return jsonify({
        "metrics": metrics,
        "online_peers": sum(now - peer["last_seen"] < 15 for peer in peers),
        "transferred_files": transfer_count,
        "activities": [dict(row) for row in activities],
    })


@app.get("/api/peers")
@login_required
def list_peers():
    with transaction() as db:
        rows = db.execute("SELECT * FROM peers ORDER BY last_seen DESC").fetchall()
    return jsonify({"peers": [_peer_dict(row) for row in rows]})


@app.post("/api/peers/<node_id>/trust")
@login_required
@csrf_protected
def trust_peer(node_id):
    with transaction() as db:
        peer = db.execute("SELECT * FROM peers WHERE node_id=?", (node_id,)).fetchone()
        if not peer:
            return jsonify({"error": "Peer not found"}), 404
        db.execute("UPDATE peers SET trusted=1 WHERE node_id=?", (node_id,))
        db.execute("INSERT INTO activities(user_id,message) VALUES (?,?)", (session["user_id"], f"Trusted peer {peer['name']}"))
    return jsonify({"ok": True})


@app.delete("/api/peers/<node_id>/trust")
@login_required
@csrf_protected
def untrust_peer(node_id):
    with transaction() as db:
        peer = db.execute("SELECT name FROM peers WHERE node_id=?", (node_id,)).fetchone()
        if not peer:
            return jsonify({"error": "Peer not found"}), 404
        db.execute("UPDATE peers SET trusted=0 WHERE node_id=?", (node_id,))
        db.execute("INSERT INTO activities(user_id,message) VALUES (?,?)", (session["user_id"], f"Removed trust for {peer['name']}"))
    return jsonify({"ok": True})


@app.route("/api/transfers", methods=["GET", "POST"])
@login_required
def transfers():
    user_id = session["user_id"]
    if request.method == "GET":
        with transaction() as db:
            rows = db.execute(
                """SELECT t.*,p.name AS peer_name FROM transfers t
                   LEFT JOIN peers p ON p.node_id=t.peer_id
                   WHERE t.owner_id=? ORDER BY t.created_at DESC LIMIT 200""",
                (user_id,),
            ).fetchall()
        return jsonify({"transfers": [
            {key: row[key] for key in ("id", "peer_id", "peer_name", "direction", "filename", "size", "content_type", "status", "created_at")}
            for row in rows
        ]})
    if not request.headers.get("X-CSRF-Token"):
        return jsonify({"error": "CSRF token required"}), 403
    return _upload_transfer(user_id)


def _upload_transfer(user_id):
    token = session.get("csrf_token", "")
    if not token or not secrets.compare_digest(token, request.headers.get("X-CSRF-Token", "")):
        return jsonify({"error": "Invalid CSRF token"}), 403
    uploaded = request.files.get("file")
    if not uploaded or not uploaded.filename:
        return jsonify({"error": "Choose a file to upload."}), 400
    filename = secure_filename(uploaded.filename)
    if not filename:
        return jsonify({"error": "Invalid filename."}), 400
    content = uploaded.read(config.MAX_FILE_SIZE + 1)
    if not content:
        return jsonify({"error": "Empty files are not allowed."}), 400
    if len(content) > config.MAX_FILE_SIZE:
        return jsonify({"error": f"File exceeds the {config.MAX_FILE_SIZE // (1024 * 1024)} MB limit."}), 413
    content_type = uploaded.mimetype or "application/octet-stream"
    peer_id = request.form.get("peer_id", "")
    if peer_id:
        with transaction() as db:
            peer = db.execute("SELECT * FROM peers WHERE node_id=?", (peer_id,)).fetchone()
        if not peer or not peer["trusted"]:
            return jsonify({"error": "Trust the recipient device before sending files."}), 403
        if time.time() - peer["last_seen"] >= 15:
            return jsonify({"error": "Recipient is offline. Try again when it is online."}), 409
        public_peer = dict(peer)
        try:
            identifier = send_to_peer(user_id, public_peer, filename, content, content_type)
        except ValueError as exc:
            return jsonify({"error": str(exc)}), 502
    else:
        identifier = str(uuid.uuid4())
        config.UPLOAD_DIR.mkdir(parents=True, exist_ok=True)
        path = config.UPLOAD_DIR / f"{identifier}.blob"
        path.write_bytes(encrypt_at_rest(content))
        try:
            os.chmod(path, 0o600)
        except OSError:
            pass
        with transaction() as db:
            db.execute(
                """INSERT INTO transfers
                   (id,owner_id,direction,filename,size,content_type,status,payload_path)
                   VALUES (?,?,'local',?,?,?,'Available',?)""",
                (identifier, user_id, filename, len(content), content_type, str(path)),
            )
            db.execute("INSERT INTO activities(user_id,message) VALUES (?,?)", (user_id, f"Stored {filename} in encrypted vault"))
    return jsonify({"id": identifier, "status": "Delivered — awaiting approval" if peer_id else "Available"}), 201


@app.post("/api/peer/transfers")
def incoming_transfer():
    if request.content_length is not None and request.content_length > config.MAX_FILE_SIZE * 2:
        return jsonify({"error": "Transfer exceeds the configured size limit."}), 413
    payload = request.get_json(silent=True)
    sender_id = payload.get("sender_node_id") if isinstance(payload, dict) else None
    if not sender_id:
        return jsonify({"error": "Invalid sender."}), 400
    with transaction() as db:
        sender = db.execute("SELECT node_id FROM peers WHERE node_id=?", (sender_id,)).fetchone()
    if not sender:
        return jsonify({"error": "Unknown NetPulse device."}), 403
    try:
        identifier = receive_from_peer(payload, sender, request.remote_addr or "")
    except PermissionError as exc:
        return jsonify({"error": str(exc)}), 403
    except ValueError as exc:
        return jsonify({"error": str(exc)}), 400
    return jsonify({"id": identifier, "status": "Awaiting approval"}), 201


@app.post("/api/transfers/<identifier>/decision")
@login_required
@csrf_protected
def decide_transfer(identifier):
    body = request.get_json(silent=True) or {}
    if not isinstance(body.get("accept"), bool):
        return jsonify({"error": "An accept decision is required."}), 400
    try:
        status = mark_decision(session["user_id"], identifier, body["accept"])
    except ValueError as exc:
        return jsonify({"error": str(exc)}), 404
    return jsonify({"status": status})


@app.get("/api/transfers/<identifier>/download")
@login_required
def download_transfer(identifier):
    transfer = get_transfer(session["user_id"], identifier)
    if not transfer:
        return jsonify({"error": "Transfer not found"}), 404
    if transfer["direction"] == "incoming" and transfer["status"] != "Accepted":
        return jsonify({"error": "Accept this transfer before downloading."}), 403
    try:
        content = download_content(transfer)
    except (PermissionError, ValueError) as exc:
        return jsonify({"error": str(exc)}), 403
    response = make_response(content)
    response.headers["Content-Type"] = transfer["content_type"]
    response.headers["Content-Disposition"] = f'attachment; filename="{secure_filename(transfer["filename"])}"'
    response.headers["Content-Length"] = str(len(content))
    response.headers["Cache-Control"] = "no-store"
    return response


@app.get("/api/telemetry")
@login_required
def telemetry_data():
    item = snapshot()
    telemetry_history.append(item)
    return jsonify(item)


@app.get("/api/network")
@login_required
def network_data():
    return jsonify(current_network_stats())


@app.get("/api/telemetry/export.csv")
@login_required
def telemetry_export():
    return send_file(
        BytesIO(export_csv(list(telemetry_history)).encode("utf-8")),
        mimetype="text/csv",
        as_attachment=True,
        download_name="netpulse-telemetry.csv",
    )


@app.get("/api/activity")
@login_required
def activity_data():
    with transaction() as db:
        rows = db.execute(
            "SELECT message,created_at FROM activities WHERE user_id=? ORDER BY id DESC LIMIT 100",
            (session["user_id"],),
        ).fetchall()
    return jsonify({"activities": [dict(row) for row in rows]})


@app.get("/api/settings")
@login_required
def get_settings():
    with transaction() as db:
        rows = db.execute("SELECT key,value FROM settings WHERE user_id=?", (session["user_id"],)).fetchall()
    saved = {row["key"]: row["value"] for row in rows}
    return jsonify({
        "monitor_interval": int(saved.get("monitor_interval", config.MONITOR_INTERVAL)),
        "theme": saved.get("theme", "dark"),
        "max_file_size": config.MAX_FILE_SIZE,
        "discovery_enabled": config.DISCOVERY_ENABLED,
        "device_name": os.environ.get("NETPULSE_DEVICE_NAME", os.environ.get("COMPUTERNAME", os.uname().nodename if hasattr(os, "uname") else "NetPulse device")),
        "node_id": NODE_ID,
        "fingerprint": fingerprint(public_key_b64()),
    })


@app.post("/api/settings")
@login_required
@csrf_protected
def save_settings():
    body = request.get_json(silent=True) or {}
    interval = body.get("monitor_interval")
    theme = body.get("theme")
    if interval is not None and (not isinstance(interval, int) or not 2 <= interval <= 30):
        return jsonify({"error": "Monitoring interval must be between 2 and 30 seconds."}), 400
    if theme is not None and theme not in {"dark", "light"}:
        return jsonify({"error": "Theme must be dark or light."}), 400
    with transaction() as db:
        for key, value in (("monitor_interval", interval), ("theme", theme)):
            if value is not None:
                db.execute(
                    "INSERT INTO settings(user_id,key,value) VALUES (?,?,?) ON CONFLICT(user_id,key) DO UPDATE SET value=excluded.value",
                    (session["user_id"], key, str(value)),
                )
    return jsonify({"ok": True})


@socketio.on("connect")
def socket_connect():
    if "user_id" not in session:
        return False
    emit("connected", {"status": "online"})


def _monitor():
    while True:
        interval = config.MONITOR_INTERVAL
        try:
            with transaction() as db:
                row = db.execute("SELECT MIN(CAST(value AS INTEGER)) AS interval FROM settings WHERE key='monitor_interval'").fetchone()
            if row and row["interval"]:
                interval = max(2, min(30, row["interval"]))
            metrics = snapshot()
            telemetry_history.append(metrics)
            with transaction() as db:
                online = db.execute("SELECT COUNT(*) AS count FROM peers WHERE ? - last_seen < 15", (time.time(),)).fetchone()["count"]
            socketio.emit("telemetry", {"metrics": metrics, "online_peers": online})
        except Exception:
            app.logger.exception("Telemetry update failed")
        time.sleep(interval)


def start_services():
    global _monitor_started
    init_db()
    start_discovery()
    if not _monitor_started:
        _monitor_started = True
        socketio.start_background_task(_monitor)


if __name__ == "__main__":
    if bool(config.TLS_CERT_FILE) != bool(config.TLS_KEY_FILE):
        raise RuntimeError("Set both NETPULSE_TLS_CERT and NETPULSE_TLS_KEY to enable HTTPS.")
    tls_context = (
        (config.TLS_CERT_FILE, config.TLS_KEY_FILE)
        if config.TLS_CERT_FILE and config.TLS_KEY_FILE
        else None
    )
    start_services()
    socketio.run(
        app,
        host=config.HOST,
        port=config.PORT,
        debug=False,
        allow_unsafe_werkzeug=True,
        ssl_context=tls_context,
    )
