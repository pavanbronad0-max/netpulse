import base64
import json
import os
import re
import urllib.error
import urllib.request
import uuid
from pathlib import Path

from config import MAX_FILE_SIZE, UPLOAD_DIR
from database import transaction
from discovery import NODE_ID, peer_url
from encryption import decrypt_from_peer, encrypt_at_rest, encrypt_for_peer

SAFE_FILENAME = re.compile(r"^[^/\\\x00-\x1f]{1,180}$")


def _store(identifier, encrypted):
    UPLOAD_DIR.mkdir(parents=True, exist_ok=True)
    path = UPLOAD_DIR / f"{identifier}.blob"
    path.write_bytes(encrypt_at_rest(encrypted))
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass
    return str(path)


def _read(path):
    from encryption import decrypt_at_rest
    return decrypt_at_rest(Path(path).read_bytes())


def _filename(value):
    value = Path(str(value or "upload")).name
    if not SAFE_FILENAME.fullmatch(value) or value in {".", ".."}:
        raise ValueError("Invalid filename.")
    return value


def send_to_peer(user_id, peer, filename, content, content_type):
    filename = _filename(filename)
    if len(content) > MAX_FILE_SIZE:
        raise ValueError(f"File exceeds the {MAX_FILE_SIZE // (1024 * 1024)} MB limit.")
    encrypted, wrapped, nonce = encrypt_for_peer(content, peer["public_key"])
    identifier = str(uuid.uuid4())
    path = _store(identifier, content)
    with transaction() as db:
        db.execute(
            """INSERT INTO transfers
               (id,owner_id,peer_id,direction,filename,size,content_type,status,payload_path,wrapped_key,nonce)
               VALUES (?,?,?,'outgoing',?,?,?,'Sending',?,?,?)""",
            (identifier, user_id, peer["node_id"], filename, len(content), content_type, path, wrapped, nonce),
        )
    payload = json.dumps({
        "sender_node_id": NODE_ID,
        "filename": filename,
        "size": len(content),
        "content_type": content_type,
        "ciphertext": base64.b64encode(encrypted).decode("ascii"),
        "wrapped_key": wrapped,
        "nonce": nonce,
    }).encode("utf-8")
    request = urllib.request.Request(
        peer_url(peer) + "/api/peer/transfers",
        data=payload,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=10) as response:
            if response.status not in {200, 201}:
                raise ValueError("Recipient did not accept the transfer.")
        status = "Delivered — awaiting approval"
    except (urllib.error.URLError, TimeoutError, ValueError) as exc:
        status = "Failed"
        with transaction() as db:
            db.execute("UPDATE transfers SET status=? WHERE id=?", (status, identifier))
        raise ValueError(f"Could not reach recipient: {exc}") from exc
    with transaction() as db:
        db.execute("UPDATE transfers SET status=? WHERE id=?", (status, identifier))
        db.execute("INSERT INTO activities(user_id,message) VALUES (?,?)", (user_id, f"Sent {filename} to {peer['name']}"))
    return identifier


def receive_from_peer(payload, sender, ip_address):
    if not isinstance(payload, dict) or payload.get("sender_node_id") != sender["node_id"]:
        raise ValueError("Sender identity does not match the authorized peer.")
    try:
        filename = _filename(payload.get("filename"))
        size = int(payload["size"])
        content_type = str(payload.get("content_type", "application/octet-stream"))[:120]
        if not re.fullmatch(r"[A-Za-z0-9!#$&^_.+-]+/[A-Za-z0-9!#$&^_.+-]+", content_type):
            content_type = "application/octet-stream"
        encrypted = base64.b64decode(payload["ciphertext"], validate=True)
        wrapped = str(payload["wrapped_key"])
        nonce = str(payload["nonce"])
    except (KeyError, TypeError, ValueError) as exc:
        raise ValueError("Invalid transfer payload.") from exc
    if size < 0 or size > MAX_FILE_SIZE or len(encrypted) != size + 16:
        raise ValueError("Transfer exceeds the configured size limit.")
    identifier = str(uuid.uuid4())
    path = _store(identifier, encrypted)
    with transaction() as db:
        peer = db.execute(
            "SELECT trusted,ip_address FROM peers WHERE node_id=?", (sender["node_id"],)
        ).fetchone()
        if not peer or not peer["trusted"] or peer["ip_address"] != ip_address:
            Path(path).unlink(missing_ok=True)
            raise PermissionError("Sender is not a trusted peer.")
        user = db.execute("SELECT id FROM users ORDER BY id LIMIT 1").fetchone()
        if not user:
            Path(path).unlink(missing_ok=True)
            raise PermissionError("This device has no registered user.")
        db.execute(
            """INSERT INTO transfers
               (id,owner_id,peer_id,direction,filename,size,content_type,status,payload_path,wrapped_key,nonce)
               VALUES (?,?,?,'incoming',?,?,?,'Awaiting approval',?,?,?)""",
            (identifier, user["id"], sender["node_id"], filename, size, content_type, path, wrapped, nonce),
        )
        db.execute("INSERT INTO activities(user_id,message) VALUES (?,?)", (user["id"], f"Incoming file request: {filename}"))
    return identifier


def get_transfer(user_id, identifier):
    with transaction() as db:
        return db.execute(
            "SELECT * FROM transfers WHERE id=? AND owner_id=?", (identifier, user_id)
        ).fetchone()


def download_content(transfer):
    encrypted = _read(transfer["payload_path"])
    if transfer["direction"] == "incoming":
        if transfer["status"] != "Accepted":
            raise PermissionError("Transfer must be accepted before download.")
        return decrypt_from_peer(encrypted, transfer["wrapped_key"], transfer["nonce"])
    return encrypted


def mark_decision(user_id, identifier, accept):
    transfer = get_transfer(user_id, identifier)
    if not transfer or transfer["direction"] != "incoming":
        raise ValueError("Incoming transfer not found.")
    if transfer["status"] != "Awaiting approval":
        raise ValueError("This transfer has already been processed.")
    with transaction() as db:
        status = "Accepted" if accept else "Rejected"
        db.execute("UPDATE transfers SET status=? WHERE id=?", (status, identifier))
        db.execute("INSERT INTO activities(user_id,message) VALUES (?,?)", (user_id, f"{status} file: {transfer['filename']}"))
    if not accept:
        Path(transfer["payload_path"]).unlink(missing_ok=True)
    return status
