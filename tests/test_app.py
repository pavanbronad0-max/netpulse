import os
import tempfile
from io import BytesIO
from pathlib import Path

os.environ.setdefault("NETPULSE_DATA_DIR", tempfile.mkdtemp(prefix="netpulse-tests-"))
os.environ.setdefault("NETPULSE_DISCOVERY", "0")

import pytest

import config
import database
from app import app
from database import transaction
from encryption import encrypt_for_peer, public_key_b64


@pytest.fixture(autouse=True)
def reset_database():
    database.init_db()
    with transaction() as db:
        db.execute("DELETE FROM transfers")
        db.execute("DELETE FROM activities")
        db.execute("DELETE FROM settings")
        db.execute("DELETE FROM peers")
        db.execute("DELETE FROM users")
    for path in config.UPLOAD_DIR.glob("*.blob"):
        path.unlink()


@pytest.fixture
def client():
    app.config.update(TESTING=True, WTF_CSRF_ENABLED=False)
    return app.test_client()


def register(client, username="testuser"):
    response = client.post("/api/auth/register", json={"username": username, "password": "a-strong-password-123"})
    assert response.status_code == 201
    return client.get("/api/auth/csrf").json["csrf_token"]


def test_registration_session_and_login(client):
    csrf = register(client)
    assert client.get("/api/auth/me").json["authenticated"] is True
    client.post("/api/auth/logout", headers={"X-CSRF-Token": csrf})
    assert client.get("/api/auth/me").json["authenticated"] is False
    response = client.post("/api/auth/login", json={"username": "testuser", "password": "a-strong-password-123"})
    assert response.status_code == 200
    assert response.json["user"]["username"] == "testuser"


def test_local_upload_is_encrypted_and_only_owner_can_download(client):
    csrf = register(client)
    response = client.post(
        "/api/transfers",
        data={"file": (BytesIO(b"private payload"), "notes.txt")},
        headers={"X-CSRF-Token": csrf},
        content_type="multipart/form-data",
    )
    assert response.status_code == 201
    identifier = response.json["id"]
    with transaction() as db:
        transfer = db.execute("SELECT payload_path FROM transfers WHERE id=?", (identifier,)).fetchone()
    assert Path(transfer["payload_path"]).read_bytes() != b"private payload"
    assert client.get(f"/api/transfers/{identifier}/download").data == b"private payload"

    other = app.test_client()
    other.post("/api/auth/register", json={"username": "otheruser", "password": "another-strong-password"})
    assert other.get(f"/api/transfers/{identifier}/download").status_code == 404


def test_incoming_peer_transfer_requires_trust_and_acceptance(client):
    csrf = register(client)
    sender_id = "authorized-sender"
    sender_key = public_key_b64()
    with transaction() as db:
        db.execute(
            """INSERT INTO peers(node_id,name,hostname,ip_address,port,scheme,public_key,fingerprint,trusted,last_seen)
               VALUES (?,?,?,?,?,?,?,?,1,?)""",
            (sender_id, "Sender", "sender-host", "127.0.0.1", 5000, "http", sender_key, "fingerprint", 1),
        )
    encrypted, wrapped, nonce = encrypt_for_peer(b"hello from peer", public_key_b64())
    import base64
    response = client.post("/api/peer/transfers", json={
        "sender_node_id": sender_id,
        "filename": "hello.txt",
        "size": len(b"hello from peer"),
        "content_type": "text/plain",
        "ciphertext": base64.b64encode(encrypted).decode("ascii"),
        "wrapped_key": wrapped,
        "nonce": nonce,
    })
    assert response.status_code == 201
    identifier = response.json["id"]
    assert client.get(f"/api/transfers/{identifier}/download").status_code == 403
    accepted = client.post(
        f"/api/transfers/{identifier}/decision",
        json={"accept": True},
        headers={"X-CSRF-Token": csrf},
    )
    assert accepted.json["status"] == "Accepted"
    assert client.get(f"/api/transfers/{identifier}/download").data == b"hello from peer"


def test_telemetry_and_dashboard_are_live_api_responses(client):
    register(client)
    response = client.get("/api/dashboard")
    assert response.status_code == 200
    assert {"cpu_percent", "memory_percent", "disk_percent", "upload_bps", "download_bps"} <= set(response.json["metrics"])
    assert client.get("/api/peers").json["peers"] == []
