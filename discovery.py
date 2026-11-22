import json
import ipaddress
import socket
import threading
import time
from urllib.parse import urlunparse

from config import DISCOVERY_ENABLED, DISCOVERY_PORT, PUBLIC_PORT, PUBLIC_SCHEME
from config import DATA_DIR, NODE_ID_FILE
from database import transaction
from encryption import fingerprint, public_key_b64


def _node_id():
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    if not NODE_ID_FILE.exists():
        NODE_ID_FILE.write_text(str(__import__("uuid").uuid4()), encoding="ascii")
        try:
            import os
            os.chmod(NODE_ID_FILE, 0o600)
        except OSError:
            pass
    return NODE_ID_FILE.read_text(encoding="ascii").strip()


NODE_ID = _node_id()
_stop = threading.Event()
_started = False


def _payload():
    key = public_key_b64()
    return {
        "app": "netpulse",
        "node_id": NODE_ID,
        "name": socket.gethostname(),
        "hostname": socket.gethostname(),
        "port": PUBLIC_PORT,
        "scheme": PUBLIC_SCHEME,
        "public_key": key,
        "fingerprint": fingerprint(key),
    }


def _record(message, address):
    if not isinstance(message, dict) or message.get("app") != "netpulse":
        return
    node_id = str(message.get("node_id", ""))
    if not node_id or node_id == NODE_ID:
        return
    try:
        port = int(message["port"])
        if not 1 <= port <= 65535:
            return
        ip = address[0]
        if not ipaddress.ip_address(ip).is_private:
            return
        key = str(message["public_key"])
        peer_fingerprint = fingerprint(key)
        name = str(message.get("name", "Unknown device"))[:100]
        hostname = str(message.get("hostname", name))[:100]
        scheme = message.get("scheme")
        if scheme not in {"http", "https"}:
            return
    except (KeyError, TypeError, ValueError):
        return
    with transaction() as db:
        current = db.execute(
            "SELECT public_key, trusted FROM peers WHERE node_id = ?", (node_id,)
        ).fetchone()
        trusted = int(bool(current and current["trusted"] and current["public_key"] == key))
        db.execute(
            """INSERT INTO peers
               (node_id,name,hostname,ip_address,port,scheme,public_key,fingerprint,trusted,last_seen)
               VALUES (?,?,?,?,?,?,?,?,?,?)
               ON CONFLICT(node_id) DO UPDATE SET
               name=excluded.name, hostname=excluded.hostname, ip_address=excluded.ip_address,
               port=excluded.port, scheme=excluded.scheme, public_key=excluded.public_key,
               fingerprint=excluded.fingerprint, trusted=excluded.trusted,last_seen=excluded.last_seen""",
            (node_id, name, hostname, ip, port, scheme, key, peer_fingerprint, trusted, time.time()),
        )


def _listen():
    listener = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        listener.bind(("", DISCOVERY_PORT))
    except OSError:
        listener.close()
        return
    listener.settimeout(1)
    while not _stop.is_set():
        try:
            raw, address = listener.recvfrom(4096)
            _record(json.loads(raw.decode("utf-8")), address)
        except socket.timeout:
            continue
        except (ValueError, UnicodeDecodeError, OSError):
            continue
    listener.close()


def _broadcast():
    sender = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sender.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    while not _stop.is_set():
        try:
            sender.sendto(json.dumps(_payload()).encode("utf-8"), ("255.255.255.255", DISCOVERY_PORT))
        except OSError:
            pass
        _stop.wait(5)
    sender.close()


def start_discovery():
    global _started
    if not DISCOVERY_ENABLED or _started:
        return
    _started = True
    threading.Thread(target=_listen, daemon=True, name="netpulse-discovery-listener").start()
    threading.Thread(target=_broadcast, daemon=True, name="netpulse-discovery-broadcaster").start()


def peer_url(peer):
    return urlunparse((peer["scheme"], f'{peer["ip_address"]}:{peer["port"]}', "", "", "", ""))
