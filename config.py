import os
from pathlib import Path


BASE_DIR = Path(__file__).resolve().parent
DATA_DIR = Path(os.environ.get("NETPULSE_DATA_DIR", BASE_DIR / "data")).resolve()
UPLOAD_DIR = DATA_DIR / "transfers"
DATABASE_PATH = DATA_DIR / "netpulse.db"
HOST = os.environ.get("NETPULSE_HOST", "0.0.0.0")
PORT = int(os.environ.get("NETPULSE_PORT", "5000"))
PUBLIC_PORT = int(os.environ.get("NETPULSE_PUBLIC_PORT", str(PORT)))
MAX_FILE_SIZE = int(os.environ.get("NETPULSE_MAX_FILE_SIZE", str(25 * 1024 * 1024)))
MONITOR_INTERVAL = max(2, int(os.environ.get("NETPULSE_MONITOR_INTERVAL", "3")))
DISCOVERY_ENABLED = os.environ.get("NETPULSE_DISCOVERY", "1").lower() in {"1", "true", "yes"}
DISCOVERY_PORT = int(os.environ.get("NETPULSE_DISCOVERY_PORT", "37020"))
TLS_CERT_FILE = os.environ.get("NETPULSE_TLS_CERT", "")
TLS_KEY_FILE = os.environ.get("NETPULSE_TLS_KEY", "")
PUBLIC_SCHEME = os.environ.get("NETPULSE_PUBLIC_SCHEME", "https" if TLS_CERT_FILE and TLS_KEY_FILE else "http")
COOKIE_SECURE = os.environ.get("NETPULSE_COOKIE_SECURE", "0").lower() in {"1", "true", "yes"}
SECRET_FILE = DATA_DIR / ".secret"
FERNET_KEY_FILE = DATA_DIR / ".fernet.key"
DEVICE_KEY_FILE = DATA_DIR / "device-private.pem"
NODE_ID_FILE = DATA_DIR / ".node-id"
