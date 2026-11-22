import base64
import os
from pathlib import Path

from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from config import DATA_DIR, DEVICE_KEY_FILE, FERNET_KEY_FILE


def _write_private(path: Path, content: bytes):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(content)
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass


def _fernet():
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    if not FERNET_KEY_FILE.exists():
        _write_private(FERNET_KEY_FILE, Fernet.generate_key())
    return Fernet(FERNET_KEY_FILE.read_bytes())


def encrypt_at_rest(data: bytes) -> bytes:
    return _fernet().encrypt(data)


def decrypt_at_rest(data: bytes) -> bytes:
    try:
        return _fernet().decrypt(data)
    except InvalidToken as exc:
        raise ValueError("Stored file failed authentication") from exc


def _device_private_key():
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    if not DEVICE_KEY_FILE.exists():
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        _write_private(
            DEVICE_KEY_FILE,
            key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption(),
            ),
        )
    return serialization.load_pem_private_key(DEVICE_KEY_FILE.read_bytes(), password=None)


def public_key_b64() -> str:
    public = _device_private_key().public_key().public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return base64.b64encode(public).decode("ascii")


def fingerprint(public_key: str) -> str:
    digest = hashes.Hash(hashes.SHA256())
    digest.update(base64.b64decode(public_key, validate=True))
    return digest.finalize().hex()


def encrypt_for_peer(data: bytes, public_key: str) -> tuple[bytes, str, str]:
    from cryptography.hazmat.primitives.serialization import load_der_public_key

    peer_key = load_der_public_key(base64.b64decode(public_key, validate=True))
    content_key = AESGCM.generate_key(bit_length=256)
    nonce = os.urandom(12)
    encrypted = AESGCM(content_key).encrypt(nonce, data, None)
    wrapped = peer_key.encrypt(
        content_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )
    return encrypted, base64.b64encode(wrapped).decode("ascii"), base64.b64encode(nonce).decode("ascii")


def decrypt_from_peer(encrypted: bytes, wrapped_key: str, nonce: str) -> bytes:
    content_key = _device_private_key().decrypt(
        base64.b64decode(wrapped_key, validate=True),
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )
    return AESGCM(content_key).decrypt(
        base64.b64decode(nonce, validate=True), encrypted, None
    )
