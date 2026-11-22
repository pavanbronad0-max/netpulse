import re
import time
from collections import defaultdict, deque
from functools import wraps

from flask import jsonify, session
from werkzeug.security import check_password_hash, generate_password_hash

from database import transaction

_attempts = defaultdict(deque)
USERNAME_RE = re.compile(r"^[A-Za-z0-9_.-]{3,32}$")


def register_user(username, password):
    if not isinstance(username, str) or not USERNAME_RE.fullmatch(username):
        raise ValueError("Username must be 3–32 letters, numbers, dots, dashes or underscores.")
    if not isinstance(password, str) or len(password) < 10 or len(password) > 256:
        raise ValueError("Password must be between 10 and 256 characters.")
    try:
        with transaction() as db:
            cursor = db.execute(
                "INSERT INTO users (username,password_hash) VALUES (?,?)",
                (username, generate_password_hash(password, method="scrypt")),
            )
            user_id = cursor.lastrowid
            db.execute("INSERT INTO activities(user_id,message) VALUES (?,?)", (user_id, "Account created"))
    except Exception as exc:
        if "UNIQUE constraint failed" in str(exc):
            raise ValueError("That username is already registered.") from exc
        raise
    return {"id": user_id, "username": username}


def authenticate(username, password, remote_addr):
    now = time.monotonic()
    attempts = _attempts[remote_addr]
    while attempts and now - attempts[0] > 300:
        attempts.popleft()
    if len(attempts) >= 10:
        return None, "Too many sign-in attempts. Try again in five minutes."
    with transaction() as db:
        user = db.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()
    if user is None or not check_password_hash(user["password_hash"], password):
        attempts.append(now)
        return None, "Invalid username or password."
    attempts.clear()
    return {"id": user["id"], "username": user["username"]}, None


def login_required(function):
    @wraps(function)
    def wrapped(*args, **kwargs):
        if "user_id" not in session:
            return jsonify({"error": "Authentication required"}), 401
        return function(*args, **kwargs)
    return wrapped
