"""Password hashing and access tokens (standard library only).

* Passwords: PBKDF2-HMAC-SHA256 with a random per-user salt.
* Tokens: compact HMAC-SHA256 signed tokens carrying user id, expiry and the
  user's token version. Raising the version (logout, password change)
  revokes every token issued before.

This is adequate for a prototype. A later phase can swap in JWT or
server-side sessions without changing the API routes.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import secrets
import time

PBKDF2_ITERATIONS = 260_000
_ALGORITHM = "pbkdf2_sha256"


def hash_password(password: str) -> str:
    salt = secrets.token_hex(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode(), salt.encode(), PBKDF2_ITERATIONS)
    return f"{_ALGORITHM}${PBKDF2_ITERATIONS}${salt}${digest.hex()}"


def verify_password(password: str, stored_hash: str) -> bool:
    try:
        algorithm, iterations, salt, expected = stored_hash.split("$")
        rounds = int(iterations)
    except (ValueError, AttributeError):
        return False  # a damaged or foreign hash never authenticates
    if algorithm != _ALGORITHM or rounds < 1:
        return False
    digest = hashlib.pbkdf2_hmac("sha256", password.encode(), salt.encode(), rounds)
    return hmac.compare_digest(digest.hex(), expected)


def _b64encode(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


def _b64decode(text: str) -> bytes:
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def create_access_token(user_id: int, secret_key: str, expire_minutes: int, version: int = 0) -> str:
    payload = {"sub": user_id, "ver": version, "exp": int(time.time()) + expire_minutes * 60}
    body = _b64encode(json.dumps(payload, separators=(",", ":")).encode())
    signature = hmac.new(secret_key.encode(), body.encode(), hashlib.sha256).digest()
    return f"{body}.{_b64encode(signature)}"


def decode_access_token(token: str, secret_key: str) -> tuple[int, int] | None:
    """Return (user id, token version) if the token is authentic and unexpired, else None."""
    try:
        body, signature = token.split(".")
        expected = hmac.new(secret_key.encode(), body.encode(), hashlib.sha256).digest()
        if not hmac.compare_digest(_b64decode(signature), expected):
            return None
        payload = json.loads(_b64decode(body))
        if int(payload["exp"]) < int(time.time()):
            return None
        return int(payload["sub"]), int(payload["ver"])
    except (ValueError, KeyError, TypeError, json.JSONDecodeError):
        return None
