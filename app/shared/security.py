"""Primitivas criptográficas comunes. Los tokens se entregan en claro una sola vez y se guardan como hash."""
import hashlib
import hmac
import secrets
from datetime import timedelta

import jwt

from app.shared.clock import now


def new_token() -> str:
    """256 bits de entropía, apto para URL."""
    return secrets.token_urlsafe(32)


def hash_token(token: str) -> str:
    """SHA-256 basta: el token es aleatorio de alta entropía (no es una contraseña)."""
    return hashlib.sha256(token.encode()).hexdigest()


def same(a: str, b: str) -> bool:
    return hmac.compare_digest(a.encode(), b.encode())


def sign(payload: dict, key: str, ttl: timedelta, purpose: str) -> str:
    """Valor firmado (HS256) con expiración y propósito; para cookies efímeras como el estado OAuth."""
    return jwt.encode({**payload, "exp": now() + ttl, "pur": purpose}, key, algorithm="HS256")


def unsign(value: str | None, key: str, purpose: str) -> dict | None:
    if not value:
        return None
    try:
        data = jwt.decode(value, key, algorithms=["HS256"])
    except jwt.PyJWTError:
        return None
    return data if data.get("pur") == purpose else None
