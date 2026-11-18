"""Reglas de sesión de servidor: emisión, validez (inactividad + absoluta) y rotación."""
from dataclasses import dataclass
from datetime import datetime, timedelta

from app.modules.iam.domain.entities.identity import AuthSession, IdentityProvider
from app.shared.clock import as_utc
from app.shared.security import hash_token, new_token

TOUCH_EVERY = timedelta(minutes=1)  # no escribir last_seen en cada request


@dataclass(frozen=True)
class SessionWindow:
    idle: timedelta
    absolute: timedelta


@dataclass(frozen=True)
class IssuedSession:
    session: AuthSession
    token: str       # va en la cookie HttpOnly; nunca se persiste
    csrf_token: str  # se devuelve al cliente para el header X-CSRF-Token


def issue(user_id: int, provider: IdentityProvider, window: SessionWindow, at: datetime,
          ip: str | None, user_agent: str | None, identity_id: int | None = None) -> IssuedSession:
    token, csrf = new_token(), new_token()
    session = AuthSession(user_id=user_id, provider=provider, identity_id=identity_id,
                          token_hash=hash_token(token), csrf_token_hash=hash_token(csrf),
                          ip=ip, user_agent=(user_agent or "")[:500] or None, created_at=at, last_seen_at=at,
                          idle_expires_at=min(at + window.idle, at + window.absolute),
                          expires_at=at + window.absolute)
    return IssuedSession(session, token, csrf)


def is_valid(session: AuthSession, at: datetime) -> bool:
    return (session.revoked_at is None and as_utc(session.idle_expires_at) > at
            and as_utc(session.expires_at) > at)


def touch(session: AuthSession, window: SessionWindow, at: datetime) -> bool:
    """Extiende la inactividad (nunca más allá de la expiración absoluta). True si hubo cambio."""
    if at - as_utc(session.last_seen_at) < TOUCH_EVERY:
        return False
    session.last_seen_at = at
    session.idle_expires_at = min(at + window.idle, as_utc(session.expires_at))
    return True


def rotate(session: AuthSession, window: SessionWindow, at: datetime) -> tuple[str, str]:
    """Nuevo token y CSRF. El hash anterior se conserva para detectar reutilización."""
    token, csrf = new_token(), new_token()
    session.previous_token_hash = session.token_hash
    session.token_hash, session.csrf_token_hash = hash_token(token), hash_token(csrf)
    session.last_seen_at = at
    session.idle_expires_at = min(at + window.idle, as_utc(session.expires_at))
    return token, csrf


def revoke(session: AuthSession, at: datetime, reason: str) -> None:
    if session.revoked_at is None:
        session.revoked_at, session.revoked_reason = at, reason
