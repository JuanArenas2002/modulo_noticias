"""Identidad de acceso: quién es el usuario y cómo se autentica. Sin datos académicos."""
from dataclasses import dataclass, field
from datetime import datetime

from app.shared.clock import now


@dataclass(kw_only=True, eq=False)
class UserStatus:
    id: int | None = None
    code: str
    name: str
    can_login: bool = False


@dataclass(kw_only=True, eq=False)
class AccountType:
    id: int | None = None
    code: str
    name: str


@dataclass(kw_only=True, eq=False)
class IdentityProvider:
    id: int | None = None
    code: str
    name: str
    is_enabled: bool = True


@dataclass(kw_only=True, eq=False)
class UserIdentity:
    """Identidad federada. Se identifica por (proveedor, tenant_id=tid, subject=oid), nunca por correo."""
    id: int | None = None
    user_id: int | None = None
    provider: IdentityProvider
    tenant_id: str
    subject: str
    email_at_link: str | None = None
    linked_by: int | None = None
    linked_at: datetime = field(default_factory=now)
    last_used_at: datetime | None = None


@dataclass(kw_only=True, eq=False)
class PasswordCredential:
    user_id: int | None = None
    password_hash: str
    password_changed_at: datetime = field(default_factory=now)
    failed_attempts: int = 0
    locked_until: datetime | None = None
    must_change: bool = False


@dataclass(kw_only=True, eq=False)
class User:
    id: int | None = None
    first_name: str
    last_name: str
    email: str
    status: UserStatus
    account_type: AccountType
    email_verified_at: datetime | None = None
    last_login_at: datetime | None = None
    created_at: datetime = field(default_factory=now)
    updated_at: datetime = field(default_factory=now)
    deleted_at: datetime | None = None
    identities: list[UserIdentity] = field(default_factory=list)
    password: PasswordCredential | None = None


@dataclass(kw_only=True, eq=False)
class AuthSession:
    id: int | None = None
    user_id: int
    token_hash: str
    csrf_token_hash: str
    provider: IdentityProvider
    identity_id: int | None = None
    previous_token_hash: str | None = None
    ip: str | None = None
    user_agent: str | None = None
    created_at: datetime = field(default_factory=now)
    last_seen_at: datetime = field(default_factory=now)
    idle_expires_at: datetime
    expires_at: datetime
    revoked_at: datetime | None = None
    revoked_reason: str | None = None


@dataclass(kw_only=True, eq=False)
class UserToken:
    """Token de un solo uso (verify_email, reset_password, invitation, link_identity)."""
    id: int | None = None
    user_id: int
    purpose: str
    token_hash: str
    context: dict | None = None
    created_by: int | None = None
    created_at: datetime = field(default_factory=now)
    expires_at: datetime
    used_at: datetime | None = None


@dataclass(kw_only=True, eq=False)
class LoginAttempt:
    id: int | None = None
    email_hash: str
    ip: str | None = None
    success: bool
    at: datetime = field(default_factory=now)
