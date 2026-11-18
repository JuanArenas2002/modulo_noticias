"""Tablas del IAM (identidad, sesiones, RBAC con alcance y auditoría).

Decisiones:
- La identidad de acceso NO duplica datos académicos: investigadores/estudiantes viven en Metri-K.
- Ningún token se guarda en claro: solo su SHA-256 (token_hash).
- Usuarios federados se identifican por (proveedor, tid, oid), nunca por correo.
- Catálogos (estados, tipos de cuenta, proveedores) son tablas, igual que en noticias.
- Asignación con scope_type_id/scope_id NULL = alcance institucional (global).
"""
from sqlalchemy import (JSON, BigInteger, Boolean, CheckConstraint, Column, DateTime, ForeignKey, Index, Integer,
                        String, Table, Text, func, text)

from app.shared.database import metadata

Ts = DateTime(timezone=True)
BigId = BigInteger().with_variant(Integer, "sqlite")  # SQLite solo autoincrementa INTEGER


def _pk():
    return Column("id", BigId, primary_key=True, autoincrement=True)


def _user_fk(name: str, nullable: bool = True, **kw):
    return Column(name, BigId, ForeignKey("users.id"), nullable=nullable, **kw)


def _where(sql: str) -> dict:
    """Índice parcial en ambos motores."""
    return {"postgresql_where": text(sql), "sqlite_where": text(sql)}


# ---------- catálogos ----------
user_statuses = Table(
    "user_statuses", metadata,
    Column("id", Integer, primary_key=True),
    Column("code", String(30), nullable=False, unique=True),
    Column("name", String(100), nullable=False),
    Column("can_login", Boolean, nullable=False, default=False),
)

account_types = Table(
    "account_types", metadata,
    Column("id", Integer, primary_key=True),
    Column("code", String(30), nullable=False, unique=True),
    Column("name", String(100), nullable=False),
)

identity_providers = Table(
    "identity_providers", metadata,
    Column("id", Integer, primary_key=True),
    Column("code", String(30), nullable=False, unique=True),
    Column("name", String(100), nullable=False),
    Column("is_enabled", Boolean, nullable=False, default=True),
)

# ---------- identidad ----------
users = Table(
    "users", metadata, _pk(),
    Column("first_name", String(100), nullable=False),
    Column("last_name", String(100), nullable=False),
    Column("email", String(254), nullable=False),  # siempre en minúsculas (normalizado en la app)
    Column("status_id", ForeignKey("user_statuses.id"), nullable=False),
    Column("account_type_id", ForeignKey("account_types.id"), nullable=False),
    Column("email_verified_at", Ts),
    Column("last_login_at", Ts),
    Column("created_at", Ts, nullable=False, server_default=func.now()),
    Column("updated_at", Ts, nullable=False, server_default=func.now()),
    Column("deleted_at", Ts),  # eliminación lógica
    CheckConstraint("email = lower(email)", name="ck_users_email_lower"),
    Index("uq_users_email_alive", "email", unique=True, **_where("deleted_at IS NULL")),
)

user_identities = Table(  # identidades federadas (Microsoft Entra ID, futuros IdP)
    "user_identities", metadata, _pk(),
    _user_fk("user_id", nullable=False, index=True),
    Column("provider_id", ForeignKey("identity_providers.id"), nullable=False),
    Column("tenant_id", String(64), nullable=False),  # tid (multi-tenant listo)
    Column("subject", String(128), nullable=False),   # oid: identificador estable
    Column("email_at_link", String(254)),             # solo informativo; no se usa para identificar
    _user_fk("linked_by"),                            # NULL = vinculada por el propio usuario
    Column("linked_at", Ts, nullable=False, server_default=func.now()),
    Column("last_used_at", Ts),
    Index("uq_user_identities_subject", "provider_id", "tenant_id", "subject", unique=True),
)

password_credentials = Table(  # 1:1 con users; solo cuentas con contraseña
    "password_credentials", metadata,
    Column("user_id", BigId, ForeignKey("users.id"), primary_key=True),
    Column("password_hash", String(255), nullable=False),  # Argon2id (incluye sal y parámetros)
    Column("password_changed_at", Ts, nullable=False, server_default=func.now()),
    Column("failed_attempts", Integer, nullable=False, default=0),
    Column("locked_until", Ts),  # bloqueo temporal por fuerza bruta
    Column("must_change", Boolean, nullable=False, default=False),
    CheckConstraint("failed_attempts >= 0", name="ck_password_failed_attempts"),
)

auth_sessions = Table(  # sesión de servidor; la cookie lleva el token, aquí solo su hash
    "auth_sessions", metadata, _pk(),
    _user_fk("user_id", nullable=False, index=True),
    Column("token_hash", String(64), nullable=False, unique=True),
    Column("previous_token_hash", String(64), unique=True),  # tras rotar: detectar reutilización
    Column("csrf_token_hash", String(64), nullable=False),
    Column("provider_id", ForeignKey("identity_providers.id"), nullable=False),  # método usado
    Column("identity_id", BigId, ForeignKey("user_identities.id")),
    Column("ip", String(45)),
    Column("user_agent", String(500)),
    Column("created_at", Ts, nullable=False, server_default=func.now()),
    Column("last_seen_at", Ts, nullable=False, server_default=func.now()),
    Column("idle_expires_at", Ts, nullable=False),
    Column("expires_at", Ts, nullable=False),  # expiración absoluta
    Column("revoked_at", Ts),
    Column("revoked_reason", String(50)),
    CheckConstraint("idle_expires_at <= expires_at", name="ck_auth_sessions_expiry"),
)

user_tokens = Table(  # verificación de correo, recuperación, invitación y vinculación: un solo uso
    "user_tokens", metadata, _pk(),
    _user_fk("user_id", nullable=False, index=True),
    Column("purpose", String(30), nullable=False),
    Column("token_hash", String(64), nullable=False, unique=True),
    Column("context", JSON),  # datos no sensibles (p.ej. identidad pendiente de vincular)
    _user_fk("created_by"),
    Column("created_at", Ts, nullable=False, server_default=func.now()),
    Column("expires_at", Ts, nullable=False),
    Column("used_at", Ts),
    # purpose es técnico y lo consume el código: CHECK en vez de catálogo.
    CheckConstraint("purpose IN ('verify_email', 'reset_password', 'invitation', 'link_identity')",
                    name="ck_user_tokens_purpose"),
)

login_attempts = Table(  # rate limiting y bloqueo; el correo se guarda como hash
    "login_attempts", metadata, _pk(),
    Column("email_hash", String(64), nullable=False),
    Column("ip", String(45)),
    Column("success", Boolean, nullable=False),
    Column("at", Ts, nullable=False, server_default=func.now()),
    Index("ix_login_attempts_email_at", "email_hash", "at"),
    Index("ix_login_attempts_ip_at", "ip", "at"),
)

# ---------- RBAC ----------
roles = Table(
    "roles", metadata,
    Column("id", Integer, primary_key=True),
    Column("code", String(50), nullable=False, unique=True),
    Column("name", String(100), nullable=False),
    Column("description", Text),
    Column("is_active", Boolean, nullable=False, default=True),
    Column("created_at", Ts, nullable=False, server_default=func.now()),
    Column("updated_at", Ts, nullable=False, server_default=func.now()),
)

permissions = Table(
    "permissions", metadata,
    Column("id", Integer, primary_key=True),
    Column("code", String(100), nullable=False, unique=True),  # p.ej. news.publish
    Column("name", String(150), nullable=False),
    Column("description", Text),
    Column("module", String(50), nullable=False),
    Column("resource", String(50), nullable=False),
    Column("action", String(50), nullable=False),
    Column("is_active", Boolean, nullable=False, default=True),
    Column("created_at", Ts, nullable=False, server_default=func.now()),
    CheckConstraint("code = lower(code)", name="ck_permissions_code_lower"),
)

role_permissions = Table(
    "role_permissions", metadata,
    Column("role_id", ForeignKey("roles.id", ondelete="CASCADE"), primary_key=True),
    Column("permission_id", ForeignKey("permissions.id"), primary_key=True),
    Column("granted_at", Ts, nullable=False, server_default=func.now()),
)

user_role_assignments = Table(
    "user_role_assignments", metadata, _pk(),
    _user_fk("user_id", nullable=False, index=True),
    Column("role_id", ForeignKey("roles.id"), nullable=False),
    Column("scope_type_id", ForeignKey("org_unit_types.id")),  # NULL = institucional
    Column("scope_id", BigInteger),                            # id de la unidad (validado contra source_table)
    _user_fk("assigned_by"),
    Column("assigned_at", Ts, nullable=False, server_default=func.now()),
    Column("revoked_at", Ts),
    _user_fk("revoked_by"),
    Column("revoke_reason", Text),
    CheckConstraint("(scope_type_id IS NULL) = (scope_id IS NULL)", name="ck_assignment_scope_pair"),
    CheckConstraint("(revoked_at IS NULL) OR (revoked_by IS NOT NULL)", name="ck_assignment_revoked_by"),
    # Una asignación activa por (usuario, rol, alcance). COALESCE porque NULL != NULL en UNIQUE.
    Index("uq_assignment_active", "user_id", "role_id",
          func.coalesce(text("scope_type_id"), 0), func.coalesce(text("scope_id"), 0),
          unique=True, **_where("revoked_at IS NULL")),
)

# ---------- auditoría ----------
audit_logs = Table(  # solo-append: sin UPDATE/DELETE (trigger en PostgreSQL, ver migración)
    "audit_logs", metadata, _pk(),
    _user_fk("actor_user_id", index=True),  # NULL = anónimo o sistema
    Column("event_type", String(60), nullable=False, index=True),  # p.ej. auth.login.failed
    Column("resource_type", String(60)),
    Column("resource_id", String(64)),
    Column("result", String(10), nullable=False),
    Column("ip", String(45)),
    Column("user_agent", String(500)),
    Column("context", JSON),  # nunca contraseñas, tokens ni cookies
    Column("at", Ts, nullable=False, server_default=func.now(), index=True),
    CheckConstraint("result IN ('success', 'failure', 'denied')", name="ck_audit_result"),
    Index("ix_audit_resource", "resource_type", "resource_id"),
)
