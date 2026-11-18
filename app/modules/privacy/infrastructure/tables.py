"""Tablas de privacidad: políticas versionadas, categorías de cookies y decisiones de consentimiento.

privacy_consents es la PRUEBA de la autorización (Decreto 1377/2013, art. 8): cada decisión es una fila nueva
(la anterior queda `superseded`), nunca se edita. No guarda IP, navegador, nombre ni correo: solo el id aleatorio
del navegador (`subject_id`, el valor de la cookie), la versión de la política, las categorías y la fecha.
"""
from sqlalchemy import (JSON, BigInteger, Boolean, CheckConstraint, Column, DateTime, ForeignKey, Index, Integer,
                        String, Table, Text, UniqueConstraint)

from app.modules.privacy.domain.rules import KINDS, METHODS
from app.shared.database import metadata

Ts = DateTime(timezone=True)
BigId = BigInteger().with_variant(Integer, "sqlite")


def _in(column: str, values: tuple[str, ...]) -> str:
    return f"{column} IN ({', '.join(repr(v) for v in values)})"


privacy_policies = Table(
    "privacy_policies", metadata,
    Column("id", Integer, primary_key=True),
    Column("kind", String(20), nullable=False),
    Column("version", Integer, nullable=False),
    Column("title", String(200), nullable=False),
    Column("summary", Text, nullable=False),
    Column("content", Text, nullable=False),               # HTML saneado
    Column("effective_at", Ts, nullable=False),            # vigente desde; antes de esa fecha aún se puede corregir
    Column("requires_reconsent", Boolean, nullable=False),  # cambio sustancial: vuelve a pedir la decisión
    Column("created_at", Ts, nullable=False),
    Column("created_by", BigInteger, ForeignKey("users.id", name="fk_privacy_policy_creator")),
    Column("updated_at", Ts, nullable=False),
    UniqueConstraint("kind", "version", name="uq_privacy_policies_kind_version"),
    CheckConstraint(_in("kind", KINDS), name="ck_privacy_policies_kind"),
)

privacy_cookie_categories = Table(
    "privacy_cookie_categories", metadata,
    Column("id", Integer, primary_key=True),
    Column("code", String(20), nullable=False, unique=True),
    Column("name", String(100), nullable=False),
    Column("description", Text, nullable=False),
    Column("purpose", Text, nullable=False),
    Column("technologies", JSON, nullable=False),          # [{name, type, duration, provider, purpose}]
    Column("retention", Text, nullable=False),
    Column("is_required", Boolean, nullable=False),        # necesarias: no se pueden apagar
    Column("is_available", Boolean, nullable=False),       # False = prevista pero sin uso (publicidad)
    Column("sort", Integer, nullable=False),
    Column("updated_at", Ts, nullable=False),
)

privacy_consents = Table(
    "privacy_consents", metadata,
    Column("id", BigId, primary_key=True),
    Column("subject_id", String(36), nullable=False),      # id aleatorio del navegador (cookie cris_consent)
    Column("user_id", BigInteger, ForeignKey("users.id", name="fk_privacy_consent_user")),  # si había sesión
    Column("policy_version", Integer, nullable=False),     # versión de la política de cookies decidida
    Column("categories", JSON, nullable=False),            # {"functional": bool, "analytics": bool, ...}
    Column("method", String(20), nullable=False),
    Column("status", String(12), nullable=False),          # active | superseded
    Column("decided_at", Ts, nullable=False),
    Column("expires_at", Ts, nullable=False),
    CheckConstraint(_in("method", METHODS), name="ck_privacy_consents_method"),
    CheckConstraint(_in("status", ("active", "superseded")), name="ck_privacy_consents_status"),
    Index("ix_privacy_consents_subject_status", "subject_id", "status"),
    Index("ix_privacy_consents_decided_at", "decided_at"),
)
