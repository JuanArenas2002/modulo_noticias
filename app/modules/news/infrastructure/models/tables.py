"""Tablas PostgreSQL del módulo. Los catálogos reemplazan a los enums: cada valor es una fila."""
from sqlalchemy import (BigInteger, Boolean, CheckConstraint, Column, DateTime, ForeignKey, Integer, String, Table,
                        Text, UniqueConstraint)

from app.shared.database import metadata

Ts = DateTime(timezone=True)


def _id():
    return Column("id", Integer, primary_key=True)


# ---------- catálogos ----------
news_statuses = Table(
    "news_statuses", metadata, _id(),
    Column("code", String(30), nullable=False, unique=True),
    Column("name", String(100), nullable=False),
    Column("is_initial", Boolean, nullable=False, default=False),
    Column("is_public", Boolean, nullable=False, default=False),
    Column("is_editable", Boolean, nullable=False, default=False),
    Column("is_archived", Boolean, nullable=False, default=False),
)

news_status_transitions = Table(
    "news_status_transitions", metadata, _id(),
    Column("action", String(30), nullable=False, index=True),
    Column("from_status_id", ForeignKey("news_statuses.id"), nullable=False),
    Column("to_status_id", ForeignKey("news_statuses.id"), nullable=False),
    # Permiso IAM que exige la acción (se evalúa sobre TODAS las dependencias de la noticia).
    Column("required_permission", String(100), ForeignKey("permissions.code", name="fk_transition_permission"),
           nullable=False),
    Column("requires_reason", Boolean, nullable=False, default=False),
    UniqueConstraint("action", "from_status_id"),
)

news_relevance_levels = Table(
    "news_relevance_levels", metadata, _id(),
    Column("code", String(30), nullable=False, unique=True),
    Column("name", String(100), nullable=False),
    Column("weight", Integer, nullable=False, default=0),
)

news_person_types = Table(
    "news_person_types", metadata, _id(),
    Column("code", String(30), nullable=False, unique=True),
    Column("name", String(100), nullable=False),
    Column("source_table", String(100)),
)

news_relationship_types = Table(
    "news_relationship_types", metadata, _id(),
    Column("code", String(40), nullable=False, unique=True),
    Column("name", String(100), nullable=False),
)

news_categories = Table(
    "news_categories", metadata, _id(),
    Column("name", String(100), nullable=False, unique=True),
)

# ---------- noticia ----------
news = Table(
    "news", metadata, _id(),
    Column("title", String(250), nullable=False),
    Column("slug", String(270), nullable=False, unique=True),
    Column("summary", Text, nullable=False),
    Column("content", Text, nullable=False),
    Column("image_url", String(500)),
    Column("image_caption", Text),
    Column("category_id", ForeignKey("news_categories.id"), nullable=False),
    Column("author_id", BigInteger, ForeignKey("users.id", name="fk_news_author"), nullable=False),
    Column("relevance_level_id", ForeignKey("news_relevance_levels.id"), nullable=False),
    Column("priority", Integer, nullable=False, default=0),
    Column("is_featured", Boolean, nullable=False, default=False),
    Column("is_pinned", Boolean, nullable=False, default=False),
    Column("start_at", Ts),
    Column("end_at", Ts),
    Column("published_at", Ts),
    Column("created_at", Ts, nullable=False),
    Column("updated_at", Ts, nullable=False),
    Column("status_id", ForeignKey("news_statuses.id"), nullable=False, index=True),
    CheckConstraint("end_at IS NULL OR start_at IS NULL OR end_at >= start_at", name="ck_news_vigencia"),
)

# scope_id es polimórfico (sin FK; se valida contra source_table). Las personas se identifican por ORCID.
news_scopes = Table(
    "news_scopes", metadata, _id(),
    Column("news_id", ForeignKey("news.id"), nullable=False, index=True),
    Column("scope_type_id", ForeignKey("org_unit_types.id"), nullable=False),
    Column("scope_id", BigInteger, nullable=False),
    Column("created_at", Ts, nullable=False),
    UniqueConstraint("news_id", "scope_type_id", "scope_id"),
)

news_people = Table(
    "news_people", metadata, _id(),
    Column("news_id", ForeignKey("news.id"), nullable=False, index=True),
    Column("person_type_id", ForeignKey("news_person_types.id"), nullable=False),
    Column("orcid", String(19), nullable=False, index=True),  # ORCID iD canónico (0000-0000-0000-000X)
    Column("relationship_type_id", ForeignKey("news_relationship_types.id"), nullable=False),
    Column("created_at", Ts, nullable=False),
    UniqueConstraint("news_id", "person_type_id", "orcid", "relationship_type_id"),
)

news_tags = Table(
    "news_tags", metadata,
    Column("news_id", ForeignKey("news.id"), primary_key=True),
    Column("tag", String(60), primary_key=True, index=True),
)

news_history = Table(
    "news_history", metadata, _id(),
    Column("news_id", ForeignKey("news.id"), nullable=False, index=True),
    Column("actor_id", BigInteger, ForeignKey("users.id", name="fk_news_history_actor"), nullable=False),
    Column("action", String(30), nullable=False),
    Column("from_status_id", ForeignKey("news_statuses.id")),
    Column("to_status_id", ForeignKey("news_statuses.id"), nullable=False),
    Column("reason", Text),
    Column("at", Ts, nullable=False),
)
