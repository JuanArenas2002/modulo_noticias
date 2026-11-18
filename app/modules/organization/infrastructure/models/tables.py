"""Copia local de dependencias de Metri-K. PK = id de Metri-K (sin autoincremento)."""
from sqlalchemy import Boolean, CheckConstraint, Column, Date, DateTime, ForeignKey, Integer, String, Table, false

from app.shared.database import metadata

Ts = DateTime(timezone=True)


def _id():
    return Column("id", Integer, primary_key=True, autoincrement=False)


org_unit_types = Table(
    "org_unit_types", metadata,
    Column("id", Integer, primary_key=True),
    Column("code", String(30), nullable=False, unique=True),
    Column("name", String(100), nullable=False),
    Column("source_table", String(100)),
    Column("parent_type_id", ForeignKey("org_unit_types.id")),
    Column("parent_column", String(100)),
    Column("is_institutional", Boolean, nullable=False, default=False, server_default=false()),  # = toda la institución
    CheckConstraint("(parent_type_id IS NULL) = (parent_column IS NULL)", name="ck_org_unit_types_parent"),
)

faculties = Table(
    "faculties", metadata, _id(),
    Column("name", String(200), nullable=False),
    Column("is_active", Boolean, nullable=False, default=True),
    Column("synced_at", Ts, nullable=False),
)

research_centers = Table(
    "research_centers", metadata, _id(),
    Column("code", String(30)),
    Column("name", String(250), nullable=False),
    Column("acronym", String(50)),
    Column("is_active", Boolean, nullable=False, default=True),
    Column("date_created", Date),
    Column("date_closed", Date),
    Column("synced_at", Ts, nullable=False),
)

academic_programs = Table(
    "academic_programs", metadata, _id(),
    Column("name", String(250), nullable=False),
    Column("faculty_id", ForeignKey("faculties.id"), nullable=False, index=True),
    Column("code_snies", String(20)),
    Column("level_academic", String(50)),
    Column("level_education", String(100)),
    Column("modality", String(50)),
    Column("is_active", Boolean, nullable=False, default=True),
    Column("synced_at", Ts, nullable=False),
)
