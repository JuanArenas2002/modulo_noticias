"""catálogos de noticias y tipos de unidad organizacional (datos iniciales).

Los datos viven aquí (no importados del código) para que la migración sea reproducible aunque
el código cambie. Después se administran en BD.

Revision ID: 0002
Revises: 0001
"""
import sqlalchemy as sa
from alembic import op

revision = "0002"
down_revision = "0001"
branch_labels = None
depends_on = None

STATUSES = [  # code, name, is_initial, is_public, is_editable, is_archived
    ("draft", "Borrador", True, False, True, False),
    ("in_review", "En revisión", False, False, False, False),
    ("approved", "Aprobada", False, False, False, False),
    ("rejected", "Rechazada", False, False, True, False),
    ("scheduled", "Programada", False, True, False, False),
    ("published", "Publicada", False, True, False, False),
    ("archived", "Archivada", False, False, False, True),
]

TRANSITIONS = [  # action, from, to, required_role, requires_reason
    ("submit", "draft", "in_review", "editor", False),
    ("submit", "rejected", "in_review", "editor", False),
    ("approve", "in_review", "approved", "admin", False),
    ("reject", "in_review", "rejected", "admin", True),
    ("publish", "approved", "published", "admin", False),
    ("schedule", "approved", "scheduled", "admin", False),
    *[("archive", s[0], "archived", "admin", False) for s in STATUSES if s[0] != "archived"],
]

RELEVANCE = [("high", "Alta", 3), ("medium", "Media", 2), ("low", "Baja", 1)]

# code, name, source_table, parent_code, parent_column
ORG_UNIT_TYPES = [
    ("institution", "Institucional", None, None, None),
    ("research_center", "Centro de investigación", "research_centers", None, None),
    ("faculty", "Facultad", "faculties", None, None),
    ("academic_program", "Programa académico", "academic_programs", "faculty", "faculty_id"),
    ("research_group", "Grupo de investigación", None, None, None),
    ("research_seedbed", "Semillero", None, None, None),
]

PERSON_TYPES = [
    ("researcher", "Investigador"), ("student", "Estudiante"), ("teacher", "Docente"),
    ("administrative", "Personal administrativo"), ("external", "Invitado externo"),
]

RELATIONSHIP_TYPES = [
    ("protagonist", "Protagonista"), ("researcher", "Investigador"), ("student", "Estudiante"),
    ("interviewee", "Entrevistado"), ("collaborator", "Colaborador"), ("featured_author", "Autor destacado"),
    ("mentioned", "Mencionado"),
]


def _t(name, *cols):
    return sa.table(name, *(sa.column(c) for c in cols))


def _ids(table: str) -> dict[str, int]:
    return dict((code, id_) for id_, code in op.get_bind().execute(sa.text(f"SELECT id, code FROM {table}")))


def upgrade() -> None:
    op.bulk_insert(_t("news_statuses", "code", "name", "is_initial", "is_public", "is_editable", "is_archived"),
                   [dict(zip(("code", "name", "is_initial", "is_public", "is_editable", "is_archived"), r))
                    for r in STATUSES])
    status = _ids("news_statuses")
    op.bulk_insert(_t("news_status_transitions", "action", "from_status_id", "to_status_id", "required_role",
                      "requires_reason"),
                   [{"action": a, "from_status_id": status[f], "to_status_id": status[to], "required_role": role,
                     "requires_reason": rr} for a, f, to, role, rr in TRANSITIONS])
    op.bulk_insert(_t("news_relevance_levels", "code", "name", "weight"),
                   [{"code": c, "name": n, "weight": w} for c, n, w in RELEVANCE])
    op.bulk_insert(_t("news_person_types", "code", "name"), [{"code": c, "name": n} for c, n in PERSON_TYPES])
    op.bulk_insert(_t("news_relationship_types", "code", "name"),
                   [{"code": c, "name": n} for c, n in RELATIONSHIP_TYPES])

    # Tipos de unidad: primero sin padre, luego se enlaza la jerarquía.
    op.bulk_insert(_t("org_unit_types", "code", "name", "source_table"),
                   [{"code": c, "name": n, "source_table": src} for c, n, src, _, _ in ORG_UNIT_TYPES])
    units = _ids("org_unit_types")
    for code, _, _, parent, column in ORG_UNIT_TYPES:
        if parent:
            op.execute(sa.text("UPDATE org_unit_types SET parent_type_id = :p, parent_column = :c WHERE code = :code")
                       .bindparams(p=units[parent], c=column, code=code))


def downgrade() -> None:
    op.execute("UPDATE org_unit_types SET parent_type_id = NULL, parent_column = NULL")
    for table in ("org_unit_types", "news_relationship_types", "news_person_types", "news_relevance_levels",
                  "news_status_transitions", "news_statuses"):
        op.execute(f"DELETE FROM {table}")
