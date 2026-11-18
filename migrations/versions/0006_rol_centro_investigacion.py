"""Rol "Centro de investigación": solo crea noticias de su centro.

Se asigna a un usuario CON ALCANCE de un centro (user_role_assignments.scope_type/scope_id); así solo
puede crear y editar noticias asociadas a ese centro. No revisa, aprueba, publica ni archiva.
Permisos mínimos para crear de verdad una noticia:
  news.create  crearla (borrador)
  news.update  completarla y subir su imagen mientras es borrador o fue rechazada
  news.view    verla en el panel (sus borradores no son públicos)
  news.submit  enviarla a revisión; sin esto se quedaría en borrador para siempre

Revision ID: 0006
Revises: 0005
"""
import sqlalchemy as sa
from alembic import op

revision = "0006"
down_revision = "0005"
branch_labels = None
depends_on = None

CODE = "research_center"
PERMISSIONS = ("news.view", "news.create", "news.update", "news.submit")


def upgrade() -> None:
    bind = op.get_bind()
    bind.execute(sa.text("INSERT INTO roles (code, name, description, is_active) VALUES (:c, :n, :d, :a)"),
                 {"c": CODE, "n": "Centro de investigación",
                  "d": "Crea noticias de su centro y las envía a revisión (asignar con alcance al centro)", "a": True})
    bind.execute(sa.text("INSERT INTO role_permissions (role_id, permission_id) "
                         "SELECT r.id, p.id FROM roles r, permissions p WHERE r.code = :c AND p.code IN :ps")
                 .bindparams(sa.bindparam("ps", expanding=True)), {"c": CODE, "ps": list(PERMISSIONS)})


def downgrade() -> None:
    bind = op.get_bind()
    role = "(SELECT id FROM roles WHERE code = :c)"
    for table in ("user_role_assignments", "role_permissions"):
        bind.execute(sa.text(f"DELETE FROM {table} WHERE role_id = {role}"), {"c": CODE})
    bind.execute(sa.text("DELETE FROM roles WHERE code = :c"), {"c": CODE})
