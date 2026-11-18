"""privacidad: la tipografía ya no viene de Google Fonts (el portal la sirve): se quita ese tercero de la lista de
tecnologías de la categoría «necesarias» que ven los visitantes. Solo datos; reversible.

Revision ID: 0009
Revises: 0008
"""
import json

import sqlalchemy as sa
from alembic import op

revision = "0009"
down_revision = "0008"
branch_labels = None
depends_on = None

GOOGLE_FONTS = {"name": "Tipografía del portal", "type": "third_party", "duration": "Según el proveedor",
                "provider": "Google Fonts",
                "purpose": "Mostrar la tipografía del portal. Al descargarla, Google recibe la dirección IP del navegador."}


def _update(fn) -> None:
    bind = op.get_bind()
    raw = bind.execute(sa.text("SELECT technologies FROM privacy_cookie_categories WHERE code = 'necessary'")).scalar()
    if raw is None:
        return
    techs = raw if isinstance(raw, list) else json.loads(raw)
    bind.execute(sa.text("UPDATE privacy_cookie_categories SET technologies = :t WHERE code = 'necessary'")
                 .bindparams(sa.bindparam("t", type_=sa.JSON)), {"t": fn(techs)})


def upgrade() -> None:
    _update(lambda techs: [t for t in techs if t.get("provider") != "Google Fonts"])


def downgrade() -> None:
    _update(lambda techs: techs if any(t.get("provider") == "Google Fonts" for t in techs) else techs + [GOOGLE_FONTS])
