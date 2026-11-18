"""privacidad: declara la cookie necesaria `cris_consent_set` (marca no secreta «ya decidió») en la categoría
«necesarias» que ven los visitantes. Solo datos; reversible.

Revision ID: 0010
Revises: 0009
"""
import json

import sqlalchemy as sa
from alembic import op

revision = "0010"
down_revision = "0009"
branch_labels = None
depends_on = None

MARK = {"name": "cris_consent_set", "type": "cookie", "duration": "12 meses",
        "provider": "Universidad Simón Bolívar (propia)",
        "purpose": "Indicar que ya decidiste sobre las cookies (solo el valor «1»), para no mostrarte el aviso otra vez."}


def _update(fn) -> None:
    bind = op.get_bind()
    raw = bind.execute(sa.text("SELECT technologies FROM privacy_cookie_categories WHERE code = 'necessary'")).scalar()
    if raw is None:
        return
    techs = raw if isinstance(raw, list) else json.loads(raw)
    bind.execute(sa.text("UPDATE privacy_cookie_categories SET technologies = :t WHERE code = 'necessary'")
                 .bindparams(sa.bindparam("t", type_=sa.JSON)), {"t": fn(techs)})


def upgrade() -> None:
    _update(lambda techs: techs if any(t.get("name") == MARK["name"] for t in techs)
            else techs[:1] + [MARK] + techs[1:])


def downgrade() -> None:
    _update(lambda techs: [t for t in techs if t.get("name") != MARK["name"]])
