"""personas de una noticia identificadas por ORCID iD (reemplaza person_id numérico).

Un id numérico no se puede convertir en ORCID: las asociaciones existentes sin ORCID se ELIMINAN
(se imprime cuántas). La tabla se recrea (portátil en PostgreSQL y SQLite).
Downgrade: vuelve al esquema anterior; las asociaciones por ORCID se pierden (no hay id numérico).

Revision ID: 0005
Revises: 0004
"""
import sqlalchemy as sa
from alembic import op

revision = "0005"
down_revision = "0004"
branch_labels = None
depends_on = None

Ts = sa.DateTime(timezone=True)


def _create(person_column: sa.Column, unique_cols: tuple[str, ...]) -> None:
    op.create_table(
        "news_people",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("news_id", sa.Integer(), sa.ForeignKey("news.id"), nullable=False),
        sa.Column("person_type_id", sa.Integer(), sa.ForeignKey("news_person_types.id"), nullable=False),
        person_column,
        sa.Column("relationship_type_id", sa.Integer(), sa.ForeignKey("news_relationship_types.id"), nullable=False),
        sa.Column("created_at", Ts, nullable=False),
        sa.UniqueConstraint(*unique_cols),
    )
    op.create_index("ix_news_people_news_id", "news_people", ["news_id"])


def _drop_existing() -> None:
    removed = op.get_bind().execute(sa.text("SELECT count(*) FROM news_people")).scalar() \
        if not op.get_context().as_sql else 0
    if removed:
        print(f"[0005] Se eliminan {removed} asociaciones de personas sin ORCID (no convertibles).")
    op.drop_index("ix_news_people_news_id", table_name="news_people")
    op.drop_table("news_people")


def upgrade() -> None:
    _drop_existing()
    _create(sa.Column("orcid", sa.String(19), nullable=False),
            ("news_id", "person_type_id", "orcid", "relationship_type_id"))
    op.create_index("ix_news_people_orcid", "news_people", ["orcid"])


def downgrade() -> None:
    op.drop_index("ix_news_people_orcid", table_name="news_people")
    _drop_existing()
    _create(sa.Column("person_id", sa.BigInteger(), nullable=False),
            ("news_id", "person_type_id", "person_id", "relationship_type_id"))
