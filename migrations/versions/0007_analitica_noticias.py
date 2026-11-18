"""analítica de noticias: lecturas, compartidos y permiso news.analytics.

Sin datos personales (ver app/modules/analytics/infrastructure/tables.py). El permiso se da a los roles que
ya gestionan o publican noticias; con alcance (p. ej. research_center) solo ve las de sus dependencias.

Revision ID: 0007
Revises: 0006
"""
import sqlalchemy as sa
from alembic import op

revision = "0007"
down_revision = "0006"
branch_labels = None
depends_on = None

Ts = sa.DateTime(timezone=True)
BigId = sa.BigInteger().with_variant(sa.Integer(), "sqlite")


def Hex(n: int):  # intercalación binaria en PostgreSQL (ver tables.Hex)
    return sa.String(n).with_variant(sa.String(n, collation="C"), "postgresql")
CODE = "news.analytics"
ROLES = ("super_admin", "admin", "publisher", "research_center")


def _in(column: str, values: tuple[str, ...]) -> str:
    return f"{column} IN ({', '.join(repr(v) for v in values)})"


def upgrade() -> None:
    op.create_table(
        "news_analytics_views",
        sa.Column("id", BigId, primary_key=True),
        sa.Column("news_id", sa.Integer(), sa.ForeignKey("news.id", ondelete="CASCADE"), nullable=False),
        sa.Column("session_id", Hex(36), nullable=False),
        sa.Column("visitor_hash", Hex(16), nullable=False),
        sa.Column("day", sa.Date(), nullable=False),
        sa.Column("viewed_at", Ts, nullable=False),
        sa.Column("last_seen_at", Ts, nullable=False),
        sa.Column("active_seconds", sa.Integer(), nullable=False),
        sa.Column("source", sa.String(10), nullable=False),
        sa.Column("referrer_host", sa.String(255)),
        sa.Column("device", sa.String(10), nullable=False),
        sa.Column("browser", sa.String(20), nullable=False),
        sa.Column("os", sa.String(20), nullable=False),
        sa.Column("is_entry", sa.Boolean(), nullable=False),
        sa.Column("from_news_id", sa.Integer()),
        sa.UniqueConstraint("news_id", "session_id", name="uq_news_analytics_views_read"),
        sa.CheckConstraint("active_seconds BETWEEN 0 AND 7200", name="ck_news_analytics_views_active"),
        sa.CheckConstraint(_in("source", ("direct", "internal", "search", "social", "external")),
                           name="ck_news_analytics_views_source"),
        sa.CheckConstraint(_in("device", ("desktop", "tablet", "mobile")), name="ck_news_analytics_views_device"),
    )
    op.create_index("ix_news_analytics_views_day", "news_analytics_views", ["day"])
    op.create_index("ix_news_analytics_views_news_day", "news_analytics_views", ["news_id", "day"])

    op.create_table(
        "news_analytics_shares",
        sa.Column("id", BigId, primary_key=True),
        sa.Column("news_id", sa.Integer(), sa.ForeignKey("news.id", ondelete="CASCADE"), nullable=False),
        sa.Column("session_id", Hex(36), nullable=False),
        sa.Column("channel", sa.String(12), nullable=False),
        sa.Column("day", sa.Date(), nullable=False),
        sa.Column("at", Ts, nullable=False),
        sa.UniqueConstraint("news_id", "session_id", "channel", name="uq_news_analytics_shares_click"),
        sa.CheckConstraint(_in("channel", ("whatsapp", "facebook", "x", "linkedin", "email", "copy_link", "native",
                                           "other")), name="ck_news_analytics_shares_channel"),
    )
    op.create_index("ix_news_analytics_shares_day", "news_analytics_shares", ["day"])
    op.create_index("ix_news_analytics_shares_news_day", "news_analytics_shares", ["news_id", "day"])

    bind = op.get_bind()
    bind.execute(sa.text("INSERT INTO permissions (code, name, module, resource, action, is_active) "
                         "VALUES (:c, 'Ver estadísticas de noticias', 'news', 'analytics', 'view', :a)"),
                 {"c": CODE, "a": True})
    bind.execute(sa.text("INSERT INTO role_permissions (role_id, permission_id) "
                         "SELECT r.id, p.id FROM roles r, permissions p WHERE p.code = :c AND r.code IN :rs")
                 .bindparams(sa.bindparam("rs", expanding=True)), {"c": CODE, "rs": list(ROLES)})


def downgrade() -> None:
    bind = op.get_bind()
    bind.execute(sa.text("DELETE FROM role_permissions WHERE permission_id = "
                         "(SELECT id FROM permissions WHERE code = :c)"), {"c": CODE})
    bind.execute(sa.text("DELETE FROM permissions WHERE code = :c"), {"c": CODE})
    op.drop_table("news_analytics_shares")
    op.drop_table("news_analytics_views")
