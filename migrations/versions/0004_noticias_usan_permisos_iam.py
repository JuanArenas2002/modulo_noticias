"""noticias consumen el IAM: transiciones por permiso, autor/actor como FK a users, alcance institucional como dato.

Revision ID: 0004
Revises: 0003
"""
import sqlalchemy as sa
from alembic import op

revision = "0004"
down_revision = "0003"
branch_labels = None
depends_on = None

# acción -> permiso (antes: rol). reject lo hace quien revisa; schedule es una forma de publicar.
ACTION_PERMISSION = {"submit": "news.submit", "approve": "news.approve", "reject": "news.review",
                     "publish": "news.publish", "schedule": "news.publish", "archive": "news.archive"}
ACTION_ROLE = {"submit": "editor"}  # downgrade: el resto era "admin"


def upgrade() -> None:
    with op.batch_alter_table("org_unit_types") as b:
        b.add_column(sa.Column("is_institutional", sa.Boolean(), nullable=False, server_default=sa.false()))
    op.execute("UPDATE org_unit_types SET is_institutional = TRUE WHERE code = 'institution'")

    with op.batch_alter_table("news_status_transitions") as b:
        b.add_column(sa.Column("required_permission", sa.String(100), nullable=True))
    for action, perm in ACTION_PERMISSION.items():
        op.execute(sa.text("UPDATE news_status_transitions SET required_permission = :p WHERE action = :a")
                   .bindparams(p=perm, a=action))
    with op.batch_alter_table("news_status_transitions") as b:
        b.alter_column("required_permission", existing_type=sa.String(100), nullable=False)
        b.create_foreign_key("fk_transition_permission", "permissions", ["required_permission"], ["code"])
        b.drop_column("required_role")

    with op.batch_alter_table("news") as b:
        b.create_foreign_key("fk_news_author", "users", ["author_id"], ["id"])
    with op.batch_alter_table("news_history") as b:
        b.create_foreign_key("fk_news_history_actor", "users", ["actor_id"], ["id"])


def downgrade() -> None:
    with op.batch_alter_table("news_history") as b:
        b.drop_constraint("fk_news_history_actor", type_="foreignkey")
    with op.batch_alter_table("news") as b:
        b.drop_constraint("fk_news_author", type_="foreignkey")

    with op.batch_alter_table("news_status_transitions") as b:
        b.add_column(sa.Column("required_role", sa.String(30), nullable=True))
    op.execute("UPDATE news_status_transitions SET required_role = 'admin'")
    for action, role in ACTION_ROLE.items():
        op.execute(sa.text("UPDATE news_status_transitions SET required_role = :r WHERE action = :a")
                   .bindparams(r=role, a=action))
    with op.batch_alter_table("news_status_transitions") as b:
        b.alter_column("required_role", existing_type=sa.String(30), nullable=False)
        b.drop_constraint("fk_transition_permission", type_="foreignkey")
        b.drop_column("required_permission")

    with op.batch_alter_table("org_unit_types") as b:
        b.drop_column("is_institutional")
