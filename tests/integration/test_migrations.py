"""Migraciones (SQLite de prueba): reversibles, sin deriva respecto a los modelos, datos iniciales y
restricciones de integridad. La validación en PostgreSQL real está en tests/postgres.
"""
import pytest
from alembic import command
from sqlalchemy import inspect, text
from sqlalchemy.exc import IntegrityError

import app.main  # noqa: F401  (inicia los mapeos)
from app.modules.iam.domain.entities.identity import IdentityProvider, PasswordCredential, User, UserIdentity
from app.modules.iam.domain.entities.identity import AccountType, UserStatus
from app.shared.database import SessionLocal, engine
from tests.conftest import alembic_config


def scalar(sql: str, **kw):
    with engine.connect() as c:
        return c.execute(text(sql), kw).scalar()


def rejects(sql: str, **kw) -> bool:
    """True si la BD rechaza la sentencia por integridad."""
    with engine.connect() as c:
        try:
            c.execute(text(sql), kw)
            c.commit()
        except IntegrityError:
            return True
    return False


def run(sql: str, **kw):
    with engine.begin() as c:
        return c.execute(text(sql), kw)


def test_reversible_and_no_drift():
    cfg = alembic_config()
    command.check(cfg)  # falla si los modelos tienen cambios sin migración
    command.downgrade(cfg, "base")
    assert set(inspect(engine).get_table_names()) == {"alembic_version"}
    command.upgrade(cfg, "head")
    command.check(cfg)


def test_upgrade_from_previous_version_keeps_data():
    """Esquema en 0003 con datos (noticia + historial) -> head: los datos siguen y las nuevas FK se cumplen."""
    cfg = alembic_config()
    command.downgrade(cfg, "0003")
    run("INSERT INTO users (first_name, last_name, email, status_id, account_type_id) VALUES "
        "('A', 'B', 'autor@x.co', (SELECT id FROM user_statuses WHERE code='active'), (SELECT min(id) FROM account_types))")
    author = scalar("SELECT id FROM users WHERE email = 'autor@x.co'")
    run("INSERT INTO news_categories (name) VALUES ('Migración')")
    run("""INSERT INTO news (title, slug, summary, content, category_id, author_id, relevance_level_id, priority,
                             is_featured, is_pinned, created_at, updated_at, status_id)
           VALUES ('T', 'mig-t', 's', 'c', (SELECT id FROM news_categories WHERE name='Migración'), :a,
                   (SELECT id FROM news_relevance_levels WHERE code='medium'), 0, FALSE, FALSE,
                   CURRENT_TIMESTAMP, CURRENT_TIMESTAMP, (SELECT id FROM news_statuses WHERE code='draft'))""", a=author)
    assert scalar("SELECT required_role FROM news_status_transitions WHERE action = 'approve'") == "admin"
    command.upgrade(cfg, "head")
    assert scalar("SELECT author_id FROM news WHERE slug = 'mig-t'") == author
    assert scalar("SELECT required_permission FROM news_status_transitions WHERE action = 'approve'") == "news.approve"
    if engine.dialect.name == "sqlite":  # en PostgreSQL las FK se validan siempre al crearlas
        with engine.connect() as c:
            assert c.exec_driver_sql("PRAGMA foreign_key_check").fetchall() == []
    assert rejects("UPDATE news SET author_id = 999999 WHERE slug = 'mig-t'")   # la FK nueva está activa
    run("DELETE FROM news WHERE slug = 'mig-t'")


def test_seed_data():
    assert scalar("SELECT count(*) FROM roles") == 8  # 7 iniciales + Centro de investigación (0006)
    total = scalar("SELECT count(*) FROM permissions")
    assert scalar("""SELECT count(*) FROM role_permissions rp JOIN roles r ON r.id = rp.role_id
                     WHERE r.code = 'super_admin'""") == total
    assert scalar("""SELECT count(*) FROM role_permissions rp JOIN roles r ON r.id = rp.role_id
                     JOIN permissions p ON p.id = rp.permission_id
                     WHERE r.code = 'admin' AND p.code = 'permissions.manage'""") == 0
    # bug corregido: la jerarquía y source_table vienen de la migración
    assert scalar("SELECT source_table FROM org_unit_types WHERE code = 'faculty'") == "faculties"
    assert scalar("""SELECT p.code FROM org_unit_types c JOIN org_unit_types p ON p.id = c.parent_type_id
                     WHERE c.code = 'academic_program'""") == "faculty"


@pytest.mark.security
def test_integrity_constraints():
    st, at = scalar("SELECT id FROM user_statuses WHERE code='active'"), scalar("SELECT id FROM account_types LIMIT 1")
    new_user = "INSERT INTO users (first_name, last_name, email, status_id, account_type_id) VALUES ('A','B',:e,:s,:a)"
    run(new_user, e="ana@unisimon.edu.co", s=st, a=at)
    uid = scalar("SELECT id FROM users WHERE email='ana@unisimon.edu.co'")

    assert rejects(new_user, e="ana@unisimon.edu.co", s=st, a=at)        # correo duplicado
    assert rejects(new_user, e="Mayus@unisimon.edu.co", s=st, a=at)      # correo no normalizado
    run("UPDATE users SET deleted_at = CURRENT_TIMESTAMP WHERE id = :u", u=uid)
    assert not rejects(new_user, e="ana@unisimon.edu.co", s=st, a=at)    # se libera tras borrado lógico

    role = scalar("SELECT id FROM roles WHERE code='editor'")
    assign = "INSERT INTO user_role_assignments (user_id, role_id, scope_type_id, scope_id) VALUES (:u,:r,:t,:i)"
    run(assign, u=uid, r=role, t=None, i=None)
    assert rejects(assign, u=uid, r=role, t=None, i=None)                # duplicada institucional (NULL)
    faculty = scalar("SELECT id FROM org_unit_types WHERE code='faculty'")
    run(assign, u=uid, r=role, t=faculty, i=5)
    assert rejects(assign, u=uid, r=role, t=faculty, i=5)                # duplicada con alcance
    assert rejects(assign, u=uid, r=role, t=faculty, i=None)             # alcance incompleto
    assert rejects("UPDATE user_role_assignments SET revoked_at = CURRENT_TIMESTAMP WHERE user_id = :u", u=uid)
    run("UPDATE user_role_assignments SET revoked_at = CURRENT_TIMESTAMP, revoked_by = :u "
        "WHERE user_id = :u AND scope_id IS NULL", u=uid)
    run(assign, u=uid, r=role, t=None, i=None)                           # revocada => se puede reasignar

    assert rejects("INSERT INTO user_tokens (user_id, purpose, token_hash, expires_at) "
                   "VALUES (:u, 'otra_cosa', 'h', CURRENT_TIMESTAMP)", u=uid)
    assert rejects("INSERT INTO audit_logs (event_type, result) VALUES ('x', 'tal_vez')")


def test_orm_mapping():
    with SessionLocal() as s:
        status = s.query(UserStatus).filter_by(code="active").one()
        acct = s.query(AccountType).filter_by(code="institutional").one()
        ms = s.query(IdentityProvider).filter_by(code="microsoft").one()
        u = User(first_name="Luis", last_name="Pérez", email="luis@unisimon.edu.co", status=status,
                 account_type=acct, password=PasswordCredential(password_hash="$argon2id$fake"),
                 identities=[UserIdentity(provider=ms, tenant_id="tid-1", subject="oid-1")])
        s.add(u)
        s.commit()
        uid = u.id
    with SessionLocal() as s:
        u = s.get(User, uid)
        assert u.status.code == "active" and u.password.password_hash.startswith("$argon2id$")
        assert [(i.provider.code, i.subject) for i in u.identities] == [("microsoft", "oid-1")]
        status, acct, ms = u.status, u.account_type, u.identities[0].provider  # de esta sesión
        s.add(User(first_name="X", last_name="Y", email="otro@unisimon.edu.co", status=status, account_type=acct,
                   identities=[UserIdentity(provider=ms, tenant_id="tid-1", subject="oid-1")]))
        try:
            s.commit()
            raise AssertionError("identidad externa duplicada aceptada")
        except IntegrityError:
            s.rollback()

