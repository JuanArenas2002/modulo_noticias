"""Validación en PostgreSQL REAL (requiere TEST_DATABASE_URL).

    TEST_DATABASE_URL=postgresql+psycopg://usuario:clave@host:5432/noticias_test pytest -m postgres -v

Salvaguardas (no negociables):
- el nombre de la BD debe contener "test" y no puede coincidir con DATABASE_URL del entorno;
- todo ocurre en un esquema NUEVO `iam_test_<aleatorio>` que se crea y se borra al final: nunca se tocan
  esquemas ni datos existentes (no hace falta permiso CREATEDB, solo CREATE en esa BD).
Sin TEST_DATABASE_URL este módulo se OMITE (y la validación en PostgreSQL queda pendiente).
"""
import os
import secrets
import subprocess
import sys

import pytest
from alembic import command
from alembic.script import ScriptDirectory
from sqlalchemy import create_engine, make_url, text
from sqlalchemy.exc import DBAPIError, IntegrityError

import app.main  # noqa: F401  (registra todas las tablas en metadata)
from app.shared.database import metadata
from tests.conftest import ORIGINAL_DATABASE_URL, ROOT, alembic_config

URL = os.environ.get("TEST_DATABASE_URL")
if not URL:
    pytest.skip("TEST_DATABASE_URL no definida: validación en PostgreSQL PENDIENTE", allow_module_level=True)

_url = make_url(URL)
if not _url.drivername.startswith("postgresql"):
    pytest.exit("TEST_DATABASE_URL debe ser PostgreSQL", returncode=2)
if "test" not in (_url.database or "").lower():
    pytest.exit("Por seguridad, la BD de TEST_DATABASE_URL debe llamarse *test*", returncode=2)
if ORIGINAL_DATABASE_URL and make_url(ORIGINAL_DATABASE_URL).render_as_string() == _url.render_as_string():
    pytest.exit("TEST_DATABASE_URL no puede ser la misma que DATABASE_URL", returncode=2)

SCHEMA = f"iam_test_{secrets.token_hex(4)}"
SCHEMA_URL = _url.update_query_dict({"options": f"-csearch_path={SCHEMA}"})


@pytest.fixture(scope="module")
def pg():
    admin = create_engine(_url)
    with admin.begin() as c:
        c.exec_driver_sql(f'CREATE SCHEMA "{SCHEMA}"')
    engine = create_engine(SCHEMA_URL)
    try:
        yield engine
    finally:
        engine.dispose()
        with admin.begin() as c:
            c.exec_driver_sql(f'DROP SCHEMA IF EXISTS "{SCHEMA}" CASCADE')
        admin.dispose()


def migrate(engine, target: str, down: bool = False) -> None:
    cfg = alembic_config()
    with engine.begin() as conn:
        cfg.attributes["connection"] = conn
        (command.downgrade if down else command.upgrade)(cfg, target)


def scalar(engine, sql: str, **kw):
    with engine.connect() as c:
        return c.execute(text(sql), kw).scalar()


def rejects(engine, sql: str, **kw) -> bool:
    try:
        with engine.begin() as c:
            c.execute(text(sql), kw)
    except (IntegrityError, DBAPIError):
        return True
    return False


def test_upgrade_from_empty_and_seed_data(pg):
    migrate(pg, "head")
    head = ScriptDirectory.from_config(alembic_config()).get_current_head()
    assert scalar(pg, "SELECT version_num FROM alembic_version") == head
    assert scalar(pg, "SELECT count(*) FROM roles") == 8  # 7 iniciales + Centro de investigación (0006)
    tables = {r[0] for r in pg.connect().execute(text(
        "SELECT table_name FROM information_schema.tables WHERE table_schema = :s"), {"s": SCHEMA})}
    assert tables == set(metadata.tables) | {"alembic_version"}                # exactamente el modelo, ni más ni menos
    assert scalar(pg, "SELECT required_permission FROM news_status_transitions WHERE action = 'approve'") == "news.approve"


def test_constraints_indexes_and_foreign_keys(pg):
    names = lambda kind: {r[0] for r in pg.connect().execute(text(  # noqa: E731
        "SELECT conname FROM pg_constraint c JOIN pg_namespace n ON n.oid = c.connamespace "
        "WHERE n.nspname = :s AND contype = :k"), {"s": SCHEMA, "k": kind})}
    assert {"ck_users_email_lower", "ck_assignment_scope_pair", "ck_assignment_revoked_by", "ck_user_tokens_purpose",
            "ck_audit_result", "ck_auth_sessions_expiry", "ck_news_vigencia", "ck_org_unit_types_parent"} <= names("c")
    assert {"fk_news_author", "fk_news_history_actor", "fk_transition_permission"} <= names("f")
    indexes = {r[0]: r[1] for r in pg.connect().execute(text(
        "SELECT indexname, indexdef FROM pg_indexes WHERE schemaname = :s"), {"s": SCHEMA})}
    assert "WHERE (deleted_at IS NULL)" in indexes["uq_users_email_alive"]
    assert "COALESCE" in indexes["uq_assignment_active"] and "revoked_at IS NULL" in indexes["uq_assignment_active"]
    assert indexes["uq_user_identities_subject"].startswith("CREATE UNIQUE INDEX")


def test_constraints_are_enforced(pg):
    st = scalar(pg, "SELECT id FROM user_statuses WHERE code = 'active'")
    at = scalar(pg, "SELECT min(id) FROM account_types")
    new_user = "INSERT INTO users (first_name, last_name, email, status_id, account_type_id) VALUES ('A','B',:e,:s,:a)"
    assert not rejects(pg, new_user, e="pg@u.co", s=st, a=at)
    assert rejects(pg, new_user, e="pg@u.co", s=st, a=at)                    # UNIQUE parcial
    assert rejects(pg, new_user, e="Mayus@u.co", s=st, a=at)                 # CHECK minúsculas
    uid = scalar(pg, "SELECT id FROM users WHERE email = 'pg@u.co'")
    role = scalar(pg, "SELECT id FROM roles WHERE code = 'editor'")
    assign = "INSERT INTO user_role_assignments (user_id, role_id, scope_type_id, scope_id) VALUES (:u,:r,:t,:i)"
    assert not rejects(pg, assign, u=uid, r=role, t=None, i=None)
    assert rejects(pg, assign, u=uid, r=role, t=None, i=None)                # índice COALESCE (NULL == NULL)
    assert rejects(pg, "UPDATE news_status_transitions SET required_permission = 'no.existe'")  # FK
    assert rejects(pg, "INSERT INTO auth_sessions (user_id, token_hash, csrf_token_hash, provider_id, "
                       "idle_expires_at, expires_at) VALUES (:u, 'a', 'b', 1, now() + interval '2 day', now())", u=uid)


def test_audit_logs_are_immutable_in_postgres(pg):
    with pg.begin() as c:
        c.execute(text("INSERT INTO audit_logs (event_type, result) VALUES ('test.event', 'success')"))
    assert rejects(pg, "UPDATE audit_logs SET result = 'failure'")             # trigger
    assert rejects(pg, "DELETE FROM audit_logs")
    assert scalar(pg, "SELECT count(*) FROM audit_logs WHERE event_type = 'test.event'") == 1


def test_upgrade_over_previous_schema_version_keeps_data(pg):
    with pg.begin() as c:  # el trigger impide borrar auditoría: se vacía con TRUNCATE (solo en este esquema)
        c.exec_driver_sql("TRUNCATE audit_logs")
    migrate(pg, "0003", down=True)
    assert scalar(pg, "SELECT required_role FROM news_status_transitions WHERE action = 'approve'") == "admin"
    with pg.begin() as c:
        c.execute(text("INSERT INTO news_categories (name) VALUES ('PG')"))
        c.execute(text("""INSERT INTO news (title, slug, summary, content, category_id, author_id, relevance_level_id,
                            priority, is_featured, is_pinned, created_at, updated_at, status_id)
                          VALUES ('T', 'pg-t', 's', 'c', (SELECT id FROM news_categories WHERE name='PG'),
                                  (SELECT id FROM users WHERE email='pg@u.co'),
                                  (SELECT id FROM news_relevance_levels WHERE code='medium'), 0, false, false,
                                  now(), now(), (SELECT id FROM news_statuses WHERE code='draft'))"""))
    migrate(pg, "head")
    assert scalar(pg, "SELECT u.email FROM news n JOIN users u ON u.id = n.author_id WHERE n.slug = 'pg-t'") == "pg@u.co"
    assert rejects(pg, "UPDATE news SET author_id = 999999 WHERE slug = 'pg-t'")  # FK nueva activa


def test_full_downgrade_is_reversible(pg):
    with pg.begin() as c:
        c.exec_driver_sql("DELETE FROM news; DELETE FROM news_categories; DELETE FROM user_role_assignments; "
                          "DELETE FROM users; TRUNCATE audit_logs")
    migrate(pg, "base", down=True)
    assert scalar(pg, "SELECT count(*) FROM information_schema.tables WHERE table_schema = :s "
                      "AND table_name != 'alembic_version'", s=SCHEMA) == 0
    migrate(pg, "head")
    assert scalar(pg, "SELECT count(*) FROM permissions") == 24  # 0007: news.analytics; 0008: privacy.manage


def test_integration_and_security_suites_pass_on_postgres(pg):
    """Repite TODA la suite de integración y seguridad contra este esquema PostgreSQL efímero."""
    env = {**os.environ, "IAM_TEST_DATABASE_URL": SCHEMA_URL.render_as_string(hide_password=False)}
    env.pop("TEST_DATABASE_URL")  # el subproceso no debe volver a entrar aquí
    result = subprocess.run([sys.executable, "-m", "pytest", "tests/integration", "tests/security", "-q",
                             "-p", "no:warnings"], cwd=ROOT, env=env, capture_output=True, text=True, timeout=1800)
    assert result.returncode == 0, result.stdout[-4000:] + result.stderr[-2000:]


def test_analytics_queries_scale(pg):
    """Rendimiento: 300 000 lecturas en un año (≈ 820/día, holgado para el portal). El panel completo
    (overview = ~15 consultas agregadas) debe responder en menos de 2 s y el filtro por noticia usar índice."""
    import time
    from datetime import date

    from sqlalchemy.orm import Session

    from app.modules.analytics.application.use_cases import news_detail, overview
    from app.modules.analytics.infrastructure.repository import AnalyticsRepository, Filters

    migrate(pg, "head")
    with pg.begin() as c:
        c.exec_driver_sql(
            "INSERT INTO users (first_name, last_name, email, status_id, account_type_id) VALUES ('P', 'Q', "
            "'perf@u.co', (SELECT id FROM user_statuses WHERE code='active'), (SELECT min(id) FROM account_types));"
            "INSERT INTO news_categories (name) VALUES ('Perf');"
            "INSERT INTO news (title, slug, summary, content, category_id, author_id, relevance_level_id, priority,"
            " is_featured, is_pinned, published_at, created_at, updated_at, status_id)"
            " SELECT 'N' || g, 'perf-' || g, 's', 'c', (SELECT id FROM news_categories WHERE name='Perf'),"
            " (SELECT id FROM users WHERE email='perf@u.co'), (SELECT id FROM news_relevance_levels WHERE code='medium'),"
            " 0, FALSE, FALSE, '2025-01-01', now(), now(), (SELECT id FROM news_statuses WHERE code='published')"
            " FROM generate_series(1, 200) g;"
            "INSERT INTO news_analytics_views (news_id, session_id, visitor_hash, day, viewed_at, last_seen_at,"
            " active_seconds, source, device, browser, os, is_entry)"
            " SELECT (SELECT min(id) FROM news) + mod(g, 200), 's' || g, 'v' || (mod(g, 50000)), DATE '2025-01-01' + mod(g, 365),"
            " now(), now(), mod(g, 400), (ARRAY['direct','search','social','external','internal'])[1 + mod(g, 5)],"
            " (ARRAY['desktop','mobile','tablet'])[1 + mod(g, 3)], 'Chrome', 'Windows', mod(g, 2) = 0"
            " FROM generate_series(1, 300000) g;"
            "INSERT INTO news_analytics_shares (news_id, session_id, channel, day, at)"
            " SELECT (SELECT min(id) FROM news) + mod(g, 200), 's' || g, 'whatsapp', DATE '2025-01-01' + mod(g, 365), now()"
            " FROM generate_series(1, 20000) g;"
            "ANALYZE news_analytics_views; ANALYZE news_analytics_shares;")
    news_id = scalar(pg, "SELECT min(id) FROM news")
    with Session(pg) as s:
        repo = AnalyticsRepository(s)
        t0 = time.perf_counter()
        data = overview(repo, Filters(start=date(2025, 1, 1), end=date(2025, 12, 31)))
        elapsed = time.perf_counter() - t0
        assert data["totals"]["page_views"] == 300000 and data["totals"]["shares"] == 20000
        assert elapsed < 2, f"overview anual tardó {elapsed:.2f} s"
        t0 = time.perf_counter()
        one = news_detail(repo, Filters(start=date(2025, 6, 1), end=date(2025, 6, 30), news_id=news_id))
        assert one["news"]["views"] > 0 and time.perf_counter() - t0 < 1
        from datetime import UTC, datetime, timedelta

        with pg.begin() as c:  # un día intenso hoy (5 000 lecturas) sobre la tabla de 300 000
            c.execute(text("INSERT INTO news_analytics_views (news_id, session_id, visitor_hash, day, viewed_at,"
                           " last_seen_at, active_seconds, source, device, browser, os, is_entry)"
                           " SELECT :n, 'today' || g, 'v' || g, :d, now(), now() - make_interval(secs => mod(g, 120)),"
                           " 0, 'direct', 'desktop', 'Chrome', 'Windows', TRUE FROM generate_series(1, 5000) g"),
                      {"n": news_id, "d": datetime.now(UTC).astimezone().date()})
            c.exec_driver_sql("ANALYZE news_analytics_views")
        t0 = time.perf_counter()
        for _ in range(10):  # el panel lo consulta cada 10 s por cada administrador conectado
            live = repo.live(Filters(start=date(2025, 1, 1), end=date(2025, 12, 31)), datetime.now(UTC), 45)
        assert live["active_readers"] > 0 and (time.perf_counter() - t0) / 10 < 0.05, "en vivo: < 50 ms"
        plan ="\n".join(r[0] for r in s.execute(text(
            "EXPLAIN SELECT count(*) FROM news_analytics_views WHERE news_id = :n AND day BETWEEN :a AND :b"),
            {"n": news_id, "a": date(2025, 6, 1), "b": date(2025, 6, 30)}))
        assert "ix_news_analytics_views_news_day" in plan or "uq_news_analytics_views_read" in plan, plan
