"""Prepara la BD de la prueba de carga (k6): esquema DESECHABLE `k6_load` en la BD de TEST_DATABASE_URL.

    .venv/Scripts/python tests/load/preparar_bd.py          # recrea el esquema, migra y siembra
    .venv/Scripts/python tests/load/preparar_bd.py --borrar # elimina el esquema al terminar

Salvaguardas: la BD debe llamarse *test* y ser distinta de DATABASE_URL; solo se toca el esquema k6_load.
Siembra: 40 noticias publicadas, 300 000 lecturas en el último año (historia para el panel) y un super_admin
k6-admin@unisimon.edu.co con la clave de K6_ADMIN_PASSWORD (por defecto una de prueba).
"""
import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
os.chdir(ROOT)

from sqlalchemy import create_engine, make_url, text  # noqa: E402

env = dict(line.split("=", 1) for line in (ROOT / ".env").read_text(encoding="utf-8").splitlines()
           if "=" in line and not line.lstrip().startswith("#"))
test_url = make_url(os.environ.get("TEST_DATABASE_URL") or env["TEST_DATABASE_URL"].strip())
if "test" not in (test_url.database or "") or test_url.database == make_url(env["DATABASE_URL"].strip()).database:
    sys.exit("TEST_DATABASE_URL debe ser una BD *test* distinta de DATABASE_URL")
SCHEMA = "k6_load"
URL = test_url.update_query_dict({"options": f"-csearch_path={SCHEMA}"})

admin = create_engine(test_url)
with admin.begin() as c:
    c.exec_driver_sql(f'DROP SCHEMA IF EXISTS "{SCHEMA}" CASCADE')
    if "--borrar" in sys.argv:
        sys.exit(print(f"Esquema {SCHEMA} eliminado"))
    c.exec_driver_sql(f'CREATE SCHEMA "{SCHEMA}"')

os.environ["DATABASE_URL"] = URL.render_as_string(hide_password=False)
from alembic import command  # noqa: E402
from alembic.config import Config  # noqa: E402

cfg = Config(str(ROOT / "alembic.ini"))
cfg.attributes["configure_logger"] = False
command.upgrade(cfg, "head")

import app.main  # noqa: E402,F401
from app.modules.iam.domain.entities.identity import PasswordCredential, User  # noqa: E402
from app.modules.iam.infrastructure.repositories.argon2_password_hasher import hasher  # noqa: E402
from app.modules.iam.infrastructure.repositories.sqlalchemy_iam_repositories import SqlAlchemyIamUnitOfWork  # noqa: E402
from app.shared.clock import now  # noqa: E402
from app.shared.database import SessionLocal, engine  # noqa: E402

with SessionLocal() as s:
    uow = SqlAlchemyIamUnitOfWork(s)
    u = User(first_name="K6", last_name="Admin", email="k6-admin@unisimon.edu.co", status=uow.users.status("active"),
             account_type=uow.users.account_type("institutional"), email_verified_at=now(),
             password=PasswordCredential(password_hash=hasher.hash(os.environ.get("K6_ADMIN_PASSWORD",
                                                                                  "Carga-K6-Prueba-2026!"))))
    uow.users.add(u)
    uow.commit()

with engine.begin() as c:
    c.execute(text("INSERT INTO user_role_assignments (user_id, role_id) SELECT u.id, r.id FROM users u, roles r "
                   "WHERE u.email = 'k6-admin@unisimon.edu.co' AND r.code = 'super_admin'"))
    c.exec_driver_sql(
        "INSERT INTO news_categories (name) VALUES ('Carga');"
        "INSERT INTO news (title, slug, summary, content, category_id, author_id, relevance_level_id, priority,"
        " is_featured, is_pinned, published_at, created_at, updated_at, status_id)"
        " SELECT 'Noticia de carga ' || g, 'carga-' || g, 's', '<p>c</p>', (SELECT id FROM news_categories),"
        " (SELECT id FROM users), (SELECT id FROM news_relevance_levels WHERE code='medium'), 0, FALSE, FALSE,"
        " now() - interval '400 days', now(), now(), (SELECT id FROM news_statuses WHERE code='published')"
        " FROM generate_series(1, 40) g;"
        "INSERT INTO news_analytics_views (news_id, session_id, visitor_hash, day, viewed_at, last_seen_at,"
        " active_seconds, source, device, browser, os, is_entry)"
        " SELECT (SELECT min(id) FROM news) + mod(g, 40), 'hist-' || g, 'v' || mod(g, 60000),"
        " current_date - 1 - mod(g, 365), now(), now(), mod(g, 400),"
        " (ARRAY['direct','search','social','external','internal'])[1 + mod(g, 5)],"
        " (ARRAY['desktop','mobile','tablet'])[1 + mod(g, 3)], 'Chrome', 'Windows', mod(g, 2) = 0"
        " FROM generate_series(1, 300000) g;"
        "ANALYZE;")
    ids = c.execute(text("SELECT min(id), max(id) FROM news")).one()
print(f"Esquema {SCHEMA} listo: noticias {ids[0]}..{ids[1]}, 300 000 lecturas históricas")
print(f"DATABASE_URL para el backend de carga:\n{URL.render_as_string(hide_password=True)}")
