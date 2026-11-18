"""Configuración global de pytest.

Aislamiento:
- DATABASE_URL se SOBRESCRIBE siempre: las pruebas jamás usan la BD del entorno (producción incluida).
  Por defecto: SQLite temporal. `IAM_TEST_DATABASE_URL` solo la fija tests/postgres para repetir la
  suite en un esquema PostgreSQL efímero (nunca la pongas a mano apuntando a una BD real).
- Cada módulo de prueba recibe una BD recién migrada con Alembic (mismo camino que producción).
- Marcadores por carpeta: unit / integration / security / postgres.
"""
import os
import re
import tempfile
from pathlib import Path

_TMP = tempfile.mkdtemp(prefix="iam-tests-")


def _dotenv(path: Path = Path(__file__).resolve().parents[1] / ".env") -> dict[str, str]:
    if not path.is_file():
        return {}
    pairs = (ln.split("=", 1) for ln in path.read_text(encoding="utf-8").splitlines()
             if "=" in ln and not ln.lstrip().startswith("#"))
    return {k.strip(): v.strip().strip("'\"") for k, v in pairs}


_env_file = _dotenv()
# La BD real (entorno o .env): solo para NEGARSE a usarla en pruebas.
ORIGINAL_DATABASE_URL = os.environ.get("DATABASE_URL") or _env_file.get("DATABASE_URL")
# Del .env solo se toma TEST_DATABASE_URL (el resto del .env no afecta a las pruebas).
if not os.environ.get("TEST_DATABASE_URL") and _env_file.get("TEST_DATABASE_URL"):
    os.environ["TEST_DATABASE_URL"] = _env_file["TEST_DATABASE_URL"]
ORIGINAL_ENVIRONMENT = os.environ.get("ENVIRONMENT")
os.environ["DATABASE_URL"] = os.environ.get("IAM_TEST_DATABASE_URL") or f"sqlite:///{_TMP}/test.db"
os.environ.update({  # valores ficticios; nunca credenciales reales
    "DOTENV_PATH": "",  # las pruebas no leen el .env local
    "ENVIRONMENT": "development",
    "RATE_LIMIT_PER_IP": "10",
    "MEDIA_DIR": f"{_TMP}/media",
    "MICROSOFT_CLIENT_ID": "test-client-id",
    "MICROSOFT_CLIENT_SECRET": "test-secret",
    "MICROSOFT_TENANT_ID": "tenant-unisimon",
    "MICROSOFT_REDIRECT_URI": "http://testserver/api/auth/microsoft/callback",
    "MICROSOFT_POST_LOGOUT_REDIRECT_URI": "http://localhost:5173/",
})

import pytest  # noqa: E402
from alembic import command  # noqa: E402
from alembic.config import Config  # noqa: E402

ROOT = Path(__file__).resolve().parents[1]


def alembic_config() -> Config:
    cfg = Config(str(ROOT / "alembic.ini"))
    cfg.attributes["configure_logger"] = False
    return cfg


def reset_database() -> None:
    """BD vacía + `alembic upgrade head`. Solo opera sobre la BD de prueba de este proceso."""
    from app.shared.database import engine

    engine.dispose()
    if engine.dialect.name == "sqlite":
        Path(engine.url.database).unlink(missing_ok=True)
    else:  # esquema efímero creado por tests/postgres (nombre iam_test_*)
        schema = re.search(r"search_path%3D(iam_test_\w+)|search_path=(iam_test_\w+)", str(engine.url))
        assert schema, "Solo se resetean esquemas iam_test_* creados por la propia suite"
        name = schema.group(1) or schema.group(2)
        with engine.begin() as c:
            c.exec_driver_sql(f'DROP SCHEMA IF EXISTS "{name}" CASCADE')
            c.exec_driver_sql(f'CREATE SCHEMA "{name}"')
    command.upgrade(alembic_config(), "head")


def pytest_collection_modifyitems(items):
    for item in items:
        for marker in ("unit", "integration", "security", "postgres"):
            if marker in Path(str(item.fspath)).parts:
                item.add_marker(getattr(pytest.mark, marker))


@pytest.fixture(scope="module", autouse=True)
def fresh_db(request):
    """Cada módulo de integración/seguridad empieza con su propia BD migrada (sin estado compartido)."""
    parts = Path(str(request.path)).parts
    if "unit" in parts or "postgres" in parts:
        yield
        return
    reset_database()
    yield


@pytest.fixture(scope="session", autouse=True)
def doubles():
    """Dobles de servicios externos: correo, Microsoft Entra ID y Metri-K."""
    from app.main import app
    from app.modules.iam.presentation.routes.dependencies import get_oidc
    from app.modules.organization.presentation.routes.organization_routes import get_source
    from app.shared.mailer import get_mailer
    from tests.support import FAKE_OIDC, FakeMetrik, Outbox

    FakeMetrik.reset()
    app.dependency_overrides.update({get_mailer: Outbox, get_oidc: lambda: FAKE_OIDC, get_source: FakeMetrik})
    yield
    app.dependency_overrides.clear()


@pytest.fixture
def outbox():
    from tests.support import Outbox

    Outbox.sent.clear()
    return Outbox
