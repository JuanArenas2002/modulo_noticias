"""Entorno de Alembic. URL = DATABASE_URL (misma que la app); metadata = tablas de todos los módulos.

Uso programático (pruebas en PostgreSQL): pasar `config.attributes["connection"]` para migrar sobre esa conexión.
"""
from logging.config import fileConfig

from alembic import context

import app.modules.analytics.infrastructure.tables  # noqa: F401  (registra tablas en metadata)
import app.modules.iam.infrastructure.models.tables  # noqa: F401
import app.modules.news.infrastructure.models.tables  # noqa: F401
import app.modules.organization.infrastructure.models.tables  # noqa: F401
import app.modules.privacy.infrastructure.tables  # noqa: F401
from app.shared.database import engine, metadata

config = context.config
if config.config_file_name is not None and config.attributes.get("configure_logger", True):
    fileConfig(config.config_file_name)


def run_migrations_offline() -> None:
    context.configure(url=str(engine.url), target_metadata=metadata, literal_binds=True,
                      render_as_batch=engine.dialect.name == "sqlite")
    with context.begin_transaction():
        context.run_migrations()


def _run(connection) -> None:
    sqlite = connection.dialect.name == "sqlite"
    if sqlite:  # batch = recrear tablas; SQLite lo impide con FKs activas. Se verifica integridad al final.
        connection.exec_driver_sql("PRAGMA foreign_keys=OFF")
    context.configure(connection=connection, target_metadata=metadata,
                      render_as_batch=sqlite)  # SQLite no soporta ALTER completo
    with context.begin_transaction():
        context.run_migrations()
    if sqlite:
        if broken := connection.exec_driver_sql("PRAGMA foreign_key_check").fetchall():
            raise RuntimeError(f"La migración dejó claves foráneas rotas: {broken[:5]}")
        connection.commit()  # el PRAGMA abrió una transacción implícita (autobegin): hay que confirmarla
        connection.exec_driver_sql("PRAGMA foreign_keys=ON")


def run_migrations_online() -> None:
    if (connection := config.attributes.get("connection")) is not None:
        _run(connection)
        return
    with engine.connect() as connection:
        _run(connection)


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
