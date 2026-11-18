import os

import app.shared.config  # noqa: F401  (carga .env antes de leer DATABASE_URL)

from sqlalchemy import MetaData, create_engine, event
from sqlalchemy.orm import registry, sessionmaker

DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///news.db")  # se define en .env: postgresql+psycopg://user:pass@host/db

# Pool: por defecto SQLAlchemy abre 5 (+10) conexiones y FastAPI atiende hasta 40 peticiones a la vez en hilos;
# en la prueba de carga (k6) las peticiones hacían fila esperando conexión. Ajustable por entorno.
_pool = {} if DATABASE_URL.startswith("sqlite") else {
    "pool_size": int(os.getenv("DB_POOL_SIZE", "20")), "max_overflow": int(os.getenv("DB_MAX_OVERFLOW", "20")),
    "pool_pre_ping": True}
engine = create_engine(DATABASE_URL, **_pool)
SessionLocal = sessionmaker(engine, expire_on_commit=False)
metadata = MetaData()
mapper_registry = registry(metadata=metadata)

if DATABASE_URL.startswith("sqlite"):  # SQLite no aplica FKs por defecto; Postgres sí.
    @event.listens_for(engine, "connect")
    def _fk_on(conn, _):
        conn.execute("PRAGMA foreign_keys=ON")


def get_db():
    with SessionLocal() as session:
        yield session
