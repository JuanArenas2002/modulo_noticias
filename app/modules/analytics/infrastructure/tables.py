"""Tablas de la analítica de noticias. Sin datos personales: ni IP, ni nombres, ni correos, ni URL completas.

Dos tablas de hechos, no una por evento:
- news_analytics_views: UNA fila por lectura (noticia x sesión). El UNIQUE deduplica la vista y los latidos
  actualizan active_seconds de esa misma fila (no generan filas: ~240 por hora de lectura serían ruido).
- news_analytics_shares: una fila por clic en compartir (noticia x sesión x canal), deduplicada igual.
Sesiones = COUNT(DISTINCT session_id); no hace falta tabla propia.
ponytail: sin tabla de agregados diarios; con índices por (día) y (noticia, día) las consultas leen solo
el rango pedido. Añadir news_analytics_daily si views pasa de ~10 M de filas.
"""
from sqlalchemy import (BigInteger, Boolean, CheckConstraint, Column, Date, DateTime, ForeignKey, Index, Integer,
                        String, Table, UniqueConstraint)

from app.modules.analytics.domain.rules import CHANNELS, DEVICES, MAX_ACTIVE_SECONDS, SOURCES
from app.shared.database import metadata

Ts = DateTime(timezone=True)
BigId = BigInteger().with_variant(Integer, "sqlite")  # SQLite solo autoincrementa INTEGER


def Hex(n: int):
    """Ids hexadecimales/ASCII: intercalación binaria en PostgreSQL. COUNT(DISTINCT) es ~9x más rápido que con
    la del sistema (medido en tests/postgres) y el orden no importa para estos valores."""
    return String(n).with_variant(String(n, collation="C"), "postgresql")


def _in(column: str, values: tuple[str, ...]) -> str:
    return f"{column} IN ({', '.join(repr(v) for v in values)})"


news_analytics_views = Table(
    "news_analytics_views", metadata,
    Column("id", BigId, primary_key=True),
    Column("news_id", ForeignKey("news.id", ondelete="CASCADE"), nullable=False),
    Column("session_id", Hex(36), nullable=False),           # UUID aleatorio por pestaña
    Column("visitor_hash", Hex(16), nullable=False),         # seudónimo diario (ver rules.visitor_hash)
    Column("day", Date, nullable=False),                     # día local (Bogotá) de la vista
    Column("viewed_at", Ts, nullable=False),
    Column("last_seen_at", Ts, nullable=False),              # último latido acreditado (reloj del servidor)
    Column("active_seconds", Integer, nullable=False, default=0),
    Column("source", String(10), nullable=False),
    Column("referrer_host", String(255)),                    # solo el dominio
    Column("device", String(10), nullable=False),
    Column("browser", String(20), nullable=False),
    Column("os", String(20), nullable=False),
    Column("is_entry", Boolean, nullable=False),             # primera página de la visita al portal
    Column("from_news_id", Integer),                         # navegación interna: noticia anterior (sin FK: histórico)
    UniqueConstraint("news_id", "session_id", name="uq_news_analytics_views_read"),
    CheckConstraint(f"active_seconds BETWEEN 0 AND {MAX_ACTIVE_SECONDS}", name="ck_news_analytics_views_active"),
    CheckConstraint(_in("source", SOURCES), name="ck_news_analytics_views_source"),
    CheckConstraint(_in("device", DEVICES), name="ck_news_analytics_views_device"),
    Index("ix_news_analytics_views_day", "day"),
    Index("ix_news_analytics_views_news_day", "news_id", "day"),
)

news_analytics_shares = Table(
    "news_analytics_shares", metadata,
    Column("id", BigId, primary_key=True),
    Column("news_id", ForeignKey("news.id", ondelete="CASCADE"), nullable=False),
    Column("session_id", Hex(36), nullable=False),
    Column("channel", String(12), nullable=False),
    Column("day", Date, nullable=False),
    Column("at", Ts, nullable=False),
    UniqueConstraint("news_id", "session_id", "channel", name="uq_news_analytics_shares_click"),
    CheckConstraint(_in("channel", CHANNELS), name="ck_news_analytics_shares_channel"),
    Index("ix_news_analytics_shares_day", "day"),
    Index("ix_news_analytics_shares_news_day", "news_id", "day"),
)
