"""Persistencia y consultas de la analítica. SQL portable (PostgreSQL y SQLite de pruebas).

Las agregaciones se hacen en la BD sobre el rango pedido (índices por día); nunca se baja el detalle al cliente.
"""
from time import monotonic
from dataclasses import dataclass
from datetime import UTC, date, datetime, time, timedelta

from sqlalchemy import and_, case, delete, distinct, exists, false, func, select, tuple_, update
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.dialects.sqlite import insert as sqlite_insert
from sqlalchemy.orm import Session

from app.modules.analytics.domain.rules import BOGOTA, ENGAGED_SECONDS, local_day
from app.modules.analytics.infrastructure.tables import news_analytics_shares as S
from app.modules.analytics.infrastructure.tables import news_analytics_views as V
from app.modules.iam.domain.services.authorization_service import Scope
from app.modules.news.domain.entities.news import News
from app.modules.news.infrastructure.models.tables import news as N
from app.modules.news.infrastructure.models.tables import news_scopes as NS
from app.modules.news.infrastructure.repositories.sqlalchemy_news_repository import visible_at

_public: tuple[float, frozenset[int]] | None = None


def forget_public() -> None:
    global _public
    _public = None

# Distribución del tiempo activo por lectura: (etiqueta, desde, hasta) en segundos.
READ_BUCKETS = (("0–10 s", 0, 10), ("10–30 s", 10, 30), ("30 s–1 min", 30, 60), ("1–3 min", 60, 180),
                ("3–5 min", 180, 300), ("Más de 5 min", 300, None))
SORTS = ("views", "visitors", "shares", "avg_active", "engaged_rate", "growth", "published_at", "title")


@dataclass(frozen=True)
class Filters:
    start: date
    end: date
    news_id: int | None = None
    category_id: int | None = None
    scope: Scope | None = None           # (scope_type_id, scope_id): noticias de esa dependencia
    device: str | None = None            # solo vistas/lecturas (y compartidos de esas lecturas)
    channel: str | None = None           # solo compartidos
    allowed: frozenset[Scope] | None = None  # alcance del usuario; None = institucional (todo)

    @property
    def previous(self) -> tuple[date, date]:
        """Periodo anterior de igual duración, inmediatamente antes."""
        days = (self.end - self.start).days + 1
        return self.start - timedelta(days=days), self.start - timedelta(days=1)


def utc_bounds(start: date, end: date) -> tuple[datetime, datetime]:
    """Días locales -> [inicio, fin) en UTC (en SQLite las fechas se guardan como UTC sin zona)."""
    to_utc = lambda d: datetime.combine(d, time(), BOGOTA).astimezone(UTC)  # noqa: E731
    return to_utc(start), to_utc(end + timedelta(days=1))


def _news_conds(f: Filters) -> list:
    conds = []
    if f.news_id:
        conds.append(N.c.id == f.news_id)
    if f.category_id:
        conds.append(N.c.category_id == f.category_id)
    if f.scope:
        conds.append(exists().where(NS.c.news_id == N.c.id, NS.c.scope_type_id == f.scope[0],
                                    NS.c.scope_id == f.scope[1]))
    if f.allowed is not None:  # misma regla que el listado interno: alguna dependencia autorizada
        conds.append(exists().where(NS.c.news_id == N.c.id,
                                    tuple_(NS.c.scope_type_id, NS.c.scope_id).in_(sorted(f.allowed)))
                     if f.allowed else false())
    return conds


def _in_news(col, f: Filters) -> list:
    conds = _news_conds(f)
    return [col.in_(select(N.c.id).where(*conds))] if conds else []


def _views(f: Filters, start: date, end: date) -> list:
    return [V.c.day.between(start, end), *([V.c.device == f.device] if f.device else []), *_in_news(V.c.news_id, f)]


def _shares(f: Filters, start: date, end: date) -> list:
    conds = [S.c.day.between(start, end), *([S.c.channel == f.channel] if f.channel else []),
             *_in_news(S.c.news_id, f)]
    if f.device:  # el dispositivo de un compartido es el de la lectura de la que salió
        conds.append(exists().where(V.c.news_id == S.c.news_id, V.c.session_id == S.c.session_id,
                                    V.c.device == f.device))
    return conds


def _insert(db: Session, table):
    return (pg_insert if db.get_bind().dialect.name == "postgresql" else sqlite_insert)(table)


class AnalyticsRepository:
    def __init__(self, db: Session):
        self.db = db

    # ---------- captura ----------
    def public_ids(self, ids: set[int], at: datetime) -> set[int]:
        """Solo noticias publicadas y vigentes reciben eventos.
        ponytail: caché por proceso de 30 s de TODAS las públicas (son cientos): ahorra una consulta por latido.
        Una noticia recién publicada o archivada tarda hasta 30 s en (dejar de) contar."""
        global _public
        if not _public or _public[0] < monotonic():
            _public = (monotonic() + 30, frozenset(self.db.scalars(select(News.id).where(visible_at(at)))))
        return ids & _public[1]

    def add_view(self, row: dict) -> None:
        self.db.execute(_insert(self.db, V).values(**row).on_conflict_do_nothing(
            index_elements=["news_id", "session_id"]))

    def add_share(self, row: dict) -> None:
        self.db.execute(_insert(self.db, S).values(**row).on_conflict_do_nothing(
            index_elements=["news_id", "session_id", "channel"]))

    def read(self, news_id: int, session_id: str):
        return self.db.execute(select(V.c.active_seconds, V.c.last_seen_at).where(
            V.c.news_id == news_id, V.c.session_id == session_id)).first()

    def credit(self, news_id: int, session_id: str, seen_before, seconds: int, at: datetime) -> None:
        """Condicionado al last_seen_at leído: dos latidos simultáneos no acreditan dos veces."""
        self.db.execute(update(V).where(V.c.news_id == news_id, V.c.session_id == session_id,
                                         V.c.last_seen_at == seen_before)
                        .values(active_seconds=V.c.active_seconds + seconds, last_seen_at=at))

    def commit(self) -> None:
        self.db.commit()

    def purge(self, before: date) -> tuple[int, int]:
        views = self.db.execute(delete(V).where(V.c.day < before)).rowcount
        shares = self.db.execute(delete(S).where(S.c.day < before)).rowcount
        self.db.commit()
        return views, shares

    # ---------- consultas ----------
    def live(self, f: Filters, at: datetime, window_seconds: int) -> dict:
        """Lectores activos ahora (latido en la ventana) y vistas de la última media hora. Solo lee el día de
        hoy y el de ayer (índice por día): barato para consultarlo cada pocos segundos."""
        base = [V.c.day >= local_day(at) - timedelta(days=1), *([V.c.device == f.device] if f.device else []),
                *_in_news(V.c.news_id, f)]
        active = and_(*base, V.c.last_seen_at >= at - timedelta(seconds=window_seconds))
        readers = func.count().label("readers")
        now_reading = self.db.execute(
            select(N.c.id, N.c.title, readers).select_from(V.join(N, N.c.id == V.c.news_id)).where(active)
            .group_by(N.c.id, N.c.title).order_by(readers.desc(), N.c.id).limit(5))
        return {
            "active_readers": self.db.scalar(select(func.count()).select_from(V).where(active)),
            "views_last_30_min": self.db.scalar(select(func.count()).select_from(V).where(
                *base, V.c.viewed_at >= at - timedelta(minutes=30))),
            "reading_now": [r._asdict() for r in now_reading],
        }

    def totals(self, f: Filters, start: date, end: date) -> dict:
        v = self.db.execute(select(
            func.count().label("page_views"),
            func.count(distinct(V.c.visitor_hash)).label("unique_visitors"),
            func.count(distinct(V.c.session_id)).label("sessions"),
            func.coalesce(func.sum(V.c.active_seconds), 0).label("active_seconds"),
            func.coalesce(func.sum(case((V.c.active_seconds >= ENGAGED_SECONDS, 1), else_=0)), 0).label("engaged"),
            func.count(distinct(V.c.news_id)).label("news_viewed"),
        ).where(*_views(f, start, end))).one()._asdict()
        v["shares"] = self.db.scalar(select(func.count()).select_from(S).where(*_shares(f, start, end)))
        lo, hi = utc_bounds(start, end)
        v["news_published"] = self.db.scalar(select(func.count()).select_from(N).where(
            N.c.published_at >= lo, N.c.published_at < hi, *_news_conds(f)))
        return v

    def daily(self, f: Filters, start: date, end: date) -> dict[date, dict]:
        rows = self.db.execute(select(
            V.c.day, func.count().label("page_views"), func.count(distinct(V.c.visitor_hash)).label("unique_visitors"),
            func.count(distinct(V.c.session_id)).label("sessions"),
            func.coalesce(func.sum(V.c.active_seconds), 0).label("active_seconds"),
        ).where(*_views(f, start, end)).group_by(V.c.day))
        out = {r.day: r._asdict() | {"shares": 0} for r in rows}
        for day, n in self.db.execute(select(S.c.day, func.count()).where(*_shares(f, start, end)).group_by(S.c.day)):
            out.setdefault(day, {"day": day, "page_views": 0, "unique_visitors": 0, "sessions": 0,
                                 "active_seconds": 0})["shares"] = n
        return out

    def breakdown(self, f: Filters, start: date, end: date, column: str, limit: int | None = None) -> list[dict]:
        col = V.c[column]
        q = (select(col.label("key"), func.count().label("page_views"))
             .where(*_views(f, start, end), col.is_not(None)).group_by(col).order_by(func.count().desc(), col))
        return [r._asdict() for r in self.db.execute(q.limit(limit) if limit else q)]

    def channels(self, f: Filters, start: date, end: date) -> list[dict]:
        q = (select(S.c.channel.label("key"), func.count().label("shares")).where(*_shares(f, start, end))
             .group_by(S.c.channel).order_by(func.count().desc(), S.c.channel))
        return [r._asdict() for r in self.db.execute(q)]

    def read_distribution(self, f: Filters, start: date, end: date) -> list[dict]:
        bucket = case(*((and_(V.c.active_seconds >= lo, *([V.c.active_seconds < hi] if hi else [])), i)
                        for i, (_, lo, hi) in enumerate(READ_BUCKETS)))
        counts = dict(self.db.execute(select(bucket, func.count()).where(*_views(f, start, end)).group_by(bucket)).all())
        return [{"key": label, "page_views": counts.get(i, 0)} for i, (label, _, _) in enumerate(READ_BUCKETS)]

    def navigation(self, f: Filters, start: date, end: date) -> dict:
        r = self.db.execute(select(
            func.coalesce(func.sum(case((V.c.is_entry, 1), else_=0)), 0).label("entries"),
            func.coalesce(func.sum(case((V.c.from_news_id.is_not(None), 1), else_=0)), 0).label("from_other_news"),
        ).where(*_views(f, start, end))).one()
        return r._asdict()

    def ranking(self, f: Filters, sort: str = "views", desc: bool = True, limit: int | None = 20, offset: int = 0,
                min_views: int = 0) -> tuple[int, list[dict]]:
        """Noticias publicadas hasta el fin del rango, con sus métricas (incluye las que no tuvieron vistas)."""
        prev_start, prev_end = f.previous
        cur = V.c.day.between(f.start, f.end)
        v = (select(V.c.news_id,
                    func.sum(case((cur, 1), else_=0)).label("views"),
                    func.sum(case((V.c.day.between(prev_start, prev_end), 1), else_=0)).label("prev_views"),
                    func.count(distinct(case((cur, V.c.visitor_hash)))).label("visitors"),
                    func.sum(case((cur, V.c.active_seconds), else_=0)).label("active"),
                    func.sum(case((and_(cur, V.c.active_seconds >= ENGAGED_SECONDS), 1), else_=0)).label("engaged"))
             .where(V.c.day.between(prev_start, f.end), *([V.c.device == f.device] if f.device else []))
             .group_by(V.c.news_id).subquery())
        s = (select(S.c.news_id, func.count().label("shares")).where(*_shares(f, f.start, f.end))
             .group_by(S.c.news_id).subquery())
        views = func.coalesce(v.c.views, 0)
        prev = func.coalesce(v.c.prev_views, 0)
        active = func.coalesce(v.c.active, 0)
        cols = {
            "views": views, "visitors": func.coalesce(v.c.visitors, 0), "shares": func.coalesce(s.c.shares, 0),
            "avg_active": case((views > 0, active * 1.0 / views)), "engaged_rate":
                case((views > 0, func.coalesce(v.c.engaged, 0) * 1.0 / views)),
            "growth": views - prev, "published_at": N.c.published_at, "title": N.c.title,
        }
        _, hi = utc_bounds(f.start, f.end)
        q = (select(N.c.id, N.c.slug, N.c.category_id, prev.label("prev_views"), active.label("active_seconds"),
                    *(c.label(k) for k, c in cols.items()))
             .select_from(N.outerjoin(v, v.c.news_id == N.c.id).outerjoin(s, s.c.news_id == N.c.id))
             .where(N.c.published_at.is_not(None), N.c.published_at < hi, *_news_conds(f),
                    *([views >= min_views] if min_views else [])))
        key = cols[sort]
        q = q.order_by((key.desc() if desc else key.asc()).nulls_last(), N.c.id.desc())
        if limit is None:  # todas: el total es su longitud (sin segunda consulta)
            rows = [r._asdict() for r in self.db.execute(q)]
            return len(rows), rows
        total = self.db.scalar(select(func.count()).select_from(q.subquery()))
        return total, [r._asdict() for r in self.db.execute(q.limit(limit).offset(offset))]
