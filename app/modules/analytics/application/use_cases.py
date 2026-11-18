"""Casos de uso de la analítica: registrar eventos (público, validado) y consultar estadísticas (IAM)."""
from dataclasses import dataclass, replace
from datetime import date, datetime, timedelta

from app.modules.analytics.domain.rules import (MIN_VIEWS_FOR_AVERAGES, active_credit, browser, device, is_bot,
                                                local_day, os_name, traffic_source, visitor_hash)
from app.modules.analytics.infrastructure.repository import AnalyticsRepository, Filters
from app.shared.clock import as_utc


@dataclass(frozen=True)
class Event:
    type: str                      # view | heartbeat | share
    news_id: int
    channel: str | None = None
    referrer: str | None = None
    from_news_id: int | None = None
    is_entry: bool = False


class RecordEventsUseCase:
    """El backend decide qué cuenta: bots fuera, solo noticias públicas, vistas y compartidos deduplicados
    por la BD y tiempo activo medido con el reloj del servidor. Lo que no es elegible se descarta sin error."""

    def __init__(self, repo: AnalyticsRepository, secret: str, own_url: str):
        self.repo, self.secret, self.own_url = repo, secret, own_url

    def execute(self, session_id: str, events: list[Event], ip: str | None, user_agent: str, at: datetime) -> int:
        if is_bot(user_agent):
            return 0
        public = self.repo.public_ids({e.news_id for e in events}, at)
        day = local_day(at)
        accepted = 0
        for e in events:
            if e.news_id not in public:
                continue
            if e.type == "view":
                source, host = traffic_source(e.referrer, self.own_url)
                self.repo.add_view(dict(
                    news_id=e.news_id, session_id=session_id, visitor_hash=visitor_hash(self.secret, day, ip, user_agent),
                    day=day, viewed_at=at, last_seen_at=at, active_seconds=0, source=source, referrer_host=host,
                    device=device(user_agent), browser=browser(user_agent), os=os_name(user_agent),
                    is_entry=e.is_entry and source != "internal",
                    from_news_id=e.from_news_id if e.from_news_id != e.news_id else None))
            elif e.type == "heartbeat":
                read = self.repo.read(e.news_id, session_id)
                if not read:  # latido sin vista registrada: no hay lectura a la que sumar
                    continue
                if seconds := active_credit(as_utc(read.last_seen_at), at, read.active_seconds):
                    self.repo.credit(e.news_id, session_id, read.last_seen_at, seconds, at)
            else:
                self.repo.add_share(dict(news_id=e.news_id, session_id=session_id, channel=e.channel, day=day, at=at))
            accepted += 1
        self.repo.commit()
        return accepted


# ---------- consultas ----------
def _ratio(a, b) -> float | None:
    return round(a / b, 4) if b else None


def derive(t: dict) -> dict:
    """Métricas calculadas a partir de los conteos (None si la base es cero: no se inventa un 0 %)."""
    return t | {
        "avg_active_per_view": _ratio(t["active_seconds"], t["page_views"]),
        "avg_active_per_session": _ratio(t["active_seconds"], t["sessions"]),
        "engaged_rate": _ratio(t["engaged"], t["page_views"]),
        "share_rate": _ratio(t["shares"], t["page_views"]),
        "avg_views_per_news": _ratio(t["page_views"], t["news_viewed"]),
    }


def auto_granularity(start: date, end: date) -> str:
    days = (end - start).days + 1
    return "day" if days <= 62 else "week" if days <= 366 else "month" if days <= 3 * 366 else "year"


def _bucket(d: date, granularity: str) -> date:
    return {"day": d, "week": d - timedelta(days=d.weekday()), "month": d.replace(day=1),
            "year": d.replace(month=1, day=1)}[granularity]


def timeline(daily: dict[date, dict], start: date, end: date, granularity: str) -> list[dict]:
    """Serie completa (días sin datos = 0), agrupada por día/semana/mes/año.
    Visitantes y sesiones agrupados son sumas de valores diarios (estimación, ver rules)."""
    fields = ("page_views", "unique_visitors", "sessions", "active_seconds", "shares")
    out: dict[date, dict] = {}
    d = start
    while d <= end:
        row = out.setdefault(_bucket(d, granularity), {"period": _bucket(d, granularity)} | dict.fromkeys(fields, 0))
        for k in fields:
            row[k] += daily.get(d, {}).get(k, 0)
        d += timedelta(days=1)
    return list(out.values())


def _top(rows: list[dict], key: str, desc: bool = True, keep=lambda r: True, n: int = 5) -> list[dict]:
    """ponytail: ordena en Python el ranking completo (una consulta en vez de cinco); son cientos de noticias,
    no millones. Paginar en SQL (endpoint /analytics/news) si llegan a ser decenas de miles."""
    rows = [r for r in rows if keep(r) and r[key] is not None]
    return sorted(rows, key=lambda r: (r[key], r["id"]), reverse=desc)[:n] if desc else         sorted(rows, key=lambda r: (r[key], -r["id"]))[:n]


def overview(repo: AnalyticsRepository, f: Filters, granularity: str | None = None) -> dict:
    granularity = granularity or auto_granularity(f.start, f.end)
    prev_start, prev_end = f.previous
    rows = repo.ranking(f, limit=None)[1] if f.news_id is None else []
    return {
        "period": {"start": f.start, "end": f.end, "previous_start": prev_start, "previous_end": prev_end,
                   "granularity": granularity},
        "totals": derive(repo.totals(f, f.start, f.end)),
        "previous": derive(repo.totals(f, prev_start, prev_end)),
        "timeline": timeline(repo.daily(f, f.start, f.end), f.start, f.end, granularity),
        # Misma agrupación del periodo anterior, para comparar en el gráfico principal (se alinea por posición).
        "previous_timeline": timeline(repo.daily(f, prev_start, prev_end), prev_start, prev_end, granularity),
        "sources": repo.breakdown(f, f.start, f.end, "source"),
        "devices": repo.breakdown(f, f.start, f.end, "device"),
        "browsers": repo.breakdown(f, f.start, f.end, "browser"),
        "os": repo.breakdown(f, f.start, f.end, "os"),
        "referrers": repo.breakdown(f, f.start, f.end, "referrer_host", limit=10),
        "channels": repo.channels(f, f.start, f.end),
        "read_distribution": repo.read_distribution(f, f.start, f.end),
        "navigation": repo.navigation(f, f.start, f.end),
        "top": {
            "views": _top(rows, "views", keep=lambda r: r["views"] > 0),
            "shares": _top(rows, "shares", keep=lambda r: r["shares"] > 0),
            "avg_active": _top(rows, "avg_active", keep=lambda r: r["views"] >= MIN_VIEWS_FOR_AVERAGES),
            "growth": _top(rows, "growth", keep=lambda r: r["growth"] > 0),
            "low": _top(rows, "views", desc=False),
        },
        "min_views_for_averages": MIN_VIEWS_FOR_AVERAGES,
    }


def news_detail(repo: AnalyticsRepository, f: Filters, granularity: str | None = None) -> dict:
    """Overview de una noticia + su posición frente a las demás del mismo periodo (si hay base suficiente)."""
    data = overview(repo, f, granularity)
    data.pop("top")
    _, rows = repo.ranking(f, limit=1)
    data["news"] = rows[0] if rows else None
    _, peers = repo.ranking(replace(f, news_id=None), min_views=1, limit=None)
    others = [p for p in peers if p["id"] != f.news_id]
    mine = data["news"]["views"] if data["news"] else 0
    data["comparison"] = None if len(others) < MIN_VIEWS_FOR_AVERAGES else {
        "peers": len(others),
        "peer_avg_views": round(sum(p["views"] for p in others) / len(others), 2),
        "peer_avg_active": _ratio(sum(p["active_seconds"] for p in others), sum(p["views"] for p in others)),
        "percentile": round(100 * sum(p["views"] < mine for p in others) / len(others)),
    }
    return data
