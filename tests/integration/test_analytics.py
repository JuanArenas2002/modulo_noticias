"""Analítica de noticias de punta a punta: captura pública validada y estadísticas protegidas por el IAM."""
import uuid
from datetime import UTC, date, datetime, timedelta

import pytest
from sqlalchemy import insert

from app.modules.analytics.domain.rules import local_day
from app.modules.analytics.infrastructure.repository import forget_public
from app.modules.analytics.infrastructure.tables import news_analytics_shares, news_analytics_views
from app.modules.analytics.presentation import routes
from app.modules.analytics.presentation.cli import purge
from app.shared.database import engine
from tests.support import client, make_user, seed_org, session, sql

CHROME = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0 Safari/537.36"
IPHONE = "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 Version/17.0 Mobile/15E148 Safari/604.1"
EVENTS = "/api/news/lecturas"
OVERVIEW = "/api/news/analytics/overview"


@pytest.fixture(scope="module")
def env():
    seed_org()
    make_user("an-admin@unisimon.edu.co", ("super_admin", None, None))
    make_user("an-editor@unisimon.edu.co", ("editor", None, None))                 # sin news.analytics
    make_user("an-centro@unisimon.edu.co", ("research_center", "research_center", 2))  # solo centro 2
    ad = session("an-admin@unisimon.edu.co")
    cat = ad.post("/api/news/categories", json={"name": "Analítica"}).json()["id"]

    def news(title: str, center: int, publish: bool = True) -> int:
        r = ad.post("/api/news", json={"title": title, "summary": "r", "content": "<p>c</p>", "category_id": cat,
                                       "scopes": [{"scope_type": "research_center", "scope_id": center}]})
        assert r.status_code == 201, r.text
        nid = r.json()["id"]
        for step in ("submit", "approve", "publish") if publish else ():
            assert ad.post(f"/api/news/{nid}/{step}").status_code == 200
        return nid

    ids = {"a": news("Noticia A", 2), "b": news("Noticia B", 4), "draft": news("Borrador", 2, publish=False)}
    forget_public()  # caché de noticias públicas de otra BD de prueba
    # publicadas antes de la historia sintética de 2025 (ver _seed)
    sql("UPDATE news SET published_at = :p WHERE id IN (:a, :b)", p=datetime(2025, 1, 1, tzinfo=UTC), a=ids["a"],
        b=ids["b"])
    return {"ad": ad, "cat": cat, "ids": ids, "editor": session("an-editor@unisimon.edu.co"),
            "center": session("an-centro@unisimon.edu.co")}


def reader(ua: str = CHROME, analytics: bool = True):
    """Navegador de un lector que ya decidió en el aviso de privacidad (por defecto: autoriza la analítica)."""
    c = client(headers={"user-agent": ua})
    assert c.post("/api/privacy/consents", json={"functional": False, "analytics": analytics,
                                                 "method": "custom"}).status_code == 200
    return c


def send(c, sid, *events):
    return c.post(EVENTS, json={"session_id": sid, "events": list(events)})


def views(nid: int) -> list:
    return sql("SELECT session_id, active_seconds, source, referrer_host, device, is_entry, from_news_id "
               "FROM news_analytics_views WHERE news_id = :n ORDER BY id", n=nid).all()


@pytest.fixture
def clock(monkeypatch):
    """Reloj controlado del endpoint de captura."""
    state = {"t": datetime.now(UTC)}
    monkeypatch.setattr(routes, "now", lambda: state["t"])
    return state


def test_view_is_registered_once_per_session(env):
    a, c, sid = env["ids"]["a"], reader(), str(uuid.uuid4())
    view = {"type": "view", "news_id": a, "referrer": "https://www.google.com/search?q=x", "is_entry": True}
    assert send(c, sid, view).json() == {"accepted": 1}
    send(c, sid, view)  # recarga en la misma pestaña: no es otra vista
    assert len(views(a)) == 1
    _, active, source, host, device, entry, _ = views(a)[0]
    assert (active, source, host, device, entry) == (0, "search", "google.com", "desktop", True)
    send(reader(IPHONE), str(uuid.uuid4()), {"type": "view", "news_id": a, "from_news_id": env["ids"]["b"],
                                              "referrer": "http://localhost:5173/noticias/b", "is_entry": True})
    last = views(a)[-1]
    assert (last.source, last.device, last.is_entry, last.from_news_id) == ("internal", "mobile", False, env["ids"]["b"])


def test_ineligible_events_are_discarded(env):
    ids, sid = env["ids"], str(uuid.uuid4())
    before = sql("SELECT count(*) FROM news_analytics_views").scalar()
    for c, nid in ((reader(), ids["draft"]), (reader(), 999999), (reader("Googlebot/2.1"), ids["a"]),
                   (reader(""), ids["a"])):
        assert send(c, sid, {"type": "view", "news_id": nid}).json() == {"accepted": 0}
    assert send(reader(), sid, {"type": "heartbeat", "news_id": ids["b"]}).json() == {"accepted": 0}  # sin vista
    assert sql("SELECT count(*) FROM news_analytics_views").scalar() == before


@pytest.mark.parametrize("body", [
    {"session_id": "no-uuid", "events": [{"type": "view", "news_id": 1}]},
    {"session_id": str(uuid.uuid4()), "events": []},
    {"session_id": str(uuid.uuid4()), "events": [{"type": "view", "news_id": 1}] * 21},
    {"session_id": str(uuid.uuid4()), "events": [{"type": "click", "news_id": 1}]},
    {"session_id": str(uuid.uuid4()), "events": [{"type": "view", "news_id": 0}]},
    {"session_id": str(uuid.uuid4()), "events": [{"type": "share", "news_id": 1}]},                      # sin canal
    {"session_id": str(uuid.uuid4()), "events": [{"type": "view", "news_id": 1, "channel": "x"}]},
    {"session_id": str(uuid.uuid4()), "events": [{"type": "share", "news_id": 1, "channel": "myspace"}]},
    {"session_id": str(uuid.uuid4()), "events": [{"type": "heartbeat", "news_id": 1, "seconds": 9999}]},  # duración: no
])
def test_malformed_events_are_rejected(env, body):
    assert reader().post(EVENTS, json=body).status_code == 422


def test_active_time_counts_only_server_measured_activity(env, clock):
    b, c, sid = env["ids"]["b"], reader(), str(uuid.uuid4())
    t0 = clock["t"]
    send(c, sid, {"type": "view", "news_id": b})
    hb = {"type": "heartbeat", "news_id": b}
    for s in (10, 11, 11, 26):          # +10, +1, +0 (mismo instante), +15
        clock["t"] = t0 + timedelta(seconds=s)
        send(c, sid, hb)
    clock["t"] = t0 + timedelta(seconds=26 + 900)  # 15 min en segundo plano/inactivo: el cliente no late
    send(c, sid, hb, hb, hb)                        # ráfaga: no suma más que el reloj
    row = next(v for v in views(b) if v.session_id == sid)
    assert row.active_seconds == 10 + 1 + 15 + 15


def test_shares_are_counted_once_per_channel_and_session(env):
    a, c, sid = env["ids"]["a"], reader(), str(uuid.uuid4())
    share = lambda ch: {"type": "share", "news_id": a, "channel": ch}  # noqa: E731
    assert send(c, sid, share("whatsapp"), share("whatsapp"), share("copy_link")).json() == {"accepted": 3}
    send(c, sid, share("linkedin"))
    assert sorted(sql("SELECT channel FROM news_analytics_shares WHERE session_id = :s", s=sid).scalars()) == \
        ["copy_link", "linkedin", "whatsapp"]


def test_unique_visitors_sessions_and_page_views_differ(env):
    ad, a, b = env["ad"], env["ids"]["a"], env["ids"]["b"]
    today = local_day(datetime.now(UTC)).isoformat()
    q = {"start_date": today, "end_date": today}
    before = ad.get(OVERVIEW, params=q).json()["totals"]
    c = reader()  # mismo navegador e IP: un visitante, dos sesiones (dos pestañas), tres vistas
    s1, s2 = str(uuid.uuid4()), str(uuid.uuid4())
    send(c, s1, {"type": "view", "news_id": a}, {"type": "view", "news_id": b})
    send(c, s2, {"type": "view", "news_id": a})
    t = ad.get(OVERVIEW, params=q).json()["totals"]
    delta = {k: t[k] - before[k] for k in ("page_views", "sessions", "unique_visitors")}
    assert delta == {"page_views": 3, "sessions": 2, "unique_visitors": 1}


def _seed(rows_views, rows_shares=()):
    """Historia sintética (días pasados) directo en la BD, para probar rangos y agregaciones."""
    base = {"visitor_hash": "h", "viewed_at": datetime.now(UTC), "last_seen_at": datetime.now(UTC), "source": "direct",
            "referrer_host": None, "device": "desktop", "browser": "Chrome", "os": "Windows", "is_entry": True,
            "from_news_id": None}
    with engine.begin() as conn:
        conn.execute(insert(news_analytics_views), [base | r for r in rows_views])
        if rows_shares:
            conn.execute(insert(news_analytics_shares), [{"at": datetime.now(UTC)} | r for r in rows_shares])


def test_date_filters_previous_period_timeline_and_consistency(env):
    ad, a, b = env["ad"], env["ids"]["a"], env["ids"]["b"]
    d = date(2025, 3, 10)  # semana del lunes 10 de marzo de 2025
    _seed([{"news_id": a, "session_id": f"s{i}", "visitor_hash": f"v{i % 7}"  # real: rota cada día
            , "day": d + timedelta(days=i % 7),
            "active_seconds": 40 if i % 2 else 5, "device": "mobile" if i < 4 else "desktop"} for i in range(10)]
          + [{"news_id": b, "session_id": "p1", "day": d - timedelta(days=3), "active_seconds": 0},   # periodo anterior
             {"news_id": b, "session_id": "out", "day": d + timedelta(days=30), "active_seconds": 0}],  # fuera
          [{"news_id": a, "session_id": "s1", "channel": "facebook", "day": d},
           {"news_id": a, "session_id": "s5", "channel": "email", "day": d + timedelta(days=1)}])
    q = {"start_date": d.isoformat(), "end_date": (d + timedelta(days=6)).isoformat()}
    o = ad.get(OVERVIEW, params=q).json()
    t = o["totals"]
    assert (t["page_views"], t["sessions"], t["unique_visitors"], t["shares"]) == (10, 10, 7, 2)
    assert (t["active_seconds"], t["engaged"], t["engaged_rate"], t["share_rate"]) == (5 * 40 + 5 * 5, 5, 0.5, 0.2)
    assert o["previous"]["page_views"] == 1 and o["period"]["previous_end"] == "2025-03-09"
    assert len(o["timeline"]) == 7 and sum(p["page_views"] for p in o["timeline"]) == t["page_views"]
    assert sum(p["page_views"] for p in o["previous_timeline"]) == o["previous"]["page_views"] == 1
    assert {r["key"]: r["shares"] for r in o["channels"]} == {"facebook": 1, "email": 1}
    assert sum(r["page_views"] for r in o["read_distribution"]) == 10
    assert o["top"]["views"][0]["id"] == a and o["top"]["views"][0]["views"] == 10

    week = ad.get(OVERVIEW, params=q | {"granularity": "week"}).json()["timeline"]
    assert week == [{"period": "2025-03-10", "page_views": 10, "unique_visitors": 7, "sessions": 10,
                     "active_seconds": 225, "shares": 2}]
    mobile = ad.get(OVERVIEW, params=q | {"device": "mobile"}).json()["totals"]
    assert (mobile["page_views"], mobile["shares"]) == (4, 1)  # el compartido de s5 vino de un desktop
    assert ad.get(OVERVIEW, params=q | {"channel": "email"}).json()["totals"]["shares"] == 1

    rank = ad.get("/api/news/analytics/news", params=q | {"sort": "growth"}).json()
    by_id = {r["id"]: r for r in rank["items"]}
    assert (by_id[a]["views"], by_id[a]["growth"], by_id[b]["views"], by_id[b]["growth"]) == (10, 10, 0, -1)
    assert sum(r["views"] for r in rank["items"]) == t["page_views"]
    page = ad.get("/api/news/analytics/news", params=q | {"page_size": 1, "page": 2}).json()
    assert page["total"] == rank["total"] and len(page["items"]) == 1

    detail = ad.get(f"/api/news/{a}/analytics", params=q).json()
    assert detail["news"]["views"] == 10 and detail["totals"]["page_views"] == 10 and detail["title"] == "Noticia A"
    assert detail["comparison"] is None  # menos de 5 noticias para comparar: no se inventa un percentil


@pytest.mark.parametrize("params", [{"start_date": "2025-02-01", "end_date": "2025-01-01"},
                                    {"start_date": "2015-01-01", "end_date": "2025-01-01"},
                                    {"device": "fridge"}, {"scope_type": "research_center"},
                                    {"scope_type": "planet", "scope_id": 1}, {"granularity": "hour"}])
def test_invalid_query_parameters(env, params):
    assert env["ad"].get(OVERVIEW, params=params).status_code == 422


def test_statistics_are_protected_and_scoped(env):
    ids = env["ids"]
    assert client().get(OVERVIEW).status_code == 401
    assert env["editor"].get(OVERVIEW).status_code == 403
    assert env["editor"].get(f"/api/news/{ids['a']}/analytics").status_code == 403
    center = env["center"]  # research_center con alcance en el centro 2: ve A, no B
    q = {"start_date": "2025-03-01", "end_date": "2025-03-31"}
    assert center.get(OVERVIEW, params=q).json()["totals"]["page_views"] == 10
    assert {r["id"] for r in center.get("/api/news/analytics/news", params=q).json()["items"]} == {ids["a"]}
    assert center.get(f"/api/news/{ids['a']}/analytics").status_code == 200
    assert center.get(f"/api/news/{ids['b']}/analytics").status_code == 403
    assert env["ad"].get("/api/news/999999/analytics").status_code == 404


def test_capture_is_rate_limited(env, monkeypatch):
    monkeypatch.setattr(routes, "limiter", routes._Limiter(3))
    c, sid, ev = reader(), str(uuid.uuid4()), {"type": "heartbeat", "news_id": env["ids"]["a"]}
    assert send(c, sid, ev, ev, ev).status_code == 202
    assert send(c, sid, ev).status_code == 429
    assert send(reader(), sid, ev).status_code == 202  # otra IP, otro cupo


def test_retention_purge(env):
    _seed([{"news_id": env["ids"]["a"], "session_id": "old", "day": date(2020, 1, 1), "active_seconds": 0}],
          [{"news_id": env["ids"]["a"], "session_id": "old", "channel": "x", "day": date(2020, 1, 1)}])
    assert purge(760) == (1, 1)
    assert sql("SELECT count(*) FROM news_analytics_views WHERE session_id = 'old'").scalar() == 0


def test_live_counts_only_recently_active_readers(env, clock):
    ad, a, LIVE = env["ad"], env["ids"]["a"], "/api/news/analytics/live"
    t0 = clock["t"] = datetime.now(UTC) + timedelta(hours=1)  # lejos de las lecturas de otras pruebas
    assert ad.get(LIVE).json()["active_readers"] == 0
    c, sid = reader(), str(uuid.uuid4())
    send(c, sid, {"type": "view", "news_id": a})
    live = ad.get(LIVE).json()
    assert (live["active_readers"], live["views_last_30_min"]) == (1, 1)
    assert live["reading_now"] == [{"id": a, "title": "Noticia A", "readers": 1}]
    clock["t"] = t0 + timedelta(seconds=40)
    send(c, sid, {"type": "heartbeat", "news_id": a})          # sigue leyendo
    clock["t"] = t0 + timedelta(seconds=80)
    assert ad.get(LIVE).json()["active_readers"] == 1           # latió hace 40 s
    clock["t"] = t0 + timedelta(seconds=90)                     # sin latidos 50 s: ya no está leyendo
    assert ad.get(LIVE).json()["active_readers"] == 0
    assert env["center"].get(LIVE, params={"news_id": env["ids"]["b"]}).json()["active_readers"] == 0
    assert env["editor"].get(LIVE).status_code == 403
