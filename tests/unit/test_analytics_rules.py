"""Reglas puras de la analítica: bots, dispositivo, procedencia, seudónimo diario y crédito de tiempo activo."""
from datetime import UTC, date, datetime, timedelta

from app.modules.analytics.domain.rules import (HEARTBEAT_SECONDS, MAX_ACTIVE_SECONDS, active_credit, browser, device,
                                                is_bot, local_day, os_name, traffic_source, visitor_hash)

CHROME = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0 Safari/537.36"
IPHONE = "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 Version/17.0 Mobile/15E148 Safari/604.1"
TAB = "Mozilla/5.0 (Linux; Android 13; SM-X200) AppleWebKit/537.36 Chrome/130.0 Safari/537.36"
OWN = "https://investigacion.unisimon.edu.co"


def test_bots_and_empty_user_agents_are_excluded():
    for ua in ("", None, "Googlebot/2.1 (+http://www.google.com/bot.html)", "facebookexternalhit/1.1",
               "WhatsApp/2.23.20.0", "curl/8.4.0", "python-requests/2.31", "Mozilla/5.0 HeadlessChrome/120.0"):
        assert is_bot(ua), ua
    assert not is_bot(CHROME) and not is_bot(IPHONE)


def test_device_browser_and_os_in_general_terms():
    assert (device(CHROME), browser(CHROME), os_name(CHROME)) == ("desktop", "Chrome", "Windows")
    assert (device(IPHONE), browser(IPHONE), os_name(IPHONE)) == ("mobile", "Safari", "iOS")
    assert (device(TAB), os_name(TAB)) == ("tablet", "Android")
    assert browser(CHROME.replace("Safari/537.36", "Safari/537.36 Edg/130.0")) == "Edge"


def test_traffic_source_keeps_only_the_domain():
    assert traffic_source(None, OWN) == ("direct", None)
    assert traffic_source("", OWN) == ("direct", None)
    assert traffic_source(f"{OWN}/noticias", OWN) == ("internal", None)
    assert traffic_source("https://www.google.com/search?q=secreto", OWN) == ("search", "google.com")
    assert traffic_source("https://scholar.google.es/", OWN) == ("search", "scholar.google.es")
    assert traffic_source("https://t.co/abc", OWN) == ("social", "t.co")
    assert traffic_source("https://l.facebook.com/l.php?u=x", OWN) == ("social", "l.facebook.com")
    assert traffic_source("https://www.eltiempo.com/ciencia/nota?id=1", OWN) == ("external", "eltiempo.com")
    assert traffic_source("not a url", OWN) == ("direct", None)


def test_visitor_hash_is_daily_and_needs_the_secret():
    d = date(2026, 11, 13)
    h = visitor_hash("s", d, "10.0.0.1", CHROME)
    assert len(h) == 16 and "10.0.0.1" not in h
    assert h == visitor_hash("s", d, "10.0.0.1", CHROME)                       # mismo día: mismo visitante
    assert h != visitor_hash("s", d + timedelta(days=1), "10.0.0.1", CHROME)   # rota cada día
    assert h != visitor_hash("otro", d, "10.0.0.1", CHROME)
    assert h != visitor_hash("s", d, "10.0.0.1", IPHONE)


def test_local_day_is_bogota():
    assert local_day(datetime(2026, 11, 13, 3, 0, tzinfo=UTC)) == date(2026, 11, 12)   # 22:00 en Bogotá
    assert local_day(datetime(2026, 11, 13, 5, 0, tzinfo=UTC)) == date(2026, 11, 13)


def test_active_credit_uses_server_clock_and_excludes_idle_time():
    t0 = datetime(2026, 11, 13, 12, tzinfo=UTC)
    at = lambda s: t0 + timedelta(seconds=s)  # noqa: E731
    assert active_credit(t0, at(10), 0) == 10                        # lo transcurrido
    assert active_credit(t0, at(15), 0) == HEARTBEAT_SECONDS
    assert active_credit(t0, at(600), 0) == HEARTBEAT_SECONDS        # 10 min sin latidos: solo un intervalo
    assert active_credit(t0, at(-5), 0) == 0                         # reloj hacia atrás: nada
    assert active_credit(t0, at(15), MAX_ACTIVE_SECONDS - 3) == 3     # tope por lectura
    assert active_credit(t0, at(15), MAX_ACTIVE_SECONDS) == 0
