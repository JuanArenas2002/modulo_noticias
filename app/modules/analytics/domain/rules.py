"""Reglas de la analítica de noticias (puras: sin BD ni HTTP).

Definiciones (no son equivalentes):
- page_views: lecturas registradas = pares (noticia, sesión). Recargar la misma noticia en la misma pestaña
  NO suma otra vista.
- sessions: sesiones anónimas distintas (id aleatorio por pestaña, sessionStorage; muere al cerrarla).
- unique_visitors: ESTIMADO. HMAC(secreto, día|IP|navegador) truncado: cambia cada día, así que en un rango
  es la suma de únicos diarios. Ni la IP ni el navegador se guardan.
- tiempo activo: lo acredita el servidor por latido, con su propio reloj (el cliente no envía duraciones).
"""
import hashlib
import hmac
import re
from datetime import date, datetime, timedelta, timezone
from urllib.parse import urlsplit

# ponytail: Colombia no tiene horario de verano; usar zoneinfo si el portal se usa en otro huso.
BOGOTA = timezone(timedelta(hours=-5))

HEARTBEAT_SECONDS = 15          # el cliente late cada 15 s SOLO si hubo actividad y la pestaña está visible
MAX_ACTIVE_SECONDS = 2 * 3600   # tope por lectura
ENGAGED_SECONDS = 30            # lectura comprometida: al menos 30 s de actividad real
LIVE_WINDOW_SECONDS = 3 * HEARTBEAT_SECONDS  # "leyendo ahora": latió en los últimos 45 s
MIN_VIEWS_FOR_AVERAGES = 5      # rankings de promedios solo con base suficiente

CHANNELS = ("whatsapp", "facebook", "x", "linkedin", "email", "copy_link", "native", "other")
SOURCES = ("direct", "internal", "search", "social", "external")
DEVICES = ("desktop", "tablet", "mobile")

_BOT = re.compile(
    r"bot|crawl|spider|slurp|scrap|preview|fetch|monitor|headless|lighthouse|pingdom|curl|wget|python|httpclient"
    r"|java/|go-http|axios|node-fetch|okhttp|facebookexternalhit|whatsapp/|embedly|validator", re.I)
_SEARCH = {"google", "bing", "duckduckgo", "yahoo", "ecosia", "baidu", "yandex", "brave", "scholar"}
_SOCIAL = {"facebook", "fb", "instagram", "twitter", "x", "t", "linkedin", "lnkd", "whatsapp", "wa", "youtube",
           "tiktok", "reddit", "telegram", "threads", "bsky", "mastodon"}


def is_bot(user_agent: str | None) -> bool:
    return not user_agent or bool(_BOT.search(user_agent))


def device(ua: str) -> str:
    u = ua.lower()
    if "ipad" in u or "tablet" in u or ("android" in u and "mobile" not in u):
        return "tablet"
    return "mobile" if "mobi" in u or "iphone" in u or "android" in u else "desktop"


def browser(ua: str) -> str:
    for token, name in (("Edg", "Edge"), ("OPR/", "Opera"), ("SamsungBrowser", "Samsung"), ("Firefox", "Firefox"),
                        ("FxiOS", "Firefox"), ("CriOS", "Chrome"), ("Chrome", "Chrome"), ("Safari", "Safari")):
        if token in ua:
            return name
    return "Otro"


def os_name(ua: str) -> str:
    for token, name in (("Windows", "Windows"), ("Android", "Android"), ("iPhone", "iOS"), ("iPad", "iOS"),
                        ("Mac OS X", "macOS"), ("CrOS", "ChromeOS"), ("Linux", "Linux")):
        if token in ua:
            return name
    return "Otro"


def _host(url: str | None) -> str | None:
    try:
        host = urlsplit(url).hostname if url else None
    except ValueError:
        return None
    return host.removeprefix("www.") if host else None


def traffic_source(referrer: str | None, own_url: str) -> tuple[str, str | None]:
    """(fuente, dominio de referencia). Solo se guarda el dominio, nunca la ruta ni la consulta."""
    host = _host(referrer)
    if not host:
        return "direct", None
    if host == _host(own_url):
        return "internal", None
    labels = set(host.split(".")[:-1])  # sin el dominio de primer nivel: "t.co" -> {"t"}
    if labels & _SEARCH:
        return "search", host
    return ("social" if labels & _SOCIAL else "external"), host


def visitor_hash(secret: str, day: date, ip: str | None, user_agent: str) -> str:
    """Seudónimo diario e irreversible sin el secreto. 64 bits bastan para contar, no para identificar."""
    msg = f"{day.isoformat()}|{ip or ''}|{user_agent}".encode()
    return hmac.new(secret.encode(), msg, hashlib.sha256).hexdigest()[:16]


def local_day(at: datetime) -> date:
    return at.astimezone(BOGOTA).date()


def active_credit(last_seen: datetime, at: datetime, active_seconds: int) -> int:
    """Segundos a sumar por un latido: lo transcurrido según el SERVIDOR, máximo un intervalo.

    Mandar latidos más seguido no suma más (cuenta el reloj, no los latidos), y tras una pausa larga
    (pestaña oculta o sin actividad: el cliente no late) solo se acredita un intervalo.
    """
    elapsed = int((at - last_seen).total_seconds())
    return max(0, min(elapsed, HEARTBEAT_SECONDS, MAX_ACTIVE_SECONDS - active_seconds))
