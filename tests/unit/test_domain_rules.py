"""Reglas de dominio puras: contraseñas, sesiones, auditoría, redirecciones, slugs y configuración segura."""
from datetime import UTC, datetime, timedelta

import pytest

from app.modules.iam.application.use_cases.authentication.microsoft_login import safe_next
from app.modules.iam.domain.entities.identity import IdentityProvider
from app.modules.iam.domain.services import session_service
from app.modules.iam.domain.services.audit_service import RequestMeta, event
from app.modules.iam.domain.services.password_policy import PasswordPolicy
from app.modules.news.domain.services.slug_service import slugify, unique_slug
from app.shared.config import load_settings
from app.shared.security import hash_token, new_token, sign, unsign

T0 = datetime(2026, 1, 1, tzinfo=UTC)
WINDOW = session_service.SessionWindow(idle=timedelta(minutes=60), absolute=timedelta(hours=12))


def test_password_policy():
    policy = PasswordPolicy(12, 128)
    assert policy.problems("Clave-Muy-Segura-2026") == []
    assert policy.problems("corta")
    assert policy.problems("x" * 129)
    assert policy.problems("aaaaaaaaaaaaaaa")                                 # repetitiva
    assert policy.problems("unisimon2026")                                    # común
    assert policy.problems("ana.perez-clave-2026", personal=("ana.perez", "Ana", "Pérez"))


def test_session_expiry_rules():
    issued = session_service.issue(1, IdentityProvider(code="password", name="p"), WINDOW, T0, "1.1.1.1", "ua")
    s = issued.session
    assert issued.token != s.token_hash and len(s.token_hash) == 64           # en BD solo el hash
    assert session_service.is_valid(s, T0 + timedelta(minutes=59))
    assert not session_service.is_valid(s, T0 + timedelta(minutes=61))       # inactividad
    assert not session_service.touch(s, WINDOW, T0 + timedelta(seconds=30))  # no escribe en cada request
    t = T0 + timedelta(hours=11, minutes=50)
    s.last_seen_at = t - timedelta(minutes=5)
    session_service.touch(s, WINDOW, t)
    assert s.idle_expires_at == s.expires_at                                  # nunca más allá de la absoluta
    assert not session_service.is_valid(s, T0 + timedelta(hours=12, seconds=1))
    old_hash = s.token_hash
    session_service.rotate(s, WINDOW, t)
    assert s.previous_token_hash == old_hash and s.token_hash != old_hash
    session_service.revoke(s, t, "logout")
    assert not session_service.is_valid(s, t)


def test_audit_never_stores_secrets():
    e = event("auth.login", "failure", RequestMeta(ip="1.2.3.4", user_agent="x" * 900), None, "user", 7,
              password="p", new_password="p", token="t", csrf_token="c", session_cookie="c", client_secret="s",
              code="oauth-code", reason="bad_password")
    assert e.context == {"reason": "bad_password"} and len(e.user_agent) == 500 and e.resource_id == "7"


def test_safe_next_blocks_open_redirect():
    assert safe_next("/noticias?x=1") == "/noticias?x=1"
    for bad in (None, "", "https://evil.com", "//evil.com", "/\\evil.com", "javascript:alert(1)"):
        assert safe_next(bad) == "/", bad


def test_signed_state_and_tokens():
    value = sign({"st": "abc"}, "k" * 40, timedelta(minutes=5), "oidc_state")
    assert unsign(value, "k" * 40, "oidc_state")["st"] == "abc"
    assert unsign(value, "otra-clave" * 4, "oidc_state") is None              # firma
    assert unsign(value, "k" * 40, "otro_proposito") is None                  # propósito
    assert unsign(value[:-2] + "xx", "k" * 40, "oidc_state") is None          # manipulado
    assert unsign(sign({}, "k" * 40, timedelta(seconds=-1), "oidc_state"), "k" * 40, "oidc_state") is None  # expirado
    assert new_token() != new_token() and len(hash_token("x")) == 64


def test_slugs():
    assert slugify("Investigación en Ingeniería: ¡Nuevo!") == "investigacion-en-ingenieria-nuevo"
    assert slugify("¿¿??") == "noticia"
    taken = {"a", "a-2"}
    assert unique_slug("A", lambda s: s in taken) == "a-3"


def test_insecure_production_config_is_refused(monkeypatch):
    monkeypatch.setenv("ENVIRONMENT", "production")
    for var in ("SECRET_KEY", "SMTP_HOST", "MAIL_BACKEND", "FRONTEND_URL", "COOKIE_SECURE"):
        monkeypatch.delenv(var, raising=False)
    with pytest.raises(RuntimeError, match="SECRET_KEY"):
        load_settings()
    monkeypatch.setenv("SECRET_KEY", "s" * 48)
    monkeypatch.setenv("SMTP_HOST", "smtp.office365.com")
    monkeypatch.setenv("FRONTEND_URL", "https://metrik.unisimon.edu.co")
    s = load_settings()
    assert s.cookie_secure and s.session_cookie_name == "__Host-session" and s.mail_backend == "smtp"
    monkeypatch.setenv("COOKIE_SECURE", "false")
    with pytest.raises(RuntimeError, match="COOKIE_SECURE"):
        load_settings()
