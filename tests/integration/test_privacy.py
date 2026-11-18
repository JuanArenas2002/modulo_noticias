"""Consentimiento de punta a punta: aviso, decisiones, revocación, versiones de política, integración con la
analítica (el servidor descarta eventos sin autorización) y protección de la administración."""
import uuid
from datetime import UTC, datetime, timedelta

import pytest

from app.modules.analytics.infrastructure.repository import forget_public
from app.modules.privacy.infrastructure.repository import forget_cache
from app.modules.privacy.presentation import routes
from tests.support import client, make_user, session, sql, uid

CHROME = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0 Safari/537.36"
PREFS, CONSENT, REVOKE = "/api/privacy/preferences", "/api/privacy/consents", "/api/privacy/consents/revoke"
ADMIN = "/api/admin/privacy/policies"
ALL = {"functional": True, "analytics": True, "method": "accept_all"}
NONE = {"functional": False, "analytics": False, "method": "reject_optional"}


@pytest.fixture(scope="module")
def env():
    forget_cache()
    make_user("pv-admin@unisimon.edu.co", ("super_admin", None, None))
    make_user("pv-editor@unisimon.edu.co", ("editor", None, None))
    ad = session("pv-admin@unisimon.edu.co")
    cat = ad.post("/api/news/categories", json={"name": "Privacidad"}).json()["id"]
    nid = ad.post("/api/news", json={"title": "Noticia privada", "summary": "r", "content": "<p>c</p>",
                                     "category_id": cat}).json()["id"]
    for step in ("submit", "approve", "publish"):
        ad.post(f"/api/news/{nid}/{step}")
    forget_public()
    return {"ad": ad, "editor": session("pv-editor@unisimon.edu.co"), "news": nid}


def visitor():
    return client(headers={"user-agent": CHROME})


def read(c, nid) -> int:
    """Lo que hace el rastreador del portal: una vista. Devuelve cuántos eventos aceptó el servidor."""
    return c.post("/api/news/lecturas", json={"session_id": str(uuid.uuid4()),
                                              "events": [{"type": "view", "news_id": nid}]}).json()["accepted"]


def history(subject: str):
    return sql("SELECT method, status, categories FROM privacy_consents WHERE subject_id = :s ORDER BY id",
               s=subject).all()


def test_first_visit_has_no_decision_and_nothing_optional(env):
    c = visitor()
    p = c.get(PREFS).json()
    assert p["needs_decision"] is True and p["consent"] is None
    assert p["categories"] == {"functional": False, "analytics": False, "advertising": False}
    assert p["cookie_policy_version"] == 1
    assert "cris_consent" not in c.cookies                      # consultar no crea identificadores
    assert read(c, env["news"]) == 0                            # el silencio no es autorización


def test_policies_and_categories_are_public(env):
    c = visitor()
    kinds = {p["kind"]: p for p in c.get("/api/privacy/policies").json()}
    assert set(kinds) == {"privacy_policy", "cookie_policy", "privacy_notice"}
    assert kinds["cookie_policy"]["versions"][0]["version"] == 1
    assert c.get("/api/privacy/policies/privacy_notice/1").json()["title"] == "Aviso de privacidad"
    assert c.get("/api/privacy/policies/privacy_notice/99").status_code == 404
    cats = {k["code"]: k for k in c.get("/api/privacy/cookie-categories").json()}
    assert cats["necessary"]["is_required"] and not cats["analytics"]["is_required"]
    assert not cats["advertising"]["is_available"] and cats["advertising"]["technologies"] == []
    assert {t["name"] for t in cats["analytics"]["technologies"]} >= {"cris-news-session"}
    assert {"cris_consent", "cris_consent_set"} <= {t["name"] for t in cats["necessary"]["technologies"]}
    assert all({"name", "type", "duration", "provider", "purpose"} <= set(t) for t in cats["necessary"]["technologies"])
    # 0009: la tipografía la sirve el portal; no quedan terceros que reciban datos del visitante.
    assert not [t for c in cats.values() for t in c["technologies"] if t["type"] == "third_party"]


def test_accept_all_enables_analytics_and_persists(env):
    c = visitor()
    p = c.post(CONSENT, json=ALL).json()
    assert p["needs_decision"] is False and p["categories"] == {"functional": True, "analytics": True,
                                                               "advertising": False}
    subject = c.cookies["cris_consent"]
    assert uuid.UUID(subject)                                   # identificador aleatorio, no datos de identidad
    assert c.cookies["cris_consent_set"] == "1"                 # marca no secreta: "ya decidió" (aviso al instante)
    assert c.get(PREFS).json()["categories"]["analytics"] is True  # persiste entre páginas/visitas
    assert read(c, env["news"]) == 1


def test_reject_optional_blocks_analytics(env):
    c = visitor()
    p = c.post(CONSENT, json=NONE).json()
    assert p["needs_decision"] is False and not any(p["categories"].values())  # decidió: no se vuelve a preguntar
    assert read(c, env["news"]) == 0


def test_custom_choice_and_change_keeps_proof(env):
    c = visitor()
    c.post(CONSENT, json={"functional": True, "analytics": False, "method": "custom"})
    assert read(c, env["news"]) == 0
    c.post(CONSENT, json={"functional": False, "analytics": True, "method": "custom"})  # cambia de opinión
    assert read(c, env["news"]) == 1
    rows = history(c.cookies["cris_consent"])
    assert [(m, s) for m, s, _ in rows] == [("custom", "superseded"), ("custom", "active")]


def test_revoke_stops_analytics_immediately(env):
    c = visitor()
    c.post(CONSENT, json=ALL)
    assert read(c, env["news"]) == 1
    p = c.post(REVOKE).json()
    assert not any(p["categories"].values()) and p["needs_decision"] is False and p["consent"]["method"] == "revoke"
    assert read(c, env["news"]) == 0                            # aunque un cliente siga enviando eventos
    assert [s for _, s, _ in history(c.cookies["cris_consent"])] == ["superseded", "active"]


def test_tampered_or_foreign_cookie_is_not_trusted(env):
    c = visitor()
    c.cookies.set("cris_consent", "no-es-un-uuid")
    assert c.get(PREFS).json()["needs_decision"] is True and read(c, env["news"]) == 0
    other = visitor()
    other.cookies.set("cris_consent", str(uuid.uuid4()))       # id inventado: sin decisión registrada
    assert other.get(PREFS).json()["consent"] is None


@pytest.mark.parametrize("body", [
    {"functional": True, "analytics": True},                                          # sin método
    {"functional": True, "analytics": True, "method": "revoke"},                      # revocar tiene su endpoint
    {"functional": True, "analytics": True, "advertising": True, "method": "custom"},  # no disponible
    {"functional": "sí", "analytics": True, "method": "custom"},
])
def test_invalid_decisions_are_rejected(env, body):
    assert visitor().post(CONSENT, json=body).status_code == 422


def test_authenticated_user_decision_is_linked_to_account(env):
    ad = env["ad"]
    ad.post(CONSENT, json=NONE)
    user = sql("SELECT user_id FROM privacy_consents WHERE subject_id = :s AND status = 'active'",
               s=ad.cookies["cris_consent"]).scalar()
    assert user == uid("pv-admin@unisimon.edu.co")
    anon = visitor()
    anon.post(CONSENT, json=NONE)
    assert sql("SELECT user_id FROM privacy_consents WHERE subject_id = :s", s=anon.cookies["cris_consent"]
               ).scalar() is None


def test_admin_endpoints_are_protected(env):
    body = {"kind": "privacy_notice", "title": "Aviso v2", "summary": "s", "content": "<p>c</p>",
            "effective_at": (datetime.now(UTC) + timedelta(days=7)).isoformat()}
    assert visitor().post(ADMIN, json=body).status_code == 401
    assert env["editor"].post(ADMIN, json=body).status_code == 403
    assert env["editor"].get("/api/admin/privacy/consents/summary").status_code == 403
    assert env["editor"].patch("/api/admin/privacy/cookie-categories/analytics", json={"name": "X"}).status_code == 403


def test_policy_versions_scheduling_and_audit(env):
    ad = env["ad"]
    future = (datetime.now(UTC) + timedelta(days=7)).isoformat()
    p = ad.post(ADMIN, json={"kind": "privacy_notice", "title": "Aviso v2", "summary": "s",
                             "content": "<p>ok</p><script>x</script>", "effective_at": future}).json()
    assert p["version"] == 2 and "<script>" not in p["content"]
    assert visitor().get("/api/privacy/policies/privacy_notice/2").status_code == 404  # aún no vigente
    assert ad.patch(f"{ADMIN}/{p['id']}", json={"title": "Aviso v2 corregido"}).json()["title"] == "Aviso v2 corregido"
    v1 = next(x for x in ad.get(ADMIN).json() if x["kind"] == "privacy_notice" and x["version"] == 1)
    assert ad.patch(f"{ADMIN}/{v1['id']}", json={"title": "Reescribir la historia"}).status_code == 409
    assert sql("SELECT count(*) FROM audit_logs WHERE event_type LIKE 'privacy.policy.%'").scalar() >= 2
    cat = ad.patch("/api/admin/privacy/cookie-categories/functional",
                   json={"retention": "Hasta revocar", "technologies": [
                       {"name": "cris-lang", "type": "localStorage", "duration": "Hasta revocar",
                        "provider": "Propia", "purpose": "Idioma"}]}).json()
    assert cat["retention"] == "Hasta revocar"
    assert ad.get("/api/admin/privacy/consents/summary").json()["active_subjects"] >= 1


def test_substantial_policy_change_asks_again_and_pauses_analytics(env):
    ad, c = env["ad"], visitor()
    c.post(CONSENT, json=ALL)
    assert read(c, env["news"]) == 1
    now = (datetime.now(UTC) - timedelta(seconds=1)).isoformat()
    ad.post(ADMIN, json={"kind": "cookie_policy", "title": "Cookies v2", "summary": "s", "content": "<p>c</p>",
                         "effective_at": now, "requires_reconsent": False})       # cambio menor
    assert c.get(PREFS).json()["needs_decision"] is False
    ad.post(ADMIN, json={"kind": "cookie_policy", "title": "Cookies v3", "summary": "s", "content": "<p>c</p>",
                         "effective_at": now, "requires_reconsent": True})        # cambio sustancial
    p = c.get(PREFS).json()
    assert p["needs_decision"] is True and p["cookie_policy_version"] == 3
    assert p["categories"]["analytics"] is False and read(c, env["news"]) == 0  # el silencio no vale
    assert p["consent"]["policy_version"] == 1                                 # se ve la decisión anterior
    c.post(CONSENT, json=ALL)
    assert c.get(PREFS).json()["consent"]["policy_version"] == 3 and read(c, env["news"]) == 1


def test_expired_decision_asks_again(env):
    c = visitor()
    c.post(CONSENT, json=ALL)
    sql("UPDATE privacy_consents SET expires_at = :e WHERE subject_id = :s",
        e=datetime.now(UTC) - timedelta(days=1), s=c.cookies["cris_consent"])
    assert c.get(PREFS).json()["needs_decision"] is True and read(c, env["news"]) == 0


def test_decisions_are_rate_limited(env, monkeypatch):
    monkeypatch.setattr(routes, "limiter", routes.Limiter(2))
    c = visitor()
    assert [c.post(CONSENT, json=NONE).status_code for _ in range(3)] == [200, 200, 429]
