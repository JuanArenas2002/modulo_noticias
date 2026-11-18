"""Seguridad transversal: CSRF y autenticación en TODAS las rutas, acceso horizontal/vertical, manipulación
de identificadores, protección de cuentas privilegiadas, anti-bloqueo, expiración de sesiones, reutilización
de tokens, fijación de sesión y rate limiting de los flujos públicos.
"""
import re
from dataclasses import replace
from datetime import timedelta

import pytest
from fastapi.testclient import TestClient

from app.main import app
from app.modules.iam.application.use_cases.authentication.common import issue_token
from app.modules.iam.application.use_cases.authentication.microsoft_login import (MicrosoftCallbackUseCase,
                                                                                  StartMicrosoftLoginUseCase)
from app.modules.iam.domain.services.audit_service import RequestMeta
from app.modules.iam.infrastructure.repositories.sqlalchemy_iam_repositories import SqlAlchemyIamUnitOfWork
from app.shared.clock import now
from app.shared.config import settings
from app.shared.database import SessionLocal
from app.shared.exceptions import ForbiddenError
from tests.support import (FAKE_OIDC, TOKENS, assign, client, error_code, id_token, login, make_user, ms_callback,
                           ms_login, seed_org, session, sql, uid)

MUTATING = {"post", "put", "patch", "delete"}
# Únicas rutas mutables sin sesión, por diseño (no hay sesión todavía).
PUBLIC_MUTATING = {("post", "/api/auth/login"), ("post", "/api/auth/register"), ("post", "/api/auth/verify-email"),
                   ("post", "/api/auth/forgot-password"), ("post", "/api/auth/reset-password"),
                   ("post", "/api/news/lecturas"),
                   # consentimiento: cada navegador decide sin cuenta (cookie propia, límite por IP)
                   ("post", "/api/privacy/consents"), ("post", "/api/privacy/consents/revoke")}  # analítica: sin sesión; valida y limita por su cuenta
# Lecturas públicas por diseño (portal y flujo OAuth).
PUBLIC_GET = {"/api/auth/providers", "/api/media/news/{name}", "/api/news", "/api/news/featured", "/api/news/{ref}", "/api/news/catalogs",
              "/api/organization/faculties", "/api/organization/centers", "/api/organization/programs",
              "/api/organization/faculties/{faculty_id}/programs", "/api/auth/microsoft/login",
              "/api/auth/microsoft/callback", "/api/privacy/policies", "/api/privacy/policies/{kind}/{version}",
              "/api/privacy/cookie-categories", "/api/privacy/preferences"}


def routes() -> list[tuple[str, str]]:
    return sorted((method, path) for path, ops in app.openapi()["paths"].items() for method in ops)


def concrete(path: str) -> str:
    return re.sub(r"\{[^}]+\}", "1", path)


@pytest.fixture(scope="module")
def owner():
    seed_org()
    make_user("owner@sec.co", ("super_admin", None, None))
    return session("owner@sec.co")


# ---------- protección de todas las rutas ----------
def test_every_mutating_route_requires_csrf(owner):
    no_csrf = session("owner@sec.co")
    del no_csrf.headers["X-CSRF-Token"]
    checked = 0
    for method, path in routes():
        if method in MUTATING and (method, path) not in PUBLIC_MUTATING:
            r = no_csrf.request(method.upper(), concrete(path), json={})
            assert r.status_code == 403 and r.json() == {"detail": "Token CSRF inválido"}, (method, path, r.text)
            checked += 1
    assert checked >= 30
    other = session("owner@sec.co")
    no_csrf.headers["X-CSRF-Token"] = other.headers["X-CSRF-Token"]           # CSRF de OTRA sesión
    assert no_csrf.post("/api/auth/logout").status_code == 403


def test_every_protected_route_requires_authentication():
    anon = client(follow_redirects=False)
    open_routes = set()
    for method, path in routes():
        if method == "get" and (path in PUBLIC_GET or path.startswith(("/openapi", "/docs", "/redoc"))):
            continue
        if (method, path) in PUBLIC_MUTATING:
            open_routes.add((method, path))
            continue
        r = anon.request(method.upper(), concrete(path), json={})
        assert r.status_code == 401, (method, path, r.status_code)
    assert open_routes == PUBLIC_MUTATING                                       # contrato: no aparecen públicas nuevas


# ---------- acceso horizontal y manipulación de identificadores ----------
def test_horizontal_access_between_users(owner):
    a_id, b_id = make_user("a@sec.co"), make_user("b@sec.co")
    a, b = session("a@sec.co"), session("b@sec.co")
    b_session = b.get(f"/api/users/{b_id}/sessions").json()[0]["id"]
    assert a.get(f"/api/users/{a_id}").status_code == 200                       # a sí mismo, sí
    for method, path, body in (("GET", f"/api/users/{b_id}", None), ("PATCH", f"/api/users/{b_id}", {"first_name": "x"}),
                               ("GET", f"/api/users/{b_id}/sessions", None),
                               ("DELETE", f"/api/users/{b_id}/sessions/{b_session}", None),
                               ("GET", f"/api/users/{b_id}/roles", None), ("GET", f"/api/users/{b_id}/permissions", None),
                               ("GET", f"/api/users/{b_id}/activity", None),
                               ("POST", f"/api/users/{b_id}/deactivate", None)):
        assert a.request(method, path, json=body).status_code == 403, (method, path)
    assert b.get("/api/auth/me").status_code == 200                              # B no fue afectado


def test_identifier_manipulation(owner):
    a_id, b_id = make_user("ida@sec.co"), make_user("idb@sec.co", ("viewer", None, None))
    session("idb@sec.co")
    b_session = sql("SELECT max(id) FROM auth_sessions WHERE user_id = :u", u=b_id).scalar()
    b_assignment = sql("SELECT id FROM user_role_assignments WHERE user_id = :u", u=b_id).scalar()
    # IDs de B colgados de la ruta de A: no se resuelven (404), no se tocan
    assert owner.delete(f"/api/users/{a_id}/sessions/{b_session}").status_code == 404
    assert owner.delete(f"/api/users/{a_id}/roles/{b_assignment}").status_code == 404
    assert owner.delete(f"/api/users/{a_id}/identities/1").status_code == 404
    assert sql("SELECT revoked_at FROM auth_sessions WHERE id = :s", s=b_session).scalar() is None
    assert sql("SELECT revoked_at FROM user_role_assignments WHERE id = :a", a=b_assignment).scalar() is None


# ---------- acceso vertical ----------
def test_vertical_access_editor_cannot_reach_admin(owner):
    make_user("ed@sec.co", ("editor", None, None))
    ed = session("ed@sec.co")
    for method, path, body in (("GET", "/api/users", None), ("POST", "/api/users", {"email": "n@sec.co", "first_name": "a", "password": "Clave-Temporal-2026!",
                                                                                     "last_name": "b"}),
                               ("GET", "/api/roles", None), ("POST", "/api/roles", {"code": "nuevo", "name": "Nuevo"}),
                               ("GET", "/api/permissions", None), ("GET", "/api/audit", None),
                               ("POST", "/api/organization/sync", None),
                               ("POST", "/api/news/categories", {"name": "X"}),
                               ("POST", f"/api/users/{uid('ed@sec.co')}/roles", {"role": "admin"})):
        assert ed.request(method, path, json=body).status_code == 403, (method, path)


def test_privileged_accounts_are_protected_from_lower_admins(owner):
    second_owner = make_user("owner2@sec.co", ("super_admin", None, None))  # hay 2 dueños: no es anti-bloqueo
    make_user("admin@sec.co", ("admin", None, None))
    editor = make_user("editor.target@sec.co", ("editor", None, None))
    admin = session("admin@sec.co")
    msg = {"detail": "No puedes administrar a un usuario con permisos que tú no tienes"}
    for method, path, body in (("PATCH", f"/api/users/{second_owner}", {"first_name": "x"}),
                               ("POST", f"/api/users/{second_owner}/deactivate", None),
                               ("POST", f"/api/users/{second_owner}/block", None),
                               ("POST", f"/api/users/{second_owner}/unlock", None),
                               ("DELETE", f"/api/users/{second_owner}", None),
                               ("POST", f"/api/users/{second_owner}/identities/microsoft/link-request", None)):
        r = admin.request(method, path, json=body)
        assert r.status_code == 403 and r.json() == msg, (method, path, r.text)
    owner2_session = sql("SELECT max(id) FROM auth_sessions WHERE user_id = :u", u=second_owner).scalar()
    if owner2_session:
        assert admin.delete(f"/api/users/{second_owner}/sessions/{owner2_session}").status_code == 403
    assert admin.post(f"/api/users/{editor}/deactivate").status_code == 200     # a un editor sí lo administra
    assert owner.post(f"/api/users/{uid('admin@sec.co')}/block").status_code == 200  # el dueño administra al admin
    assert sql("SELECT count(*) FROM audit_logs WHERE event_type = 'iam.user.change' AND result = 'denied'").scalar() >= 6


def test_last_institutional_owner_cannot_be_removed():
    only = make_user("unico@sec.dueno", ("super_admin", None, None))
    others = sql("SELECT a.id, a.user_id FROM user_role_assignments a JOIN roles r ON r.id = a.role_id "
                     "WHERE r.code = 'super_admin' AND a.revoked_at IS NULL AND a.user_id != :u", u=only).all()
    for assignment_id, _ in others:  # deja a "only" como único dueño (se restaura al final)
        sql("UPDATE user_role_assignments SET revoked_at = CURRENT_TIMESTAMP, revoked_by = :u WHERE id = :a",
            u=only, a=assignment_id)
    s = session("unico@sec.dueno")
    own = s.get(f"/api/users/{only}/roles").json()[0]["id"]
    assert s.delete(f"/api/users/{only}/roles/{own}").status_code == 409        # revocarse el último
    assert s.delete(f"/api/users/{only}").status_code == 403                     # eliminarse
    assert s.post(f"/api/users/{only}/deactivate").status_code == 403            # desactivarse
    role = sql("SELECT id FROM roles WHERE code = 'super_admin'").scalar()
    assert s.patch(f"/api/roles/{role}", json={"is_active": False}).status_code == 409
    perm = sql("SELECT id FROM permissions WHERE code = 'permissions.manage'").scalar()
    assert s.patch(f"/api/permissions/{perm}", json={"is_active": False}).status_code == 409
    make_user("admin.global@sec.dueno", ("admin", None, None))
    assert session("admin.global@sec.dueno").delete(f"/api/users/{only}").status_code == 403  # ni otro admin
    assert s.get("/api/auth/me/permissions").json()["permissions"]               # sigue con todo
    for _, user_id in others:
        assign(user_id, "super_admin")


# ---------- sesiones y tokens ----------
def test_session_idle_and_absolute_expiry():
    user = make_user("expira@sec.co")
    c = session("expira@sec.co")
    sql("UPDATE auth_sessions SET idle_expires_at = '2000-01-01', last_seen_at = '2000-01-01' WHERE user_id = :u",
        u=user)
    assert c.get("/api/auth/me").status_code == 401                              # inactividad
    c = session("expira@sec.co")
    sql("UPDATE auth_sessions SET expires_at = '2000-01-01', idle_expires_at = '2000-01-01' "
        "WHERE user_id = :u AND revoked_at IS NULL", u=user)
    assert c.get("/api/auth/me").status_code == 401                              # absoluta
    assert c.post("/api/auth/refresh").status_code == 401                        # refresh no la revive


def test_session_fixation_and_cookie_flags():
    make_user("fija@sec.co")
    c = client()
    c.cookies.set(settings.session_cookie_name, "valor-impuesto-por-atacante")
    r = login(c, "fija@sec.co")
    issued = r.cookies.get(settings.session_cookie_name)
    assert issued and issued != "valor-impuesto-por-atacante"                   # siempre se emite un token nuevo
    cookies = r.headers.get_list("set-cookie")
    session_cookie = next(x for x in cookies if x.startswith(settings.session_cookie_name + "="))
    csrf_cookie = next(x for x in cookies if x.startswith(settings.csrf_cookie_name + "="))
    assert "HttpOnly" in session_cookie and "Path=/" in session_cookie and "SameSite=lax" in session_cookie
    assert "HttpOnly" not in csrf_cookie                                         # el frontend lo lee para el header
    attacker = client()
    attacker.cookies.set(settings.session_cookie_name, "valor-impuesto-por-atacante")
    assert attacker.get("/api/auth/me").status_code == 401


def test_oauth_callback_cannot_be_replayed_and_state_cookie_is_cleared():
    inv_user = make_user("replay@sec.co", password=None, status="invited", verified=False)
    with SessionLocal() as s:
        uow = SqlAlchemyIamUnitOfWork(s)
        raw = issue_token(uow, inv_user, "invitation", timedelta(hours=1), now())
        uow.commit()
    c = client(follow_redirects=False)
    q = ms_login(c, invitation=raw)
    r = ms_callback(c, q, id_token(q["nonce"][0], oid="oid-replay"))
    assert "error" not in r.headers["location"]
    assert any(x.startswith("oidc_flow=") and ("Max-Age=0" in x or 'oidc_flow=""' in x)
               for x in r.headers.get_list("set-cookie"))                       # estado de un solo uso en el cliente
    code = r.request.url.params["code"]                                         # el mismo code de Microsoft
    replay = client(follow_redirects=False).get("/api/auth/microsoft/callback",
                                                params={"code": code, "state": q["state"][0]})
    assert error_code(replay) == "401"                                          # sin la cookie de estado no hay login
    q = ms_login(c, invitation=raw)                                             # la invitación ya se consumió
    assert error_code(ms_callback(c, q, id_token(q["nonce"][0], oid="oid-replay-2"))) == "422"


def test_microsoft_auto_provision_never_links_by_email():
    cfg = replace(settings, microsoft_auto_provision=True)
    make_user("existente@unisimon.edu.co")

    def callback(oid, email):
        start = StartMicrosoftLoginUseCase(FAKE_OIDC, cfg).execute("/")
        state = re.search(r"state=([^&]+)", start.redirect_url).group(1)
        nonce = re.search(r"nonce=([^&]+)", start.redirect_url).group(1)
        TOKENS[f"auto-{oid}"] = id_token(nonce, oid=oid, email=email)
        with SessionLocal() as s:
            return MicrosoftCallbackUseCase(SqlAlchemyIamUnitOfWork(s), FAKE_OIDC, cfg).execute(
                f"auto-{oid}", state, start.state_cookie, None, RequestMeta())

    result = callback("oid-auto", "auto.nuevo@unisimon.edu.co")
    assert result.issued and result.user.status.code == "active" and result.user.account_type.code == "institutional"
    assert sql("SELECT count(*) FROM user_role_assignments WHERE user_id = :u", u=result.user.id).scalar() == 0
    with pytest.raises(ForbiddenError):                                         # mismo correo, otra identidad
        callback("oid-intruso", "existente@unisimon.edu.co")
    assert sql("SELECT count(*) FROM user_identities WHERE subject = 'oid-intruso'").scalar() == 0


def test_public_flows_are_rate_limited():
    c = client()
    for i in range(settings.rate_limit_per_ip):
        assert c.post("/api/auth/forgot-password", json={"email": f"p{i}@sec.co"}).status_code == 202
    assert c.post("/api/auth/forgot-password", json={"email": "p@sec.co"}).status_code == 429
    r = client()
    for _ in range(settings.rate_limit_per_ip):
        r.post("/api/auth/register", json={"token": "x" * 30, "password": "Clave-Larga-2026!"})
    assert r.post("/api/auth/register", json={"token": "x" * 30, "password": "Clave-Larga-2026!"}).status_code == 429
    v = client()
    for _ in range(settings.rate_limit_per_ip):
        v.post("/api/auth/verify-email", json={"token": "y" * 30})
    assert v.post("/api/auth/verify-email", json={"token": "y" * 30}).status_code == 429


def test_permission_removal_from_role_is_immediate(owner):
    user = make_user("inmediato@sec.co")
    assign(user, "reviewer", "faculty", 5)
    c = session("inmediato@sec.co")
    assert "news.approve" in c.get("/api/auth/me/permissions").json()["permissions"]
    role = sql("SELECT id FROM roles WHERE code = 'reviewer'").scalar()
    assert owner.put(f"/api/roles/{role}/permissions", json={"permissions": ["news.view", "news.review"]}).status_code == 200
    assert "news.approve" not in c.get("/api/auth/me/permissions").json()["permissions"]
    assert owner.put(f"/api/roles/{role}/permissions",
                     json={"permissions": ["news.view", "news.review", "news.approve"]}).status_code == 200


def test_audit_is_append_only_via_api(owner):
    for method in ("PUT", "PATCH", "DELETE"):
        assert owner.request(method, "/api/audit", json={}).status_code == 405
    assert not [p for p in app.openapi()["paths"] if p.startswith("/api/audit") and set(app.openapi()["paths"][p]) - {"get"}]
    assert TestClient(app).get("/api/audit").status_code == 401
