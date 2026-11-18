"""Autenticación: contraseña, bloqueo, rate limiting, sesiones/CSRF, recuperación, invitaciones y Entra ID.

Entra se simula con llaves RSA locales: se prueba la validación real (firma, iss, aud, exp, nonce, tid).
"""
import time

import pytest
from sqlalchemy import select, text

from app.modules.iam.application.dto.auth_dto import InviteUserDTO
from app.modules.iam.application.use_cases.authentication.invitations import (InviteUserUseCase,
                                                                              RequestEmailVerificationUseCase)
from app.modules.iam.domain.services.audit_service import RequestMeta
from app.modules.iam.infrastructure.repositories.sqlalchemy_iam_repositories import SqlAlchemyIamUnitOfWork
from app.modules.iam.presentation.cli import create_admin
from app.shared.config import settings
from app.shared.database import SessionLocal
from app.shared.exceptions import DomainError
from tests.support import (INVALID_LOGIN, OTHER_KEY, PASSWORD, Outbox, client, csrf, ensure_user, error_code, id_token,
                           link_token, login, make_user, ms_callback, ms_login, sql)


def invite(email: str) -> str:
    with SessionLocal() as s:
        _, mail = InviteUserUseCase(SqlAlchemyIamUnitOfWork(s), settings).execute(
            InviteUserDTO(email=email, first_name="Invi", last_name="Tado"), None, RequestMeta())
    return link_token(mail.body)


def test_password_login():
    c = client()
    make_user("ana@unisimon.edu.co")
    assert c.get("/api/auth/me").status_code == 401                                   # sin autenticación
    r1, r2 = login(c, "ana@unisimon.edu.co", "otra-cosa-larga"), login(c, "nadie@unisimon.edu.co")
    assert r1.status_code == r2.status_code == 401 and r1.json() == r2.json() == {"detail": INVALID_LOGIN}

    r = login(c, "ANA@unisimon.edu.co ")                                              # correo se normaliza
    assert r.status_code == 200 and r.json()["csrf_token"]
    cookie = r.headers["set-cookie"]
    assert "HttpOnly" in cookie and "SameSite=lax" in cookie
    assert c.get("/api/auth/me").json()["auth_methods"] == ["password"]
    stored = sql("SELECT password_hash FROM password_credentials pc JOIN users u ON u.id = pc.user_id "
                 "WHERE u.email = 'ana@unisimon.edu.co'").scalar()
    assert stored.startswith("$argon2id$") and PASSWORD not in stored

    make_user("inactiva@unisimon.edu.co", status="inactive")
    make_user("sinverificar@unisimon.edu.co", verified=False)
    make_user("invitada@unisimon.edu.co", status="invited")
    for email in ("inactiva@unisimon.edu.co", "sinverificar@unisimon.edu.co", "invitada@unisimon.edu.co"):
        assert login(client(), email).json() == {"detail": INVALID_LOGIN}


@pytest.mark.security
def test_lockout():
    c = client()
    make_user("bloq@unisimon.edu.co")
    for _ in range(settings.login_max_failures):
        assert login(c, "bloq@unisimon.edu.co", "incorrecta-larga").status_code == 401
    assert login(c, "bloq@unisimon.edu.co").status_code == 401                        # bloqueada aun con la correcta
    assert login(client(), "bloq@unisimon.edu.co").status_code == 401                 # también desde otra IP
    sql("UPDATE password_credentials SET locked_until = '2000-01-01' "
        "WHERE user_id = (SELECT id FROM users WHERE email = 'bloq@unisimon.edu.co')")
    assert login(c, "bloq@unisimon.edu.co").status_code == 200                        # bloqueo vencido


@pytest.mark.security
def test_rate_limit():
    ensure_user("ana@unisimon.edu.co")
    c = client()
    for i in range(settings.rate_limit_per_ip):
        login(c, f"x{i}@unisimon.edu.co")
    assert login(c, "ana@unisimon.edu.co").status_code == 429
    assert login(client(), "ana@unisimon.edu.co").status_code == 200                  # otra IP no se afecta


@pytest.mark.security
def test_csrf_logout_refresh():
    make_user("ses@unisimon.edu.co")
    c = client()
    r = login(c, "ses@unisimon.edu.co")
    assert c.post("/api/auth/logout").status_code == 403                               # sin CSRF
    assert c.post("/api/auth/logout", headers={"X-CSRF-Token": "falso" * 5}).status_code == 403
    old = c.cookies.get(settings.session_cookie_name)
    assert c.post("/api/auth/logout", headers=csrf(r)).json() == {"federated_logout_url": None}
    c.cookies.set(settings.session_cookie_name, old)
    assert c.get("/api/auth/me").status_code == 401                                   # sesión revocada

    c = client()
    r = login(c, "ses@unisimon.edu.co")
    assert c.post("/api/auth/refresh").status_code == 403
    old = c.cookies.get(settings.session_cookie_name)
    r2 = c.post("/api/auth/refresh", headers=csrf(r))
    assert r2.status_code == 200 and r2.json()["csrf_token"] != r.json()["csrf_token"]
    new = c.cookies.get(settings.session_cookie_name)
    assert c.get("/api/auth/me").status_code == 200 and new != old
    c.cookies.set(settings.session_cookie_name, old)
    assert c.get("/api/auth/me").status_code == 401                                   # token rotado ya no sirve
    assert c.post("/api/auth/refresh", headers=csrf(r)).status_code == 401           # reutilización detectada
    c.cookies.set(settings.session_cookie_name, new)
    assert c.get("/api/auth/me").status_code == 401                                   # => todas revocadas
    assert sql("SELECT count(*) FROM audit_logs WHERE event_type = 'auth.session.reuse_detected'").scalar() == 1


def test_password_recovery_and_change(outbox):
    make_user("rec@unisimon.edu.co")
    c = client()
    other = client()
    login(other, "rec@unisimon.edu.co")
    r1 = c.post("/api/auth/forgot-password", json={"email": "nadie@unisimon.edu.co"})
    r2 = c.post("/api/auth/forgot-password", json={"email": "rec@unisimon.edu.co"})
    assert r1.status_code == r2.status_code == 202 and r1.json() == r2.json()          # no revela si existe
    assert [t for t, _, _ in outbox.sent] == ["rec@unisimon.edu.co"]
    token = outbox.last_token("rec@unisimon.edu.co")

    assert c.post("/api/auth/reset-password", json={"token": token, "new_password": "corta"}).status_code == 422
    new = "Nueva-Clave-Segura-99"
    assert c.post("/api/auth/reset-password", json={"token": token, "new_password": new}).status_code == 200
    assert c.post("/api/auth/reset-password", json={"token": token, "new_password": new}).status_code == 422  # 1 uso
    assert other.get("/api/auth/me").status_code == 401                                # sesiones previas revocadas
    assert login(c, "rec@unisimon.edu.co", new).status_code == 200

    c.post("/api/auth/forgot-password", json={"email": "rec@unisimon.edu.co"})
    sql("UPDATE user_tokens SET expires_at = '2000-01-01' WHERE used_at IS NULL")
    expired = outbox.last_token("rec@unisimon.edu.co")
    assert c.post("/api/auth/reset-password", json={"token": expired, "new_password": new + "x"}).status_code == 422

    # cambio de contraseña: cierra las demás sesiones, no la actual
    s1, s2 = client(), client()
    r = login(s1, "rec@unisimon.edu.co", new)
    login(s2, "rec@unisimon.edu.co", new)
    body = {"current_password": "no-es-esta-clave", "new_password": "Otra-Clave-Segura-77"}
    assert s1.post("/api/auth/change-password", json=body, headers=csrf(r)).status_code == 422
    body["current_password"] = new
    assert s1.post("/api/auth/change-password", json=body, headers=csrf(r)).status_code == 200
    assert s1.get("/api/auth/me").status_code == 200 and s2.get("/api/auth/me").status_code == 401


def test_invitation_and_email_verification():
    c = client()
    assert c.post("/api/auth/register", json={"email": "libre@x.co", "password": PASSWORD}).status_code == 422
    token = invite("nuevo@unisimon.edu.co")
    assert login(c, "nuevo@unisimon.edu.co").status_code == 401                       # invitado aún no entra
    assert c.post("/api/auth/register", json={"token": "x" * 30, "password": PASSWORD}).status_code == 422
    assert c.post("/api/auth/register", json={"token": token, "password": "nuevo-unisimon-1"}).status_code == 422
    r = c.post("/api/auth/register", json={"token": token, "password": PASSWORD})      # el enlace sigue sirviendo
    assert r.status_code == 201 and r.json()["status"] == "active" and r.json()["email_verified"]
    assert c.post("/api/auth/register", json={"token": token, "password": PASSWORD}).status_code == 422
    assert login(c, "nuevo@unisimon.edu.co").status_code == 200

    with SessionLocal() as s:
        uow = SqlAlchemyIamUnitOfWork(s)
        mail = RequestEmailVerificationUseCase(uow, settings).execute(uow.users.by_email("nuevo@unisimon.edu.co"))
    vtoken = link_token(mail.body)
    assert c.get("/api/auth/me").json()["email_verified"] is False
    assert c.post("/api/auth/verify-email", json={"token": vtoken}).status_code == 200
    assert c.post("/api/auth/verify-email", json={"token": vtoken}).status_code == 422
    assert c.get("/api/auth/me").json()["email_verified"] is True


@pytest.mark.security
def test_microsoft_flow():
    c = client()
    q = ms_login(c, next="/noticias")
    assert q["code_challenge_method"] == ["S256"] and q["code_challenge"] and q["nonce"] and q["state"]
    assert q["scope"] == ["openid profile email"]
    nonce = q["nonce"][0]

    assert error_code(ms_callback(c, q, id_token(nonce), state="manipulado")) == "401"  # state alterado
    assert error_code(client(follow_redirects=False).get("/api/auth/microsoft/callback",
                                                         params={"code": "c", "state": "s"})) == "401"  # sin cookie
    q = ms_login(c)
    assert error_code(ms_callback(c, q, id_token(q["nonce"][0], oid="desconocido"))) == "403"  # no habilitada
    denied = client(follow_redirects=False).get("/api/auth/microsoft/callback", params={"error": "access_denied"})
    assert "error=microsoft" in denied.headers["location"]                            # usuario canceló en Microsoft

    # firma ajena, expirado, otra audiencia, nonce distinto, tenant no permitido, issuer falso
    for bad in (dict(key=OTHER_KEY), dict(exp=int(time.time()) - 3600), dict(aud="otra-app"),
                dict(nonce="otro"), dict(tid="tenant-ajeno"), dict(iss="https://evil/v2.0")):
        q = ms_login(c)
        assert error_code(ms_callback(c, q, id_token(q["nonce"][0], **bad))) == "401", bad

    # invitación aceptada con Microsoft => identidad (tid, oid) vinculada y sesión creada
    inv = invite("institucional@unisimon.edu.co")
    q = ms_login(c, invitation=inv, next="/panel")
    r = ms_callback(c, q, id_token(q["nonce"][0], oid="oid-inst"))
    assert r.headers["location"].endswith("/panel"), r.headers["location"]
    me = c.get("/api/auth/me").json()
    assert me["email"] == "institucional@unisimon.edu.co" and me["auth_methods"] == ["microsoft"]
    assert me["session"]["method"] == "microsoft"

    c2 = client()                                                                     # siguiente login: por oid
    q = ms_login(c2, next="//evil.com")
    r = ms_callback(c2, q, id_token(q["nonce"][0], oid="oid-inst", email="cambio@otro.com"))
    assert r.headers["location"] == f"{settings.frontend_url}/"                       # sin open redirect
    assert c2.get("/api/auth/me").json()["email"] == "institucional@unisimon.edu.co"  # identifica por oid, no correo
    rc = c2.post("/api/auth/refresh", headers={"X-CSRF-Token": c2.cookies.get(settings.csrf_cookie_name)})
    out = c2.post("/api/auth/logout", headers=csrf(rc)).json()
    assert out["federated_logout_url"].startswith("https://login.microsoftonline.com/tenant-unisimon/oauth2/v2.0/logout")


def test_identity_linking():
    make_user("local@unisimon.edu.co")
    c = client()
    assert client(follow_redirects=False).get("/api/auth/microsoft/login", params={"link": "true"}).headers[
        "location"].endswith("session_required")
    login(c, "local@unisimon.edu.co")
    q = ms_login(c, link="true")
    r = ms_callback(c, q, id_token(q["nonce"][0], oid="oid-local"))
    assert "error" not in r.headers["location"]
    assert c.get("/api/auth/me").json()["auth_methods"] == ["microsoft", "password"]

    make_user("otro@unisimon.edu.co")
    c3 = client()
    login(c3, "otro@unisimon.edu.co")
    q = ms_login(c3, link="true")
    assert error_code(ms_callback(c3, q, id_token(q["nonce"][0], oid="oid-local"))) == "409"  # ya vinculada


@pytest.mark.security
def test_audit_has_no_secrets(outbox):
    ensure_user("ana@unisimon.edu.co")
    c = client()
    login(c, "ana@unisimon.edu.co")
    login(c, "ana@unisimon.edu.co", "Clave-Equivocada-123")
    c.post("/api/auth/forgot-password", json={"email": "ana@unisimon.edu.co"})
    rows = [str(tuple(r)) for r in sql("SELECT * FROM audit_logs")]
    assert rows and any("auth.login" in r for r in rows)
    tokens = [link_token(b) for _, _, b in outbox.sent if "token=" in b]
    assert tokens and not any(secret in r for r in rows for secret in (PASSWORD, "Clave-Equivocada-123", *tokens))
    with SessionLocal() as s:
        hashes = list(s.scalars(select(text("token_hash")).select_from(text("auth_sessions"))))
        assert hashes and all(len(h) == 64 for h in hashes)
        assert c.cookies.get(settings.session_cookie_name) not in hashes             # la cookie no está en BD


def test_cli_create_admin():
    user_id = create_admin("root@unisimon.edu.co", "Root", "Admin", "Clave-Raiz-Segura-2026!")
    assert sql("""SELECT r.code FROM user_role_assignments a JOIN roles r ON r.id = a.role_id
                  WHERE a.user_id = :u AND a.scope_type_id IS NULL""", u=user_id).scalar() == "super_admin"
    with pytest.raises(DomainError):
        create_admin("root2@unisimon.edu.co", "Root", "Dos", "Clave-Raiz-Segura-2026!")  # solo un bootstrap
