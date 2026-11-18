"""Utilidades compartidas por las pruebas: usuarios con roles por alcance, sesiones reales, dobles de
Entra ID / correo / Metri-K. Se importa después de que conftest.py fijó el entorno de prueba.
"""
import itertools
import time
from urllib.parse import parse_qs, urlparse

import jwt
from cryptography.hazmat.primitives.asymmetric import rsa
from fastapi.testclient import TestClient
from sqlalchemy import text

from app.main import app
from app.modules.iam.domain.entities.identity import PasswordCredential, User
from app.modules.iam.infrastructure.repositories.argon2_password_hasher import hasher
from app.modules.iam.infrastructure.repositories.entra_oidc_client import EntraOidcClient
from app.modules.iam.infrastructure.repositories.sqlalchemy_iam_repositories import SqlAlchemyIamUnitOfWork
from app.modules.organization.domain.entities.organization import AcademicProgram, Faculty, ResearchCenter
from app.shared.clock import now
from app.shared.config import settings
from app.shared.database import SessionLocal, engine

PASSWORD = "Clave-De-Prueba-2026!"
INVALID_LOGIN = "Correo o contraseña incorrectos"
_ips = itertools.count(1)


# ---------- BD ----------
def sql(q: str, **kw):
    with engine.begin() as conn:
        return conn.execute(text(q), kw)


def uid(email: str) -> int | None:
    return sql("SELECT id FROM users WHERE email = :e AND deleted_at IS NULL", e=email).scalar()


def make_user(email: str, *roles: tuple[str, str | None, int | None], password: str | None = PASSWORD,
              status: str = "active", verified: bool = True) -> int:
    """roles: (rol, tipo_de_alcance | None, id | None). None = institucional."""
    with SessionLocal() as s:
        uow = SqlAlchemyIamUnitOfWork(s)
        u = User(first_name="Prueba", last_name="Usuario", email=email, status=uow.users.status(status),
                 account_type=uow.users.account_type("institutional"), email_verified_at=now() if verified else None,
                 password=PasswordCredential(password_hash=hasher.hash(password)) if password else None)
        uow.users.add(u)
        uow.commit()
        user_id = u.id
    for role, scope_type, scope_id in roles:
        assign(user_id, role, scope_type, scope_id)
    return user_id


def ensure_user(email: str, *roles) -> int:
    return uid(email) or make_user(email, *roles)


def assign(user_id: int, role: str, scope_type: str | None = None, scope_id: int | None = None) -> int:
    sql("""INSERT INTO user_role_assignments (user_id, role_id, scope_type_id, scope_id)
           VALUES (:u, (SELECT id FROM roles WHERE code = :r),
                   (SELECT id FROM org_unit_types WHERE code = :t), :i)""", u=user_id, r=role, t=scope_type, i=scope_id)
    return sql("SELECT max(id) FROM user_role_assignments").scalar()


def seed_org() -> None:
    """Dependencias mínimas (como si vinieran de Metri-K): facultades 3 y 5 (con programa 8); centros 2 y 4."""
    if sql("SELECT count(*) FROM faculties WHERE id = 5").scalar():
        return
    for fid, name in ((5, "Ingenierías"), (3, "Salud")):
        sql("INSERT INTO faculties (id, name, is_active, synced_at) VALUES (:i, :n, TRUE, CURRENT_TIMESTAMP)",
            i=fid, n=name)
    sql("INSERT INTO academic_programs (id, name, faculty_id, is_active, synced_at) "
        "VALUES (8, 'Diseño Industrial', 5, TRUE, CURRENT_TIMESTAMP)")
    for cid in (2, 4):
        sql("INSERT INTO research_centers (id, name, is_active, synced_at) VALUES (:i, :n, TRUE, CURRENT_TIMESTAMP)",
            i=cid, n=f"Centro {cid}")


# ---------- clientes HTTP ----------
def client(**kw) -> TestClient:
    """Cliente con IP propia: el rate limiting de una prueba no afecta a otra."""
    n = next(_ips)
    return TestClient(app, client=(f"10.{n // 250}.{n % 250}.1", 50000), **kw)


def login(c: TestClient, email: str, password: str = PASSWORD):
    return c.post("/api/auth/login", json={"email": email, "password": password})


def csrf(r) -> dict:
    return {"X-CSRF-Token": r.json()["csrf_token"]}


def session(email: str, password: str = PASSWORD, **kw) -> TestClient:
    """Cliente con sesión iniciada y header CSRF puesto (como haría el frontend)."""
    c = client(**kw)
    r = login(c, email, password)
    assert r.status_code == 200, r.text
    c.headers["X-CSRF-Token"] = r.json()["csrf_token"]
    return c


def link_token(body: str) -> str:
    return body.split("token=")[1].split()[0]


# ---------- correo ----------
class Outbox:
    sent: list[tuple[str, str, str]] = []

    def send(self, to, subject, body):
        Outbox.sent.append((to, subject, body))

    @classmethod
    def last_token(cls, to: str) -> str:
        return link_token(next(b for t, _, b in reversed(cls.sent) if t == to))


# ---------- Microsoft Entra ID simulado (validación real con llaves RSA locales) ----------
KEY = rsa.generate_private_key(public_exponent=65537, key_size=2048)
OTHER_KEY = rsa.generate_private_key(public_exponent=65537, key_size=2048)
TOKENS: dict[str, str] = {}  # code -> id_token que "devuelve" Entra


class _Jwks:
    def get_signing_key_from_jwt(self, _token):
        return type("K", (), {"key": KEY.public_key()})()


def id_token(nonce_value: str, oid="oid-1", tid="tenant-unisimon", key=KEY, **over) -> str:
    t = int(time.time())
    claims = {"iss": f"https://login.microsoftonline.com/{tid}/v2.0", "aud": "test-client-id", "sub": "pairwise",
              "oid": oid, "tid": tid, "nonce": nonce_value, "iat": t, "nbf": t, "exp": t + 600,
              "email": f"{oid}@unisimon.edu.co", "given_name": "Inst", "family_name": "User"} | over
    return jwt.encode(claims, key, algorithm="RS256", headers={"kid": "k1"})


FAKE_OIDC = EntraOidcClient(settings, http_post=lambda _url, data: {"id_token": TOKENS[data["code"]]}
                            if data["code"] in TOKENS else {"error": "invalid_grant"}, jwks_client=_Jwks())


def ms_login(c: TestClient, **params) -> dict:
    r = c.get("/api/auth/microsoft/login", params=params, follow_redirects=False)
    assert r.status_code == 302, r.text
    return parse_qs(urlparse(r.headers["location"]).query)


def ms_callback(c: TestClient, q: dict, token: str, state: str | None = None):
    code = f"code-{next(_ips)}"
    TOKENS[code] = token
    return c.get("/api/auth/microsoft/callback", params={"code": code, "state": state or q["state"][0]},
                 follow_redirects=False)


def error_code(r) -> str | None:
    return parse_qs(urlparse(r.headers["location"]).query).get("code", [None])[0]


# ---------- Metri-K simulado ----------
class FakeMetrik:
    """Misma forma que MetrikOrganizationSource, sin red."""
    centers_data: list[ResearchCenter] = []

    def faculties(self):
        return [Faculty(id=5, name="Facultad de Ingenierías")]

    def centers(self):
        return list(FakeMetrik.centers_data)

    def programs(self, faculty_id):
        return [AcademicProgram(id=8, name="DISEÑO INDUSTRIAL", faculty_id=faculty_id)]

    @classmethod
    def reset(cls):
        cls.centers_data = [ResearchCenter(id=2, code="CI-2", name="CICV"),
                            ResearchCenter(id=4, code="CI-4", name="AudacIA")]
