"""Administración de usuarios, roles, permisos, asignaciones, sesiones, identidades y auditoría."""
import pytest
from fastapi.testclient import TestClient

from app.main import app
from tests.support import (PASSWORD, Outbox, assign, ensure_user, error_code, id_token, make_user, ms_callback,
                           ms_login, seed_org, session, sql, uid)


@pytest.fixture(scope="module")
def owner():
    """Único dueño de la plataforma (super_admin institucional) en la BD de este módulo."""
    seed_org()
    return make_user("owner@adm.co", ("super_admin", None, None)), session("owner@adm.co")


@pytest.fixture
def root(owner):
    return owner[1]


@pytest.fixture
def root_id(owner):
    return owner[0]


TEMP = "Clave-Temporal-2026!"


def login_status(email: str) -> int:
    return TestClient(app).post("/api/auth/login", json={"email": email, "password": PASSWORD}).status_code


@pytest.mark.security
def test_access_control(root, root_id):
    assert TestClient(app).get("/api/users").status_code == 401
    make_user("sinrol@adm.co")
    nobody = session("sinrol@adm.co")
    for path in ("/api/users", "/api/roles", "/api/permissions", "/api/audit"):
        assert nobody.get(path).status_code == 403, path
    assert nobody.get(f"/api/users/{uid('sinrol@adm.co')}").status_code == 200   # se ve a sí mismo
    assert nobody.post("/api/users", json={"email": "x@adm.co", "first_name": "x", "last_name": "y",
                                           "password": TEMP}).status_code == 403


def test_user_crud_and_listing(root, root_id):
    Outbox.sent.clear()
    new = {"first_name": "Nueva", "last_name": "Persona", "password": TEMP}
    r = root.post("/api/users", json={"email": "Nueva@Adm.co", **new})
    assert r.status_code == 201 and r.json()["status"] == "active" and r.json()["email"] == "nueva@adm.co"
    assert r.json()["must_change_password"] is True and not Outbox.sent          # sin correo
    assert root.post("/api/users", json={"email": "nueva@adm.co", **new}).status_code == 409
    assert root.post("/api/users", json={"email": "z@adm.co", **new, "account_type": "marciano"}).status_code == 422
    assert root.post("/api/users", json={"email": "z@adm.co", **new, "password": "corta"}).status_code == 422
    assert root.post("/api/users", json={"email": "z@adm.co", "first_name": "a", "last_name": "b"}).status_code == 422
    nid = r.json()["id"]

    page = root.get("/api/users", params={"q": "nueva", "limit": 5}).json()
    assert page["total"] == 1 and page["items"][0]["id"] == nid and page["limit"] == 5
    assert root.get("/api/users", params={"q": "100%_"}).json()["total"] == 0  # comodines escapados
    assert root.get("/api/users", params={"sort": "password_hash"}).status_code == 422  # orden controlado
    emails = [u["email"] for u in root.get("/api/users", params={"sort": "email", "order": "asc", "limit": 100}).json()["items"]]
    assert emails == sorted(emails)
    assert root.get("/api/users", params={"status": "active"}).json()["total"] >= 1
    assert root.get("/api/users", params={"limit": 1}).json()["total"] > 1   # total real, no el de la página

    assert root.patch(f"/api/users/{nid}", json={"first_name": "Renombrada"}).json()["first_name"] == "Renombrada"
    assert root.patch(f"/api/users/{nid}", json={"email": "owner@adm.co"}).status_code == 409
    make_user("cambio@adm.co")
    cid = uid("cambio@adm.co")
    r = root.patch(f"/api/users/{cid}", json={"email": "nuevo.correo@adm.co"})
    assert r.json()["email_verified"] is True and not Outbox.sent               # sigue pudiendo entrar
    assert login_status("nuevo.correo@adm.co") == 200
    assert root.post(f"/api/users/{cid}/resend-invitation").status_code == 409  # ya activó su cuenta


def test_temporary_password_must_be_changed_first(root, root_id):
    r = root.post("/api/users", json={"email": "primera@adm.co", "first_name": "Primera", "last_name": "Vez",
                                      "password": TEMP})
    pid = r.json()["id"]
    root.post(f"/api/users/{pid}/roles", json={"role": "editor"})
    c = TestClient(app)
    r = c.post("/api/auth/login", json={"email": "primera@adm.co", "password": TEMP})
    assert r.status_code == 200 and r.json()["user"]["must_change_password"] is True
    c.headers["X-CSRF-Token"] = r.json()["csrf_token"]
    assert c.get("/api/auth/me").status_code == 200
    assert c.get("/api/auth/me/permissions").status_code == 403                 # nada más hasta cambiarla
    assert c.post("/api/news/categories", json={"name": "x"}).status_code == 403
    assert c.post("/api/auth/change-password", json={"current_password": TEMP, "new_password": TEMP}).status_code == 422
    assert c.post("/api/auth/change-password", json={"current_password": TEMP,
                                                      "new_password": PASSWORD}).status_code == 200
    assert c.get("/api/auth/me").json()["must_change_password"] is False
    assert c.get("/api/auth/me/permissions").status_code == 200


@pytest.mark.security
def test_admin_sets_temporary_password(root, root_id):
    oid = make_user("olvido@adm.co")
    s = session("olvido@adm.co")
    assert root.post(f"/api/users/{oid}/password", json={"password": "corta"}).status_code == 422
    r = root.post(f"/api/users/{oid}/password", json={"password": TEMP})
    assert r.status_code == 200 and r.json()["must_change_password"] is True
    assert s.get("/api/auth/me").status_code == 401                            # sesiones cerradas
    assert login_status("olvido@adm.co") == 401                                # la anterior ya no sirve
    assert TestClient(app).post("/api/auth/login", json={"email": "olvido@adm.co", "password": TEMP}).status_code == 200
    assert root.post(f"/api/users/{root_id}/password", json={"password": TEMP}).status_code == 403  # no a sí mismo
    # invitada que nunca recibió el correo: queda activa
    iid = make_user("pendiente@adm.co", status="invited")
    assert root.post(f"/api/users/{iid}/password", json={"password": TEMP}).json()["status"] == "active"
    # un admin no puede cambiar la del super_admin (más permisos que él)
    make_user("admin.pw@adm.co", ("admin", None, None))
    assert session("admin.pw@adm.co").post(f"/api/users/{root_id}/password",
                                           json={"password": TEMP}).status_code == 403
    # sin users.update
    make_user("sinpermiso.pw@adm.co")
    assert session("sinpermiso.pw@adm.co").post(f"/api/users/{oid}/password",
                                                json={"password": TEMP}).status_code == 403


def test_status_changes_and_unlock(root, root_id):
    make_user("estado@adm.co")
    sid = uid("estado@adm.co")
    s = session("estado@adm.co")
    assert root.post(f"/api/users/{sid}/deactivate", json={"reason": "licencia"}).json()["status"] == "inactive"
    assert s.get("/api/auth/me").status_code == 401                            # sesiones revocadas
    assert login_status("estado@adm.co") == 401
    assert root.post(f"/api/users/{sid}/deactivate").status_code == 409        # ya inactivo
    assert root.post(f"/api/users/{sid}/activate").json()["status"] == "active"
    assert login_status("estado@adm.co") == 200
    assert root.post(f"/api/users/{sid}/block").json()["status"] == "blocked"
    assert login_status("estado@adm.co") == 401
    assert root.post(f"/api/users/{sid}/unblock").json()["status"] == "active"
    assert root.post(f"/api/users/{root_id}/deactivate").status_code == 403    # no a sí mismo

    for _ in range(5):
        TestClient(app, client=("10.9.9.9", 1)).post("/api/auth/login", json={"email": "estado@adm.co",
                                                                               "password": "incorrecta-larga"})
    assert login_status("estado@adm.co") == 401                                 # bloqueo temporal
    assert root.get(f"/api/users/{sid}").json()["locked_until"]
    assert root.post(f"/api/users/{sid}/unlock").status_code == 200
    assert login_status("estado@adm.co") == 200


def test_soft_delete(root, root_id):
    did = make_user("borrar@adm.co", ("editor", "research_center", 2))
    s = session("borrar@adm.co")
    assert root.delete(f"/api/users/{did}").status_code == 204
    assert root.get(f"/api/users/{did}").status_code == 404
    assert s.get("/api/auth/me").status_code == 401
    assert sql("SELECT count(*) FROM user_role_assignments WHERE user_id = :u AND revoked_at IS NULL", u=did).scalar() == 0
    assert sql("SELECT count(*) FROM users WHERE id = :u", u=did).scalar() == 1  # se conserva (trazabilidad)
    assert root.post("/api/users", json={"email": "borrar@adm.co", "first_name": "a", "last_name": "b",
                                         "password": TEMP}).status_code == 201
    assert root.delete(f"/api/users/{root_id}").status_code == 403


@pytest.mark.security
def test_assignments_scoped_delegation_and_escalation(root, root_id):
    tid = make_user("destino@adm.co")
    r = root.post(f"/api/users/{tid}/roles", json={"role": "editor", "scope_type": "research_center", "scope_id": 2})
    assert r.status_code == 201 and r.json()["scope_type"] == "research_center"
    c2_assignment = r.json()["id"]
    assert root.post(f"/api/users/{tid}/roles", json={"role": "editor", "scope_type": "research_center",
                                                      "scope_id": 2}).status_code == 409  # duplicada
    for bad in ({"role": "fantasma"}, {"role": "editor", "scope_type": "faculty", "scope_id": 99},
                {"role": "editor", "scope_type": "faculty"}, {"role": "editor", "scope_type": "planeta", "scope_id": 1}):
        assert root.post(f"/api/users/{tid}/roles", json=bad).status_code == 422, bad

    ensure_user("admin.fac@adm.co", ("admin", "faculty", 5))
    fa = session("admin.fac@adm.co")
    ok = fa.post(f"/api/users/{tid}/roles", json={"role": "publisher", "scope_type": "faculty", "scope_id": 5})
    assert ok.status_code == 201
    assert fa.post(f"/api/users/{tid}/roles", json={"role": "reviewer", "scope_type": "academic_program",
                                                    "scope_id": 8}).status_code == 201  # programa de su facultad
    assert fa.post(f"/api/users/{tid}/roles", json={"role": "editor", "scope_type": "faculty",
                                                    "scope_id": 3}).status_code == 403  # otra facultad
    assert fa.post(f"/api/users/{tid}/roles", json={"role": "viewer"}).status_code == 403  # institucional
    assert fa.post(f"/api/users/{tid}/roles", json={"role": "super_admin", "scope_type": "faculty",
                                                    "scope_id": 5}).status_code == 403  # permisos que no tiene
    assert fa.delete(f"/api/users/{tid}/roles/{c2_assignment}").status_code == 403  # revocar fuera de su ámbito

    editor = session("destino@adm.co")
    assert editor.post(f"/api/users/{tid}/roles", json={"role": "editor", "scope_type": "research_center",
                                                        "scope_id": 2}).status_code == 403  # sin users.manage_roles

    perms = root.get(f"/api/users/{tid}/permissions").json()
    assert {"news.create", "news.publish", "news.approve"} <= set(perms["permissions"])
    revoked = fa.request("DELETE", f"/api/users/{tid}/roles/{ok.json()['id']}", json={"reason": "cambio de cargo"})
    assert revoked.status_code == 200 and revoked.json()["is_active"] is False
    assert fa.delete(f"/api/users/{tid}/roles/{ok.json()['id']}").status_code == 409
    history = root.get(f"/api/users/{tid}/role-assignments").json()
    revoked_row = next(a for a in history if a["id"] == ok.json()["id"])
    assert revoked_row["revoked_by"] == uid("admin.fac@adm.co") and revoked_row["revoke_reason"] == "cambio de cargo"
    assert ok.json()["id"] not in {a["id"] for a in root.get(f"/api/users/{tid}/roles").json()}
    assert "news.publish" not in root.get(f"/api/users/{tid}/permissions").json()["permissions"]


def test_roles_management(root, root_id):
    roles = root.get("/api/roles", params={"limit": 3, "order": "asc"}).json()
    assert roles["total"] >= 7 and len(roles["items"]) == 3
    body = {"code": "comunicaciones", "name": "Comunicaciones", "permissions": ["news.view", "news.create"]}
    r = root.post("/api/roles", json=body)
    assert r.status_code == 201 and r.json()["permissions"] == ["news.create", "news.view"]
    rid = r.json()["id"]
    assert root.post("/api/roles", json=body).status_code == 409
    assert root.post("/api/roles", json=body | {"code": "otro", "permissions": ["no.existe"]}).status_code == 422
    assert root.post("/api/roles", json=body | {"code": "Mal Codigo"}).status_code == 422

    ensure_user("admin.global@adm.co", ("admin", None, None))                  # admin: todo menos permissions.manage
    ag = session("admin.global@adm.co")
    assert ag.post("/api/roles", json={"code": "escalador", "name": "Escalador",
                                       "permissions": ["permissions.manage"]}).status_code == 403
    ensure_user("admin.fac@adm.co", ("admin", "faculty", 5))
    fa = session("admin.fac@adm.co")
    assert fa.post("/api/roles", json=body | {"code": "local"}).status_code == 403  # roles: solo institucional

    member = make_user("comms@adm.co")
    assign(member, "comunicaciones", "research_center", 2)
    m = session("comms@adm.co")
    assert "news.publish" not in m.get("/api/auth/me/permissions").json()["permissions"]
    r = root.put(f"/api/roles/{rid}/permissions", json={"permissions": ["news.view", "news.create", "news.publish"]})
    assert r.json()["permissions"] == ["news.create", "news.publish", "news.view"]
    assert "news.publish" in m.get("/api/auth/me/permissions").json()["permissions"]  # efecto inmediato
    assert root.get(f"/api/roles/{rid}/permissions").json() == ["news.create", "news.publish", "news.view"]

    assert root.delete(f"/api/roles/{rid}").status_code == 409                 # en uso
    aid = root.get(f"/api/users/{member}/roles").json()[0]["id"]
    root.delete(f"/api/users/{member}/roles/{aid}")
    assert root.delete(f"/api/roles/{rid}").status_code == 204
    assert root.get(f"/api/roles/{rid}").json()["is_active"] is False


def test_permissions_management(root, root_id):
    new = {"code": "events.create", "name": "Crear eventos", "module": "events", "resource": "events",
           "action": "create"}
    r = root.post("/api/permissions", json=new)
    assert r.status_code == 201
    assert root.post("/api/permissions", json=new).status_code == 409
    assert root.post("/api/permissions", json=new | {"code": "events.delete"}).status_code == 422  # acción != código
    ensure_user("admin.global@adm.co", ("admin", None, None))
    ag = session("admin.global@adm.co")
    assert ag.post("/api/permissions", json=new | {"code": "events.view", "action": "view"}).status_code == 403
    assert root.patch(f"/api/permissions/{r.json()['id']}", json={"description": "Eventos"}).json()["description"] == "Eventos"
    news = root.get("/api/permissions", params={"module": "news", "limit": 100}).json()
    assert news["total"] == len(news["items"]) and all(p["module"] == "news" for p in news["items"])


@pytest.mark.security
def test_lockout_protection(root, root_id):
    owner_perm = sql("SELECT id FROM permissions WHERE code = 'permissions.manage'").scalar()
    super_role = sql("SELECT id FROM roles WHERE code = 'super_admin'").scalar()
    assert root.patch(f"/api/permissions/{owner_perm}", json={"is_active": False}).status_code == 409
    assert root.patch(f"/api/roles/{super_role}", json={"is_active": False}).status_code == 409
    keep = [p for p in root.get(f"/api/roles/{super_role}/permissions").json() if p != "permissions.manage"]
    assert root.put(f"/api/roles/{super_role}/permissions", json={"permissions": keep}).status_code == 409
    own = root.get(f"/api/users/{root_id}/roles").json()[0]["id"]
    assert root.delete(f"/api/users/{root_id}/roles/{own}").status_code == 409  # último dueño
    assert sql("SELECT revoked_at FROM user_role_assignments WHERE id = :a", a=own).scalar() is None  # sin cambios


@pytest.mark.security
def test_sessions_admin(root, root_id):
    sid = make_user("sesiones@adm.co")
    a, b = session("sesiones@adm.co"), session("sesiones@adm.co")
    listed = root.get(f"/api/users/{sid}/sessions").json()
    assert len(listed) == 2 and all("token" not in k for k in listed[0])
    assert root.delete(f"/api/users/{sid}/sessions/{listed[0]['id']}").status_code == 204
    assert sorted([a.get("/api/auth/me").status_code, b.get("/api/auth/me").status_code]) == [200, 401]
    survivor = a if a.get("/api/auth/me").status_code == 200 else b
    assert len(survivor.get(f"/api/users/{sid}/sessions").json()) == 1          # las propias sí
    assert survivor.get(f"/api/users/{root_id}/sessions").status_code == 403    # las ajenas no
    assert root.delete(f"/api/users/{sid}/sessions/999999").status_code == 404


def test_admin_identity_linking(root, root_id):
    lid = make_user("vincular@adm.co")
    Outbox.sent.clear()
    assert root.post(f"/api/users/{lid}/identities/microsoft/link-request").status_code == 200
    token = Outbox.sent[-1][2].split("token=")[1].split()[0]
    c = TestClient(app, client=("10.7.7.7", 1), follow_redirects=False)
    q = ms_login(c, link_token=token)
    r = ms_callback(c, q, id_token(q["nonce"][0], oid="oid-admin-link"))
    assert "error" not in r.headers["location"], r.headers["location"]
    assert c.get("/api/auth/me").json()["auth_methods"] == ["microsoft", "password"]
    q = ms_login(c, link_token=token)                                          # enlace de un solo uso
    assert error_code(ms_callback(c, q, id_token(q["nonce"][0], oid="oid-otro"))) == "422"

    identity = root.get(f"/api/users/{lid}").json()["linked_identities"][0]
    assert root.delete(f"/api/users/{lid}/identities/{identity['id']}").status_code == 204
    assert root.get(f"/api/users/{lid}").json()["auth_methods"] == ["password"]
    assert c.get("/api/auth/me").status_code == 401                            # su sesión de Microsoft se revocó

    # eliminar un usuario que entró con Microsoft (sesión ligada a la identidad) no rompe la integridad
    root.post(f"/api/users/{lid}/identities/microsoft/link-request")
    token = Outbox.sent[-1][2].split("token=")[1].split()[0]
    c2 = TestClient(app, client=("10.7.7.8", 1), follow_redirects=False)
    q = ms_login(c2, link_token=token)
    ms_callback(c2, q, id_token(q["nonce"][0], oid="oid-admin-link-2"))
    assert c2.get("/api/auth/me").status_code == 200
    assert root.delete(f"/api/users/{lid}").status_code == 204
    assert c2.get("/api/auth/me").status_code == 401


def test_audit_query(root, root_id):
    page = root.get("/api/audit", params={"event_type": "iam.role", "limit": 2}).json()
    assert page["total"] >= 2 and len(page["items"]) == 2
    assert all(i["event_type"].startswith("iam.role") for i in page["items"])
    assert root.get("/api/audit", params={"result": "denied"}).json()["total"] >= 1   # intentos de escalamiento
    assert root.get("/api/audit", params={"event_type": "%"}).json()["total"] == 0   # comodín escapado
    mine = root.get(f"/api/users/{root_id}/activity", params={"limit": 100}).json()
    assert mine["total"] > 0 and all(i["actor_user_id"] == root_id for i in mine["items"])
    assert root.delete("/api/audit").status_code == 405                       # inmutable por API
    assert root.put("/api/audit").status_code == 405

