"""RBAC con alcance organizacional integrado con noticias.

Escenarios del requerimiento: editor de un centro, reviewer institucional, publisher de una facultad
(con herencia a sus programas), roles múltiples, revocación inmediata y operaciones solo institucionales.
"""
from types import SimpleNamespace

import pytest
from fastapi.testclient import TestClient

from app.main import app
from tests.support import assign, make_user, seed_org, session, sql

C2, F5, P8, F3 = (("research_center", 2), ("faculty", 5), ("academic_program", 8), ("faculty", 3))


@pytest.fixture(scope="module")
def w():
    """Mundo de la prueba: dependencias, usuarios con roles por alcance y una categoría."""
    seed_org()
    make_user("root@u.co", ("super_admin", None, None))
    make_user("nadie@u.co")
    make_user("ed.c2@u.co", ("editor", "research_center", 2))
    make_user("rev@u.co", ("reviewer", None, None))
    make_user("pub.f5@u.co", ("publisher", "faculty", 5))
    make_user("multi@u.co", ("editor", "research_center", 2), ("reviewer", "faculty", 5))
    make_user("viewer@u.co", ("viewer", None, None))
    make_user("admin.f5@u.co", ("admin", "faculty", 5))
    make_user("centro.c2@u.co", ("research_center", "research_center", 2))
    root = session("root@u.co")
    cat = root.post("/api/news/categories", json={"name": "General"}).json()["id"]
    return SimpleNamespace(root=root, cat=cat)


def body(w, *scopes, title="Noticia"):
    return {"title": title, "summary": "r", "content": "<p>c</p>", "category_id": w.cat,
            "scopes": [{"scope_type": t, "scope_id": i} for t, i in scopes]}


def approved_by_root(w, *scopes) -> int:
    nid = w.root.post("/api/news", json=body(w, *scopes)).json()["id"]
    for step in ("submit", "approve"):
        assert w.root.post(f"/api/news/{nid}/{step}").status_code == 200
    return nid


def ids(r):
    return {x["id"] for x in r.json()}


def test_unauthenticated_and_no_roles(w):
    anon = TestClient(app)
    assert anon.post("/api/news", json=body(w, C2)).status_code == 401
    assert anon.post("/api/news/1/approve").status_code == 401
    nadie = session("nadie@u.co")
    assert nadie.post("/api/news", json=body(w, C2)).status_code == 403        # autenticado sin permiso
    assert nadie.get("/api/auth/me/permissions").json() == {"permissions": [], "grants": [], "names": {}}
    draft = w.root.post("/api/news", json=body(w, C2)).json()["id"]
    assert draft not in ids(nadie.get("/api/news"))                             # ve solo lo público
    assert nadie.get(f"/api/news/{draft}").status_code == 404


@pytest.mark.security
def test_editor_scoped_to_center(w):
    ed = session("ed.c2@u.co")
    own = ed.post("/api/news", json=body(w, C2))
    assert own.status_code == 201, own.text
    nid = own.json()["id"]
    assert ed.post("/api/news", json=body(w, F5)).status_code == 403           # otra dependencia
    assert ed.post("/api/news", json=body(w, C2, F5)).status_code == 403       # regla: TODAS
    assert ed.post("/api/news", json=body(w)).status_code == 403               # institucional
    assert ed.post("/api/news", json=body(w, ("institution", 1))).status_code == 403
    # manipulación de scope_id: no puede "mover" su noticia a una dependencia ajena
    assert ed.patch(f"/api/news/{nid}", json={"scopes": [{"scope_type": "faculty", "scope_id": 5}]}).status_code == 403
    assert ed.patch(f"/api/news/{nid}", json={"title": "Editada"}).status_code == 200

    foreign = w.root.post("/api/news", json=body(w, F5, title="De ingeniería")).json()["id"]
    assert ed.patch(f"/api/news/{foreign}", json={"title": "x"}).status_code == 403
    assert ed.get(f"/api/news/{foreign}").status_code == 404                    # ni la ve
    assert ed.get(f"/api/news/{foreign}/history").status_code == 404
    listed = ids(ed.get("/api/news"))
    assert nid in listed and foreign not in listed
    assert foreign not in ids(ed.get("/api/news", params={"scope_type": "faculty", "scope_id": 5}))  # filtro no amplía
    assert nid not in ids(ed.get("/api/news", params={"public": "true"}))       # portada: nunca borradores
    assert ed.post(f"/api/news/{nid}/submit").status_code == 200
    assert ed.post(f"/api/news/{nid}/approve").status_code == 403              # no tiene news.approve


@pytest.mark.security
def test_research_center_role_only_creates_news_of_its_center(w):
    """Rol "Centro de investigación" (migración 0006): crea, completa y envía a revisión; nada más."""
    perms = sql("SELECT p.code FROM role_permissions rp JOIN roles r ON r.id = rp.role_id "
                "JOIN permissions p ON p.id = rp.permission_id WHERE r.code = 'research_center'").scalars().all()
    assert sorted(perms) == ["news.analytics", "news.create", "news.submit", "news.update", "news.view"]

    centro = session("centro.c2@u.co")
    nid = centro.post("/api/news", json=body(w, C2, title="Del centro")).json()["id"]
    assert centro.patch(f"/api/news/{nid}", json={"summary": "completo"}).status_code == 200
    assert centro.post("/api/news", json=body(w)).status_code == 403                  # institucional
    assert centro.post("/api/news", json=body(w, ("research_center", 4))).status_code == 403  # otro centro
    assert centro.post("/api/news", json=body(w, F5)).status_code == 403
    assert centro.post(f"/api/news/{nid}/submit").status_code == 200
    for step in ("approve", "publish"):
        assert centro.post(f"/api/news/{nid}/{step}").status_code == 403
    assert centro.delete(f"/api/news/{nid}").status_code == 403                        # no archiva
    assert centro.post("/api/news/categories", json={"name": "X"}).status_code == 403
    assert centro.get("/api/users").status_code == 403


def test_institutional_reviewer_and_scoped_publisher_with_inheritance(w):
    rev, pub = session("rev@u.co"), session("pub.f5@u.co")
    n = w.root.post("/api/news", json=body(w, C2)).json()["id"]
    w.root.post(f"/api/news/{n}/submit")
    assert rev.post(f"/api/news/{n}/approve").status_code == 200               # institucional: cualquiera
    assert pub.post(f"/api/news/{n}/publish").status_code == 403               # centro 2 no es su ámbito

    program_news = approved_by_root(w, P8)                                      # programa de la facultad 5
    assert pub.post(f"/api/news/{program_news}/publish").json()["status"] == "published"  # herencia
    mixed = approved_by_root(w, F5, C2)
    assert pub.post(f"/api/news/{mixed}/publish").status_code == 403           # regla: TODAS
    other_faculty = approved_by_root(w, F3)
    assert pub.post(f"/api/news/{other_faculty}/publish").status_code == 403


def test_multiple_roles_and_effective_permissions(w):
    m = session("multi@u.co")
    assert m.post("/api/news", json=body(w, C2)).status_code == 201            # editor en el centro 2
    f5 = w.root.post("/api/news", json=body(w, F5)).json()["id"]
    c2 = w.root.post("/api/news", json=body(w, C2)).json()["id"]
    for nid in (f5, c2):
        w.root.post(f"/api/news/{nid}/submit")
    assert m.post(f"/api/news/{f5}/approve").status_code == 200                # reviewer en la facultad 5
    assert m.post(f"/api/news/{c2}/approve").status_code == 403                # pero no en el centro 2
    perms = m.get("/api/auth/me/permissions").json()
    assert {"news.create", "news.approve", "news.review"} <= set(perms["permissions"])
    assert {"permission": "news.approve", "permission_name": "Aprobar", "scope_type": "faculty",
            "scope_id": 5} in perms["grants"]
    assert {"permission": "news.create", "permission_name": "Crear noticias", "scope_type": "research_center",
            "scope_id": 2} in perms["grants"]
    assert perms["names"]["news.review"] == "Revisar y rechazar"                      # nombres para la UI


@pytest.mark.security
def test_revocation_is_immediate(w):
    uid = make_user("temp@u.co")
    aid = assign(uid, "editor", "research_center", 2)
    t = session("temp@u.co")
    assert t.post("/api/news", json=body(w, C2)).status_code == 201
    sql("UPDATE user_role_assignments SET revoked_at = CURRENT_TIMESTAMP, revoked_by = :u WHERE id = :a", u=uid, a=aid)
    assert t.post("/api/news", json=body(w, C2)).status_code == 403            # misma sesión, ya sin permiso

    v = session("viewer@u.co")
    draft = w.root.post("/api/news", json=body(w, F5)).json()["id"]
    assert v.get(f"/api/news/{draft}").status_code == 200
    sql("UPDATE roles SET is_active = FALSE WHERE code = 'viewer'")             # rol desactivado
    assert v.get(f"/api/news/{draft}").status_code == 404
    sql("UPDATE roles SET is_active = TRUE WHERE code = 'viewer'")
    sql("UPDATE permissions SET is_active = FALSE WHERE code = 'news.view'")    # permiso desactivado
    assert v.get(f"/api/news/{draft}").status_code == 404
    sql("UPDATE permissions SET is_active = TRUE WHERE code = 'news.view'")


def test_global_only_operations(w):
    a = session("admin.f5@u.co")                                                # admin, pero solo de la facultad 5
    assert a.post("/api/organization/sync").status_code == 403                 # sincronizar es institucional
    assert a.post("/api/news/categories", json={"name": "Otra"}).status_code == 403
    assert a.post("/api/users", json={"email": "x@u.co", "first_name": "x", "last_name": "y",
                                      "password": "Clave-Temporal-2026!"}).status_code == 403
