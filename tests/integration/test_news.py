"""Reglas de negocio de noticias de punta a punta, con sesiones y permisos reales del IAM."""
from datetime import UTC, datetime, timedelta

import pytest
from fastapi.testclient import TestClient

from app.main import app
from tests.support import FakeMetrik, make_user, session


@pytest.fixture(scope="module")
def clients():
    FakeMetrik.reset()
    make_user("editor@unisimon.edu.co", ("editor", None, None))        # editor institucional
    make_user("admin@unisimon.edu.co", ("super_admin", None, None))
    yield TestClient(app), session("editor@unisimon.edu.co"), session("admin@unisimon.edu.co")  # anónimo, ed, ad
    FakeMetrik.reset()


iso = lambda d: (datetime.now(UTC) + timedelta(days=d)).isoformat()  # noqa: E731
ids = lambda r: [x["id"] for x in r.json()]  # noqa: E731


def make(ed, cat, **kw):
    body = {"title": "Investigadores en evento", "summary": "r", "content": "<p>ok</p><script>x</script>",
            "category_id": cat} | kw
    r = ed.post("/api/news", json=body)
    assert r.status_code == 201, r.text
    return r.json()


def test_flow(clients):
    c, ed, ad = clients
    # sincronización Metri-K -> nuestra BD
    assert ed.post("/api/organization/sync").status_code == 403
    r = ad.post("/api/organization/sync").json()
    assert (r["faculties"], r["centers"], r["programs"]) == (1, 2, 1), r
    assert ids(c.get("/api/organization/faculties/5/programs")) == [8]

    cats = c.get("/api/news/catalogs").json()
    assert {s["code"] for s in cats["statuses"]} >= {"draft", "in_review", "approved", "rejected",
                                                     "scheduled", "published", "archived"}
    cat = ad.post("/api/news/categories", json={"name": "Investigación"}).json()["id"]
    assert ed.post("/api/news/categories", json={"name": "X"}).status_code == 403
    assert c.post("/api/news", json={}).status_code == 401  # anónimo: no autenticado

    # vigencia inválida, códigos de catálogo inexistentes -> 422
    base = {"title": "Malo", "summary": "r", "content": "c", "category_id": cat}
    assert ed.post("/api/news", json=base | {"start_at": iso(5), "end_at": iso(1)}).status_code == 422
    assert ed.post("/api/news", json=base | {"relevance_level": "urgent"}).status_code == 422
    assert ed.post("/api/news", json=base | {"scopes": [{"scope_type": "planet", "scope_id": 1}]}).status_code == 422
    assert ed.post("/api/news", json=base | {"scopes": [{"scope_type": "faculty", "scope_id": 99}]}
                   ).status_code == 422  # facultad que no existe en la copia de Metri-K

    # sin asociaciones permitida; duplicados ignorados; HTML sanitizado; slug único
    n = make(ed, cat, relevance_level="high", scopes=[{"scope_type": "research_center", "scope_id": 2}] * 2,
             people=[{"person_type": "researcher", "orcid": "https://orcid.org/0000-0002-1825-0097", "relationship_type": "protagonist"},
                     {"person_type": "student", "orcid": "0000-0002-1694-233x", "relationship_type": "mentioned"}],
             tags=[" IA ", "ia", "Ciencia"])
    assert n["status"] == "draft" and "<script>" not in n["content"] and n["slug"] == "investigadores-en-evento"
    assert len(n["scopes"]) == 1 and len(n["people"]) == 2
    assert {p["orcid"] for p in n["people"]} == {"0000-0002-1825-0097", "0000-0002-1694-233X"}  # canónicos
    bad = {"person_type": "researcher", "orcid": "0000-0002-1825-0098", "relationship_type": "protagonist"}
    assert ed.post("/api/news", json=base | {"people": [bad]}).status_code == 422             # dígito de control and n["tags"] == ["ciencia", "ia"]
    assert make(ed, cat)["slug"] == "investigadores-en-evento-2"
    nid = n["id"]

    # borrador invisible; no se publica sin aprobación; editor no aprueba
    assert c.get(f"/api/news/{nid}").status_code == 404
    assert ad.post(f"/api/news/{nid}/publish").status_code == 409
    ed.post(f"/api/news/{nid}/submit")
    assert ed.post(f"/api/news/{nid}/approve").status_code == 403

    # rechazo exige motivo; se corrige y reenvía
    assert ad.post(f"/api/news/{nid}/reject", json={}).status_code == 422
    assert ad.post(f"/api/news/{nid}/reject", json={"reason": "Falta fuente"}).json()["status"] == "rejected"
    assert ed.patch(f"/api/news/{nid}", json={"end_at": iso(-1), "start_at": iso(1)}).status_code == 422
    r = ed.patch(f"/api/news/{nid}", json={"is_featured": True, "scopes": [
        {"scope_type": "research_center", "scope_id": 2}, {"scope_type": "faculty", "scope_id": 5}, {"scope_type": "academic_program", "scope_id": 8}]})
    assert r.status_code == 200 and len(r.json()["scopes"]) == 3, r.text

    for step in ("submit", "approve", "publish"):
        r = (ed if step == "submit" else ad).post(f"/api/news/{nid}/{step}")
    assert r.json()["status"] == "published" and r.json()["published_at"]
    assert c.get(f"/api/news/{r.json()['slug']}").status_code == 200
    assert ids(c.get("/api/news/featured")) == [nid]
    assert ids(c.get("/api/news?scope_type=faculty&scope_id=5")) == [nid]
    assert ids(c.get("/api/news?person_type=researcher&orcid=0000-0002-1825-0097")) == [nid]
    assert ids(c.get("/api/news?relevance_level=high")) == [nid]
    assert c.get("/api/news?scope_type=research_seedbed").json() == []
    assert ids(c.get("/api/news?tag=IA")) == [nid]

    # publicada: contenido bloqueado; admin sí cambia campos libres
    assert ad.patch(f"/api/news/{nid}", json={"title": "Otro"}).status_code == 409
    assert ed.patch(f"/api/news/{nid}", json={"priority": 9}).status_code == 403  # editor no tiene news.curate
    assert ad.patch(f"/api/news/{nid}", json={"priority": 9}).json()["priority"] == 9

    # vencida: sigue 'published' pero se oculta, también de destacadas
    assert ad.patch(f"/api/news/{nid}", json={"end_at": iso(-1)}).json()["status"] == "published"
    assert c.get(f"/api/news/{nid}").status_code == 404 and c.get("/api/news/featured").json() == []

    # programada: no visible antes de su fecha
    s = make(ed, cat, title="Convocatoria semilleros")
    ed.post(f"/api/news/{s['id']}/submit")
    ad.post(f"/api/news/{s['id']}/approve")
    assert ad.post(f"/api/news/{s['id']}/schedule", json={"start_at": iso(-1)}).status_code == 422
    r = ad.post(f"/api/news/{s['id']}/schedule", json={"start_at": iso(3)}).json()
    assert r["status"] == "scheduled" and c.get(f"/api/news/{s['id']}").status_code == 404
    assert s["id"] in ids(ed.get("/api/news?status=scheduled"))

    # archivar = borrado lógico, solo admin
    assert ed.delete(f"/api/news/{nid}").status_code == 403
    assert ad.delete(f"/api/news/{nid}").json()["status"] == "archived"
    assert nid not in ids(ed.get("/api/news"))
    # centro que desaparece de Metri-K: se inactiva, no se borra
    FakeMetrik.centers_data = FakeMetrik.centers_data[1:]
    assert ad.post("/api/organization/sync").json()["centers_deactivated"] == 1
    assert ids(c.get("/api/organization/centers")) == [4]
    assert 2 in ids(c.get("/api/organization/centers?include_inactive=true"))

    actions = [h["action"] for h in ed.get(f"/api/news/{nid}/history").json()]
    assert actions[:3] == ["create", "submit", "reject"] and actions[-1] == "archive", actions


def test_update_re_sanitizes_html_and_normalizes_tags(clients):
    c, ed, _ = clients
    cat = c.get("/api/news/catalogs").json()["categories"][0]["id"]
    n = make(ed, cat, title="Edición con HTML", content="<p>Bueno</p><script>alert(1)</script>")
    r = ed.patch(f"/api/news/{n['id']}", json={
        "content": "<p>Hola</p><script>alert(1)</script><img src=x onerror=alert(1)>",
        "tags": [" IA ", "ia", "Ciencia"],
    })
    assert r.status_code == 200, r.text
    body = r.json()
    assert "<script>" not in body["content"]
    assert "onerror" not in body["content"]
    assert body["tags"] == ["ciencia", "ia"]

