"""Imagen principal de noticias: tipo por firma de bytes, tamaño, permisos y servido público seguro."""
import pytest
from fastapi.testclient import TestClient

from app.main import app
from app.shared.config import settings
from tests.support import make_user, seed_org, session

PNG = b"\x89PNG\r\n\x1a\n" + b"\x00" * 64
JPG = b"\xff\xd8\xff\xe0" + b"\x00" * 64
WEBP = b"RIFF\x24\x00\x00\x00WEBPVP8 " + b"\x00" * 64


@pytest.fixture(scope="module")
def editor():
    seed_org()
    make_user("img.ed@u.co", ("editor", "faculty", 5))
    make_user("img.otro@u.co", ("editor", "research_center", 2))
    ed = session("img.ed@u.co")
    root = make_user("img.root@u.co", ("super_admin", None, None)) and session("img.root@u.co")
    cat = root.post("/api/news/categories", json={"name": "Imágenes"}).json()["id"]
    nid = ed.post("/api/news", json={"title": "Con foto", "summary": "r", "content": "c", "category_id": cat,
                                     "scopes": [{"scope_type": "faculty", "scope_id": 5}]}).json()["id"]
    return ed, root, nid


def put_image(client, nid, content, ctype="image/png"):
    return client.put(f"/api/news/{nid}/image", content=content, headers={"Content-Type": ctype})


def test_upload_and_serve_image(editor):
    ed, _, nid = editor
    for content, ext in ((PNG, "png"), (JPG, "jpg"), (WEBP, "webp")):
        r = put_image(ed, nid, content)
        assert r.status_code == 200, r.text
        url = r.json()["image_url"]
        assert url.startswith("/media/news/") and url.endswith(f".{ext}")
    served = TestClient(app).get("/api" + url)                                      # público, sin sesión
    assert served.status_code == 200 and served.content == WEBP
    assert "immutable" in served.headers["cache-control"] and served.headers["x-content-type-options"] == "nosniff"


def test_content_images_do_not_replace_main_image(editor):
    ed, _, nid = editor
    main = ed.get(f"/api/news/{nid}").json()["image_url"]
    r = ed.put(f"/api/news/{nid}/content-image", content=JPG, headers={"Content-Type": "image/jpeg"})
    assert r.status_code == 200 and r.json()["url"].startswith("/media/news/") and r.json()["url"] != main
    assert ed.get(f"/api/news/{nid}").json()["image_url"] == main                  # la principal no cambia
    assert TestClient(app).get("/api" + r.json()["url"]).content == JPG
    bad = ed.put(f"/api/news/{nid}/content-image", content=b"<svg/>", headers={"Content-Type": "image/png"})
    assert bad.status_code == 422
    assert session("img.otro@u.co").put(f"/api/news/{nid}/content-image", content=JPG).status_code == 403


@pytest.mark.security
def test_upload_rejects_bad_files_and_unauthorized(editor):
    ed, root, nid = editor
    assert put_image(ed, nid, b"<svg onload=alert(1)>", "image/png").status_code == 422   # firma, no Content-Type
    assert put_image(ed, nid, b"GIF89a" + b"\x00" * 10, "image/gif").status_code == 422
    assert put_image(ed, nid, b"").status_code == 422
    big = PNG + b"\x00" * (settings.max_image_mb * 1024 * 1024)
    assert put_image(ed, nid, big).status_code == 422                                     # tamaño
    assert put_image(session("img.otro@u.co"), nid, PNG).status_code == 403              # otra dependencia
    no_csrf = session("img.ed@u.co")
    del no_csrf.headers["X-CSRF-Token"]
    assert put_image(no_csrf, nid, PNG).status_code == 403
    assert put_image(TestClient(app), nid, PNG).status_code == 401
    for step in ("submit", "approve"):                                                    # tras revisión: bloqueada
        root.post(f"/api/news/{nid}/{step}")
    assert put_image(ed, nid, PNG).status_code == 409


@pytest.mark.security
def test_media_route_only_serves_generated_names():
    anon = TestClient(app)
    for name in ("..%2F..%2F.env", "1-zzzz.png", "x.png", "1-0123456789abcdef.svg", "1-0123456789abcdef.png"):
        assert anon.get(f"/api/media/news/{name}").status_code == 404, name


def test_resized_webp_variants_for_responsive_images(editor):
    """?w=: versión WebP del ancho pedido (nunca mayor que el original), creada una vez e inmutable."""
    import io

    from PIL import Image

    ed, root, _ = editor
    cat = root.post("/api/news/categories", json={"name": "Variantes"}).json()["id"]
    nid = ed.post("/api/news", json={"title": "Foto grande", "summary": "r", "content": "c", "category_id": cat,
                                     "scopes": [{"scope_type": "faculty", "scope_id": 5}]}).json()["id"]
    buf = io.BytesIO()
    Image.new("RGB", (2400, 1350), (0, 109, 48)).save(buf, "PNG")  # foto grande, 16:9
    url = put_image(ed, nid, buf.getvalue()).json()["image_url"]
    anon = TestClient(app)
    small = anon.get(f"/api{url}?w=640")
    assert small.status_code == 200 and small.headers["content-type"] == "image/webp"
    assert "immutable" in small.headers["cache-control"]
    with Image.open(io.BytesIO(small.content)) as img:
        assert img.size == (640, 360)                                   # conserva la proporción
    assert len(small.content) < len(buf.getvalue()) / 10
    assert anon.get(f"/api{url}?w=640").content == small.content        # segunda vez: desde disco
    with Image.open(io.BytesIO(anon.get(f"/api{url}?w=1920").content)) as img:
        assert img.size == (1920, 1080)
    assert anon.get(f"/api{url}?w=333").status_code == 422              # solo anchos permitidos
    assert anon.get("/api/media/news/../../etc?w=640").status_code == 404
    assert anon.get("/api/media/news/1-0000000000000000.png?w=640").status_code == 404  # no existe
