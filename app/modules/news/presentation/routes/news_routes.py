"""Endpoints de noticias. Autorización del IAM:
- `require_permission(code)` filtra el endpoint (401 sin sesión, 403 sin el permiso en ningún alcance);
- el caso de uso exige el permiso sobre TODAS las dependencias de la noticia (leídas de la BD).
"""
from typing import Annotated

from fastapi import APIRouter, Depends, Query, Request
from fastapi.concurrency import run_in_threadpool
from fastapi.responses import FileResponse
from pydantic import BaseModel
from sqlalchemy.orm import Session

from app.modules.iam.domain.services.authorization_service import Principal
from app.modules.iam.infrastructure.repositories.sqlalchemy_authorization_repository import (
    SqlAlchemyAuthorizationRepository)
from app.modules.iam.presentation.routes.dependencies import optional_principal, require_permission
from app.modules.news.application.dto.news_dto import (NewsCreateDTO, NewsFilterDTO, NewsUpdateDTO, RejectDTO,
                                                       ScheduleDTO)
from app.modules.news.application.use_cases.change_news_status import ChangeNewsStatusUseCase
from app.modules.news.application.use_cases.create_news import CreateNewsUseCase
from app.modules.news.application.use_cases.get_news import GetNewsHistoryUseCase, GetNewsUseCase
from app.modules.news.application.use_cases.list_news import ListFeaturedNewsUseCase, ListNewsUseCase
from app.modules.news.application.use_cases.update_news import UpdateNewsUseCase
from app.modules.news.application.use_cases.upload_news_image import UploadNewsImageUseCase
from app.modules.news.infrastructure.repositories.local_media_storage import WIDTHS, LocalMediaStorage
from app.modules.news.infrastructure.repositories.sqlalchemy_catalog_repository import SqlAlchemyCatalogRepository
from app.modules.news.infrastructure.repositories.sqlalchemy_news_repository import SqlAlchemyNewsRepository
from app.modules.news.presentation.schemas.news_schemas import HistoryResponse, NewsResponse
from app.shared.config import settings
from app.shared.database import get_db
from app.shared.exceptions import InvalidDataError, NotFoundError

router = APIRouter(prefix="/api/news", tags=["Noticias"])


class Repos:
    def __init__(self, db: Session = Depends(get_db)):
        self.news = SqlAlchemyNewsRepository(db)
        self.catalogs = SqlAlchemyCatalogRepository(db)


def _status(repos: Repos, news_id: int, action: str, user: Principal, **kw) -> NewsResponse:
    return NewsResponse.from_entity(
        ChangeNewsStatusUseCase(repos.news, repos.catalogs).execute(news_id, action, user, **kw))


@router.post("", response_model=NewsResponse, status_code=201)
def create_news(body: NewsCreateDTO, r: Repos = Depends(),
                user: Principal = Depends(require_permission("news.create"))):
    return NewsResponse.from_entity(CreateNewsUseCase(r.news, r.catalogs).execute(body, user))


@router.get("", response_model=list[NewsResponse])
def list_news(f: Annotated[NewsFilterDTO, Query()], r: Repos = Depends(),
              user: Principal | None = Depends(optional_principal)):
    """Público: solo publicadas y vigentes. Con news.view: internas de sus dependencias (todas si es institucional)."""
    return [NewsResponse.from_entity(n) for n in ListNewsUseCase(r.news, r.catalogs).execute(f, user)]


@router.get("/featured", response_model=list[NewsResponse])
def featured_news(limit: int = Query(5, ge=1, le=20), r: Repos = Depends()):
    return [NewsResponse.from_entity(n) for n in ListFeaturedNewsUseCase(r.news).execute(limit)]


@router.get("/{ref}", response_model=NewsResponse)
def get_news(ref: str, r: Repos = Depends(), user: Principal | None = Depends(optional_principal)):
    """`ref` = id numérico o slug."""
    return NewsResponse.from_entity(GetNewsUseCase(r.news).execute(ref, user))


@router.patch("/{news_id}", response_model=NewsResponse)
def update_news(news_id: int, body: NewsUpdateDTO, r: Repos = Depends(),
                user: Principal = Depends(require_permission("news.view"))):
    """Exige news.update (borrador/rechazada) o news.curate (revisada/publicada) sobre todas sus dependencias."""
    return NewsResponse.from_entity(UpdateNewsUseCase(r.news, r.catalogs).execute(news_id, body, user))


@router.delete("/{news_id}", response_model=NewsResponse)
def archive_news(news_id: int, r: Repos = Depends(), user: Principal = Depends(require_permission("news.archive"))):
    """Eliminación lógica: archiva y deja traza en el historial."""
    return _status(r, news_id, "archive", user)


@router.post("/{news_id}/submit", response_model=NewsResponse)
def submit(news_id: int, r: Repos = Depends(), user: Principal = Depends(require_permission("news.submit"))):
    return _status(r, news_id, "submit", user)


@router.post("/{news_id}/approve", response_model=NewsResponse)
def approve(news_id: int, r: Repos = Depends(), user: Principal = Depends(require_permission("news.approve"))):
    return _status(r, news_id, "approve", user)


@router.post("/{news_id}/reject", response_model=NewsResponse)
def reject(news_id: int, body: RejectDTO, r: Repos = Depends(),
           user: Principal = Depends(require_permission("news.review"))):
    return _status(r, news_id, "reject", user, reason=body.reason)


@router.post("/{news_id}/publish", response_model=NewsResponse)
def publish(news_id: int, r: Repos = Depends(), user: Principal = Depends(require_permission("news.publish"))):
    """Con start_at futuro queda 'scheduled'; la visibilidad la decide la consulta, sin cron."""
    return _status(r, news_id, "publish", user)


@router.post("/{news_id}/schedule", response_model=NewsResponse)
def schedule(news_id: int, body: ScheduleDTO, r: Repos = Depends(),
             user: Principal = Depends(require_permission("news.publish"))):
    return _status(r, news_id, "schedule", user, start_at=body.start_at)


@router.put("/{news_id}/image", response_model=NewsResponse)
async def upload_image(news_id: int, request: Request, r: Repos = Depends(),
                       user: Principal = Depends(require_permission("news.view"))):
    """Imagen principal (JPG, PNG o WebP; cuerpo crudo, sin multipart). Exige el permiso de edición."""
    limit = settings.max_image_mb * 1024 * 1024
    if int(request.headers.get("content-length") or 0) > limit:
        raise InvalidDataError(f"La imagen debe pesar como máximo {settings.max_image_mb} MB")
    content = await request.body()
    use_case = UploadNewsImageUseCase(r.news, LocalMediaStorage(settings.media_dir), limit)
    return NewsResponse.from_entity(await run_in_threadpool(use_case.execute, news_id, content, user))


class ImageUrlResponse(BaseModel):
    url: str


@router.put("/{news_id}/content-image", response_model=ImageUrlResponse)
async def upload_content_image(news_id: int, request: Request, r: Repos = Depends(),
                               user: Principal = Depends(require_permission("news.view"))):
    """Imagen para insertar dentro del contenido (mismas reglas que la principal)."""
    limit = settings.max_image_mb * 1024 * 1024
    if int(request.headers.get("content-length") or 0) > limit:
        raise InvalidDataError(f"La imagen debe pesar como máximo {settings.max_image_mb} MB")
    content = await request.body()
    use_case = UploadNewsImageUseCase(r.news, LocalMediaStorage(settings.media_dir), limit)
    return ImageUrlResponse(url=await run_in_threadpool(use_case.inline, news_id, content, user))


media_router = APIRouter(prefix="/api/media", tags=["Noticias"])


@media_router.get("/news/{name}")
def news_image(name: str, w: int | None = None):
    """Imágenes públicas de noticias. El nombre incluye el hash del contenido: caché larga e inmutable.
    `?w=640` devuelve una versión WebP de ese ancho (las páginas la piden con srcset según el tamaño en pantalla)."""
    if w is not None and w not in WIDTHS:
        raise InvalidDataError(f"w debe ser uno de {WIDTHS}")
    storage = LocalMediaStorage(settings.media_dir)
    if (file := storage.variant(name, w) if w else storage.path(name)) is None:
        raise NotFoundError("Imagen no encontrada")
    return FileResponse(file, headers={"Cache-Control": "public, max-age=31536000, immutable",
                                       "X-Content-Type-Options": "nosniff"})


@router.get("/{news_id}/history", response_model=list[HistoryResponse])
def history(news_id: int, r: Repos = Depends(), user: Principal = Depends(require_permission("news.view")),
            db: Session = Depends(get_db)):
    entries = GetNewsHistoryUseCase(r.news).execute(news_id, user)
    names = SqlAlchemyAuthorizationRepository(db).user_names({h.actor_id for h in entries})
    return [HistoryResponse.from_entity(h).model_copy(update={"actor_name": names.get(h.actor_id)}) for h in entries]
