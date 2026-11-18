"""Endpoints de analítica de noticias.

- POST /api/news/lecturas           público: lote de 1 a 20 eventos (una vista suelta es un lote de uno).
- GET  /api/news/analytics/overview estadísticas generales (KPIs, serie, procedencia, dispositivos, rankings).
- GET  /api/news/analytics/live     en vivo: lectores activos ahora (para consultar cada ~10 s).
- GET  /api/news/analytics/news     ranking paginado y ordenable (más vistas, menos vistas, más compartidas…).
- GET  /api/news/{news_id}/analytics estadísticas de una noticia.
Las consultas exigen `news.analytics` y se limitan a las dependencias donde el usuario lo tiene.
"""
from datetime import date, datetime, timedelta
from typing import Annotated, Literal
from uuid import UUID

from fastapi import APIRouter, Depends, Query, Request
from pydantic import BaseModel, ConfigDict, Field, model_validator
from sqlalchemy.orm import Session

from app.modules.analytics.application.use_cases import Event, RecordEventsUseCase, news_detail, overview
from app.modules.analytics.domain.rules import CHANNELS, DEVICES, LIVE_WINDOW_SECONDS, local_day
from app.modules.analytics.infrastructure.repository import SORTS, AnalyticsRepository, Filters
from app.modules.iam.domain.services.authorization_service import Principal
from app.modules.iam.presentation.routes.dependencies import request_meta, require_permission
from app.modules.news.application.validators.news_validators import resolve_code
from app.modules.news.domain.entities.catalogs import ScopeType
from app.modules.news.infrastructure.repositories.sqlalchemy_catalog_repository import SqlAlchemyCatalogRepository
from app.modules.news.infrastructure.repositories.sqlalchemy_news_repository import SqlAlchemyNewsRepository
from app.shared.clock import now
from app.shared.config import settings
from app.shared.database import get_db
from app.modules.privacy.domain.rules import COOKIE
from app.modules.privacy.infrastructure.repository import PrivacyRepository
from app.shared.rate_limit import Limiter
from app.shared.exceptions import ForbiddenError, InvalidDataError, NotFoundError, TooManyRequestsError

router = APIRouter(prefix="/api/news", tags=["Analítica de noticias"])
PERMISSION = "news.analytics"
MAX_RANGE_DAYS = 5 * 366
EVENTS_PER_MINUTE = 240  # por IP; generoso porque el campus sale a internet por pocas IP (NAT)


_Limiter = Limiter  # alias usado por las pruebas
limiter = _Limiter(EVENTS_PER_MINUTE)


# ---------- captura pública ----------
class EventIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    type: Literal["view", "heartbeat", "share"]
    news_id: int = Field(gt=0)
    channel: Literal[CHANNELS] | None = None
    referrer: str | None = Field(None, max_length=2048)
    from_news_id: int | None = Field(None, gt=0)
    is_entry: bool = False

    @model_validator(mode="after")
    def share_needs_channel(self):
        if (self.type == "share") != (self.channel is not None):
            raise ValueError("channel es obligatorio en share y solo se admite en share")
        return self


class EventsIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    session_id: UUID
    events: list[EventIn] = Field(min_length=1, max_length=20)


# Ruta sin "analytics"/"track"/"events": los bloqueadores de rastreadores (EasyPrivacy, Brave, Opera) cortan esas URL.
@router.post("/lecturas", status_code=202)
def collect(body: EventsIn, request: Request, db: Session = Depends(get_db)):
    """Sin sesión ni CSRF (lo llama cualquier lector). Lo no elegible (sin consentimiento de analítica, bots,
    noticias no públicas, latidos sin vista) se descarta en silencio; `accepted` dice cuántos eventos se consideraron."""
    meta, at = request_meta(request), now()
    if not limiter.allow(meta.ip or "-", len(body.events), at):
        raise TooManyRequestsError("Demasiados eventos; intenta más tarde")
    # Consentimiento (control central, también en el servidor): sin autorización de analítica vigente para
    # este navegador no se registra nada, aunque un cliente modificado envíe eventos.
    if not PrivacyRepository(db).allows(request.cookies.get(COOKIE), "analytics", at):
        return {"accepted": 0}
    accepted = RecordEventsUseCase(AnalyticsRepository(db), settings.secret_key, settings.frontend_url).execute(
        str(body.session_id), [Event(**e.model_dump()) for e in body.events], meta.ip, meta.user_agent or "", at)
    return {"accepted": accepted}


# ---------- consultas ----------
class StatsQuery(BaseModel):
    start_date: date | None = None
    end_date: date | None = None
    category_id: int | None = Field(None, gt=0)
    scope_type: str | None = Field(None, max_length=40)
    scope_id: int | None = Field(None, gt=0)
    device: Literal[DEVICES] | None = None
    channel: Literal[CHANNELS] | None = None
    granularity: Literal["day", "week", "month", "year"] | None = None

    @model_validator(mode="after")
    def valid_range(self):
        if self.start_date and self.end_date and self.end_date < self.start_date:
            raise ValueError("end_date no puede ser anterior a start_date")
        if (self.scope_type is None) != (self.scope_id is None):
            raise ValueError("scope_type y scope_id van juntos")
        return self


def _filters(q: StatsQuery, user: Principal, db: Session, news_id: int | None = None) -> Filters:
    end = q.end_date or local_day(now())
    start = q.start_date or end - timedelta(days=29)  # por defecto, últimos 30 días
    if (end - start).days + 1 > MAX_RANGE_DAYS:
        raise InvalidDataError("El rango máximo es de 5 años")
    scope = None
    if q.scope_type:
        scope = (resolve_code(SqlAlchemyCatalogRepository(db), ScopeType, q.scope_type).id, q.scope_id)
    allowed = user.visible_scopes(PERMISSION)
    return Filters(start=start, end=end, news_id=news_id, category_id=q.category_id, scope=scope, device=q.device,
                   channel=q.channel, allowed=None if allowed is None else frozenset(allowed))


@router.get("/analytics/overview")
def analytics_overview(q: Annotated[StatsQuery, Query()], db: Session = Depends(get_db),
                       user: Principal = Depends(require_permission(PERMISSION))):
    return overview(AnalyticsRepository(db), _filters(q, user, db), q.granularity)


@router.get("/analytics/live")
def analytics_live(q: Annotated[StatsQuery, Query()], news_id: int | None = Query(None, gt=0),
                   db: Session = Depends(get_db), user: Principal = Depends(require_permission(PERMISSION))):
    """En vivo: lectores con actividad en los últimos 45 s. Respeta categoría, dependencia, dispositivo y alcance."""
    at = now()
    return {"at": at, "window_seconds": LIVE_WINDOW_SECONDS,
            **AnalyticsRepository(db).live(_filters(q, user, db, news_id), at, LIVE_WINDOW_SECONDS)}


@router.get("/analytics/news")
def analytics_ranking(q: Annotated[StatsQuery, Query()], db: Session = Depends(get_db),
                      sort: Literal[SORTS] = "views", order: Literal["asc", "desc"] = "desc",
                      page: int = Query(1, ge=1), page_size: int = Query(20, ge=1, le=100),
                      min_views: int = Query(0, ge=0),
                      user: Principal = Depends(require_permission(PERMISSION))):
    total, items = AnalyticsRepository(db).ranking(_filters(q, user, db), sort=sort, desc=order == "desc",
                                                   limit=page_size, offset=(page - 1) * page_size, min_views=min_views)
    return {"total": total, "page": page, "page_size": page_size, "items": items}


@router.get("/{news_id}/analytics")
def analytics_news(news_id: int, q: Annotated[StatsQuery, Query()], db: Session = Depends(get_db),
                   user: Principal = Depends(require_permission(PERMISSION))):
    """Ver estadísticas de una noticia: basta el permiso en una de sus dependencias (como para verla)."""
    item = SqlAlchemyNewsRepository(db).get(news_id)
    if item is None:
        raise NotFoundError("Noticia no encontrada")
    if not user.allows_any(PERMISSION, item.scope_keys):
        raise ForbiddenError(f"No tienes '{PERMISSION}' sobre las dependencias de esta noticia")
    f = _filters(q, user, db, news_id)
    return news_detail(AnalyticsRepository(db), f, q.granularity) | {
        "title": item.title, "slug": item.slug, "published_at": item.published_at, "status": item.status.code}
