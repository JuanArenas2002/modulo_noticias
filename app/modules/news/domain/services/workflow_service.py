from collections.abc import Callable
from datetime import datetime

from app.modules.news.domain.entities.catalogs import StatusTransition
from app.modules.news.domain.entities.news import News, NewsHistory
from app.shared.clock import as_utc
from app.shared.exceptions import ConflictError, ForbiddenError, InvalidDataError

PUBLISH, SCHEDULE = "publish", "schedule"


def resolve_action(action: str, news: News, at: datetime) -> str:
    """Publicar con start_at futuro equivale a programar."""
    if action == PUBLISH and news.start_at and as_utc(news.start_at) > at:
        return SCHEDULE
    return action


def apply_transition(news: News, action: str, transitions: list[StatusTransition], actor_id: int,
                     authorized: Callable[[str], bool], at: datetime, reason: str | None = None) -> NewsHistory:
    """Mueve la noticia según la tabla de transiciones.

    `authorized(permission) -> bool` decide con el IAM (sobre todas las dependencias de la noticia).
    """
    t = next((t for t in transitions if t.from_status.id == news.status.id), None)
    if t is None:
        raise ConflictError(f"No se puede '{action}' una noticia en estado '{news.status.code}'")
    if not authorized(t.required_permission):
        raise ForbiddenError(f"'{action}' requiere '{t.required_permission}' sobre todas las dependencias de la noticia")
    if t.requires_reason and not (reason and reason.strip()):
        raise InvalidDataError(f"'{action}' requiere un motivo")

    previous, news.status = news.status, t.to_status
    if t.to_status.is_public:
        # published_at = cuándo queda oficialmente publicada (inicio de vigencia si es futura).
        news.published_at = news.start_at if news.start_at and as_utc(news.start_at) > at else at
    return NewsHistory(news_id=news.id, actor_id=actor_id, action=action,
                       from_status=previous, to_status=t.to_status, reason=reason)
