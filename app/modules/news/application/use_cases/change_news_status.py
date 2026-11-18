"""Caso de uso: mover una noticia por el flujo editorial (submit, approve, reject, publish, schedule, archive).

Qué acción es válida desde qué estado, con qué rol y si exige motivo lo define la tabla
news_status_transitions; aquí no hay estados escritos en código.
"""
from datetime import datetime

from app.modules.news.domain.entities.news import News
from app.modules.news.domain.repositories.catalog_repository import CatalogRepository
from app.modules.news.domain.repositories.news_repository import NewsRepository
from app.modules.news.domain.services.workflow_service import SCHEDULE, apply_transition, resolve_action
from app.modules.iam.domain.services.authorization_service import Principal
from app.shared.clock import now
from app.shared.exceptions import InvalidDataError, NotFoundError


class ChangeNewsStatusUseCase:
    def __init__(self, news: NewsRepository, catalogs: CatalogRepository):
        self.news, self.catalogs = news, catalogs

    def execute(self, news_id: int, action: str, user: Principal,
                reason: str | None = None, start_at: datetime | None = None) -> News:
        if (n := self.news.get(news_id)) is None:
            raise NotFoundError("Noticia no encontrada")
        at = now()
        if action == SCHEDULE:
            if start_at is None or start_at <= at:
                raise InvalidDataError("start_at debe ser una fecha futura")
            n.start_at = start_at
            n.ensure_valid_window()
        action = resolve_action(action, n, at)
        scopes = n.scope_keys
        entry = apply_transition(n, action, self.catalogs.transitions(action), user.user_id,
                                 lambda permission: user.allows_all(permission, scopes), at, reason)
        self.news.add_history(entry)
        self.news.commit()
        return n
