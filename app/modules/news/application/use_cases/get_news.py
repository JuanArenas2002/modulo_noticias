"""Casos de uso de consulta individual: detalle (por id o slug) e historial editorial.

Ver una noticia no publicada exige news.view sobre AL MENOS UNA de sus dependencias.
Si no se puede ver, se responde 404 (no se revela que existe).
"""
from app.modules.iam.domain.services.authorization_service import Principal
from app.modules.news.domain.entities.news import News, NewsHistory
from app.modules.news.domain.repositories.news_repository import NewsRepository
from app.shared.clock import now
from app.shared.exceptions import NotFoundError

VIEW = "news.view"
NOT_FOUND = "Noticia no encontrada"


def can_view_internal(user: Principal | None, n: News) -> bool:
    return bool(user) and user.allows_any(VIEW, n.scope_keys)


class GetNewsUseCase:
    def __init__(self, news: NewsRepository):
        self.news = news

    def execute(self, ref: str, user: Principal | None) -> News:
        if user and user.can_any(VIEW) and (n := self.news.find_by_ref(ref, public_at=None)) and can_view_internal(user, n):
            return n
        if (n := self.news.find_by_ref(ref, public_at=now())) is None:  # público: publicada y vigente
            raise NotFoundError(NOT_FOUND)
        return n


class GetNewsHistoryUseCase:
    def __init__(self, news: NewsRepository):
        self.news = news

    def execute(self, news_id: int, user: Principal) -> list[NewsHistory]:
        if (n := self.news.get(news_id)) is None or not can_view_internal(user, n):
            raise NotFoundError(NOT_FOUND)
        return self.news.history(news_id)
