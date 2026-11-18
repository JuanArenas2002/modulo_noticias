"""Caso de uso: listado con filtros. Los códigos de catálogo se resuelven a ids antes de consultar."""
from app.modules.news.application.dto.news_dto import NewsFilterDTO
from app.modules.news.application.validators.news_validators import resolve_code
from app.modules.news.domain.entities.catalogs import NewsStatus, PersonType, RelevanceLevel, ScopeType
from app.modules.news.domain.entities.news import News
from app.modules.news.domain.repositories.catalog_repository import CatalogRepository
from app.modules.news.domain.repositories.news_repository import NewsQuery, NewsRepository
from app.modules.iam.domain.services.authorization_service import Principal
from app.shared.clock import now


class ListNewsUseCase:
    def __init__(self, news: NewsRepository, catalogs: CatalogRepository):
        self.news, self.catalogs = news, catalogs

    def _id(self, model, code: str | None) -> int | None:
        return resolve_code(self.catalogs, model, code).id if code else None

    def execute(self, f: NewsFilterDTO, user: Principal | None) -> list[News]:
        # Con news.view: listado interno, limitado a las dependencias donde lo tiene (None = todas).
        # Sin él (o anónimo): solo publicadas y vigentes.
        staff = bool(user) and user.can_any("news.view") and not f.public
        return self.news.list(NewsQuery(
            public_at=None if staff else now(),
            visible_scopes=user.visible_scopes("news.view") if staff else None,
            status_id=self._id(NewsStatus, f.status) if staff else None,
            category_id=f.category_id,
            relevance_level_id=self._id(RelevanceLevel, f.relevance_level),
            scope_type_id=self._id(ScopeType, f.scope_type), scope_id=f.scope_id,
            person_type_id=self._id(PersonType, f.person_type), orcid=f.orcid,
            tag=f.tag.strip().lower() if f.tag else None,
            featured=f.featured,
            start_date=f.start_date, end_date=f.end_date,
            limit=f.limit, offset=f.offset,
        ))


class ListFeaturedNewsUseCase:
    """Destacada = is_featured AND publicada AND vigente. La regla vive en la consulta, no en un flag."""

    def __init__(self, news: NewsRepository):
        self.news = news

    def execute(self, limit: int) -> list[News]:
        return self.news.list(NewsQuery(public_at=now(), featured=True, limit=limit))
