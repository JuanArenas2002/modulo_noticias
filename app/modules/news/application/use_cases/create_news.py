"""Caso de uso: crear una noticia en el estado inicial del catálogo (borrador)."""
from app.modules.news.application.dto.news_dto import NewsCreateDTO
from app.modules.news.application.validators.news_validators import resolve_references
from app.modules.news.domain.entities.news import News, NewsHistory
from app.modules.news.domain.repositories.catalog_repository import CatalogRepository
from app.modules.news.domain.repositories.news_repository import NewsRepository
from app.modules.news.domain.services.slug_service import unique_slug
from app.modules.iam.domain.services.authorization_service import Principal

SCALAR_FIELDS = {"title", "summary", "content", "image_url", "image_caption", "category_id",
                 "priority", "is_featured", "is_pinned", "start_at", "end_at"}


class CreateNewsUseCase:
    def __init__(self, news: NewsRepository, catalogs: CatalogRepository):
        self.news, self.catalogs = news, catalogs

    def execute(self, dto: NewsCreateDTO, user: Principal) -> News:
        refs = resolve_references(dto, self.catalogs)
        # Nunca se confía en los scopes del request: se exige news.create sobre CADA uno (sin scopes = institucional).
        user.ensure_all("news.create", [s.key for s in refs["scopes"]])
        news = News(
            **dto.model_dump(include=SCALAR_FIELDS),
            relevance_level=refs["relevance_level"],
            slug=unique_slug(dto.slug or dto.title, self.news.slug_exists),
            author_id=user.user_id,
            status=self.catalogs.initial_status(),
        )
        news.replace_links(refs["scopes"], refs["people"], refs["tags"])
        news.ensure_valid_window()
        self.news.add(news)
        self.news.add_history(NewsHistory(news_id=news.id, actor_id=user.user_id, action="create",
                                          from_status=None, to_status=news.status))
        self.news.commit()
        return news
