"""Caso de uso: actualización parcial. Se fusiona con el estado actual y se revalida todo."""
from pydantic import BaseModel, ValidationError

from app.modules.news.application.dto.news_dto import NewsCreateDTO
from app.modules.news.application.use_cases.create_news import SCALAR_FIELDS
from app.modules.news.application.validators.news_validators import resolve_references
from app.modules.news.domain.entities.news import News, NewsHistory
from app.modules.news.domain.repositories.catalog_repository import CatalogRepository
from app.modules.news.domain.repositories.news_repository import NewsRepository
from app.modules.news.domain.services.slug_service import unique_slug
from app.modules.iam.domain.services.authorization_service import Principal
from app.shared.clock import now
from app.shared.exceptions import InvalidDataError, NotFoundError


def current_state(n: News) -> dict:
    return {
        **{f: getattr(n, f) for f in SCALAR_FIELDS},
        "slug": n.slug,
        "relevance_level": n.relevance_level.code,
        "tags": [t.tag for t in n.tags],
        "scopes": [{"scope_type": s.scope_type.code, "scope_id": s.scope_id} for s in n.scopes],
        "people": [{"person_type": p.person_type.code, "orcid": p.orcid,
                    "relationship_type": p.relationship_type.code} for p in n.people],
    }


class UpdateNewsUseCase:
    def __init__(self, news: NewsRepository, catalogs: CatalogRepository):
        self.news, self.catalogs = news, catalogs

    def execute(self, news_id: int, patch: BaseModel, user: Principal) -> News:
        if (n := self.news.get(news_id)) is None:
            raise NotFoundError("Noticia no encontrada")
        changes = patch.model_dump(exclude_unset=True)
        permission = n.edit_permission(set(changes))
        user.ensure_all(permission, n.scope_keys)  # autoridad sobre las dependencias actuales...
        try:
            dto = NewsCreateDTO.model_validate({**current_state(n), **changes})
        except ValidationError as e:
            raise InvalidDataError(e.errors(include_url=False, include_context=False, include_input=False))

        refs = resolve_references(dto, self.catalogs)
        user.ensure_all(permission, [s.key for s in refs["scopes"]])  # ...y sobre las nuevas (no se "mueve" a ajenas)
        for f in SCALAR_FIELDS:
            setattr(n, f, getattr(dto, f))
        n.relevance_level = refs["relevance_level"]
        n.replace_links(refs["scopes"], refs["people"], refs["tags"])
        if changes.get("slug"):
            n.slug = unique_slug(changes["slug"], lambda s: self.news.slug_exists(s, n.id))
        n.updated_at = now()
        n.ensure_valid_window()
        self.news.add_history(NewsHistory(news_id=n.id, actor_id=user.user_id, action="update",
                                          from_status=n.status, to_status=n.status))
        self.news.commit()
        return n
