"""Respuestas HTTP. Los catálogos se exponen por código (estable) en vez de id."""
from datetime import datetime

from pydantic import BaseModel

from app.modules.news.domain.entities.news import News, NewsHistory


class ScopeResponse(BaseModel):
    scope_type: str
    scope_id: int


class PersonResponse(BaseModel):
    person_type: str
    orcid: str
    relationship_type: str


class NewsResponse(BaseModel):
    id: int
    title: str
    slug: str
    summary: str
    content: str
    image_url: str | None
    image_caption: str | None
    category_id: int
    author_id: int
    relevance_level: str
    priority: int
    is_featured: bool
    is_pinned: bool
    start_at: datetime | None
    end_at: datetime | None
    published_at: datetime | None
    created_at: datetime
    updated_at: datetime
    status: str
    tags: list[str]
    scopes: list[ScopeResponse]
    people: list[PersonResponse]

    @classmethod
    def from_entity(cls, n: News) -> "NewsResponse":
        return cls(
            **{f: getattr(n, f) for f in cls.model_fields
               if f not in {"relevance_level", "status", "tags", "scopes", "people"}},
            relevance_level=n.relevance_level.code,
            status=n.status.code,
            tags=[t.tag for t in n.tags],
            scopes=[ScopeResponse(scope_type=s.scope_type.code, scope_id=s.scope_id) for s in n.scopes],
            people=[PersonResponse(person_type=p.person_type.code, orcid=p.orcid,
                                   relationship_type=p.relationship_type.code) for p in n.people],
        )


class HistoryResponse(BaseModel):
    actor_id: int
    actor_name: str | None = None
    action: str
    from_status: str | None
    to_status: str
    reason: str | None
    at: datetime

    @classmethod
    def from_entity(cls, h: NewsHistory) -> "HistoryResponse":
        return cls(actor_id=h.actor_id, action=h.action, reason=h.reason, at=h.at,
                   from_status=h.from_status.code if h.from_status else None, to_status=h.to_status.code)


class CategoryResponse(BaseModel):
    id: int
    name: str


class CatalogItemResponse(BaseModel):
    id: int
    code: str
    name: str


class CatalogsResponse(BaseModel):
    statuses: list[CatalogItemResponse]
    relevance_levels: list[CatalogItemResponse]
    scope_types: list[CatalogItemResponse]
    person_types: list[CatalogItemResponse]
    relationship_types: list[CatalogItemResponse]
    categories: list[CategoryResponse]

    @classmethod
    def from_catalogs(cls, data: dict[str, list]) -> "CatalogsResponse":
        return cls(**{k: [_catalog_item(x) for x in v] for k, v in data.items()})


def _catalog_item(entity) -> dict:
    return {k: getattr(entity, k) for k in ("id", "code", "name") if hasattr(entity, k)}
