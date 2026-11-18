from dataclasses import dataclass
from datetime import date, datetime
from typing import Protocol

from app.modules.news.domain.entities.news import News, NewsHistory


@dataclass
class NewsQuery:
    """Criterios ya resueltos a ids. public_at != None => solo noticias visibles en ese instante."""
    public_at: datetime | None = None
    visible_scopes: set[tuple[int, int]] | None = None  # interno con alcance: noticias con alguna de estas
    status_id: int | None = None
    category_id: int | None = None
    relevance_level_id: int | None = None
    scope_type_id: int | None = None
    scope_id: int | None = None
    person_type_id: int | None = None
    orcid: str | None = None
    tag: str | None = None
    featured: bool | None = None
    start_date: date | None = None
    end_date: date | None = None
    limit: int = 20
    offset: int = 0


class NewsRepository(Protocol):
    def get(self, news_id: int) -> News | None: ...
    def find_by_ref(self, ref: str, public_at: datetime | None) -> News | None: ...
    def slug_exists(self, slug: str, exclude_id: int | None = None) -> bool: ...
    def list(self, query: NewsQuery) -> list[News]: ...
    def add(self, news: News) -> None: ...
    def add_history(self, entry: NewsHistory) -> None: ...
    def history(self, news_id: int) -> list[NewsHistory]: ...
    def commit(self) -> None: ...
