from datetime import datetime, timedelta

from sqlalchemy import and_, exists, false, or_, select, tuple_
from sqlalchemy.orm import Session

from app.modules.news.domain.entities.catalogs import NewsStatus
from app.modules.news.domain.entities.news import News, NewsHistory, NewsPerson, NewsScope, NewsTag
from app.modules.news.domain.repositories.news_repository import NewsQuery


def visible_at(at: datetime):
    """Visibilidad pública = estado público (catálogo) + vigencia. Vencer no cambia el estado."""
    return and_(
        News.status.has(NewsStatus.is_public.is_(True)),
        News.published_at.is_not(None), News.published_at <= at,
        or_(News.start_at.is_(None), News.start_at <= at),
        or_(News.end_at.is_(None), News.end_at >= at),
    )


class SqlAlchemyNewsRepository:
    def __init__(self, session: Session):
        self.s = session

    def get(self, news_id: int) -> News | None:
        return self.s.get(News, news_id)

    def find_by_ref(self, ref: str, public_at: datetime | None) -> News | None:
        q = select(News).where(News.id == int(ref) if ref.isdigit() else News.slug == ref)
        if public_at:
            q = q.where(visible_at(public_at))
        return self.s.scalar(q)

    def slug_exists(self, slug: str, exclude_id: int | None = None) -> bool:
        return bool(self.s.scalar(select(exists().where(News.slug == slug, News.id != exclude_id))))

    def list(self, q: NewsQuery) -> list[News]:
        stmt = select(News)
        if q.public_at:
            stmt = stmt.where(visible_at(q.public_at))
        elif q.status_id:
            stmt = stmt.where(News.status_id == q.status_id)
        else:
            stmt = stmt.where(News.status.has(NewsStatus.is_archived.is_(False)))
        if q.public_at is None and q.visible_scopes is not None:
            # Sin alcance institucional: solo noticias con alguna dependencia autorizada (vacío => ninguna).
            stmt = stmt.where(News.scopes.any(
                tuple_(NewsScope.scope_type_id, NewsScope.scope_id).in_(sorted(q.visible_scopes)))
                if q.visible_scopes else false())

        equals = {News.category_id: q.category_id, News.relevance_level_id: q.relevance_level_id,
                  News.is_featured: q.featured}
        stmt = stmt.where(*(col == v for col, v in equals.items() if v is not None))
        if q.tag:
            stmt = stmt.where(News.tags.any(NewsTag.tag == q.tag))
        for relation, values in ((News.scopes, {NewsScope.scope_type_id: q.scope_type_id, NewsScope.scope_id: q.scope_id}),
                                 (News.people, {NewsPerson.person_type_id: q.person_type_id,
                                                NewsPerson.orcid: q.orcid})):
            if conds := [col == v for col, v in values.items() if v is not None]:
                stmt = stmt.where(relation.any(and_(*conds)))
        if q.start_date:
            stmt = stmt.where(News.published_at >= q.start_date)
        if q.end_date:
            stmt = stmt.where(News.published_at < q.end_date + timedelta(days=1))

        stmt = stmt.order_by(News.is_pinned.desc(), News.priority.desc(),
                             News.published_at.desc().nulls_last(), News.id.desc())
        return list(self.s.scalars(stmt.limit(q.limit).offset(q.offset)).unique())

    def add(self, news: News) -> None:
        self.s.add(news)
        self.s.flush()  # asigna id para el historial

    def add_history(self, entry: NewsHistory) -> None:
        self.s.add(entry)

    def history(self, news_id: int) -> list[NewsHistory]:
        return list(self.s.scalars(select(NewsHistory).where(NewsHistory.news_id == news_id)
                                   .order_by(NewsHistory.id)).unique())

    def commit(self) -> None:
        self.s.commit()
