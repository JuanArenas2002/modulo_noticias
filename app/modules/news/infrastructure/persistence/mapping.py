"""Mapeo imperativo: las entidades de dominio (dataclasses puras) se persisten sin heredar de SQLAlchemy."""
from sqlalchemy.orm import relationship

from app.modules.news.domain.entities import catalogs as c
from app.modules.news.domain.entities import news as n
from app.modules.news.infrastructure.models import tables as t
from app.shared.database import mapper_registry

_started = False


def start_mappers() -> None:
    global _started
    if _started:
        return
    _started = True
    m = mapper_registry.map_imperatively

    m(c.NewsStatus, t.news_statuses)
    m(c.RelevanceLevel, t.news_relevance_levels)
    m(c.PersonType, t.news_person_types)
    m(c.RelationshipType, t.news_relationship_types)
    m(c.Category, t.news_categories)
    m(c.StatusTransition, t.news_status_transitions, properties={
        "from_status": relationship(c.NewsStatus, foreign_keys=t.news_status_transitions.c.from_status_id, lazy="joined"),
        "to_status": relationship(c.NewsStatus, foreign_keys=t.news_status_transitions.c.to_status_id, lazy="joined"),
    })

    m(n.NewsScope, t.news_scopes, properties={"scope_type": relationship(c.ScopeType, lazy="joined")})
    m(n.NewsPerson, t.news_people, properties={
        "person_type": relationship(c.PersonType, lazy="joined"),
        "relationship_type": relationship(c.RelationshipType, lazy="joined"),
    })
    m(n.NewsTag, t.news_tags)
    m(n.NewsHistory, t.news_history, properties={
        "from_status": relationship(c.NewsStatus, foreign_keys=t.news_history.c.from_status_id, lazy="joined"),
        "to_status": relationship(c.NewsStatus, foreign_keys=t.news_history.c.to_status_id, lazy="joined"),
    })
    m(n.News, t.news, properties={
        "status": relationship(c.NewsStatus, lazy="joined"),
        "relevance_level": relationship(c.RelevanceLevel, lazy="joined"),
        "scopes": relationship(n.NewsScope, cascade="all, delete-orphan", lazy="selectin"),
        "people": relationship(n.NewsPerson, cascade="all, delete-orphan", lazy="selectin"),
        "tags": relationship(n.NewsTag, cascade="all, delete-orphan", lazy="selectin"),
    })
