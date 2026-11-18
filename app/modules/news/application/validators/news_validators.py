"""Validaciones de entrada: puras (formato) y de referencias (contra catálogos y tablas de origen)."""
from datetime import datetime

import nh3

from app.modules.news.domain.entities.catalogs import PersonType, RelationshipType, RelevanceLevel, ScopeType
from app.modules.news.domain.entities.news import NewsPerson, NewsScope, NewsTag
from app.modules.news.domain.repositories.catalog_repository import CatalogRepository
from app.shared.clock import as_utc
from app.shared.exceptions import InvalidDataError


def sanitize_html(html: str) -> str:
    return nh3.clean(html)


def normalize_tags(tags) -> list[str]:
    return sorted({str(t).strip().lower()[:60] for t in tags} - {""})


def ensure_window(start_at: datetime | None, end_at: datetime | None) -> None:
    if start_at and end_at and as_utc(end_at) < as_utc(start_at):
        raise ValueError("end_at no puede ser anterior a start_at")


def resolve_code(catalogs: CatalogRepository, model: type, code: str):
    if (item := catalogs.by_code(model, code)) is None:
        raise InvalidDataError(f"{model.__name__} '{code}' no existe")
    return item


def ensure_reference(catalogs: CatalogRepository, kind, ref_id: int) -> None:
    """Integridad del vínculo polimórfico: valida en la tabla que indica el catálogo (source_table)."""
    if kind.source_table and not catalogs.reference_exists(kind.source_table, ref_id):
        raise InvalidDataError(f"{kind.code} {ref_id} no existe")


def resolve_references(dto, catalogs: CatalogRepository) -> dict:
    """Convierte códigos del DTO en entidades de catálogo y vínculos de dominio."""
    if not catalogs.category_exists(dto.category_id):
        raise InvalidDataError(f"category_id {dto.category_id} no existe")
    scopes = []
    for s in dto.scopes:
        scope_type = resolve_code(catalogs, ScopeType, s.scope_type)
        ensure_reference(catalogs, scope_type, s.scope_id)
        scopes.append(NewsScope(scope_type=scope_type, scope_id=s.scope_id))
    people = []
    for p in dto.people:
        person_type = resolve_code(catalogs, PersonType, p.person_type)
        people.append(NewsPerson(person_type=person_type, orcid=p.orcid,  # ORCID ya validado en el DTO
                                 relationship_type=resolve_code(catalogs, RelationshipType, p.relationship_type)))
    return {
        "relevance_level": resolve_code(catalogs, RelevanceLevel, dto.relevance_level),
        "scopes": scopes,
        "people": people,
        "tags": [NewsTag(tag=t) for t in dto.tags],
    }
