"""Catálogos: todo valor "tipo enum" vive en su propia tabla. Agregar un valor = insertar una fila."""
from dataclasses import dataclass

from app.modules.organization.domain.entities.organization import OrgUnitType as ScopeType  # noqa: F401  (tipo compartido)


@dataclass(kw_only=True, eq=False)
class NewsStatus:
    id: int | None = None
    code: str
    name: str
    is_initial: bool = False   # estado con el que nace una noticia
    is_public: bool = False    # visible al público si además está vigente
    is_editable: bool = False  # el contenido editorial se puede modificar
    is_archived: bool = False  # fuera de listados (incluso internos) salvo filtro explícito


@dataclass(kw_only=True, eq=False)
class StatusTransition:
    """Flujo editorial como datos: qué acción mueve de qué estado a cuál y quién puede hacerlo."""
    id: int | None = None
    action: str
    from_status: NewsStatus
    to_status: NewsStatus
    required_permission: str  # código IAM, p.ej. news.publish
    requires_reason: bool = False


@dataclass(kw_only=True, eq=False)
class RelevanceLevel:
    id: int | None = None
    code: str
    name: str
    weight: int = 0  # mayor = más relevante; sirve para ordenar


@dataclass(kw_only=True, eq=False)
class PersonType:
    id: int | None = None
    code: str
    name: str
    source_table: str | None = None


@dataclass(kw_only=True, eq=False)
class RelationshipType:
    id: int | None = None
    code: str
    name: str


@dataclass(kw_only=True, eq=False)
class Category:
    id: int | None = None
    name: str
