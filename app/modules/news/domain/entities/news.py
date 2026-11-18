from dataclasses import dataclass, field
from datetime import datetime

from app.modules.news.domain.entities.catalogs import NewsStatus, PersonType, RelationshipType, RelevanceLevel, ScopeType
from app.shared.clock import as_utc, now
from app.shared.exceptions import ConflictError, InvalidDataError

UPDATE, CURATE = "news.update", "news.curate"  # permisos IAM que usa la edición
# Campos que se pueden curar (news.curate) aunque la noticia ya no sea editable (revisada/publicada).
FREE_FIELDS = frozenset({"priority", "is_featured", "is_pinned", "relevance_level", "end_at", "tags", "scopes", "people"})


@dataclass(kw_only=True, eq=False)
class NewsScope:
    """Asociación organizacional polimórfica: (tipo, id) en la tabla del tipo."""
    id: int | None = None
    scope_type: ScopeType
    scope_id: int
    created_at: datetime = field(default_factory=now)

    @property
    def key(self):
        return self.scope_type.id, self.scope_id


@dataclass(kw_only=True, eq=False)
class NewsPerson:
    """Persona identificada por su ORCID iD. No se guardan datos personales: el perfil público vive en ORCID."""
    id: int | None = None
    person_type: PersonType
    orcid: str
    relationship_type: RelationshipType
    created_at: datetime = field(default_factory=now)

    @property
    def key(self):
        return self.person_type.id, self.orcid, self.relationship_type.id


@dataclass(kw_only=True, eq=False)
class NewsTag:
    tag: str

    @property
    def key(self):
        return self.tag


@dataclass(kw_only=True, eq=False)
class NewsHistory:
    id: int | None = None
    news_id: int
    actor_id: int
    action: str
    from_status: NewsStatus | None
    to_status: NewsStatus
    reason: str | None = None
    at: datetime = field(default_factory=now)


@dataclass(kw_only=True, eq=False)
class News:
    id: int | None = None
    # Editorial
    title: str
    slug: str
    summary: str
    content: str
    image_url: str | None = None
    image_caption: str | None = None
    category_id: int
    author_id: int
    # Relevancia
    relevance_level: RelevanceLevel
    priority: int = 0
    is_featured: bool = False
    is_pinned: bool = False
    # Vigencia
    start_at: datetime | None = None
    end_at: datetime | None = None
    published_at: datetime | None = None
    created_at: datetime = field(default_factory=now)
    updated_at: datetime = field(default_factory=now)
    # Estado
    status: NewsStatus
    # Vínculos opcionales (0..n)
    scopes: list[NewsScope] = field(default_factory=list)
    people: list[NewsPerson] = field(default_factory=list)
    tags: list[NewsTag] = field(default_factory=list)

    def ensure_valid_window(self) -> None:
        if self.start_at and self.end_at and as_utc(self.end_at) < as_utc(self.start_at):
            raise InvalidDataError("end_at no puede ser anterior a start_at")

    @property
    def scope_keys(self) -> list[tuple[int, int]]:
        return [s.key for s in self.scopes]

    def edit_permission(self, fields: set[str]) -> str:
        """Permiso necesario para cambiar `fields` en el estado actual."""
        if self.status.is_editable:
            return UPDATE
        if fields - FREE_FIELDS:
            raise ConflictError(f"En estado '{self.status.code}' solo se puede cambiar: {sorted(FREE_FIELDS)}")
        return CURATE

    def replace_links(self, scopes: list[NewsScope], people: list[NewsPerson], tags: list[NewsTag]) -> None:
        """Reemplaza vínculos reutilizando las filas que ya existen (sin duplicados ni choque con UNIQUE)."""
        self.scopes = _merge(self.scopes, scopes)
        self.people = _merge(self.people, people)
        self.tags = _merge(self.tags, tags)


def _merge(current: list, incoming: list) -> list:
    existing = {x.key: x for x in current}
    result = {}
    for item in incoming:
        result.setdefault(item.key, existing.get(item.key, item))
    return list(result.values())
