from datetime import date, datetime

from pydantic import BaseModel, Field, field_validator, model_validator

from app.modules.news.application.validators.news_validators import ensure_window, normalize_tags, sanitize_html
from app.shared.clock import as_utc
from app.shared.orcid import normalize_orcid


class ScopeDTO(BaseModel, frozen=True):
    scope_type: str = Field(examples=["research_center"])
    scope_id: int = Field(gt=0)


class PersonDTO(BaseModel, frozen=True):
    person_type: str = Field(examples=["researcher"])
    orcid: str = Field(examples=["0000-0002-1825-0097"], description="ORCID iD (también acepta la URL https://orcid.org/…)")

    @field_validator("orcid")
    @classmethod
    def valid_orcid(cls, v: str) -> str:
        return normalize_orcid(v)
    relationship_type: str = Field(examples=["protagonist"])


class NewsCreateDTO(BaseModel):
    title: str = Field(min_length=3, max_length=250)
    slug: str | None = Field(None, max_length=250)
    summary: str = Field(min_length=1)
    content: str = Field(min_length=1, description="HTML; se sanitiza")
    image_url: str | None = Field(None, max_length=500)
    image_caption: str | None = None
    category_id: int
    relevance_level: str = "medium"
    priority: int = 0
    is_featured: bool = False
    is_pinned: bool = False
    start_at: datetime | None = None
    end_at: datetime | None = None
    tags: list[str] = []
    scopes: list[ScopeDTO] = []   # vacío = noticia institucional sin asociación
    people: list[PersonDTO] = []

    @field_validator("content")
    @classmethod
    def clean_content(cls, v):
        return sanitize_html(v)

    @field_validator("tags", mode="before")
    @classmethod
    def clean_tags(cls, v):
        return normalize_tags(v)

    @field_validator("start_at", "end_at")
    @classmethod
    def to_utc(cls, v):
        return as_utc(v)

    @model_validator(mode="after")
    def check_window(self):
        ensure_window(self.start_at, self.end_at)
        return self


class NewsUpdateDTO(BaseModel):
    """PATCH parcial. Sin reglas de longitud/vigencia aquí a propósito: el caso de uso primero verifica el
    permiso (403) y luego valida el estado fusionado con NewsCreateDTO (422). Así no se revela nada a quien
    no tiene autoridad sobre la noticia, y la vigencia se compara contra lo ya guardado."""
    title: str | None = Field(None, description="3 a 250 caracteres")
    slug: str | None = None
    summary: str | None = None
    content: str | None = Field(None, description="HTML; se sanitiza")
    image_url: str | None = None
    image_caption: str | None = None
    category_id: int | None = None
    relevance_level: str | None = None
    priority: int | None = None
    is_featured: bool | None = None
    is_pinned: bool | None = None
    start_at: datetime | None = None
    end_at: datetime | None = None
    tags: list[str] | None = None
    scopes: list[ScopeDTO] | None = None
    people: list[PersonDTO] | None = None

    @field_validator("content")
    @classmethod
    def clean_content(cls, v):
        if v is not None:
            return sanitize_html(v)
        return v

    @field_validator("tags", mode="before")
    @classmethod
    def clean_tags(cls, v):
        if v is not None:
            return normalize_tags(v)
        return v

    @field_validator("start_at", "end_at")
    @classmethod
    def to_utc(cls, v):
        if v is not None:
            return as_utc(v)
        return v


class NewsFilterDTO(BaseModel):
    public: bool = Field(False, description="Fuerza la vista pública aunque haya sesión (portada del portal)")
    category_id: int | None = None
    scope_type: str | None = None
    scope_id: int | None = None
    person_type: str | None = None
    orcid: str | None = Field(None, description="Noticias donde aparece este ORCID")

    @field_validator("orcid")
    @classmethod
    def valid_orcid(cls, v: str | None) -> str | None:
        return normalize_orcid(v) if v else None
    relevance_level: str | None = None
    status: str | None = None
    tag: str | None = None
    featured: bool | None = None
    start_date: date | None = None
    end_date: date | None = None
    limit: int = Field(20, ge=1, le=100)
    offset: int = Field(0, ge=0)


class RejectDTO(BaseModel):
    reason: str = Field(min_length=5)


class ScheduleDTO(BaseModel):
    start_at: datetime

    @field_validator("start_at")
    @classmethod
    def to_utc(cls, v):
        return as_utc(v)


class CategoryCreateDTO(BaseModel):
    name: str = Field(min_length=2, max_length=100)
