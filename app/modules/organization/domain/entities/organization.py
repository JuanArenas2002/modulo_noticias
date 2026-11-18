"""Dependencias institucionales replicadas desde Metri-K. `id` = id en Metri-K (fuente de verdad)."""
from dataclasses import dataclass, field
from datetime import date, datetime

from app.shared.clock import now


@dataclass(kw_only=True, eq=False)
class OrgUnitType:
    """Tipo de unidad organizacional (institución, facultad, programa...). Compartido por noticias e IAM.

    La jerarquía es dato: un programa pertenece a una facultad vía academic_programs.faculty_id
    => parent_type_id = facultad, parent_column = "faculty_id". Permite heredar permisos hacia abajo.
    """
    id: int | None = None
    code: str
    name: str
    source_table: str | None = None   # tabla local donde existe la unidad (None = no se valida)
    parent_type_id: int | None = None
    parent_column: str | None = None  # columna en source_table que apunta al padre
    is_institutional: bool = False    # alcance = toda la institución (solo lo cubren permisos globales)


@dataclass(kw_only=True, eq=False)
class Faculty:
    id: int
    name: str
    is_active: bool = True
    synced_at: datetime = field(default_factory=now)


@dataclass(kw_only=True, eq=False)
class ResearchCenter:
    id: int
    code: str | None = None
    name: str
    acronym: str | None = None
    is_active: bool = True
    date_created: date | None = None
    date_closed: date | None = None
    synced_at: datetime = field(default_factory=now)


@dataclass(kw_only=True, eq=False)
class AcademicProgram:
    id: int
    name: str
    faculty_id: int
    code_snies: str | None = None
    level_academic: str | None = None
    level_education: str | None = None
    modality: str | None = None
    is_active: bool = True
    synced_at: datetime = field(default_factory=now)
