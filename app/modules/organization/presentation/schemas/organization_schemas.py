from datetime import date, datetime

from pydantic import BaseModel, ConfigDict


class _Out(BaseModel):
    model_config = ConfigDict(from_attributes=True)


class FacultyResponse(_Out):
    id: int
    name: str
    is_active: bool
    synced_at: datetime  # última sincronización con Metri-K


class ResearchCenterResponse(_Out):
    id: int
    code: str | None
    name: str
    acronym: str | None
    is_active: bool
    date_created: date | None
    date_closed: date | None
    synced_at: datetime  # última sincronización con Metri-K


class AcademicProgramResponse(_Out):
    id: int
    name: str
    faculty_id: int
    code_snies: str | None
    level_academic: str | None
    level_education: str | None
    modality: str | None
    is_active: bool
    synced_at: datetime  # última sincronización con Metri-K


class SyncResponse(BaseModel):
    faculties: int
    faculties_deactivated: int
    centers: int
    centers_deactivated: int
    programs: int
    programs_deactivated: int
    synced_at: datetime
