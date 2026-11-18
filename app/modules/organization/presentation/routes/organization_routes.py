from urllib.error import URLError

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from app.modules.organization.application.use_cases.list_organization import ListOrganizationUseCase
from app.modules.organization.application.use_cases.sync_organization import SyncOrganizationUseCase
from app.modules.organization.infrastructure.repositories.metrik_organization_source import MetrikOrganizationSource
from app.modules.organization.infrastructure.repositories.sqlalchemy_organization_repository import (
    SqlAlchemyOrganizationRepository)
from app.modules.organization.presentation.schemas.organization_schemas import (AcademicProgramResponse,
                                                                                FacultyResponse,
                                                                                ResearchCenterResponse, SyncResponse)
from app.modules.iam.domain.services.authorization_service import Principal
from app.modules.iam.presentation.routes.dependencies import require_permission
from app.shared.clock import now
from app.shared.database import get_db

router = APIRouter(prefix="/api/organization", tags=["Dependencias (Metri-K)"])


def get_source() -> MetrikOrganizationSource:  # se sobreescribe en tests
    return MetrikOrganizationSource()


def _list(db: Session) -> ListOrganizationUseCase:
    return ListOrganizationUseCase(SqlAlchemyOrganizationRepository(db))


@router.post("/sync", response_model=SyncResponse)
def sync(db: Session = Depends(get_db), source: MetrikOrganizationSource = Depends(get_source),
         user: Principal = Depends(require_permission("organization.sync"))):
    """Trae facultades, centros y programas de Metri-K y los guarda/actualiza en nuestra BD."""
    try:
        result = SyncOrganizationUseCase(source, SqlAlchemyOrganizationRepository(db)).execute(user)
    except (URLError, TimeoutError, KeyError, ValueError) as e:
        raise HTTPException(502, f"Metri-K no respondió correctamente: {e}")
    return SyncResponse(**result, synced_at=now())


@router.get("/faculties", response_model=list[FacultyResponse])
def faculties(include_inactive: bool = False, db: Session = Depends(get_db)):
    return _list(db).faculties(not include_inactive)


@router.get("/centers", response_model=list[ResearchCenterResponse])
def centers(include_inactive: bool = False, db: Session = Depends(get_db)):
    return _list(db).centers(not include_inactive)


@router.get("/faculties/{faculty_id}/programs", response_model=list[AcademicProgramResponse])
def faculty_programs(faculty_id: int, include_inactive: bool = False, db: Session = Depends(get_db)):
    return _list(db).programs(faculty_id, not include_inactive)


@router.get("/programs", response_model=list[AcademicProgramResponse])
def programs(include_inactive: bool = False, db: Session = Depends(get_db)):
    return _list(db).programs(None, not include_inactive)
