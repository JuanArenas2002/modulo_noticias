from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from app.modules.news.application.dto.news_dto import CategoryCreateDTO
from app.modules.news.application.use_cases.manage_catalogs import CreateCategoryUseCase, ListCatalogsUseCase
from app.modules.news.infrastructure.repositories.sqlalchemy_catalog_repository import SqlAlchemyCatalogRepository
from app.modules.news.presentation.schemas.news_schemas import CatalogsResponse, CategoryResponse
from app.modules.iam.domain.services.authorization_service import Principal
from app.modules.iam.presentation.routes.dependencies import require_permission
from app.shared.database import get_db

router = APIRouter(prefix="/api/news", tags=["Catálogos"])


@router.get("/catalogs", response_model=CatalogsResponse)
def list_catalogs(db: Session = Depends(get_db)):
    """Todos los catálogos, para poblar selects en el frontend."""
    return CatalogsResponse.from_catalogs(ListCatalogsUseCase(SqlAlchemyCatalogRepository(db)).execute())


@router.post("/categories", response_model=CategoryResponse, status_code=201)
def create_category(body: CategoryCreateDTO, db: Session = Depends(get_db),
                    user: Principal = Depends(require_permission("news.manage_categories"))):
    c = CreateCategoryUseCase(SqlAlchemyCatalogRepository(db)).execute(body, user)
    return CategoryResponse(id=c.id, name=c.name)
