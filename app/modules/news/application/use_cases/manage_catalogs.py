"""Casos de uso de catálogos: consultarlos (para los selects del frontend) y crear categorías."""
from app.modules.iam.domain.services.authorization_service import Principal
from app.modules.news.application.dto.news_dto import CategoryCreateDTO
from app.modules.news.domain.entities.catalogs import (Category, NewsStatus, PersonType, RelationshipType,
                                                       RelevanceLevel, ScopeType)
from app.modules.news.domain.repositories.catalog_repository import CatalogRepository
from app.shared.exceptions import ConflictError

CATALOGS = {
    "statuses": NewsStatus,
    "relevance_levels": RelevanceLevel,
    "scope_types": ScopeType,
    "person_types": PersonType,
    "relationship_types": RelationshipType,
    "categories": Category,
}


class ListCatalogsUseCase:
    def __init__(self, catalogs: CatalogRepository):
        self.catalogs = catalogs

    def execute(self) -> dict[str, list]:
        return {name: self.catalogs.all(model) for name, model in CATALOGS.items()}


class CreateCategoryUseCase:
    def __init__(self, catalogs: CatalogRepository):
        self.catalogs = catalogs

    def execute(self, dto: CategoryCreateDTO, user: Principal) -> Category:
        user.ensure_global("news.manage_categories")  # las categorías son de toda la institución
        if any(c.name.lower() == dto.name.lower() for c in self.catalogs.all(Category)):
            raise ConflictError(f"La categoría '{dto.name}' ya existe")
        category = Category(name=dto.name)
        self.catalogs.add_category(category)
        self.catalogs.commit()
        return category
