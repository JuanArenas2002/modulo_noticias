"""Consultas sobre la copia local (para los selects de asociación en el frontend)."""
from app.modules.organization.domain.repositories.organization_repository import OrganizationRepository


class ListOrganizationUseCase:
    def __init__(self, repo: OrganizationRepository):
        self.repo = repo

    def faculties(self, only_active: bool = True):
        return self.repo.faculties(only_active)

    def centers(self, only_active: bool = True):
        return self.repo.centers(only_active)

    def programs(self, faculty_id: int | None = None, only_active: bool = True):
        return self.repo.programs(faculty_id, only_active)
