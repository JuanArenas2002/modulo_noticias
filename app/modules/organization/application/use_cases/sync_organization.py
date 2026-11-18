"""Caso de uso: sincronizar facultades, centros y programas desde Metri-K a nuestra BD.

Upsert por id de Metri-K. Lo que ya no viene en la fuente se marca inactivo (no se borra:
noticias antiguas pueden seguir asociadas). Todo o nada: si Metri-K falla, no se toca la BD.
"""
from app.modules.iam.domain.services.authorization_service import Principal
from app.modules.organization.domain.entities.organization import AcademicProgram, Faculty, ResearchCenter
from app.modules.organization.domain.repositories.organization_repository import (OrganizationRepository,
                                                                                  OrganizationSource)


class SyncOrganizationUseCase:
    def __init__(self, source: OrganizationSource, repo: OrganizationRepository):
        self.source, self.repo = source, repo

    def execute(self, user: Principal) -> dict[str, int]:
        user.ensure_global("organization.sync")  # afecta a toda la institución
        # Primero leer todo de la fuente; si algo falla aquí, la BD queda intacta.
        faculties = self.source.faculties()
        centers = self.source.centers()
        programs = [p for f in faculties for p in self.source.programs(f.id)]

        result = {}
        for name, model, items in (("faculties", Faculty, faculties), ("centers", ResearchCenter, centers),
                                   ("programs", AcademicProgram, programs)):
            self.repo.upsert(items)
            result[name] = len(items)
            result[f"{name}_deactivated"] = self.repo.deactivate_missing(model, {i.id for i in items})
        self.repo.commit()
        return result
