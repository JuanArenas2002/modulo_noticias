from app.modules.organization.domain.entities import organization as o
from app.modules.organization.infrastructure.models import tables as t
from app.shared.database import mapper_registry

_started = False


def start_mappers() -> None:
    global _started
    if _started:
        return
    _started = True
    mapper_registry.map_imperatively(o.OrgUnitType, t.org_unit_types)
    mapper_registry.map_imperatively(o.Faculty, t.faculties)
    mapper_registry.map_imperatively(o.ResearchCenter, t.research_centers)
    mapper_registry.map_imperatively(o.AcademicProgram, t.academic_programs)
