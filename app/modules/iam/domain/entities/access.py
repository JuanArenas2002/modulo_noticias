"""Autorización: roles dinámicos, permisos granulares y asignaciones con alcance organizacional."""
from dataclasses import dataclass, field
from datetime import datetime

from app.modules.organization.domain.entities.organization import OrgUnitType
from app.shared.clock import now


@dataclass(kw_only=True, eq=False)
class Permission:
    id: int | None = None
    code: str  # modulo.recurso.accion, p.ej. news.publish
    name: str
    description: str | None = None
    module: str
    resource: str
    action: str
    is_active: bool = True
    created_at: datetime = field(default_factory=now)


@dataclass(kw_only=True, eq=False)
class Role:
    id: int | None = None
    code: str
    name: str
    description: str | None = None
    is_active: bool = True
    created_at: datetime = field(default_factory=now)
    updated_at: datetime = field(default_factory=now)
    permissions: list[Permission] = field(default_factory=list)


@dataclass(kw_only=True, eq=False)
class RoleAssignment:
    """Rol de un usuario en un alcance. scope_type=None => institucional (todas las dependencias)."""
    id: int | None = None
    user_id: int
    role: Role
    scope_type: OrgUnitType | None = None
    scope_id: int | None = None
    assigned_by: int | None = None
    assigned_at: datetime = field(default_factory=now)
    revoked_at: datetime | None = None
    revoked_by: int | None = None
    revoke_reason: str | None = None

    @property
    def is_active(self) -> bool:
        return self.revoked_at is None and self.role.is_active
