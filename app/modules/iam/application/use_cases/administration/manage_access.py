"""Gestión de acceso: roles, permisos, asignaciones (con alcance) y consulta de auditoría.

Anti-escalamiento en todo punto donde se otorga poder:
- asignar/revocar un rol: users.manage_roles + cada permiso del rol, en ese alcance (can_assign);
- crear un rol o agregarle permisos: tener cada permiso agregado con alcance institucional.
Anti-bloqueo: nunca queda la plataforma sin alguien con permissions.manage institucional.
"""
from app.modules.iam.application.dto.admin_dto import (AssignRoleDTO, AuditFilterDTO, PermissionCreateDTO,
                                                       PermissionFilterDTO, PermissionUpdateDTO, RoleCreateDTO,
                                                       RoleFilterDTO, RoleUpdateDTO)
from app.modules.iam.application.use_cases.administration.base import OWNER_PERMISSION, AdminUseCase
from app.modules.iam.domain.entities.access import Permission, Role, RoleAssignment
from app.modules.iam.domain.entities.audit import AuditLog
from app.modules.iam.domain.services.authorization_service import can_assign
from app.shared.clock import now
from app.shared.exceptions import ConflictError, ForbiddenError, InvalidDataError, NotFoundError


def _codes(role: Role) -> list[str]:
    return [p.code for p in role.permissions if p.is_active]


# ---------- asignaciones ----------
class RoleAssignmentsUseCase(AdminUseCase):
    def list(self, user_id: int, active_only: bool) -> list[RoleAssignment]:
        if user_id != self.principal.user_id and not self.principal.can_any("users.view"):
            raise ForbiddenError("Requiere 'users.view'")
        self.target(user_id)
        return self.admin.assignments(user_id, active_only)

    def _scope(self, dto: AssignRoleDTO):
        if dto.scope_type is None:
            return None, None
        unit_type = self.admin.unit_type(dto.scope_type)
        if unit_type is None:
            raise InvalidDataError(f"Tipo de alcance '{dto.scope_type}' no existe")
        if unit_type.is_institutional:
            return None, None  # "institución" = alcance global
        if not self.admin.unit_exists(unit_type, dto.scope_id):
            raise InvalidDataError(f"{dto.scope_type} {dto.scope_id} no existe")
        return unit_type, (unit_type.id, dto.scope_id)

    def assign(self, user_id: int, dto: AssignRoleDTO) -> RoleAssignment:
        user = self.target(user_id)
        role = self.admin.role_by_code(dto.role)
        if role is None or not role.is_active:
            raise InvalidDataError(f"Rol '{dto.role}' no existe o está inactivo")
        unit_type, scope = self._scope(dto)
        if not can_assign(self.principal, _codes(role), scope):
            self.audit("iam.role.assign", "user", user.id, result="denied", role=role.code)
            self.uow.commit()
            raise ForbiddenError("No puedes asignar un rol con permisos que no tienes en ese alcance")
        scope_id = scope[1] if scope else None
        key = (role.id, scope)
        existing = {(a.role.id, (a.scope_type.id, a.scope_id) if a.scope_type else None)
                    for a in self.admin.assignments(user.id, active_only=True)}
        if key in existing:
            raise ConflictError("El usuario ya tiene ese rol en ese alcance")
        assignment = RoleAssignment(user_id=user.id, role=role, scope_type=unit_type, scope_id=scope_id,
                                    assigned_by=self.principal.user_id, assigned_at=now())
        self.admin.add_assignment(assignment)
        self.audit("iam.role.assigned", "role_assignment", assignment.id, user_id=user.id, role=role.code,
                   scope_type=dto.scope_type if scope else None, scope_id=scope_id)
        self.uow.commit()
        return assignment

    def revoke(self, user_id: int, assignment_id: int, reason: str | None) -> RoleAssignment:
        a = self.admin.assignment_of(user_id, assignment_id)
        if a is None:
            raise NotFoundError("Asignación no encontrada")
        if a.revoked_at is not None:
            raise ConflictError("La asignación ya está revocada")
        scope = (a.scope_type.id, a.scope_id) if a.scope_type else None
        if not can_assign(self.principal, _codes(a.role), scope):
            raise ForbiddenError("No puedes revocar un rol con permisos que no tienes en ese alcance")
        a.revoked_at, a.revoked_by, a.revoke_reason = now(), self.principal.user_id, reason
        self.ensure_owner_remains()
        self.audit("iam.role.revoked", "role_assignment", a.id, user_id=user_id, role=a.role.code, reason=reason)
        self.uow.commit()
        return a


# ---------- roles ----------
class RolesUseCase(AdminUseCase):
    def _view(self):
        if not self.principal.can_any("roles.view") and not self.principal.can_any("users.manage_roles"):
            raise ForbiddenError("Requiere 'roles.view'")

    def list(self, f: RoleFilterDTO) -> tuple[list[Role], int]:
        self._view()
        return self.admin.search_roles(f)

    def get(self, role_id: int) -> Role:
        self._view()
        if (role := self.admin.role(role_id)) is None:
            raise NotFoundError("Rol no encontrado")
        return role

    def _permissions(self, codes: list[str]) -> list[Permission]:
        wanted = set(codes)
        found = self.admin.permissions_by_codes(wanted)
        if missing := wanted - {p.code for p in found}:
            raise InvalidDataError(f"Permisos inexistentes: {sorted(missing)}")
        if not_held := [p.code for p in found if not self.principal.is_global(p.code)]:
            raise ForbiddenError(f"No puedes otorgar permisos que no tienes: {sorted(not_held)}")
        return found

    def create(self, dto: RoleCreateDTO) -> Role:
        self.principal.ensure_global("roles.manage")
        if self.admin.role_by_code(dto.code):
            raise ConflictError(f"El rol '{dto.code}' ya existe")
        role = Role(code=dto.code, name=dto.name, description=dto.description,
                    permissions=self._permissions(dto.permissions))
        self.admin.add(role)
        self.audit("iam.role.created", "role", role.id, code=role.code, permissions=sorted(dto.permissions))
        self.uow.commit()
        return role

    def update(self, role_id: int, dto: RoleUpdateDTO) -> Role:
        self.principal.ensure_global("roles.manage")
        role = self.get(role_id)
        changes = dto.model_dump(exclude_unset=True, exclude_none=True)
        for field, value in changes.items():
            setattr(role, field, value)
        role.updated_at = now()
        if changes.get("is_active") is False:
            self.ensure_owner_remains()
        self.audit("iam.role.updated", "role", role.id, fields=sorted(changes))
        self.uow.commit()
        return role

    def set_permissions(self, role_id: int, codes: list[str]) -> Role:
        self.principal.ensure_global("roles.manage")
        role = self.get(role_id)
        before = {p.code for p in role.permissions}
        added = set(codes) - before
        role.permissions = [p for p in role.permissions if p.code in codes] + self._permissions(sorted(added))
        role.updated_at = now()
        self.ensure_owner_remains()
        self.audit("iam.role.permissions_updated", "role", role.id, added=sorted(added),
                   removed=sorted(before - set(codes)))
        self.uow.commit()
        return role

    def delete(self, role_id: int) -> None:
        """Eliminación lógica (las asignaciones históricas lo referencian). No si está en uso."""
        self.principal.ensure_global("roles.manage")
        role = self.get(role_id)
        if (in_use := self.admin.active_assignment_count(role.id)):
            raise ConflictError(f"El rol está asignado a {in_use} usuario(s); revoca esas asignaciones primero")
        role.is_active, role.updated_at = False, now()
        self.audit("iam.role.deleted", "role", role.id, code=role.code)
        self.uow.commit()


# ---------- permisos ----------
class PermissionsUseCase(AdminUseCase):
    def _view(self):
        if not self.principal.can_any("permissions.view") and not self.principal.can_any("roles.manage"):
            raise ForbiddenError("Requiere 'permissions.view'")

    def list(self, f: PermissionFilterDTO) -> tuple[list[Permission], int]:
        self._view()
        return self.admin.search_permissions(f)

    def get(self, permission_id: int) -> Permission:
        self._view()
        if (p := self.admin.permission(permission_id)) is None:
            raise NotFoundError("Permiso no encontrado")
        return p

    def create(self, dto: PermissionCreateDTO) -> Permission:
        """Registrar el permiso de un módulo nuevo. Luego se agrega a roles con PUT /roles/{id}/permissions."""
        self.principal.ensure_global("permissions.manage")
        if self.admin.permissions_by_codes({dto.code}):
            raise ConflictError(f"El permiso '{dto.code}' ya existe")
        p = Permission(**dto.model_dump(), created_at=now())
        self.admin.add(p)
        self.audit("iam.permission.created", "permission", p.id, code=p.code)
        self.uow.commit()
        return p

    def update(self, permission_id: int, dto: PermissionUpdateDTO) -> Permission:
        self.principal.ensure_global("permissions.manage")
        p = self.get(permission_id)
        changes = dto.model_dump(exclude_unset=True, exclude_none=True)
        if changes.get("is_active") is False and p.code == OWNER_PERMISSION:
            raise ConflictError(f"'{OWNER_PERMISSION}' no se puede desactivar")
        for field, value in changes.items():
            setattr(p, field, value)
        self.audit("iam.permission.updated", "permission", p.id, code=p.code, fields=sorted(changes))
        self.uow.commit()
        return p


# ---------- auditoría ----------
class AuditQueryUseCase(AdminUseCase):
    def execute(self, f: AuditFilterDTO) -> tuple[list[AuditLog], int]:
        self.principal.ensure_global("audit.view")
        return self.admin.search_audit(f)

    def user_activity(self, user_id: int, f: AuditFilterDTO) -> tuple[list[AuditLog], int]:
        self.principal.ensure_global("audit.view")
        self.target(user_id)
        return self.admin.search_audit(f.model_copy(update={"actor_id": user_id}))
