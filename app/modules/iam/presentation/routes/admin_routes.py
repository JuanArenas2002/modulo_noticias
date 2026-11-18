"""Administración IAM: usuarios, roles, permisos, asignaciones y auditoría.

Cada ruta exige sesión (y CSRF si muta) vía `current_principal`; el permiso fino (y su alcance)
lo decide el caso de uso. Ninguna ruta depende del nombre de un rol.
"""
from typing import Annotated

from fastapi import APIRouter, BackgroundTasks, Depends, Query, status
from sqlalchemy.orm import Session

from app.modules.iam.application.dto.admin_dto import (AssignRoleDTO, AuditFilterDTO, PermissionCreateDTO,
                                                       PermissionFilterDTO, PermissionUpdateDTO, ReasonDTO,
                                                       RoleCreateDTO, RoleFilterDTO, RolePermissionsDTO,
                                                       RoleUpdateDTO, SetPasswordDTO, UserCreateDTO, UserFilterDTO, UserUpdateDTO)
from app.modules.iam.application.use_cases.administration.manage_access import (AuditQueryUseCase,
                                                                                PermissionsUseCase,
                                                                                RoleAssignmentsUseCase, RolesUseCase)
from app.modules.iam.application.use_cases.administration.manage_users import (ChangeUserStatusUseCase,
                                                                               CreateUserUseCase, DeleteUserUseCase,
                                                                               GetUserUseCase, ListUsersUseCase,
                                                                               ResendInvitationUseCase,
                                                                               SetUserPasswordUseCase,
                                                                               UnlockUserUseCase,
                                                                               UpdateUserUseCase,
                                                                               UserIdentitiesUseCase,
                                                                               UserSessionsUseCase)
from app.modules.iam.application.use_cases.authentication.common import OutgoingMail
from app.modules.iam.application.use_cases.authorization.load_principal import LoadPrincipalUseCase
from app.modules.iam.domain.services.audit_service import RequestMeta
from app.modules.iam.domain.services.authorization_service import Principal
from app.modules.iam.infrastructure.repositories.argon2_password_hasher import hasher
from app.modules.iam.infrastructure.repositories.sqlalchemy_admin_repository import SqlAlchemyAdminRepository
from app.modules.iam.infrastructure.repositories.sqlalchemy_authorization_repository import (
    SqlAlchemyAuthorizationRepository)
from app.modules.iam.presentation.routes.dependencies import current_principal, get_uow, request_meta
from app.modules.iam.presentation.schemas.admin_schemas import (AssignmentResponse, AuditResponse, Page,
                                                                PermissionResponse, RoleResponse, SessionResponse,
                                                                UserResponse, page)
from app.modules.iam.presentation.schemas.auth_schemas import MessageResponse, PermissionsResponse
from app.shared.database import get_db
from app.shared.mailer import Mailer, get_mailer

router = APIRouter(prefix="/api", tags=["Administración IAM"])


class Ctx:
    """Contexto de cada petición administrativa (unidad de trabajo + repos + quién actúa)."""

    def __init__(self, db: Session = Depends(get_db), uow=Depends(get_uow),
                 principal: Principal = Depends(current_principal), meta: RequestMeta = Depends(request_meta)):
        self.db, self.args = db, (uow, SqlAlchemyAdminRepository(db), principal, meta)

    def __call__(self, use_case):
        return use_case(*self.args)


def _send(tasks: BackgroundTasks, mailer: Mailer, mail: OutgoingMail | None) -> None:
    if mail:
        tasks.add_task(mailer.send, mail.to, mail.subject, mail.body)


# ---------- usuarios ----------
@router.get("/users", response_model=Page[UserResponse])
def list_users(f: Annotated[UserFilterDTO, Query()], c: Ctx = Depends()):
    return page(*c(ListUsersUseCase).execute(f), f, UserResponse.of)


@router.post("/users", response_model=UserResponse, status_code=status.HTTP_201_CREATED)
def create_user(body: UserCreateDTO, c: Ctx = Depends()):
    """Crea la cuenta activa con una contraseña temporal que el usuario debe cambiar al entrar."""
    return UserResponse.of(c(CreateUserUseCase).execute(body, hasher))


@router.get("/users/{user_id}", response_model=UserResponse)
def get_user(user_id: int, c: Ctx = Depends()):
    return UserResponse.of(c(GetUserUseCase).execute(user_id))


@router.patch("/users/{user_id}", response_model=UserResponse)
def update_user(user_id: int, body: UserUpdateDTO, c: Ctx = Depends()):
    return UserResponse.of(c(UpdateUserUseCase).execute(user_id, body))


@router.post("/users/{user_id}/password", response_model=UserResponse)
def set_user_password(user_id: int, body: SetPasswordDTO, c: Ctx = Depends()):
    """Fija una contraseña temporal (p.ej. si la olvidó); cierra sus sesiones y deberá cambiarla al entrar."""
    return UserResponse.of(c(SetUserPasswordUseCase).execute(user_id, body, hasher))


@router.delete("/users/{user_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_user(user_id: int, c: Ctx = Depends()):
    """Eliminación lógica: revoca sesiones y roles; conserva la trazabilidad."""
    c(DeleteUserUseCase).execute(user_id)


def _status_route(action: str):
    def handler(user_id: int, body: ReasonDTO | None = None, c: Ctx = Depends()):
        return UserResponse.of(c(ChangeUserStatusUseCase).execute(user_id, action, body.reason if body else None))
    handler.__name__ = f"{action}_user"
    return handler


for _action in ("activate", "deactivate", "block", "unblock"):
    router.post(f"/users/{{user_id}}/{_action}", response_model=UserResponse)(_status_route(_action))


@router.post("/users/{user_id}/unlock", response_model=UserResponse)
def unlock_user(user_id: int, c: Ctx = Depends()):
    """Quita el bloqueo temporal por intentos fallidos."""
    return UserResponse.of(c(UnlockUserUseCase).execute(user_id))


@router.post("/users/{user_id}/resend-invitation", response_model=MessageResponse)
def resend_invitation(user_id: int, tasks: BackgroundTasks, c: Ctx = Depends(), mailer: Mailer = Depends(get_mailer)):
    _send(tasks, mailer, c(ResendInvitationUseCase).execute(user_id))
    return MessageResponse(detail="Invitación reenviada")


@router.get("/users/{user_id}/sessions", response_model=list[SessionResponse])
def user_sessions(user_id: int, c: Ctx = Depends()):
    return [SessionResponse.of(s) for s in c(UserSessionsUseCase).list(user_id)]


@router.delete("/users/{user_id}/sessions/{session_id}", status_code=status.HTTP_204_NO_CONTENT)
def revoke_user_session(user_id: int, session_id: int, c: Ctx = Depends()):
    c(UserSessionsUseCase).revoke(user_id, session_id)


@router.post("/users/{user_id}/identities/microsoft/link-request", response_model=MessageResponse)
def request_microsoft_link(user_id: int, tasks: BackgroundTasks, c: Ctx = Depends(),
                           mailer: Mailer = Depends(get_mailer)):
    """Vinculación auditada: envía al correo de la cuenta un enlace de un solo uso para entrar con Microsoft."""
    _send(tasks, mailer, c(UserIdentitiesUseCase).request_microsoft_link(user_id))
    return MessageResponse(detail="Enlace de vinculación enviado al correo del usuario")


@router.delete("/users/{user_id}/identities/{identity_id}", status_code=status.HTTP_204_NO_CONTENT)
def unlink_identity(user_id: int, identity_id: int, c: Ctx = Depends()):
    c(UserIdentitiesUseCase).unlink(user_id, identity_id)


# ---------- roles de un usuario ----------
@router.get("/users/{user_id}/roles", response_model=list[AssignmentResponse])
def user_roles(user_id: int, c: Ctx = Depends()):
    """Asignaciones activas."""
    return [AssignmentResponse.of(a) for a in c(RoleAssignmentsUseCase).list(user_id, active_only=True)]


@router.get("/users/{user_id}/role-assignments", response_model=list[AssignmentResponse])
def user_role_history(user_id: int, c: Ctx = Depends()):
    """Historial completo (incluye revocadas): trazabilidad de quién asignó/revocó y cuándo."""
    return [AssignmentResponse.of(a) for a in c(RoleAssignmentsUseCase).list(user_id, active_only=False)]


@router.post("/users/{user_id}/roles", response_model=AssignmentResponse, status_code=status.HTTP_201_CREATED)
def assign_role(user_id: int, body: AssignRoleDTO, c: Ctx = Depends()):
    return AssignmentResponse.of(c(RoleAssignmentsUseCase).assign(user_id, body))


@router.delete("/users/{user_id}/roles/{assignment_id}", response_model=AssignmentResponse)
def revoke_role(user_id: int, assignment_id: int, body: ReasonDTO | None = None, c: Ctx = Depends()):
    return AssignmentResponse.of(c(RoleAssignmentsUseCase).revoke(user_id, assignment_id, body.reason if body else None))


@router.get("/users/{user_id}/permissions", response_model=PermissionsResponse)
def user_permissions(user_id: int, c: Ctx = Depends()):
    """Permisos efectivos (roles activos x permisos activos x alcance, con herencia)."""
    c(GetUserUseCase).execute(user_id)  # mismo control de acceso que ver al usuario
    repo = SqlAlchemyAuthorizationRepository(c.db)
    return PermissionsResponse.of(LoadPrincipalUseCase(repo).execute(user_id), repo.unit_type_codes(),
                                  repo.permission_names())


@router.get("/users/{user_id}/activity", response_model=Page[AuditResponse])
def user_activity(user_id: int, f: Annotated[AuditFilterDTO, Query()], c: Ctx = Depends()):
    return _audit_page(c, *c(AuditQueryUseCase).user_activity(user_id, f), f)


# ---------- roles ----------
@router.get("/roles", response_model=Page[RoleResponse])
def list_roles(f: Annotated[RoleFilterDTO, Query()], c: Ctx = Depends()):
    return page(*c(RolesUseCase).list(f), f, RoleResponse.of)


@router.post("/roles", response_model=RoleResponse, status_code=status.HTTP_201_CREATED)
def create_role(body: RoleCreateDTO, c: Ctx = Depends()):
    return RoleResponse.of(c(RolesUseCase).create(body))


@router.get("/roles/{role_id}", response_model=RoleResponse)
def get_role(role_id: int, c: Ctx = Depends()):
    return RoleResponse.of(c(RolesUseCase).get(role_id))


@router.patch("/roles/{role_id}", response_model=RoleResponse)
def update_role(role_id: int, body: RoleUpdateDTO, c: Ctx = Depends()):
    return RoleResponse.of(c(RolesUseCase).update(role_id, body))


@router.delete("/roles/{role_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_role(role_id: int, c: Ctx = Depends()):
    """Lógica (queda inactivo). 409 si tiene asignaciones activas."""
    c(RolesUseCase).delete(role_id)


@router.get("/roles/{role_id}/permissions", response_model=list[str])
def role_permissions(role_id: int, c: Ctx = Depends()):
    return RoleResponse.of(c(RolesUseCase).get(role_id)).permissions


@router.put("/roles/{role_id}/permissions", response_model=RoleResponse)
def set_role_permissions(role_id: int, body: RolePermissionsDTO, c: Ctx = Depends()):
    """Reemplaza el conjunto de permisos del rol (efecto inmediato en todos sus usuarios)."""
    return RoleResponse.of(c(RolesUseCase).set_permissions(role_id, body.permissions))


# ---------- permisos ----------
@router.get("/permissions", response_model=Page[PermissionResponse])
def list_permissions(f: Annotated[PermissionFilterDTO, Query()], c: Ctx = Depends()):
    return page(*c(PermissionsUseCase).list(f), f, PermissionResponse.of)


@router.get("/permissions/{permission_id}", response_model=PermissionResponse)
def get_permission(permission_id: int, c: Ctx = Depends()):
    return PermissionResponse.of(c(PermissionsUseCase).get(permission_id))


@router.post("/permissions", response_model=PermissionResponse, status_code=status.HTTP_201_CREATED)
def create_permission(body: PermissionCreateDTO, c: Ctx = Depends()):
    return PermissionResponse.of(c(PermissionsUseCase).create(body))


@router.patch("/permissions/{permission_id}", response_model=PermissionResponse)
def update_permission(permission_id: int, body: PermissionUpdateDTO, c: Ctx = Depends()):
    return PermissionResponse.of(c(PermissionsUseCase).update(permission_id, body))


# ---------- auditoría ----------
def _audit_page(c: "Ctx", items, total, f) -> dict:
    names = SqlAlchemyAuthorizationRepository(c.db).user_names({a.actor_user_id for a in items if a.actor_user_id})
    return page(items, total, f, lambda a: AuditResponse.of(a).model_copy(update={"actor_name": names.get(a.actor_user_id)}))


@router.get("/audit", response_model=Page[AuditResponse])
def list_audit(f: Annotated[AuditFilterDTO, Query()], c: Ctx = Depends()):
    """Solo lectura: no existe endpoint para modificar ni borrar auditoría (y en PostgreSQL un trigger lo impide)."""
    return _audit_page(c, *c(AuditQueryUseCase).execute(f), f)
