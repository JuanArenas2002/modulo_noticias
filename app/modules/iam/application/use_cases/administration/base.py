"""Base de los casos de uso de administración: contexto común y protecciones transversales."""
from app.modules.iam.application.use_cases.authentication.common import audit
from app.modules.iam.domain.entities.identity import User
from app.modules.iam.domain.repositories.admin_repositories import AdminRepository
from app.modules.iam.domain.repositories.iam_repositories import IamUnitOfWork
from app.modules.iam.domain.services.audit_service import RequestMeta
from app.modules.iam.domain.services.authorization_service import Principal
from app.shared.config import Settings, settings
from app.shared.exceptions import ConflictError, ForbiddenError, NotFoundError

OWNER_PERMISSION = "permissions.manage"  # quien lo tiene global puede reconstruir todo lo demás


class AdminUseCase:
    def __init__(self, uow: IamUnitOfWork, admin: AdminRepository, principal: Principal, meta: RequestMeta,
                 cfg: Settings = settings):
        self.uow, self.admin, self.principal, self.meta, self.cfg = uow, admin, principal, meta, cfg

    def target(self, user_id: int) -> User:
        if (user := self.uow.users.get(user_id)) is None:
            raise NotFoundError("Usuario no encontrado")
        return user

    def target_for_change(self, user_id: int) -> User:
        """Protección de cuentas privilegiadas (escalamiento vertical): no puedes administrar a alguien que
        tiene permisos que tú no tienes con alcance institucional (p.ej. un admin no toca a un super_admin)."""
        user = self.target(user_id)
        if user_id != self.principal.user_id:
            if missing := {c for c in self.admin.permission_codes(user_id) if not self.principal.is_global(c)}:
                self.audit("iam.user.change", "user", user_id, result="denied", missing=sorted(missing))
                self.uow.commit()
                raise ForbiddenError("No puedes administrar a un usuario con permisos que tú no tienes")
        return user

    def audit(self, event_type: str, resource_type: str, resource_id, result: str = "success", **context) -> None:
        audit(self.uow, event_type, result, self.meta, self.principal.user_id, resource_type, resource_id, **context)

    def ensure_owner_remains(self, removing_user_id: int | None = None) -> None:
        """Anti-bloqueo: debe quedar al menos un usuario habilitado con OWNER_PERMISSION institucional.

        Se llama DESPUÉS de aplicar el cambio en la sesión (flush), así cuenta el estado resultante.
        """
        self.uow.flush()
        holders = self.admin.global_holders(OWNER_PERMISSION) - ({removing_user_id} if removing_user_id else set())
        if not holders:
            raise ConflictError("La operación dejaría la plataforma sin administrador con 'permissions.manage'")
