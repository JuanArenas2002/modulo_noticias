"""Gestión de usuarios: listar, crear, editar, estados, eliminación lógica, sesiones e identidades.

Las cuentas son institucionales: mutarlas exige el permiso con alcance institucional.
Leer el directorio basta con users.view en algún alcance (lo necesita quien asigna roles en su dependencia).
"""
from datetime import timedelta

from app.modules.iam.application.dto.admin_dto import SetPasswordDTO, UserCreateDTO, UserFilterDTO, UserUpdateDTO
from app.modules.iam.application.use_cases.administration.base import AdminUseCase
from app.modules.iam.application.use_cases.authentication.common import (LINK_IDENTITY, OutgoingMail, check_password,
                                                                         issue_token)
from app.modules.iam.application.use_cases.authentication.invitations import INVITATION, activate
from app.modules.iam.domain.entities.identity import AuthSession, PasswordCredential, User
from app.modules.iam.domain.repositories.iam_repositories import PasswordHasher
from app.modules.iam.domain.services import session_service
from app.shared.clock import now
from app.shared.exceptions import ConflictError, ForbiddenError, NotFoundError

# acción -> (estados de origen, estado destino)
STATUS_ACTIONS = {
    "activate": ({"inactive"}, "active"),
    "deactivate": ({"active", "invited", "blocked"}, "inactive"),
    "block": ({"active", "inactive", "invited"}, "blocked"),
    "unblock": ({"blocked"}, "active"),
}


class ListUsersUseCase(AdminUseCase):
    def execute(self, f: UserFilterDTO) -> tuple[list[User], int]:
        if not self.principal.can_any("users.view"):
            raise ForbiddenError("Requiere 'users.view'")
        return self.admin.search_users(f)


class GetUserUseCase(AdminUseCase):
    def execute(self, user_id: int) -> User:
        if user_id != self.principal.user_id and not self.principal.can_any("users.view"):
            raise ForbiddenError("Requiere 'users.view'")
        return self.target(user_id)


class CreateUserUseCase(AdminUseCase):
    """No hay registro público: un administrador crea la cuenta con una contraseña temporal (sin correo).
    Queda activa y con `must_change`: hasta que la cambie no puede usar nada más."""

    def execute(self, dto: UserCreateDTO, hasher: PasswordHasher) -> User:
        self.principal.ensure_global("users.create")
        if self.uow.users.by_email(dto.email):
            raise ConflictError("Ya existe un usuario con ese correo")
        at = now()
        user = User(first_name=dto.first_name.strip(), last_name=dto.last_name.strip(), email=dto.email,
                    status=self.uow.users.status("active"), account_type=self.uow.users.account_type(dto.account_type),
                    email_verified_at=at, created_at=at, updated_at=at)  # el administrador responde por el correo
        check_password(self.cfg, dto.password, user)
        user.password = PasswordCredential(password_hash=hasher.hash(dto.password), password_changed_at=at,
                                           must_change=True)
        self.uow.users.add(user)
        self.audit("iam.user.created", "user", user.id)
        self.uow.commit()
        return user


class SetUserPasswordUseCase(AdminUseCase):
    """Olvido de contraseña sin correo: el administrador fija una temporal, se cierran sus sesiones y
    el usuario debe cambiarla al entrar. No aplica a cuentas con más permisos que el administrador."""

    def execute(self, user_id: int, dto: SetPasswordDTO, hasher: PasswordHasher) -> User:
        self.principal.ensure_global("users.update")
        if user_id == self.principal.user_id:
            raise ForbiddenError("Para tu propia cuenta usa 'Cambiar contraseña'")
        user, at = self.target_for_change(user_id), now()
        if user.status.code not in ("active", "invited"):
            raise ConflictError(f"No se puede fijar la contraseña de un usuario en estado '{user.status.code}'")
        check_password(self.cfg, dto.password, user)
        if user.status.code == "invited":  # cuentas que quedaron esperando la invitación por correo
            activate(self.uow, user, at)
        cred = user.password or PasswordCredential(password_hash="")
        cred.password_hash, cred.password_changed_at = hasher.hash(dto.password), at
        cred.failed_attempts, cred.locked_until, cred.must_change = 0, None, True
        user.password, user.updated_at = cred, at
        self.uow.sessions.revoke_all(user.id, at, "password_set_by_admin")
        self.audit("iam.user.password_set", "user", user.id)  # nunca la contraseña
        self.uow.commit()
        return user


class ResendInvitationUseCase(AdminUseCase):
    def execute(self, user_id: int) -> OutgoingMail:
        self.principal.ensure_global("users.create")
        user = self.target(user_id)
        if user.status.code != "invited":
            raise ConflictError("El usuario ya activó su cuenta")
        raw = issue_token(self.uow, user.id, INVITATION, timedelta(hours=self.cfg.invitation_token_hours), now(),
                          created_by=self.principal.user_id)
        self.audit("iam.user.invitation_resent", "user", user.id)
        self.uow.commit()
        return OutgoingMail(user.email, "Invitación a la plataforma de noticias",
                            f"Activa tu cuenta:\n{self.cfg.frontend_url}{self.cfg.frontend_login_path}/aceptar-invitacion?token={raw}")


class UpdateUserUseCase(AdminUseCase):
    def execute(self, user_id: int, dto: UserUpdateDTO) -> User:
        self.principal.ensure_global("users.update")
        user = self.target_for_change(user_id)
        changes = dto.model_dump(exclude_unset=True, exclude_none=True)
        if "email" in changes and changes["email"] != user.email:
            if self.uow.users.by_email(changes["email"]):
                raise ConflictError("Ya existe un usuario con ese correo")
            # ponytail: sin verificación por correo (no llegan); el administrador responde por el cambio.
            user.email = changes["email"]
        if "account_type" in changes:  # el catálogo valida (422 si no existe)
            user.account_type = self.uow.users.account_type(changes["account_type"])
        for field in ("first_name", "last_name"):
            if field in changes:
                setattr(user, field, changes[field].strip())
        user.updated_at = now()
        self.audit("iam.user.updated", "user", user.id, fields=sorted(changes))  # nombres de campos, no valores
        self.uow.commit()
        return user


class ChangeUserStatusUseCase(AdminUseCase):
    def execute(self, user_id: int, action: str, reason: str | None = None) -> User:
        self.principal.ensure_global("users.update")
        if user_id == self.principal.user_id:
            raise ForbiddenError("No puedes cambiar el estado de tu propia cuenta")
        user = self.target_for_change(user_id)
        sources, destination = STATUS_ACTIONS[action]
        if user.status.code not in sources:
            raise ConflictError(f"No se puede '{action}' un usuario en estado '{user.status.code}'")
        at = now()
        user.status, user.updated_at = self.uow.users.status(destination), at
        if not user.status.can_login:
            self.uow.sessions.revoke_all(user.id, at, f"user_{action}")
            self.ensure_owner_remains()
        self.audit(f"iam.user.{action}", "user", user.id, reason=reason)
        self.uow.commit()
        return user


class UnlockUserUseCase(AdminUseCase):
    """Quita el bloqueo temporal por intentos fallidos (no confundir con 'block')."""

    def execute(self, user_id: int) -> User:
        self.principal.ensure_global("users.update")
        user = self.target_for_change(user_id)
        if user.password:
            user.password.locked_until, user.password.failed_attempts = None, 0
        self.audit("iam.user.unlocked", "user", user.id)
        self.uow.commit()
        return user


class DeleteUserUseCase(AdminUseCase):
    """Eliminación lógica: conserva trazabilidad; revoca sesiones y roles; libera el correo e identidades."""

    def execute(self, user_id: int) -> None:
        self.principal.ensure_global("users.delete")
        if user_id == self.principal.user_id:
            raise ForbiddenError("No puedes eliminar tu propia cuenta")
        user, at = self.target_for_change(user_id), now()
        user.deleted_at = user.updated_at = at
        user.status = self.uow.users.status("inactive")
        self.uow.sessions.revoke_all(user.id, at, "user_deleted")
        for a in self.admin.assignments(user.id, active_only=True):
            a.revoked_at, a.revoked_by, a.revoke_reason = at, self.principal.user_id, "user_deleted"
        for identity in list(user.identities):
            self.admin.detach_identity_sessions(identity.id, at, "user_deleted")
            user.identities.remove(identity)
        self.ensure_owner_remains()
        self.audit("iam.user.deleted", "user", user.id)
        self.uow.commit()


class UserSessionsUseCase(AdminUseCase):
    """Sesiones activas: el propio usuario o quien tenga users.manage_sessions institucional."""

    def _allowed(self, user_id: int) -> None:
        if user_id != self.principal.user_id:
            self.principal.ensure_global("users.manage_sessions")

    def list(self, user_id: int) -> list[AuthSession]:
        self._allowed(user_id)
        self.target(user_id)
        return self.uow.sessions.active_for_user(user_id, now())

    def revoke(self, user_id: int, session_id: int) -> None:
        self._allowed(user_id)
        if user_id != self.principal.user_id:
            self.target_for_change(user_id)
        if (s := self.admin.session_of(user_id, session_id)) is None or s.revoked_at is not None:
            raise NotFoundError("Sesión no encontrada")
        session_service.revoke(s, now(), "revoked_by_admin" if user_id != self.principal.user_id else "revoked_by_user")
        self.audit("auth.session.revoked", "session", s.id, target_user=user_id)
        self.uow.commit()


class UserIdentitiesUseCase(AdminUseCase):
    """Procedimiento administrativo auditado para identidades externas.

    No vincula por correo: emite un enlace de un solo uso al correo de la cuenta; el usuario lo abre e inicia
    sesión con Microsoft (prueba control del correo Y de la cuenta Microsoft).
    """

    def request_microsoft_link(self, user_id: int) -> OutgoingMail:
        self.principal.ensure_global("users.update")
        user = self.target_for_change(user_id)
        if not user.status.can_login:
            raise ConflictError("La cuenta no está activa")
        raw = issue_token(self.uow, user.id, LINK_IDENTITY, timedelta(hours=self.cfg.invitation_token_hours), now(),
                          created_by=self.principal.user_id)
        self.audit("auth.identity.link_requested", "user", user.id, provider="microsoft")
        self.uow.commit()
        return OutgoingMail(user.email, "Vincula tu cuenta de Microsoft",
                            f"Para vincular tu cuenta institucional de Microsoft abre este enlace "
                            f"(un solo uso):\n{self.cfg.frontend_url}{self.cfg.frontend_login_path}/vincular-microsoft?token={raw}")

    def unlink(self, user_id: int, identity_id: int) -> None:
        self.principal.ensure_global("users.update")
        user = self.target_for_change(user_id)
        if (identity := self.admin.identity_of(user_id, identity_id)) is None:
            raise NotFoundError("Identidad no encontrada")
        if not user.password and len(user.identities) == 1:
            raise ConflictError("Es el único método de acceso de la cuenta")
        self.admin.detach_identity_sessions(identity.id, now(), "identity_unlinked")
        user.identities.remove(identity)
        self.audit("auth.identity.unlinked", "user", user.id, provider=identity.provider.code)
        self.uow.commit()
