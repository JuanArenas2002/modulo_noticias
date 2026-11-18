"""Casos de uso: recuperar, restablecer y cambiar contraseña."""
from datetime import timedelta

from app.modules.iam.application.dto.auth_dto import ChangePasswordDTO, ResetPasswordDTO
from app.modules.iam.application.use_cases.authentication.common import (OutgoingMail, audit, check_password,
                                                                         valid_token, issue_token, rate_limit)
from app.modules.iam.domain.entities.identity import AuthSession, User
from app.modules.iam.domain.repositories.iam_repositories import IamUnitOfWork, PasswordHasher
from app.modules.iam.domain.services.audit_service import RequestMeta
from app.shared.clock import now
from app.shared.config import Settings
from app.shared.exceptions import ConflictError, InvalidDataError
from app.shared.security import hash_token

PURPOSE = "reset_password"


def _set_password(user: User, hasher: PasswordHasher, password: str, at) -> None:
    cred = user.password
    cred.password_hash, cred.password_changed_at = hasher.hash(password), at
    cred.failed_attempts, cred.locked_until, cred.must_change = 0, None, False


class ForgotPasswordUseCase:
    """Siempre la misma respuesta. Si la cuenta existe y usa contraseña, se emite un enlace de un solo uso."""

    def __init__(self, uow: IamUnitOfWork, cfg: Settings):
        self.uow, self.cfg = uow, cfg

    def execute(self, email: str, meta: RequestMeta) -> OutgoingMail | None:
        at = now()
        rate_limit(self.uow, self.cfg, "auth.password.forgot", meta, at)
        user = self.uow.users.by_email(email)
        mail = None
        if user and user.password and user.status.can_login:
            raw = issue_token(self.uow, user.id, PURPOSE, timedelta(minutes=self.cfg.reset_token_minutes), at)
            mail = OutgoingMail(user.email, "Restablecer contraseña",
                                f"Hola {user.first_name},\n\nPara restablecer tu contraseña abre este enlace "
                                f"(válido {self.cfg.reset_token_minutes} minutos, un solo uso):\n"
                                f"{self.cfg.frontend_url}{self.cfg.frontend_login_path}/restablecer?token={raw}\n\n"
                                "Si no lo solicitaste, ignora este correo.")
        audit(self.uow, "auth.password.forgot", "success", meta, user.id if user else None,
              "user", user.id if user else None, issued=mail is not None)
        self.uow.commit()
        return mail


class ResetPasswordUseCase:
    def __init__(self, uow: IamUnitOfWork, hasher: PasswordHasher, cfg: Settings):
        self.uow, self.hasher, self.cfg = uow, hasher, cfg

    def execute(self, dto: ResetPasswordDTO, meta: RequestMeta) -> None:
        at = now()
        rate_limit(self.uow, self.cfg, "auth.password.reset", meta, at)
        try:
            token = valid_token(self.uow, hash_token(dto.token), PURPOSE, at)
            user = self.uow.users.get(token.user_id)
            if not user or not user.password:
                raise InvalidDataError("El enlace no es válido o ya expiró")
            check_password(self.cfg, dto.new_password, user)
        except InvalidDataError:
            audit(self.uow, "auth.password.reset", "failure", meta)
            self.uow.commit()
            raise
        token.used_at = at
        _set_password(user, self.hasher, dto.new_password, at)
        revoked = self.uow.sessions.revoke_all(user.id, at, "password_reset")  # quien robó la sesión la pierde
        audit(self.uow, "auth.password.reset", "success", meta, user.id, "user", user.id, revoked_sessions=revoked)
        self.uow.commit()


class ChangePasswordUseCase:
    def __init__(self, uow: IamUnitOfWork, hasher: PasswordHasher, cfg: Settings):
        self.uow, self.hasher, self.cfg = uow, hasher, cfg

    def execute(self, user: User, session: AuthSession, dto: ChangePasswordDTO, meta: RequestMeta) -> None:
        at = now()
        if not user.password:
            raise ConflictError("La cuenta no tiene contraseña (inicia sesión con Microsoft)")
        if not self.hasher.verify(user.password.password_hash, dto.current_password):
            audit(self.uow, "auth.password.change", "failure", meta, user.id, "user", user.id, reason="bad_current")
            self.uow.commit()
            raise InvalidDataError("La contraseña actual no es correcta")
        if dto.new_password == dto.current_password:
            raise InvalidDataError("La nueva contraseña debe ser distinta de la actual")
        check_password(self.cfg, dto.new_password, user)
        _set_password(user, self.hasher, dto.new_password, at)
        revoked = self.uow.sessions.revoke_all(user.id, at, "password_change", except_id=session.id)
        audit(self.uow, "auth.password.change", "success", meta, user.id, "user", user.id, revoked_sessions=revoked)
        self.uow.commit()

