"""Alta controlada de cuentas: no hay registro público. Un administrador invita; el invitado acepta
(con contraseña o con Microsoft). Aceptar la invitación prueba el control del correo.
"""
from datetime import timedelta

from app.modules.iam.application.dto.auth_dto import InviteUserDTO, RegisterDTO
from app.modules.iam.application.use_cases.authentication.common import (OutgoingMail, audit, check_password,
                                                                         valid_token, issue_token, rate_limit)
from app.modules.iam.domain.entities.identity import PasswordCredential, User
from app.modules.iam.domain.repositories.iam_repositories import IamUnitOfWork, PasswordHasher
from app.modules.iam.domain.services.audit_service import RequestMeta
from app.shared.clock import now
from app.shared.config import Settings
from app.shared.exceptions import ConflictError, InvalidDataError
from app.shared.security import hash_token

INVITATION, VERIFY = "invitation", "verify_email"


class InviteUserUseCase:
    def __init__(self, uow: IamUnitOfWork, cfg: Settings):
        self.uow, self.cfg = uow, cfg

    def execute(self, dto: InviteUserDTO, invited_by: int | None, meta: RequestMeta) -> tuple[User, OutgoingMail]:
        at = now()
        if self.uow.users.by_email(dto.email):
            raise ConflictError("Ya existe un usuario con ese correo")
        user = User(first_name=dto.first_name.strip(), last_name=dto.last_name.strip(), email=dto.email,
                    status=self.uow.users.status("invited"), account_type=self.uow.users.account_type(dto.account_type),
                    created_at=at, updated_at=at)
        self.uow.users.add(user)
        raw = issue_token(self.uow, user.id, INVITATION, timedelta(hours=self.cfg.invitation_token_hours), at,
                          created_by=invited_by)
        audit(self.uow, "iam.user.invited", "success", meta, invited_by, "user", user.id)
        self.uow.commit()
        return user, OutgoingMail(user.email, "Invitación a la plataforma de noticias",
                                  f"Hola {user.first_name},\n\nFuiste invitado a la plataforma. Activa tu cuenta "
                                  f"(válido {self.cfg.invitation_token_hours} horas):\n"
                                  f"{self.cfg.frontend_url}{self.cfg.frontend_login_path}/aceptar-invitacion?token={raw}\n\n"
                                  "Puedes definir una contraseña o entrar con tu cuenta institucional de Microsoft.")


class AcceptInvitationUseCase:
    """POST /auth/register: activa la cuenta invitada definiendo contraseña."""

    def __init__(self, uow: IamUnitOfWork, hasher: PasswordHasher, cfg: Settings):
        self.uow, self.hasher, self.cfg = uow, hasher, cfg

    def execute(self, dto: RegisterDTO, meta: RequestMeta) -> User:
        at = now()
        rate_limit(self.uow, self.cfg, "auth.register", meta, at)
        try:
            token = valid_token(self.uow, hash_token(dto.token), INVITATION, at)
            user = self.uow.users.get(token.user_id)
            if not user or user.status.code != "invited":
                raise InvalidDataError("El enlace no es válido o ya expiró")
            check_password(self.cfg, dto.password, user)
        except InvalidDataError:
            audit(self.uow, "auth.register", "failure", meta)
            self.uow.commit()
            raise
        token.used_at = at
        activate(self.uow, user, at)
        user.password = PasswordCredential(password_hash=self.hasher.hash(dto.password), password_changed_at=at)
        audit(self.uow, "auth.register", "success", meta, user.id, "user", user.id, method="password")
        self.uow.commit()
        return user


def activate(uow: IamUnitOfWork, user: User, at) -> None:
    user.status, user.email_verified_at, user.updated_at = uow.users.status("active"), at, at


class RequestEmailVerificationUseCase:
    """Se usa cuando cambia el correo de una cuenta: hay que volver a probar su control."""

    def __init__(self, uow: IamUnitOfWork, cfg: Settings):
        self.uow, self.cfg = uow, cfg

    def execute(self, user: User) -> OutgoingMail:
        at = now()
        user.email_verified_at = None
        raw = issue_token(self.uow, user.id, VERIFY, timedelta(hours=self.cfg.verify_token_hours), at,
                          context={"email": user.email})
        self.uow.commit()
        return OutgoingMail(user.email, "Verifica tu correo",
                            f"Confirma tu correo abriendo este enlace:\n{self.cfg.frontend_url}{self.cfg.frontend_login_path}/verificar-correo?token={raw}")


class VerifyEmailUseCase:
    def __init__(self, uow: IamUnitOfWork, cfg: Settings):
        self.uow, self.cfg = uow, cfg

    def execute(self, raw_token: str, meta: RequestMeta) -> None:
        at = now()
        rate_limit(self.uow, self.cfg, "auth.email.verify", meta, at)
        try:
            token = valid_token(self.uow, hash_token(raw_token), VERIFY, at)
            user = self.uow.users.get(token.user_id)
            # El enlace solo vale para el correo al que se envió.
            if not user or (token.context or {}).get("email") != user.email:
                raise InvalidDataError("El enlace no es válido o ya expiró")
        except InvalidDataError:
            audit(self.uow, "auth.email.verify", "failure", meta)
            self.uow.commit()
            raise
        token.used_at = user.email_verified_at = at
        audit(self.uow, "auth.email.verify", "success", meta, user.id, "user", user.id)
        self.uow.commit()
