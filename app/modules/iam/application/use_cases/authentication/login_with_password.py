"""Caso de uso: inicio de sesión con correo y contraseña.

- Mensaje y tiempo iguales exista o no la cuenta (anti-enumeración: Argon2 sobre hash ficticio).
- Bloqueo temporal tras N fallos seguidos; límite de intentos fallidos por IP.
- Todo intento queda en login_attempts y audit_logs (sin contraseña ni correo en claro).
"""
from datetime import timedelta

from app.modules.iam.application.dto.auth_dto import LoginDTO
from app.modules.iam.application.use_cases.authentication.common import audit, window
from app.modules.iam.domain.entities.identity import LoginAttempt, User
from app.modules.iam.domain.repositories.iam_repositories import IamUnitOfWork, PasswordHasher
from app.modules.iam.domain.services import session_service
from app.modules.iam.domain.services.audit_service import RequestMeta
from app.shared.clock import as_utc, now
from app.shared.config import Settings
from app.shared.exceptions import TooManyRequestsError, UnauthorizedError
from app.shared.security import hash_token

INVALID = "Correo o contraseña incorrectos"


class LoginWithPasswordUseCase:
    def __init__(self, uow: IamUnitOfWork, hasher: PasswordHasher, cfg: Settings):
        self.uow, self.hasher, self.cfg = uow, hasher, cfg

    def execute(self, dto: LoginDTO, meta: RequestMeta) -> tuple[session_service.IssuedSession, User]:
        at = now()
        since = at - timedelta(minutes=self.cfg.rate_limit_window_minutes)
        if meta.ip and self.uow.attempts.count_ip(meta.ip, since) >= self.cfg.rate_limit_per_ip:
            audit(self.uow, "auth.login.rate_limited", "denied", meta)
            self.uow.commit()
            raise TooManyRequestsError("Demasiados intentos. Intenta más tarde.")

        user = self.uow.users.by_email(dto.email)
        cred = user.password if user else None
        reason = None
        if cred is None:
            self.hasher.burn(dto.password)
            reason = "no_password_account"
        elif cred.locked_until and as_utc(cred.locked_until) > at:
            self.hasher.burn(dto.password)
            reason = "locked"
        elif not self.hasher.verify(cred.password_hash, dto.password):
            reason = "bad_password"
            cred.failed_attempts += 1
            if cred.failed_attempts >= self.cfg.login_max_failures:
                cred.locked_until, cred.failed_attempts = at + timedelta(minutes=self.cfg.login_lock_minutes), 0
                audit(self.uow, "auth.account.locked", "success", meta, user.id, "user", user.id)
        elif not user.status.can_login:
            reason = f"status_{user.status.code}"
        elif user.email_verified_at is None:
            reason = "email_not_verified"

        self.uow.attempts.add(LoginAttempt(email_hash=hash_token(dto.email), ip=meta.ip, success=reason is None,
                                           at=at))
        if reason:
            audit(self.uow, "auth.login", "failure", meta, user.id if user else None,
                  "user", user.id if user else None, reason=reason)
            self.uow.commit()
            raise UnauthorizedError(INVALID)

        cred.failed_attempts, cred.locked_until = 0, None
        if self.hasher.needs_rehash(cred.password_hash):
            cred.password_hash = self.hasher.hash(dto.password)
        user.last_login_at = at
        issued = session_service.issue(user.id, self.uow.users.provider("password"), window(self.cfg), at,
                                       meta.ip, meta.user_agent)
        self.uow.sessions.add(issued.session)
        audit(self.uow, "auth.login", "success", meta, user.id, "session", issued.session.id, method="password")
        self.uow.commit()
        return issued, user
