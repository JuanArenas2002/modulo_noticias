"""Casos de uso de sesión: resolver la sesión de una petición, cerrar sesión y rotar (refresh)."""
from app.modules.iam.application.use_cases.authentication.common import audit, window
from app.modules.iam.domain.entities.identity import AuthSession, User
from app.modules.iam.domain.repositories.iam_repositories import IamUnitOfWork
from app.modules.iam.domain.services import session_service
from app.modules.iam.domain.services.audit_service import RequestMeta
from app.shared.clock import now
from app.shared.config import Settings
from app.shared.exceptions import ForbiddenError, UnauthorizedError
from app.shared.security import hash_token, same

UNAUTHENTICATED = "Sesión inválida o expirada"


class ResolveSessionUseCase:
    """Token de la cookie -> (sesión, usuario). Valida expiración, revocación y estado de la cuenta."""

    def __init__(self, uow: IamUnitOfWork, cfg: Settings):
        self.uow, self.cfg = uow, cfg

    def execute(self, token: str | None) -> tuple[AuthSession, User]:
        if not token:
            raise UnauthorizedError(UNAUTHENTICATED)
        at = now()
        session = self.uow.sessions.by_token_hash(hash_token(token))
        user = self.uow.users.get(session.user_id) if session else None
        if not session or not session_service.is_valid(session, at) or not user or not user.status.can_login:
            raise UnauthorizedError(UNAUTHENTICATED)
        if session_service.touch(session, window(self.cfg), at):
            self.uow.commit()
        return session, user


def check_csrf(session: AuthSession, header_value: str | None) -> None:
    """Token sincronizador: el header debe coincidir con el CSRF emitido para ESTA sesión."""
    if not header_value or not same(hash_token(header_value), session.csrf_token_hash):
        raise ForbiddenError("Token CSRF inválido")


class LogoutUseCase:
    def __init__(self, uow: IamUnitOfWork):
        self.uow = uow

    def execute(self, session: AuthSession, meta: RequestMeta) -> str:
        """Devuelve el código del proveedor de la sesión (para decidir el cierre federado)."""
        session_service.revoke(session, now(), "logout")
        audit(self.uow, "auth.logout", "success", meta, session.user_id, "session", session.id)
        self.uow.commit()
        return session.provider.code


class RefreshSessionUseCase:
    """Rota el token de la sesión. Presentar un token ya rotado = robo probable: se revocan TODAS las sesiones."""

    def __init__(self, uow: IamUnitOfWork, cfg: Settings):
        self.uow, self.cfg = uow, cfg

    def execute(self, token: str | None, csrf_header: str | None, meta: RequestMeta) -> tuple[str, str]:
        if not token:
            raise UnauthorizedError(UNAUTHENTICATED)
        at, token_hash = now(), hash_token(token)
        session = self.uow.sessions.by_token_hash(token_hash)
        if session is None:
            if reused := self.uow.sessions.by_previous_hash(token_hash):
                revoked = self.uow.sessions.revoke_all(reused.user_id, at, "refresh_token_reuse")
                audit(self.uow, "auth.session.reuse_detected", "denied", meta, reused.user_id, "session", reused.id,
                      revoked_sessions=revoked)
                self.uow.commit()
            raise UnauthorizedError(UNAUTHENTICATED)
        user = self.uow.users.get(session.user_id)
        if not session_service.is_valid(session, at) or not user or not user.status.can_login:
            raise UnauthorizedError(UNAUTHENTICATED)
        check_csrf(session, csrf_header)
        new_token, new_csrf = session_service.rotate(session, window(self.cfg), at)
        audit(self.uow, "auth.session.refresh", "success", meta, user.id, "session", session.id)
        self.uow.commit()
        return new_token, new_csrf
