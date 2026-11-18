"""Dependencias FastAPI del IAM: unidad de trabajo, metadatos de la petición, sesión autenticada y cookies.

`authenticated` exige CSRF en todo método que modifica estado: protección por defecto, no opt-in.
"""
from dataclasses import dataclass
from functools import lru_cache

from fastapi import Depends, Request, Response
from sqlalchemy.orm import Session

from app.modules.iam.application.use_cases.authentication.sessions import ResolveSessionUseCase, check_csrf
from app.modules.iam.application.use_cases.authorization.load_principal import LoadPrincipalUseCase
from app.modules.iam.domain.entities.identity import AuthSession, User
from app.modules.iam.domain.services.audit_service import RequestMeta
from app.modules.iam.domain.services.authorization_service import Principal
from app.modules.iam.infrastructure.repositories.entra_oidc_client import EntraOidcClient
from app.modules.iam.infrastructure.repositories.sqlalchemy_authorization_repository import (
    SqlAlchemyAuthorizationRepository)
from app.modules.iam.infrastructure.repositories.sqlalchemy_iam_repositories import SqlAlchemyIamUnitOfWork
from app.shared.config import settings
from app.shared.database import get_db
from app.shared.exceptions import ForbiddenError, NotFoundError, UnauthorizedError

SAFE_METHODS = {"GET", "HEAD", "OPTIONS"}
CSRF_HEADER = "X-CSRF-Token"
MUST_CHANGE = "Debes cambiar tu contraseña temporal antes de continuar"


@dataclass(frozen=True)
class Authenticated:
    session: AuthSession
    user: User


def get_uow(db: Session = Depends(get_db)) -> SqlAlchemyIamUnitOfWork:
    return SqlAlchemyIamUnitOfWork(db)


def request_meta(request: Request) -> RequestMeta:
    # Detrás de proxy: uvicorn --proxy-headers --forwarded-allow-ips=<ip del proxy> para que client.host sea real.
    return RequestMeta(ip=request.client.host if request.client else None,
                       user_agent=request.headers.get("user-agent"))


def authenticated(request: Request, uow: SqlAlchemyIamUnitOfWork = Depends(get_uow)) -> Authenticated:
    session, user = ResolveSessionUseCase(uow, settings).execute(request.cookies.get(settings.session_cookie_name))
    if request.method not in SAFE_METHODS:
        check_csrf(session, request.headers.get(CSRF_HEADER))
    return Authenticated(session, user)


def optional_authenticated(request: Request, uow: SqlAlchemyIamUnitOfWork = Depends(get_uow)) -> Authenticated | None:
    try:
        return authenticated(request, uow)
    except UnauthorizedError:
        return None


@lru_cache
def _entra() -> EntraOidcClient:
    return EntraOidcClient(settings)  # una instancia por proceso: cachea las llaves JWKS


def get_oidc() -> EntraOidcClient:
    if not settings.microsoft_enabled:
        raise NotFoundError("El inicio de sesión con Microsoft no está configurado")
    return _entra()


def set_session_cookies(response: Response, token: str, csrf: str) -> None:
    common = dict(secure=settings.cookie_secure, samesite=settings.cookie_samesite, path="/",
                  max_age=settings.session_absolute_hours * 3600)
    domain = None if settings.session_cookie_name.startswith("__Host-") else settings.cookie_domain
    response.set_cookie(settings.session_cookie_name, token, httponly=True, domain=domain, **common)
    # Legible por JS (no es secreto frente al propio usuario); el valor que vale es el del header.
    response.set_cookie(settings.csrf_cookie_name, csrf, httponly=False, domain=domain, **common)


def clear_session_cookies(response: Response) -> None:
    for name in (settings.session_cookie_name, settings.csrf_cookie_name):
        response.delete_cookie(name, path="/", secure=settings.cookie_secure, samesite=settings.cookie_samesite)


# ---------- autorización (lo que consumen los demás módulos) ----------
def _principal(db: Session, auth: Authenticated) -> Principal:
    return LoadPrincipalUseCase(SqlAlchemyAuthorizationRepository(db)).execute(auth.user.id, auth.session.id)


def _must_change(auth: Authenticated) -> bool:
    return bool(auth.user.password and auth.user.password.must_change)


def current_principal(db: Session = Depends(get_db), auth: Authenticated = Depends(authenticated)) -> Principal:
    """Usuario autenticado (401 si no) con sus permisos efectivos.
    Con contraseña temporal solo puede ver /me, cambiarla y cerrar sesión (403 en todo lo demás)."""
    if _must_change(auth):
        raise ForbiddenError(MUST_CHANGE)
    return _principal(db, auth)


def optional_principal(db: Session = Depends(get_db),
                       auth: Authenticated | None = Depends(optional_authenticated)) -> Principal | None:
    """Para endpoints públicos que muestran más a usuarios autorizados."""
    return _principal(db, auth) if auth and not _must_change(auth) else None


def require_permission(code: str):
    """Filtro de endpoint: 401 sin sesión, 403 si no tiene `code` en NINGÚN alcance.

    El chequeo por alcance del recurso concreto va en el caso de uso (principal.ensure_all(code, scopes)),
    con los alcances leídos de la BD, nunca del request.
    """
    def dependency(principal: Principal = Depends(current_principal)) -> Principal:
        if not principal.can_any(code):
            raise ForbiddenError(f"Requiere el permiso '{code}'")
        return principal
    dependency.__name__ = f"require_{code.replace('.', '_')}"
    return dependency
