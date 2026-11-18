"""Endpoints de autenticación. Sin lógica de negocio: cada ruta delega en un caso de uso."""
from fastapi import APIRouter, BackgroundTasks, Depends, Query, Request, Response, status
from fastapi.responses import RedirectResponse
from sqlalchemy.orm import Session

from app.modules.iam.application.dto.auth_dto import (ChangePasswordDTO, ForgotPasswordDTO, LoginDTO, RegisterDTO,
                                                      ResetPasswordDTO, TokenDTO)
from app.modules.iam.application.use_cases.authentication.common import OutgoingMail
from app.modules.iam.application.use_cases.authentication.invitations import (AcceptInvitationUseCase,
                                                                              VerifyEmailUseCase)
from app.modules.iam.application.use_cases.authentication.login_with_password import LoginWithPasswordUseCase
from app.modules.iam.application.use_cases.authentication.microsoft_login import (STATE_TTL,
                                                                                  MicrosoftCallbackUseCase,
                                                                                  StartMicrosoftLoginUseCase)
from app.modules.iam.application.use_cases.authentication.password_recovery import (ChangePasswordUseCase,
                                                                                    ForgotPasswordUseCase,
                                                                                    ResetPasswordUseCase)
from app.modules.iam.application.use_cases.authentication.sessions import LogoutUseCase, RefreshSessionUseCase
from app.modules.iam.domain.services.audit_service import RequestMeta
from app.modules.iam.infrastructure.repositories.argon2_password_hasher import Argon2PasswordHasher, hasher
from app.modules.iam.domain.services.authorization_service import Principal
from app.modules.iam.infrastructure.repositories.sqlalchemy_authorization_repository import (
    SqlAlchemyAuthorizationRepository)
from app.modules.iam.presentation.routes.dependencies import (CSRF_HEADER, Authenticated, authenticated,
                                                              clear_session_cookies, current_principal, get_oidc,
                                                              get_uow,
                                                              optional_authenticated, request_meta,
                                                              set_session_cookies)
from app.modules.iam.presentation.schemas.auth_schemas import (CsrfResponse, LoginResponse,
                                                               LogoutResponse, MeResponse, MessageResponse,
                                                               PermissionsResponse, ProvidersResponse)
from app.shared.config import settings
from app.shared.database import get_db
from app.shared.exceptions import DomainError
from app.shared.mailer import Mailer, get_mailer

router = APIRouter(prefix="/api/auth", tags=["Autenticación"])
STATE_COOKIE = "oidc_flow"
STATE_PATH = "/api/auth/microsoft"
GENERIC_FORGOT = "Si la cuenta existe, enviamos un enlace para restablecer la contraseña."


def get_hasher() -> Argon2PasswordHasher:
    return hasher


def _send(tasks: BackgroundTasks, mailer: Mailer, mail: OutgoingMail | None) -> None:
    if mail:  # en segundo plano: la respuesta tarda lo mismo exista o no la cuenta
        tasks.add_task(mailer.send, mail.to, mail.subject, mail.body)


@router.get("/providers", response_model=ProvidersResponse)
def providers():
    """Métodos de inicio de sesión disponibles (el frontend muestra solo los configurados)."""
    return ProvidersResponse(password=True, microsoft=settings.microsoft_enabled)


@router.post("/login", response_model=LoginResponse)
def login(body: LoginDTO, response: Response, uow=Depends(get_uow), meta: RequestMeta = Depends(request_meta),
          pw=Depends(get_hasher)):
    issued, user = LoginWithPasswordUseCase(uow, pw, settings).execute(body, meta)
    set_session_cookies(response, issued.token, issued.csrf_token)
    return LoginResponse(user=MeResponse.build(user, issued.session), csrf_token=issued.csrf_token)


@router.post("/logout", response_model=LogoutResponse)
def logout(response: Response, auth: Authenticated = Depends(authenticated), uow=Depends(get_uow),
           meta: RequestMeta = Depends(request_meta)):
    provider = LogoutUseCase(uow).execute(auth.session, meta)
    clear_session_cookies(response)
    federated = get_oidc().logout_url() if provider == "microsoft" and settings.microsoft_enabled else None
    return LogoutResponse(federated_logout_url=federated)


@router.get("/me", response_model=MeResponse)
def me(auth: Authenticated = Depends(authenticated)):
    return MeResponse.build(auth.user, auth.session)


@router.get("/me/permissions", response_model=PermissionsResponse)
def my_permissions(principal: Principal = Depends(current_principal), db: Session = Depends(get_db)):
    repo = SqlAlchemyAuthorizationRepository(db)
    return PermissionsResponse.of(principal, repo.unit_type_codes(), repo.permission_names())


@router.post("/refresh", response_model=CsrfResponse)
def refresh(request: Request, response: Response, uow=Depends(get_uow), meta: RequestMeta = Depends(request_meta)):
    """Rota el token de sesión (y el CSRF). Llamar periódicamente y de a una petición a la vez."""
    token, csrf = RefreshSessionUseCase(uow, settings).execute(
        request.cookies.get(settings.session_cookie_name), request.headers.get(CSRF_HEADER), meta)
    set_session_cookies(response, token, csrf)
    return CsrfResponse(csrf_token=csrf)


@router.post("/register", response_model=MeResponse, status_code=status.HTTP_201_CREATED)
def register(body: RegisterDTO, uow=Depends(get_uow), meta: RequestMeta = Depends(request_meta),
             pw=Depends(get_hasher)):
    """Solo con invitación: activa la cuenta invitada definiendo una contraseña."""
    return MeResponse.build(AcceptInvitationUseCase(uow, pw, settings).execute(body, meta))


@router.post("/verify-email", response_model=MessageResponse)
def verify_email(body: TokenDTO, uow=Depends(get_uow), meta: RequestMeta = Depends(request_meta)):
    VerifyEmailUseCase(uow, settings).execute(body.token, meta)
    return MessageResponse(detail="Correo verificado")


@router.post("/forgot-password", response_model=MessageResponse, status_code=status.HTTP_202_ACCEPTED)
def forgot_password(body: ForgotPasswordDTO, tasks: BackgroundTasks, uow=Depends(get_uow),
                    meta: RequestMeta = Depends(request_meta), mailer: Mailer = Depends(get_mailer)):
    _send(tasks, mailer, ForgotPasswordUseCase(uow, settings).execute(body.email, meta))
    return MessageResponse(detail=GENERIC_FORGOT)


@router.post("/reset-password", response_model=MessageResponse)
def reset_password(body: ResetPasswordDTO, uow=Depends(get_uow), meta: RequestMeta = Depends(request_meta),
                   pw=Depends(get_hasher)):
    ResetPasswordUseCase(uow, pw, settings).execute(body, meta)
    return MessageResponse(detail="Contraseña actualizada. Inicia sesión de nuevo.")


@router.post("/change-password", response_model=MessageResponse)
def change_password(body: ChangePasswordDTO, auth: Authenticated = Depends(authenticated), uow=Depends(get_uow),
                    meta: RequestMeta = Depends(request_meta), pw=Depends(get_hasher)):
    ChangePasswordUseCase(uow, pw, settings).execute(auth.user, auth.session, body, meta)
    return MessageResponse(detail="Contraseña actualizada. Las demás sesiones se cerraron.")


# ---------- Microsoft Entra ID ----------
@router.get("/microsoft/login")
def microsoft_login(next: str | None = Query(None, max_length=500), invitation: str | None = Query(None, max_length=200),
                    link: bool = False, link_token: str | None = Query(None, max_length=200),
                    auth: Authenticated | None = Depends(optional_authenticated), oidc=Depends(get_oidc)):
    """Redirige a Microsoft. `invitation` = aceptar invitación; `link=true` = vincular a la sesión actual;
    `link_token` = vinculación pedida por un administrador."""
    if link and not auth:
        return RedirectResponse(f"{settings.frontend_url}{settings.frontend_login_path}?error=session_required",
                                status_code=302)
    start = StartMicrosoftLoginUseCase(oidc, settings).execute(next, invitation, auth.user.id if link else None,
                                                               link_token)
    response = RedirectResponse(start.redirect_url, status_code=302)
    response.set_cookie(STATE_COOKIE, start.state_cookie, httponly=True, secure=settings.cookie_secure,
                        samesite="lax", path=STATE_PATH, max_age=int(STATE_TTL.total_seconds()))
    return response


@router.get("/microsoft/callback")
def microsoft_callback(request: Request, code: str | None = Query(None, max_length=4000),
                       state: str | None = Query(None, max_length=200), error: str | None = Query(None, max_length=200),
                       uow=Depends(get_uow), meta: RequestMeta = Depends(request_meta), oidc=Depends(get_oidc),
                       auth: Authenticated | None = Depends(optional_authenticated)):
    """Microsoft redirige aquí. Siempre termina en una redirección al frontend (sin detalles internos)."""
    try:
        if error:
            raise DomainError("microsoft_denied")
        result = MicrosoftCallbackUseCase(uow, oidc, settings).execute(
            code, state, request.cookies.get(STATE_COOKIE), auth.user.id if auth else None, meta)
        response = RedirectResponse(f"{settings.frontend_url}{result.next_path}", status_code=302)
        if result.issued:
            set_session_cookies(response, result.issued.token, result.issued.csrf_token)
    except DomainError as e:
        response = RedirectResponse(
            f"{settings.frontend_url}{settings.frontend_login_path}?error=microsoft&code={e.status_code}",
            status_code=302)
    response.delete_cookie(STATE_COOKIE, path=STATE_PATH)
    return response
