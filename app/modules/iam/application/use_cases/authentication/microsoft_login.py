"""Inicio de sesión con Microsoft Entra ID (OIDC Authorization Code + PKCE).

El estado del flujo (state, nonce, code_verifier, destino) viaja en una cookie efímera firmada y HttpOnly.
Vinculación de identidades, nunca por coincidencia de correo:
  - login normal: la identidad (tid, oid) ya está vinculada a un usuario;
  - invitación: el invitado prueba control del correo (enlace) y de la cuenta Microsoft (login) a la vez;
  - vinculación: un usuario con sesión activa prueba control de la cuenta Microsoft;
  - vinculación administrativa: enlace de un solo uso al correo de la cuenta + login Microsoft.
"""
import base64
import hashlib
from dataclasses import dataclass
from datetime import timedelta

from app.modules.iam.application.use_cases.authentication.common import LINK_IDENTITY, audit, valid_token, window
from app.modules.iam.application.use_cases.authentication.invitations import INVITATION, activate
from app.modules.iam.domain.entities.identity import User, UserIdentity
from app.modules.iam.domain.repositories.iam_repositories import IamUnitOfWork, OidcClient
from app.modules.iam.domain.services import session_service
from app.modules.iam.domain.services.audit_service import RequestMeta
from app.shared.clock import now
from app.shared.config import Settings
from app.shared.exceptions import ConflictError, ForbiddenError, InvalidDataError, UnauthorizedError
from app.shared.security import hash_token, new_token, same, sign, unsign

STATE_PURPOSE = "oidc_state"
STATE_TTL = timedelta(minutes=10)
INVALID = "No fue posible validar la identidad de Microsoft"


def safe_next(path: str | None) -> str:
    """Solo rutas relativas del propio frontend (evita open redirect)."""
    return path if path and path.startswith("/") and not path.startswith("//") and "\\" not in path else "/"


@dataclass(frozen=True)
class MicrosoftStart:
    redirect_url: str
    state_cookie: str


@dataclass(frozen=True)
class MicrosoftResult:
    next_path: str
    issued: session_service.IssuedSession | None  # None = solo se vinculó la identidad a la sesión actual
    user: User


class StartMicrosoftLoginUseCase:
    def __init__(self, oidc: OidcClient, cfg: Settings):
        self.oidc, self.cfg = oidc, cfg

    def execute(self, next_path: str | None, invitation: str | None = None,
                link_user_id: int | None = None, link_token: str | None = None) -> MicrosoftStart:
        state, nonce, verifier = new_token(), new_token(), new_token() + new_token()  # verifier: 43-128 chars
        challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b"=").decode()
        cookie = sign({"st": state, "nn": nonce, "cv": verifier, "nx": safe_next(next_path),
                       "inv": hash_token(invitation) if invitation else None, "lnk": link_user_id,
                       "ltk": hash_token(link_token) if link_token else None},
                      self.cfg.secret_key, STATE_TTL, STATE_PURPOSE)
        return MicrosoftStart(self.oidc.authorization_url(state, nonce, challenge), cookie)


class MicrosoftCallbackUseCase:
    def __init__(self, uow: IamUnitOfWork, oidc: OidcClient, cfg: Settings):
        self.uow, self.oidc, self.cfg = uow, oidc, cfg

    def _fail(self, meta: RequestMeta, reason: str, exc: Exception):
        audit(self.uow, "auth.login", "failure", meta, method="microsoft", reason=reason)
        self.uow.commit()
        raise exc

    def execute(self, code: str | None, state: str | None, state_cookie: str | None,
                current_user_id: int | None, meta: RequestMeta) -> MicrosoftResult:
        at = now()
        flow = unsign(state_cookie, self.cfg.secret_key, STATE_PURPOSE)
        if not flow or not state or not code or not same(state, flow["st"]):
            self._fail(meta, "bad_state", UnauthorizedError(INVALID))  # callback manipulado o expirado
        try:
            claims = self.oidc.validate_id_token(self.oidc.exchange_code(code, flow["cv"]), flow["nn"])
        except UnauthorizedError as e:
            self._fail(meta, "invalid_token", e)
        tid, oid = claims["tid"], claims["oid"]
        email = (claims.get("email") or claims.get("preferred_username") or "").lower() or None
        identity = self.uow.users.by_identity("microsoft", tid, oid)

        if flow.get("lnk"):  # vincular a la cuenta con sesión activa
            if current_user_id != flow["lnk"]:
                self._fail(meta, "link_session_mismatch", UnauthorizedError(INVALID))
            user = self.uow.users.get(current_user_id)
            if identity and identity.user_id != user.id:
                self._fail(meta, "identity_taken", ConflictError("Esa cuenta de Microsoft ya está vinculada a otro usuario"))
            if not identity:
                self._link(user, tid, oid, email, meta, via="session")
            self.uow.commit()
            return MicrosoftResult(flow["nx"], None, user)

        if flow.get("ltk"):  # vinculación pedida por un administrador (enlace al correo de la cuenta)
            try:
                token = valid_token(self.uow, flow["ltk"], LINK_IDENTITY, at)
            except InvalidDataError as e:
                self._fail(meta, "bad_link_token", e)
            if identity and identity.user_id != token.user_id:
                self._fail(meta, "identity_taken", ConflictError("Esa cuenta de Microsoft ya está vinculada a otro usuario"))
            user = self.uow.users.get(token.user_id)
            token.used_at = at
            identity = identity or self._link(user, tid, oid, email, meta, via="admin_request")
        elif identity:
            user = self.uow.users.get(identity.user_id)
        elif flow.get("inv"):
            try:
                token = valid_token(self.uow, flow["inv"], INVITATION, at)
            except InvalidDataError as e:
                self._fail(meta, "bad_invitation", e)
            user = self.uow.users.get(token.user_id)
            token.used_at = at
            activate(self.uow, user, at)
            identity = self._link(user, tid, oid, email, meta, via="invitation")
        elif self.cfg.microsoft_auto_provision:
            if email and self.uow.users.by_email(email):  # no se vincula por correo
                self._fail(meta, "email_exists_unlinked",
                           ForbiddenError("Ya existe una cuenta con ese correo. Pide a un administrador vincularla."))
            user = User(first_name=claims.get("given_name") or claims.get("name") or "Usuario",
                        last_name=claims.get("family_name") or "-", email=email or f"{oid}@{tid}",
                        status=self.uow.users.status("active"), account_type=self.uow.users.account_type("institutional"),
                        email_verified_at=at, created_at=at, updated_at=at)
            self.uow.users.add(user)
            identity = self._link(user, tid, oid, email, meta, via="auto_provision")
        else:
            self._fail(meta, "not_provisioned", ForbiddenError("Tu cuenta no está habilitada en la plataforma"))

        if not user or not user.status.can_login:
            self._fail(meta, "status", ForbiddenError("Tu cuenta no está habilitada en la plataforma"))
        identity = identity or self.uow.users.by_identity("microsoft", tid, oid)
        identity.last_used_at = user.last_login_at = at
        issued = session_service.issue(user.id, self.uow.users.provider("microsoft"), window(self.cfg), at,
                                       meta.ip, meta.user_agent, identity_id=identity.id)
        self.uow.sessions.add(issued.session)
        audit(self.uow, "auth.login", "success", meta, user.id, "session", issued.session.id, method="microsoft")
        self.uow.commit()
        return MicrosoftResult(flow["nx"], issued, user)

    def _link(self, user: User, tid: str, oid: str, email: str | None, meta: RequestMeta, via: str) -> UserIdentity:
        identity = UserIdentity(user_id=user.id, provider=self.uow.users.provider("microsoft"), tenant_id=tid,
                                subject=oid, email_at_link=email)
        user.identities.append(identity)
        self.uow.users.add(user)  # flush: asigna id a la identidad
        audit(self.uow, "auth.identity.linked", "success", meta, user.id, "user", user.id, provider="microsoft", via=via)
        return identity
