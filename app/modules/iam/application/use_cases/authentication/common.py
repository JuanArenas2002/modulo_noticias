"""Piezas compartidas por los casos de uso de autenticación."""
from dataclasses import dataclass
from datetime import datetime, timedelta

from app.modules.iam.domain.entities.identity import User, UserToken
from app.modules.iam.domain.repositories.iam_repositories import IamUnitOfWork
from app.modules.iam.domain.services.audit_service import RequestMeta, event
from app.modules.iam.domain.services.password_policy import PasswordPolicy
from app.modules.iam.domain.services.session_service import SessionWindow
from app.shared.clock import as_utc
from app.shared.config import Settings
from app.shared.exceptions import InvalidDataError, TooManyRequestsError
from app.shared.security import hash_token, new_token

INVALID_TOKEN = "El enlace no es válido o ya expiró"
LINK_IDENTITY = "link_identity"  # enlace de vinculación emitido por un administrador


@dataclass(frozen=True)
class OutgoingMail:
    """Correo a enviar en segundo plano (respuesta en tiempo constante, no revela si la cuenta existe)."""
    to: str
    subject: str
    body: str


def window(cfg: Settings) -> SessionWindow:
    return SessionWindow(idle=timedelta(minutes=cfg.session_idle_minutes),
                         absolute=timedelta(hours=cfg.session_absolute_hours))


def check_password(cfg: Settings, password: str, user: User) -> None:
    policy = PasswordPolicy(cfg.password_min_length, cfg.password_max_length)
    if problems := policy.problems(password, (user.email.split("@")[0], user.first_name, user.last_name)):
        raise InvalidDataError("; ".join(problems))


def rate_limit(uow: IamUnitOfWork, cfg: Settings, event_type: str, meta: RequestMeta, at: datetime) -> None:
    """Límite por IP sobre eventos auditados (sirve con varias instancias: el estado vive en BD)."""
    since = at - timedelta(minutes=cfg.rate_limit_window_minutes)
    if meta.ip and uow.audit.count_recent(event_type, meta.ip, since) >= cfg.rate_limit_per_ip:
        raise TooManyRequestsError("Demasiados intentos. Intenta más tarde.")


def issue_token(uow: IamUnitOfWork, user_id: int, purpose: str, ttl: timedelta, at: datetime,
                created_by: int | None = None, context: dict | None = None) -> str:
    uow.tokens.invalidate(user_id, purpose, at)  # solo el último enlace emitido es válido
    raw = new_token()
    uow.tokens.add(UserToken(user_id=user_id, purpose=purpose, token_hash=hash_token(raw), expires_at=at + ttl,
                             created_by=created_by, context=context, created_at=at))
    return raw


def valid_token(uow: IamUnitOfWork, token_hash: str, purpose: str, at: datetime) -> UserToken:
    """Valida sin consumir: el caller marca used_at solo si la operación completa sale bien
    (una contraseña débil no debe quemar el enlace)."""
    t = uow.tokens.by_hash(token_hash)
    if t is None or t.purpose != purpose or t.used_at is not None or as_utc(t.expires_at) <= at:
        raise InvalidDataError(INVALID_TOKEN)
    return t


def audit(uow: IamUnitOfWork, event_type: str, result: str, meta: RequestMeta, actor_id=None,
          resource_type: str | None = None, resource_id=None, **context) -> None:
    uow.audit.add(event(event_type, result, meta, actor_id, resource_type, resource_id, **context))
