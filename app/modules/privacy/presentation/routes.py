"""Endpoints de privacidad y consentimiento.

Públicos (sin cuenta; cada navegador solo ve y cambia SU decisión, identificada por la cookie cris_consent):
- GET  /api/privacy/policies                    versión vigente de cada política + historial de versiones
- GET  /api/privacy/policies/{kind}/{version}   una versión publicada (trazabilidad)
- GET  /api/privacy/cookie-categories           categorías, finalidad, tecnologías y duración
- GET  /api/privacy/preferences                 decisión vigente y si hay que preguntar
- POST /api/privacy/consents                    registrar o cambiar la decisión (fija la cookie)
- POST /api/privacy/consents/revoke             revocar: todo lo opcional apagado
Administración (permiso privacy.manage, auditado):
- GET/POST /api/admin/privacy/policies, PATCH /api/admin/privacy/policies/{id} (solo antes de entrar en vigor)
- PATCH /api/admin/privacy/cookie-categories/{code}
- GET /api/admin/privacy/consents/summary       agregados, nunca decisiones individuales
"""
import uuid
from datetime import datetime, timedelta
from typing import Literal

from fastapi import APIRouter, Depends, Request, Response
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy.orm import Session

from app.modules.iam.domain.services.audit_service import event
from app.modules.iam.domain.services.authorization_service import Principal
from app.modules.iam.infrastructure.repositories.sqlalchemy_iam_repositories import SqlAlchemyIamUnitOfWork
from app.modules.iam.presentation.routes.dependencies import optional_principal, request_meta, require_permission
from app.modules.news.application.validators.news_validators import sanitize_html
from app.modules.privacy.domain.rules import COOKIE, DECIDED_COOKIE, KINDS, METHODS, VALIDITY
from app.modules.privacy.infrastructure.repository import PrivacyRepository
from app.shared.clock import as_utc, now
from app.shared.config import settings
from app.shared.database import get_db
from app.shared.exceptions import ConflictError, NotFoundError, TooManyRequestsError
from app.shared.rate_limit import Limiter

router = APIRouter(tags=["Privacidad y consentimiento"])
PERMISSION = "privacy.manage"
limiter = Limiter(30)  # decisiones por IP y minuto: de sobra para personas, corta abusos


def _subject(request: Request) -> str | None:
    value = request.cookies.get(COOKIE)
    try:
        return str(uuid.UUID(value)) if value else None
    except ValueError:
        return None  # cookie manipulada: como si no hubiera decisión


# ---------- público ----------
@router.get("/api/privacy/policies")
def policies(db: Session = Depends(get_db)):
    return PrivacyRepository(db).current_policies(now())


@router.get("/api/privacy/policies/{kind}/{version}")
def policy_version(kind: Literal[KINDS], version: int, db: Session = Depends(get_db)):
    if (p := PrivacyRepository(db).policy(kind, version, now())) is None:
        raise NotFoundError("Versión no publicada")
    return p


@router.get("/api/privacy/cookie-categories")
def cookie_categories(db: Session = Depends(get_db)):
    return PrivacyRepository(db).categories()


@router.get("/api/privacy/preferences")
def preferences(request: Request, response: Response, db: Session = Depends(get_db)):
    response.headers["Cache-Control"] = "no-store"
    state = PrivacyRepository(db).state(_subject(request), now())
    if state["consent"] and not request.cookies.get(DECIDED_COOKIE):  # decisiones anteriores a la marca
        _mark_decided(response)
    return state


def _mark_decided(response: Response) -> None:
    response.set_cookie(DECIDED_COOKIE, "1", max_age=int(VALIDITY.total_seconds()), httponly=False, path="/",
                        secure=settings.cookie_secure, samesite="lax")


class ConsentIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    functional: bool
    analytics: bool
    method: Literal[METHODS[:3]] = Field(description="accept_all | reject_optional | custom")


def _save(request: Request, response: Response, db: Session, user: Principal | None, categories: dict,
          method: str):
    at = now()
    if not limiter.allow(request_meta(request).ip or "-", 1, at):
        raise TooManyRequestsError("Demasiadas solicitudes; intenta en un minuto")
    subject = _subject(request) or str(uuid.uuid4())
    repo = PrivacyRepository(db)
    repo.decide(subject, user.user_id if user else None, categories, method, at)
    # Cookie NECESARIA (guarda la decisión): HttpOnly, solo este sitio, vence con la decisión.
    response.set_cookie(COOKIE, subject, max_age=int(VALIDITY.total_seconds()), httponly=True, path="/",
                        secure=settings.cookie_secure, samesite="lax")
    _mark_decided(response)
    response.headers["Cache-Control"] = "no-store"
    return repo.state(subject, at)


@router.post("/api/privacy/consents")
def give_consent(body: ConsentIn, request: Request, response: Response, db: Session = Depends(get_db),
                 user: Principal | None = Depends(optional_principal)):
    return _save(request, response, db, user, {"functional": body.functional, "analytics": body.analytics},
                 body.method)


@router.post("/api/privacy/consents/revoke")
def revoke_consent(request: Request, response: Response, db: Session = Depends(get_db),
                   user: Principal | None = Depends(optional_principal)):
    """Tan fácil como autorizar: un clic. Queda registrada la revocación (prueba) y todo lo opcional se apaga."""
    return _save(request, response, db, user, {}, "revoke")


# ---------- administración ----------
class PolicyIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    kind: Literal[KINDS]
    title: str = Field(min_length=3, max_length=200)
    summary: str = Field(min_length=1, max_length=2000)
    content: str = Field(min_length=1, max_length=100_000)
    effective_at: datetime
    requires_reconsent: bool = False


class PolicyPatch(BaseModel):
    model_config = ConfigDict(extra="forbid")
    title: str | None = Field(None, min_length=3, max_length=200)
    summary: str | None = Field(None, min_length=1, max_length=2000)
    content: str | None = Field(None, min_length=1, max_length=100_000)
    effective_at: datetime | None = None
    requires_reconsent: bool | None = None


class Technology(BaseModel):
    model_config = ConfigDict(extra="forbid")
    name: str = Field(min_length=1, max_length=100)
    type: Literal["cookie", "localStorage", "sessionStorage", "server", "third_party"]
    duration: str = Field(min_length=1, max_length=100)
    provider: str = Field(min_length=1, max_length=100)
    purpose: str = Field(min_length=1, max_length=500)


class CategoryPatch(BaseModel):
    model_config = ConfigDict(extra="forbid")
    name: str | None = Field(None, min_length=2, max_length=100)
    description: str | None = Field(None, min_length=1, max_length=2000)
    purpose: str | None = Field(None, min_length=1, max_length=2000)
    retention: str | None = Field(None, min_length=1, max_length=500)
    technologies: list[Technology] | None = None


def _audit(db: Session, request: Request, user: Principal, event_type: str, resource_type: str, resource_id,
           **context) -> None:
    SqlAlchemyIamUnitOfWork(db).audit.add(event(event_type, "success", request_meta(request), user.user_id,
                                                resource_type, resource_id, **context))


@router.get("/api/admin/privacy/policies")
def admin_policies(db: Session = Depends(get_db), _: Principal = Depends(require_permission(PERMISSION))):
    return PrivacyRepository(db).all_policies()


@router.post("/api/admin/privacy/policies", status_code=201)
def admin_create_policy(body: PolicyIn, request: Request, db: Session = Depends(get_db),
                        user: Principal = Depends(require_permission(PERMISSION))):
    """Nueva versión (las vigentes no se editan: así queda la trazabilidad de qué decía cada versión)."""
    at = now()
    p = PrivacyRepository(db).add_policy(body.model_dump() | {
        "content": sanitize_html(body.content), "effective_at": as_utc(body.effective_at), "created_at": at,
        "updated_at": at, "created_by": user.user_id})
    _audit(db, request, user, "privacy.policy.create", "privacy_policy", p["id"], kind=p["kind"], version=p["version"],
           requires_reconsent=p["requires_reconsent"])
    db.commit()
    return p


@router.patch("/api/admin/privacy/policies/{policy_id}")
def admin_update_policy(policy_id: int, body: PolicyPatch, request: Request, db: Session = Depends(get_db),
                        user: Principal = Depends(require_permission(PERMISSION))):
    repo, at = PrivacyRepository(db), now()
    if (p := repo.policy_by_id(policy_id)) is None:
        raise NotFoundError("Política no encontrada")
    if as_utc(p["effective_at"]) <= at:
        raise ConflictError("Esta versión ya está vigente: publica una versión nueva")
    values = body.model_dump(exclude_none=True)
    if "content" in values:
        values["content"] = sanitize_html(values["content"])
    if "effective_at" in values:
        values["effective_at"] = as_utc(values["effective_at"])
    p = repo.update_policy(policy_id, values | {"updated_at": at})
    _audit(db, request, user, "privacy.policy.update", "privacy_policy", policy_id, fields=sorted(values))
    db.commit()
    return p


@router.patch("/api/admin/privacy/cookie-categories/{code}")
def admin_update_category(code: str, body: CategoryPatch, request: Request, db: Session = Depends(get_db),
                          user: Principal = Depends(require_permission(PERMISSION))):
    values = body.model_dump(exclude_none=True)
    if (c := PrivacyRepository(db).update_category(code, values | {"updated_at": now()})) is None:
        raise NotFoundError("Categoría no encontrada")
    _audit(db, request, user, "privacy.category.update", "cookie_category", code, fields=sorted(values))
    db.commit()
    return c


@router.get("/api/admin/privacy/consents/summary")
def admin_summary(days: int = 30, db: Session = Depends(get_db),
                  _: Principal = Depends(require_permission(PERMISSION))):
    return PrivacyRepository(db).summary(now() - timedelta(days=max(1, min(days, 3650))))
