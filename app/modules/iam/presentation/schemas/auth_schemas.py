from datetime import datetime

from pydantic import BaseModel

from app.modules.iam.domain.entities.identity import AuthSession, User


class IdentityResponse(BaseModel):
    provider: str
    tenant_id: str
    linked_at: datetime
    last_used_at: datetime | None


class SessionInfo(BaseModel):
    id: int
    method: str
    created_at: datetime
    expires_at: datetime


class MeResponse(BaseModel):
    id: int
    first_name: str
    last_name: str
    email: str
    status: str
    account_type: str
    email_verified: bool
    last_login_at: datetime | None
    auth_methods: list[str]
    identities: list[IdentityResponse]
    must_change_password: bool
    session: SessionInfo | None = None

    @classmethod
    def build(cls, u: User, s: AuthSession | None = None) -> "MeResponse":
        methods = sorted({i.provider.code for i in u.identities} | ({"password"} if u.password else set()))
        return cls(id=u.id, first_name=u.first_name, last_name=u.last_name, email=u.email, status=u.status.code,
                   account_type=u.account_type.code, email_verified=u.email_verified_at is not None,
                   last_login_at=u.last_login_at, auth_methods=methods,
                   identities=[IdentityResponse(provider=i.provider.code, tenant_id=i.tenant_id, linked_at=i.linked_at,
                                                last_used_at=i.last_used_at) for i in u.identities],
                   must_change_password=bool(u.password and u.password.must_change),
                   session=SessionInfo(id=s.id, method=s.provider.code, created_at=s.created_at,
                                       expires_at=s.expires_at) if s else None)


class GrantResponse(BaseModel):
    permission: str
    permission_name: str
    scope_type: str | None  # None = institucional
    scope_id: int | None


class PermissionsResponse(BaseModel):
    """Para que el frontend decida qué mostrar. El backend vuelve a verificar todo igual."""
    permissions: list[str]      # códigos efectivos en algún alcance
    grants: list[GrantResponse]  # tal como están asignados (la herencia a programas se aplica en el backend)

    names: dict[str, str]        # código -> nombre legible de cada permiso efectivo

    @classmethod
    def of(cls, p, unit_type_codes: dict[int, str], names: dict[str, str]) -> "PermissionsResponse":
        grants = sorted(set(p.grants), key=lambda g: (g.permission, g.scope_type_id or 0, g.scope_id or 0))
        return cls(permissions=p.permissions, names={c: names.get(c, c) for c in p.permissions}, grants=[
            GrantResponse(permission=g.permission, permission_name=names.get(g.permission, g.permission),
                          scope_type=unit_type_codes.get(g.scope_type_id), scope_id=g.scope_id)
            for g in grants])


class LoginResponse(BaseModel):
    user: MeResponse
    csrf_token: str  # enviar en X-CSRF-Token en cada POST/PUT/PATCH/DELETE


class CsrfResponse(BaseModel):
    csrf_token: str


class LogoutResponse(BaseModel):
    federated_logout_url: str | None  # si la sesión fue con Microsoft: navegar ahí para cerrar también en Entra


class ProvidersResponse(BaseModel):
    password: bool
    microsoft: bool


class MessageResponse(BaseModel):
    detail: str
