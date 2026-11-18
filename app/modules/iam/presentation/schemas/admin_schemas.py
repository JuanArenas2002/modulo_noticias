from datetime import datetime

from pydantic import BaseModel

from app.modules.iam.domain.entities.access import Permission, Role, RoleAssignment
from app.modules.iam.domain.entities.audit import AuditLog
from app.modules.iam.domain.entities.identity import AuthSession, User
from app.modules.iam.presentation.schemas.auth_schemas import MeResponse


class Page[T](BaseModel):
    items: list[T]
    total: int
    limit: int
    offset: int


class AdminIdentityResponse(BaseModel):
    id: int
    provider: str
    tenant_id: str
    email_at_link: str | None
    linked_at: datetime
    last_used_at: datetime | None


class UserResponse(MeResponse):
    created_at: datetime
    updated_at: datetime
    locked_until: datetime | None
    linked_identities: list[AdminIdentityResponse]

    @classmethod
    def of(cls, u: User) -> "UserResponse":
        return cls(**MeResponse.build(u).model_dump(), created_at=u.created_at, updated_at=u.updated_at,
                   locked_until=u.password.locked_until if u.password else None,
                   linked_identities=[AdminIdentityResponse(id=i.id, provider=i.provider.code, tenant_id=i.tenant_id,
                                                            email_at_link=i.email_at_link, linked_at=i.linked_at,
                                                            last_used_at=i.last_used_at) for i in u.identities])


class SessionResponse(BaseModel):
    id: int
    method: str
    ip: str | None
    user_agent: str | None
    created_at: datetime
    last_seen_at: datetime
    expires_at: datetime

    @classmethod
    def of(cls, s: AuthSession) -> "SessionResponse":
        return cls(id=s.id, method=s.provider.code, ip=s.ip, user_agent=s.user_agent, created_at=s.created_at,
                   last_seen_at=s.last_seen_at, expires_at=s.expires_at)


class AssignmentResponse(BaseModel):
    id: int
    role: str
    role_name: str
    scope_type: str | None  # None = institucional
    scope_id: int | None
    assigned_by: int | None
    assigned_at: datetime
    revoked_at: datetime | None
    revoked_by: int | None
    revoke_reason: str | None
    is_active: bool

    @classmethod
    def of(cls, a: RoleAssignment) -> "AssignmentResponse":
        return cls(id=a.id, role=a.role.code, role_name=a.role.name, scope_type=a.scope_type.code if a.scope_type else None,
                   scope_id=a.scope_id, assigned_by=a.assigned_by, assigned_at=a.assigned_at,
                   revoked_at=a.revoked_at, revoked_by=a.revoked_by, revoke_reason=a.revoke_reason,
                   is_active=a.is_active)


class PermissionResponse(BaseModel):
    id: int
    code: str
    name: str
    description: str | None
    module: str
    resource: str
    action: str
    is_active: bool

    @classmethod
    def of(cls, p: Permission) -> "PermissionResponse":
        return cls(id=p.id, code=p.code, name=p.name, description=p.description, module=p.module,
                   resource=p.resource, action=p.action, is_active=p.is_active)


class RoleResponse(BaseModel):
    id: int
    code: str
    name: str
    description: str | None
    is_active: bool
    permissions: list[str]
    permission_names: dict[str, str]  # código -> nombre legible
    created_at: datetime
    updated_at: datetime

    @classmethod
    def of(cls, r: Role) -> "RoleResponse":
        return cls(id=r.id, code=r.code, name=r.name, description=r.description, is_active=r.is_active,
                   permissions=sorted(p.code for p in r.permissions),
                   permission_names={p.code: p.name for p in r.permissions}, created_at=r.created_at,
                   updated_at=r.updated_at)


class AuditResponse(BaseModel):
    id: int
    actor_user_id: int | None
    actor_name: str | None = None
    event_type: str
    result: str
    resource_type: str | None
    resource_id: str | None
    ip: str | None
    context: dict | None
    at: datetime

    @classmethod
    def of(cls, a: AuditLog) -> "AuditResponse":
        return cls(id=a.id, actor_user_id=a.actor_user_id, event_type=a.event_type, result=a.result,
                   resource_type=a.resource_type, resource_id=a.resource_id, ip=a.ip, context=a.context, at=a.at)


def page(items, total, f, mapper) -> dict:
    return {"items": [mapper(x) for x in items], "total": total, "limit": f.limit, "offset": f.offset}
