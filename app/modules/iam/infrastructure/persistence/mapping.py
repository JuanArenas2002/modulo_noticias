"""Mapeo imperativo del IAM sobre las dataclasses de dominio."""
from sqlalchemy.orm import relationship

from app.modules.iam.domain.entities import access as a
from app.modules.iam.domain.entities import audit as au
from app.modules.iam.domain.entities import identity as i
from app.modules.iam.infrastructure.models import tables as t
from app.modules.organization.domain.entities.organization import OrgUnitType
from app.shared.database import mapper_registry

_started = False


def start_mappers() -> None:
    global _started
    if _started:
        return
    _started = True
    m = mapper_registry.map_imperatively

    m(i.UserStatus, t.user_statuses)
    m(i.AccountType, t.account_types)
    m(i.IdentityProvider, t.identity_providers)
    m(i.UserIdentity, t.user_identities, properties={
        "provider": relationship(i.IdentityProvider, lazy="joined"),
    })
    m(i.PasswordCredential, t.password_credentials)
    m(i.User, t.users, properties={
        "status": relationship(i.UserStatus, lazy="joined"),
        "account_type": relationship(i.AccountType, lazy="joined"),
        "identities": relationship(i.UserIdentity, foreign_keys=t.user_identities.c.user_id,
                                   cascade="all, delete-orphan", lazy="selectin"),
        "password": relationship(i.PasswordCredential, uselist=False, cascade="all, delete-orphan", lazy="selectin"),
    })
    m(i.AuthSession, t.auth_sessions, properties={"provider": relationship(i.IdentityProvider, lazy="joined")})
    m(i.UserToken, t.user_tokens)
    m(i.LoginAttempt, t.login_attempts)

    m(a.Permission, t.permissions)
    m(a.Role, t.roles, properties={
        "permissions": relationship(a.Permission, secondary=t.role_permissions, lazy="selectin"),
    })
    m(a.RoleAssignment, t.user_role_assignments, properties={
        "role": relationship(a.Role, lazy="joined"),
        "scope_type": relationship(OrgUnitType, lazy="joined"),
    })

    m(au.AuditLog, t.audit_logs)
