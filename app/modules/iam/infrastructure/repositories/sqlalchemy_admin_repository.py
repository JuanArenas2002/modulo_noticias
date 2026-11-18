import re

from sqlalchemy import exists, func, or_, select, text
from sqlalchemy.orm import Session

from app.modules.iam.domain.entities.access import Permission, Role, RoleAssignment
from app.modules.iam.domain.entities.audit import AuditLog
from app.modules.iam.domain.entities.identity import AccountType, AuthSession, User, UserIdentity, UserStatus
from app.modules.organization.domain.entities.organization import OrgUnitType
from app.shared.clock import as_utc

_IDENT = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")


def _escape(value: str) -> str:
    """Escapa comodines LIKE que vengan del usuario."""
    return value.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")


def _like(value: str) -> str:
    return "%" + _escape(value.lower()) + "%"


class SqlAlchemyAdminRepository:
    def __init__(self, s: Session):
        self.s = s

    def _page(self, stmt, sort_col, id_col, f) -> tuple[list, int]:
        """Total + página. id_col desempata para que la paginación sea estable."""
        total = self.s.scalar(select(func.count()).select_from(stmt.subquery()))
        order = sort_col.asc() if f.order == "asc" else sort_col.desc()
        rows = self.s.scalars(stmt.order_by(order, id_col.asc()).limit(f.limit).offset(f.offset)).unique()
        return list(rows), total

    # ---------- usuarios ----------
    def search_users(self, f) -> tuple[list[User], int]:
        stmt = select(User).where(User.deleted_at.is_(None))
        if f.q:
            p = _like(f.q)
            stmt = stmt.where(or_(func.lower(User.first_name).like(p, escape="\\"),
                                  func.lower(User.last_name).like(p, escape="\\"), User.email.like(p, escape="\\")))
        if f.status:
            stmt = stmt.where(User.status.has(UserStatus.code == f.status))
        if f.account_type:
            stmt = stmt.where(User.account_type.has(AccountType.code == f.account_type))
        if f.role:
            stmt = stmt.where(exists().where(RoleAssignment.user_id == User.id, RoleAssignment.revoked_at.is_(None),
                                             RoleAssignment.role.has(Role.code == f.role)))
        return self._page(stmt, getattr(User, f.sort), User.id, f)

    def session_of(self, user_id: int, session_id: int) -> AuthSession | None:
        s = self.s.get(AuthSession, session_id)
        return s if s and s.user_id == user_id else None

    def identity_of(self, user_id: int, identity_id: int) -> UserIdentity | None:
        i = self.s.get(UserIdentity, identity_id)
        return i if i and i.user_id == user_id else None

    def delete_identity(self, identity: UserIdentity) -> None:
        self.s.delete(identity)

    # ---------- asignaciones ----------
    def assignments(self, user_id: int, active_only: bool) -> list[RoleAssignment]:
        stmt = select(RoleAssignment).where(RoleAssignment.user_id == user_id)
        if active_only:
            stmt = stmt.where(RoleAssignment.revoked_at.is_(None))
        return list(self.s.scalars(stmt.order_by(RoleAssignment.id)).unique())

    def assignment_of(self, user_id: int, assignment_id: int) -> RoleAssignment | None:
        a = self.s.get(RoleAssignment, assignment_id)
        return a if a and a.user_id == user_id else None

    def add_assignment(self, a: RoleAssignment) -> None:
        self.s.add(a)
        self.s.flush()

    def active_assignment_count(self, role_id: int) -> int:
        return self.s.scalar(select(func.count()).where(RoleAssignment.role_id == role_id,
                                                        RoleAssignment.revoked_at.is_(None)))

    # ---------- roles / permisos ----------
    def search_roles(self, f) -> tuple[list[Role], int]:
        stmt = select(Role)
        if f.q:
            p = _like(f.q)
            stmt = stmt.where(or_(Role.code.like(p, escape="\\"), func.lower(Role.name).like(p, escape="\\")))
        if f.is_active is not None:
            stmt = stmt.where(Role.is_active.is_(f.is_active))
        return self._page(stmt, getattr(Role, f.sort), Role.id, f)

    def role(self, role_id: int) -> Role | None:
        return self.s.get(Role, role_id)

    def role_by_code(self, code: str) -> Role | None:
        return self.s.scalar(select(Role).where(Role.code == code))

    def add(self, entity) -> None:
        self.s.add(entity)
        self.s.flush()

    def search_permissions(self, f) -> tuple[list[Permission], int]:
        stmt = select(Permission)
        if f.q:
            p = _like(f.q)
            stmt = stmt.where(or_(Permission.code.like(p, escape="\\"), func.lower(Permission.name).like(p, escape="\\")))
        if f.module:
            stmt = stmt.where(Permission.module == f.module)
        if f.is_active is not None:
            stmt = stmt.where(Permission.is_active.is_(f.is_active))
        return self._page(stmt, getattr(Permission, f.sort), Permission.id, f)

    def permission(self, permission_id: int) -> Permission | None:
        return self.s.get(Permission, permission_id)

    def permissions_by_codes(self, codes: set[str]) -> list[Permission]:
        return list(self.s.scalars(select(Permission).where(Permission.code.in_(codes)))) if codes else []

    # ---------- organización ----------
    def unit_type(self, code: str) -> OrgUnitType | None:
        return self.s.scalar(select(OrgUnitType).where(OrgUnitType.code == code))

    def unit_exists(self, unit_type: OrgUnitType, unit_id: int) -> bool:
        table = unit_type.source_table
        if not table:
            return True  # tipo sin tabla local (p.ej. grupos aún no sincronizados): no se puede validar
        if not _IDENT.fullmatch(table):
            raise ValueError(f"source_table inválido: {table}")
        return bool(self.s.scalar(text(f"SELECT 1 FROM {table} WHERE id = :id"), {"id": unit_id}))

    # ---------- auditoría ----------
    def search_audit(self, f) -> tuple[list[AuditLog], int]:
        stmt = select(AuditLog)
        if f.event_type:
            stmt = stmt.where(AuditLog.event_type.like(_escape(f.event_type) + "%", escape="\\"))
        for col, value in ((AuditLog.actor_user_id, f.actor_id), (AuditLog.resource_type, f.resource_type),
                           (AuditLog.resource_id, f.resource_id), (AuditLog.result, f.result)):
            if value is not None:
                stmt = stmt.where(col == value)
        if f.since:
            stmt = stmt.where(AuditLog.at >= as_utc(f.since))
        if f.until:
            stmt = stmt.where(AuditLog.at <= as_utc(f.until))
        return self._page(stmt, AuditLog.at, AuditLog.id, f)

    def global_holders(self, permission_code: str) -> set[int]:
        """Usuarios habilitados que tienen `permission_code` con alcance institucional (para no dejar la
        plataforma sin administrador)."""
        q = text("""
            SELECT DISTINCT a.user_id FROM user_role_assignments a
            JOIN roles r ON r.id = a.role_id AND r.is_active
            JOIN role_permissions rp ON rp.role_id = r.id
            JOIN permissions p ON p.id = rp.permission_id AND p.is_active AND p.code = :code
            JOIN users u ON u.id = a.user_id AND u.deleted_at IS NULL
            JOIN user_statuses st ON st.id = u.status_id AND st.can_login
            WHERE a.revoked_at IS NULL AND a.scope_type_id IS NULL""")
        return {uid for (uid,) in self.s.execute(q, {"code": permission_code})}

    def detach_identity_sessions(self, identity_id: int, at, reason: str) -> None:
        """Las sesiones abiertas con una identidad desvinculada se revocan (y se conserva su registro)."""
        for s in self.s.scalars(select(AuthSession).where(AuthSession.identity_id == identity_id)):
            s.identity_id = None
            if s.revoked_at is None:
                s.revoked_at, s.revoked_reason = at, reason
        self.s.flush()

    def permission_codes(self, user_id: int) -> set[str]:
        q = text("""
            SELECT DISTINCT p.code FROM user_role_assignments a
            JOIN roles r ON r.id = a.role_id AND r.is_active
            JOIN role_permissions rp ON rp.role_id = r.id
            JOIN permissions p ON p.id = rp.permission_id AND p.is_active
            WHERE a.user_id = :u AND a.revoked_at IS NULL""")
        return {code for (code,) in self.s.execute(q, {"u": user_id})}
