import re

from sqlalchemy import select, text
from sqlalchemy.orm import Session

from app.modules.iam.domain.services.authorization_service import Grant
from app.modules.iam.infrastructure.models import tables as t
from app.modules.organization.infrastructure.models.tables import org_unit_types

_IDENT = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")


class SqlAlchemyAuthorizationRepository:
    def __init__(self, s: Session):
        self.s = s

    def grants(self, user_id: int) -> list[Grant]:
        a, r, rp, p = t.user_role_assignments, t.roles, t.role_permissions, t.permissions
        rows = self.s.execute(
            select(p.c.code, a.c.scope_type_id, a.c.scope_id)
            .select_from(a.join(r, r.c.id == a.c.role_id).join(rp, rp.c.role_id == r.c.id)
                         .join(p, p.c.id == rp.c.permission_id))
            .where(a.c.user_id == user_id, a.c.revoked_at.is_(None), r.c.is_active.is_(True),
                   p.c.is_active.is_(True)))
        return [Grant(code, st, sid) for code, st, sid in rows]

    def institutional_types(self) -> frozenset[int]:
        return frozenset(self.s.scalars(select(org_unit_types.c.id).where(org_unit_types.c.is_institutional.is_(True))))

    def permission_names(self) -> dict[str, str]:
        return dict(self.s.execute(select(t.permissions.c.code, t.permissions.c.name)).all())

    def user_names(self, ids: set[int]) -> dict[int, str]:
        """Nombre visible de usuarios (para historial y auditoría). Solo nombre y apellido."""
        if not ids:
            return {}
        u = t.users
        rows = self.s.execute(select(u.c.id, u.c.first_name, u.c.last_name).where(u.c.id.in_(ids)))
        return {i: f"{f} {l}" for i, f, l in rows}

    def unit_type_codes(self) -> dict[int, str]:
        return dict(self.s.execute(select(org_unit_types.c.id, org_unit_types.c.code)).all())

    def children(self, scope_type_id: int, parent_ids: set[int]) -> dict[int, set[tuple[int, int]]]:
        """Hijos directos según el catálogo (source_table + parent_column), sin jerarquías escritas en código."""
        out: dict[int, set[tuple[int, int]]] = {}
        rows = self.s.execute(select(org_unit_types.c.id, org_unit_types.c.source_table, org_unit_types.c.parent_column)
                              .where(org_unit_types.c.parent_type_id == scope_type_id))
        for child_type, table, column in rows:
            if not (table and column and _IDENT.fullmatch(table) and _IDENT.fullmatch(column)):
                continue
            ids = ", ".join(str(int(i)) for i in parent_ids)  # enteros: sin riesgo de inyección
            q = text(f"SELECT id, {column} FROM {table} WHERE {column} IN ({ids})")
            out[child_type] = {(cid, pid) for cid, pid in self.s.execute(q)}
        return out
