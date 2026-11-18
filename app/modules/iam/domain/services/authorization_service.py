"""Motor de autorización RBAC con alcance organizacional.

- Denegación por defecto: sin concesión explícita, no hay permiso.
- Asignación institucional (sin alcance) = el permiso vale en todas las dependencias.
- Asignación con alcance = vale en esa unidad y en sus descendientes (facultad -> sus programas).
  La herencia se expande al cargar el Principal, así cada chequeo es una búsqueda en un set.
- Nada depende del nombre del rol: solo de los códigos de permiso que el rol contiene.
"""
from collections.abc import Callable, Iterable
from dataclasses import dataclass, field

from app.shared.exceptions import ForbiddenError

Scope = tuple[int, int]  # (scope_type_id, scope_id)


@dataclass(frozen=True)
class Grant:
    permission: str
    scope_type_id: int | None = None
    scope_id: int | None = None

    @property
    def is_global(self) -> bool:
        return self.scope_type_id is None


@dataclass
class Principal:
    """Usuario autenticado + permisos efectivos de ESTA petición (se recalculan en cada request:
    revocar una asignación surte efecto inmediato)."""
    user_id: int
    session_id: int | None = None
    grants: tuple[Grant, ...] = ()  # tal como fueron asignados (para mostrarlos)
    institutional_types: frozenset[int] = frozenset()
    _global: set[str] = field(default_factory=set)
    _scoped: dict[str, set[Scope]] = field(default_factory=dict)

    # ---------- consultas ----------
    def can_any(self, code: str) -> bool:
        """¿Tiene el permiso en algún alcance? (filtro grueso de endpoint)."""
        return code in self._global or bool(self._scoped.get(code))

    def is_global(self, code: str) -> bool:
        return code in self._global

    def allows(self, code: str, scope: Scope) -> bool:
        if code in self._global:
            return True
        if scope[0] in self.institutional_types:  # una "unidad" institucional solo la cubre lo global
            return False
        return scope in self._scoped.get(code, ())

    def allows_all(self, code: str, scopes: Iterable[Scope]) -> bool:
        """Regla para actuar: autoridad sobre TODAS las dependencias. Sin dependencias => institucional."""
        scopes = list(scopes)
        return all(self.allows(code, s) for s in scopes) if scopes else self.is_global(code)

    def allows_any(self, code: str, scopes: Iterable[Scope]) -> bool:
        """Regla para ver: basta una de las dependencias."""
        scopes = list(scopes)
        return any(self.allows(code, s) for s in scopes) if scopes else self.is_global(code)

    def visible_scopes(self, code: str) -> set[Scope] | None:
        """None = sin restricción (global). Set vacío = nada."""
        return None if code in self._global else set(self._scoped.get(code, ()))

    @property
    def permissions(self) -> list[str]:
        return sorted(self._global | {c for c, s in self._scoped.items() if s})

    # ---------- exigencias ----------
    def ensure_all(self, code: str, scopes: Iterable[Scope]) -> None:
        if not self.allows_all(code, scopes):
            raise ForbiddenError(f"No tienes '{code}' sobre todas las dependencias de este recurso")

    def ensure_global(self, code: str) -> None:
        if not self.is_global(code):
            raise ForbiddenError(f"'{code}' requiere alcance institucional")


Children = Callable[[int, set[int]], dict[int, set[tuple[int, int]]]]
"""children(scope_type_id, parent_ids) -> {child_type_id: {(child_id, parent_id)}} (un nivel)."""


def build_principal(user_id: int, session_id: int | None, grants: Iterable[Grant],
                    institutional_types: frozenset[int], children: Children) -> Principal:
    grants = tuple(grants)
    p = Principal(user_id, session_id, grants, institutional_types)
    by_scope: dict[Scope, set[str]] = {}
    for g in grants:
        if g.is_global or g.scope_type_id in institutional_types:
            p._global.add(g.permission)
        else:
            by_scope.setdefault((g.scope_type_id, g.scope_id), set()).add(g.permission)

    # Herencia hacia abajo, por niveles, agrupando por tipo para pocas consultas.
    frontier = dict(by_scope)
    while frontier:
        next_frontier: dict[Scope, set[str]] = {}
        by_type: dict[int, dict[int, set[str]]] = {}
        for (t, i), codes in frontier.items():
            by_type.setdefault(t, {})[i] = codes
        for t, parents in by_type.items():
            for child_type, ids in children(t, set(parents)).items():
                for cid, parent_id in ids:
                    scope = (child_type, cid)
                    new = parents[parent_id] - by_scope.get(scope, set())
                    if new:
                        by_scope.setdefault(scope, set()).update(new)
                        next_frontier.setdefault(scope, set()).update(new)
        frontier = next_frontier

    for scope, codes in by_scope.items():
        for code in codes:
            p._scoped.setdefault(code, set()).add(scope)
    return p


def can_assign(principal: Principal, role_permissions: Iterable[str], scope: Scope | None) -> bool:
    """Anti-escalamiento: solo puedes asignar un rol si tienes users.manage_roles en ese alcance
    Y ya tienes cada permiso del rol en ese mismo alcance."""
    scopes = [scope] if scope else []
    return all(principal.allows_all(code, scopes) for code in ("users.manage_roles", *role_permissions))
