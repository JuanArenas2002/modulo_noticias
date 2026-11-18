"""Motor de autorización (dominio puro): alcance, herencia, denegación por defecto y anti-escalamiento."""
from app.modules.iam.domain.services.authorization_service import Grant, build_principal, can_assign

CENTER, FACULTY, PROGRAM, INSTITUTION = 1, 2, 3, 9
HIERARCHY = {FACULTY: {PROGRAM: {(8, 5), (9, 5), (10, 3)}}}  # programas 8 y 9 de la facultad 5; 10 de la 3


def children(scope_type, parent_ids):
    return {child: {(cid, pid) for cid, pid in pairs if pid in parent_ids}
            for child, pairs in HIERARCHY.get(scope_type, {}).items()}


def principal(*grants):
    return build_principal(1, None, grants, frozenset({INSTITUTION}), children)


def test_deny_by_default():
    p = principal()
    assert not p.can_any("news.create") and not p.allows("news.create", (CENTER, 2))
    assert p.visible_scopes("news.view") == set() and p.permissions == []


def test_global_grant_covers_everything_and_empty_scopes():
    p = principal(Grant("news.create"))
    assert p.allows_all("news.create", [(CENTER, 2), (FACULTY, 5)]) and p.allows_all("news.create", [])
    assert p.visible_scopes("news.create") is None  # None = sin restricción


def test_scoped_grant_and_inheritance():
    p = principal(Grant("news.publish", FACULTY, 5))
    assert p.allows("news.publish", (FACULTY, 5))
    assert p.allows("news.publish", (PROGRAM, 8)) and p.allows("news.publish", (PROGRAM, 9))  # hijos
    assert not p.allows("news.publish", (PROGRAM, 10))                                       # hijo de otra
    assert not p.allows("news.publish", (FACULTY, 3)) and not p.allows("news.publish", (CENTER, 2))
    assert not p.allows_all("news.publish", [])                 # sin dependencias = institucional
    assert not p.allows_all("news.publish", [(FACULTY, 5), (CENTER, 2)])  # TODAS
    assert p.allows_any("news.publish", [(FACULTY, 5), (CENTER, 2)])      # alguna (para ver)
    assert p.visible_scopes("news.publish") == {(FACULTY, 5), (PROGRAM, 8), (PROGRAM, 9)}


def test_institutional_unit_requires_global():
    p = principal(Grant("news.create", CENTER, 2))
    assert not p.allows("news.create", (INSTITUTION, 1))
    institutional_assignment = principal(Grant("news.create", INSTITUTION, 1))  # asignado a "la institución"
    assert institutional_assignment.is_global("news.create")


def test_permissions_do_not_leak_between_codes_or_scopes():
    p = principal(Grant("news.create", CENTER, 2), Grant("news.approve", FACULTY, 5))
    assert p.allows("news.create", (CENTER, 2)) and not p.allows("news.approve", (CENTER, 2))
    assert p.allows("news.approve", (PROGRAM, 8)) and not p.allows("news.create", (PROGRAM, 8))
    assert p.permissions == ["news.approve", "news.create"]


def test_privilege_escalation_rules():
    editor_perms = ["news.view", "news.create", "news.update", "news.submit"]
    admin = principal(*[Grant(c) for c in ["users.manage_roles", *editor_perms]])
    assert can_assign(admin, editor_perms, (CENTER, 2)) and can_assign(admin, editor_perms, None)
    assert not can_assign(admin, [*editor_perms, "permissions.manage"], None)   # no otorga lo que no tiene

    faculty_admin = principal(*[Grant(c, FACULTY, 5) for c in ["users.manage_roles", *editor_perms]])
    assert can_assign(faculty_admin, editor_perms, (FACULTY, 5))
    assert can_assign(faculty_admin, editor_perms, (PROGRAM, 8))                 # programa de su facultad
    assert not can_assign(faculty_admin, editor_perms, (PROGRAM, 10))            # programa de otra facultad
    assert not can_assign(faculty_admin, editor_perms, (CENTER, 2))              # centro ajeno
    assert not can_assign(faculty_admin, editor_perms, None)                     # institucional

    editor = principal(*[Grant(c, CENTER, 2) for c in editor_perms])
    assert not can_assign(editor, editor_perms, (CENTER, 2))                     # sin users.manage_roles
    assert not can_assign(editor, [], (CENTER, 2))                               # ni siquiera un rol vacío
