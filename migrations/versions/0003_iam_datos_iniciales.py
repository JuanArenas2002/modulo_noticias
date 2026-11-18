"""IAM: catálogos, permisos y roles iniciales.

Los roles son configuración inicial, no reglas fijas: después se administran por API/BD.
super_admin no es un comodín en código; simplemente recibe todos los permisos.

Revision ID: 0003
Revises: 0002
"""
import sqlalchemy as sa
from alembic import op

revision = "0003"
down_revision = "0002"
branch_labels = None
depends_on = None

USER_STATUSES = [  # code, name, can_login
    ("invited", "Invitado (pendiente de activar)", False),
    ("active", "Activo", True),
    ("inactive", "Inactivo", False),
    ("blocked", "Bloqueado por administrador", False),
]
ACCOUNT_TYPES = [("institutional", "Institucional"), ("external", "Externo")]
IDENTITY_PROVIDERS = [("password", "Correo y contraseña"), ("microsoft", "Microsoft Entra ID")]

# code, name, module, resource, action  (solo permisos que el backend realmente exige)
PERMISSIONS = [
    ("users.view", "Ver usuarios", "iam", "users", "view"),
    ("users.create", "Crear usuarios", "iam", "users", "create"),
    ("users.update", "Editar, activar y bloquear usuarios", "iam", "users", "update"),
    ("users.delete", "Eliminar usuarios (lógico)", "iam", "users", "delete"),
    ("users.manage_roles", "Asignar y revocar roles", "iam", "users", "manage_roles"),
    ("users.manage_sessions", "Ver y revocar sesiones de otros", "iam", "users", "manage_sessions"),
    ("roles.view", "Ver roles", "iam", "roles", "view"),
    ("roles.manage", "Crear, editar y eliminar roles", "iam", "roles", "manage"),
    ("permissions.view", "Ver permisos", "iam", "permissions", "view"),
    ("permissions.manage", "Crear y modificar permisos", "iam", "permissions", "manage"),
    ("audit.view", "Consultar auditoría", "iam", "audit", "view"),
    ("news.view", "Ver noticias no publicadas", "news", "news", "view"),
    ("news.create", "Crear noticias", "news", "news", "create"),
    ("news.update", "Editar noticias", "news", "news", "update"),
    ("news.submit", "Enviar a revisión", "news", "news", "submit"),
    ("news.review", "Revisar y rechazar", "news", "news", "review"),
    ("news.approve", "Aprobar", "news", "news", "approve"),
    ("news.publish", "Publicar y programar", "news", "news", "publish"),
    ("news.archive", "Archivar", "news", "news", "archive"),
    ("news.curate", "Destacar, fijar y priorizar publicadas", "news", "news", "curate"),
    ("news.manage_categories", "Administrar categorías", "news", "categories", "manage"),
    ("organization.sync", "Sincronizar dependencias desde Metri-K", "organization", "organization", "sync"),
]

ALL = [p[0] for p in PERMISSIONS]
ROLES = {  # code: (name, description, permisos)
    "super_admin": ("Super administrador", "Administración global de la plataforma", ALL),
    "admin": ("Administrador", "Usuarios y módulos (no modifica el catálogo de permisos)",
              [p for p in ALL if p != "permissions.manage"]),
    "editor": ("Editor", "Crea y edita contenidos", ["news.view", "news.create", "news.update", "news.submit"]),
    "reviewer": ("Revisor", "Revisa y aprueba contenidos", ["news.view", "news.review", "news.approve"]),
    "publisher": ("Publicador", "Publica contenidos aprobados",
                  ["news.view", "news.publish", "news.archive", "news.curate"]),
    "viewer": ("Consulta", "Consulta información interna", ["news.view"]),
    "user": ("Usuario", "Usuario básico", []),
}


def _t(name, *cols):
    return sa.table(name, *(sa.column(c) for c in cols))


def _ids(table: str) -> dict[str, int]:
    return dict((code, id_) for id_, code in op.get_bind().execute(sa.text(f"SELECT id, code FROM {table}")))


def upgrade() -> None:
    op.bulk_insert(_t("user_statuses", "code", "name", "can_login"),
                   [{"code": c, "name": n, "can_login": cl} for c, n, cl in USER_STATUSES])
    op.bulk_insert(_t("account_types", "code", "name"), [{"code": c, "name": n} for c, n in ACCOUNT_TYPES])
    op.bulk_insert(_t("identity_providers", "code", "name", "is_enabled"),
                   [{"code": c, "name": n, "is_enabled": True} for c, n in IDENTITY_PROVIDERS])
    op.bulk_insert(_t("permissions", "code", "name", "module", "resource", "action", "is_active"),
                   [{"code": c, "name": n, "module": m, "resource": r, "action": a, "is_active": True}
                    for c, n, m, r, a in PERMISSIONS])
    op.bulk_insert(_t("roles", "code", "name", "description", "is_active"),
                   [{"code": c, "name": n, "description": d, "is_active": True} for c, (n, d, _) in ROLES.items()])
    perm, role = _ids("permissions"), _ids("roles")
    op.bulk_insert(_t("role_permissions", "role_id", "permission_id"),
                   [{"role_id": role[r], "permission_id": perm[p]} for r, (_, _, ps) in ROLES.items() for p in ps])


def downgrade() -> None:
    for table in ("role_permissions", "roles", "permissions", "identity_providers", "account_types", "user_statuses"):
        op.execute(f"DELETE FROM {table}")
