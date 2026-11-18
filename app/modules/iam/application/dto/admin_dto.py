"""Entradas de administración. Orden "controlado" = lista cerrada de columnas (Literal), nunca texto libre."""
from datetime import datetime
from typing import Literal

from pydantic import BaseModel, Field, field_validator, model_validator

from app.modules.iam.application.dto.auth_dto import Password, _EmailIn

Order = Literal["asc", "desc"]
CODE_ROLE = r"^[a-z][a-z0-9_]{2,49}$"
CODE_PERMISSION = r"^[a-z][a-z0-9_]*(\.[a-z][a-z0-9_]*){1,2}$"  # modulo.accion | modulo.recurso.accion


class PageDTO(BaseModel):
    limit: int = Field(20, ge=1, le=100)
    offset: int = Field(0, ge=0)
    order: Order = "desc"


# ---------- usuarios ----------
class UserFilterDTO(PageDTO):
    q: str | None = Field(None, max_length=100, description="Busca en nombre, apellido o correo")
    status: str | None = None
    account_type: str | None = None
    role: str | None = Field(None, description="Usuarios con una asignación activa de este rol")
    sort: Literal["created_at", "last_login_at", "email", "last_name"] = "created_at"


class UserCreateDTO(_EmailIn):
    """Crear con contraseña temporal: queda activa y debe cambiarla en su primer inicio de sesión."""
    first_name: str = Field(min_length=1, max_length=100)
    last_name: str = Field(min_length=1, max_length=100)
    account_type: str = "institutional"
    password: str = Password


class SetPasswordDTO(BaseModel):
    """Un administrador fija una contraseña temporal (olvido); el usuario debe cambiarla al entrar."""
    password: str = Password


class UserUpdateDTO(BaseModel):
    first_name: str | None = Field(None, min_length=1, max_length=100)
    last_name: str | None = Field(None, min_length=1, max_length=100)
    email: str | None = Field(None, max_length=254, pattern=r"^[^@\s]{1,64}@[^@\s]+\.[^@\s]+$")
    account_type: str | None = None

    @field_validator("email", mode="before")
    @classmethod
    def normalize(cls, v):
        return v.strip().lower() if isinstance(v, str) else v


class ReasonDTO(BaseModel):
    reason: str | None = Field(None, max_length=500)


class AssignRoleDTO(BaseModel):
    role: str = Field(pattern=CODE_ROLE)
    scope_type: str | None = None  # None = institucional
    scope_id: int | None = Field(None, gt=0)

    @model_validator(mode="after")
    def pair(self):
        if (self.scope_type is None) != (self.scope_id is None):
            raise ValueError("scope_type y scope_id van juntos (o ninguno = institucional)")
        return self


# ---------- roles ----------
class RoleFilterDTO(PageDTO):
    q: str | None = Field(None, max_length=100)
    is_active: bool | None = None
    sort: Literal["code", "name", "created_at"] = "code"
    order: Order = "asc"


class RoleCreateDTO(BaseModel):
    code: str = Field(pattern=CODE_ROLE)
    name: str = Field(min_length=2, max_length=100)
    description: str | None = Field(None, max_length=1000)
    permissions: list[str] = []


class RoleUpdateDTO(BaseModel):
    name: str | None = Field(None, min_length=2, max_length=100)
    description: str | None = Field(None, max_length=1000)
    is_active: bool | None = None


class RolePermissionsDTO(BaseModel):
    permissions: list[str]


# ---------- permisos ----------
class PermissionFilterDTO(PageDTO):
    q: str | None = Field(None, max_length=100)
    module: str | None = Field(None, max_length=50)
    is_active: bool | None = None
    sort: Literal["code", "module", "created_at"] = "code"
    order: Order = "asc"


class PermissionCreateDTO(BaseModel):
    code: str = Field(pattern=CODE_PERMISSION, max_length=100)
    name: str = Field(min_length=2, max_length=150)
    description: str | None = Field(None, max_length=1000)
    module: str = Field(pattern=r"^[a-z][a-z0-9_]{1,49}$")
    resource: str = Field(pattern=r"^[a-z][a-z0-9_]{1,49}$")
    action: str = Field(pattern=r"^[a-z][a-z0-9_]{1,49}$")

    @model_validator(mode="after")
    def consistent(self):
        if self.code.split(".")[-1] != self.action:
            raise ValueError("La acción debe ser el último segmento del código")
        return self


class PermissionUpdateDTO(BaseModel):
    name: str | None = Field(None, min_length=2, max_length=150)
    description: str | None = Field(None, max_length=1000)
    is_active: bool | None = None


# ---------- auditoría ----------
class AuditFilterDTO(PageDTO):
    event_type: str | None = Field(None, max_length=60, description="Prefijo, p.ej. 'auth.login'")
    actor_id: int | None = None
    resource_type: str | None = Field(None, max_length=60)
    resource_id: str | None = Field(None, max_length=64)
    result: Literal["success", "failure", "denied"] | None = None
    since: datetime | None = None
    until: datetime | None = None
