from pydantic import BaseModel, Field, field_validator

# Longitud máxima: evita gastar CPU de Argon2 con entradas gigantes (DoS). La política real va aparte.
Password = Field(min_length=1, max_length=1024)
Token = Field(min_length=20, max_length=200)


class _EmailIn(BaseModel):
    email: str = Field(max_length=254, pattern=r"^[^@\s]{1,64}@[^@\s]+\.[^@\s]+$")

    @field_validator("email", mode="before")  # antes del patrón: " ANA@x.co " es válido
    @classmethod
    def normalize(cls, v):
        return v.strip().lower() if isinstance(v, str) else v


class LoginDTO(_EmailIn):
    password: str = Password


class ForgotPasswordDTO(_EmailIn):
    pass


class ResetPasswordDTO(BaseModel):
    token: str = Token
    new_password: str = Password


class ChangePasswordDTO(BaseModel):
    current_password: str = Password
    new_password: str = Password


class RegisterDTO(BaseModel):
    """Aceptar invitación: no hay registro abierto, solo con token de invitación."""
    token: str = Token
    password: str = Password


class TokenDTO(BaseModel):
    token: str = Token


class InviteUserDTO(_EmailIn):
    first_name: str = Field(min_length=1, max_length=100)
    last_name: str = Field(min_length=1, max_length=100)
    account_type: str = "institutional"
