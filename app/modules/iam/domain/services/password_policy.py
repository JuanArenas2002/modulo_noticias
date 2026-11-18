"""Política de contraseñas (OWASP ASVS v4 2.1): longitud mínima, sin reglas de composición forzadas,
rechazo de contraseñas comunes y de las que contienen datos del propio usuario.
"""
from dataclasses import dataclass

# ponytail: lista mínima de contraseñas comunes; para producción seria, consultar HIBP (k-anonimato).
COMMON = {
    "123456789012", "password1234", "contraseña123", "qwertyuiop12", "unisimon2024", "unisimon2025",
    "unisimon2026", "administrador", "bienvenido123", "1234567890ab", "passwordpassword", "aaaaaaaaaaaa",
}


@dataclass(frozen=True)
class PasswordPolicy:
    min_length: int = 12
    max_length: int = 128

    def problems(self, password: str, personal: tuple[str, ...] = ()) -> list[str]:
        errors = []
        if len(password) < self.min_length:
            errors.append(f"Debe tener al menos {self.min_length} caracteres")
        if len(password) > self.max_length:
            errors.append(f"Debe tener como máximo {self.max_length} caracteres")
        lowered = password.lower()
        if lowered in COMMON or len(set(lowered)) <= 3:
            errors.append("Es demasiado común o repetitiva")
        if any(p and len(p) >= 4 and p.lower() in lowered for p in personal):
            errors.append("No debe contener tu nombre ni tu correo")
        return errors
