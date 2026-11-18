"""ORCID iD: normalización y validación (formato + dígito de control ISO 7064 MOD 11-2).

Acepta "0000-0002-1825-0097", "https://orcid.org/0000-0002-1825-0097", "orcid.org/…" o sin guiones.
Devuelve siempre la forma canónica con guiones y X mayúscula.
"""
import re

_SHAPE = re.compile(r"^\d{15}[\dX]$")


def checksum(base15: str) -> str:
    """Dígito de control de los 15 primeros dígitos (ISO 7064 MOD 11-2)."""
    total = 0
    for digit in base15:
        total = (total + int(digit)) * 2
    result = (12 - total % 11) % 11
    return "X" if result == 10 else str(result)


def normalize_orcid(raw: str) -> str:
    """ORCID canónico o ValueError si el formato o el dígito de control no son válidos."""
    value = (raw or "").strip().upper()
    value = re.sub(r"^(HTTPS?://)?(WWW\.)?ORCID\.ORG/", "", value).replace("-", "").replace(" ", "")
    if not _SHAPE.fullmatch(value):
        raise ValueError("El ORCID debe tener 16 caracteres: 0000-0000-0000-0000")
    if checksum(value[:15]) != value[15]:
        raise ValueError("El ORCID no es válido (el dígito de control no coincide)")
    return "-".join(value[i:i + 4] for i in range(0, 16, 4))
