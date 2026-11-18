"""Reglas del consentimiento (puras).

- Las categorías opcionales se autorizan una por una; las necesarias no dependen del consentimiento.
- El silencio no es autorización (Decreto 1377/2013, art. 7): sin decisión registrada, todo lo opcional está
  apagado.
- Una decisión vale 12 meses o hasta que se publique una versión de la política de cookies marcada como
  `requires_reconsent` (cambio sustancial de finalidades, tecnologías o categorías). Entonces se pregunta otra vez.
"""
from datetime import datetime, timedelta

OPTIONAL = ("functional", "analytics")        # las que el visitante puede activar hoy
UNAVAILABLE = ("advertising",)                # prevista en la arquitectura, no se usa: siempre apagada
KINDS = ("privacy_policy", "cookie_policy", "privacy_notice")
METHODS = ("accept_all", "reject_optional", "custom", "revoke")
COOKIE = "cris_consent"                       # cookie NECESARIA: guarda solo el id aleatorio del navegador
# Marca NO secreta legible por JS ("1"): dice solo que este navegador ya decidió. Permite mostrar el aviso al
# instante a quien no decidió, sin esperar una consulta (el aviso era el LCP tardío en celulares).
DECIDED_COOKIE = "cris_consent_set"
VALIDITY = timedelta(days=365)


def normalize(categories: dict[str, bool]) -> dict[str, bool]:
    """Solo categorías opcionales conocidas; lo no disponible queda en False aunque el cliente diga otra cosa."""
    return {c: bool(categories.get(c)) for c in OPTIONAL} | dict.fromkeys(UNAVAILABLE, False)


def needs_decision(policy_version: int | None, expires_at: datetime | None, reconsent_version: int,
                   at: datetime) -> bool:
    """¿Hay que (volver a) preguntar? Sin decisión, vencida o anterior a un cambio sustancial."""
    return policy_version is None or expires_at is None or expires_at <= at or policy_version < reconsent_version
