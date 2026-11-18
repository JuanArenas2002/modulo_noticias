from dataclasses import dataclass, field
from datetime import datetime

from app.shared.clock import now


@dataclass(kw_only=True, eq=False)
class AuditLog:
    """Evento auditable. Solo-append. `context` nunca lleva contraseñas, tokens ni cookies."""
    id: int | None = None
    actor_user_id: int | None = None
    event_type: str
    result: str  # success | failure | denied
    resource_type: str | None = None
    resource_id: str | None = None
    ip: str | None = None
    user_agent: str | None = None
    context: dict | None = None
    at: datetime = field(default_factory=now)
