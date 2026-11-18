"""Construcción de eventos de auditoría. Filtra claves sensibles por si alguien las pasa por error."""
from dataclasses import dataclass

from app.modules.iam.domain.entities.audit import AuditLog

SENSITIVE = ("password", "token", "secret", "cookie", "code", "authorization", "csrf")


@dataclass(frozen=True)
class RequestMeta:
    ip: str | None = None
    user_agent: str | None = None


def event(event_type: str, result: str, meta: RequestMeta, actor_id: int | None = None,
          resource_type: str | None = None, resource_id=None, **context) -> AuditLog:
    safe = {k: v for k, v in context.items() if not any(s in k.lower() for s in SENSITIVE)}
    return AuditLog(event_type=event_type, result=result, actor_user_id=actor_id, resource_type=resource_type,
                    resource_id=None if resource_id is None else str(resource_id), ip=meta.ip,
                    user_agent=(meta.user_agent or "")[:500] or None, context=safe or None)
